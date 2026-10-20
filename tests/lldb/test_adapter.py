import asyncio
import json
import sys
import time

import pytest

from dea.adapters.lldb import LldbAdapter
from dea.adapters.lldb import adapter as module
from dea.adapters.lldb.discovery import Interpreter
from dea.contracts.adapter import AdapterContext
from dea.contracts.models import (
    AttachSpec, Backend, CaptureRequest, DebuggerEvent, DeaError, ErrorCode,
    HelperMessage, LaunchSpec, MemoryRegion, RuntimeLimits, StepMode, StopReason,
    TerminationPolicy,
)
from tests.support.fakes import FakeClock, FakeHistory, FakeProcessManager, SID


def response(request, body, operation=None):
    return HelperMessage(kind="response", operation=operation or request.operation,
        request_id=request.request_id, body_json=json.dumps(body))


def event(identifier=1, kind="stopped", reason="entry"):
    body = dict(event_id=identifier, kind=kind)
    if kind == "stopped": body["reason"] = reason
    if kind == "exited": body["exit_code"] = 0
    return HelperMessage(kind="event", operation="debugger_event", event_id=identifier,
                         body_json=json.dumps(body))


class Runtime(FakeProcessManager):
    def __init__(self):
        super().__init__()
        self.hook = None

    async def spawn(self, spec):
        process = await super().spawn(spec)
        original = process.control.send

        async def send(message):
            await original(message)
            if self.hook:
                self.hook(process, message)
                return
            body = {"request_id": message.request_id, "accepted": True}
            if message.operation in ("session_start", "session_attach"):
                process.control.feed(event())
            if message.operation == "session_terminate": body = {}
            process.control.feed(response(message, body))
        process.control.send = send
        return process


@pytest.fixture
async def adapter(monkeypatch):
    monkeypatch.setattr(module, "candidate", lambda: Interpreter(sys.executable))
    monkeypatch.setattr(module, "discover", lambda: Interpreter(sys.executable))
    runtime = Runtime()
    adapter = LldbAdapter(AdapterContext(SID, runtime, FakeHistory(), FakeClock(), RuntimeLimits(command_seconds=1)))
    yield adapter, runtime
    await adapter._cleanup()


async def start(adapter):
    return await adapter.session_start(LaunchSpec(backend=Backend.LLDB, binary_path="demo"))


async def test_event_before_ack_and_target_output_isolation(adapter):
    native, runtime = adapter
    stream = native.events()
    waiting = asyncio.create_task(anext(stream))
    ack = await start(native)
    assert ack.request_id == 2
    assert (await waiting).kind == "stopped"
    assert runtime.specs[0].helper_control
    assert "-I" in runtime.specs[0].argv
    runtime.processes[0].feed(b'{"kind":"stopped"}(lldb)', "stdout")
    await asyncio.sleep(0)
    assert native._events.empty()
    await stream.aclose()


async def test_exit_before_ack_is_terminal_but_ack_is_correlated(adapter):
    native, runtime = adapter
    def hook(process, request):
        process.control.feed(event(kind="exited"))
        process.control.feed(response(request, dict(request_id=request.request_id, accepted=True)))
    runtime.hook = hook
    assert (await start(native)).accepted
    assert [item.kind async for item in native.events()] == ["exited"]


async def test_missing_bindings_are_capability_failure(monkeypatch):
    monkeypatch.setattr(module, "candidate", lambda: None)
    runtime = Runtime()
    native = LldbAdapter(AdapterContext(SID, runtime, FakeHistory(), FakeClock(), RuntimeLimits()))
    assert native.capabilities().available is False
    with pytest.raises(DeaError) as caught:
        await start(native)
    assert caught.value.code is ErrorCode.CAPABILITY_UNAVAILABLE
    assert not runtime.processes


async def test_abi_probe_does_not_block_event_loop(adapter, monkeypatch):
    native, runtime = adapter
    def slow_probe():
        time.sleep(0.1)
        return None
    monkeypatch.setattr(module, "discover", slow_probe)
    pending = asyncio.create_task(start(native))
    beats = 0
    while not pending.done():
        beats += 1
        await asyncio.sleep(0.005)
    with pytest.raises(DeaError) as caught:
        await pending
    assert caught.value.code is ErrorCode.CAPABILITY_UNAVAILABLE
    assert beats >= 5 and not native.capabilities().available
    assert not runtime.processes


async def test_timeout_cancels_correlation_and_stale_reply_cannot_satisfy_new_request(adapter):
    native, runtime = adapter
    await start(native)
    runtime.hook = lambda process, request: None
    with pytest.raises(DeaError) as caught:
        await native.execution_continue()
    assert caught.value.code is ErrorCode.COMMAND_TIMEOUT
    previous = runtime.processes[0].control.sent[-1]
    pending = asyncio.create_task(native.execution_interrupt())
    await asyncio.sleep(0)
    control = runtime.processes[0].control
    control.feed(response(previous, dict(request_id=previous.request_id, accepted=True)))
    current = control.sent[-1]
    control.feed(response(current, dict(request_id=current.request_id, accepted=True)))
    assert (await pending).request_id == current.request_id != previous.request_id


@pytest.mark.parametrize("bad", ["wrong_operation", "wrong_event_id", "bad_body", "unexpected_request"])
async def test_malformed_protocol_fails_and_closes_helper(adapter, bad):
    native, runtime = adapter
    await start(native)
    process = runtime.processes[0]
    if bad == "wrong_event_id":
        message = event(2).model_copy(update={"event_id": 3})
    elif bad == "wrong_operation":
        message = event(2).model_copy(update={"operation": "junk"})
    elif bad == "bad_body":
        message = event(2).model_copy(update={"body_json": '{"kind":"stopped"}'})
    else:
        message = HelperMessage(kind="request", request_id=99, operation="execution_continue", body_json="{}")
    process.control.feed(message)
    for _ in range(20):
        if native._error: break
        await asyncio.sleep(0)
    assert native._error.code is ErrorCode.PROTOCOL_ERROR
    assert process.closed


async def test_control_overflow_is_explicit(adapter):
    native, runtime = adapter
    await start(native)
    for index in range(2, 258):
        runtime.processes[0].control.feed(event(index))
    for _ in range(20):
        if native._error: break
        await asyncio.sleep(0)
    assert native._error.code is ErrorCode.CONTROL_OVERFLOW


async def test_helper_crash_fails_pending_command(adapter):
    native, runtime = adapter
    await start(native)
    runtime.hook = lambda process, request: None
    pending = asyncio.create_task(native.execution_continue())
    await asyncio.sleep(0)
    await runtime.processes[0].control.close()
    with pytest.raises(DeaError) as caught:
        await pending
    assert caught.value.code is ErrorCode.PROTOCOL_ERROR


async def test_detach_failure_and_idempotent_cleanup(adapter):
    native, runtime = adapter
    await native.session_attach(AttachSpec(backend=Backend.LLDB, pid=99))
    def hook(process, request):
        process.control.feed(response(request, {"code": "DETACH_FAILED"}, "error"))
    runtime.hook = hook
    with pytest.raises(DeaError) as caught:
        await native.session_terminate(TerminationPolicy.DETACH)
    assert caught.value.code is ErrorCode.DETACH_FAILED
    assert runtime.processes[0].closed
    await native.session_terminate(TerminationPolicy.DETACH)


async def test_pty_rejected_before_helper_spawn(adapter):
    native, runtime = adapter
    with pytest.raises(DeaError) as caught:
        await native.session_start(LaunchSpec(backend=Backend.LLDB, binary_path="demo", io_mode="pty"))
    assert caught.value.code is ErrorCode.CAPABILITY_UNAVAILABLE
    assert not runtime.processes


async def test_expected_eof_immediately_after_termination_ack(adapter):
    native, runtime = adapter
    await start(native)
    def hook(process, request):
        process.control.feed(response(request, {}))
        asyncio.create_task(process.control.close())
    runtime.hook = hook
    await native.session_terminate(TerminationPolicy.TERMINATE_OWNED)
    assert native._error is None and runtime.processes[0].closed
