import asyncio
import json
import re

import pytest

from dea.adapters.gdb import GdbAdapter
from dea.adapters.gdb.adapter import quote
from dea.contracts.adapter import AdapterContext
from dea.contracts.models import (AttachSpec, Backend, BreakpointSpec, CaptureRequest,
    DeaError, ErrorCode, LaunchSpec, MemoryRegion, RuntimeLimits, StepMode, StopReason,
    TerminationPolicy)
from tests.support.fakes import FakeClock, FakeHistory, FakeProcess, FakeProcessManager, SID


class ScriptProcess(FakeProcess):
    def __init__(self):
        super().__init__()
        self.hook = None

    async def write(self, data):
        await super().write(data)
        token, command = re.fullmatch(r"(\d+)(.*)\n", data.decode()).groups()
        if self.hook and await self.hook(int(token), command):
            return
        reply = '^done,value="on"' if command == "-gdb-show mi-async" else '^done'
        if command.startswith("-exec-run"):
            self.feed(b'*running,thread-id="all"\n*stopped,reason="breakpoint-hit",thread-id="3"\n')
            reply = '^running'
        elif command == "-target-attach 55":
            self.feed(b'*stopped,reason="signal-received",signal-name="SIGTRAP",thread-id="3"\n')
        elif command == "-gdb-exit":
            reply = '^exit'
        elif command.startswith("-break-insert"):
            reply = '^done,bkpt={number="12",addr="0x123"}'
        self.feed((token + reply + "\n").encode())


class ScriptRuntime(FakeProcessManager):
    async def spawn(self, spec):
        self.specs.append(spec)
        process = ScriptProcess()
        self.processes.append(process)
        return process


def adapter_context(**kwargs):
    limits = RuntimeLimits(**kwargs)
    runtime = ScriptRuntime()
    return runtime, GdbAdapter(AdapterContext(SID, runtime, FakeHistory(), FakeClock(), limits))


async def launch(adapter):
    await adapter.session_start(LaunchSpec(backend=Backend.GDB, binary_path="fake target"))


@pytest.mark.asyncio
async def test_initialization_protocol_and_stop_before_ack(monkeypatch):
    monkeypatch.setattr("dea.adapters.gdb.adapter.shutil.which", lambda _: "gdb")
    runtime, adapter = adapter_context()
    try:
        await launch(adapter)
        events = adapter.events()
        assert [event.kind for event in [await anext(events) for _ in range(3)]] == ["started", "running", "stopped"]
        await events.aclose()
        assert adapter._stopped
        spec = runtime.specs[0]
        assert "--nx" in spec.argv and "--nh" in spec.argv and spec.transport == "pipes"
        assert not spec.helper_control
        assert all(b"interpreter-exec" not in write for write in adapter._process.writes)
        assert adapter.capabilities().available and not adapter.capabilities().terminal
    finally:
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)


@pytest.mark.asyncio
@pytest.mark.parametrize("record,reason", [
    ('*stopped,reason="watchpoint-trigger",wpt={number="2",exp="x"}', StopReason.WATCHPOINT),
    ('*stopped,reason="read-watchpoint-trigger"', StopReason.WATCHPOINT),
    ('*stopped,reason="access-watchpoint-trigger"', StopReason.WATCHPOINT),
    ('*stopped,reason="watchpoint-scope"', StopReason.WATCHPOINT),
    ('*stopped,reason="signal-received",signal-name="SIGSEGV"', StopReason.SIGNAL),
    ('*stopped,reason="signal-received",signal-name="SIGINT"', StopReason.SIGNAL),
    ('*stopped,reason="signal-received",signal-name="SIGTRAP"', StopReason.SIGNAL),
    ('*stopped,reason="function-finished"', StopReason.STEP),
    ('*stopped,reason="end-stepping-range"', StopReason.STEP),
])
async def test_independent_tokenless_events(record, reason):
    _, adapter = adapter_context()
    from dea.adapters.gdb.mi import parse_record
    adapter._record(parse_record(record))
    assert (await anext(adapter.events())).reason is reason


@pytest.mark.asyncio
async def test_exit_before_execution_ack_stays_terminal(monkeypatch):
    monkeypatch.setattr("dea.adapters.gdb.adapter.shutil.which", lambda _: "gdb")
    _, adapter = adapter_context()
    await launch(adapter)
    while not adapter._queue.empty():
        adapter._queue.get_nowait()
    async def hook(token, command):
        if command.startswith("-exec-continue"):
            adapter._process.feed(f'=thread-group-exited,id="i1",exit-code="010"\n*stopped,reason="exited",exit-code="010"\n{token}^running\n'.encode())
            return True
    adapter._process.hook = hook
    ack = await adapter.execution_continue()
    assert ack.accepted and adapter._terminal and not adapter._stopped
    assert (await anext(adapter.events())).exit_code == 8
    assert adapter._queue.empty()
    await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)


@pytest.mark.asyncio
async def test_quoting_condition_and_pending_breakpoint(monkeypatch):
    monkeypatch.setattr("dea.adapters.gdb.adapter.shutil.which", lambda _: "gdb")
    _, adapter = adapter_context()
    try:
        await launch(adapter)
        spec = BreakpointSpec(location='source with space.c:9', condition='x == "a\\b"\n')
        result = await adapter.breakpoint_set(spec)
        assert result.breakpoint_id == "12" and result.verified
        command = adapter._process.writes[-1].decode()
        assert quote(spec.location) in command and quote(spec.condition) in command
        assert command.count("\n") == 1
        async def hook(token, command):
            if command.startswith("-break-insert"):
                adapter._process.feed(f'{token}^done,bkpt={{number="13",addr="<PENDING>"}}\n'.encode())
                return True
        adapter._process.hook = hook
        assert not (await adapter.breakpoint_set(spec)).verified
    finally:
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)


@pytest.mark.asyncio
async def test_timeout_and_stale_reply_cannot_satisfy_next_command(monkeypatch):
    monkeypatch.setattr("dea.adapters.gdb.adapter.shutil.which", lambda _: "gdb")
    _, adapter = adapter_context(command_seconds=1)
    try:
        await launch(adapter)
        stale = None
        async def hook(token, command):
            nonlocal stale
            if command == "-slow":
                stale = token
                return True
            if command == "-next":
                adapter._process.feed(f'{stale}^done,value="WRONG"\n{token}^done,value="right"\n'.encode())
                return True
        adapter._process.hook = hook
        with pytest.raises(DeaError) as exc:
            await adapter._command("-slow")
        assert exc.value.code is ErrorCode.COMMAND_TIMEOUT and not adapter._pending
        _, result = await adapter._command("-next")
        assert result["value"] == "right"
    finally:
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)


@pytest.mark.asyncio
async def test_stderr_and_stream_spoofs_never_become_events(monkeypatch):
    monkeypatch.setattr("dea.adapters.gdb.adapter.shutil.which", lambda _: "gdb")
    _, adapter = adapter_context(diagnostic_bytes=60)
    try:
        await launch(adapter)
        before = adapter._queue.qsize()
        adapter._process.feed(b'*stopped,reason="signal-received"\n999^done\n' * 4, "stderr")
        adapter._process.feed(b'@"*stopped,reason=\\"signal-received\\"\\n999^done\\n"\n')
        await asyncio.sleep(0.02)
        assert adapter._queue.qsize() == before
        assert len(adapter._diagnostics) <= 60 and adapter.diagnostic_dropped_bytes
    finally:
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)


@pytest.mark.asyncio
async def test_cancelled_command_and_protocol_failure_cleanup(monkeypatch):
    monkeypatch.setattr("dea.adapters.gdb.adapter.shutil.which", lambda _: "gdb")
    _, adapter = adapter_context()
    await launch(adapter)
    async def hook(token, command):
        return command == "-slow"
    adapter._process.hook = hook
    command = asyncio.create_task(adapter._command("-slow"))
    await asyncio.sleep(0)
    command.cancel()
    with pytest.raises(asyncio.CancelledError):
        await command
    assert not adapter._pending
    adapter._process.feed(b'not an MI record\n')
    await asyncio.sleep(0.02)
    events = []
    while not adapter._queue.empty():
        events.append(adapter._queue.get_nowait())
    assert events[-1].error_code is ErrorCode.PROTOCOL_ERROR
    await adapter._cleanup_task
    assert adapter._process.closed and adapter._target_io.closed


@pytest.mark.asyncio
async def test_control_overflow_fails_loudly_and_cleans_up(monkeypatch):
    monkeypatch.setattr("dea.adapters.gdb.adapter.shutil.which", lambda _: "gdb")
    _, adapter = adapter_context(control_events=3)
    await launch(adapter)
    adapter._process.feed(b'*running,thread-id="all"\n')
    await asyncio.sleep(0.02)
    event = await anext(adapter.events())
    assert event.kind == "failed" and event.error_code is ErrorCode.CONTROL_OVERFLOW
    await adapter._cleanup_task
    assert adapter._process.closed


@pytest.mark.asyncio
async def test_attach_detach_failure_is_explicit(monkeypatch):
    monkeypatch.setattr("dea.adapters.gdb.adapter.shutil.which", lambda _: "gdb")
    _, adapter = adapter_context()
    await adapter.session_attach(AttachSpec(backend=Backend.GDB, pid=55))
    async def hook(token, command):
        if command == "-target-detach":
            adapter._process.feed(f'{token}^error,msg="Access denied"\n'.encode())
            return True
    adapter._process.hook = hook
    with pytest.raises(DeaError) as exc:
        await adapter.session_terminate(TerminationPolicy.DETACH)
    assert exc.value.code is ErrorCode.DETACH_FAILED and adapter._process.closed


@pytest.mark.asyncio
async def test_missing_executable_and_unsupported_terminal(monkeypatch):
    monkeypatch.delenv("DEA_GDB", raising=False)
    monkeypatch.setattr("dea.adapters.gdb.adapter.shutil.which", lambda _: None)
    runtime, adapter = adapter_context()
    for io_mode in ("capture", "pty"):
        with pytest.raises(DeaError) as exc:
            await adapter.session_start(LaunchSpec(backend=Backend.GDB, binary_path="target", io_mode=io_mode))
        assert exc.value.code is ErrorCode.CAPABILITY_UNAVAILABLE
    assert not runtime.specs and not adapter.capabilities().available


def test_nul_is_never_accepted_as_protocol_argument():
    with pytest.raises(DeaError):
        quote("break\x00point")


@pytest.mark.asyncio
async def test_activation_identity_distinguishes_recursive_frames_and_raw_bytes(monkeypatch):
    monkeypatch.setattr("dea.adapters.gdb.adapter.shutil.which", lambda _: "gdb")
    _, adapter = adapter_context()
    try:
        await launch(adapter)
        pointer = "0x1000"
        async def hook(token, command):
            replies = {
                "-stack-info-frame": '^done,frame={level="0",func="recurse",addr="0x40"}',
                '-data-evaluate-expression "$sp"': f'^done,value="{pointer}"',
                "-stack-list-variables --all-values": r'^done,variables=[{name="x",value="\377"}]',
            }
            if command in replies:
                adapter._process.feed(f"{token}{replies[command]}\n".encode())
                return True
        adapter._process.hook = hook
        first = await adapter.state_inspect_frame(0, 1)
        same = await adapter.state_inspect_frame(0, 1)
        pointer = "0x0f00"
        nested = await adapter.state_inspect_frame(0, 1)
        assert first.identity == same.identity
        assert nested.identity != first.identity
        assert nested.variables[0].identity != first.variables[0].identity
        assert "<dea:bytes>" in first.variables[0].value
        assert first.model_dump_json()  # No invalid surrogate escapes at wire boundary.
        from dea.adapters.gdb.adapter import observation_text
        assert observation_text(first.variables[0].value) != first.variables[0].value
    finally:
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)


@pytest.mark.asyncio
async def test_requested_interrupt_normalization_and_single_event_reader():
    _, adapter = adapter_context()
    from dea.adapters.gdb.mi import parse_record
    events = adapter.events()
    waiting = asyncio.create_task(anext(events))
    await asyncio.sleep(0)
    with pytest.raises(DeaError) as exc:
        await anext(adapter.events())
    assert exc.value.code is ErrorCode.INVALID_STATE
    adapter._interrupt_requested = True
    adapter._record(parse_record('*stopped,reason="signal-received",signal-name="SIGINT"'))
    assert (await waiting).reason is StopReason.INTERRUPT
    assert not adapter._interrupt_requested
    adapter._record(parse_record('*stopped,reason="signal-received",signal-name="SIGINT"'))
    assert (await anext(events)).reason is StopReason.SIGNAL
    await events.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("reply,code", [
    ('^done,memory=[{begin="0x1000",contents="ff"}]', ErrorCode.INVALID_REQUEST),
    ('^done,memory=[{begin="0x1001",contents="ffff"}]', ErrorCode.PROTOCOL_ERROR),
    ('^done,memory=[{begin="0x1000",contents="ffffff"}]', ErrorCode.PROTOCOL_ERROR),
    ('^done,memory=[{begin="bad",contents="ffff"}]', ErrorCode.PROTOCOL_ERROR),
    ('^done,memory=[{begin="0x1000",contents="zzzz"}]', ErrorCode.PROTOCOL_ERROR),
    ('^done,memory=[{}]', ErrorCode.PROTOCOL_ERROR),
])
async def test_memory_capture_malformed_or_partial_is_never_padded(monkeypatch, reply, code):
    monkeypatch.setattr("dea.adapters.gdb.adapter.shutil.which", lambda _: "gdb")
    _, adapter = adapter_context()
    try:
        await launch(adapter)
        async def hook(token, command):
            if command.startswith("-data-read-memory-bytes"):
                adapter._process.feed(f'{token}{reply}\n'.encode())
                return True
        adapter._process.hook = hook
        with pytest.raises(DeaError) as exc:
            await adapter.state_read_memory(MemoryRegion(address=0x1000, size=2))
        assert exc.value.code is code
    finally:
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)


@pytest.mark.asyncio
async def test_command_deadline_also_covers_blocked_write(monkeypatch):
    monkeypatch.setattr("dea.adapters.gdb.adapter.shutil.which", lambda _: "gdb")
    _, adapter = adapter_context(command_seconds=1)
    try:
        await launch(adapter)
        original = adapter._process.write
        async def blocked(data):
            await asyncio.Event().wait()
        adapter._process.write = blocked
        with pytest.raises(DeaError) as exc:
            await adapter._command("-blocked")
        assert exc.value.code is ErrorCode.COMMAND_TIMEOUT and not adapter._pending
        adapter._process.write = original
    finally:
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)
