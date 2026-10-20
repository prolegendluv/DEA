import asyncio
from pathlib import Path

import pytest

from dea.bootstrap import ADAPTER_FACTORIES, build_application
from dea.contracts.adapter import AdapterContext, UnimplementedAdapter
from dea.contracts.models import Backend, DebuggerEvent, DeaError, ErrorCode, HelperMessage, LaunchSpec, ProcessSpec, RawMemoryDiff, RuntimeLimits, StopReason
from dea.contracts.ownership import WORK_PACKAGES, validate_ownership, worker_can_write
from tests.support.fakes import FakeAdapter, FakeClock, FakeHistory, FakeProcess, FakeProcessManager, SID


def context():
    return AdapterContext(SID, FakeProcessManager(), FakeHistory(), FakeClock(), RuntimeLimits())


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", tuple(Backend))
async def test_adapter_stubs_are_honest(backend):
    # Exercise the architect-owned scaffold, so these frozen tests also pass
    # after workers replace real adapter implementations independently.
    scaffold = type("Scaffold", (UnimplementedAdapter,), {"backend": backend})
    adapter = scaffold(context())
    assert not adapter.capabilities().available
    with pytest.raises(DeaError) as exc:
        await adapter.session_start(LaunchSpec(backend=backend, binary_path="not-a-real-target"))
    assert exc.value.code is ErrorCode.NOT_IMPLEMENTED
    with pytest.raises(DeaError) as exc:
        await anext(adapter.events())
    assert exc.value.code is ErrorCode.NOT_IMPLEMENTED


@pytest.mark.asyncio
async def test_memory_diff_delegates_to_injected_history():
    ctx = context()
    history = ctx.history
    history.result = RawMemoryDiff(session_id=SID, since_step_id=1, stop_id=2)
    adapter = FakeAdapter(ctx)
    assert await adapter.state_memory_diff(1) == history.result
    assert history.requests == [(SID, 1)]


@pytest.mark.asyncio
async def test_stop_can_precede_ack_without_being_lost():
    adapter = FakeAdapter(context())
    event = DebuggerEvent(event_id=1, kind="stopped", reason=StopReason.ENTRY)
    adapter.before_ack = event
    events = adapter.events()
    pending = asyncio.create_task(anext(events))
    ack = await adapter.session_start(LaunchSpec(backend=Backend.GDB, binary_path="fake"))
    assert await pending == event
    assert ack.accepted
    await events.aclose()


@pytest.mark.asyncio
async def test_fake_process_fragmentation_and_cleanup():
    runtime = FakeProcessManager()
    process = await runtime.spawn(ProcessSpec(argv=("fake",)))
    process.feed(b"1^do")
    process.feed(b"ne\n")
    process.feed(b"diagnostic", "stderr")
    await process.write(b"2-exec-continue\n")
    await process.interrupt()
    process.finish(7)
    chunks = [chunk async for chunk in process.read()]
    assert b"".join(c.data for c in chunks if c.stream == "stdout") == b"1^done\n"
    assert process.interrupts == 1
    assert await process.wait() == 7
    await runtime.close()
    await runtime.close()
    assert process.closed


@pytest.mark.asyncio
async def test_helper_control_is_separate_from_program_output():
    runtime = FakeProcessManager()
    process = await runtime.spawn(ProcessSpec(argv=("fake-helper",), helper_control=True))
    assert process.control is not None
    request = HelperMessage(kind="request", request_id=2, operation="execution_continue", body_json="{}")
    event = HelperMessage(kind="event", event_id=1, operation="debugger_event", body_json='{"kind":"running","event_id":1}')
    await process.control.send(request)
    process.control.feed(event)
    process.feed(b'not a control event: {"kind":"stopped"}')
    messages = process.control.messages()
    assert await anext(messages) == event
    assert process.control.sent == [request]
    await runtime.close()
    assert [chunk.data async for chunk in process.read()] == [b'not a control event: {"kind":"stopped"}']
    await messages.aclose()


def test_control_overflow_is_explicit():
    process = FakeProcess(capacity=1)
    process.feed(b"first")
    with pytest.raises(DeaError) as exc:
        process.feed(b"second")
    assert exc.value.code is ErrorCode.CONTROL_OVERFLOW


@pytest.mark.asyncio
async def test_manual_clock_controls_deadlines():
    clock = FakeClock()
    pending = asyncio.create_task(clock.sleep(5))
    await asyncio.sleep(0)
    clock.advance(4)
    assert not pending.done()
    clock.advance(1)
    await pending
    assert clock.now() == 5
    assert not clock.sleepers


def test_worker_ownership_has_no_overlap_and_protects_shared_files():
    validate_ownership()
    assert len(WORK_PACKAGES) == 8
    for package, roots in WORK_PACKAGES.items():
        for root in roots:
            assert worker_can_write(package, root + "/new_file.py")
        assert not worker_can_write(package, "src/dea/contracts/models.py")
        assert not worker_can_write(package, "src/dea/bootstrap.py")
        assert not worker_can_write(package, "tests/support/fakes.py")
    with pytest.raises(ValueError):
        worker_can_write(1, "src/dea/runtime/../contracts/models.py")
    with pytest.raises(ValueError):
        worker_can_write(1, "E:\\Projects\\stars\\src\\dea\\runtime\\x.py")
    assert not worker_can_write(1, "src/dea/runtime_lookalike/x.py")


def test_checked_in_schema_matches_contract():
    import json
    from dea.contracts.compact import CompactDebugState
    schema = Path(__file__).resolve().parents[2] / "schemas" / "compact-debug-state.schema.json"
    assert json.loads(schema.read_text(encoding="utf-8")) == CompactDebugState.model_json_schema(by_alias=True)


@pytest.mark.asyncio
async def test_bootstrap_imports_without_debuggers_and_closes():
    app = build_application()
    assert set(ADAPTER_FACTORIES) == set(Backend)
    assert app.runtime is not None and app.state is not None and app.sessions is not None
    await app.close()
    await app.close()

