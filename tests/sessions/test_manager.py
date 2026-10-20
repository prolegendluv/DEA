"""Deterministic session policy checks using only frozen injection boundaries."""
import asyncio
import contextlib

import pytest

from dea.contracts.compact import CompactDebugState, ErrorResponse, InspectionPage
from dea.contracts.models import (
    AttachSpec, Backend, DebuggerEvent, DeaError, ErrorCode, LaunchSpec,
    RawFrame, RawSnapshot, RawValue, RuntimeLimits, SessionPhase, SourceLocation,
    StepMode, StopReason, TerminationPolicy,
)
from dea.sessions import SessionManager
from tests.support.fakes import FakeAdapter, FakeClock, FakeProcessManager


class State:
    def __init__(self):
        self.records = []
        self.closed = []

    async def record(self, snapshot, event_id, hint=False):
        self.records.append((snapshot, hint))
        return CompactDebugState(session_id=snapshot.session_id, event_id=event_id,
                                 stop_id=snapshot.stop_id, reason=snapshot.reason,
                                 hint="set_breakpoint" if hint else None)

    async def close_session(self, sid):
        self.closed.append(sid)

    async def inspect(self, sid, stop, value_json):
        return InspectionPage(session_id=sid, stop_id=stop, object_id="0" * 16,
                              offset=0, next_offset=len(value_json), text=value_json)

    async def page(self, sid, cursor):
        raise DeaError(ErrorCode.CURSOR_EXPIRED)


class Adapter(FakeAdapter):
    def __init__(self, ctx):
        super().__init__(ctx)
        self.seq = 0
        self.value = "0"
        self.other = "0"
        self.reason = StopReason.STEP
        self.step_gate = None
        self.capture_gate = None
        self.fail_detach = False
        self.stop_on_interrupt = False
        self.block_start = False

    def stop(self, reason):
        self.seq += 1
        self.emit(DebuggerEvent(event_id=self.seq, kind="stopped", reason=reason))

    async def session_start(self, spec):
        if self.block_start:
            await asyncio.Event().wait()
        self.stop(StopReason.ENTRY)
        return await self._ack("start")

    async def session_attach(self, spec):
        return await self.session_start(spec)

    async def execution_step(self, mode):
        self.calls.append("step-enter")
        if self.step_gate is not None:
            await self.step_gate.wait()
        self.stop(self.reason)
        return await self._ack("step")

    async def execution_interrupt(self):
        if self.stop_on_interrupt:
            self.stop(StopReason.INTERRUPT)
        return await self._ack("interrupt")

    async def snapshot_capture(self, request):
        if self.capture_gate is not None:
            await self.capture_gate.wait()
        return RawSnapshot(session_id=self.context.session_id, stop_id=request.stop_id,
                           thread_id=1, frame_context="frame", reason=request.reason,
                           variables=(RawValue(identity="frame:x", name="x", value=self.value, watched=True),
                                      RawValue(identity="frame:y", name="y", value=self.other)),
                           registers=(RawValue(identity="pc", name="pc", value=str(request.stop_id)),))

    async def state_inspect_frame(self, frame_index, max_depth):
        return RawFrame(index=frame_index, identity="f", location=SourceLocation(function="main"))

    async def state_eval_expression(self, expr):
        self.value = expr
        return RawValue(identity="result", name="result", value=expr)

    async def session_terminate(self, policy):
        await super().session_terminate(policy)
        if self.fail_detach:
            raise RuntimeError("detach failed")


async def turns(n=15):
    for _ in range(n):
        await asyncio.sleep(0)


def setup(**limits):
    clock, state, adapters = FakeClock(), State(), []
    def factory(ctx):
        adapter = Adapter(ctx)
        adapters.append(adapter)
        return adapter
    manager = SessionManager(FakeProcessManager(), state, {Backend.GDB: factory}, clock,
                             RuntimeLimits(**limits))
    return manager, state, adapters, clock


async def start(manager):
    ack = await manager.session_start(LaunchSpec(backend=Backend.GDB, binary_path="fake"))
    await turns()
    return ack.session_id


async def latest(manager, sid):
    s = manager._get(sid)
    await turns()
    return await manager.session_wait(sid, s.eid - 1, 0)


async def test_immediate_stop_before_ack_is_captured_and_repeatable():
    manager, state, adapters, _ = setup()
    sid = await start(manager)
    first = await manager.session_wait(sid, 0, 0)
    assert isinstance(first, CompactDebugState)
    assert first == await manager.session_wait(sid, 0, 0)
    assert first.stop_id == 1 and state.records[0][0].reason is StopReason.ENTRY
    assert (await manager.state_inspect_frame(sid, 0, 1)).stop_id == 1
    await manager.close()
    assert adapters[0].termination_policy is TerminationPolicy.TERMINATE_OWNED


async def test_inspection_and_execution_wait_for_capture_barrier():
    manager, state, adapters, _ = setup()
    sid = await start(manager)
    adapter = adapters[0]
    adapter.capture_gate = asyncio.Event()
    adapter.stop(StopReason.BREAKPOINT)
    await turns()
    pending = asyncio.create_task(manager.execution_continue(sid))
    await turns()
    assert not pending.done() and "continue" not in adapter.calls
    adapter.capture_gate.set()
    await pending
    with pytest.raises(DeaError) as exc:
        await manager.state_inspect_frame(sid, 0, 1)
    assert exc.value.code is ErrorCode.INVALID_STATE
    await manager.close()


async def test_eight_steps_ignore_unwatched_and_pc_changes_reset_on_exact_watch():
    manager, state, adapters, _ = setup()
    sid = await start(manager)
    adapter = adapters[0]
    for index in range(10):
        adapter.other = str(index)
        await manager.execution_step(sid, StepMode.OVER)
        await turns()
        assert state.records[-1][1] == (index >= 7)
    adapter.value = "1"
    await manager.execution_step(sid, StepMode.OVER)
    await turns()
    assert not state.records[-1][1]
    adapter.reason = StopReason.BREAKPOINT
    await manager.execution_step(sid, StepMode.OVER)
    await turns()
    assert manager._get(sid).steps == 0
    await manager.close()


async def test_sessions_are_independent_and_execution_is_exclusive():
    manager, _, adapters, _ = setup()
    first, second = await start(manager), await start(manager)
    adapters[0].step_gate = asyncio.Event()
    pending = asyncio.create_task(manager.execution_step(first, StepMode.INTO))
    await turns()
    await manager.execution_step(second, StepMode.OVER)
    assert not pending.done()
    interrupt = await manager.execution_interrupt(first)
    assert interrupt.accepted and "interrupt" in adapters[0].calls
    other = asyncio.create_task(manager.execution_continue(first))
    await turns()
    assert "continue" not in adapters[0].calls
    adapters[0].step_gate.set()
    await pending
    await other
    await manager.close()


async def test_journal_eviction_is_gap_aware_and_poll_timeout_does_not_stop_target():
    manager, _, _, _ = setup(control_events=2)
    sid = await start(manager)
    for _ in range(3):
        await manager.execution_step(sid, StepMode.OUT)
        await turns()
    with pytest.raises(DeaError) as exc:
        await manager.session_wait(sid, 0, 0)
    assert exc.value.code is ErrorCode.HISTORY_UNAVAILABLE
    await manager.execution_continue(sid)
    result = await manager.session_wait(sid, manager._get(sid).eid, 0)
    assert result.code is ErrorCode.WAIT_TIMEOUT
    assert manager._get(sid).phase is SessionPhase.RUNNING
    await manager.close()


async def test_registry_never_evicts_active_then_evicts_oldest_terminal():
    manager, state, _, _ = setup(maximum_sessions=1)
    sid = await start(manager)
    with pytest.raises(DeaError) as exc:
        await start(manager)
    assert exc.value.code is ErrorCode.RESOURCE_LIMIT
    ack = await manager.session_terminate(sid)
    assert ack == await manager.session_terminate(sid)
    new_sid = await start(manager)
    assert new_sid != sid and sid in state.closed
    with pytest.raises(DeaError) as exc:
        await manager.session_capabilities(sid)
    assert exc.value.code is ErrorCode.SESSION_NOT_FOUND
    await manager.close()


async def test_attached_shutdown_detaches_and_failure_is_observable():
    manager, _, adapters, _ = setup()
    ack = await manager.session_attach(AttachSpec(backend=Backend.GDB, pid=123))
    await turns()
    adapters[0].fail_detach = True
    with pytest.raises(DeaError) as exc:
        await manager.session_terminate(ack.session_id)
    assert exc.value.code is ErrorCode.DETACH_FAILED
    assert adapters[0].termination_policy is TerminationPolicy.DETACH
    assert manager._get(ack.session_id).phase is SessionPhase.FAILED
    with pytest.raises(DeaError):
        await manager.close()


async def test_priority_termination_invalidates_late_ack_and_cleans_once():
    manager, _, adapters, _ = setup()
    sid = await start(manager)
    adapters[0].step_gate = asyncio.Event()
    pending = asyncio.create_task(manager.execution_step(sid, StepMode.OVER))
    await turns()
    await manager.session_terminate(sid)
    with pytest.raises(DeaError) as exc:
        await pending
    assert exc.value.code is ErrorCode.INVALID_STATE
    assert adapters[0].calls.count("terminate") == 1
    assert manager._get(sid).phase is SessionPhase.TERMINATED
    await manager.close()


async def test_command_timeout_recovers_only_after_new_captured_stop():
    manager, _, adapters, clock = setup(command_seconds=1)
    sid = await start(manager)
    adapters[0].step_gate = asyncio.Event()
    adapters[0].stop_on_interrupt = True
    pending = asyncio.create_task(manager.execution_step(sid, StepMode.OVER))
    await turns()
    clock.advance(1)
    await turns(50)
    with pytest.raises(DeaError) as exc:
        await pending
    assert exc.value.code is ErrorCode.COMMAND_TIMEOUT
    assert manager._get(sid).phase is SessionPhase.STOPPED
    assert manager._get(sid).ready.is_set()
    assert "interrupt" in adapters[0].calls
    adapters[0].step_gate = None
    await manager.execution_step(sid, StepMode.OVER)
    await turns()
    await manager.close()


async def test_wait_deadline_is_injected_and_does_not_mutate_execution():
    manager, _, _, clock = setup()
    sid = await start(manager)
    await manager.execution_continue(sid)
    pending = asyncio.create_task(manager.session_wait(sid, manager._get(sid).eid, 1000))
    await turns()
    clock.advance(1)
    assert (await pending).code is ErrorCode.WAIT_TIMEOUT
    assert manager._get(sid).phase is SessionPhase.RUNNING
    await manager.close()


async def test_exit_during_capture_cannot_publish_complete_stopped_state():
    manager, state, adapters, _ = setup()
    sid = await start(manager)
    adapter = adapters[0]
    adapter.capture_gate = asyncio.Event()
    adapter.stop(StopReason.STEP)
    await turns()
    adapter.seq += 1
    adapter.emit(DebuggerEvent(event_id=adapter.seq, kind="exited", exit_code=7))
    await turns(40)
    assert manager._get(sid).phase is SessionPhase.TERMINATED
    assert len(state.records) == 1
    terminal = await latest(manager, sid)
    assert terminal.exit_code == 7
    await manager.close()


async def test_evaluation_resets_history_and_recaptures_before_mutation():
    manager, state, _, _ = setup()
    sid = await start(manager)
    page = await manager.state_eval_expression(sid, "changed")
    assert page.stop_id == 2
    assert sid in state.closed
    assert len(state.records) == 2
    assert manager._get(sid).ready.is_set()
    await manager.close()


async def test_unexpected_stream_end_fails_session():
    manager, _, adapters, _ = setup()
    sid = await start(manager)
    await adapters[0].event_queue.put(None)
    await turns(40)
    assert manager._get(sid).phase is SessionPhase.FAILED
    assert isinstance(await latest(manager, sid), ErrorResponse)
    await manager.close()

async def test_startup_timeout_fails_and_terminates_owned_adapter():
    manager, _, adapters, clock = setup(startup_seconds=1)
    original = manager.adapters[Backend.GDB]
    def blocked(ctx):
        adapter = original(ctx)
        adapter.block_start = True
        return adapter
    manager.adapters = {Backend.GDB: blocked}
    pending = asyncio.create_task(start(manager))
    await turns()
    clock.advance(1)
    await turns(40)
    with pytest.raises(DeaError) as exc:
        await pending
    assert exc.value.code is ErrorCode.STARTUP_TIMEOUT
    assert adapters[0].termination_policy is TerminationPolicy.TERMINATE_OWNED
    assert next(iter(manager._sessions.values())).phase is SessionPhase.FAILED
    await manager.close()


async def test_recovery_without_stop_fails_after_second_deadline():
    manager, _, adapters, clock = setup(command_seconds=1)
    sid = await start(manager)
    adapters[0].step_gate = asyncio.Event()
    pending = asyncio.create_task(manager.execution_step(sid, StepMode.INTO))
    await turns()
    clock.advance(1)
    await turns(30)
    clock.advance(1)
    await turns(40)
    with pytest.raises(DeaError) as exc:
        await pending
    assert exc.value.code is ErrorCode.COMMAND_TIMEOUT
    assert manager._get(sid).phase is SessionPhase.FAILED
    assert "terminate" in adapters[0].calls
    await manager.close()


async def test_cancelled_termination_finishes_and_concurrent_call_reuses_ack():
    manager, _, adapters, _ = setup()
    sid = await start(manager)
    adapter = adapters[0]
    original = adapter.session_terminate
    gate = asyncio.Event()
    async def delayed(policy):
        await gate.wait()
        await original(policy)
    adapter.session_terminate = delayed
    pending = asyncio.create_task(manager.session_terminate(sid))
    await turns()
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    retry = asyncio.create_task(manager.session_terminate(sid))
    gate.set()
    ack = await retry
    assert ack == await manager.session_terminate(sid)
    assert adapter.calls.count("terminate") == 1
    await manager.close()


async def test_repeated_source_event_id_is_protocol_failure():
    manager, _, adapters, _ = setup()
    sid = await start(manager)
    adapters[0].emit(DebuggerEvent(event_id=1, kind="running"))
    await turns(40)
    assert manager._get(sid).phase is SessionPhase.FAILED
    assert (await latest(manager, sid)).code is ErrorCode.PROTOCOL_ERROR
    await manager.close()


async def test_waiting_evicted_session_wakes_with_not_found():
    manager, _, _, _ = setup(maximum_sessions=1)
    sid = await start(manager)
    await manager.session_terminate(sid)
    pending = asyncio.create_task(manager.session_wait(sid, manager._get(sid).eid, 1000))
    await turns()
    await start(manager)
    with pytest.raises(DeaError) as exc:
        await pending
    assert exc.value.code is ErrorCode.SESSION_NOT_FOUND
    await manager.close()


async def test_closed_manager_rejects_new_sessions():
    manager, _, _, _ = setup()
    await manager.close()
    await manager.close()
    with pytest.raises(DeaError) as exc:
        await start(manager)
    assert exc.value.code is ErrorCode.INVALID_STATE

async def test_inspection_timeout_cannot_recover_from_old_ready_barrier():
    manager, _, adapters, clock = setup(command_seconds=1)
    sid = await start(manager)
    async def blocked(frame_index, max_depth):
        await asyncio.Event().wait()
    adapters[0].state_inspect_frame = blocked
    pending = asyncio.create_task(manager.state_inspect_frame(sid, 0, 1))
    await turns()
    clock.advance(1)
    await turns(30)
    assert not pending.done()
    assert not manager._get(sid).ready.is_set()
    clock.advance(1)
    await turns(40)
    with pytest.raises(DeaError) as exc:
        await pending
    assert exc.value.code is ErrorCode.COMMAND_TIMEOUT
    assert manager._get(sid).phase is SessionPhase.FAILED
    await manager.close()

@pytest.mark.parametrize("complete,expected_hint", [(False, False), (True, True)])
async def test_partial_capture_preserves_exact_watch_baseline_until_proven_removed(complete, expected_hint):
    manager, state, adapters, _ = setup()
    sid = await start(manager)
    adapter = adapters[0]
    original = adapter.snapshot_capture
    for _ in range(7):
        await manager.execution_step(sid, StepMode.OVER)
        await turns()
    async def missing(request):
        snapshot = await original(request)
        return snapshot.model_copy(update={"variables": (), "variables_complete": complete})
    adapter.snapshot_capture = missing
    await manager.execution_step(sid, StepMode.OVER)
    await turns()
    assert state.records[-1][1]
    adapter.snapshot_capture = original
    adapter.value = "1"
    await manager.execution_step(sid, StepMode.OVER)
    await turns()
    assert state.records[-1][1] == expected_hint
    await manager.close()


async def test_scope_switch_discards_old_watch_values_without_resetting_pacing():
    manager, state, adapters, _ = setup()
    sid = await start(manager)
    adapter = adapters[0]
    original = adapter.snapshot_capture
    for _ in range(7):
        await manager.execution_step(sid, StepMode.OVER)
        await turns()
    async def other_scope(request):
        snapshot = await original(request)
        return snapshot.model_copy(update={"frame_context": "different_frame"})
    adapter.snapshot_capture = other_scope
    adapter.value = "1"
    await manager.execution_step(sid, StepMode.OVER)
    await turns()
    assert state.records[-1][1]
    await manager.close()

async def test_unavailable_adapter_is_capability_failure_without_guessing_implementation_status():
    from dea.contracts.models import AdapterCapabilities
    manager, _, _, _ = setup()
    original = manager.adapters[Backend.GDB]
    def unavailable(context):
        adapter = original(context)
        adapter.capabilities = lambda: AdapterCapabilities(backend=Backend.GDB)
        return adapter
    manager.adapters = {Backend.GDB: unavailable}
    with pytest.raises(DeaError) as exc:
        await start(manager)
    assert exc.value.code is ErrorCode.CAPABILITY_UNAVAILABLE
    assert not manager._sessions
    await manager.close()
