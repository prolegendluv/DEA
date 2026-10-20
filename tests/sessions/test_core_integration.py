"""Exercise the real orchestration/state composition with a scripted adapter.

These tests intentionally do not claim debugger-adapter coverage. Native
process/PTY coverage belongs to the runtime suite.
"""
import asyncio
import json
import sys

import pytest

from dea.bootstrap import build_application
from dea.contracts.compact import CompactDebugState, ErrorResponse, InspectionPage
from dea.contracts.models import (
    Backend, BreakpointSpec, DebuggerEvent, DeaError, ErrorCode, LaunchSpec,
    MemoryRead, MemoryRegion, ProcessSpec, RawFrame, RawMemoryDiff, RawSnapshot, RawValue,
    RuntimeLimits, SourceLocation, StepMode, StopReason,
)
from tests.support.fakes import FakeAdapter, FakeProcessManager


class CoreAdapter(FakeAdapter):
    def __init__(self, context):
        super().__init__(context)
        self.value = 0
        self.steps = 0
        self.event_number = 0
        self.regions = ()

    def event(self, kind, reason=None):
        self.event_number += 1
        return DebuggerEvent(event_id=self.event_number, kind=kind, reason=reason)

    async def session_start(self, spec):
        self.regions = spec.memory_regions
        self.before_ack = self.event("stopped", StopReason.ENTRY)
        return await self._ack("start")

    async def execution_step(self, mode):
        self.steps += 1
        self.emit(self.event("running"))
        self.before_ack = self.event("stopped", StopReason.STEP)
        return await self._ack("step")

    async def execution_continue(self):
        self.value += 1
        self.emit(self.event("running"))
        self.before_ack = self.event("stopped", StopReason.BREAKPOINT)
        return await self._ack("continue")

    async def snapshot_capture(self, request):
        return RawSnapshot(
            session_id=self.context.session_id, stop_id=request.stop_id,
            thread_id=1, frame_context="thread:1/frame:main", reason=request.reason,
            location=SourceLocation(file="main.py", line=self.steps + 1),
            registers=(RawValue(identity="rip", name="rip", value=str(self.steps)),),
            variables=(RawValue(identity="main/count", name="count", value=str(self.value), watched=True),),
            memory=tuple(MemoryRead(region=region, data=bytes([self.value]) * region.size) for region in self.regions),
            registers_complete=True, variables_complete=True,
        )

    async def state_inspect_frame(self, frame_index, max_depth):
        return RawFrame(index=frame_index, identity="main", location=SourceLocation(file="main.py", line=1),
                        variables=(RawValue(identity="main/large", name="large", value="漢🪲" * 250),),
                        variables_complete=True)

    async def state_eval_expression(self, expr):
        self.value += 1
        return RawValue(identity="eval/result", name="result", value=str(self.value))


class ProcessBackedCoreAdapter(CoreAdapter):
    """A real owned child and scripted observations, not a debugger adapter."""
    async def session_start(self, spec):
        self.process = await self.context.runtime.spawn(ProcessSpec(argv=(
            sys.executable, "-u", "-c",
            "import time; print('core-ready', flush=True); time.sleep(60)",
        )))
        self.output = self.process.read()
        chunk = await asyncio.wait_for(anext(self.output), 5)
        assert b"core-ready" in chunk.data
        return await super().session_start(spec)

    async def session_terminate(self, policy):
        try:
            if hasattr(self, "process"):
                await self.process.close()
                await self.output.aclose()
        finally:
            await super().session_terminate(policy)


def make_application():
    app = build_application(runtime=FakeProcessManager())
    sessions = type(app.sessions)(app.runtime, app.state, {Backend.GDB: CoreAdapter},
                                  app.sessions.clock, RuntimeLimits())
    return app, sessions


async def next_stop(sessions, sid, after=0):
    for _ in range(20):
        response = await sessions.session_wait(sid, after, 1000)
        assert not isinstance(response, ErrorResponse), response
        if isinstance(response, CompactDebugState):
            return response
        after = response.event_id
    pytest.fail("No captured stop was published")


async def read_detail(sessions, guard, sid, page):
    assert isinstance(page, InspectionPage)
    offset = 0
    text = []
    object_id = page.object_id
    for _ in range(300):
        assert page.object_id == object_id
        assert page.offset == offset
        assert all(count <= 191 for _, count in guard.encode(page).token_counts)
        text.append(page.text)
        offset = page.next_offset
        if page.cursor_id is None:
            return "".join(text)
        cursor = page.cursor_id
        replay = await sessions.state_page(sid, cursor)
        assert replay == await sessions.state_page(sid, cursor)
        page = replay
    pytest.fail("Detail pagination failed to make bounded progress")


@pytest.mark.asyncio
async def test_real_state_and_sessions_pacing_memory_and_pagination():
    before = set(asyncio.all_tasks())
    app, sessions = make_application()
    try:
        ack = await sessions.session_start(LaunchSpec(
            backend=Backend.GDB, binary_path="scripted-adapter-only",
            memory_regions=(MemoryRegion(address=4096, size=4),),
        ))
        sid = ack.session_id
        stop = await next_stop(sessions, sid)
        baseline = stop.stop_id
        assert stop.base_stop_id is None
        await sessions.breakpoint_set(sid, BreakpointSpec(location="main.py:3"))
        for index in range(8):
            await sessions.execution_step(sid, StepMode.OVER)
            stop = await next_stop(sessions, sid, stop.event_id)
            assert all(count <= 191 for _, count in app.guard.encode(stop).token_counts)
            assert stop.hint == ("set_breakpoint" if index == 7 else None)

        detail = await sessions.state_inspect_frame(sid, 0, 1)
        reconstructed = json.loads(await read_detail(sessions, app.guard, sid, detail))
        assert reconstructed["variables"][0]["value"] == "漢🪲" * 250

        await sessions.execution_continue(sid)
        stop = await next_stop(sessions, sid, stop.event_id)
        assert stop.reason is StopReason.BREAKPOINT
        assert stop.hint is None
        memory_page = await sessions.state_memory_diff(sid, baseline)
        memory_json = await read_detail(sessions, app.guard, sid, memory_page)
        diff = RawMemoryDiff.model_validate_json(memory_json)
        assert diff.changes[0].address == 4096
        assert diff.changes[0].before == bytes(4)
        assert diff.changes[0].after == bytes([1]) * 4
        terminated = await sessions.session_terminate(sid)
        assert terminated == await sessions.session_terminate(sid)
    finally:
        await sessions.close()
        await app.close()
    await asyncio.sleep(0)
    leaked = [task for task in asyncio.all_tasks() - before if not task.done()]
    assert not leaked, leaked


@pytest.mark.asyncio
async def test_eval_recapture_resets_state_without_reusing_old_memory_baseline():
    app, sessions = make_application()
    try:
        ack = await sessions.session_start(LaunchSpec(
            backend=Backend.GDB, binary_path="scripted-adapter-only",
            memory_regions=(MemoryRegion(address=4096, size=4),),
        ))
        stop = await next_stop(sessions, ack.session_id)
        await sessions.state_eval_expression(ack.session_id, "increment")
        try:
            result = await sessions.state_memory_diff(ack.session_id, stop.stop_id)
        except DeaError as exc:
            assert exc.code is ErrorCode.HISTORY_UNAVAILABLE
        else:
            assert isinstance(result, ErrorResponse)
            assert result.code is ErrorCode.HISTORY_UNAVAILABLE
    finally:
        await sessions.close()
        await app.close()


@pytest.mark.asyncio
async def test_native_runtime_composes_with_real_sessions_and_state():
    app = build_application()
    sessions = type(app.sessions)(app.runtime, app.state,
        {Backend.GDB: ProcessBackedCoreAdapter}, app.sessions.clock, RuntimeLimits())
    try:
        ack = await sessions.session_start(LaunchSpec(backend=Backend.GDB, binary_path="scripted-owned-child"))
        stop = await next_stop(sessions, ack.session_id)
        assert all(count <= 191 for _, count in app.guard.encode(stop).token_counts)
        await sessions.execution_step(ack.session_id, StepMode.OVER)
        updated = await next_stop(sessions, ack.session_id, stop.event_id)
        assert updated.base_stop_id == stop.stop_id
        await sessions.session_terminate(ack.session_id)
    finally:
        await sessions.close()
        await app.close()
