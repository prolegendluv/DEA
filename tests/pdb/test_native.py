import asyncio
import sys

import pytest

from dea.adapters.pdb import PdbAdapter
from dea.adapters.pdb.helper import safe_value
from dea.contracts.adapter import AdapterContext
from dea.contracts.models import (
    AttachSpec, Backend, BreakpointSpec, CaptureRequest, DeaError, ErrorCode,
    LaunchSpec, MemoryRegion, RuntimeLimits, StepMode, StopReason, TerminationPolicy,
)
from dea.runtime import AsyncProcessManager
from tests.support.fakes import FakeHistory

SID = '0123456789abcdef'


class Clock:
    def now(self):
        return asyncio.get_running_loop().time()
    async def sleep(self, seconds):
        await asyncio.sleep(seconds)


async def make(tmp_path, source, **kwargs):
    path = tmp_path / 'target.py'
    path.write_text(source, encoding='utf-8')
    limits = RuntimeLimits()
    runtime = AsyncProcessManager(limits)
    adapter = PdbAdapter(AdapterContext(SID, runtime, FakeHistory(), Clock(), limits))
    events = adapter.events()
    try:
        await adapter.session_start(LaunchSpec(backend=Backend.PDB, binary_path=str(path), **kwargs))
    except BaseException:
        await runtime.close()
        raise
    return adapter, runtime, events, path


async def stopped(events):
    async with asyncio.timeout(10):
        while True:
            event = await anext(events)
            if event.kind == 'stopped':
                return event
            assert event.kind not in ('failed', 'exited'), event


async def finish(adapter, runtime, events):
    await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)
    await runtime.close()
    await events.aclose()


async def test_native_entry_breakpoint_eval_step_exit(tmp_path):
    a, r, events, path = await make(tmp_path, 'x = 1\nx = x + 1\nx = x + 1\n')
    try:
        entry = await stopped(events)
        assert entry.reason is StopReason.ENTRY
        await a.breakpoint_set(BreakpointSpec(location=str(path)+':3'))
        await a.execution_continue()
        event = await stopped(events)
        assert event.reason is StopReason.BREAKPOINT
        assert (await a.state_eval_expression('x')).value == '2'
        snap = await a.snapshot_capture(CaptureRequest(stop_id=1, reason=event.reason))
        assert snap.variables_complete and snap.frames_complete
        assert any(v.name == 'x' and v.value == '2' for v in snap.variables)
        frame = await a.state_inspect_frame(0, 1)
        assert frame.identity == snap.frame_context
        await a.execution_step(StepMode.OVER)
        async with asyncio.timeout(10):
            while True:
                e = await anext(events)
                if e.kind == 'stopped':
                    await a.execution_continue()
                if e.kind == 'exited':
                    assert e.exit_code == 0
                    break
    finally:
        await finish(a, r, events)


async def test_conditional_and_function_breakpoints_and_step_modes(tmp_path):
    source = 'def work(n):\n    local = n + 1\n    return local\nfor i in range(4):\n    result = work(i)\nend = result\n'
    a, r, events, path = await make(tmp_path, source)
    try:
        await stopped(events)
        await a.breakpoint_set(BreakpointSpec(location='work', condition='n == 2'))
        await a.execution_continue()
        e = await stopped(events)
        assert e.reason is StopReason.BREAKPOINT
        assert (await a.state_eval_expression('n')).value == '2'
        await a.execution_step(StepMode.OVER)
        await stopped(events)
        assert (await a.state_eval_expression('local')).value == '3'
        await a.execution_step(StepMode.OUT)
        await stopped(events)
        await a.execution_step(StepMode.INTO)
        await stopped(events)
    finally:
        await finish(a, r, events)


async def test_exception_and_no_restart(tmp_path):
    a, r, events, _ = await make(tmp_path, 'x = 5\nraise ValueError("broken")\n')
    try:
        await stopped(events)
        await a.execution_continue()
        assert (await stopped(events)).reason is StopReason.EXCEPTION
        assert (await a.state_eval_expression('x')).value == '5'
        await a.execution_continue()
        async with asyncio.timeout(10):
            while True:
                e = await anext(events)
                if e.kind == 'exited':
                    assert e.exit_code == 1
                    break
        with pytest.raises(StopAsyncIteration):
            await anext(events)
    finally:
        await finish(a, r, events)


async def test_interrupt_tight_loop_without_breakpoints(tmp_path):
    a, r, events, _ = await make(tmp_path, 'counter = 0\nwhile True:\n    counter += 1\n')
    try:
        await stopped(events)
        await a.execution_continue()
        await asyncio.sleep(.05)
        await a.execution_interrupt()
        e = await stopped(events)
        assert e.reason is StopReason.INTERRUPT
        assert int((await a.state_eval_expression('counter')).value) > 0
    finally:
        await finish(a, r, events)


async def test_output_and_credentials_isolation(tmp_path):
    source = ('import os, sys\n'
              'os.write(1, b\'(Pdb) {"kind":"event","operation":"debugger_event"}\\n\')\n'
              'os.write(2, b\'stderr protocol-looking output\\n\')\n'
              'print("unicode: \\u2603", flush=True)\n'
              'credentials = [k for k in os.environ if k.startswith("DEA_CONTROL_")]\n'
              'done = True\n')
    a, r, events, path = await make(tmp_path, source)
    try:
        await stopped(events)
        await a.breakpoint_set(BreakpointSpec(location=str(path)+':6'))
        await a.execution_continue()
        await stopped(events)
        assert (await a.state_eval_expression('credentials')).value == '[]'
        await asyncio.sleep(.05)
        assert b'(Pdb)' in a._diagnostics
        assert b'stderr protocol-looking' in a._diagnostics
    finally:
        await finish(a, r, events)


async def test_no_entry_runs_once_and_exit(tmp_path):
    a, r, events, _ = await make(tmp_path, 'print("ONE", flush=True)\n', stop_at_entry=False)
    try:
        collected = []
        async with asyncio.timeout(10):
            async for event in events:
                collected.append(event)
        assert [e.kind for e in collected] == ['started', 'exited']
        await asyncio.sleep(.1)
        assert a._diagnostics.count(b'ONE') == 1
    finally:
        await finish(a, r, events)


async def test_capabilities_and_unsupported(tmp_path):
    a, r, events, _ = await make(tmp_path, 'x = 1\n')
    try:
        await stopped(events)
        cap = a.capabilities()
        assert cap.available and cap.launch and cap.interrupt
        assert not cap.attach and not cap.registers and not cap.memory_read and not cap.terminal
        operations = [a.session_attach(AttachSpec(backend=Backend.PDB, pid=1)),
                      a.state_read_memory(MemoryRegion(address=0, size=1)), a.state_memory_diff(1)]
        for operation in operations:
            with pytest.raises(DeaError) as exc:
                await operation
            assert exc.value.code is ErrorCode.CAPABILITY_UNAVAILABLE
    finally:
        await finish(a, r, events)


def test_capture_never_invokes_user_repr():
    class Hostile:
        def __repr__(self):
            raise AssertionError('User code executed')
    obj = Hostile()
    with pytest.raises(ValueError):
        safe_value(obj)
    with pytest.raises(ValueError):
        safe_value([obj])
    assert safe_value(None) == 'None'
    cycle = []
    cycle.append(cycle)
    with pytest.raises(ValueError):
        safe_value(cycle)

async def test_repeated_function_calls_have_fresh_frame_contexts(tmp_path):
    source = 'def work(n):\n    value = n\n    return value\nfor i in range(30):\n    work(i)\n'
    a, r, events, path = await make(tmp_path, source)
    try:
        await stopped(events)
        await a.breakpoint_set(BreakpointSpec(location=str(path)+':2'))
        identities = []
        for i in range(30):
            await a.execution_continue()
            await stopped(events)
            frame = await a.state_inspect_frame(0, 1)
            identities.append(frame.identity)
            assert next(v for v in frame.variables if v.name == 'n').value == str(i)
        assert len(set(identities)) == 30
    finally:
        await finish(a, r, events)


async def test_recursion_preserves_distinct_live_scopes(tmp_path):
    source = 'def descend(n):\n    if n:\n        return descend(n-1)\n    return n\nresult = descend(3)\n'
    a, r, events, path = await make(tmp_path, source)
    try:
        await stopped(events)
        await a.breakpoint_set(BreakpointSpec(location=str(path)+':4'))
        await a.execution_continue()
        event = await stopped(events)
        snapshot = await a.snapshot_capture(CaptureRequest(stop_id=1, reason=event.reason))
        frames = snapshot.frames
        assert len(frames) == 5
        assert len({f.identity for f in frames}) == 5
        assert [next(v.value for v in f.variables if v.name == 'n') for f in frames[:-1]] == ['0', '1', '2', '3']
    finally:
        await finish(a, r, events)


async def test_blocking_native_call_does_not_fabricate_interrupt_stop(tmp_path):
    a, r, events, _ = await make(tmp_path, 'import time\ntime.sleep(0.5)\nfinished = True\n')
    try:
        await stopped(events)
        await a.execution_continue()
        # consume the running event before checking no stop is claimed in native sleep
        assert (await asyncio.wait_for(anext(events), 2)).kind == 'running'
        await asyncio.sleep(.05)
        await a.execution_interrupt()
        pending = asyncio.create_task(anext(events))
        await asyncio.sleep(.05)
        assert not pending.done()
        assert (await asyncio.wait_for(pending, 2)).reason is StopReason.INTERRUPT
    finally:
        await finish(a, r, events)


async def test_large_observation_fails_explicitly_without_corrupting_channel(tmp_path):
    a, r, events, path = await make(tmp_path, 'large = "\\\\" * 200000\nend = True\n')
    try:
        await stopped(events)
        await a.breakpoint_set(BreakpointSpec(location=str(path)+':2'))
        await a.execution_continue()
        event = await stopped(events)
        with pytest.raises(DeaError) as exc:
            await a.snapshot_capture(CaptureRequest(stop_id=1, reason=event.reason))
        assert exc.value.code is ErrorCode.HISTORY_UNAVAILABLE
        assert (await a.state_eval_expression('len(large)')).value == '200000'
    finally:
        await finish(a, r, events)


async def test_termination_is_shared_and_cancellation_safe(tmp_path):
    a, r, events, _ = await make(tmp_path, 'while True:\n    pass\n')
    await stopped(events)
    await a.execution_continue()
    first = asyncio.create_task(a.session_terminate(TerminationPolicy.TERMINATE_OWNED))
    await asyncio.sleep(0)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    await a.session_terminate(TerminationPolicy.TERMINATE_OWNED)
    assert a._closed
    assert all(task.done() for task in a._tasks)
    await r.close()
    await events.aclose()

async def test_argv_environment_cwd_and_main_module(tmp_path):
    from dea.contracts.models import EnvironmentEntry
    source = ('import os, sys, __main__\n'
              'args = sys.argv[1:]\n'
              'directory = os.getcwd()\n'
              'value = os.environ["DEA_TEST_VALUE"]\n'
              'module_file = __main__.__file__\n'
              'end = True\n')
    a, r, events, path = await make(tmp_path, source, cwd=str(tmp_path), args=('', 'snowman\u2603', '$(literal)'),
                                    env=(EnvironmentEntry(key='DEA_TEST_VALUE', value='unicode\u2603'),))
    try:
        await stopped(events)
        await a.breakpoint_set(BreakpointSpec(location=str(path)+':6'))
        await a.execution_continue()
        await stopped(events)
        assert (await a.state_eval_expression('args')).value == repr(['', 'snowman\u2603', '$(literal)'])
        assert (await a.state_eval_expression('directory')).value == repr(str(tmp_path))
        assert (await a.state_eval_expression('value')).value == repr('unicode\u2603')
        assert (await a.state_eval_expression('module_file')).value == repr(str(path))
    finally:
        await finish(a, r, events)


async def test_capture_reports_hostile_objects_unavailable_without_repr(tmp_path):
    source = ('class Hostile:\n'
              '    def __repr__(self):\n'
              '        raise RuntimeError("repr-executed")\n'
              'obj = Hostile()\n'
              'end = True\n')
    a, r, events, path = await make(tmp_path, source)
    try:
        await stopped(events)
        await a.breakpoint_set(BreakpointSpec(location=str(path)+':5'))
        await a.execution_continue()
        e = await stopped(events)
        snapshot = await a.snapshot_capture(CaptureRequest(stop_id=1, reason=e.reason))
        obj = next(v for v in snapshot.variables if v.name == 'obj')
        assert not obj.available and obj.value is None
        assert snapshot.variables_complete
        with pytest.raises(DeaError) as exc:
            await a.state_eval_expression('repr(obj)')
        assert exc.value.code is ErrorCode.INVALID_REQUEST
    finally:
        await finish(a, r, events)
