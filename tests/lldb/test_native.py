"""Native smoke; absence is explicit and never replaced with an SB double."""
import asyncio
import sys

import pytest

from dea.adapters.lldb import LldbAdapter
from dea.adapters.lldb.discovery import discover
from dea.bootstrap import SystemClock
from dea.contracts.adapter import AdapterContext
from dea.contracts.models import Backend, CaptureRequest, LaunchSpec, RuntimeLimits, StopReason, TerminationPolicy
from dea.runtime import AsyncProcessManager
from tests.support.fakes import FakeHistory, SID


async def test_native_launch_register_capture_and_cleanup():
    interpreter = await asyncio.to_thread(discover)
    if interpreter is None:
        pytest.skip("LLDB Python bindings/compatible interpreter unavailable; native LLDB support unverified")
    limits = RuntimeLimits()
    runtime = AsyncProcessManager(limits)
    adapter = LldbAdapter(AdapterContext(SID, runtime, FakeHistory(), SystemClock(), limits))
    events = adapter.events()
    try:
        await adapter.session_start(LaunchSpec(backend=Backend.LLDB, binary_path=sys.executable,
                                               args=("-c", "value=42;print(value)")))
        async with asyncio.timeout(15):
            while True:
                event = await anext(events)
                if event.kind == "stopped": break
        snapshot = await adapter.snapshot_capture(CaptureRequest(stop_id=1, reason=StopReason.ENTRY, max_depth=0))
        assert snapshot.registers and snapshot.frames and snapshot.thread_id > 0
    finally:
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)
        await events.aclose()
        await runtime.close()
