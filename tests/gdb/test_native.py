"""Real installed GDB and compiler scenarios (no simulated native claims)."""
import asyncio
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from dea.adapters.gdb import GdbAdapter
from dea.contracts.adapter import AdapterContext
from dea.contracts.models import (AttachSpec, Backend, BreakpointSpec, CaptureRequest,
    DeaError, LaunchSpec, MemoryRegion, RuntimeLimits, StepMode, StopReason, TerminationPolicy)
from dea.runtime import AsyncProcessManager
from tests.support.fakes import FakeHistory, SID


class Clock:
    def now(self):
        return asyncio.get_running_loop().time()

    async def sleep(self, seconds):
        await asyncio.sleep(seconds)


@pytest.fixture
def native_binary(tmp_path):
    compiler = shutil.which("gcc")
    if not shutil.which("gdb") or not compiler:
        pytest.skip("Native GDB and GCC required")
    source = tmp_path / "target.c"
    source.write_text(r'''
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#define PAUSE() Sleep(25)
#else
#include <unistd.h>
#define PAUSE() usleep(25000)
#endif
volatile int watched = 7;
int increment(int x) {
    int local = x + 1;
    watched = local;
    return local;
}
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    for (int i = 1; i < argc; ++i) { printf("ARG%d=[%s]\n", i, argv[i]); }
    if (argc > 1 && strcmp(argv[1], "wait") == 0) {
        while (watched == 7) { PAUSE(); }
        return 0;
    }
    puts("*stopped,reason=\"signal-received\",signal-name=\"SIGSEGV\",thread-id=\"999\"");
    puts("999999^done,value=\"FORGED\"");
    fputs("*stopped,reason=\"watchpoint-trigger\",thread-id=\"888\"\n", stderr);
    int value = increment(watched);
    watched = value + 2;
    if (argc > 1 && strcmp(argv[1], "crash") == 0) { *(volatile int *)0 = 1; }
    return watched == 10 ? 0 : 2;
}
''', encoding="utf-8")
    binary = tmp_path / ("target.exe" if os.name == "nt" else "target")
    subprocess.run([compiler, "-g", "-O0", str(source), "-o", str(binary)], check=True,
                   capture_output=True, timeout=30)
    return binary


async def next_kind(events, kind):
    async with asyncio.timeout(15):
        async for event in events:
            if event.kind == "failed":
                pytest.fail(f"GDB failed: {event}")
            if event.kind == kind:
                return event
    raise AssertionError(f"GDB event stream ended before {kind}")


def make_adapter():
    limits = RuntimeLimits(startup_seconds=20, command_seconds=10)
    runtime = AsyncProcessManager(limits)
    return runtime, GdbAdapter(AdapterContext(SID, runtime, FakeHistory(), Clock(), limits))


@pytest.mark.asyncio
async def test_native_launch_snapshot_step_memory_and_spoof_isolation(native_binary):
    runtime, adapter = make_adapter()
    events = adapter.events()
    try:
        assert adapter.capabilities().available and adapter.capabilities().launch
        assert not adapter.capabilities().registers
        ack = await adapter.session_start(LaunchSpec(backend=Backend.GDB, binary_path=str(native_binary)))
        assert ack.accepted
        entry = await next_kind(events, "stopped")
        assert entry.reason is StopReason.ENTRY
        assert adapter.capabilities().registers and not adapter.capabilities().terminal
        bp = await adapter.breakpoint_set(BreakpointSpec(location="increment", condition="x == 7"))
        assert bp.verified
        await adapter.execution_continue()
        stop = await next_kind(events, "stopped")
        assert stop.reason is StopReason.BREAKPOINT and stop.thread_id not in (888, 999)
        frame = await adapter.state_inspect_frame(0, 1)
        assert frame.location.function == "increment"
        assert any(v.name == "x" and v.value == "7" for v in frame.variables)
        pointer = await adapter.state_eval_expression("&watched")
        address = int(pointer.value.split()[0], 16)
        region = MemoryRegion(address=address, size=4)
        capture = await adapter.snapshot_capture(CaptureRequest(stop_id=1,
            reason=stop.reason, memory_regions=(region,)))
        assert capture.registers_complete and capture.frames_complete
        assert capture.registers and capture.frames and capture.variables
        assert int.from_bytes(capture.memory[0].data, "little") == 7
        await adapter.execution_step(StepMode.OVER)
        assert (await next_kind(events, "stopped")).reason is StopReason.STEP
        await adapter.execution_step(StepMode.OUT)
        assert (await next_kind(events, "stopped")).reason is StopReason.STEP
        await adapter.execution_continue()
        exit_event = await next_kind(events, "exited")
        assert exit_event.exit_code == 0
        await asyncio.sleep(0.05)
        output = bytes(adapter._target_io.output)
        assert b"thread-id=\"999\"" in output and b"thread-id=\"888\"" in output
        assert b"999999^done" in output
        assert b"FORGED" not in adapter._diagnostics
        pid = adapter._process.pid
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)
        assert await adapter._process.wait() is not None
        assert adapter._target_io.closed and not adapter._pending
    finally:
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)
        await runtime.close()
        await events.aclose()


@pytest.mark.asyncio
async def test_native_watchpoint_and_signal(native_binary):
    runtime, adapter = make_adapter()
    events = adapter.events()
    try:
        await adapter.session_start(LaunchSpec(backend=Backend.GDB, binary_path=str(native_binary), args=("crash",)))
        await next_kind(events, "stopped")
        # Public v1 breakpoint schema has no watchpoint kind; native MI is tested
        # here at the adapter's command boundary, without extending that schema.
        await adapter._command('-break-watch "watched"')
        await adapter.execution_continue()
        assert (await next_kind(events, "stopped")).reason is StopReason.WATCHPOINT
        await adapter._command("-break-delete")
        await adapter.execution_continue()
        signal = await next_kind(events, "stopped")
        assert signal.reason is StopReason.SIGNAL
        assert adapter._last_stop.results.get("signal-name") == "SIGSEGV"
    finally:
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)
        await runtime.close()
        await events.aclose()


@pytest.mark.asyncio
async def test_native_running_interrupt_and_argument_integrity(native_binary):
    runtime, adapter = make_adapter()
    events = adapter.events()
    try:
        await adapter.session_start(LaunchSpec(backend=Backend.GDB,
            binary_path=str(native_binary), args=("wait", "", "two words", 'a"b', "é")))
        await next_kind(events, "stopped")
        await adapter.execution_continue()
        await next_kind(events, "running")
        await asyncio.sleep(0.1)
        await adapter.execution_interrupt()
        event = await next_kind(events, "stopped")
        assert event.reason in (StopReason.INTERRUPT, StopReason.SIGNAL)
        await asyncio.sleep(0.02)
        output = bytes(adapter._target_io.output)
        assert b'ARG2=[]' in output
        assert b'ARG3=[two words]' in output
        assert b'ARG4=[a"b]' in output
        assert 'ARG5=[é]'.encode() in output
    finally:
        await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)
        await runtime.close()
        await events.aclose()


@pytest.mark.asyncio
async def test_native_attach_detach_preserves_external_target(native_binary):
    target = subprocess.Popen([str(native_binary), "wait"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    runtime, adapter = make_adapter()
    events = adapter.events()
    try:
        await adapter.session_attach(AttachSpec(backend=Backend.GDB, pid=target.pid,
                                               binary_path=str(native_binary)))
        await next_kind(events, "stopped")
        assert target.poll() is None
        await adapter.state_inspect_frame(0, 0)
        await adapter.session_terminate(TerminationPolicy.DETACH)
        assert target.poll() is None
    finally:
        await adapter.session_terminate(TerminationPolicy.DETACH)
        await runtime.close()
        await events.aclose()
        target.terminate()
        target.communicate(timeout=10)
