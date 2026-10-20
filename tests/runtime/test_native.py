"""Real native process tests. Windows core tests run, rather than using mocks."""
import asyncio
import ctypes
import json
import os
from pathlib import Path
import signal
import sys
import threading

import pytest

from dea.contracts.models import DeaError, EnvironmentEntry, HelperMessage, ProcessSpec, RuntimeLimits
from dea.runtime import AsyncProcessManager
from dea.runtime.manager import build_environment

HELPER = str(Path(__file__).with_name("helper_child.py").resolve())


async def collect(process):
    return [chunk async for chunk in process.read()]


async def child(code, *, limits=None, transport="pipes"):
    manager = AsyncProcessManager(limits or RuntimeLimits())
    process = await manager.spawn(ProcessSpec(argv=(sys.executable, "-u", "-c", code), transport=transport))
    return manager, process


def alive(pid):
    if os.name == "nt":
        from dea.runtime.windows import k, WaitForSingleObject, CloseHandle
        k.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        k.OpenProcess.restype = ctypes.c_void_p
        handle = k.OpenProcess(0x100000, False, pid)
        if not handle:
            return False
        try:
            return WaitForSingleObject(handle, 0) == 258
        finally:
            CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def no_workers(process):
    if os.name == "nt":
        assert process._handles_closed
        assert not any(worker.is_alive() for worker in process._threads)


async def test_native_pipe_roundtrip_unicode_empty_arguments_cwd_env(tmp_path):
    manager = AsyncProcessManager(RuntimeLimits())
    code = ("import os,sys,json; print(json.dumps([sys.argv[1:],os.getcwd(),os.environ['DEA_TEST_VAR']],"
            "ensure_ascii=False)); print(sys.stdin.buffer.readline().decode('utf-8'),end='');"
            " print('DIAGNOSTIC',file=sys.stderr)")
    process = await manager.spawn(ProcessSpec(argv=(sys.executable,"-u","-c",code,"","水 🍇"),
        cwd=str(tmp_path),env=(EnvironmentEntry(key="DEA_TEST_VAR",value="unicode 水"),)))
    reading = asyncio.create_task(collect(process))
    await process.write("echo é 水\n".encode())
    assert await asyncio.wait_for(process.wait(),5) == 0
    chunks = await asyncio.wait_for(reading,5)
    stdout = b"".join(c.data for c in chunks if c.stream=="stdout").decode()
    assert json.loads(stdout.splitlines()[0]) == [["","水 🍇"],str(tmp_path),"unicode 水"]
    assert "echo é 水" in stdout
    assert b"DIAGNOSTIC" in b"".join(c.data for c in chunks if c.stream=="stderr")
    assert sum(c.eof for c in chunks) == 2
    if os.name == "nt":
        assert process.assigned_before_resume
    await manager.close()
    no_workers(process)


async def test_concurrent_stdout_stderr_flood_keeps_event_loop_responsive():
    limits = RuntimeLimits(control_events=4096, diagnostic_bytes=8192)
    manager, process = await child(
        "import os,threading; "
        "t=threading.Thread(target=lambda:[os.write(2,b'e'*4096) for _ in range(512)]);"
        "t.start(); [os.write(1,b'o'*4096) for _ in range(512)];t.join()", limits=limits)
    ticks = 0
    finished = asyncio.Event()
    async def heartbeat():
        nonlocal ticks
        while not finished.is_set():
            ticks += 1
            await asyncio.sleep(.001)
    beat = asyncio.create_task(heartbeat())
    # Stall the consumer while both native channels flood.
    await asyncio.wait_for(process.wait(),10)
    chunks = await asyncio.wait_for(collect(process),5)
    finished.set()
    await beat
    assert ticks > 2
    assert sum(len(c.data) for c in chunks if c.stream=="stdout") == 2*1024*1024
    assert sum(len(c.data) for c in chunks if c.stream=="stderr") <= 8192
    assert process.diagnostic_loss > 0
    await manager.close()
    no_workers(process)


async def test_control_overflow_fails_and_cleans_owned_tree():
    manager, process = await child("import os,time; [os.write(1,b'x'*65536) for _ in range(1000)];time.sleep(30)",
                                   limits=RuntimeLimits(control_events=1))
    try:
        async def failed():
            while not process._failure:
                await asyncio.sleep(.005)
        await asyncio.wait_for(failed(),5)
        assert process._failure.code.value == "CONTROL_OVERFLOW"
        with pytest.raises(DeaError,match="CONTROL_OVERFLOW"):
            await anext(process.read())
        await asyncio.wait_for(process.close(),5)
        assert not alive(process.pid)
        no_workers(process)
    finally:
        await manager.close()


async def test_blocked_write_cancellation_cleans_workers_and_keeps_heartbeat():
    manager, process = await child("import time;time.sleep(30)")
    writer = asyncio.create_task(process.write(b"x"*1_048_576))
    for _ in range(20):
        await asyncio.sleep(.002)
    assert not writer.done()
    writer.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(writer,5)
    await manager.close()
    assert not alive(process.pid)
    no_workers(process)


async def test_close_is_idempotent_concurrent_and_cancellation_safe():
    manager, process = await child("import time;time.sleep(30)")
    closer = asyncio.create_task(process.close())
    await asyncio.sleep(0)
    closer.cancel()
    with pytest.raises(asyncio.CancelledError):
        await closer
    await asyncio.gather(process.close(),process.close(),manager.close(),manager.close())
    assert not alive(process.pid)
    no_workers(process)


async def test_child_descendants_are_contained_even_if_leader_exits():
    manager, process = await child(
        "import subprocess,sys; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
        "print(p.pid,flush=True)")
    iterator = process.read()
    data = b""
    while b"\n" not in data:
        data += (await asyncio.wait_for(anext(iterator),5)).data
    descendant = int(data.strip())
    assert alive(descendant)
    assert await asyncio.wait_for(process.wait(),5) == 0
    await manager.close()
    assert not alive(descendant)
    no_workers(process)


async def test_one_reader_and_no_operations_after_close():
    manager, process = await child("print('ready');import time;time.sleep(30)")
    iterator = process.read()
    await asyncio.wait_for(anext(iterator),5)
    with pytest.raises(DeaError,match="INVALID_STATE"):
        await anext(process.read())
    await manager.close()
    with pytest.raises(DeaError,match="INVALID_STATE"):
        await process.write(b"x")
    with pytest.raises(DeaError,match="INVALID_STATE"):
        await process.interrupt()


async def test_repeated_spawn_close_deregisters_native_resources():
    manager = AsyncProcessManager(RuntimeLimits(maximum_sessions=1))
    for _ in range(12):
        process = await manager.spawn(ProcessSpec(argv=(sys.executable,"-c","pass")))
        await asyncio.wait_for(process.wait(),5)
        await process.close()
        assert len(manager._processes)==0
        no_workers(process)
    await manager.close()
    with pytest.raises(DeaError,match="INVALID_STATE"):
        await manager.spawn(ProcessSpec(argv=(sys.executable,"-c","pass")))


async def test_active_process_limit_and_failed_spawn_cleanup():
    manager = AsyncProcessManager(RuntimeLimits(maximum_sessions=1))
    with pytest.raises(DeaError,match="CAPABILITY_UNAVAILABLE"):
        await manager.spawn(ProcessSpec(argv=("dea-does-not-exist-02834293",)))
    assert not manager._processes
    process = await manager.spawn(ProcessSpec(argv=(sys.executable,"-c","import time;time.sleep(30)")))
    with pytest.raises(DeaError,match="RESOURCE_LIMIT"):
        await manager.spawn(ProcessSpec(argv=(sys.executable,"-c","pass")))
    await manager.close()
    no_workers(process)


@pytest.mark.parametrize("transport",["pipes","pty"])
async def test_cancel_spawn_never_loses_native_process(transport):
    manager = AsyncProcessManager(RuntimeLimits())
    task = asyncio.create_task(manager.spawn(ProcessSpec(
        argv=(sys.executable,"-c","import time;time.sleep(30)"),transport=transport)))
    await asyncio.sleep(.001)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task,10)
    await manager.close()
    assert not manager._processes


async def test_native_terminal_roundtrip_and_clean_exit():
    manager, process = await child(
        "import sys;print('PTY_READY',flush=True);x=input();print('PTY_REPLY:'+x,flush=True)",
        transport="pty")
    output = bytearray()
    async def reader():
        async for chunk in process.read():
            assert chunk.stream=="terminal"
            output.extend(chunk.data)
    reading = asyncio.create_task(reader())
    async def ready():
        while b"PTY_READY" not in output:
            await asyncio.sleep(.005)
    try:
        await asyncio.wait_for(ready(),5)
        await process.write(b"terminal-input\r\n")
        assert await asyncio.wait_for(process.wait(),5) == 0
        await asyncio.wait_for(reading,5)
        assert b"PTY_REPLY:terminal-input" in output
    finally:
        await manager.close()
    no_workers(process)


async def test_native_terminal_flood_close_does_not_deadlock():
    manager, process = await child(
        "import os;[os.write(1,b'terminal-flood'*1024) for _ in range(100000)]",
        transport="pty", limits=RuntimeLimits(diagnostic_bytes=4096))
    await asyncio.sleep(.1)
    await asyncio.wait_for(manager.close(),8)
    assert not alive(process.pid)
    no_workers(process)


async def test_native_interrupt_is_honest():
    manager, process = await child("import time;time.sleep(30)")
    try:
        if os.name == "nt":
            with pytest.raises(DeaError,match="CAPABILITY_UNAVAILABLE"):
                await process.interrupt()
            assert alive(process.pid)
        else:
            await process.interrupt()
            assert await asyncio.wait_for(process.wait(),5) != 0
    finally:
        await manager.close()


def test_environment_credentials_removed_and_duplicate_overrides_rejected(monkeypatch):
    monkeypatch.setenv("DEA_CONTROL_TOKEN","SECRET")
    env=build_environment(ProcessSpec(argv=("python",)))
    assert "DEA_CONTROL_TOKEN" not in env
    with pytest.raises(DeaError,match="INVALID_REQUEST"):
        build_environment(ProcessSpec(argv=("python",),env=(EnvironmentEntry(key="DEA_CONTROL_HOST",value="bad"),)))
    overrides=(EnvironmentEntry(key="DEA_TEST",value="a"), EnvironmentEntry(key="dea_test",value="b"))
    if os.name=="nt":
        with pytest.raises(DeaError,match="INVALID_REQUEST"):
            build_environment(ProcessSpec(argv=("python",),env=overrides))


async def test_real_authenticated_helper_roundtrip_and_target_output_separation():
    manager=AsyncProcessManager(RuntimeLimits())
    process=await manager.spawn(ProcessSpec(argv=(sys.executable,"-u",HELPER,"echo"),helper_control=True))
    try:
        assert process.control is not None
        await process.control.send(HelperMessage(kind="request",request_id=2,
            operation="execution_continue",body_json="{}"))
        message=await asyncio.wait_for(anext(process.control.messages()),5)
        assert message.kind=="response" and message.request_id==2
        chunk=await asyncio.wait_for(anext(process.read()),5)
        assert b'"operation":"debugger_event"' in chunk.data
    finally:
        await manager.close()
    no_workers(process)


async def test_wrong_handshake_cleans_helper():
    manager=AsyncProcessManager(RuntimeLimits(startup_seconds=2))
    with pytest.raises(DeaError,match="PROTOCOL_ERROR"):
        await manager.spawn(ProcessSpec(argv=(sys.executable,"-u",HELPER,"bad"),helper_control=True))
    assert not manager._processes
    await manager.close()


async def test_helper_startup_timeout_cleans_owned_child():
    manager=AsyncProcessManager(RuntimeLimits(startup_seconds=1))
    with pytest.raises(DeaError,match="STARTUP_TIMEOUT"):
        await manager.spawn(ProcessSpec(argv=(sys.executable,"-c","import time;time.sleep(30)"),helper_control=True))
    assert not manager._processes
    await manager.close()


@pytest.mark.parametrize("mode,code",[("truncated","PROTOCOL_ERROR"),("overflow","CONTROL_OVERFLOW"),
                                     ("unexpected-eof","PROTOCOL_ERROR")])
async def test_helper_fatal_protocol_or_queue_error_cleans_process(mode,code):
    manager=AsyncProcessManager(RuntimeLimits(control_events=2))
    process=await manager.spawn(ProcessSpec(argv=(sys.executable,"-u",HELPER,mode),helper_control=True))
    try:
        async def failed():
            while not process._failure:
                await asyncio.sleep(.005)
        await asyncio.wait_for(failed(),5)
        with pytest.raises(DeaError,match=code):
            await anext(process.control.messages())
        await asyncio.wait_for(process.close(),5)
        assert not alive(process.pid)
        no_workers(process)
    finally:
        await manager.close()


async def test_clean_helper_eof_after_exit_event_is_expected():
    manager=AsyncProcessManager(RuntimeLimits())
    process=await manager.spawn(ProcessSpec(argv=(sys.executable,"-u",HELPER,"expected-eof"),helper_control=True))
    try:
        messages=[message async for message in process.control.messages()]
        assert len(messages)==1
        assert json.loads(messages[0].body_json)["kind"]=="exited"
        assert process._failure is None
    finally:
        await manager.close()


@pytest.mark.skipif(os.name!="nt",reason="Windows writer-queue scheduling regression")
async def test_windows_close_with_full_single_slot_write_queue(monkeypatch):
    from dea.runtime.windows import WindowsProcess
    original=WindowsProcess._writer
    gate=threading.Event()
    def held_writer(self):
        assert gate.wait(5)
        original(self)
    monkeypatch.setattr(WindowsProcess,"_writer",held_writer)
    manager,process=await child("import time;time.sleep(30)", limits=RuntimeLimits(control_events=1))
    pending=asyncio.create_task(process.write(b"queued"))
    await asyncio.sleep(0)
    assert process._write_queue.full()
    closer=asyncio.create_task(process.close())
    try:
        with pytest.raises(DeaError,match="INVALID_STATE"):
            await asyncio.wait_for(pending,2)
    finally:
        gate.set()
        await asyncio.wait_for(closer,5)
        await manager.close()
    no_workers(process)


@pytest.mark.skipif(os.name=="nt",reason="POSIX native process-group/PTY scenario; Windows uses real ConPTY tests")
async def test_posix_session_and_terminal_are_native():
    manager,process=await child("import os;print(os.getsid(0),os.getpid(),os.isatty(0),flush=True)",transport="pty")
    try:
        output=b"".join(c.data for c in await asyncio.wait_for(collect(process),5))
        sid,pid,tty=output.strip().split()
        assert int(sid)==int(pid)==process.pid
        assert tty==b"True"
    finally:
        await manager.close()


@pytest.mark.skipif(os.name!="nt",reason="Windows native job/handle inspection")
async def test_windows_native_handle_count_does_not_grow():
    from dea.runtime.windows import k
    from ctypes import wintypes as w
    k.GetCurrentProcess.restype=ctypes.c_void_p
    k.GetProcessHandleCount.argtypes=[ctypes.c_void_p,ctypes.POINTER(w.DWORD)]
    manager=AsyncProcessManager(RuntimeLimits())
    # asyncio's default executor lazily caches Windows thread/event handles.
    # Warm both native allocation and concurrent ConPTY drain before baseline.
    for transport in ("pipes","pty"):
        warm=await manager.spawn(ProcessSpec(argv=(sys.executable,"-c","pass"),transport=transport))
        await warm.wait()
        await warm.close()
    await asyncio.sleep(.05)
    count=w.DWORD()
    assert k.GetProcessHandleCount(k.GetCurrentProcess(),ctypes.byref(count))
    baseline=count.value
    for transport in ("pipes","pty")*5:
        process=await manager.spawn(ProcessSpec(argv=(sys.executable,"-c","pass"),transport=transport))
        await process.wait()
        await process.close()
        no_workers(process)
    await manager.close()
    await asyncio.sleep(.05)
    assert k.GetProcessHandleCount(k.GetCurrentProcess(),ctypes.byref(count))
    assert count.value<=baseline+2

async def test_native_terminal_interrupt_reaches_target():
    manager,process=await child(
        "import signal,sys,time;"
        "signal.signal(signal.SIGINT,lambda *_:(print('INTERRUPTED',flush=True),sys.exit(0)));"
        "print('INTERRUPT_READY',flush=True);time.sleep(30)",
        transport="pty")
    output=bytearray()
    async def reader():
        async for chunk in process.read():
            output.extend(chunk.data)
    reading=asyncio.create_task(reader())
    try:
        async def ready():
            while b"INTERRUPT_READY" not in output:
                await asyncio.sleep(.005)
        await asyncio.wait_for(ready(),5)
        await process.interrupt()
        assert await asyncio.wait_for(process.wait(),5)==0
        await asyncio.wait_for(reading,5)
        assert b"INTERRUPTED" in output
    finally:
        await manager.close()

async def test_cancel_helper_startup_does_not_wait_for_startup_deadline():
    manager=AsyncProcessManager(RuntimeLimits(startup_seconds=10))
    pending=asyncio.create_task(manager.spawn(ProcessSpec(
        argv=(sys.executable,"-c","import time;time.sleep(30)"),helper_control=True)))
    await asyncio.sleep(.05)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(pending,3)
    assert not manager._processes
    await manager.close()
