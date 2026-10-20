"""Native Windows suspended launch, Job Objects, pipes and ConPTY.

Synchronous handles are serviced by owned reader/writer/wait threads. No blocking
native operation runs on the event loop. Child code starts only after job assignment.
"""
from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes as w
import os
import queue
import shutil
import subprocess
import threading

from dea.contracts.models import DeaError, ErrorCode
from .streams import BaseProcess

k = ctypes.WinDLL("kernel32", use_last_error=True)
HANDLE = w.HANDLE
SIZE_T = ctypes.c_size_t
ULONG_PTR = ctypes.c_size_t


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", w.DWORD), ("lpSecurityDescriptor", w.LPVOID), ("bInheritHandle", w.BOOL)]


class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR),
                ("lpTitle", w.LPWSTR), ("dwX", w.DWORD), ("dwY", w.DWORD),
                ("dwXSize", w.DWORD), ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD),
                ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD),
                ("dwFlags", w.DWORD), ("wShowWindow", w.WORD), ("cbReserved2", w.WORD),
                ("lpReserved2", ctypes.POINTER(w.BYTE)), ("hStdInput", HANDLE),
                ("hStdOutput", HANDLE), ("hStdError", HANDLE)]


class STARTUPINFOEX(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFO), ("lpAttributeList", w.LPVOID)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", HANDLE), ("hThread", HANDLE), ("dwProcessId", w.DWORD),
                ("dwThreadId", w.DWORD)]


class BASIC_LIMIT(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", SIZE_T),
                ("MaximumWorkingSetSize", SIZE_T), ("ActiveProcessLimit", w.DWORD),
                ("Affinity", ULONG_PTR), ("PriorityClass", w.DWORD),
                ("SchedulingClass", w.DWORD)]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
               ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class EXTENDED_LIMIT(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", BASIC_LIMIT), ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", SIZE_T), ("JobMemoryLimit", SIZE_T),
                ("PeakProcessMemoryUsed", SIZE_T), ("PeakJobMemoryUsed", SIZE_T)]


class COORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]


def _api(name, restype, argtypes):
    fn = getattr(k, name)
    fn.restype, fn.argtypes = restype, argtypes
    return fn


CloseHandle = _api("CloseHandle", w.BOOL, [HANDLE])
CreatePipe = _api("CreatePipe", w.BOOL, [ctypes.POINTER(HANDLE), ctypes.POINTER(HANDLE), ctypes.POINTER(SECURITY_ATTRIBUTES), w.DWORD])
SetHandleInformation = _api("SetHandleInformation", w.BOOL, [HANDLE, w.DWORD, w.DWORD])
CreateJobObject = _api("CreateJobObjectW", HANDLE, [w.LPVOID, w.LPCWSTR])
SetInformationJobObject = _api("SetInformationJobObject", w.BOOL, [HANDLE, ctypes.c_int, w.LPVOID, w.DWORD])
AssignProcessToJobObject = _api("AssignProcessToJobObject", w.BOOL, [HANDLE, HANDLE])
TerminateJobObject = _api("TerminateJobObject", w.BOOL, [HANDLE, w.UINT])
TerminateProcess = _api("TerminateProcess", w.BOOL, [HANDLE, w.UINT])
CreateProcess = _api("CreateProcessW", w.BOOL, [w.LPCWSTR, w.LPWSTR, w.LPVOID, w.LPVOID, w.BOOL, w.DWORD, w.LPVOID, w.LPCWSTR, w.LPVOID, ctypes.POINTER(PROCESS_INFORMATION)])
ResumeThread = _api("ResumeThread", w.DWORD, [HANDLE])
WaitForSingleObject = _api("WaitForSingleObject", w.DWORD, [HANDLE, w.DWORD])
GetExitCodeProcess = _api("GetExitCodeProcess", w.BOOL, [HANDLE, ctypes.POINTER(w.DWORD)])
ReadFile = _api("ReadFile", w.BOOL, [HANDLE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID])
WriteFile = _api("WriteFile", w.BOOL, [HANDLE, w.LPCVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID])
OpenThread = _api("OpenThread", HANDLE, [w.DWORD, w.BOOL, w.DWORD])
CancelSynchronousIo = _api("CancelSynchronousIo", w.BOOL, [HANDLE])
InitializeAttributes = _api("InitializeProcThreadAttributeList", w.BOOL, [w.LPVOID, w.DWORD, w.DWORD, ctypes.POINTER(SIZE_T)])
UpdateAttribute = _api("UpdateProcThreadAttribute", w.BOOL, [w.LPVOID, w.DWORD, SIZE_T, w.LPVOID, SIZE_T, w.LPVOID, w.LPVOID])
DeleteAttributes = _api("DeleteProcThreadAttributeList", None, [w.LPVOID])
_CREATE_LOCK = threading.Lock()


def _check(result):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return result


def _close(handle):
    if handle:
        CloseHandle(handle)


def conpty_available():
    return hasattr(k, "CreatePseudoConsole")


class WindowsProcess(BaseProcess):
    def __init__(self, limits, spec):
        super().__init__(limits, spec)
        self.loop = asyncio.get_running_loop()
        self._pid = 0
        self._process = self._job = self._console = None
        self._input = None
        self._outputs = []
        self._threads = []
        self._stop = threading.Event()
        self._write_queue = queue.Queue(limits.control_events)
        self._write_lock = asyncio.Lock()
        self._exit = self.loop.create_future()
        self._handles_closed = False
        self.assigned_before_resume = False
        self._console_lock = threading.Lock()
        self._drain_task = None

    @property
    def pid(self):
        return self._pid

    def launch(self, env):
        """Called on a worker. Every failure closes handles and kills suspended child."""
        if self.spec.transport == "pty" and not conpty_available():
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE, "ConPTY unavailable")
        handles = []
        child_ends = []
        attributes = None
        pi = PROCESS_INFORMATION()
        try:
            def pipe(inherit):
                read, write = HANDLE(), HANDLE()
                sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, inherit)
                _check(CreatePipe(ctypes.byref(read), ctypes.byref(write), ctypes.byref(sa), 0))
                handles.extend((read.value, write.value))
                return read.value, write.value

            startup = STARTUPINFOEX()
            startup.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
            startup.StartupInfo.dwFlags = 1  # STARTF_USESHOWWINDOW / SW_HIDE
            startup.StartupInfo.wShowWindow = 0
            if self.spec.transport == "pty":
                # Explicit NULL standard handles let console initialization open
                # ConDrv handles instead of copying the parent's redirected pipes.
                startup.StartupInfo.dwFlags |= 0x100
                console_in, self._input = pipe(False)
                output, console_out = pipe(False)
                self._outputs = [("terminal", output)]
                create_console = _api("CreatePseudoConsole", ctypes.c_long,
                                      [COORD, HANDLE, HANDLE, w.DWORD, ctypes.POINTER(HANDLE)])
                console = HANDLE()
                hr = create_console(COORD(120, 40), console_in, console_out, 0, ctypes.byref(console))
                if hr != 0:
                    raise OSError(f"CreatePseudoConsole failed: {hr:#x}")
                self._console = console.value
                child_ends = [console_in, console_out]
                attribute_key = 0x00020016  # PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
                attribute_value = ctypes.c_void_p(self._console)
                attribute_pointer = attribute_value
                attribute_size = ctypes.sizeof(HANDLE)
                inherit = False
            else:
                child_in, self._input = pipe(True)
                stdout, child_out = pipe(True)
                stderr, child_err = pipe(True)
                self._outputs = [("stdout", stdout), ("stderr", stderr)]
                for parent in (self._input, stdout, stderr):
                    _check(SetHandleInformation(parent, 1, 0))
                child_ends = [child_in, child_out, child_err]
                startup.StartupInfo.dwFlags |= 0x100  # STARTF_USESTDHANDLES
                startup.StartupInfo.hStdInput = child_in
                startup.StartupInfo.hStdOutput = child_out
                startup.StartupInfo.hStdError = child_err
                attribute_key = 0x00020002  # PROC_THREAD_ATTRIBUTE_HANDLE_LIST
                attribute_value = (HANDLE * 3)(*child_ends)
                attribute_pointer = ctypes.cast(attribute_value, w.LPVOID)
                attribute_size = ctypes.sizeof(attribute_value)
                inherit = True

            size = SIZE_T()
            InitializeAttributes(None, 1, 0, ctypes.byref(size))
            attributes = ctypes.create_string_buffer(size.value)
            _check(InitializeAttributes(attributes, 1, 0, ctypes.byref(size)))
            startup.lpAttributeList = ctypes.cast(attributes, w.LPVOID)
            _check(UpdateAttribute(attributes, 0, attribute_key, attribute_pointer,
                                   attribute_size, None, None))
            self._job = _check(CreateJobObject(None, None))
            limits = EXTENDED_LIMIT()
            limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
            _check(SetInformationJobObject(self._job, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
            environment = ctypes.create_unicode_buffer("\0".join(f"{key}={value}" for key, value in
                sorted(env.items(), key=lambda entry: entry[0].upper())) + "\0\0")
            executable = shutil.which(self.spec.argv[0], path=env.get("PATH")) or self.spec.argv[0]
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline(self.spec.argv))
            flags = 0x4 | 0x400 | 0x80000  # SUSPENDED | UNICODE_ENV | EXTENDED_STARTUPINFO
            if self.spec.transport == "pipes":
                flags |= 0x08000000  # CREATE_NO_WINDOW
            with _CREATE_LOCK:
                _check(CreateProcess(executable, command, None, None, inherit, flags,
                                     environment, self.spec.cwd, ctypes.byref(startup), ctypes.byref(pi)))
                self._process, self._pid = pi.hProcess, pi.dwProcessId
                _check(AssignProcessToJobObject(self._job, self._process))
                self.assigned_before_resume = True
                if ResumeThread(pi.hThread) == 0xFFFFFFFF:
                    raise ctypes.WinError(ctypes.get_last_error())
            _close(pi.hThread)
            pi.hThread = None
            for handle in child_ends:
                _close(handle)
                handles.remove(handle)
            handles.clear()  # Ownership transferred to instance.
        except BaseException:
            if self._process:
                TerminateProcess(self._process, 1)
                WaitForSingleObject(self._process, 5000)
            for handle in handles:
                _close(handle)
            _close(pi.hThread)
            _close(self._process)
            _close(self._job)
            self._process = self._job = None
            if self._console:
                _api("ClosePseudoConsole", None, [HANDLE])(self._console)
                self._console = None
            raise
        finally:
            if attributes is not None:
                DeleteAttributes(attributes)

    def start_io(self):
        for stream, handle in self._outputs:
            self._thread(self._reader, stream, handle, name=f"dea-reader-{stream}-{self.pid}")
        self._thread(self._writer, name=f"dea-writer-{self.pid}")
        self._thread(self._waiter, name=f"dea-wait-{self.pid}")

    def _thread(self, target, *args, name):
        worker = threading.Thread(target=target, args=args, name=name, daemon=True)
        self._threads.append(worker)
        worker.start()

    def _reader(self, stream, handle):
        buffer = ctypes.create_string_buffer(65536)
        count = w.DWORD()
        while True:
            if not ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None):
                code = ctypes.get_last_error()
                if code not in (109, 232, 995, 6) and not self._stop.is_set():
                    self._buffer.fail(DeaError(ErrorCode.PROTOCOL_ERROR, f"ReadFile: {code}"))
                break
            if count.value == 0:
                break
            self._buffer.feed(stream, buffer.raw[:count.value])
        self._buffer.feed(stream, b"", eof=True)

    def _complete_write(self, future, error):
        if not future.done():
            if error:
                future.set_exception(error)
            else:
                future.set_result(None)

    def _writer(self):
        while True:
            entry = self._write_queue.get()
            if entry is None:
                return
            data, future = entry
            error = None
            try:
                if self._stop.is_set():
                    raise DeaError(ErrorCode.INVALID_STATE)
                view = memoryview(data)
                while view:
                    part = bytes(view[:65536])
                    count = w.DWORD()
                    if not WriteFile(self._input, part, len(part), ctypes.byref(count), None):
                        raise DeaError(ErrorCode.INVALID_STATE, "Child input closed")
                    if count.value == 0:
                        raise DeaError(ErrorCode.INVALID_STATE, "Zero write")
                    view = view[count.value:]
            except BaseException as exc:
                error = exc
            self.loop.call_soon_threadsafe(self._complete_write, future, error)

    def _waiter(self):
        status = WaitForSingleObject(self._process, 0xFFFFFFFF)
        code = w.DWORD()
        error = None
        if status != 0 or not GetExitCodeProcess(self._process, ctypes.byref(code)):
            error = DeaError(ErrorCode.INTERNAL_ERROR, "Native process wait failed")
        self.loop.call_soon_threadsafe(self._completed, code.value, error)

    def _completed(self, code, error):
        if not self._exit.done():
            if error:
                self._exit.set_exception(error)
            else:
                self._exit.set_result(code)
        # EOF may still be buffered. Read completion is independent of wait().
        if not self._closing:
            self._drain_task = asyncio.create_task(self._finish_streams(), name="dea-drain-exited")

    async def _finish_streams(self):
        if self.spec.transport == "pty":
            await asyncio.to_thread(self._close_console)
        readers = [t for t in self._threads if t.name.startswith("dea-reader")]
        # Descendants can retain inherited output handles after the parent exits;
        # normal wait must not wait for them. close() owns tree termination.
        while any(t.is_alive() for t in readers) and not self._closing:
            await asyncio.sleep(.01)
        if not any(t.is_alive() for t in readers):
            self._buffer.finish()

    def _close_console(self):
        with self._console_lock:
            console, self._console = self._console, None
            if console:
                _api("ClosePseudoConsole", None, [HANDLE])(console)

    async def write(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError("Process writes require bytes")
        if len(data) > self.limits.protocol_bytes:
            raise DeaError(ErrorCode.RESOURCE_LIMIT, "Write exceeds bounded command size")
        async with self._write_lock:
            if self._closing or self._exit.done():
                raise DeaError(ErrorCode.INVALID_STATE)
            future = self.loop.create_future()
            try:
                self._write_queue.put_nowait((data, future))
            except queue.Full as exc:
                raise DeaError(ErrorCode.RESOURCE_LIMIT) from exc
            try:
                await future
            except asyncio.CancelledError:
                await self.close()
                raise

    async def wait(self):
        return await asyncio.shield(self._exit)

    async def interrupt(self):
        if self._closing or self._exit.done():
            raise DeaError(ErrorCode.INVALID_STATE)
        if self.spec.transport == "pty":
            await self.write(b"\x03")
        else:
            # CREATE_NO_WINDOW has no console to receive CTRL_BREAK. Adapters
            # use their debugger-native protocol interrupt on pipe transports.
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE, "No console interrupt for hidden pipes")

    def _close_native(self):
        self._stop.set()
        errors = []
        def cancel(worker):
            if worker.is_alive() and worker.native_id:
                handle = OpenThread(1, False, worker.native_id)
                if handle:
                    CancelSynchronousIo(handle)
                    CloseHandle(handle)
        try:
            if self._job and not TerminateJobObject(self._job, 1):
                errors.append(ctypes.WinError(ctypes.get_last_error()))
            # Keep console output readers alive until ClosePseudoConsole has
            # emitted and drained its last terminal records. Cancel writes first.
            for worker in self._threads:
                if worker.name.startswith("dea-writer"):
                    cancel(worker)
            # A pending bounded write may not have been picked up by its worker.
            # Remove pending entries before inserting the wakeup sentinel.
            while True:
                try:
                    entry = self._write_queue.get_nowait()
                except queue.Empty:
                    break
                if entry is not None:
                    _, future = entry
                    self.loop.call_soon_threadsafe(self._complete_write, future,
                                                   DeaError(ErrorCode.INVALID_STATE))
            self._write_queue.put_nowait(None)
            self._close_console()
            for worker in self._threads:
                worker.join(2)
                if worker.is_alive():
                    cancel(worker)
                    worker.join(5)
                if worker.is_alive():
                    errors.append(RuntimeError(f"Native worker failed to stop: {worker.name}"))
        finally:
            for handle in [self._input, *(handle for _, handle in self._outputs),
                           self._process, self._job]:
                _close(handle)
            self._input = self._process = self._job = None
            self._outputs.clear()
            self._handles_closed = True
        if errors:
            raise errors[0]

    async def _close_backend(self):
        await asyncio.to_thread(self._close_native)
        if self._drain_task:
            await self._drain_task
        if not self._exit.done():
            # Native waiter callback is scheduled before thread join completes.
            await asyncio.sleep(0)
