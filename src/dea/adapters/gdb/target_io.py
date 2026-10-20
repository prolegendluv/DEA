"""An inferior-only terminal/pipe, separate from the MI control descriptors.

Target output is retained as a bounded byte ring. No byte from this sink is ever
given to the MI parser, even if it contains valid control records.
"""
from __future__ import annotations

import asyncio
import os
import secrets


class TargetIO:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.output = bytearray()
        self.dropped_bytes = 0
        self.closed = False
        self._task = None
        self.handle = None
        self.slave = None
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            self._api = ctypes.WinDLL("kernel32", use_last_error=True)
            self._api.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                wintypes.DWORD, wintypes.LPVOID]
            self._api.CreateNamedPipeW.restype = wintypes.HANDLE
            self._api.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
            self._api.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID,
                wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
            self._api.CloseHandle.argtypes = [wintypes.HANDLE]
            self.path = "\\\\.\\pipe\\dea-gdb-" + secrets.token_hex(16)
            # PIPE_ACCESS_DUPLEX, PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS.
            self.handle = self._api.CreateNamedPipeW(self.path, 3, 1 | 8, 1,
                                                    65536, 65536, 0, None)
            if self.handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            self._api.ConnectNamedPipe(self.handle, None)
        else:
            import termios
            self.handle, self.slave = os.openpty()
            os.set_blocking(self.handle, False)
            attrs = termios.tcgetattr(self.slave)
            attrs[3] &= ~termios.ECHO
            termios.tcsetattr(self.slave, termios.TCSANOW, attrs)
            self.path = os.ttyname(self.slave)

    def _append(self, data: bytes):
        self.output.extend(data)
        excess = len(self.output) - self.capacity
        if excess > 0:
            del self.output[:excess]
            self.dropped_bytes += excess

    def start(self):
        self._task = asyncio.create_task(self._drain(), name="dea-gdb-target-io")

    async def _drain(self):
        while not self.closed:
            data = self._read()
            if data:
                self._append(data)
                await asyncio.sleep(0)
            else:
                await asyncio.sleep(0.005)

    def _read(self):
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            buffer = ctypes.create_string_buffer(65536)
            count = wintypes.DWORD()
            okay = self._api.ReadFile(self.handle, buffer, len(buffer),
                                     ctypes.byref(count), None)
            if not okay:
                error = ctypes.get_last_error()
                # Not connected yet, no currently available data, or EOF.
                if error in (109, 232, 233, 536):
                    return b""
                raise ctypes.WinError(error)
            return buffer.raw[:count.value]
        try:
            return os.read(self.handle, 65536)
        except BlockingIOError:
            return b""
        except OSError as exc:
            if exc.errno == 5:  # PTY has no attached inferior yet.
                return b""
            raise

    async def close(self):
        if self.closed:
            return
        self.closed = True
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        if self.handle is not None:
            if os.name == "nt":
                self._api.CloseHandle(self.handle)
            else:
                os.close(self.handle)
            self.handle = None
        if self.slave is not None:
            os.close(self.slave)
            self.slave = None
