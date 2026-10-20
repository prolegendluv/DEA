"""POSIX nonblocking pipes/PTY and owned process-group cleanup."""
from __future__ import annotations

import asyncio
import errno
import os
import signal

from dea.contracts.models import DeaError, ErrorCode
from .streams import BaseProcess


class PosixProcess(BaseProcess):
    @classmethod
    async def launch(cls, limits, spec, env):
        self = cls(limits, spec)
        self._master = None
        self._tasks = []
        self._write_lock = asyncio.Lock()
        slave = None
        try:
            if spec.transport == "pty":
                import pty
                self._master, slave = pty.openpty()
                os.set_blocking(self._master, False)
                self._process = await asyncio.create_subprocess_exec(
                    *spec.argv, stdin=slave, stdout=slave, stderr=slave,
                    cwd=spec.cwd, env=env, start_new_session=True)
            else:
                self._process = await asyncio.create_subprocess_exec(
                    *spec.argv, stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    cwd=spec.cwd, env=env, start_new_session=True)
        except BaseException:
            if self._master is not None:
                os.close(self._master)
            raise
        finally:
            if slave is not None:
                os.close(slave)
        return self

    @property
    def pid(self):
        return self._process.pid

    def start_io(self):
        if self._master is not None:
            self._tasks.append(asyncio.create_task(self._pty_pump(), name="dea-posix-pty"))
        else:
            for stream in ("stdout", "stderr"):
                self._tasks.append(asyncio.create_task(
                    self._pipe_pump(stream), name=f"dea-posix-{stream}"))
        self._drain_task = asyncio.create_task(self._finish(), name="dea-posix-drain")

    async def _finish(self):
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._buffer.finish()

    async def _pipe_pump(self, stream):
        try:
            reader = getattr(self._process, stream)
            while data := await reader.read(65536):
                self._buffer.feed(stream, data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._buffer.fail(DeaError(ErrorCode.PROTOCOL_ERROR, str(exc)))
        finally:
            self._buffer.feed(stream, b"", eof=True)

    async def _ready(self, writing=False):
        loop = asyncio.get_running_loop()
        ready = loop.create_future()
        def notify():
            if not ready.done():
                ready.set_result(None)
        add = loop.add_writer if writing else loop.add_reader
        remove = loop.remove_writer if writing else loop.remove_reader
        add(self._master, notify)
        try:
            await ready
        finally:
            remove(self._master)

    async def _pty_pump(self):
        try:
            while True:
                try:
                    data = os.read(self._master, 65536)
                    if not data:
                        break
                    self._buffer.feed("terminal", data)
                except BlockingIOError:
                    await self._ready()
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._buffer.fail(DeaError(ErrorCode.PROTOCOL_ERROR, str(exc)))
        finally:
            self._buffer.feed("terminal", b"", eof=True)

    async def write(self, data):
        if not isinstance(data, bytes):
            raise TypeError("Process writes require bytes")
        if len(data) > self.limits.protocol_bytes:
            raise DeaError(ErrorCode.RESOURCE_LIMIT)
        async with self._write_lock:
            if self._closing or self._process.returncode is not None:
                raise DeaError(ErrorCode.INVALID_STATE)
            try:
                if self._master is None:
                    self._process.stdin.write(data)
                    await self._process.stdin.drain()
                else:
                    view = memoryview(data)
                    while view:
                        try:
                            count = os.write(self._master, view)
                            view = view[count:]
                        except BlockingIOError:
                            await self._ready(writing=True)
            except asyncio.CancelledError:
                await self.close()
                raise
            except (OSError, ConnectionError) as exc:
                raise DeaError(ErrorCode.INVALID_STATE) from exc

    async def wait(self):
        return await self._process.wait()

    async def interrupt(self):
        if self._closing or self._process.returncode is not None:
            raise DeaError(ErrorCode.INVALID_STATE)
        try:
            os.killpg(self.pid, signal.SIGINT)
        except ProcessLookupError as exc:
            raise DeaError(ErrorCode.INVALID_STATE) from exc

    async def _close_backend(self):
        # Kill a group even if the leader already exited: descendants may retain
        # inherited pipes and continue running.
        try:
            os.killpg(self.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(asyncio.shield(self._process.wait()), .5)
        except asyncio.TimeoutError:
            pass
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await self._process.wait()
        if self._process.stdin:
            self._process.stdin.close()
            try:
                await self._process.stdin.wait_closed()
            except (OSError, ConnectionError):
                pass
        try:
            await asyncio.wait_for(asyncio.shield(self._drain_task), .5)
        except asyncio.TimeoutError:
            for task in self._tasks:
                task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._drain_task
        if self._master is not None:
            os.close(self._master)
            self._master = None
