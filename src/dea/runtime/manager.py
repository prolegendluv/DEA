"""Owned platform process selection and single-use authenticated helper startup."""
from __future__ import annotations

import asyncio
import os
import secrets

from dea.contracts.models import DeaError, ErrorCode, ProcessSpec, RuntimeLimits
from dea.contracts.services import ManagedProcess
from .framing import FramedConnection

_CONTROL_KEYS = ("DEA_CONTROL_HOST", "DEA_CONTROL_PORT", "DEA_CONTROL_TOKEN")


def build_environment(spec: ProcessSpec):
    """Never inherit stale helper credentials or ambiguous Windows overrides."""
    env = {key: value for key, value in os.environ.items()
           if key.upper() not in _CONTROL_KEYS}
    seen = set()
    for entry in spec.env:
        key = entry.key.upper() if os.name == "nt" else entry.key
        if key in seen:
            raise DeaError(ErrorCode.INVALID_REQUEST, "Duplicate environment override")
        seen.add(key)
        if entry.key.upper() in _CONTROL_KEYS:
            raise DeaError(ErrorCode.INVALID_REQUEST, "Reserved control credential")
        if os.name == "nt":
            for old in tuple(env):
                if old.upper() == key:
                    del env[old]
        env[entry.key] = entry.value
    return env


class AsyncProcessManager:
    def __init__(self, limits: RuntimeLimits) -> None:
        self.limits = limits
        self._processes = set()
        self._spawns = set()
        self._closed = False
        self._closing = None

    async def spawn(self, spec: ProcessSpec) -> ManagedProcess:
        if self._closed:
            raise DeaError(ErrorCode.INVALID_STATE)
        if len(self._processes) + len(self._spawns) >= self.limits.maximum_sessions:
            raise DeaError(ErrorCode.RESOURCE_LIMIT)
        task = asyncio.create_task(self._spawn(spec), name="dea-spawn")
        self._spawns.add(task)
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # Never lose a suspended/native process if caller cancellation races
            # with allocation on a worker thread.
            task.cancel()
            try:
                process = await asyncio.shield(task)
                await process.close()
            except (Exception, asyncio.CancelledError):
                pass
            raise
        finally:
            self._spawns.discard(task)

    async def _spawn(self, spec):
        process = None
        server = None
        accepted = None
        writer = None
        env = build_environment(spec)
        try:
            if spec.helper_control:
                loop = asyncio.get_running_loop()
                accepted = loop.create_future()
                def on_client(reader, connection_writer):
                    nonlocal server
                    if accepted.done():
                        connection_writer.close()
                        return
                    accepted.set_result((reader, connection_writer))
                    server.close()  # Single-use endpoint, before authentication.
                server = await asyncio.start_server(on_client, "127.0.0.1", 0,
                                                    limit=min(self.limits.protocol_bytes, 65536))
                token = secrets.token_hex(32)
                env.update(DEA_CONTROL_HOST="127.0.0.1",
                           DEA_CONTROL_PORT=str(server.sockets[0].getsockname()[1]),
                           DEA_CONTROL_TOKEN=token)
            async with asyncio.timeout(self.limits.startup_seconds):
                if os.name == "nt":
                    from .windows import WindowsProcess
                    process = WindowsProcess(self.limits, spec)
                    # Shield allocation: suspended process cleanup belongs to the
                    # launch worker even when the startup deadline expires.
                    launch = asyncio.create_task(asyncio.to_thread(process.launch, env))
                    try:
                        await asyncio.shield(launch)
                    except BaseException:
                        await asyncio.shield(launch)
                        # I/O must start before closing a ConPTY; its output drain
                        # runs independently while ClosePseudoConsole executes.
                        process.start_io()
                        raise
                else:
                    from .posix import PosixProcess
                    process = await PosixProcess.launch(self.limits, spec, env)
                process.start_io()
                process._on_closed = self._processes.discard
                self._processes.add(process)
                if spec.helper_control:
                    reader, writer = await accepted
                    control = FramedConnection(reader, writer, self.limits, process._fail)
                    process._control = control
                    await control.handshake(token)
                    control.start()
            if self._closed:
                await process.close()
                raise DeaError(ErrorCode.INVALID_STATE)
            return process
        except BaseException as exc:
            if process is not None and process.pid:
                await process.close()
                self._processes.discard(process)
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
            if isinstance(exc, TimeoutError):
                raise DeaError(ErrorCode.STARTUP_TIMEOUT) from exc
            if isinstance(exc, (DeaError, asyncio.CancelledError)):
                raise
            if isinstance(exc, (FileNotFoundError, PermissionError, OSError)):
                raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE, str(exc)) from exc
            raise
        finally:
            if server is not None:
                server.close()
                # Since Python 3.13 wait_closed() also waits for accepted client
                # transports. The authenticated connection deliberately outlives
                # this single-use listener and is closed by ManagedProcess.
                if accepted is None or not accepted.done():
                    await server.wait_closed()
            # A socket may have connected just as the launch failed.
            if accepted is not None and accepted.done() and not accepted.cancelled():
                _, connection_writer = accepted.result()
                if process is None or process._control is None:
                    connection_writer.close()
                    try:
                        await connection_writer.wait_closed()
                    except OSError:
                        pass

    async def _close(self):
        self._closed = True
        if self._spawns:
            await asyncio.gather(*tuple(self._spawns), return_exceptions=True)
        results = await asyncio.gather(*(p.close() for p in self._processes), return_exceptions=True)
        self._processes.clear()
        errors = [result for result in results if isinstance(result, BaseException)]
        if errors:
            raise errors[0]

    async def close(self) -> None:
        self._closed = True
        if self._closing is None:
            self._closing = asyncio.create_task(self._close(), name="dea-manager-cleanup")
        try:
            await asyncio.shield(self._closing)
        except asyncio.CancelledError:
            await asyncio.shield(self._closing)
            raise
