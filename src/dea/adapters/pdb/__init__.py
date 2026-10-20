"""Launch-only structured PDB adapter using an authenticated helper channel."""
from __future__ import annotations

import asyncio
from collections import deque
import json
import os
import sys
from pathlib import Path

from dea.contracts.adapter import BaseDebuggerAdapter
from dea.contracts.models import (
    AdapterCapabilities, Backend, Breakpoint, CommandAck, DebuggerEvent,
    DeaError, ErrorCode, EnvironmentEntry, HelperMessage, ProcessSpec, RawFrame, RawSnapshot, RawValue,
    TerminationPolicy,
)


class PdbAdapter(BaseDebuggerAdapter):
    backend = Backend.PDB

    def __init__(self, context):
        super().__init__(context)
        self.process = None
        self._pending = {}
        self._retired = deque(maxlen=context.limits.control_events)
        self._event_reading = False
        self._closing_task = None
        self._queue = asyncio.Queue(context.limits.control_events)
        self._tasks = []
        self._request_id = 1
        self._last_event = 0
        self._closed = False
        self._started = False
        self._terminal = False
        self._diagnostics = bytearray()
        self.diagnostic_loss = 0

    def capabilities(self):
        return AdapterCapabilities(backend=Backend.PDB, available=True, launch=True, interrupt=True)

    async def events(self):
        if self._event_reading:
            raise DeaError(ErrorCode.INVALID_STATE)
        self._event_reading = True
        try:
            while True:
                event = await self._queue.get()
                if event is None:
                    return
                yield event
                if event.kind in ('failed', 'exited'):
                    return
        finally:
            self._event_reading = False

    async def _drain(self):
        try:
            async for chunk in self.process.read():
                self._diagnostics.extend(chunk.data)
                excess = len(self._diagnostics) - self.context.limits.diagnostic_bytes
                if excess > 0:
                    del self._diagnostics[:excess]
                    self.diagnostic_loss += excess
        except (DeaError, OSError):
            pass

    def _fail(self, code):
        for future in tuple(self._pending.values()):
            if not future.done():
                future.set_exception(DeaError(code))
        if not self._closed:
            self._last_event += 1
            event = DebuggerEvent(event_id=self._last_event, kind='failed', error_code=code)
            if self._queue.full():
                # A failure is observable rather than silently dropping a stop.
                while not self._queue.empty():
                    self._queue.get_nowait()
            self._queue.put_nowait(event)

    async def _reader(self):
        try:
            async for message in self.process.control.messages():
                if message.kind == 'response':
                    future = self._pending.get(message.request_id)
                    if future is None:
                        if message.request_id in self._retired:
                            continue
                        raise DeaError(ErrorCode.PROTOCOL_ERROR)
                    if future.done():
                        raise DeaError(ErrorCode.PROTOCOL_ERROR)
                    operation = getattr(future, '_dea_operation', None)
                    if message.operation == 'error':
                        body = json.loads(message.body_json)
                        if set(body) != {'code'}:
                            raise DeaError(ErrorCode.PROTOCOL_ERROR)
                        future.set_exception(DeaError(ErrorCode(body['code'])))
                    elif message.operation != operation:
                        raise DeaError(ErrorCode.PROTOCOL_ERROR)
                    elif not future.done():
                        future.set_result(message.body_json)
                elif message.kind == 'event' and message.operation == 'debugger_event':
                    event = DebuggerEvent.model_validate_json(message.body_json)
                    if event.event_id != message.event_id or event.event_id <= self._last_event:
                        raise DeaError(ErrorCode.PROTOCOL_ERROR)
                    self._last_event = event.event_id
                    try:
                        self._queue.put_nowait(event)
                    except asyncio.QueueFull:
                        raise DeaError(ErrorCode.CONTROL_OVERFLOW)
                    if event.kind in ('exited', 'failed'):
                        self._terminal = True
                        for pending in tuple(self._pending.values()):
                            if not pending.done():
                                pending.set_exception(DeaError(ErrorCode.INVALID_STATE))
                        return
                else:
                    raise DeaError(ErrorCode.PROTOCOL_ERROR)
            if not self._closed:
                raise DeaError(ErrorCode.PROTOCOL_ERROR)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._fail(exc.code if isinstance(exc, DeaError) else ErrorCode.PROTOCOL_ERROR)
            await self.process.close()

    async def _call(self, operation, body=None, model=None, *, startup=False):
        if self._closed or self._terminal or self.process is None or self.process.control is None:
            raise DeaError(ErrorCode.INVALID_STATE)
        if len(self._pending) >= self.context.limits.control_events:
            raise DeaError(ErrorCode.RESOURCE_LIMIT)
        if self._request_id >= 2**63 - 1:
            raise DeaError(ErrorCode.RESOURCE_LIMIT)
        self._request_id += 1
        request_id = self._request_id
        future = asyncio.get_running_loop().create_future()
        future._dea_operation = operation
        self._pending[request_id] = future
        if hasattr(body, 'model_dump_json'):
            body_json = body.model_dump_json()
        else:
            body_json = json.dumps(body or {}, allow_nan=False)
        timeout = self.context.limits.startup_seconds if startup else self.context.limits.command_seconds
        try:
            async with asyncio.timeout(timeout):
                await self.process.control.send(HelperMessage(kind='request', request_id=request_id,
                                                             operation=operation, body_json=body_json))
                raw = await future
            if model is not None:
                try:
                    result = model.model_validate_json(raw)
                    if model is CommandAck and result.request_id != request_id:
                        raise ValueError('Mismatched acknowledgement')
                    if model is RawSnapshot and (result.session_id != self.context.session_id or result.stop_id != body.stop_id):
                        raise ValueError('Mismatched capture')
                    if model is RawFrame and result.index != body['frame_index']:
                        raise ValueError('Mismatched frame')
                    return result
                except ValueError as exc:
                    raise DeaError(ErrorCode.PROTOCOL_ERROR) from exc
            if json.loads(raw) != {}:
                raise DeaError(ErrorCode.PROTOCOL_ERROR)
        except TimeoutError as exc:
            self._retired.append(request_id)
            raise DeaError(ErrorCode.STARTUP_TIMEOUT if startup else ErrorCode.COMMAND_TIMEOUT) from exc
        except asyncio.CancelledError:
            self._retired.append(request_id)
            raise
        finally:
            self._pending.pop(request_id, None)
            if not future.done():
                future.cancel()

    async def session_start(self, spec):
        if self._started:
            raise DeaError(ErrorCode.INVALID_STATE)
        if spec.backend is not Backend.PDB:
            raise DeaError(ErrorCode.INVALID_REQUEST)
        keys = [entry.key.casefold() if os.name == 'nt' else entry.key for entry in spec.env]
        if len(keys) != len(set(keys)):
            raise DeaError(ErrorCode.INVALID_REQUEST)
        if spec.io_mode != 'capture' or spec.memory_regions:
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)
        if not Path(spec.binary_path).is_file():
            raise DeaError(ErrorCode.INVALID_REQUEST)
        self._started = True
        try:
            # Absolute helper script works even if target cwd has no installed DEA package.
            helper = str(Path(__file__).with_name('helper.py'))
            self.process = await self.context.runtime.spawn(ProcessSpec(
                argv=(sys.executable, '-u', helper), helper_control=True, env=(EnvironmentEntry(key='DEA_PDB_SESSION_ID', value=self.context.session_id), EnvironmentEntry(key='DEA_PDB_CAPACITY', value=str(self.context.limits.control_events)), EnvironmentEntry(key='DEA_PDB_PROTOCOL_BYTES', value=str(self.context.limits.protocol_bytes)))))
            if self.process.control is None:
                raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)
            self._tasks = [asyncio.create_task(self._reader()), asyncio.create_task(self._drain())]
            return await self._call('session_start', spec, CommandAck, startup=True)
        except BaseException:
            await self.session_terminate(TerminationPolicy.TERMINATE_OWNED)
            raise

    async def session_attach(self, spec):
        raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)

    async def breakpoint_set(self, spec):
        return await self._call('breakpoint_set', spec, Breakpoint)

    async def execution_continue(self):
        return await self._call('execution_continue', model=CommandAck)

    async def execution_step(self, mode):
        return await self._call('execution_step', {'mode': mode.value}, CommandAck)

    async def execution_interrupt(self):
        return await self._call('execution_interrupt', model=CommandAck)

    async def snapshot_capture(self, request):
        if request.memory_regions:
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)
        return await self._call('snapshot_capture', request, RawSnapshot)

    async def state_inspect_frame(self, frame_index, max_depth):
        return await self._call('state_inspect_frame', {'frame_index': frame_index, 'max_depth': max_depth}, RawFrame)

    async def state_eval_expression(self, expr):
        return await self._call('state_eval_expression', {'expr': expr}, RawValue)

    async def state_read_memory(self, region):
        raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)

    async def session_terminate(self, policy):
        if policy is TerminationPolicy.DETACH:
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)
        if self._closing_task is None:
            self._closing_task = asyncio.create_task(self._shutdown())
        await asyncio.shield(self._closing_task)

    async def _shutdown(self):
        if self._closed:
            return
        try:
            if self.process is not None and self.process.control is not None:
                try:
                    await self._call('session_terminate', {'policy': TerminationPolicy.TERMINATE_OWNED.value})
                except (DeaError, OSError):
                    pass
        finally:
            self._closed = True
            if self.process is not None:
                await self.process.close()
            for task in self._tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
            for future in tuple(self._pending.values()):
                if not future.done():
                    future.set_exception(DeaError(ErrorCode.INVALID_STATE))
            if not self._queue.full():
                self._queue.put_nowait(None)


__all__ = ['PdbAdapter']
