"""Bounded native-thread to asyncio bridge, without one callback per byte chunk."""
from __future__ import annotations

import asyncio
import threading
from collections import deque
from dea.contracts.models import DeaError, ErrorCode, ProcessChunk, RuntimeLimits


class StreamBuffer:
    def __init__(self, limits: RuntimeLimits, *, stdout_control: bool, on_failure):
        self.loop = asyncio.get_running_loop()
        self.limits, self.stdout_control = limits, stdout_control
        self.on_failure = on_failure
        self._lock = threading.Lock()
        self._items = deque()
        self._diagnostic_size = self._control_size = 0
        self._scheduled = False
        self._event = asyncio.Event()
        self._error = None
        self._finished = False
        self._loss = 0

    @property
    def diagnostic_loss(self):
        with self._lock:
            return self._loss

    def _notify(self):
        self._event.set()
        error = None
        with self._lock:
            self._scheduled = False
            if self._error and not self._finished:
                self._finished = True
                error = self._error
        if error:
            self.on_failure(error)

    def _schedule(self):
        if not self._scheduled:
            self._scheduled = True
            self.loop.call_soon_threadsafe(self._notify)

    def fail(self, error: DeaError):
        with self._lock:
            self._error = self._error or error
            self._schedule()

    def finish(self):
        with self._lock:
            self._finished = True
            self._schedule()

    def feed(self, stream: str, data: bytes, eof=False):
        with self._lock:
            if self._finished or self._error:
                return
            control = stream == "stdout" and self.stdout_control and not eof
            if control and self._control_size >= self.limits.control_events:
                self._error = DeaError(ErrorCode.CONTROL_OVERFLOW)
                self._schedule()
                return
            if not control and not eof:
                # All diagnostic streams share a single byte bound.
                overflow = self._diagnostic_size + len(data) - self.limits.diagnostic_bytes
                if overflow > 0:
                    for index in range(len(self._items)):
                        item, is_control = self._items[index]
                        if is_control or item.eof:
                            continue
                        removed = min(overflow, len(item.data))
                        self._loss += removed
                        self._diagnostic_size -= removed
                        overflow -= removed
                        self._items[index] = (
                            item.model_copy(update={"data": item.data[removed:]}), False)
                        if overflow == 0:
                            break
                    self._items = deque((item, is_control) for item, is_control in self._items
                                        if item.data or item.eof)
                    if overflow > 0:
                        self._loss += overflow
                        data = data[overflow:]
                self._diagnostic_size += len(data)
            if control:
                self._control_size += 1
            # Drop empty diagnostic chunks: zero-sized records must not bypass bounds.
            if data or eof:
                self._items.append((ProcessChunk(stream=stream, data=data, eof=eof), control))
            self._schedule()

    async def next(self):
        while True:
            with self._lock:
                if self._error:
                    raise self._error
                while self._items:
                    item, control = self._items.popleft()
                    if control:
                        self._control_size -= 1
                    elif not item.eof:
                        self._diagnostic_size -= len(item.data)
                    if item.data or item.eof:
                        return item
                if self._finished:
                    return None
                self._event.clear()
            await self._event.wait()


class BaseProcess:
    def __init__(self, limits, spec):
        self.limits, self.spec = limits, spec
        self._control = None
        self._reading = False
        self._closing = None
        self._failure = None
        self._buffer = StreamBuffer(limits, stdout_control=not spec.helper_control,
                                    on_failure=self._fail)

    @property
    def control(self):
        return self._control

    @property
    def diagnostic_loss(self):
        return self._buffer.diagnostic_loss

    def _fail(self, error):
        self._failure = self._failure or error
        self._buffer.fail(error)
        if self._closing is None:
            self._closing = asyncio.create_task(self._cleanup(), name="dea-process-cleanup")

    async def read(self):
        if self._reading:
            raise DeaError(ErrorCode.INVALID_STATE, "One process reader allowed")
        self._reading = True
        while True:
            chunk = await self._buffer.next()
            if chunk is None:
                return
            yield chunk

    async def _cleanup(self):
        try:
            if self._control:
                await self._control.close()
        finally:
            try:
                await self._close_backend()
            finally:
                self._buffer.finish()
                callback = getattr(self, "_on_closed", None)
                if callback:
                    callback(self)

    async def close(self):
        if self._closing is None:
            self._closing = asyncio.create_task(self._cleanup(), name="dea-process-cleanup")
        try:
            await asyncio.shield(self._closing)
        except asyncio.CancelledError:
            # A cancelled owner still waits for resource release before propagating.
            await asyncio.shield(self._closing)
            raise
