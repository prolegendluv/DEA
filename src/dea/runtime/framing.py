"""Strict bounded helper framing. Target output never enters this channel."""
from __future__ import annotations

import asyncio
import hmac
import json
import struct
from collections.abc import AsyncIterator
from pydantic import Field

from dea.contracts.models import (
    AttachSpec, Breakpoint, BreakpointSpec, CaptureRequest, CommandAck,
    DebuggerEvent, DeaError, ErrorCode, HelperMessage, LaunchSpec, MemoryRead,
    MemoryRegion, RawFrame, RawSnapshot, RawValue, RuntimeLimits, StepMode,
    StrictModel, TerminationPolicy,
)


class _Step(StrictModel):
    mode: StepMode


class _Frame(StrictModel):
    frame_index: int = Field(ge=0, le=2**63-1)
    max_depth: int = Field(ge=0, le=8)


class _Eval(StrictModel):
    expr: str = Field(min_length=1, max_length=4096)


class _Terminate(StrictModel):
    policy: TerminationPolicy


class _Error(StrictModel):
    code: ErrorCode


class _Hello(StrictModel):
    token: str = Field(min_length=1, max_length=256)


_REQUESTS = {
    "session_start": LaunchSpec, "session_attach": AttachSpec,
    "breakpoint_set": BreakpointSpec, "execution_continue": None,
    "execution_step": _Step, "execution_interrupt": None,
    "snapshot_capture": CaptureRequest, "state_inspect_frame": _Frame,
    "state_eval_expression": _Eval, "state_read_memory": MemoryRegion,
    "session_terminate": _Terminate,
}
_RESPONSES = {
    "session_start": CommandAck, "session_attach": CommandAck,
    "breakpoint_set": Breakpoint, "execution_continue": CommandAck,
    "execution_step": CommandAck, "execution_interrupt": CommandAck,
    "snapshot_capture": RawSnapshot, "state_inspect_frame": RawFrame,
    "state_eval_expression": RawValue, "state_read_memory": MemoryRead,
    "session_terminate": None, "error": _Error,
}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def strict_json(text: str):
    return json.loads(text, object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def validate_message(message: HelperMessage) -> None:
    """Validate envelope and its operation-specific typed body, in both directions."""
    try:
        HelperMessage.model_validate_json(message.model_dump_json())
        body = strict_json(message.body_json)
        if message.operation == "hello":
            if message.kind == "event" or message.request_id != 1:
                raise ValueError("Invalid handshake")
            model = _Hello if message.kind == "request" else None
        elif message.kind == "event":
            if message.operation != "debugger_event":
                raise ValueError("Unknown event")
            event = DebuggerEvent.model_validate_json(message.body_json)
            if event.event_id != message.event_id:
                raise ValueError("Event correlation mismatch")
            return
        else:
            if message.request_id is None or message.request_id < 2:
                raise ValueError("Reserved request ID")
            models = _REQUESTS if message.kind == "request" else _RESPONSES
            if message.operation not in models:
                raise ValueError("Unknown operation")
            model = models[message.operation]
        if model is None:
            if body != {}:
                raise ValueError("Expected empty object")
        else:
            model.model_validate_json(message.body_json)
    except Exception as exc:
        raise DeaError(ErrorCode.PROTOCOL_ERROR, "Invalid helper envelope/body") from exc


def encode_frame(message: HelperMessage, maximum: int = 1_048_576) -> bytes:
    validate_message(message)
    try:
        data = message.model_dump_json(exclude_none=True).encode("utf-8", "strict")
    except Exception as exc:
        raise DeaError(ErrorCode.PROTOCOL_ERROR) from exc
    if not 1 <= len(data) <= min(maximum, 1_048_576):
        raise DeaError(ErrorCode.PROTOCOL_ERROR, "Helper frame length")
    return struct.pack("!I", len(data)) + data


class FrameDecoder:
    """At most one bounded partial frame; preserves fragmented UTF-8."""
    def __init__(self, maximum: int = 1_048_576):
        self.maximum = min(maximum, 1_048_576)
        self._buffer = bytearray()
        self._length: int | None = None
        self._failed = False

    def feed(self, data: bytes) -> list[HelperMessage]:
        if self._failed:
            raise DeaError(ErrorCode.PROTOCOL_ERROR)
        result = []
        view = memoryview(data)
        try:
            while view:
                target = 4 if self._length is None else self._length
                take = min(target - len(self._buffer), len(view))
                self._buffer.extend(view[:take])
                view = view[take:]
                if len(self._buffer) != target:
                    continue
                if self._length is None:
                    self._length = struct.unpack("!I", self._buffer)[0]
                    self._buffer.clear()
                    if not 1 <= self._length <= self.maximum:
                        raise ValueError("Frame length")
                else:
                    text = self._buffer.decode("utf-8", "strict")
                    strict_json(text)
                    message = HelperMessage.model_validate_json(text)
                    validate_message(message)
                    result.append(message)
                    self._buffer.clear()
                    self._length = None
        except Exception as exc:
            self._failed = True
            self._buffer.clear()
            if isinstance(exc, DeaError):
                raise
            raise DeaError(ErrorCode.PROTOCOL_ERROR, "Malformed helper frame") from exc
        return result

    def eof(self) -> None:
        if self._failed or self._buffer or self._length is not None:
            self._failed = True
            raise DeaError(ErrorCode.PROTOCOL_ERROR, "Truncated helper frame")


class FramedConnection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 limits: RuntimeLimits, on_failure=None):
        self._reader, self._writer, self._limits = reader, writer, limits
        self._queue: asyncio.Queue[HelperMessage] = asyncio.Queue(limits.control_events)
        self._changed = asyncio.Event()
        self._writing = asyncio.Lock()
        self._reading = False
        self._closed = False
        self._error: DeaError | None = None
        self._on_failure = on_failure
        self._task: asyncio.Task | None = None
        self._expected_eof = False
        self._close_task: asyncio.Task | None = None

    async def handshake(self, token: str) -> None:
        try:
            prefix = await self._reader.readexactly(4)
            length = struct.unpack("!I", prefix)[0]
            if not 1 <= length <= min(self._limits.protocol_bytes, 1_048_576):
                raise ValueError("Handshake length")
            decoder = FrameDecoder(self._limits.protocol_bytes)
            message = decoder.feed(prefix + await self._reader.readexactly(length))[0]
            if (message.kind != "request" or message.operation != "hello" or
                    not hmac.compare_digest(strict_json(message.body_json)["token"], token)):
                raise ValueError("Handshake authentication")
            await self.send(HelperMessage(kind="response", request_id=1,
                                          operation="hello", body_json="{}"))
        except Exception as exc:
            await self.close()
            if isinstance(exc, DeaError):
                raise
            raise DeaError(ErrorCode.PROTOCOL_ERROR, "Helper authentication failed") from exc

    def start(self):
        self._task = asyncio.create_task(self._pump(), name="dea-helper-reader")

    async def _pump(self):
        decoder = FrameDecoder(self._limits.protocol_bytes)
        try:
            while not self._closed:
                data = await self._reader.read(65536)
                if not data:
                    decoder.eof()
                    if not self._expected_eof and not self._closed:
                        raise DeaError(ErrorCode.PROTOCOL_ERROR, "Unexpected helper EOF")
                    break
                for message in decoder.feed(data):
                    if message.operation == "hello":
                        raise DeaError(ErrorCode.PROTOCOL_ERROR, "Repeated handshake")
                    if (message.kind == "event" and message.operation == "debugger_event"
                            and strict_json(message.body_json).get("kind") == "exited"):
                        self._expected_eof = True
                    try:
                        self._queue.put_nowait(message)
                    except asyncio.QueueFull as exc:
                        raise DeaError(ErrorCode.CONTROL_OVERFLOW) from exc
                    self._changed.set()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._error = exc if isinstance(exc, DeaError) else DeaError(ErrorCode.PROTOCOL_ERROR)
            if self._on_failure:
                self._on_failure(self._error)
        finally:
            self._closed = True
            self._writer.close()
            self._changed.set()

    async def messages(self) -> AsyncIterator[HelperMessage]:
        if self._reading:
            raise DeaError(ErrorCode.INVALID_STATE, "One helper reader allowed")
        self._reading = True
        while True:
            if self._error:
                raise self._error
            if not self._queue.empty():
                yield self._queue.get_nowait()
            elif self._closed:
                return
            else:
                self._changed.clear()
                await self._changed.wait()

    async def send(self, message: HelperMessage) -> None:
        data = encode_frame(message, self._limits.protocol_bytes)
        async with self._writing:
            if self._closed:
                raise DeaError(ErrorCode.INVALID_STATE)
            try:
                if message.kind == "request" and message.operation == "session_terminate":
                    self._expected_eof = True
                self._writer.write(data)
                await self._writer.drain()
            except (ConnectionError, OSError) as exc:
                raise DeaError(ErrorCode.PROTOCOL_ERROR) from exc

    async def _close(self) -> None:
        self._closed = True
        self._writer.close()
        if self._task and self._task is not asyncio.current_task():
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        try:
            await self._writer.wait_closed()
        except (OSError, ConnectionError):
            pass
        self._changed.set()

    async def close(self) -> None:
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close(), name="dea-helper-cleanup")
        try:
            await asyncio.shield(self._close_task)
        except asyncio.CancelledError:
            await asyncio.shield(self._close_task)
            raise
