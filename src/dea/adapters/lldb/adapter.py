"""Contract-only supervisor for LLDB's independent response and event streams."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
import json

from dea.contracts.adapter import AdapterContext, BaseDebuggerAdapter
from dea.contracts.models import (
    AdapterCapabilities, AttachSpec, Backend, Breakpoint, BreakpointSpec,
    CaptureRequest, CommandAck, DebuggerEvent, DeaError, ErrorCode, HelperMessage,
    LaunchSpec, MemoryRead, MemoryRegion, ProcessSpec, RawFrame, RawSnapshot,
    RawValue, StepMode, TerminationPolicy,
)
from .discovery import HELPER, candidate, discover


class LldbAdapter(BaseDebuggerAdapter):
    backend = Backend.LLDB

    def __init__(self, context: AdapterContext):
        super().__init__(context)
        self._interpreter = candidate()
        self._process = self._reader = self._drainer = None
        self._pending = {}
        self._next_request = 2
        self._last_event = 0
        self._events = asyncio.Queue(context.limits.control_events)
        self._changed = asyncio.Event()
        self._closed = self._terminal = self._attached = self._reading = False
        self._error = self._cleanup_task = None

    def capabilities(self) -> AdapterCapabilities:
        available = self._interpreter is not None
        return AdapterCapabilities(backend=Backend.LLDB, available=available,
            launch=available, attach=available, interrupt=available,
            registers=available, memory_read=available, terminal=False)

    async def events(self) -> AsyncIterator[DebuggerEvent]:
        if self._reading:
            raise DeaError(ErrorCode.INVALID_STATE, "Only one event subscriber")
        self._reading = True
        while True:
            if not self._events.empty():
                yield self._events.get_nowait()
            elif self._error:
                raise self._error
            elif self._closed or self._terminal:
                return
            else:
                self._changed.clear()
                await self._changed.wait()

    async def _start_helper(self):
        if self._closed or self._process:
            raise DeaError(ErrorCode.INVALID_STATE)
        if self._interpreter is None:
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE, "LLDB Python bindings/ABI unavailable")
        try:
            async with asyncio.timeout(self.context.limits.startup_seconds):
                self._interpreter = await asyncio.to_thread(discover)
                if self._interpreter is None:
                    raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE, "LLDB Python ABI probe failed")
                argv = [self._interpreter.executable, "-I", str(HELPER),
                        "--session-id", self.context.session_id,
                        "--max-bytes", str(self.context.limits.protocol_bytes)]
                if self._interpreter.module_path:
                    argv.extend(["--module-path", self._interpreter.module_path])
                self._process = await self.context.runtime.spawn(
                    ProcessSpec(argv=tuple(argv), helper_control=True))
            if self._process.control is None:
                raise DeaError(ErrorCode.PROTOCOL_ERROR, "Missing helper channel")
            self._reader = asyncio.create_task(self._pump(), name="dea-lldb-control")
            self._drainer = asyncio.create_task(self._drain(), name="dea-lldb-output")
        except TimeoutError as exc:
            await self._cleanup()
            raise DeaError(ErrorCode.STARTUP_TIMEOUT) from exc
        except BaseException:
            await self._cleanup()
            raise

    async def _drain(self):
        try:
            async for _ in self._process.read():
                pass  # Never interpret program output as debugger protocol.
        except asyncio.CancelledError:
            raise
        except Exception:
            self._fail(DeaError(ErrorCode.PROTOCOL_ERROR, "Helper output channel failed"))

    def _fail(self, error):
        if self._closed or self._error:
            return
        self._error = error
        for _, future in self._pending.values():
            if not future.done():
                future.set_exception(error)
        self._changed.set()

    async def _pump(self):
        try:
            async for message in self._process.control.messages():
                message = HelperMessage.model_validate_json(message.model_dump_json())
                if message.kind == "event":
                    if message.operation != "debugger_event":
                        raise DeaError(ErrorCode.PROTOCOL_ERROR)
                    event = DebuggerEvent.model_validate_json(message.body_json)
                    if event.event_id != message.event_id or event.event_id <= self._last_event:
                        raise DeaError(ErrorCode.PROTOCOL_ERROR, "Event correlation")
                    self._last_event = event.event_id
                    self._terminal = event.kind in ("exited", "failed")
                    try:
                        self._events.put_nowait(event)
                    except asyncio.QueueFull as exc:
                        raise DeaError(ErrorCode.CONTROL_OVERFLOW) from exc
                    self._changed.set()
                    continue
                if message.kind != "response" or message.request_id < 2:
                    raise DeaError(ErrorCode.PROTOCOL_ERROR)
                entry = self._pending.get(message.request_id)
                if entry is None:
                    if message.request_id >= self._next_request:
                        raise DeaError(ErrorCode.PROTOCOL_ERROR, "Unissued response")
                    continue  # A timed-out command cannot satisfy a later request.
                operation, future = entry
                if future.done():
                    raise DeaError(ErrorCode.PROTOCOL_ERROR, "Duplicate response")
                if message.operation == "error":
                    body = json.loads(message.body_json)
                    if set(body) != {"code"}:
                        raise DeaError(ErrorCode.PROTOCOL_ERROR)
                    future.set_exception(DeaError(ErrorCode(body["code"])))
                elif message.operation != operation:
                    raise DeaError(ErrorCode.PROTOCOL_ERROR, "Operation correlation")
                else:
                    if operation == "session_terminate" and json.loads(message.body_json) == {}:
                        self._terminal = True  # Helper may close immediately after this reply.
                    future.set_result(message.body_json)
            if not self._closed and not self._terminal:
                raise DeaError(ErrorCode.PROTOCOL_ERROR, "Unexpected helper EOF")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._fail(exc if isinstance(exc, DeaError) else DeaError(ErrorCode.PROTOCOL_ERROR))
            if self._process:
                await self._process.close()

    async def _request(self, operation, body, result_type):
        if self._error:
            raise self._error
        if self._closed or not self._process:
            raise DeaError(ErrorCode.INVALID_STATE)
        if self._next_request > 2**63 - 1 or len(self._pending) >= self.context.limits.control_events:
            raise DeaError(ErrorCode.RESOURCE_LIMIT)
        request_id = self._next_request
        self._next_request += 1
        future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = (operation, future)
        body_json = body.model_dump_json() if hasattr(body, "model_dump_json") else json.dumps(body)
        try:
            async with asyncio.timeout(self.context.limits.command_seconds):
                await self._process.control.send(HelperMessage(kind="request", request_id=request_id,
                    operation=operation, body_json=body_json))
                payload = await future
            if result_type is None:
                if json.loads(payload) != {}:
                    raise ValueError("Nonempty termination response")
                return None
            result = result_type.model_validate_json(payload)
            if isinstance(result, CommandAck) and result.request_id != request_id:
                raise ValueError("Acknowledgement correlation")
            if isinstance(result, RawSnapshot) and result.session_id != self.context.session_id:
                raise ValueError("Snapshot session correlation")
            if isinstance(result, RawSnapshot) and (
                    result.stop_id != body.stop_id or result.reason is not body.reason
                    or tuple(read.region for read in result.memory) != body.memory_regions):
                raise ValueError("Snapshot request correlation")
            if isinstance(result, MemoryRead) and result.region != body:
                raise ValueError("Memory request correlation")
            if isinstance(result, RawFrame) and result.index != body["frame_index"]:
                raise ValueError("Frame request correlation")
            return result
        except TimeoutError as exc:
            raise DeaError(ErrorCode.COMMAND_TIMEOUT) from exc
        except (ValueError, TypeError) as exc:
            error = DeaError(ErrorCode.PROTOCOL_ERROR)
            self._fail(error)
            raise error from exc
        finally:
            self._pending.pop(request_id, None)
            if not future.done():
                future.cancel()

    async def session_start(self, spec: LaunchSpec) -> CommandAck:
        if spec.backend is not self.backend:
            raise DeaError(ErrorCode.INVALID_REQUEST)
        if spec.io_mode != "capture":
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE, "Separate LLDB target PTY unavailable")
        await self._start_helper()
        try:
            return await self._request("session_start", spec, CommandAck)
        except BaseException:
            await self._cleanup()
            raise

    async def session_attach(self, spec: AttachSpec) -> CommandAck:
        if spec.backend is not self.backend:
            raise DeaError(ErrorCode.INVALID_REQUEST)
        self._attached = True
        await self._start_helper()
        try:
            return await self._request("session_attach", spec, CommandAck)
        except BaseException:
            await self._cleanup()
            raise

    async def breakpoint_set(self, spec: BreakpointSpec) -> Breakpoint:
        return await self._request("breakpoint_set", spec, Breakpoint)

    async def execution_continue(self) -> CommandAck:
        return await self._request("execution_continue", {}, CommandAck)

    async def execution_step(self, mode: StepMode) -> CommandAck:
        return await self._request("execution_step", {"mode": mode.value}, CommandAck)

    async def execution_interrupt(self) -> CommandAck:
        return await self._request("execution_interrupt", {}, CommandAck)

    async def snapshot_capture(self, request: CaptureRequest) -> RawSnapshot:
        return await self._request("snapshot_capture", request, RawSnapshot)

    async def state_inspect_frame(self, frame_index: int, max_depth: int) -> RawFrame:
        return await self._request("state_inspect_frame", {"frame_index": frame_index,
            "max_depth": max_depth}, RawFrame)

    async def state_eval_expression(self, expr: str) -> RawValue:
        return await self._request("state_eval_expression", {"expr": expr}, RawValue)

    async def state_read_memory(self, region: MemoryRegion) -> MemoryRead:
        return await self._request("state_read_memory", region, MemoryRead)

    async def _cleanup(self):
        self._closed = True
        self._changed.set()
        for _, future in self._pending.values():
            if not future.done():
                future.set_exception(DeaError(ErrorCode.INVALID_STATE))
        if self._process:
            await self._process.close()
        tasks = [t for t in (self._reader, self._drainer)
                 if t and t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def session_terminate(self, policy: TerminationPolicy) -> None:
        if self._closed:
            return
        if self._attached and policy is not TerminationPolicy.DETACH:
            raise DeaError(ErrorCode.INVALID_REQUEST, "Attached target must be detached")
        error = None
        try:
            if self._process and not self._terminal:
                await self._request("session_terminate", {"policy": policy.value}, None)
        except BaseException as exc:
            error = exc
        finally:
            if self._cleanup_task is None:
                self._cleanup_task = asyncio.create_task(self._cleanup())
            try:
                await asyncio.shield(self._cleanup_task)
            except asyncio.CancelledError:
                await asyncio.shield(self._cleanup_task)
                raise
        if error:
            if self._attached and isinstance(error, Exception):
                raise DeaError(ErrorCode.DETACH_FAILED) from error
            raise error
