"""Scripted observations and explicit scheduling; never launch real targets."""
import asyncio
from collections.abc import AsyncIterator

from dea.contracts.adapter import AdapterContext, UnimplementedAdapter
from dea.contracts.compact import AckResponse, CapabilitiesResponse, ErrorResponse, ToolResponse
from dea.contracts.models import (
    AdapterCapabilities, AttachSpec, Backend, Breakpoint, BreakpointSpec,
    CaptureRequest, CommandAck, DebuggerEvent, DeaError, ErrorCode, HelperMessage, LaunchSpec,
    ProcessChunk, ProcessSpec, RawMemoryDiff, RawSnapshot, StepMode,
    TerminationPolicy,
)

SID = "0123456789abcdef"


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleepers: list[tuple[float, asyncio.Future]] = []

    def now(self) -> float:
        return self.value

    async def sleep(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("Negative sleep")
        if seconds == 0:
            await asyncio.sleep(0)
            return
        future = asyncio.get_running_loop().create_future()
        entry = (self.value + seconds, future)
        self.sleepers.append(entry)
        try:
            await future
        finally:
            self.sleepers.remove(entry)

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("Clock cannot go backwards")
        self.value += seconds
        for deadline, future in tuple(self.sleepers):
            if deadline <= self.value and not future.done():
                future.set_result(None)


class FakeHelperConnection:
    def __init__(self) -> None:
        self.queue: asyncio.Queue[HelperMessage | None] = asyncio.Queue(256)
        self.sent: list[HelperMessage] = []
        self.closed = False

    def feed(self, message: HelperMessage) -> None:
        if self.closed:
            raise DeaError(ErrorCode.INVALID_STATE)
        try:
            self.queue.put_nowait(message)
        except asyncio.QueueFull as exc:
            raise DeaError(ErrorCode.CONTROL_OVERFLOW) from exc

    async def messages(self) -> AsyncIterator[HelperMessage]:
        while not (self.closed and self.queue.empty()):
            message = await self.queue.get()
            if message is None:
                return
            yield message

    async def send(self, message: HelperMessage) -> None:
        if self.closed:
            raise DeaError(ErrorCode.INVALID_STATE)
        self.sent.append(message)

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            if not self.queue.full():
                self.queue.put_nowait(None)


class FakeProcess:
    def __init__(self, pid: int = 100, capacity: int = 256, helper_control: bool = False) -> None:
        self._pid = pid
        self.queue: asyncio.Queue[ProcessChunk | None] = asyncio.Queue(capacity)
        self.writes: list[bytes] = []
        self.interrupts = 0
        self.closed = False
        self.returncode: int | None = None
        self._exited = asyncio.Event()
        self._reading = False
        self._control = FakeHelperConnection() if helper_control else None

    @property
    def pid(self) -> int:
        return self._pid

    @property
    def control(self) -> FakeHelperConnection | None:
        return self._control

    def feed(self, data: bytes, stream: str = "stdout") -> None:
        if self.closed:
            raise DeaError(ErrorCode.INVALID_STATE)
        try:
            self.queue.put_nowait(ProcessChunk(stream=stream, data=data))
        except asyncio.QueueFull as exc:
            raise DeaError(ErrorCode.CONTROL_OVERFLOW) from exc

    def finish(self, code: int = 0) -> None:
        self.returncode = code
        self.closed = True
        self._exited.set()
        if not self.queue.full():
            self.queue.put_nowait(None)

    async def read(self) -> AsyncIterator[ProcessChunk]:
        if self._reading:
            raise DeaError(ErrorCode.INVALID_STATE)
        self._reading = True
        while not (self.closed and self.queue.empty()):
            chunk = await self.queue.get()
            if chunk is None:
                break
            yield chunk

    async def write(self, data: bytes) -> None:
        if self.closed:
            raise DeaError(ErrorCode.INVALID_STATE)
        self.writes.append(data)

    async def wait(self) -> int:
        await self._exited.wait()
        assert self.returncode is not None
        return self.returncode

    async def interrupt(self) -> None:
        if self.closed:
            raise DeaError(ErrorCode.INVALID_STATE)
        self.interrupts += 1

    async def close(self) -> None:
        if self._control is not None:
            await self._control.close()
        if not self.closed:
            self.finish(-1)


class FakeProcessManager:
    def __init__(self) -> None:
        self.processes: list[FakeProcess] = []
        self.specs: list[ProcessSpec] = []

    async def spawn(self, spec: ProcessSpec) -> FakeProcess:
        process = FakeProcess(pid=100 + len(self.processes), helper_control=spec.helper_control)
        self.specs.append(spec)
        self.processes.append(process)
        return process

    async def close(self) -> None:
        for process in self.processes:
            await process.close()


class FakeHistory:
    def __init__(self) -> None:
        self.result: RawMemoryDiff | None = None
        self.requests: list[tuple[str, int]] = []

    async def memory_diff(self, session_id: str, since_step_id: int) -> RawMemoryDiff:
        self.requests.append((session_id, since_step_id))
        if self.result is None:
            raise DeaError(ErrorCode.HISTORY_UNAVAILABLE)
        return self.result


class FakeAdapter(UnimplementedAdapter):
    backend = Backend.GDB

    def __init__(self, context: AdapterContext) -> None:
        super().__init__(context)
        self.event_queue: asyncio.Queue[DebuggerEvent | None] = asyncio.Queue(256)
        self.calls: list[str] = []
        self.next_ack = 1
        self.before_ack: DebuggerEvent | None = None
        self.snapshot: RawSnapshot | None = None
        self.termination_policy: TerminationPolicy | None = None

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(backend=self.backend, available=True, launch=True,
                                   attach=True, interrupt=True, registers=True, memory_read=True)

    def emit(self, event: DebuggerEvent) -> None:
        try:
            self.event_queue.put_nowait(event)
        except asyncio.QueueFull as exc:
            raise DeaError(ErrorCode.CONTROL_OVERFLOW) from exc

    async def events(self) -> AsyncIterator[DebuggerEvent]:
        while True:
            event = await self.event_queue.get()
            if event is None:
                return
            yield event

    async def _ack(self, operation: str) -> CommandAck:
        self.calls.append(operation)
        if self.before_ack is not None:
            self.emit(self.before_ack)
            self.before_ack = None
            await asyncio.sleep(0)
        ack = CommandAck(request_id=self.next_ack)
        self.next_ack += 1
        return ack

    async def session_start(self, spec: LaunchSpec) -> CommandAck:
        return await self._ack("start")

    async def session_attach(self, spec: AttachSpec) -> CommandAck:
        return await self._ack("attach")

    async def execution_continue(self) -> CommandAck:
        return await self._ack("continue")

    async def execution_step(self, mode: StepMode) -> CommandAck:
        return await self._ack("step:" + mode.value)

    async def execution_interrupt(self) -> CommandAck:
        return await self._ack("interrupt")

    async def breakpoint_set(self, spec: BreakpointSpec) -> Breakpoint:
        self.calls.append("breakpoint")
        return Breakpoint(breakpoint_id="1", verified=True)

    async def snapshot_capture(self, request: CaptureRequest) -> RawSnapshot:
        if self.snapshot is None:
            raise DeaError(ErrorCode.INVALID_STATE)
        return self.snapshot

    async def session_terminate(self, policy: TerminationPolicy) -> None:
        self.termination_policy = policy
        self.calls.append("terminate")
        await self.event_queue.put(None)


class FakeSessions:
    """Minimal persistent service for testing the real MCP boundary."""
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.started = False
        self.closed = False
        self.next_request = 1

    async def _call(self, operation: str, argument: object) -> ToolResponse:
        self.calls.append((operation, argument))
        if operation not in ("start", "attach") and not self.started:
            raise DeaError(ErrorCode.SESSION_NOT_FOUND)
        if operation in ("start", "attach"):
            self.started = True
        result = AckResponse(session_id=SID, request_id=self.next_request)
        self.next_request += 1
        return result

    async def session_start(self, spec: LaunchSpec) -> ToolResponse:
        return await self._call("start", spec)

    async def session_attach(self, spec: AttachSpec) -> ToolResponse:
        return await self._call("attach", spec)

    async def breakpoint_set(self, session_id: str, spec: BreakpointSpec) -> ToolResponse:
        return await self._call("breakpoint", (session_id, spec))

    async def execution_continue(self, session_id: str) -> ToolResponse:
        return await self._call("continue", session_id)

    async def execution_step(self, session_id: str, mode: StepMode) -> ToolResponse:
        return await self._call("step", (session_id, mode))

    async def execution_interrupt(self, session_id: str) -> ToolResponse:
        return await self._call("interrupt", session_id)

    async def state_inspect_frame(self, session_id: str, frame_index: int, max_depth: int) -> ToolResponse:
        return await self._call("frame", (session_id, frame_index, max_depth))

    async def state_eval_expression(self, session_id: str, expr: str) -> ToolResponse:
        return await self._call("eval", (session_id, expr))

    async def state_memory_diff(self, session_id: str, since_step_id: int) -> ToolResponse:
        return await self._call("memory", (session_id, since_step_id))

    async def session_wait(self, session_id: str, after_event_id: int, timeout_ms: int) -> ToolResponse:
        self.calls.append(("wait", (session_id, after_event_id, timeout_ms)))
        return ErrorResponse(code=ErrorCode.WAIT_TIMEOUT)

    async def state_page(self, session_id: str, cursor_id: str) -> ToolResponse:
        return ErrorResponse(code=ErrorCode.CURSOR_EXPIRED)

    async def session_capabilities(self, session_id: str) -> ToolResponse:
        return CapabilitiesResponse(capabilities=AdapterCapabilities(backend=Backend.GDB))

    async def session_terminate(self, session_id: str) -> ToolResponse:
        result = await self._call("terminate", session_id)
        self.started = False
        return result

    async def close(self) -> None:
        self.closed = True

