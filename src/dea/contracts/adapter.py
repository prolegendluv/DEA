"""Frozen adapter interface; concrete adapters own debugger-specific behavior."""
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import NoReturn

from .models import (
    AdapterCapabilities, AttachSpec, Breakpoint, BreakpointSpec, CaptureRequest,
    CommandAck, DebuggerEvent, DeaError, ErrorCode, LaunchSpec, MemoryRead,
    MemoryRegion, RawFrame, RawMemoryDiff, RawSnapshot, RawValue, RuntimeLimits,
    StepMode, TerminationPolicy,
)
from .services import Clock, MemoryHistory, ProcessManager


@dataclass(frozen=True)
class AdapterContext:
    session_id: str
    runtime: ProcessManager
    history: MemoryHistory
    clock: Clock
    limits: RuntimeLimits


class BaseDebuggerAdapter(ABC):
    def __init__(self, context: AdapterContext) -> None:
        self.context = context

    @abstractmethod
    def capabilities(self) -> AdapterCapabilities: ...

    @abstractmethod
    def events(self) -> AsyncIterator[DebuggerEvent]: ...

    @abstractmethod
    async def session_start(self, spec: LaunchSpec) -> CommandAck: ...

    @abstractmethod
    async def session_attach(self, spec: AttachSpec) -> CommandAck: ...

    @abstractmethod
    async def breakpoint_set(self, spec: BreakpointSpec) -> Breakpoint: ...

    @abstractmethod
    async def execution_continue(self) -> CommandAck: ...

    @abstractmethod
    async def execution_step(self, mode: StepMode) -> CommandAck: ...

    @abstractmethod
    async def execution_interrupt(self) -> CommandAck: ...

    @abstractmethod
    async def snapshot_capture(self, request: CaptureRequest) -> RawSnapshot: ...

    @abstractmethod
    async def state_inspect_frame(self, frame_index: int, max_depth: int) -> RawFrame: ...

    @abstractmethod
    async def state_eval_expression(self, expr: str) -> RawValue: ...

    @abstractmethod
    async def state_read_memory(self, region: MemoryRegion) -> MemoryRead: ...

    async def state_memory_diff(self, since_step_id: int) -> RawMemoryDiff:
        if not self.capabilities().memory_read:
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)
        return await self.context.history.memory_diff(self.context.session_id, since_step_id)

    @abstractmethod
    async def session_terminate(self, policy: TerminationPolicy) -> None: ...


class UnimplementedAdapter(BaseDebuggerAdapter):
    """Honest placeholder used until a worker implements its adapter."""
    backend = None

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(backend=self.backend)

    def _unimplemented(self) -> NoReturn:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def events(self) -> AsyncIterator[DebuggerEvent]:
        self._unimplemented()
        yield  # pragma: no cover - establishes async-iterator shape

    async def session_start(self, spec: LaunchSpec) -> CommandAck:
        self._unimplemented()

    async def session_attach(self, spec: AttachSpec) -> CommandAck:
        self._unimplemented()

    async def breakpoint_set(self, spec: BreakpointSpec) -> Breakpoint:
        self._unimplemented()

    async def execution_continue(self) -> CommandAck:
        self._unimplemented()

    async def execution_step(self, mode: StepMode) -> CommandAck:
        self._unimplemented()

    async def execution_interrupt(self) -> CommandAck:
        self._unimplemented()

    async def snapshot_capture(self, request: CaptureRequest) -> RawSnapshot:
        self._unimplemented()

    async def state_inspect_frame(self, frame_index: int, max_depth: int) -> RawFrame:
        self._unimplemented()

    async def state_eval_expression(self, expr: str) -> RawValue:
        self._unimplemented()

    async def state_read_memory(self, region: MemoryRegion) -> MemoryRead:
        self._unimplemented()

    async def session_terminate(self, policy: TerminationPolicy) -> None:
        self._unimplemented()

