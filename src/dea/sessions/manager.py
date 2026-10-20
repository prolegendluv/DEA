"""WP2 scaffold. Inspect only stopped targets; never hold a lock awaiting a stop.

Subscribe before execution; accept stop-before-ack ordering. Journal events
with session-local sequence numbers. Eight consecutive steps without a watched
value divergence or breakpoint/watchpoint produce the set_breakpoint hint.
"""
from collections.abc import Callable, Mapping
from types import MappingProxyType

from dea.contracts.adapter import AdapterContext, BaseDebuggerAdapter
from dea.contracts.compact import ToolResponse
from dea.contracts.models import (
    AttachSpec, Backend, BreakpointSpec, DeaError, ErrorCode, LaunchSpec,
    RuntimeLimits, StepMode,
)
from dea.contracts.services import Clock, ProcessManager, StateService

AdapterFactory = Callable[[AdapterContext], BaseDebuggerAdapter]


class SessionManager:
    def __init__(self, runtime: ProcessManager, state: StateService,
                 adapters: Mapping[Backend, AdapterFactory], clock: Clock,
                 limits: RuntimeLimits) -> None:
        self.runtime, self.state = runtime, state
        self.adapters = MappingProxyType(dict(adapters))
        self.clock, self.limits = clock, limits

    async def session_start(self, spec: LaunchSpec) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def session_attach(self, spec: AttachSpec) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def breakpoint_set(self, session_id: str, spec: BreakpointSpec) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def execution_continue(self, session_id: str) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def execution_step(self, session_id: str, mode: StepMode) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def execution_interrupt(self, session_id: str) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def state_inspect_frame(self, session_id: str, frame_index: int, max_depth: int) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def state_eval_expression(self, session_id: str, expr: str) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def state_memory_diff(self, session_id: str, since_step_id: int) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def session_wait(self, session_id: str, after_event_id: int, timeout_ms: int) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def state_page(self, session_id: str, cursor_id: str) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def session_capabilities(self, session_id: str) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def session_terminate(self, session_id: str) -> ToolResponse:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def close(self) -> None:
        # No sessions have been created by this scaffold.
        return None

