"""WP3 scaffold; never derive future deltas from a compact response."""
from dea.contracts.compact import CompactDebugState, InspectionPage
from dea.contracts.models import DeaError, ErrorCode, RawMemoryDiff, RawSnapshot, RuntimeLimits
from dea.contracts.services import Clock
from dea.contracts.wire import WireGuard


class StateEngine:
    def __init__(self, limits: RuntimeLimits, clock: Clock, guard: WireGuard) -> None:
        self.limits, self.clock, self.guard = limits, clock, guard

    async def record(self, snapshot: RawSnapshot, event_id: int, hint: bool = False) -> CompactDebugState:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def page(self, session_id: str, cursor_id: str) -> InspectionPage:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def inspect(self, session_id: str, stop_id: int, value_json: str) -> InspectionPage:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def memory_diff(self, session_id: str, since_step_id: int) -> RawMemoryDiff:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def close_session(self, session_id: str) -> None:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

