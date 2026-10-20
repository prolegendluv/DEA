"""WP1 scaffold. Reader tasks must never wait for command acknowledgement.

spawn selects pipes or an explicitly supported terminal backend. Establish
ownership before executing child code. close drains, joins, closes and reaps;
it must be idempotent under cancellation and concurrent shutdown.
"""
from dea.contracts.models import DeaError, ErrorCode, ProcessSpec, RuntimeLimits
from dea.contracts.services import ManagedProcess


class AsyncProcessManager:
    def __init__(self, limits: RuntimeLimits) -> None:
        self.limits = limits

    async def spawn(self, spec: ProcessSpec) -> ManagedProcess:
        raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    async def close(self) -> None:
        # This scaffold has never created resources.
        return None

