"""Architect-owned composition root. Workers keep these constructor contracts."""
import asyncio
import time
from dataclasses import dataclass
from types import MappingProxyType

from dea.adapters.gdb import GdbAdapter
from dea.adapters.lldb import LldbAdapter
from dea.adapters.pdb import PdbAdapter
from dea.contracts.models import Backend, RuntimeLimits
from dea.contracts.services import Clock, ProcessManager, SessionService, StateService
from dea.contracts.wire import WireGuard
from dea.runtime import AsyncProcessManager
from dea.sessions import SessionManager
from dea.state import StateEngine

ADAPTER_FACTORIES = MappingProxyType({
    Backend.GDB: GdbAdapter, Backend.LLDB: LldbAdapter, Backend.PDB: PdbAdapter,
})


class SystemClock:
    def now(self) -> float:
        return time.monotonic()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


@dataclass(frozen=True)
class Application:
    runtime: ProcessManager
    state: StateService
    sessions: SessionService
    guard: WireGuard

    async def close(self) -> None:
        try:
            await self.sessions.close()
        finally:
            await self.runtime.close()


def build_application(*, runtime: ProcessManager | None = None,
                      state: StateService | None = None,
                      sessions: SessionService | None = None,
                      clock: Clock | None = None,
                      limits: RuntimeLimits | None = None) -> Application:
    limits = limits if limits is not None else RuntimeLimits()
    clock = clock if clock is not None else SystemClock()
    guard = WireGuard()
    runtime = runtime if runtime is not None else AsyncProcessManager(limits)
    state = state if state is not None else StateEngine(limits, clock, guard)
    sessions = sessions if sessions is not None else SessionManager(runtime, state, ADAPTER_FACTORIES, clock, limits)
    return Application(runtime, state, sessions, guard)

