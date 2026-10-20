"""Session policy, independent debugger events and bounded event history."""
import asyncio
import contextlib
import secrets
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from dea.contracts.adapter import AdapterContext, BaseDebuggerAdapter
from dea.contracts.compact import (
    AckResponse, CapabilitiesResponse, CompactDebugState, ErrorResponse,
    LifecycleResponse, ToolResponse,
)
from dea.contracts.models import (
    MAX_INT, AttachSpec, Backend, BreakpointSpec, CaptureRequest, DeaError,
    ErrorCode, LaunchSpec, RawSnapshot, RuntimeLimits, SessionPhase, StepMode,
    StopReason, TerminationPolicy,
)
from dea.contracts.services import Clock, ProcessManager, StateService

AdapterFactory = Callable[[AdapterContext], BaseDebuggerAdapter]
_TERMINAL = (SessionPhase.TERMINATED, SessionPhase.FAILED)


@dataclass
class _Entry:
    eid: int
    response: ToolResponse | None = None
    size: int = 0


@dataclass
class _Session:
    sid: str
    adapter: BaseDebuggerAdapter
    spec: LaunchSpec | AttachSpec
    owned: bool
    phase: SessionPhase = SessionPhase.STARTING
    eid: int = 0
    stop: int = 0
    source_eid: int = 0
    generation: int = 0
    steps: int = 0
    pending_step: bool = False
    last_reason: StopReason = StopReason.ENTRY
    watched: dict[str, str] = field(default_factory=dict)
    watched_context: tuple[int, str] | None = None
    journal: deque = field(default_factory=deque)
    journal_bytes: int = 0
    evicted_through: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    listening: asyncio.Event = field(default_factory=asyncio.Event)
    reader: asyncio.Task | None = None
    capture: asyncio.Task | None = None
    command: asyncio.Task | None = None
    cleanup: asyncio.Task | None = None
    terminate_ack: AckResponse | None = None
    next_rid: int = 0
    termination: asyncio.Task | None = None
    evicted: bool = False
    recovering: bool = False


class SessionManager:
    def __init__(self, runtime: ProcessManager, state: StateService,
                 adapters: Mapping[Backend, AdapterFactory], clock: Clock,
                 limits: RuntimeLimits) -> None:
        self.runtime, self.state = runtime, state
        self.adapters = MappingProxyType(dict(adapters))
        self.clock, self.limits = clock, limits
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._registry_lock = asyncio.Lock()
        self._closed = False
        self._closing = None

    def _get(self, sid):
        try:
            return self._sessions[sid]
        except KeyError:
            raise DeaError(ErrorCode.SESSION_NOT_FOUND) from None

    @staticmethod
    def _cancel(task):
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()
            task.add_done_callback(SessionManager._consume)

    @staticmethod
    def _consume(task):
        if not task.cancelled():
            task.exception()

    async def _deadline(self, awaitable, seconds, code):
        task = asyncio.ensure_future(awaitable)
        timer = asyncio.create_task(self.clock.sleep(seconds))
        try:
            done, _ = await asyncio.wait((task, timer), return_when=asyncio.FIRST_COMPLETED)
            if task in done:
                return task.result()
            self._cancel(task)
            raise DeaError(code)
        except BaseException:
            self._cancel(task)
            raise
        finally:
            self._cancel(timer)

    def _ack(self, s, breakpoint_id=None):
        if s.next_rid == MAX_INT:
            raise DeaError(ErrorCode.RESOURCE_LIMIT)
        s.next_rid += 1
        return AckResponse(session_id=s.sid, request_id=s.next_rid, breakpoint_id=breakpoint_id)

    def _entry(self, s):
        if s.eid == MAX_INT:
            raise DeaError(ErrorCode.RESOURCE_LIMIT)
        s.eid += 1
        entry = _Entry(s.eid)
        s.journal.append(entry)
        self._trim(s)
        s.changed.set()
        return entry

    def _trim(self, s):
        while (len(s.journal) > self.limits.control_events or
               s.journal_bytes > self.limits.history_bytes):
            old = s.journal.popleft()
            s.journal_bytes -= old.size
            s.evicted_through = old.eid

    def _publish(self, s, entry, response):
        # Capture can complete after a terminal event. Never publish that stale stop.
        if entry.response is not None:
            return
        entry.response = response
        entry.size = len(response.model_dump_json(by_alias=True, exclude_none=True).encode())
        if entry in s.journal:
            s.journal_bytes += entry.size
            self._trim(s)
        s.changed.set()

    def _lifecycle(self, s, exit_code=None):
        entry = self._entry(s)
        self._publish(s, entry, LifecycleResponse(session_id=s.sid, event_id=entry.eid,
                                                 phase=s.phase, exit_code=exit_code))

    async def _cleanup_adapter(self, s):
        policy = TerminationPolicy.TERMINATE_OWNED if s.owned else TerminationPolicy.DETACH
        try:
            await self._deadline(s.adapter.session_terminate(policy), self.limits.command_seconds,
                                 ErrorCode.COMMAND_TIMEOUT if s.owned else ErrorCode.DETACH_FAILED)
        except Exception as exc:
            if not s.owned:
                raise DeaError(ErrorCode.DETACH_FAILED) from exc
            raise
        finally:
            self._cancel(s.reader)
            self._cancel(s.capture)
            await asyncio.gather(*(task for task in (s.reader, s.capture)
                                   if task is not None and task is not asyncio.current_task()),
                                 return_exceptions=True)

    async def _cleanup(self, s):
        if s.cleanup is None:
            s.cleanup = asyncio.create_task(self._cleanup_adapter(s))
        await asyncio.shield(s.cleanup)

    async def _fail(self, s, code):
        if s.phase in _TERMINAL:
            return
        s.phase = SessionPhase.FAILED
        s.generation += 1
        s.recovering = False
        self._cancel(s.command)
        self._cancel(s.capture)
        for entry in tuple(s.journal):
            if entry.response is None:
                self._publish(s, entry, ErrorResponse(code=code, session_id=s.sid))
        entry = self._entry(s)
        self._publish(s, entry, ErrorResponse(code=code, session_id=s.sid))
        s.ready.set()
        try:
            await self._cleanup(s)
        except DeaError as exc:
            if exc.code is ErrorCode.DETACH_FAILED:
                entry = self._entry(s)
                self._publish(s, entry, ErrorResponse(code=exc.code, session_id=s.sid))
        except Exception:
            pass

    async def _listen(self, s):
        try:
            stream = s.adapter.events()
            # Prime the first read before allowing the launch command to run.
            pending = asyncio.create_task(anext(stream))
            await asyncio.sleep(0)
            s.listening.set()
            try:
                while True:
                    event = await pending
                    if event.event_id <= s.source_eid:
                        raise DeaError(ErrorCode.PROTOCOL_ERROR)
                    s.source_eid = event.event_id
                    if s.phase in _TERMINAL or s.phase is SessionPhase.TERMINATING:
                        return
                    if event.kind == "stopped":
                        if s.capture is not None and not s.capture.done():
                            raise DeaError(ErrorCode.CONTROL_OVERFLOW)
                        s.phase = SessionPhase.STOPPED
                        s.ready.clear()
                        entry = self._entry(s)
                        s.capture = asyncio.create_task(self._capture(s, event.reason, entry))
                    elif event.kind == "exited":
                        s.phase = SessionPhase.TERMINATED
                        s.generation += 1
                        self._cancel(s.capture)
                        for entry in tuple(s.journal):
                            if entry.response is None:
                                self._publish(s, entry, ErrorResponse(code=ErrorCode.INVALID_STATE, session_id=s.sid))
                        s.ready.set()
                        self._lifecycle(s, event.exit_code)
                        with contextlib.suppress(Exception):
                            await self._cleanup(s)
                        return
                    elif event.kind == "failed":
                        await self._fail(s, event.error_code)
                        return
                    elif event.kind == "running":
                        if s.capture is not None and not s.capture.done():
                            raise DeaError(ErrorCode.PROTOCOL_ERROR)
                        s.phase = SessionPhase.RUNNING
                        s.ready.clear()
                        self._lifecycle(s)
                    elif event.kind == "started":
                        self._lifecycle(s)
                    pending = asyncio.create_task(anext(stream))
            finally:
                self._cancel(pending)
                with contextlib.suppress(Exception):
                    await stream.aclose()
        except asyncio.CancelledError:
            raise
        except StopAsyncIteration:
            if s.phase not in _TERMINAL and s.phase is not SessionPhase.TERMINATING:
                await self._fail(s, ErrorCode.PROTOCOL_ERROR)
        except Exception as exc:
            await self._fail(s, exc.code if isinstance(exc, DeaError) else ErrorCode.INTERNAL_ERROR)
        finally:
            s.listening.set()

    async def _capture(self, s, reason, entry):
        try:
            if s.stop == MAX_INT:
                raise DeaError(ErrorCode.RESOURCE_LIMIT)
            s.stop += 1
            snapshot = await self._deadline(s.adapter.snapshot_capture(CaptureRequest(
                stop_id=s.stop, reason=reason, memory_regions=s.spec.memory_regions)),
                self.limits.command_seconds, ErrorCode.COMMAND_TIMEOUT)
            if snapshot.session_id != s.sid or snapshot.stop_id != s.stop or snapshot.reason is not reason:
                raise DeaError(ErrorCode.PROTOCOL_ERROR)
            if s.phase is not SessionPhase.STOPPED:
                return
            s.last_reason = reason
            context = (snapshot.thread_id, snapshot.frame_context)
            if s.watched_context != context:
                s.watched.clear()
                s.watched_context = context
            watched = {v.identity: v.value for v in snapshot.variables if v.watched and v.available}
            divergence = any(identity in s.watched and s.watched[identity] != value
                             for identity, value in watched.items())
            if reason in (StopReason.BREAKPOINT, StopReason.WATCHPOINT) or divergence:
                s.steps = 0
            elif s.pending_step:
                s.steps += 1
            s.pending_step = False
            # Missing observations prove removal only with complete coverage.
            # Keep prior exact values across partial captures within the same scope.
            retained = {} if snapshot.variables_complete else dict(s.watched)
            for value in snapshot.variables:
                if value.watched:
                    known = value.value if value.available else s.watched.get(value.identity)
                    if known is not None:
                        retained[value.identity] = known
            if sum(len(k.encode()) + len(v.encode()) for k, v in retained.items()) > self.limits.history_bytes:
                raise DeaError(ErrorCode.HISTORY_UNAVAILABLE)
            s.watched = retained
            response = await self.state.record(snapshot, entry.eid, hint=s.steps >= 8)
            self._publish(s, entry, response)
            s.ready.set()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self._fail(s, exc.code if isinstance(exc, DeaError) else ErrorCode.INTERNAL_ERROR)

    async def _create(self, spec, owned):
        async with self._registry_lock:
            if self._closed:
                raise DeaError(ErrorCode.INVALID_STATE)
            if len(self._sessions) >= self.limits.maximum_sessions:
                victim = next((x for x in self._sessions.values() if x.phase in _TERMINAL), None)
                if victim is None:
                    raise DeaError(ErrorCode.RESOURCE_LIMIT)
                await self.state.close_session(victim.sid)
                victim.evicted = True
                victim.changed.set()
                del self._sessions[victim.sid]
            while True:
                sid = secrets.token_hex(8)
                if sid not in self._sessions:
                    break
            factory = self.adapters.get(spec.backend)
            if factory is None:
                raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)
            adapter = factory(AdapterContext(sid, self.runtime, self.state, self.clock, self.limits))
            caps = adapter.capabilities()
            if not caps.available:
                raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)
            if not (caps.launch if owned else caps.attach):
                raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)
            if owned and spec.io_mode == "pty" and not caps.terminal:
                raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)
            s = _Session(sid, adapter, spec, owned)
            self._sessions[sid] = s
            s.reader = asyncio.create_task(self._listen(s))
        try:
            await s.listening.wait()
            if s.phase in _TERMINAL:
                raise DeaError(ErrorCode.INVALID_STATE)
            operation = adapter.session_start(spec) if owned else adapter.session_attach(spec)
            async with s.lock:
                await self._command(s, operation, startup=True)
            return self._ack(s)
        except BaseException as exc:
            await self._fail(s, exc.code if isinstance(exc, DeaError) else ErrorCode.INTERNAL_ERROR)
            raise

    async def session_start(self, spec: LaunchSpec) -> ToolResponse:
        return await self._create(spec, True)

    async def session_attach(self, spec: AttachSpec) -> ToolResponse:
        return await self._create(spec, False)

    async def _recover(self, s):
        s.recovering = True
        baseline_stop = s.stop
        s.ready.clear()
        async def fresh_stop():
            while True:
                await s.ready.wait()
                if s.phase in _TERMINAL:
                    raise DeaError(ErrorCode.INVALID_STATE)
                if s.phase is SessionPhase.STOPPED and s.stop > baseline_stop:
                    return
                s.ready.clear()
        try:
            await self._deadline(s.adapter.execution_interrupt(), self.limits.command_seconds,
                                 ErrorCode.COMMAND_TIMEOUT)
            await self._deadline(fresh_stop(), self.limits.command_seconds, ErrorCode.COMMAND_TIMEOUT)
            if s.phase is not SessionPhase.STOPPED:
                raise DeaError(ErrorCode.INVALID_STATE)
            s.recovering = False
        except Exception:
            await self._fail(s, ErrorCode.COMMAND_TIMEOUT)

    async def _command(self, s, operation, startup=False):
        generation = s.generation
        s.command = asyncio.create_task(operation)
        try:
            result = await self._deadline(s.command,
                self.limits.startup_seconds if startup else self.limits.command_seconds,
                ErrorCode.STARTUP_TIMEOUT if startup else ErrorCode.COMMAND_TIMEOUT)
            if s.generation != generation and s.phase is not SessionPhase.TERMINATED:
                raise DeaError(ErrorCode.INVALID_STATE)
            return result
        except asyncio.CancelledError:
            if s.generation != generation:
                raise DeaError(ErrorCode.INVALID_STATE) from None
            await self._fail(s, ErrorCode.INVALID_STATE)
            raise
        except DeaError as exc:
            if exc.code is ErrorCode.COMMAND_TIMEOUT:
                s.generation += 1
                await self._recover(s)
            raise
        finally:
            s.command = None

    async def _stopped(self, s):
        if s.recovering or s.phase is not SessionPhase.STOPPED:
            raise DeaError(ErrorCode.INVALID_STATE)
        await self._deadline(s.ready.wait(), self.limits.command_seconds, ErrorCode.COMMAND_TIMEOUT)
        if s.phase is not SessionPhase.STOPPED:
            raise DeaError(ErrorCode.INVALID_STATE)

    async def breakpoint_set(self, session_id: str, spec: BreakpointSpec) -> ToolResponse:
        s = self._get(session_id)
        async with s.lock:
            await self._stopped(s)
            bp = await self._command(s, s.adapter.breakpoint_set(spec))
            return self._ack(s, bp.breakpoint_id)

    async def _execute(self, session_id, mode=None):
        s = self._get(session_id)
        async with s.lock:
            await self._stopped(s)
            s.phase = SessionPhase.RUNNING
            s.ready.clear()
            s.pending_step = mode is not None
            operation = s.adapter.execution_continue() if mode is None else s.adapter.execution_step(mode)
            try:
                await self._command(s, operation)
            except Exception:
                if s.phase is SessionPhase.RUNNING and not s.recovering:
                    await self._fail(s, ErrorCode.INVALID_STATE)
                raise
            return self._ack(s)

    async def execution_continue(self, session_id: str) -> ToolResponse:
        return await self._execute(session_id)

    async def execution_step(self, session_id: str, mode: StepMode) -> ToolResponse:
        return await self._execute(session_id, mode)

    async def execution_interrupt(self, session_id: str) -> ToolResponse:
        s = self._get(session_id)
        if s.phase not in (SessionPhase.RUNNING, SessionPhase.STARTING):
            raise DeaError(ErrorCode.INVALID_STATE)
        if not s.adapter.capabilities().interrupt:
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE)
        # Priority lane intentionally bypasses the acceptance/inspection lock.
        try:
            await self._deadline(s.adapter.execution_interrupt(), self.limits.command_seconds,
                                 ErrorCode.COMMAND_TIMEOUT)
        except DeaError as exc:
            if exc.code is ErrorCode.COMMAND_TIMEOUT:
                s.generation += 1
                self._cancel(s.command)
                await self._recover(s)
            raise
        return self._ack(s)

    async def _inspect(self, s, operation):
        value = await self._command(s, operation)
        if s.phase is not SessionPhase.STOPPED:
            raise DeaError(ErrorCode.INVALID_STATE)
        return await self.state.inspect(s.sid, s.stop, value.model_dump_json())

    async def state_inspect_frame(self, session_id: str, frame_index: int, max_depth: int) -> ToolResponse:
        s = self._get(session_id)
        async with s.lock:
            await self._stopped(s)
            return await self._inspect(s, s.adapter.state_inspect_frame(frame_index, max_depth))

    async def state_eval_expression(self, session_id: str, expr: str) -> ToolResponse:
        s = self._get(session_id)
        async with s.lock:
            await self._stopped(s)
            # Evaluation may alter the target even when the adapter raises.
            await self.state.close_session(s.sid)
            try:
                value = await self._command(s, s.adapter.state_eval_expression(expr))
            except BaseException:
                await self._fail(s, ErrorCode.INVALID_STATE)
                raise
            if s.phase is not SessionPhase.STOPPED:
                raise DeaError(ErrorCode.INVALID_STATE)
            # StateService reset above ensures the recapture has no stale baseline.
            s.watched.clear()
            s.steps = 0
            s.ready.clear()
            entry = self._entry(s)
            s.capture = asyncio.create_task(self._capture(s, s.last_reason, entry))
            await self._stopped(s)
            return await self.state.inspect(s.sid, s.stop, value.model_dump_json())

    async def state_memory_diff(self, session_id: str, since_step_id: int) -> ToolResponse:
        s = self._get(session_id)
        async with s.lock:
            await self._stopped(s)
            return await self._inspect(s, s.adapter.state_memory_diff(since_step_id))

    async def session_wait(self, session_id: str, after_event_id: int, timeout_ms: int) -> ToolResponse:
        s = self._get(session_id)
        if not 0 <= after_event_id <= MAX_INT or not 0 <= timeout_ms <= self.limits.maximum_wait_ms:
            raise DeaError(ErrorCode.INVALID_REQUEST)
        async def wait():
            while True:
                s.changed.clear()
                if s.evicted:
                    raise DeaError(ErrorCode.SESSION_NOT_FOUND)
                if after_event_id < s.evicted_through:
                    raise DeaError(ErrorCode.HISTORY_UNAVAILABLE)
                for entry in s.journal:
                    if entry.eid > after_event_id:
                        if entry.response is not None:
                            return entry.response
                        break
                if timeout_ms == 0:
                    return ErrorResponse(code=ErrorCode.WAIT_TIMEOUT, session_id=s.sid)
                await s.changed.wait()
        try:
            return await self._deadline(wait(), timeout_ms / 1000, ErrorCode.WAIT_TIMEOUT)
        except DeaError as exc:
            if exc.code is ErrorCode.WAIT_TIMEOUT:
                return ErrorResponse(code=exc.code, session_id=s.sid)
            raise

    async def state_page(self, session_id: str, cursor_id: str) -> ToolResponse:
        self._get(session_id)
        return await self.state.page(session_id, cursor_id)

    async def session_capabilities(self, session_id: str) -> ToolResponse:
        return CapabilitiesResponse(capabilities=self._get(session_id).adapter.capabilities())

    async def session_terminate(self, session_id: str) -> ToolResponse:
        s = self._get(session_id)
        if s.termination is None:
            s.termination = asyncio.create_task(self._terminate(s))
        return await asyncio.shield(s.termination)

    async def _terminate(self, s):
        if s.terminate_ack is not None:
            return s.terminate_ack
        s.phase = SessionPhase.TERMINATING
        s.generation += 1
        self._cancel(s.command)
        self._cancel(s.capture)
        try:
            await self._cleanup(s)
        except Exception:
            s.phase = SessionPhase.FAILED
            entry = self._entry(s)
            code = ErrorCode.DETACH_FAILED if not s.owned else ErrorCode.INTERNAL_ERROR
            self._publish(s, entry, ErrorResponse(code=code, session_id=s.sid))
            s.ready.set()
            raise
        s.phase = SessionPhase.TERMINATED
        s.ready.set()
        for entry in tuple(s.journal):
            if entry.response is None:
                self._publish(s, entry, ErrorResponse(code=ErrorCode.INVALID_STATE, session_id=s.sid))
        self._lifecycle(s)
        s.terminate_ack = self._ack(s)
        return s.terminate_ack

    async def _close(self):
        failures = []
        for s in tuple(self._sessions.values()):
            try:
                await self.session_terminate(s.sid)
            except Exception as exc:
                failures.append(exc)
            finally:
                try:
                    await self.state.close_session(s.sid)
                except Exception as exc:
                    failures.append(exc)
        if failures:
            raise failures[0]

    async def close(self) -> None:
        if self._closing is None:
            self._closed = True
            self._closing = asyncio.create_task(self._close())
        await asyncio.shield(self._closing)
