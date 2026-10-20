"""GDB/MI command correlation and independent asynchronous state events."""
from __future__ import annotations

import asyncio
from collections import deque
from functools import wraps
import json
import hashlib
import os
import shutil

from dea.contracts.adapter import AdapterContext, BaseDebuggerAdapter
from dea.contracts.models import (
    MAX_INT, AdapterCapabilities, AttachSpec, Backend, Breakpoint, BreakpointSpec,
    CaptureRequest, CommandAck, DebuggerEvent, DeaError, ErrorCode, LaunchSpec,
    MemoryRead, MemoryRegion, ProcessSpec, RawFrame, RawSnapshot, RawValue,
    SourceLocation, StepMode, StopReason, TerminationPolicy,
)
from .mi import MIList, MIMap, MIParseError, MIParser
from .target_io import TargetIO


def quote(value: str) -> str:
    if "\x00" in value:
        raise DeaError(ErrorCode.INVALID_REQUEST, "NUL in MI argument")
    return json.dumps(value, ensure_ascii=False)


def observation_text(value: str) -> str:
    """Losslessly expose non-Unicode debugger octets as tagged JSON escapes.

    Escape the tag namespace itself to avoid aliasing a literal target string.
    Ordinary GDB representations are unchanged.
    """
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        return "<dea:bytes>" + json.dumps(value, ensure_ascii=True)
    return "<dea:text>" + value if value.startswith("<dea:") else value


def typed_observation(function):
    @wraps(function)
    async def checked(*args, **kwargs):
        try:
            return await function(*args, **kwargs)
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise DeaError(ErrorCode.PROTOCOL_ERROR, "Malformed GDB observation") from exc
    return checked


def entries(value, key=None):
    if not isinstance(value, MIList):
        raise DeaError(ErrorCode.PROTOCOL_ERROR, "Expected MI list")
    if key is None:
        return value.values
    return tuple(item[1] if isinstance(item, tuple) and item[0] == key else item
                 for item in value.values)


def number(value, default=None):
    if value is None:
        return default
    try:
        result = int(value, 16 if value.startswith("0x") else 10)
        if not 0 <= result <= MAX_INT:
            return default
        return result
    except (TypeError, ValueError, AttributeError):
        return default


def location(value: MIMap) -> SourceLocation:
    file = value.get("fullname") or value.get("file")
    line = number(value.get("line")) if file else None
    address_text = value.get("addr")
    try:
        address = int(address_text, 16) if address_text else None
    except ValueError:
        address = None
    return SourceLocation(file=file, line=line or None,
                          function=value.get("func"), address=address)


class GdbAdapter(BaseDebuggerAdapter):
    backend = Backend.GDB

    def __init__(self, context: AdapterContext):
        super().__init__(context)
        self._process = None
        self._reader = None
        self._target_io = None
        self._parser = MIParser(context.limits.protocol_bytes)
        self._pending = {}
        self._counter = 0
        self._event_counter = 0
        self._queue = asyncio.Queue(context.limits.control_events)
        configured = os.environ.get("DEA_GDB") or "gdb"
        self._executable = shutil.which(configured)
        # SessionService checks eligibility synchronously before calling start.
        # Native MI/register capability probing completes during initialization.
        self._available = self._executable is not None
        self._initialized = False
        self._stopped = False
        self._terminal = False
        self._closing = False
        self._cleanup_task = None
        self._attached = False
        self._entry_expected = False
        self._interrupt_requested = False
        self._events_reading = False
        self._frame_activation = "unknown"
        self._thread_id = 1
        self._last_stop = None
        self._generation = 0
        self._watched = deque(maxlen=context.limits.control_events)
        self._operation = asyncio.Lock()
        self._diagnostics = bytearray()
        self.diagnostic_dropped_bytes = 0
        self.thread_notifications = deque(maxlen=context.limits.control_events)

    def capabilities(self):
        return AdapterCapabilities(backend=self.backend, available=self._available,
            launch=self._available, attach=self._available, interrupt=self._available,
            registers=self._available and self._initialized,
            memory_read=self._available and self._initialized, terminal=False)

    async def events(self):
        if self._events_reading:
            raise DeaError(ErrorCode.INVALID_STATE, "GDB events already have a reader")
        self._events_reading = True
        try:
            while True:
                event = await self._queue.get()
                if event is None:
                    return
                yield event
                if event.kind in ("exited", "failed"):
                    return
        finally:
            self._events_reading = False

    def _emit(self, kind, **fields):
        if self._terminal:
            return
        self._event_counter += 1
        if self._event_counter > MAX_INT:
            raise DeaError(ErrorCode.RESOURCE_LIMIT)
        event = DebuggerEvent(event_id=self._event_counter, kind=kind, **fields)
        if self._queue.full():
            self._terminal = True
            self._stopped = False
            while not self._queue.empty():
                self._queue.get_nowait()
            self._queue.put_nowait(DebuggerEvent(event_id=self._event_counter,
                kind="failed", error_code=ErrorCode.CONTROL_OVERFLOW))
            self._reject_pending(ErrorCode.CONTROL_OVERFLOW)
            self._schedule_cleanup()
            return
        if kind in ("exited", "failed"):
            self._terminal = True
            self._stopped = False
        self._queue.put_nowait(event)

    def _diagnostic(self, data: bytes):
        self._diagnostics.extend(data)
        excess = len(self._diagnostics) - self.context.limits.diagnostic_bytes
        if excess > 0:
            del self._diagnostics[:excess]
            self.diagnostic_dropped_bytes += excess

    def _reject_pending(self, code):
        for future in tuple(self._pending.values()):
            if not future.done():
                future.set_exception(DeaError(code))

    def _record(self, record):
        if record.kind == "^":
            future = self._pending.get(record.token)
            if future is not None and not future.done():
                future.set_result(record)
            return
        if record.kind in ("~", "&", "@"):
            output = (record.text or "").encode("utf-8", "surrogateescape")
            if record.kind == "@" and self._target_io is not None:
                self._target_io._append(output)
            else:
                self._diagnostic(output)
            if record.kind == "&" and "Failed to open TTY" in (record.text or ""):
                raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE, "Inferior I/O isolation failed")
            return
        fields = record.results
        if record.kind == "=" and record.cls in ("thread-created", "thread-exited", "thread-selected"):
            self.thread_notifications.append(record)
        if record.kind == "=" and record.cls == "thread-group-exited":
            code = fields.get("exit-code")
            try:
                exit_code = int(code, 8) if code else 0
            except ValueError:
                exit_code = None
            self._emit("exited", exit_code=exit_code)
        elif record.kind == "*" and record.cls == "running":
            self._stopped = False
            self._emit("running")
        elif record.kind == "*" and record.cls == "stopped":
            reason_text = fields.get("reason", "")
            if reason_text.startswith("exited"):
                code = fields.get("exit-code")
                try:
                    exit_code = int(code, 8) if code else 0
                except ValueError:
                    exit_code = None
                self._emit("exited", exit_code=exit_code)
                return
            if self._terminal:
                return
            self._last_stop = record
            self._thread_id = number(fields.get("thread-id"), self._thread_id)
            for key in ("wpt", "hw-rwpt", "hw-awpt"):
                watch = fields.get(key)
                if isinstance(watch, MIMap) and isinstance(watch.get("exp"), str):
                    expression = watch["exp"]
                    if expression not in self._watched:
                        self._watched.append(expression)
            reason = {"breakpoint-hit": StopReason.BREAKPOINT,
                "watchpoint-trigger": StopReason.WATCHPOINT,
                "read-watchpoint-trigger": StopReason.WATCHPOINT,
                "access-watchpoint-trigger": StopReason.WATCHPOINT,
                "watchpoint-scope": StopReason.WATCHPOINT,
                "end-stepping-range": StopReason.STEP,
                "function-finished": StopReason.STEP,
                "location-reached": StopReason.STEP,
                "signal-received": StopReason.SIGNAL}.get(reason_text, StopReason.INTERRUPT)
            if (reason is StopReason.SIGNAL and self._interrupt_requested
                    and fields.get("signal-name") in ("SIGINT", "SIGTRAP")):
                reason = StopReason.INTERRUPT
            self._interrupt_requested = False
            if self._entry_expected and reason is StopReason.BREAKPOINT:
                self._entry_expected = False
                reason = StopReason.ENTRY
            self._stopped = True
            self._emit("stopped", reason=reason, thread_id=self._thread_id)

    async def _read(self):
        try:
            async for chunk in self._process.read():
                if chunk.stream == "stdout":
                    for record in self._parser.feed(chunk.data):
                        self._record(record)
                else:
                    self._diagnostic(chunk.data)
            self._parser.finish()
            if not self._terminal and not self._closing:
                self._emit("failed", error_code=ErrorCode.PROTOCOL_ERROR)
                self._schedule_cleanup()
            self._reject_pending(ErrorCode.INVALID_STATE)
        except asyncio.CancelledError:
            raise
        except (DeaError, MIParseError, ValueError, OSError) as exc:
            code = exc.code if isinstance(exc, DeaError) else ErrorCode.PROTOCOL_ERROR
            self._emit("failed", error_code=code)
            self._reject_pending(code)
            self._schedule_cleanup()

    def _schedule_cleanup(self):
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup(), name="dea-gdb-cleanup")

    async def _cleanup(self):
        try:
            if self._process is not None:
                await self._process.close()
        finally:
            if self._reader and self._reader is not asyncio.current_task() and not self._reader.done():
                self._reader.cancel()
                await asyncio.gather(self._reader, return_exceptions=True)
            if self._target_io:
                await self._target_io.close()
            self._reject_pending(ErrorCode.INVALID_STATE)

    async def _wait_cleanup(self):
        self._schedule_cleanup()
        try:
            await asyncio.shield(self._cleanup_task)
        except asyncio.CancelledError:
            await asyncio.shield(self._cleanup_task)
            raise

    async def _command(self, command, *, allow_terminal=False):
        if self._process is None or (self._terminal and not allow_terminal):
            raise DeaError(ErrorCode.INVALID_STATE)
        if len(self._pending) >= self.context.limits.control_events:
            raise DeaError(ErrorCode.RESOURCE_LIMIT)
        self._counter += 1
        if self._counter > MAX_INT:
            raise DeaError(ErrorCode.RESOURCE_LIMIT)
        token = self._counter
        future = asyncio.get_running_loop().create_future()
        self._pending[token] = future
        try:
            async with asyncio.timeout(self.context.limits.command_seconds):
                await self._process.write(f"{token}{command}\n".encode("utf-8"))
                record = await future
            if record.cls == "error":
                raise DeaError(ErrorCode.INVALID_REQUEST, record.results.get("msg", "GDB command failed"))
            if record.cls not in ("done", "running", "connected", "exit"):
                raise DeaError(ErrorCode.PROTOCOL_ERROR, "Unexpected command acknowledgement")
            return token, record.results
        except TimeoutError as exc:
            raise DeaError(ErrorCode.COMMAND_TIMEOUT) from exc
        finally:
            self._pending.pop(token, None)
            if not future.done():
                future.cancel()
            elif not future.cancelled():
                future.exception()

    async def _initialize(self, spec):
        if self._process is not None or self._terminal:
            raise DeaError(ErrorCode.INVALID_STATE)
        if spec.backend is not self.backend:
            raise DeaError(ErrorCode.INVALID_REQUEST)
        executable = self._executable
        if not executable:
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE, "GDB executable unavailable")
        self._process = await self.context.runtime.spawn(ProcessSpec(
            argv=(executable, "--nx", "--nh", "--quiet", "--interpreter=mi3"),
            cwd=spec.cwd if isinstance(spec, LaunchSpec) else None,
            env=spec.env if isinstance(spec, LaunchSpec) else ()))
        self._reader = asyncio.create_task(self._read(), name="dea-gdb-mi-reader")
        if os.name != "nt":
            await self._command("-gdb-set startup-with-shell off")
        for command in ("-gdb-set pagination off", "-gdb-set confirm off",
                "-gdb-set auto-load off",
                "-gdb-set non-stop off", "-gdb-set mi-async on",
                "-gdb-set print raw-values on", "-gdb-set print elements 0",
                "-gdb-set print repeats 0"):
            try:
                await self._command(command)
            except DeaError as exc:
                if exc.code is ErrorCode.INVALID_REQUEST:
                    raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE,
                                   f"Required MI setting unsupported: {command}") from exc
                raise
        _, result = await self._command("-gdb-show mi-async")
        if result.get("value") != "on":
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE, "Asynchronous MI unavailable")
        self._available = True
        self._initialized = True

    async def session_start(self, spec: LaunchSpec):
        if spec.io_mode != "capture":
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE, "Interactive target terminal is unavailable")
        try:
            await self._initialize(spec)
            self._target_io = TargetIO(self.context.limits.diagnostic_bytes)
            self._target_io.start()
            await self._command("-inferior-tty-set " + quote(self._target_io.path))
            await self._command("-file-exec-and-symbols " + quote(spec.binary_path))
            await self._command("-exec-arguments " + " ".join(quote(arg) for arg in spec.args))
            self._entry_expected = spec.stop_at_entry
            self._emit("started")
            token, _ = await self._command("-exec-run --start" if spec.stop_at_entry else "-exec-run")
            return CommandAck(request_id=token)
        except OSError as exc:
            self._available = False
            self._closing = True
            await self._wait_cleanup()
            raise DeaError(ErrorCode.CAPABILITY_UNAVAILABLE, str(exc)) from exc
        except BaseException:
            self._available = False
            self._closing = True
            await self._wait_cleanup()
            raise

    async def session_attach(self, spec: AttachSpec):
        self._attached = True
        try:
            await self._initialize(spec)
            if spec.binary_path:
                await self._command("-file-exec-and-symbols " + quote(spec.binary_path))
            if os.name == "nt":
                await self._command("-gdb-set detach-on-fork on")
            self._emit("started")
            token, _ = await self._command("-target-attach " + str(spec.pid))
            return CommandAck(request_id=token)
        except BaseException:
            self._available = False
            self._closing = True
            await self._wait_cleanup()
            raise

    def _require_stopped(self):
        if not self._stopped or self._terminal or self._closing:
            raise DeaError(ErrorCode.INVALID_STATE)

    @typed_observation
    async def breakpoint_set(self, spec: BreakpointSpec):
        async with self._operation:
            command = "-break-insert -f "
            if spec.condition is not None:
                command += "-c " + quote(spec.condition) + " "
            _, result = await self._command(command + "-- " + quote(spec.location))
            bp = result.get("bkpt")
            if not isinstance(bp, MIMap):
                raise DeaError(ErrorCode.PROTOCOL_ERROR)
            return Breakpoint(breakpoint_id=bp["number"], verified=bp.get("addr") != "<PENDING>")

    async def _execute(self, command):
        async with self._operation:
            self._require_stopped()
            self._stopped = False
            try:
                token, _ = await self._command(command)
                return CommandAck(request_id=token)
            except DeaError as exc:
                if exc.code is ErrorCode.INVALID_REQUEST and not self._terminal:
                    self._stopped = True
                raise

    async def execution_continue(self):
        return await self._execute("-exec-continue --all")

    async def execution_step(self, mode: StepMode):
        commands = {StepMode.OVER: "-exec-next", StepMode.INTO: "-exec-step", StepMode.OUT: "-exec-finish"}
        if mode not in commands:
            raise DeaError(ErrorCode.INVALID_REQUEST)
        return await self._execute(commands[mode])

    async def execution_interrupt(self):
        self._interrupt_requested = True
        try:
            token, _ = await self._command("-exec-interrupt --all")
            return CommandAck(request_id=token)
        except BaseException:
            self._interrupt_requested = False
            raise

    @typed_observation
    async def _frame(self, frame_index: int, max_depth: int):
        self._require_stopped()
        if not 0 <= frame_index <= MAX_INT or not 0 <= max_depth <= 8:
            raise DeaError(ErrorCode.INVALID_REQUEST)
        await self._command("-stack-select-frame " + str(frame_index))
        _, result = await self._command("-stack-info-frame")
        frame = result.get("frame")
        if not isinstance(frame, MIMap):
            raise DeaError(ErrorCode.PROTOCOL_ERROR)
        loc = location(frame)
        _, stack = await self._command('-data-evaluate-expression "$sp"')
        self._frame_activation = stack["value"]
        identity = self._frame_identity(frame_index, loc.function)
        variables = []
        complete = False
        if max_depth:
            _, values = await self._command("-stack-list-variables --all-values")
            seen = {}
            for value in entries(values.get("variables")):
                name = value["name"]
                duplicate = seen.get(name, 0)
                seen[name] = duplicate + 1
                text = value.get("value")
                available = text is not None and text not in ("<optimized out>", "<unavailable>")
                digest = hashlib.sha256(name.encode("utf-8", "surrogateescape")).hexdigest()
                variables.append(RawValue(identity=f"{identity}:v{digest}:{duplicate}",
                    name=observation_text(name), value=observation_text(text) if available else None, available=available,
                    watched=name in self._watched))
            complete = True
        return RawFrame(index=frame_index, identity=identity, location=loc,
                        variables=tuple(variables), variables_complete=complete)

    async def state_inspect_frame(self, frame_index: int, max_depth: int):
        async with self._operation:
            return await self._frame(frame_index, max_depth)

    def _frame_identity(self, index, function):
        digest = hashlib.sha256((function or "?").encode("utf-8", "surrogateescape")).hexdigest()
        activation = hashlib.sha256(self._frame_activation.encode("utf-8", "surrogateescape")).hexdigest()
        return f"t{self._thread_id}:f{index}:{digest}:a{activation}:g{self._generation}"

    @typed_observation
    async def state_eval_expression(self, expr: str):
        async with self._operation:
            self._require_stopped()
            self._generation += 1
            _, result = await self._command("-data-evaluate-expression " + quote(expr))
            digest = hashlib.sha256(expr.encode("utf-8", "surrogateescape")).hexdigest()
            return RawValue(identity=f"t{self._thread_id}:eval:{digest}", name=expr,
                            value=observation_text(result["value"]))

    @typed_observation
    async def _memory(self, region: MemoryRegion):
        self._require_stopped()
        _, result = await self._command(f"-data-read-memory-bytes 0x{region.address:x} {region.size}")
        blocks = entries(result.get("memory"))
        output = bytearray()
        position = region.address
        for block in blocks:
            if int(block["begin"], 16) != position:
                raise DeaError(ErrorCode.PROTOCOL_ERROR, "Discontiguous memory response")
            try:
                data = bytes.fromhex(block["contents"])
            except ValueError as exc:
                raise DeaError(ErrorCode.PROTOCOL_ERROR) from exc
            if len(data) > region.size - len(output):
                raise DeaError(ErrorCode.PROTOCOL_ERROR, "Memory response exceeds requested region")
            output.extend(data)
            position += len(data)
        if len(output) != region.size:
            raise DeaError(ErrorCode.INVALID_REQUEST, "Memory read was partial")
        return MemoryRead(region=region, data=bytes(output))

    async def state_read_memory(self, region: MemoryRegion):
        async with self._operation:
            return await self._memory(region)

    @typed_observation
    async def snapshot_capture(self, request: CaptureRequest):
        async with self._operation:
            self._require_stopped()
            frame = await self._frame(request.frame_index, request.max_depth)
            _, result = await self._command("-stack-list-frames")
            frames = []
            for value in entries(result.get("stack"), "frame"):
                index = number(value.get("level"))
                loc = location(value)
                frames.append(frame if index == frame.index else RawFrame(index=index,
                    identity=self._frame_identity(index, loc.function),
                    location=loc))
            _, names = await self._command("-data-list-register-names")
            _, values = await self._command("-data-list-register-values x")
            register_names = entries(names.get("register-names"))
            registers = []
            observed_indices = set()
            for value in entries(values.get("register-values")):
                index = number(value.get("number"))
                if index is None or index >= len(register_names):
                    raise DeaError(ErrorCode.PROTOCOL_ERROR)
                name = register_names[index]
                if not name:
                    continue
                if index in observed_indices:
                    raise DeaError(ErrorCode.PROTOCOL_ERROR, "Duplicate register index")
                observed_indices.add(index)
                text = value.get("value")
                available = text is not None and text not in ("<unavailable>", "<optimized out>")
                registers.append(RawValue(identity=f"t{self._thread_id}:reg:{index}", name=name,
                    value=observation_text(text) if available else None, available=available))
            memory = tuple([await self._memory(region) for region in request.memory_regions])
            self._require_stopped()
            return RawSnapshot(session_id=self.context.session_id, stop_id=request.stop_id,
                thread_id=self._thread_id, frame_context=frame.identity, reason=request.reason,
                location=frame.location, variables=frame.variables, frames=tuple(frames),
                registers=tuple(registers), memory=memory, variables_complete=frame.variables_complete,
                registers_complete=observed_indices == {i for i, name in enumerate(register_names) if name},
                frames_complete=True)

    async def session_terminate(self, policy: TerminationPolicy):
        if self._closing:
            if self._cleanup_task:
                await self._wait_cleanup()
            return
        self._closing = True
        error = None
        try:
            if self._process is not None:
                if self._attached and not self._terminal:
                    if policy is not TerminationPolicy.DETACH:
                        raise DeaError(ErrorCode.DETACH_FAILED, "Cannot terminate external target")
                    try:
                        await self._command("-target-detach")
                    except DeaError as exc:
                        raise DeaError(ErrorCode.DETACH_FAILED, exc.detail) from exc
                elif policy is TerminationPolicy.DETACH and not self._terminal:
                    await self._command("-target-detach")
                await self._command("-gdb-exit", allow_terminal=True)
        except DeaError as exc:
            if not self._terminal or exc.code is ErrorCode.DETACH_FAILED:
                error = exc
        finally:
            await self._wait_cleanup()
            if not self._terminal:
                self._emit("exited")
        if error:
            raise error
