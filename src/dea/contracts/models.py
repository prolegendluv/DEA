"""Strict internal observations and requests; these are not tool responses."""
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_INT = 2**63 - 1
BoundedInt = Annotated[int, Field(ge=0, le=MAX_INT)]
PositiveInt = Annotated[int, Field(ge=1, le=MAX_INT)]
Handle = Annotated[str, Field(min_length=16, max_length=16, pattern=r"^[0-9a-f]{16}$")]
Name = Annotated[str, Field(min_length=1, max_length=64)]
ShortText = Annotated[str, Field(max_length=96)]
PathText = Annotated[str, Field(min_length=1, max_length=4096)]
ArgumentText = Annotated[str, Field(max_length=32768)]
Address = Annotated[int, Field(ge=0, le=2**64 - 1)]


class StrictModel(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, validate_default=True,
        validate_by_alias=True, validate_by_name=True,
        ser_json_bytes="base64", val_json_bytes="base64",
    )


class Backend(StrEnum):
    GDB = "gdb"
    LLDB = "lldb"
    PDB = "pdb"


class StepMode(StrEnum):
    OVER = "over"
    INTO = "into"
    OUT = "out"


class SessionPhase(StrEnum):
    NEW = "new"
    STARTING = "starting"
    STOPPED = "stopped"
    RUNNING = "running"
    TERMINATING = "terminating"
    TERMINATED = "terminated"
    FAILED = "failed"


class StopReason(StrEnum):
    ENTRY = "entry"
    BREAKPOINT = "breakpoint"
    WATCHPOINT = "watchpoint"
    STEP = "step"
    SIGNAL = "signal"
    EXCEPTION = "exception"
    INTERRUPT = "interrupt"


class ErrorCode(StrEnum):
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_STATE = "INVALID_STATE"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    CURSOR_EXPIRED = "CURSOR_EXPIRED"
    HISTORY_UNAVAILABLE = "HISTORY_UNAVAILABLE"
    WAIT_TIMEOUT = "WAIT_TIMEOUT"
    COMMAND_TIMEOUT = "COMMAND_TIMEOUT"
    STARTUP_TIMEOUT = "STARTUP_TIMEOUT"
    CONTROL_OVERFLOW = "CONTROL_OVERFLOW"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    DETACH_FAILED = "DETACH_FAILED"
    SERIALIZATION_FAILED = "SERIALIZATION_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"


class DeaError(Exception):
    def __init__(self, code: ErrorCode, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(code.value)


class RuntimeLimits(StrictModel):
    protocol_bytes: PositiveInt = 1_048_576
    control_events: PositiveInt = 256
    diagnostic_bytes: PositiveInt = 1_048_576
    history_snapshots: PositiveInt = 128
    history_bytes: PositiveInt = 16_777_216
    cursor_ttl_seconds: PositiveInt = 600
    startup_seconds: PositiveInt = 10
    command_seconds: PositiveInt = 5
    maximum_wait_ms: PositiveInt = 30_000
    maximum_sessions: PositiveInt = 16


class EnvironmentEntry(StrictModel):
    key: Annotated[str, Field(min_length=1, max_length=256)]
    value: Annotated[str, Field(max_length=32768)]

    @model_validator(mode="after")
    def valid_environment(self) -> "EnvironmentEntry":
        if "=" in self.key or "\x00" in self.key or "\x00" in self.value:
            raise ValueError("Invalid environment entry")
        return self


class MemoryRegion(StrictModel):
    address: Address
    size: Annotated[int, Field(ge=1, le=65536)]

    @model_validator(mode="after")
    def no_overflow(self) -> "MemoryRegion":
        if self.address + self.size > 2**64:
            raise ValueError("Memory region overflows address range")
        return self


class TargetSpec(StrictModel):
    backend: Backend
    memory_regions: Annotated[tuple[MemoryRegion, ...], Field(max_length=16)] = ()

    @model_validator(mode="after")
    def memory_limit(self) -> "TargetSpec":
        if sum(r.size for r in self.memory_regions) > 65536:
            raise ValueError("At most 64 KiB of memory may be captured per stop")
        ordered = sorted(self.memory_regions, key=lambda region: region.address)
        if any(left.address + left.size > right.address for left, right in zip(ordered, ordered[1:])):
            raise ValueError("Memory regions must not overlap")
        return self


class LaunchSpec(TargetSpec):
    binary_path: PathText
    args: Annotated[tuple[ArgumentText, ...], Field(max_length=256)] = ()
    env: Annotated[tuple[EnvironmentEntry, ...], Field(max_length=256)] = ()
    cwd: PathText | None = None
    io_mode: Literal["capture", "pty"] = "capture"
    stop_at_entry: bool = True

    @model_validator(mode="after")
    def valid_launch(self) -> "LaunchSpec":
        if any("\x00" in value for value in (self.binary_path, *self.args)):
            raise ValueError("NUL in process arguments")
        keys = [entry.key for entry in self.env]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate environment key")
        return self


class AttachSpec(TargetSpec):
    pid: PositiveInt
    binary_path: PathText | None = None


class ProcessSpec(StrictModel):
    argv: Annotated[tuple[ArgumentText, ...], Field(min_length=1, max_length=257)]
    env: Annotated[tuple[EnvironmentEntry, ...], Field(max_length=256)] = ()
    cwd: PathText | None = None
    transport: Literal["pipes", "pty"] = "pipes"
    owned: Literal[True] = True
    helper_control: bool = False

    @model_validator(mode="after")
    def no_nul(self) -> "ProcessSpec":
        if not self.argv[0] or any("\x00" in arg for arg in self.argv):
            raise ValueError("NUL in process arguments")
        return self


class ProcessChunk(StrictModel):
    stream: Literal["stdout", "stderr", "terminal"]
    data: Annotated[bytes, Field(max_length=1_048_576)]
    eof: bool = False


class AdapterCapabilities(StrictModel):
    backend: Backend
    available: bool = False
    launch: bool = False
    attach: bool = False
    interrupt: bool = False
    registers: bool = False
    memory_read: bool = False
    terminal: bool = False

    @model_validator(mode="after")
    def truthful_capabilities(self) -> "AdapterCapabilities":
        features = (self.launch, self.attach, self.interrupt, self.registers,
                    self.memory_read, self.terminal)
        if not self.available and any(features):
            raise ValueError("Unavailable adapter cannot advertise capabilities")
        if self.backend is Backend.PDB and (self.attach or self.registers or self.memory_read):
            raise ValueError("PDB native capabilities are unavailable in v1")
        return self


class BreakpointSpec(StrictModel):
    location: PathText
    condition: Annotated[str, Field(max_length=4096)] | None = None


class Breakpoint(StrictModel):
    breakpoint_id: Name
    verified: bool


class CommandAck(StrictModel):
    request_id: PositiveInt
    accepted: Literal[True] = True


class SourceLocation(StrictModel):
    file: PathText | None = None
    line: PositiveInt | None = None
    function: PathText | None = None
    address: Address | None = None

    @model_validator(mode="after")
    def identifiable(self) -> "SourceLocation":
        if not (self.file or self.function or self.address is not None):
            raise ValueError("Location must identify source, function, or address")
        if self.line is not None and self.file is None:
            raise ValueError("Source line requires a file")
        return self


class RawValue(StrictModel):
    identity: PathText
    name: PathText
    value: Annotated[str, Field(max_length=1_048_576)] | None = None
    available: bool = True
    watched: bool = False

    @model_validator(mode="after")
    def known_value(self) -> "RawValue":
        if self.available and self.value is None:
            raise ValueError("Available observation needs an exact value")
        return self


class RawFrame(StrictModel):
    index: BoundedInt
    identity: PathText
    location: SourceLocation
    variables: tuple[RawValue, ...] = ()
    variables_complete: bool = False


class MemoryRead(StrictModel):
    region: MemoryRegion
    data: Annotated[bytes, Field(max_length=65536)]

    @model_validator(mode="after")
    def exact_read(self) -> "MemoryRead":
        if len(self.data) != self.region.size:
            raise ValueError("Partial reads are errors, not zero-filled bytes")
        return self


class RawSnapshot(StrictModel):
    session_id: Handle
    stop_id: PositiveInt
    thread_id: BoundedInt
    frame_context: PathText
    reason: StopReason
    location: SourceLocation | None = None
    registers: tuple[RawValue, ...] = ()
    variables: tuple[RawValue, ...] = ()
    frames: tuple[RawFrame, ...] = ()
    memory: tuple[MemoryRead, ...] = ()
    registers_complete: bool = False
    variables_complete: bool = False
    frames_complete: bool = False

    @model_validator(mode="after")
    def unique_observations(self) -> "RawSnapshot":
        for observations in (self.registers, self.variables):
            identities = [value.identity for value in observations]
            if len(set(identities)) != len(identities):
                raise ValueError("Duplicate observation identity")
        return self


class CaptureRequest(StrictModel):
    stop_id: PositiveInt
    reason: StopReason
    frame_index: BoundedInt = 0
    max_depth: Annotated[int, Field(ge=0, le=8)] = 1
    memory_regions: Annotated[tuple[MemoryRegion, ...], Field(max_length=16)] = ()

    @model_validator(mode="after")
    def bounded_capture(self) -> "CaptureRequest":
        if sum(region.size for region in self.memory_regions) > 65536:
            raise ValueError("At most 64 KiB of memory may be captured per stop")
        ordered = sorted(self.memory_regions, key=lambda region: region.address)
        if any(left.address + left.size > right.address for left, right in zip(ordered, ordered[1:])):
            raise ValueError("Memory regions must not overlap")
        return self


class MemoryChange(StrictModel):
    address: Address
    before: Annotated[bytes, Field(max_length=65536)]
    after: Annotated[bytes, Field(max_length=65536)]

    @model_validator(mode="after")
    def changed_bytes(self) -> "MemoryChange":
        if len(self.before) != len(self.after) or self.before == self.after:
            raise ValueError("Memory change must contain unequal, equal-length byte ranges")
        return self


class RawMemoryDiff(StrictModel):
    session_id: Handle
    since_step_id: PositiveInt
    stop_id: PositiveInt
    changes: tuple[MemoryChange, ...] = ()

    @model_validator(mode="after")
    def chronological(self) -> "RawMemoryDiff":
        if self.since_step_id >= self.stop_id:
            raise ValueError("Memory baseline must precede current stop")
        return self


class TerminationPolicy(StrEnum):
    TERMINATE_OWNED = "terminate_owned"
    DETACH = "detach"


class DebuggerEvent(StrictModel):
    event_id: PositiveInt
    kind: Literal["started", "running", "stopped", "exited", "failed"]
    reason: StopReason | None = None
    thread_id: BoundedInt | None = None
    exit_code: Annotated[int, Field(ge=-(2**31), le=2**32-1)] | None = None
    error_code: ErrorCode | None = None

    @model_validator(mode="after")
    def event_fields(self) -> "DebuggerEvent":
        if (self.kind == "stopped") != (self.reason is not None):
            raise ValueError("Only stopped events require a reason")
        if (self.kind == "failed") != (self.error_code is not None):
            raise ValueError("Only failed events require an error code")
        if self.exit_code is not None and self.kind != "exited":
            raise ValueError("Exit code requires exited event")
        return self


class HelperMessage(StrictModel):
    version: Literal[1] = 1
    kind: Literal["request", "response", "event"]
    request_id: PositiveInt | None = None
    event_id: PositiveInt | None = None
    operation: Name
    body_json: Annotated[str, Field(max_length=1_048_576)]

    @model_validator(mode="after")
    def correlation(self) -> "HelperMessage":
        import json
        json.loads(self.body_json, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        if self.kind == "event":
            if self.event_id is None or self.request_id is not None:
                raise ValueError("Events use event_id only")
        elif self.request_id is None or self.event_id is not None:
            raise ValueError("Requests/responses use request_id only")
        return self


class SessionRequest(StrictModel):
    session_id: Handle


class BreakpointRequest(SessionRequest):
    spec: BreakpointSpec


class StepRequest(SessionRequest):
    mode: StepMode


class FrameRequest(SessionRequest):
    frame_index: BoundedInt = 0
    max_depth: Annotated[int, Field(ge=0, le=8)] = 1


class EvaluationRequest(SessionRequest):
    expr: Annotated[str, Field(min_length=1, max_length=4096)]


class MemoryDiffRequest(SessionRequest):
    since_step_id: PositiveInt


class WaitRequest(SessionRequest):
    after_event_id: BoundedInt = 0
    timeout_ms: Annotated[int, Field(ge=0, le=30000)] = 1000


class PageRequest(SessionRequest):
    cursor_id: Handle


