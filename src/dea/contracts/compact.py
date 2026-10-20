"""Agent-facing payloads. Every response must pass WireGuard before delivery."""
from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, model_validator

from .models import (
    AdapterCapabilities, BoundedInt, ErrorCode, Handle, Name, PositiveInt,
    SessionPhase, ShortText, StopReason, StrictModel,
)


class ValueDelta(StrictModel):
    identity: Name = Field(alias="id")
    name: Name
    operation: Literal["add", "set", "del"] = Field(alias="op")
    before: ShortText | None = None
    after: ShortText | None = None
    before_reference: Handle | None = Field(default=None, alias="bref")
    after_reference: Handle | None = Field(default=None, alias="aref")

    @model_validator(mode="after")
    def applicable_values(self) -> "ValueDelta":
        before = self.before is not None
        after = self.after is not None
        expected = {"add": (False, True), "set": (True, True), "del": (True, False)}
        if (before, after) != expected[self.operation]:
            raise ValueError("Delta values do not match operation")
        if self.before_reference is not None and not before:
            raise ValueError("Before reference requires a before display value")
        if self.after_reference is not None and not after:
            raise ValueError("After reference requires an after display value")
        if self.operation == "set" and (self.before, self.before_reference) == (self.after, self.after_reference):
            raise ValueError("Unchanged values are not deltas")
        return self


class CompactLocation(StrictModel):
    file: Name | None = None
    line: PositiveInt | None = None
    function: Name | None = Field(default=None, alias="fn")
    address: Annotated[str, Field(pattern=r"^0x[0-9a-f]{1,16}$")] | None = Field(default=None, alias="pc")

    @model_validator(mode="after")
    def valid_location(self) -> "CompactLocation":
        if self.file is None and self.function is None and self.address is None:
            raise ValueError("Empty location")
        if self.line is not None and self.file is None:
            raise ValueError("Line requires file")
        return self


class CompactFrame(StrictModel):
    index: BoundedInt = Field(alias="i")
    location: CompactLocation = Field(alias="at")


class OmissionCounts(StrictModel):
    registers: BoundedInt = Field(default=0, alias="regs")
    variables: BoundedInt = Field(default=0, alias="vars")
    frames: BoundedInt = 0

    @model_validator(mode="after")
    def nonempty(self) -> "OmissionCounts":
        if not (self.registers or self.variables or self.frames):
            raise ValueError("Omission counts must describe at least one omitted item")
        return self


class CompactDebugState(StrictModel):
    model_config = {"json_schema_extra": {
        "x-token-budget": {"maximum": 191, "encodings": ["cl100k_base", "o200k_base"],
                           "enforcedBy": "dea.contracts.wire.WireGuard.encode"},
    }}
    kind: Literal["stop"] = Field(default="stop", alias="type")
    schema_version: Literal[1] = Field(default=1, alias="v")
    session_id: Handle = Field(alias="sid")
    event_id: PositiveInt = Field(alias="eid")
    stop_id: PositiveInt = Field(alias="stop")
    base_stop_id: PositiveInt | None = Field(default=None, alias="base")
    reason: StopReason
    thread_id: BoundedInt | None = Field(default=None, alias="thread")
    location: CompactLocation | None = Field(default=None, alias="at")
    frames: Annotated[tuple[CompactFrame, ...], Field(max_length=5)] = Field(default=(), exclude_if=lambda v: not v)
    register_deltas: Annotated[tuple[ValueDelta, ...], Field(max_length=8)] = Field(default=(), alias="regs", exclude_if=lambda v: not v)
    variable_deltas: Annotated[tuple[ValueDelta, ...], Field(max_length=8)] = Field(default=(), alias="vars", exclude_if=lambda v: not v)
    omitted: OmissionCounts | None = None
    cursor_id: Handle | None = Field(default=None, alias="cursor")
    hint: Literal["set_breakpoint"] | None = None

    @model_validator(mode="after")
    def consistent_stop(self) -> "CompactDebugState":
        if self.base_stop_id is not None and self.base_stop_id >= self.stop_id:
            raise ValueError("Baseline must precede current stop")
        for deltas in (self.register_deltas, self.variable_deltas):
            ids = [delta.identity for delta in deltas]
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate delta identity")
            if self.base_stop_id is None and any(delta.operation != "add" for delta in deltas):
                raise ValueError("Reset baseline permits additions only")
        if self.omitted is not None and self.cursor_id is None:
            raise ValueError("Omitted data requires a cursor")
        if any(d.before_reference or d.after_reference for d in (*self.register_deltas, *self.variable_deltas)) and self.cursor_id is None:
            raise ValueError("Referenced values require a details cursor")
        return self


class AckResponse(StrictModel):
    kind: Literal["ack"] = Field(default="ack", alias="type")
    session_id: Handle = Field(alias="sid")
    request_id: PositiveInt = Field(alias="rid")
    accepted: Literal[True] = True
    breakpoint_id: Name | None = Field(default=None, alias="bp")


class InspectionPage(StrictModel):
    kind: Literal["page"] = Field(default="page", alias="type")
    session_id: Handle = Field(alias="sid")
    stop_id: PositiveInt = Field(alias="stop")
    object_id: Handle = Field(alias="object")
    offset: BoundedInt
    next_offset: BoundedInt = Field(alias="next")
    text: Annotated[str, Field(max_length=4096)]
    cursor_id: Handle | None = Field(default=None, alias="cursor")

    @model_validator(mode="after")
    def progress(self) -> "InspectionPage":
        if self.next_offset != self.offset + len(self.text):
            raise ValueError("Page offset counts Unicode characters")
        if self.cursor_id is not None and not self.text:
            raise ValueError("Continuation must make progress")
        return self


class LifecycleResponse(StrictModel):
    kind: Literal["event"] = Field(default="event", alias="type")
    session_id: Handle = Field(alias="sid")
    event_id: PositiveInt = Field(alias="eid")
    phase: SessionPhase
    exit_code: Annotated[int, Field(ge=-(2**31), le=2**32-1)] | None = Field(default=None, alias="exit")


class CapabilitiesResponse(StrictModel):
    kind: Literal["capabilities"] = Field(default="capabilities", alias="type")
    capabilities: AdapterCapabilities


class ErrorResponse(StrictModel):
    kind: Literal["error"] = Field(default="error", alias="type")
    code: ErrorCode
    session_id: Handle | None = Field(default=None, alias="sid")
    cursor_id: Handle | None = Field(default=None, alias="cursor")


ToolResponse = Annotated[
    CompactDebugState | AckResponse | InspectionPage | LifecycleResponse | CapabilitiesResponse | ErrorResponse,
    Field(discriminator="kind"),
]
RESPONSE_ADAPTER = TypeAdapter(ToolResponse)

