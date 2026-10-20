import json

import pytest
from pydantic import ValidationError

from dea.contracts.compact import CompactDebugState, InspectionPage, OmissionCounts, ValueDelta
from dea.contracts.models import (
    AdapterCapabilities, Backend, DebuggerEvent, EnvironmentEntry, LaunchSpec,
    MemoryRead, MemoryRegion, RawSnapshot, RawValue, StepMode, StopReason, WaitRequest,
)
from tests.support.fakes import SID


def stop(**overrides):
    return CompactDebugState(session_id=SID, event_id=1, stop_id=1, reason=StopReason.ENTRY, **overrides)


@pytest.mark.parametrize("change", [
    {"stop_id": "1"}, {"stop_id": True}, {"stop_id": 0}, {"stop_id": 2**63},
    {"event_id": -1}, {"session_id": "BAD"}, {"extra": 1}, {"reason": "entry"},
])
def test_strict_fields(change):
    data = dict(session_id=SID, event_id=1, stop_id=1, reason=StopReason.ENTRY)
    data.update(change)
    with pytest.raises(ValidationError):
        CompactDebugState(**data)


def test_wire_aliases_and_json_enum_validation():
    result = stop()
    assert CompactDebugState.model_validate_json(result.model_dump_json(by_alias=True)) == result
    with pytest.raises(ValidationError):
        CompactDebugState.model_validate_json(json.dumps({
            "sid": SID, "eid": 1, "stop": 1, "reason": "entry", "unexpected": 1,
        }))


def test_deep_frozen_collections():
    delta = ValueDelta(identity="x", name="x", operation="add", after="1")
    result = stop(variable_deltas=(delta,))
    with pytest.raises(ValidationError):
        result.variable_deltas[0].after = "2"
    with pytest.raises(ValidationError):
        result.stop_id = 2
    with pytest.raises(ValidationError):
        stop(variable_deltas=[delta])


@pytest.mark.parametrize("values", [
    {"operation": "add", "before": "0", "after": "1"},
    {"operation": "set", "before": "1", "after": "1"},
    {"operation": "del", "before": "1", "after": "0"},
    {"operation": "set", "after": "1"},
    {"operation": "add", "after": "x" * 97},
    {"operation": "add", "after": "1", "before_reference": SID},
])
def test_delta_semantics(values):
    with pytest.raises(ValidationError):
        ValueDelta(identity="x", name="x", **values)


def test_baselines_bounds_and_omissions():
    delta = ValueDelta(identity="x", name="x", operation="set", before="0", after="1")
    with pytest.raises(ValidationError):
        stop(variable_deltas=(delta,))
    with pytest.raises(ValidationError):
        stop(base_stop_id=1)
    with pytest.raises(ValidationError):
        stop(omitted=OmissionCounts(variables=1))
    with pytest.raises(ValidationError):
        stop(variable_deltas=tuple(ValueDelta(identity=str(i), name="x", operation="add", after="1") for i in range(9)))
    with pytest.raises(ValidationError):
        OmissionCounts()


def test_long_values_use_distinct_references():
    delta = ValueDelta(identity="x", name="x", operation="set", before="<value>", after="<value>",
                       before_reference="0000000000000001", after_reference="0000000000000002")
    result = CompactDebugState(session_id=SID, event_id=2, stop_id=2, base_stop_id=1,
                               reason=StopReason.STEP, variable_deltas=(delta,), cursor_id=SID)
    assert result.variable_deltas[0].before_reference != result.variable_deltas[0].after_reference


@pytest.mark.parametrize("kwargs", [
    {"offset": 0, "next_offset": 0, "text": "", "cursor_id": SID},
    {"offset": 1, "next_offset": 1, "text": "a"},
])
def test_pages_must_advance(kwargs):
    with pytest.raises(ValidationError):
        InspectionPage(session_id=SID, stop_id=1, object_id=SID, **kwargs)


def test_unicode_page_offsets_count_characters():
    assert InspectionPage(session_id=SID, stop_id=1, object_id=SID,
                          offset=0, next_offset=2, text="🪲漢").next_offset == 2


def test_launch_environment_and_memory_are_bounded():
    with pytest.raises(ValidationError):
        EnvironmentEntry(key="BAD=KEY", value="x")
    with pytest.raises(ValidationError):
        LaunchSpec(backend=Backend.GDB, binary_path="a\x00b")
    with pytest.raises(ValidationError):
        LaunchSpec(backend=Backend.GDB, binary_path="program", memory_regions=(MemoryRegion(address=0, size=65536), MemoryRegion(address=65536, size=1)))
    with pytest.raises(ValidationError):
        MemoryRead(region=MemoryRegion(address=0, size=2), data=b"a")


def test_binary_memory_roundtrips_and_empty_arguments_are_preserved():
    observation = MemoryRead(region=MemoryRegion(address=2**64-2, size=2), data=b"\x00\xff")
    assert MemoryRead.model_validate_json(observation.model_dump_json()) == observation
    assert LaunchSpec(backend=Backend.GDB, binary_path="program", args=("",)).args == ("",)


def test_truthful_capabilities_and_events():
    with pytest.raises(ValidationError):
        AdapterCapabilities(backend=Backend.GDB, launch=True)
    with pytest.raises(ValidationError):
        AdapterCapabilities(backend=Backend.PDB, available=True, attach=True)
    with pytest.raises(ValidationError):
        DebuggerEvent(event_id=1, kind="stopped")
    with pytest.raises(ValidationError):
        WaitRequest(session_id=SID, timeout_ms=30001)


def test_snapshot_does_not_conflate_unknown_with_deleted():
    unknown = RawValue(identity="t1/f1/x", name="x", available=False)
    snapshot = RawSnapshot(session_id=SID, stop_id=1, thread_id=1,
                           frame_context="t1/f1", reason=StopReason.STEP, variables=(unknown,))
    assert not snapshot.variables_complete
    assert snapshot.variables[0].value is None
    with pytest.raises(ValidationError):
        RawValue(identity="x", name="x")

