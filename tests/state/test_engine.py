"""State invariants tested through the frozen public surface."""
import json

import pytest

from dea.contracts.models import (
    DeaError, ErrorCode, MAX_INT, MemoryRead, MemoryRegion, RawFrame, RawSnapshot,
    RawValue, RuntimeLimits, SourceLocation, StopReason,
)
from dea.contracts.ownership import worker_can_write
from dea.contracts.wire import WireGuard
from dea.state import StateEngine
from tests.support.fakes import FakeClock, SID


@pytest.fixture
def engine():
    return StateEngine(RuntimeLimits(), FakeClock(), WireGuard())


def value(identity="x", text="1", **kwargs):
    return RawValue(identity=identity, name=identity, value=text, **kwargs)


def snapshot(stop=1, **kwargs):
    return RawSnapshot(session_id=SID, stop_id=stop, thread_id=1,
        frame_context="main", reason=StopReason.STEP, **kwargs)


async def collect(engine, first):
    result = first
    text = result.text
    object_id = result.object_id
    while result.cursor_id:
        before = result.next_offset
        result = await engine.page(SID, result.cursor_id)
        assert result.object_id == object_id
        assert result.offset == before
        assert result.next_offset > before
        assert all(count <= 191 for _, count in engine.guard.encode(result).token_counts)
        text += result.text
    return text


async def details(engine, stop):
    return json.loads(await collect(engine, await engine.page(SID, stop.cursor_id)))


async def test_add_set_delete_and_unchanged(engine):
    a = await engine.record(snapshot(variables=(value(),), variables_complete=True), 1)
    assert a.base_stop_id is None
    assert a.variable_deltas[0].operation == "add"
    b = await engine.record(snapshot(2, variables=(value(text="2"),), variables_complete=True), 2)
    assert b.base_stop_id == 1
    assert (b.variable_deltas[0].before, b.variable_deltas[0].after) == ("1", "2")
    c = await engine.record(snapshot(3, variables=(value(text="2"),), variables_complete=True), 3)
    assert not c.variable_deltas
    d = await engine.record(snapshot(4, variables_complete=True), 4)
    assert d.variable_deltas[0].operation == "del"


async def test_unknown_and_incomplete_keep_last_known_baseline(engine):
    await engine.record(snapshot(variables=(value(),), variables_complete=True), 1)
    unknown = RawValue(identity="x", name="x", available=False)
    b = await engine.record(snapshot(2, variables=(unknown,), variables_complete=True), 2)
    assert not b.variable_deltas
    c = await engine.record(snapshot(3), 3)
    assert not c.variable_deltas
    d = await engine.record(snapshot(4, variables=(value(text="2"),)), 4)
    assert d.variable_deltas[0].operation == "set"
    assert d.variable_deltas[0].before == "1"


@pytest.mark.parametrize("changed", ["thread", "frame"])
async def test_context_reset(engine, changed):
    await engine.record(snapshot(variables=(value(),)), 1)
    raw = snapshot(2, variables=(value(text="2"),))
    raw = raw.model_copy(update={"thread_id": 2} if changed == "thread" else {"frame_context": "other"})
    out = await engine.record(raw, 2)
    assert out.base_stop_id is None
    assert out.variable_deltas[0].operation == "add"


async def test_distinct_large_values_have_distinct_stable_references(engine):
    a, b = "prefix" * 30 + "A", "prefix" * 30 + "B"
    out = await engine.record(snapshot(variables=(value(text=a),)), 1)
    first = out.variable_deltas[0].after_reference
    out = await engine.record(snapshot(2, variables=(value(text=b),)), 2)
    delta = out.variable_deltas[0]
    assert delta.before == delta.after == "<value>"
    assert delta.before_reference == first
    assert delta.before_reference != delta.after_reference
    exact = await details(engine, out)
    assert exact["variables"][0]["before"] == a
    assert exact["variables"][0]["after"] == b


async def test_long_scoped_names_preserve_exact_detail(engine):
    raw = value("scope/" * 50)
    out = await engine.record(snapshot(variables=(raw,)), 1)
    exact = await details(engine, out)
    assert exact["variables"][0]["id"] == raw.identity
    for delta in out.variable_deltas:
        assert len(delta.identity) <= 64 and len(delta.name) <= 64


async def test_priority_omission_counts_and_full_raw_history(engine):
    values = tuple(value(f"v{i:02}", "x" * 80, watched=(i == 19)) for i in range(20))
    regs = tuple(value(f"r{i:02}") for i in range(20))
    out = await engine.record(snapshot(variables=values, registers=regs), 1, hint=True)
    assert out.hint == "set_breakpoint"
    assert out.omitted.variables == 20 - len(out.variable_deltas)
    assert out.omitted.registers == 20 - len(out.register_deltas)
    if out.variable_deltas:
        assert out.variable_deltas[0].identity == "v19"
    exact = await details(engine, out)
    assert len(exact["variables"]) == len(exact["registers"]) == 20
    out2 = await engine.record(snapshot(2, variables=values, registers=regs), 2)
    assert not out2.variable_deltas and not out2.register_deltas


async def test_order_is_independent_of_capture_order(engine):
    values = tuple(value(name) for name in ("z", "a", "m"))
    out = await engine.record(snapshot(variables=values), 1)
    assert [d.identity for d in out.variable_deltas] == ["a", "m", "z"]


async def test_extreme_metadata_preserves_cap_and_hint(engine):
    raw = snapshot(MAX_INT, variables=tuple(value(str(i), "\\\"🔥" * 30) for i in range(15)),
                   location=SourceLocation(file="中" * 4096, line=MAX_INT))
    raw = raw.model_copy(update={"thread_id": MAX_INT})
    out = await engine.record(raw, MAX_INT, hint=True)
    assert out.hint == "set_breakpoint"
    assert max(n for _, n in engine.guard.encode(out).token_counts) <= 191
    assert out.cursor_id


@pytest.mark.parametrize("text", ["🔥中é\"\\\n" * 250, "<|endoftext|>" * 200, "a" * 10000])
async def test_unicode_pages_exact_replay_and_progress(engine, text):
    await engine.record(snapshot(), 1)
    canonical = json.dumps({"payload": text}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    first = await engine.inspect(SID, 1, canonical)
    assert first.offset == 0
    cursor = first.cursor_id
    assert cursor
    a = await engine.page(SID, cursor)
    b = await engine.page(SID, cursor)
    assert engine.guard.encode(a).text == engine.guard.encode(b).text
    assert await collect(engine, first) == canonical


async def test_cursor_ttl_does_not_refresh_on_replay(engine):
    await engine.record(snapshot(), 1)
    first = await engine.inspect(SID, 1, json.dumps("🔥中" * 1000, ensure_ascii=False))
    engine.clock.advance(599)
    await engine.page(SID, first.cursor_id)
    engine.clock.advance(1)
    with pytest.raises(DeaError) as err:
        await engine.page(SID, first.cursor_id)
    assert err.value.code == ErrorCode.CURSOR_EXPIRED


async def test_count_eviction_invalidates_dependent_cursors():
    engine = StateEngine(RuntimeLimits(history_snapshots=1), FakeClock(), WireGuard())
    await engine.record(snapshot(), 1)
    first = await engine.inspect(SID, 1, json.dumps("🔥中" * 1000, ensure_ascii=False))
    await engine.record(snapshot(2), 2)
    with pytest.raises(DeaError) as err:
        await engine.page(SID, first.cursor_id)
    assert err.value.code == ErrorCode.CURSOR_EXPIRED


async def test_byte_eviction_and_atomic_oversize():
    engine = StateEngine(RuntimeLimits(history_bytes=4000), FakeClock(), WireGuard())
    await engine.record(snapshot(), 1)
    first = await engine.inspect(SID, 1, json.dumps("x" * 600))
    for i in range(2, 8):
        await engine.record(snapshot(i), i)
    assert engine._sessions[SID].size <= 4000
    with pytest.raises(DeaError):
        await engine.page(SID, first.cursor_id)
    with pytest.raises(DeaError) as err:
        await engine.record(snapshot(8, variables=(value(text="x" * 10000),)), 8)
    assert err.value.code == ErrorCode.HISTORY_UNAVAILABLE
    assert engine._sessions[SID].last_stop == 7


async def test_memory_exact_contiguous_changes_and_requested_baseline(engine):
    region = MemoryRegion(address=0x1000, size=6)
    for stop, data in ((1, b"abcdef"), (2, b"XbcXYf"), (3, b"Abcdef")):
        await engine.record(snapshot(stop, memory=(MemoryRead(region=region, data=data),)), stop)
    out = await engine.memory_diff(SID, 1)
    assert out.stop_id == 3
    assert [(d.address, d.before, d.after) for d in out.changes] == [(0x1000, b"a", b"A")]
    out = await engine.memory_diff(SID, 2)
    assert [(d.address, d.before, d.after) for d in out.changes] == [
        (0x1000, b"X", b"A"), (0x1003, b"XY", b"de")]


async def test_memory_missing_mismatched_and_current_baseline(engine):
    await engine.record(snapshot(), 1)
    await engine.record(snapshot(2), 2)
    for baseline in (1, 2, 999):
        with pytest.raises(DeaError) as err:
            await engine.memory_diff(SID, baseline)
        assert err.value.code == ErrorCode.HISTORY_UNAVAILABLE


async def test_monotonic_stop_and_event_rejected(engine):
    await engine.record(snapshot(), 3)
    for raw, event in ((snapshot(), 4), (snapshot(2), 3)):
        with pytest.raises(DeaError) as err:
            await engine.record(raw, event)
        assert err.value.code == ErrorCode.INVALID_REQUEST


async def test_inspect_invalid_json_and_no_live_recapture(engine):
    await engine.record(snapshot(), 1)
    for text in ("NaN", "{", '{"value":Infinity}'):
        with pytest.raises(DeaError) as err:
            await engine.inspect(SID, 1, text)
        assert err.value.code == ErrorCode.INVALID_REQUEST
    first = await engine.inspect(SID, 1, '{ "x": "value" }')
    assert first.text == '{"x":"value"}'


async def test_close_idempotent_releases_all_state(engine):
    await engine.record(snapshot(), 1)
    page = await engine.inspect(SID, 1, json.dumps("🔥中" * 1000, ensure_ascii=False))
    await engine.close_session(SID)
    await engine.close_session(SID)
    assert not engine._sessions
    with pytest.raises(DeaError) as err:
        await engine.page(SID, page.cursor_id)
    assert err.value.code == ErrorCode.CURSOR_EXPIRED


def test_owned_roots():
    assert worker_can_write(3, "src/dea/state/engine.py")
    assert worker_can_write(3, "tests/state/test_engine.py")

async def test_each_continuation_has_its_own_creation_deadline(engine):
    await engine.record(snapshot(), 1)
    first = await engine.inspect(SID, 1, json.dumps("🔥中" * 1000, ensure_ascii=False))
    engine.clock.advance(599)
    second = await engine.page(SID, first.cursor_id)
    engine.clock.advance(2)
    with pytest.raises(DeaError):
        await engine.page(SID, first.cursor_id)
    third = await engine.page(SID, second.cursor_id)
    assert third.offset == second.next_offset
    engine.clock.advance(598)
    with pytest.raises(DeaError):
        await engine.page(SID, second.cursor_id)


async def test_exact_same_memory_region_set_required(engine):
    a = MemoryRead(region=MemoryRegion(address=10, size=2), data=b"ab")
    b = MemoryRead(region=MemoryRegion(address=20, size=2), data=b"cd")
    await engine.record(snapshot(memory=(a, b)), 1)
    await engine.record(snapshot(2, memory=(a,)), 2)
    with pytest.raises(DeaError) as err:
        await engine.memory_diff(SID, 1)
    assert err.value.code == ErrorCode.HISTORY_UNAVAILABLE


async def test_overlapping_raw_regions_rejected(engine):
    a = MemoryRead(region=MemoryRegion(address=10, size=2), data=b"ab")
    b = MemoryRead(region=MemoryRegion(address=11, size=2), data=b"cd")
    with pytest.raises(DeaError) as err:
        await engine.record(snapshot(memory=(a, b)), 1)
    assert err.value.code == ErrorCode.INVALID_REQUEST


async def test_long_frame_metadata_has_exact_detail_cursor(engine):
    frame = RawFrame(index=0, identity="main", location=SourceLocation(
        file="main.c", line=1, function="f" * 100))
    out = await engine.record(snapshot(frames=(frame,)), 1)
    assert out.cursor_id
    exact = await details(engine, out)
    assert exact["frames"][0]["location"]["function"] == "f" * 100


async def test_session_capacity_released_on_close():
    engine = StateEngine(RuntimeLimits(maximum_sessions=1), FakeClock(), WireGuard())
    await engine.record(snapshot(), 1)
    other = snapshot().model_copy(update={"session_id": "fedcba9876543210"})
    with pytest.raises(DeaError) as err:
        await engine.record(other, 1)
    assert err.value.code == ErrorCode.RESOURCE_LIMIT
    await engine.close_session(SID)
    await engine.record(other, 1)


async def test_unreadable_first_value_is_not_a_deletion(engine):
    raw = RawValue(identity="x", name="x", available=False)
    out = await engine.record(snapshot(variables=(raw,), variables_complete=True), 1)
    assert not out.variable_deltas
    out = await engine.record(snapshot(2, variables=(value(),)), 2)
    assert out.variable_deltas[0].operation == "add"


async def test_value_reference_stable_between_stops(engine):
    out = await engine.record(snapshot(variables=(value(text="x" * 200),)), 1)
    reference = out.variable_deltas[0].after_reference
    out = await engine.record(snapshot(2, variables=(value(text="y" * 200),)), 2)
    assert out.variable_deltas[0].before_reference == reference
    exact = await details(engine, out)
    assert exact["references"][reference] == "x" * 200


async def test_error_payloads_are_always_measured(engine):
    for code in ErrorCode:
        result = engine.guard.error(code)
        assert all(count <= 191 for _, count in result.token_counts)

async def test_long_symbol_hash_collision_preserves_distinct_exact_names(engine, monkeypatch):
    class Collision:
        def hexdigest(self):
            return "0" * 64
    monkeypatch.setattr("dea.state.engine.hashlib.sha256", lambda data: Collision())
    raw = (value("a" * 80), value("b" * 80), value("@" + "0" * 63))
    out = await engine.record(snapshot(variables=raw), 1)
    exact = await details(engine, out)
    mapped = exact["symbols"]
    assert mapped["a" * 80] != mapped["b" * 80]
    assert mapped["a" * 80] != "@" + "0" * 63
    assert {item["id"] for item in exact["variables"]} == {item.identity for item in raw}
    out = await engine.record(snapshot(2, variables=tuple(v.model_copy(update={"value": "2"}) for v in raw)), 2)
    exact2 = await details(engine, out)
    assert exact2["symbols"]["a" * 80] == mapped["a" * 80]


async def test_reference_survives_cursor_expiry_while_snapshot_retained(engine):
    out = await engine.record(snapshot(variables=(value(text="a" * 200),)), 1)
    reference = out.variable_deltas[0].after_reference
    engine.clock.advance(600)
    out = await engine.record(snapshot(2, variables=(value(text="b" * 200),)), 2)
    assert out.variable_deltas[0].before_reference == reference


async def test_near_budget_paging_does_not_duplicate_immutable_text():
    engine = StateEngine(RuntimeLimits(history_bytes=16000), FakeClock(), WireGuard())
    await engine.record(snapshot(), 1)
    exact = json.dumps("🔥中" * 900, ensure_ascii=False, separators=(",", ":"))
    first = await engine.inspect(SID, 1, exact)
    assert await collect(engine, first) == exact
    session = engine._sessions[SID]
    assert session.size <= 16000
    assert all(not hasattr(cursor, "result") for cursor in session.cursors.values())

@pytest.mark.parametrize("repetitions", [900, 1000])
async def test_cursor_replay_cache_evicts_before_blocking_accepted_object(repetitions):
    engine = StateEngine(RuntimeLimits(history_bytes=10000), FakeClock(), WireGuard())
    await engine.record(snapshot(), 1)
    exact = json.dumps("漢🪲" * repetitions, ensure_ascii=False)
    first = await engine.inspect(SID, 1, exact)
    original_cursor = first.cursor_id
    result = first
    reconstructed = first.text
    pages = 1
    while result.cursor_id:
        cursor_id = result.cursor_id
        result = await engine.page(SID, cursor_id)
        replay = await engine.page(SID, cursor_id)
        assert engine.guard.encode(replay).text == engine.guard.encode(result).text
        reconstructed += result.text
        pages += 1
        assert engine._sessions[SID].size <= 10000
    assert reconstructed == exact
    assert pages > 25
    assert len(engine._sessions[SID].cursors) < pages - 1
    with pytest.raises(DeaError) as err:
        await engine.page(SID, original_cursor)
    assert err.value.code == ErrorCode.CURSOR_EXPIRED
