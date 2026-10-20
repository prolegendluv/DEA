"""Exact bounded history and immutable, token-measured presentations.

This module depends only on frozen contracts. No compact result participates in
subsequent comparisons, and paging never performs a debugger operation.
"""
from collections import OrderedDict
from dataclasses import dataclass, field
import hashlib
import json

from dea.contracts.compact import (
    CompactDebugState, CompactFrame, CompactLocation, InspectionPage,
    OmissionCounts, ValueDelta,
)
from dea.contracts.models import (
    DeaError, ErrorCode, MAX_INT, MemoryChange, RawMemoryDiff, RawSnapshot,
    RawValue, RuntimeLimits, SourceLocation,
)
from dea.contracts.services import Clock
from dea.contracts.wire import TokenBudgetExceeded, WireGuard


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def _size(text: str) -> int:
    return len(text.encode("utf-8", errors="strict"))


@dataclass
class _Cursor:
    object_id: str
    offset: int
    created: float
    end: int | None = None
    next_handle: str | None = None
    size: int = 128


@dataclass
class _Object:
    stop_id: int
    text: str
    created: float
    size: int
    references: dict[str, str] = field(default_factory=dict)


@dataclass
class _Stop:
    snapshot: RawSnapshot
    registers: dict[str, RawValue]
    variables: dict[str, RawValue]
    size: int
    symbols: dict[str, str] = field(default_factory=dict)
    references: dict[str, str] = field(default_factory=dict)


@dataclass
class _Session:
    stops: OrderedDict[int, _Stop] = field(default_factory=OrderedDict)
    objects: dict[str, _Object] = field(default_factory=dict)
    cursors: dict[str, _Cursor] = field(default_factory=dict)
    size: int = 0
    last_stop: int = 0
    last_event: int = 0


class StateEngine:
    def __init__(self, limits: RuntimeLimits, clock: Clock, guard: WireGuard) -> None:
        self.limits, self.clock, self.guard = limits, clock, guard
        self._sessions: dict[str, _Session] = {}
        self._sequence = 0

    def _handle(self) -> str:
        # One allocator for all live detail/cursor handles; never wrap or reuse.
        if self._sequence == 2**64 - 1:
            raise DeaError(ErrorCode.RESOURCE_LIMIT)
        self._sequence += 1
        return f"{self._sequence:016x}"

    def _drop_object(self, session: _Session, object_id: str) -> None:
        obj = session.objects.pop(object_id)
        session.size -= obj.size
        for handle, cursor in tuple(session.cursors.items()):
            if cursor.object_id == object_id:
                session.size -= cursor.size
                del session.cursors[handle]

    def _drop_stop(self, session: _Session, stop_id: int) -> None:
        session.size -= session.stops.pop(stop_id).size
        for handle, obj in tuple(session.objects.items()):
            if obj.stop_id == stop_id:
                self._drop_object(session, handle)

    def _expire(self, session: _Session) -> None:
        now = self.clock.now()
        for handle, cursor in tuple(session.cursors.items()):
            if now - cursor.created >= self.limits.cursor_ttl_seconds:
                session.size -= cursor.size
                del session.cursors[handle]
        referenced = {cursor.object_id for cursor in session.cursors.values()}
        for handle in tuple(session.objects):
            if handle not in referenced:
                self._drop_object(session, handle)

    def _room(self, session: _Session, extra: int, protect: int,
              protected_cursors: frozenset[str] = frozenset()) -> None:
        # Cursor replay is a bounded cache. Preserve the requesting cursor and
        # its immutable object while retiring oldest replay entries first.
        protected = session.stops.get(protect)
        protected_objects = {session.cursors[handle].object_id
                             for handle in protected_cursors}
        retained = (protected.size if protected else 0) + sum(
            session.objects[handle].size for handle in protected_objects
        ) + sum(session.cursors[handle].size for handle in protected_cursors)
        if retained + extra > self.limits.history_bytes:
            raise DeaError(ErrorCode.HISTORY_UNAVAILABLE)
        while session.size + extra > self.limits.history_bytes:
            cursor_id = next((handle for handle in session.cursors
                              if handle not in protected_cursors), None)
            if cursor_id is not None:
                cursor = session.cursors.pop(cursor_id)
                session.size -= cursor.size
                if (cursor.object_id not in protected_objects and
                        not any(cur.object_id == cursor.object_id
                                for cur in session.cursors.values())):
                    self._drop_object(session, cursor.object_id)
                continue
            victim = next((sid for sid in session.stops if sid != protect), None)
            if victim is None:
                raise DeaError(ErrorCode.HISTORY_UNAVAILABLE)
            self._drop_stop(session, victim)

    @staticmethod
    def _effective(values: tuple[RawValue, ...], previous: dict[str, RawValue],
                   complete: bool) -> dict[str, RawValue]:
        current = {} if complete else previous.copy()
        for value in values:
            if value.available:
                current[value.identity] = value
            elif value.identity in previous:
                current[value.identity] = previous[value.identity]
        return current

    @staticmethod
    def _deltas(values: tuple[RawValue, ...], previous: dict[str, RawValue], complete: bool):
        observed = {value.identity: value for value in values}
        result = []
        for identity in sorted(previous.keys() | observed.keys()):
            before, after = previous.get(identity), observed.get(identity)
            if after is not None and not after.available:
                continue
            if after is None and (not complete or before is None):
                continue
            if before is not None and after is not None and before.value == after.value:
                continue
            item = {"id": identity, "name": (after or before).name,
                    "op": "add" if before is None else "del" if after is None else "set"}
            if before is not None:
                item["before"] = before.value
            if after is not None:
                item["after"] = after.value
            result.append((bool((after or before).watched), item))
        return sorted(result, key=lambda entry: (not entry[0], entry[1]["id"]))

    def _display_delta(self, raw: dict, references: dict, session: _Session,
                       symbols: dict[str, str], reserved: set[str]) -> tuple[ValueDelta, bool]:
        item = dict(raw)
        needs_detail = False
        for key in ("id", "name"):
            exact_name = item[key]
            if exact_name in symbols:
                item[key] = symbols[exact_name]
                needs_detail = True
            elif len(exact_name) > 64 or exact_name in symbols.values():
                candidate = "@" + hashlib.sha256(exact_name.encode()).hexdigest()[:63]
                while candidate in reserved or candidate in symbols.values():
                    candidate = "@" + self._handle()
                symbols[exact_name] = candidate
                item[key] = candidate
                needs_detail = True
        for key, ref_key in (("before", "bref"), ("after", "aref")):
            if key in item and len(item[key]) > 96:
                exact = item[key]
                reference = next((handle for handle, text in references.items() if text == exact), None)
                if reference is None:
                    reference = next((handle for stop in session.stops.values()
                                      for handle, text in stop.references.items() if text == exact), None)
                if reference is None:
                    reference = self._handle()
                references[reference] = exact
                item[key], item[ref_key] = "<value>", reference
                needs_detail = True
        return ValueDelta(**item), needs_detail

    @staticmethod
    def _location(location: SourceLocation | None) -> CompactLocation | None:
        if location is None:
            return None
        values = {}
        if location.file is not None and len(location.file) <= 64:
            values["file"] = location.file
            values["line"] = location.line
        if location.function is not None and len(location.function) <= 64:
            values["function"] = location.function
        if location.address is not None:
            values["address"] = hex(location.address)
        return CompactLocation(**values) if values else None

    async def record(self, snapshot: RawSnapshot, event_id: int, hint: bool = False) -> CompactDebugState:
        # Validate callers that bypassed Pydantic's normal constructors.
        try:
            snapshot = RawSnapshot.model_validate_json(snapshot.model_dump_json())
        except (ValueError, TypeError, UnicodeError) as exc:
            raise DeaError(ErrorCode.INVALID_REQUEST) from exc
        regions = sorted(snapshot.memory, key=lambda item: item.region.address)
        if (len(regions) > 16 or sum(read.region.size for read in regions) > 65536 or
                any(a.region.address + a.region.size > b.region.address
                    for a, b in zip(regions, regions[1:]))):
            raise DeaError(ErrorCode.INVALID_REQUEST)
        session = self._sessions.get(snapshot.session_id)
        if session is None:
            if len(self._sessions) >= self.limits.maximum_sessions:
                raise DeaError(ErrorCode.RESOURCE_LIMIT)
            session = _Session()
        if snapshot.stop_id <= session.last_stop or event_id <= session.last_event:
            raise DeaError(ErrorCode.INVALID_REQUEST)
        self._expire(session)
        previous = next(reversed(session.stops.values()), None) if session.stops else None
        comparable = previous is not None and (
            previous.snapshot.thread_id, previous.snapshot.frame_context
        ) == (snapshot.thread_id, snapshot.frame_context)
        old_regs = previous.registers if comparable else {}
        old_vars = previous.variables if comparable else {}
        registers = self._effective(snapshot.registers, old_regs, snapshot.registers_complete)
        variables = self._effective(snapshot.variables, old_vars, snapshot.variables_complete)
        raw_regs = self._deltas(snapshot.registers, old_regs, snapshot.registers_complete)
        raw_vars = self._deltas(snapshot.variables, old_vars, snapshot.variables_complete)
        references = previous.references.copy() if comparable else {}
        symbols = previous.symbols.copy() if comparable else {}
        reserved = {item[key] for _, item in (*raw_regs, *raw_vars)
                    for key in ("id", "name") if len(item[key]) <= 64}
        regs, vars_ = [], []
        needs_detail = False
        for source, target in ((raw_vars, vars_), (raw_regs, regs)):
            for _, raw in source:
                display, referenced = self._display_delta(raw, references, session, symbols, reserved)
                target.append(display)
                needs_detail |= referenced
        frames = []
        for frame in sorted(snapshot.frames, key=lambda frame: (frame.index, frame.identity)):
            location = self._location(frame.location)
            if location is not None:
                frames.append(CompactFrame(index=frame.index, location=location))
            if ((frame.location.file and len(frame.location.file) > 64) or
                    (frame.location.function and len(frame.location.function) > 64)):
                needs_detail = True
        detail = _json({"registers": [item for _, item in raw_regs],
                        "variables": [item for _, item in raw_vars],
                        "frames": [frame.model_dump(mode="json") for frame in snapshot.frames],
                        "location": snapshot.location.model_dump(mode="json") if snapshot.location else None,
                        "references": references, "symbols": symbols})
        object_id, cursor_id = self._handle(), self._handle()
        location = self._location(snapshot.location)
        if snapshot.location is not None and (location is None or
                (snapshot.location.file and len(snapshot.location.file) > 64) or
                (snapshot.location.function and len(snapshot.location.function) > 64)):
            needs_detail = True
        keep_vars, keep_regs, keep_frames = min(8, len(vars_)), min(8, len(regs)), min(5, len(frames))
        thread = snapshot.thread_id
        while True:
            omitted = (len(regs) - keep_regs, len(vars_) - keep_vars,
                       len(snapshot.frames) - keep_frames)
            has_details = needs_detail or any(omitted)
            result = CompactDebugState(
                session_id=snapshot.session_id, event_id=event_id, stop_id=snapshot.stop_id,
                base_stop_id=previous.snapshot.stop_id if comparable else None,
                reason=snapshot.reason, thread_id=thread, location=location,
                register_deltas=tuple(regs[:keep_regs]), variable_deltas=tuple(vars_[:keep_vars]),
                frames=tuple(frames[:keep_frames]),
                omitted=OmissionCounts(registers=omitted[0], variables=omitted[1], frames=omitted[2]) if any(omitted) else None,
                cursor_id=cursor_id if has_details else None,
                hint="set_breakpoint" if hint else None,
            )
            try:
                self.guard.encode(result)
                break
            except TokenBudgetExceeded:
                if location is not None:
                    location = None
                    needs_detail |= snapshot.location is not None
                elif thread is not None:
                    thread = None
                elif keep_frames:
                    keep_frames -= 1
                elif keep_regs:
                    keep_regs -= 1
                elif keep_vars:
                    keep_vars -= 1
                else:
                    raise DeaError(ErrorCode.SERIALIZATION_FAILED)
        size = _size(snapshot.model_dump_json()) + 128 + _size(_json({
            "registers": [value.model_dump(mode="json") for value in registers.values()],
            "variables": [value.model_dump(mode="json") for value in variables.values()],
            "symbols": symbols,
            "references": references,
        }))
        object_size = _size(detail) + 128 if has_details else 0
        # Reserve space for both an initial cursor and its first continuation;
        # later reads can evict older replay entries without losing progress.
        self._room(session, size + object_size + (256 if has_details else 0), snapshot.stop_id)
        while len(session.stops) >= self.limits.history_snapshots:
            self._drop_stop(session, next(iter(session.stops)))
        effective = (*registers.values(), *variables.values())
        names = {text for value in effective for text in (value.identity, value.name)}
        values = {value.value for value in effective}
        session.stops[snapshot.stop_id] = _Stop(snapshot, registers, variables, size,
            {key: mapped for key, mapped in symbols.items() if key in names},
            {handle: text for handle, text in references.items() if text in values})
        session.size += size
        if has_details:
            session.objects[object_id] = _Object(snapshot.stop_id, detail, self.clock.now(), object_size, references)
            session.cursors[cursor_id] = _Cursor(object_id, 0, self.clock.now())
            session.size += object_size + 128
        session.last_stop, session.last_event = snapshot.stop_id, event_id
        self._sessions[snapshot.session_id] = session
        return result

    def _make_page(self, session_id: str, object_id: str, obj: _Object, offset: int,
                   next_handle: str) -> InspectionPage:
        remaining = len(obj.text) - offset
        # The binary search seeks a fitting chunk, not a mathematically maximal
        # chunk: tokenizer lengths need not be monotonic with character count.
        low, high, best = 1, min(4096, remaining), None
        if not remaining:
            low, high = 0, 0
        while low <= high:
            count = (low + high) // 2
            result = InspectionPage(session_id=session_id, stop_id=obj.stop_id,
                object_id=object_id, offset=offset, next_offset=offset + count,
                text=obj.text[offset:offset + count],
                cursor_id=next_handle if count < remaining else None)
            try:
                self.guard.encode(result)
            except TokenBudgetExceeded:
                high = count - 1
            else:
                best = result
                low = count + 1
        if best is None:
            raise DeaError(ErrorCode.SERIALIZATION_FAILED)
        return best

    async def page(self, session_id: str, cursor_id: str) -> InspectionPage:
        session = self._sessions.get(session_id)
        if session is None:
            raise DeaError(ErrorCode.CURSOR_EXPIRED)
        self._expire(session)
        cursor = session.cursors.get(cursor_id)
        if cursor is None:
            raise DeaError(ErrorCode.CURSOR_EXPIRED)
        obj = session.objects[cursor.object_id]
        if cursor.end is not None:
            result = InspectionPage(session_id=session_id, stop_id=obj.stop_id,
                object_id=cursor.object_id, offset=cursor.offset,
                next_offset=cursor.end, text=obj.text[cursor.offset:cursor.end],
                cursor_id=cursor.next_handle)
            self.guard.encode(result)
            return result
        next_handle = self._handle()
        result = self._make_page(session_id, cursor.object_id, obj, cursor.offset, next_handle)
        extra = 128 if result.cursor_id else 0
        self._room(session, extra, obj.stop_id, frozenset((cursor_id,)))
        cursor.end, cursor.next_handle = result.next_offset, result.cursor_id
        session.size += extra
        if result.cursor_id:
            session.cursors[next_handle] = _Cursor(cursor.object_id, result.next_offset, self.clock.now())
        return result

    async def inspect(self, session_id: str, stop_id: int, value_json: str) -> InspectionPage:
        session = self._sessions.get(session_id)
        if session is None or stop_id not in session.stops:
            raise DeaError(ErrorCode.HISTORY_UNAVAILABLE)
        self._expire(session)
        try:
            text = _json(json.loads(value_json, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value))))
            size = _size(text) + 128
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise DeaError(ErrorCode.INVALID_REQUEST) from exc
        object_id, next_handle = self._handle(), self._handle()
        obj = _Object(stop_id, text, self.clock.now(), size)
        result = self._make_page(session_id, object_id, obj, 0, next_handle)
        self._room(session, size + (256 if result.cursor_id else 0), stop_id)
        if result.cursor_id:
            session.objects[object_id] = obj
            session.cursors[next_handle] = _Cursor(object_id, result.next_offset, self.clock.now())
            session.size += size + 128
        return result

    async def memory_diff(self, session_id: str, since_step_id: int) -> RawMemoryDiff:
        session = self._sessions.get(session_id)
        if session is None or since_step_id not in session.stops:
            raise DeaError(ErrorCode.HISTORY_UNAVAILABLE)
        baseline = session.stops[since_step_id].snapshot
        current = next(reversed(session.stops.values())).snapshot
        before = {(read.region.address, read.region.size): read.data for read in baseline.memory}
        after = {(read.region.address, read.region.size): read.data for read in current.memory}
        if since_step_id >= current.stop_id or not before or before.keys() != after.keys():
            raise DeaError(ErrorCode.HISTORY_UNAVAILABLE)
        changes = []
        for (address, size), data in sorted(before.items()):
            updated = after[address, size]
            start = None
            for index in range(size + 1):
                differs = index < size and data[index] != updated[index]
                if differs and start is None:
                    start = index
                elif not differs and start is not None:
                    changes.append(MemoryChange(address=address + start,
                        before=data[start:index], after=updated[start:index]))
                    start = None
        return RawMemoryDiff(session_id=session_id, since_step_id=since_step_id,
                             stop_id=current.stop_id, changes=tuple(changes))

    async def close_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
