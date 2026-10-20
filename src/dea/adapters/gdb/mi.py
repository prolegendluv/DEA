"""Incremental GDB/MI grammar. Results retain ordering and duplicate keys."""
from __future__ import annotations

from dataclasses import dataclass
import re


class MIParseError(ValueError):
    pass


@dataclass(frozen=True)
class MIMap:
    pairs: tuple[tuple[str, object], ...] = ()

    def get(self, key, default=None):
        return next((value for name, value in self.pairs if name == key), default)

    def all(self, key):
        return tuple(value for name, value in self.pairs if name == key)

    def __getitem__(self, key):
        found = self.all(key)
        if not found:
            raise KeyError(key)
        return found[0]


@dataclass(frozen=True)
class MIList:
    values: tuple[object, ...] = ()


@dataclass(frozen=True)
class MIRecord:
    kind: str
    cls: str = ""
    token: int | None = None
    results: MIMap = MIMap()
    text: str | None = None


class _Grammar:
    def __init__(self, line: str):
        self.line = line
        self.pos = 0

    def fail(self):
        raise MIParseError(f"Invalid MI grammar at position {self.pos}")

    def peek(self):
        return self.line[self.pos:self.pos + 1]

    def consume(self, text):
        if not self.line.startswith(text, self.pos):
            self.fail()
        self.pos += len(text)

    def word(self):
        match = re.match(r"[A-Za-z_][A-Za-z0-9_-]*", self.line[self.pos:])
        if not match:
            self.fail()
        self.pos += len(match[0])
        return match[0]

    def string(self):
        self.consume('"')
        out = bytearray()
        escapes = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12,
                   "r": 13, '"': 34, "'": 39, "\\": 92, "?": 63}
        while self.peek() and self.peek() != '"':
            ch = self.peek()
            self.pos += 1
            if ch != "\\":
                if ord(ch) < 32:
                    self.fail()
                out.extend(ch.encode("utf-8"))
                continue
            ch = self.peek()
            self.pos += 1
            if ch in escapes:
                out.append(escapes[ch])
            elif ch and ch in "01234567":
                digits = ch
                for _ in range(2):
                    if self.peek() and self.peek() in "01234567":
                        digits += self.peek()
                        self.pos += 1
                value = int(digits, 8)
                if value > 255:
                    self.fail()
                out.append(value)
            elif ch == "x":
                match = re.match(r"[0-9a-fA-F]+", self.line[self.pos:])
                if not match or int(match[0], 16) > 255:
                    self.fail()
                out.append(int(match[0], 16))
                self.pos += len(match[0])
            else:
                self.fail()
        self.consume('"')
        # GDB emits byte-valued C strings, including non-UTF8 target strings.
        # surrogateescape preserves every original byte without replacement.
        return out.decode("utf-8", errors="surrogateescape")

    def result(self, depth):
        name = self.word()
        self.consume("=")
        return name, self.value(depth)

    def value(self, depth=0):
        if depth > 64:
            self.fail()
        ch = self.peek()
        if ch == '"':
            return self.string()
        if ch == "{":
            self.pos += 1
            pairs = []
            if self.peek() != "}":
                pairs.append(self.result(depth + 1))
                while self.peek() == ",":
                    self.pos += 1
                    pairs.append(self.result(depth + 1))
            self.consume("}")
            return MIMap(tuple(pairs))
        if ch == "[":
            self.pos += 1
            values = []
            if self.peek() != "]":
                # A list is either a list of values or a list of results.
                results = self.peek() not in ('"', "{", "[")
                values.append(self.result(depth + 1) if results else self.value(depth + 1))
                while self.peek() == ",":
                    self.pos += 1
                    values.append(self.result(depth + 1) if results else self.value(depth + 1))
            self.consume("]")
            return MIList(tuple(values))
        self.fail()


def parse_record(line: str) -> MIRecord | None:
    if line.strip() == "(gdb)" or not line:
        return None
    grammar = _Grammar(line)
    match = re.match(r"[0-9]+", line)
    token = None
    if match:
        digits = match[0].lstrip("0") or "0"
        if len(digits) > 19:
            grammar.fail()
        token = int(digits)
        if token > 2**63 - 1:
            grammar.fail()
        grammar.pos = len(match[0])
    kind = grammar.peek()
    if kind not in ("^", "*", "+", "=", "~", "@", "&"):
        grammar.fail()
    grammar.pos += 1
    if kind in ("~", "@", "&"):
        if token is not None:
            grammar.fail()
        record = MIRecord(kind, text=grammar.string())
    else:
        cls = grammar.word()
        pairs = []
        while grammar.peek() == ",":
            grammar.pos += 1
            pairs.append(grammar.result(0))
        record = MIRecord(kind, cls, token, MIMap(tuple(pairs)))
    if grammar.pos != len(line):
        grammar.fail()
    return record


class MIParser:
    """One parser per trusted control stdout; never feed program output here."""
    def __init__(self, max_bytes: int = 1_048_576):
        self._buffer = bytearray()
        self.max_bytes = max_bytes

    def feed(self, data: bytes) -> tuple[MIRecord, ...]:
        records = []
        for part in data.splitlines(keepends=True):
            self._buffer.extend(part)
            if len(self._buffer) > self.max_bytes:
                raise MIParseError("MI record exceeds configured byte limit")
            if self._buffer.endswith(b"\n"):
                line = bytes(self._buffer[:-1]).removesuffix(b"\r")
                self._buffer.clear()
                try:
                    record = parse_record(line.decode("utf-8", errors="surrogateescape"))
                except (UnicodeError, RecursionError) as exc:
                    raise MIParseError("Malformed MI record") from exc
                if record is not None:
                    records.append(record)
        return tuple(records)

    def finish(self) -> tuple[MIRecord, ...]:
        if not self._buffer:
            return ()
        if bytes(self._buffer).strip() == b"(gdb)":
            self._buffer.clear()
            return ()
        raise MIParseError("Truncated MI record at EOF")
