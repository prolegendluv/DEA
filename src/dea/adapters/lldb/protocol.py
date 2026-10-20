"""Standalone standard-library codec for an LLDB-compatible helper interpreter."""
import json
import socket
import struct
import threading

MAXIMUM = 1048576


class ProtocolError(Exception):
    pass


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ProtocolError("Duplicate key")
        result[key] = value
    return result


def loads(value):
    return json.loads(value, object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ProtocolError("Nonfinite JSON")))


def dumps(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def validate_request(operation, body):
    """Mirror frozen JSON request primitives without depending on Pydantic's ABI."""
    fields = {
        "session_start": ({"backend", "binary_path"}, {"backend", "binary_path", "args", "env", "cwd", "io_mode", "stop_at_entry", "memory_regions"}),
        "session_attach": ({"backend", "pid"}, {"backend", "pid", "binary_path", "memory_regions"}),
        "breakpoint_set": ({"location"}, {"location", "condition"}),
        "execution_continue": (set(), set()), "execution_interrupt": (set(), set()),
        "execution_step": ({"mode"}, {"mode"}),
        "snapshot_capture": ({"stop_id", "reason"}, {"stop_id", "reason", "frame_index", "max_depth", "memory_regions"}),
        "state_inspect_frame": ({"frame_index", "max_depth"}, {"frame_index", "max_depth"}),
        "state_eval_expression": ({"expr"}, {"expr"}),
        "state_read_memory": ({"address", "size"}, {"address", "size"}),
        "session_terminate": ({"policy"}, {"policy"}),
    }
    if operation not in fields or not isinstance(body, dict):
        raise ProtocolError("Unknown request")
    required, allowed = fields[operation]
    if not required <= set(body) or set(body) - allowed:
        raise ProtocolError("Request fields")
    integers = {"pid": (1, 2**63-1), "stop_id": (1, 2**63-1), "frame_index": (0, 2**63-1),
                "max_depth": (0, 8), "address": (0, 2**64-1), "size": (1, 65536)}
    strings = {"binary_path": (1, 4096), "cwd": (1, 4096), "location": (1, 4096),
               "condition": (0, 4096), "expr": (1, 4096)}
    enums = {"backend": ("lldb",), "io_mode": ("capture", "pty"), "mode": ("over", "into", "out"),
             "reason": ("entry", "breakpoint", "watchpoint", "step", "signal", "exception", "interrupt"),
             "policy": ("detach", "terminate_owned")}
    for key, value in body.items():
        if key in integers:
            low, high = integers[key]
            if type(value) is not int or not low <= value <= high:
                raise ProtocolError("Request integer")
        elif key in strings:
            if value is None and key in ("cwd", "condition", "binary_path") and key not in required:
                continue
            low, high = strings[key]
            if not isinstance(value, str) or not low <= len(value) <= high or "\x00" in value:
                raise ProtocolError("Request string")
        elif key in enums:
            if value not in enums[key]:
                raise ProtocolError("Request enum")
        elif key == "stop_at_entry" and type(value) is not bool:
            raise ProtocolError("Request boolean")
        elif key == "args":
            if not isinstance(value, list) or len(value) > 256 or any(
                    not isinstance(item, str) or len(item) > 32768 or "\x00" in item for item in value):
                raise ProtocolError("Request arguments")
        elif key == "env":
            if not isinstance(value, list) or len(value) > 256:
                raise ProtocolError("Request environment")
            keys = set()
            for entry in value:
                if not isinstance(entry, dict) or set(entry) != {"key", "value"}:
                    raise ProtocolError("Environment fields")
                name, content = entry["key"], entry["value"]
                if (not isinstance(name, str) or not 1 <= len(name) <= 256 or "=" in name or "\x00" in name
                        or not isinstance(content, str) or len(content) > 32768 or "\x00" in content
                        or name in keys):
                    raise ProtocolError("Environment value")
                keys.add(name)
        elif key == "memory_regions":
            if not isinstance(value, list) or len(value) > 16:
                raise ProtocolError("Memory regions")
            for region in value:
                validate_request("state_read_memory", region)
            ordered = sorted(value, key=lambda region: region["address"])
            if sum(region["size"] for region in value) > 65536 or any(
                    left["address"] + left["size"] > right["address"] for left, right in zip(ordered, ordered[1:])):
                raise ProtocolError("Memory bounds")
    if operation == "state_read_memory" and body["address"] + body["size"] > 2**64:
        raise ProtocolError("Memory overflow")
    return body


def validate(message):
    if not isinstance(message, dict) or set(message) - {
            "version", "kind", "operation", "request_id", "event_id", "body_json"}:
        raise ProtocolError("Invalid envelope")
    if type(message.get("version")) is not int or message["version"] != 1:
        raise ProtocolError("Version")
    if message.get("kind") not in ("request", "response", "event"):
        raise ProtocolError("Kind")
    operation = message.get("operation")
    if not isinstance(operation, str) or not 1 <= len(operation) <= 64:
        raise ProtocolError("Operation")
    correlation = "event_id" if message["kind"] == "event" else "request_id"
    other = "request_id" if correlation == "event_id" else "event_id"
    identifier = message.get(correlation)
    if type(identifier) is not int or not 1 <= identifier <= 2**63 - 1 or message.get(other) is not None:
        raise ProtocolError("Correlation")
    if not isinstance(message.get("body_json"), str) or len(message["body_json"]) > MAXIMUM:
        raise ProtocolError("Body")
    body = loads(message["body_json"])
    if not isinstance(body, dict):
        raise ProtocolError("Body must be an object")
    return body


def frame(message, maximum=MAXIMUM):
    validate(message)
    data = dumps(message).encode("utf-8", "strict")
    if not 1 <= len(data) <= min(maximum, MAXIMUM):
        raise ProtocolError("Length")
    return struct.pack("!I", len(data)) + data


class Connection:
    def __init__(self, sock, maximum=MAXIMUM):
        self.socket = sock
        self.maximum = min(maximum, MAXIMUM)
        self.writing = threading.Lock()

    def _read(self, length, allow_eof=False):
        data = bytearray()
        while len(data) < length:
            part = self.socket.recv(length - len(data))
            if not part:
                if allow_eof and not data:
                    raise EOFError()
                raise ProtocolError("Truncated frame")
            data.extend(part)
        return bytes(data)

    def receive(self):
        prefix = self._read(4, allow_eof=True)
        length = struct.unpack("!I", prefix)[0]
        if not 1 <= length <= self.maximum:
            raise ProtocolError("Length")
        message = loads(self._read(length).decode("utf-8", "strict"))
        validate(message)
        return message

    def send(self, message):
        data = frame(message, self.maximum)
        with self.writing:
            self.socket.sendall(data)

    def close(self):
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.socket.close()


def envelope(kind, operation, identifier, body):
    return {"version": 1, "kind": kind, "operation": operation,
            "event_id" if kind == "event" else "request_id": identifier,
            "body_json": dumps(body)}
