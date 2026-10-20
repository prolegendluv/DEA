import json
import socket
import struct
import threading

import pytest

from dea.adapters.lldb.protocol import Connection, ProtocolError, envelope, frame, validate_request


def test_fragmented_utf8_and_coalesced_frames():
    left, right = socket.socketpair()
    connection = Connection(left)
    one = envelope("request", "state_eval_expression", 2, {"expr": "λ + '雪'"})
    two = envelope("request", "execution_continue", 3, {})
    def writer():
        for byte in frame(one) + frame(two): right.sendall(bytes([byte]))
        right.close()
    worker = threading.Thread(target=writer)
    worker.start()
    try:
        assert connection.receive() == one
        assert connection.receive() == two
        with pytest.raises(EOFError): connection.receive()
    finally:
        connection.close()
        worker.join(2)


@pytest.mark.parametrize("payload", [b"\x00\x00", struct.pack("!I", 0),
    struct.pack("!I", 1048577), struct.pack("!I", 3) + b"{}",
    struct.pack("!I", 1) + b"\xff"])
def test_malformed_frames(payload):
    left, right = socket.socketpair()
    right.sendall(payload)
    right.close()
    connection = Connection(left)
    try:
        with pytest.raises((ProtocolError, UnicodeError)): connection.receive()
    finally:
        connection.close()


@pytest.mark.parametrize("body", ['{"x":NaN}', '{"x":1,"x":2}', '[]'])
def test_invalid_body_json(body):
    message = envelope("request", "state_eval_expression", 2, {})
    message["body_json"] = body
    with pytest.raises((ProtocolError, ValueError)): frame(message)


def test_outer_byte_limit_accounts_for_escaping():
    message = envelope("request", "state_eval_expression", 2, {"expr": '"' * 100})
    with pytest.raises(ProtocolError): frame(message, 200)


@pytest.mark.parametrize("operation,body", [
    ("execution_continue", {"raw_command": "spoof"}),
    ("state_inspect_frame", {"frame_index": True, "max_depth": 0}),
    ("state_read_memory", {"address": 2**64-1, "size": 2}),
    ("execution_step", {"mode": "reverse"}),
    ("session_start", {"backend": "lldb", "binary_path": "demo", "stop_at_entry": 1}),
    ("session_start", {"backend": "lldb", "binary_path": "demo", "args": [1]}),
    ("unknown", {}),
])
def test_helper_rejects_untyped_or_extra_request_fields(operation, body):
    with pytest.raises(ProtocolError): validate_request(operation, body)
