import json
import struct
import pytest
from dea.contracts.models import DeaError, ErrorCode, HelperMessage
from dea.runtime.framing import FrameDecoder, encode_frame


def request(**updates):
    fields = dict(kind="request", request_id=2, operation="state_eval_expression",
                  body_json=json.dumps({"expr": "🍇水 + é"}))
    fields.update(updates)
    return HelperMessage(**fields)


def raw_frame(text):
    data = text.encode("utf-8") if isinstance(text, str) else text
    return struct.pack("!I", len(data)) + data


def test_every_fragment_boundary_and_multiple_records():
    message = request()
    wire = encode_frame(message)
    for index in range(len(wire)+1):
        decoder = FrameDecoder()
        assert decoder.feed(wire[:index]) + decoder.feed(wire[index:]) == [message]
        decoder.eof()
    decoder = FrameDecoder()
    assert decoder.feed(wire*3) == [message]*3
    decoder.eof()


def test_bytewise_utf8():
    decoder = FrameDecoder()
    result = []
    for value in encode_frame(request()):
        result.extend(decoder.feed(bytes([value])))
    assert result == [request()]
    decoder.eof()


@pytest.mark.parametrize("wire", [
    struct.pack("!I", 0), struct.pack("!I", 1_048_577), raw_frame(b"\xff"),
    raw_frame('{"version":1,"kind":"request","request_id":2,"operation":"execution_continue","body_json":"NaN"}'),
    raw_frame('{"version":1,"kind":"request","request_id":2,"operation":"execution_continue","body_json":"{}","extra":1}'),
    raw_frame('{"version":1,"kind":"request","request_id":2,"operation":"execution_continue","body_json":"{}","request_id":3}'),
    raw_frame('[]'), raw_frame('{}'), raw_frame('{"hello":Infinity}'),
])
def test_malformed_framing_is_fatal(wire):
    decoder = FrameDecoder()
    with pytest.raises(DeaError, match="PROTOCOL_ERROR"):
        decoder.feed(wire)
    with pytest.raises(DeaError):
        decoder.feed(encode_frame(request()))


@pytest.mark.parametrize("prefix", [b"\0", b"\0\0", b"\0\0\0", struct.pack("!I", 5), struct.pack("!I", 5)+b"abc"])
def test_truncated_eof(prefix):
    decoder = FrameDecoder()
    decoder.feed(prefix)
    with pytest.raises(DeaError, match="PROTOCOL_ERROR"):
        decoder.eof()


@pytest.mark.parametrize("message", [
    request(operation="unknown"),
    request(operation="execution_step", body_json='{"mode":"sideways"}'),
    request(operation="execution_step", body_json='{"mode":"over","extra":true}'),
    request(operation="execution_continue", body_json="[]"),
    request(operation="execution_continue", body_json='{"x":1}'),
    request(operation="state_eval_expression", body_json='{"expr":42}'),
    request(operation="state_eval_expression", body_json='{"expr":"x","expr":"y"}'),
    request(operation="state_read_memory", body_json='{"address":"1","size":1}'),
    request(operation="state_inspect_frame", body_json='{"frame_index":true,"max_depth":1}'),
    request(request_id=1),
    HelperMessage(kind="event",event_id=1,operation="debugger_event",body_json='{"event_id":2,"kind":"running"}'),
    HelperMessage(kind="event",event_id=1,operation="unknown",body_json='{}'),
    HelperMessage(kind="response",request_id=2,operation="error",body_json='{"code":"BOGUS"}'),
])
def test_body_and_correlation_validation(message):
    with pytest.raises(DeaError, match="PROTOCOL_ERROR"):
        encode_frame(message)


def test_encoded_byte_limit_includes_envelope_and_escaping():
    with pytest.raises(DeaError, match="PROTOCOL_ERROR"):
        encode_frame(request(), maximum=10)
    decoder = FrameDecoder(100)
    with pytest.raises(DeaError, match="PROTOCOL_ERROR"):
        decoder.feed(struct.pack("!I", 101))


def test_all_declared_request_and_response_shapes():
    messages = [
        request(operation="execution_continue", body_json="{}"),
        request(operation="execution_step", body_json='{"mode":"over"}'),
        request(operation="session_terminate", body_json='{"policy":"detach"}'),
        HelperMessage(kind="response",request_id=2,operation="session_terminate",body_json="{}"),
        HelperMessage(kind="response",request_id=2,operation="error",body_json='{"code":"CAPABILITY_UNAVAILABLE"}'),
        HelperMessage(kind="event",event_id=1,operation="debugger_event",body_json='{"event_id":1,"kind":"stopped","reason":"step"}'),
    ]
    for message in messages:
        assert FrameDecoder().feed(encode_frame(message)) == [message]
