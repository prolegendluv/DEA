"""A real child using only stdlib, intentionally independent of runtime framing."""
import json
import os
import socket
import struct
import sys
import time


def send(sock, envelope):
    body = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(body)) + body)


def receive(sock):
    def exact(size):
        result = b""
        while len(result) < size:
            part = sock.recv(size-len(result))
            if not part:
                raise EOFError
            result += part
        return result
    return json.loads(exact(struct.unpack("!I", exact(4))[0]))


mode = sys.argv[1]
sock = socket.create_connection((os.environ["DEA_CONTROL_HOST"], int(os.environ["DEA_CONTROL_PORT"])))
token = os.environ["DEA_CONTROL_TOKEN"] if mode != "bad" else "wrong-token"
send(sock, dict(version=1, kind="request", request_id=1, operation="hello",
                body_json=json.dumps({"token":token})))
if mode == "bad":
    time.sleep(30)
else:
    receive(sock)
    if mode == "truncated":
        sock.sendall(b"\0\0\0\x10bad")
        sock.close()
        time.sleep(30)
    elif mode == "overflow":
        for index in range(100):
            send(sock, dict(version=1, kind="event", event_id=index+1, operation="debugger_event",
                body_json=json.dumps(dict(event_id=index+1, kind="running"))))
        time.sleep(30)
    elif mode == "unexpected-eof":
        sock.close()
        time.sleep(30)
    elif mode == "expected-eof":
        send(sock, dict(version=1, kind="event", event_id=1, operation="debugger_event",
             body_json=json.dumps(dict(event_id=1, kind="exited", exit_code=0))))
        sock.close()
        time.sleep(30)
    else:
        print('{"kind":"event","operation":"debugger_event"}', flush=True)
        request = receive(sock)
        send(sock, dict(version=1, kind="response", request_id=request["request_id"],
                        operation=request["operation"], body_json='{"request_id":2,"accepted":true}'))
        # Exit is controlled by the supervisor, keeping unexpected-EOF out of echo tests.
        time.sleep(30)
