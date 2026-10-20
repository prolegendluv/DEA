"""Exercise the real isolated helper and framed socket on the host OS with SB doubles."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

from dea.adapters.lldb.discovery import HELPER
from dea.adapters.lldb.protocol import Connection, envelope, loads
from dea.contracts.models import RawSnapshot


def test_isolated_helper_authenticated_socket_and_output_separation(tmp_path):
    doubles = Path(__file__).with_name("doubles.py")
    stub = tmp_path / "lldb.py"
    stub.write_text(
        "import importlib.util\n"
        f"_spec = importlib.util.spec_from_file_location('_test_sb', {str(doubles)!r})\n"
        "_mod = importlib.util.module_from_spec(_spec)\n_spec.loader.exec_module(_mod)\n"
        "_api = _mod.make_api()\nglobals().update(vars(_api))\n"
        "SBDebugger.Initialize = lambda: None\nSBDebugger.Terminate = lambda: None\n"
        "debugger.IsValid = lambda: True\n"
        "process.stdout.append('(lldb){\"event_id\":999}\\n')\n"
        "process.stderr.append('separate diagnostic channel\\n')\n", encoding="utf-8")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    env = dict(os.environ, DEA_CONTROL_HOST="127.0.0.1", DEA_CONTROL_PORT=str(listener.getsockname()[1]),
               DEA_CONTROL_TOKEN="single-use-token")
    child = subprocess.Popen([sys.executable, "-I", str(HELPER), "--module-path", str(tmp_path),
        "--session-id", "0123456789abcdef"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=0x08000000 if os.name == "nt" else 0)
    connection = None
    events = []
    try:
        sock, _ = listener.accept()
        sock.settimeout(5)
        connection = Connection(sock)
        hello = connection.receive()
        assert hello == envelope("request", "hello", 1, {"token": "single-use-token"})
        connection.send(envelope("response", "hello", 1, {}))

        def request(identifier, operation, body):
            connection.send(envelope("request", operation, identifier, body))
            while True:
                message = connection.receive()
                if message["kind"] == "event":
                    events.append(loads(message["body_json"]))
                    continue
                assert message["request_id"] == identifier
                assert message["operation"] == operation, message
                return loads(message["body_json"])

        assert request(2, "session_start", {"backend": "lldb", "binary_path": "demo"})["accepted"]
        snapshot = request(3, "snapshot_capture", {"stop_id": 1, "reason": "entry", "max_depth": 0})
        assert RawSnapshot.model_validate_json(json.dumps(snapshot)).registers[0].value == "0x2a"
        assert request(4, "state_eval_expression", {"expr": "x+1"})["value"] == "43"
        assert request(5, "state_read_memory", {"address": 4096, "size": 3})["data"] == "enp6"
        assert request(6, "session_terminate", {"policy": "terminate_owned"}) == {}
        stdout, stderr = child.communicate(timeout=5)
        assert child.returncode == 0, stderr
        assert b'"event_id":999' in stdout
        assert b"separate diagnostic channel" in stderr
        assert all(event["event_id"] != 999 for event in events)
    finally:
        if connection:
            connection.close()
        listener.close()
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)
