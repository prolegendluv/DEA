"""Real Python-only WP8 scenarios through the public MCP tool boundary."""
import asyncio
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from dea.bootstrap import build_application
from dea.contracts.compact import RESPONSE_ADAPTER
from dea.contracts.wire import ENCODINGS
from dea.gateways.mcp_server import create_server


DEMO = Path(__file__).resolve().parents[2] / "demos" / "python_offbyone"
EXPECTED = sum(range(10_000))


def require_python():
    if not Path(sys.executable).is_file():
        pytest.skip("requires an executable native Python interpreter for PDB subprocesses")


def require_pdb():
    require_python()
    if importlib.util.find_spec("pdb") is None:
        pytest.skip("requires the standard-library PDB debugger in the native Python interpreter")


class ProcessWitness:
    """Hold a native Windows process handle so PID reuse cannot fake cleanup."""

    def __init__(self, process):
        self.process = process
        self.handle = None
        if os.name == "nt":
            from ctypes import wintypes
            self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            self.kernel.OpenProcess.restype = wintypes.HANDLE
            self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            self.kernel.WaitForSingleObject.restype = wintypes.DWORD
            self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            self.kernel.CloseHandle.restype = wintypes.BOOL
            self.handle = self.kernel.OpenProcess(0x00100000, False, process.pid)
            assert self.handle, ctypes.WinError(ctypes.get_last_error())

    async def assert_reaped(self):
        # Public ManagedProcess.wait() verifies the same owned process was reaped.
        async with asyncio.timeout(5):
            code = await self.process.wait()
        assert isinstance(code, int)
        if self.handle is not None:
            assert self.kernel.WaitForSingleObject(self.handle, 0) == 0
        else:
            with pytest.raises(ProcessLookupError):
                os.kill(self.process.pid, 0)

    def close(self):
        if self.handle is not None:
            assert self.kernel.CloseHandle(self.handle)
            self.handle = None


class ToolClient:
    def __init__(self, app):
        self.app = app
        self.server = create_server(app.sessions, app.guard)
        self.responses = []

    async def call(self, name, request, *, allow_timeout=False):
        async with asyncio.timeout(15):
            result = await self.server.call_tool(name, {"request": request})
        assert result.structured_content is None
        assert len(result.content) == 1 and result.content[0].type == "text"
        text = result.content[0].text
        # Round-trip the actual returned bytes through the existing executable guard.
        payload = self.app.guard.encode(RESPONSE_ADAPTER.validate_json(text))
        assert payload.text == text
        assert tuple(name for name, _ in payload.token_counts) == ENCODINGS
        assert all(count <= 191 for _, count in payload.token_counts)
        value = json.loads(text)
        self.responses.append(value)
        assert result.is_error == (value["type"] == "error")
        if result.is_error:
            assert allow_timeout and value["code"] == "WAIT_TIMEOUT", value
        return value

    async def wait(self, sid, after, kind):
        async with asyncio.timeout(15):
            while True:
                value = await self.call("session_wait", {
                    "session_id": sid, "after_event_id": after, "timeout_ms": 1000,
                }, allow_timeout=True)
                if value["type"] == "error":
                    continue
                assert value["eid"] > after
                after = value["eid"]
                if value["type"] == kind:
                    return value
                assert value["type"] == "event" and value["phase"] != "failed", value
                assert value["phase"] != "terminated", value

    async def details(self, sid, page):
        text = []
        offset, object_id = 0, page["object"]
        for _ in range(500):
            assert page["type"] == "page"
            assert page["offset"] == offset and page["object"] == object_id
            assert page["next"] == offset + len(page["text"])
            text.append(page["text"])
            offset = page["next"]
            if "cursor" not in page:
                return json.loads("".join(text))
            assert page["text"], "Continuation must make progress"
            page = await self.call("state_page", {"session_id": sid, "cursor_id": page["cursor"]})
        pytest.fail("Inspection cursor did not finish")

    async def terminated(self, sid, after, *, allow_recapture=False):
        async with asyncio.timeout(15):
            while True:
                event = await self.call("session_wait", {
                    "session_id": sid, "after_event_id": after, "timeout_ms": 1000,
                }, allow_timeout=True)
                if event["type"] == "error":
                    continue
                assert event["eid"] > after
                after = event["eid"]
                if event["type"] == "stop":
                    assert allow_recapture, event
                    continue
                assert event["type"] == "event" and event["phase"] != "failed", event
                if event["phase"] == "terminated":
                    return event


@pytest.fixture
async def native_app(monkeypatch):
    require_pdb()
    app = build_application()
    witnesses = []
    real_spawn = app.runtime.spawn

    async def observed_spawn(spec):
        # Pure instrumentation: the actual runtime creates every actual process.
        process = await real_spawn(spec)
        witnesses.append(ProcessWitness(process))
        return process

    monkeypatch.setattr(app.runtime, "spawn", observed_spawn)
    try:
        yield app, ToolClient(app), witnesses
    finally:
        try:
            async with asyncio.timeout(15):
                await app.close()
            for witness in witnesses:
                await witness.assert_reaped()
        finally:
            for witness in witnesses:
                witness.close()


def run_script(path):
    require_python()
    result = subprocess.run([sys.executable, str(path)], capture_output=True,
                            text=True, check=True, timeout=10)
    assert result.stderr == ""
    return int(result.stdout.strip())


def test_bug_is_repeatable_and_fixed_reference_matches_patch(tmp_path):
    buggy = DEMO / "buggy.py"
    fixed = DEMO / "fixed.py"
    assert [run_script(buggy) for _ in range(3)] == [EXPECTED - 1] * 3
    assert run_script(fixed) == EXPECTED
    source = buggy.read_text(encoding="utf-8")
    assert source.count("item = index - 1") == 1
    patched = source.replace("item = index - 1", "item = index")
    assert patched == fixed.read_text(encoding="utf-8")
    patched_path = tmp_path / "patched.py"
    patched_path.write_text(patched, encoding="utf-8")
    assert run_script(patched_path) == EXPECTED


async def test_pdb_python_offbyone_end_to_end(native_app):
    app, client, witnesses = native_app
    target = DEMO / "buggy.py"
    source = target.read_text(encoding="utf-8").splitlines()
    line = next(index for index, text in enumerate(source, 1) if text.strip() == "item = index - 1")
    ack = await client.call("session_start", {"backend": "pdb", "binary_path": str(target)})
    sid = ack["sid"]
    entry = await client.wait(sid, 0, "stop")
    assert entry["reason"] == "entry"
    await client.call("breakpoint_set", {"session_id": sid,
        "spec": {"location": f"{target}:{line}", "condition": "index == 4096"}})
    await client.call("execution_continue", {"session_id": sid})
    stopped = await client.wait(sid, entry["eid"], "stop")
    assert stopped["reason"] == "breakpoint"
    frame = await client.details(sid, await client.call("state_inspect_frame", {
        "session_id": sid, "frame_index": 0, "max_depth": 1}))
    values = {value["name"]: value["value"] for value in frame["variables"]}
    assert {name: values[name] for name in ("index", "item", "total")} == {
        "index": "4096", "item": "4096", "total": str(sum(range(4096)))}
    assert frame["location"]["line"] == line
    evaluation = await client.details(sid, await client.call("state_eval_expression", {
        "session_id": sid, "expr": "item - index"}))
    assert evaluation["available"] and evaluation["value"] == "0"
    reset = await client.wait(sid, stopped["eid"], "stop")
    assert "base" not in reset
    await client.call("execution_step", {"session_id": sid, "mode": "over"})
    stepped = await client.wait(sid, reset["eid"], "stop")
    assert stepped["reason"] == "step" and stepped["base"] == reset["stop"]
    assert any(delta["name"] == "item" and delta["op"] == "set"
               and delta["before"] == "4096" and delta["after"] == "4095"
               for delta in stepped.get("vars", [])), stepped
    assert len(witnesses) == 1
    pid = await client.details(sid, await client.call("state_eval_expression", {
        "session_id": sid, "expr": "__import__('os').getpid()"}))
    assert int(pid["value"]) == witnesses[0].process.pid
    terminated = await client.call("session_terminate", {"session_id": sid})
    assert terminated["type"] == "ack"
    assert await client.call("session_terminate", {"session_id": sid}) == terminated
    await client.terminated(sid, stepped["eid"], allow_recapture=True)
    # Check before application.close(): session_terminate itself must complete cleanup.
    await witnesses[0].assert_reaped()


async def test_native_platform_pdb_smoke(native_app):
    app, client, witnesses = native_app
    ack = await client.call("session_start", {
        "backend": "pdb", "binary_path": str(DEMO / "fixed.py")})
    sid = ack["sid"]
    entry = await client.wait(sid, 0, "stop")
    assert entry["reason"] == "entry"
    response = await client.call("session_capabilities", {"session_id": sid})
    assert response["type"] == "capabilities"
    capabilities = response["capabilities"]
    assert capabilities["backend"] == "pdb" and capabilities["available"] and capabilities["launch"]
    await client.call("execution_continue", {"session_id": sid})
    event = await client.terminated(sid, entry["eid"])
    assert event["exit"] == 0
    await client.call("session_terminate", {"session_id": sid})
    assert len(witnesses) == 1
    await witnesses[0].assert_reaped()
