"""Native PDB debugging through an actual MCP client/server stdio connection."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import TextContent
import pytest

from dea.contracts.compact import RESPONSE_ADAPTER
from dea.contracts.wire import ENCODINGS, WireGuard


@pytest.mark.asyncio
async def test_real_stdio_pdb_offbyone_breakpoint_inspect_step_terminate():
    if not Path(sys.executable).is_file() or importlib.util.find_spec("pdb") is None:
        pytest.skip("requires a native Python interpreter with standard-library PDB")
    root = Path(__file__).resolve().parents[2]
    target = root / "demos" / "python_offbyone" / "buggy.py"
    line = next(index for index, text in enumerate(target.read_text(encoding="utf-8").splitlines(), 1)
                if text.strip() == "item = index - 1")
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (str(root / "src"), env.get("PYTHONPATH"))))
    params = StdioServerParameters(command=sys.executable, args=["-m", "dea", "serve"],
                                   cwd=root, env=env)
    guard = WireGuard()

    async with asyncio.timeout(60):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                tools = await client.list_tools()
                assert {"session_start", "breakpoint_set", "session_wait", "state_inspect_frame",
                        "state_page", "execution_step", "session_terminate"} <= {
                            tool.name for tool in tools.tools}

                async def call(name, request, *, allow_timeout=False):
                    async with asyncio.timeout(15):
                        result = await client.call_tool(name, {"request": request})
                    assert result.structured_content is None
                    assert len(result.content) == 1 and isinstance(result.content[0], TextContent)
                    wire = result.content[0].text
                    # Measure the actual tool payload delivered over stdio. MCP metadata
                    # (initialize/list_tools/envelopes) is outside the frozen payload cap.
                    checked = guard.encode(RESPONSE_ADAPTER.validate_json(wire))
                    assert checked.text == wire
                    assert tuple(name for name, _ in checked.token_counts) == ENCODINGS
                    assert all(count <= 191 for _, count in checked.token_counts)
                    value = json.loads(wire)
                    assert result.is_error == (value["type"] == "error")
                    if result.is_error:
                        assert allow_timeout and value["code"] == "WAIT_TIMEOUT", value
                    return value

                async def wait_for(sid, after, kind, phase=None):
                    async with asyncio.timeout(15):
                        while True:
                            event = await call("session_wait", {"session_id": sid,
                                "after_event_id": after, "timeout_ms": 1000}, allow_timeout=True)
                            if event["type"] == "error":
                                continue
                            assert event["eid"] > after
                            after = event["eid"]
                            if event["type"] == kind and (phase is None or event.get("phase") == phase):
                                return event
                            assert event["type"] == "event", event
                            assert event["phase"] not in ("failed", "terminated"), event

                async def inspect(sid):
                    page = await call("state_inspect_frame", {
                        "session_id": sid, "frame_index": 0, "max_depth": 1})
                    chunks, offset, object_id = [], 0, page["object"]
                    for _ in range(500):
                        assert page["type"] == "page" and page["object"] == object_id
                        assert page["offset"] == offset
                        assert page["next"] == offset + len(page["text"])
                        chunks.append(page["text"])
                        offset = page["next"]
                        if "cursor" not in page:
                            return json.loads("".join(chunks))
                        assert page["text"]
                        page = await call("state_page", {"session_id": sid, "cursor_id": page["cursor"]})
                    pytest.fail("Frame pagination failed to finish")

                sid = None
                try:
                    ack = await call("session_start", {"backend": "pdb", "binary_path": str(target)})
                    assert ack["type"] == "ack" and ack["accepted"]
                    sid = ack["sid"]
                    entry = await wait_for(sid, 0, "stop")
                    assert entry["reason"] == "entry"
                    breakpoint = await call("breakpoint_set", {"session_id": sid,
                        "spec": {"location": f"{target}:{line}", "condition": "index == 4096"}})
                    assert breakpoint["type"] == "ack" and breakpoint["bp"]
                    await call("execution_continue", {"session_id": sid})
                    stopped = await wait_for(sid, entry["eid"], "stop")
                    assert stopped["reason"] == "breakpoint"
                    frame = await inspect(sid)
                    values = {value["name"]: value["value"] for value in frame["variables"]}
                    assert frame["location"]["line"] == line
                    assert {name: values[name] for name in ("index", "item", "total")} == {
                        "index": "4096", "item": "4096", "total": str(sum(range(4096)))}
                    await call("execution_step", {"session_id": sid, "mode": "over"})
                    stepped = await wait_for(sid, stopped["eid"], "stop")
                    assert stepped["reason"] == "step" and stepped["base"] == stopped["stop"]
                    assert any(delta["name"] == "item" and delta["op"] == "set"
                               and delta["before"] == "4096" and delta["after"] == "4095"
                               for delta in stepped.get("vars", [])), stepped
                    changed = await inspect(sid)
                    assert next(value["value"] for value in changed["variables"]
                                if value["name"] == "item") == "4095"
                    termination = await call("session_terminate", {"session_id": sid})
                    assert termination["type"] == "ack" and termination["accepted"]
                    await wait_for(sid, stepped["eid"], "event", "terminated")
                finally:
                    if sid is not None:
                        # Complete native cleanup even if a preceding assertion fails.
                        await call("session_terminate", {"session_id": sid})
