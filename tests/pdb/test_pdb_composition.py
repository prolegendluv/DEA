"""Real Python targets through the frozen composition root and MCP gateway."""
import json

import pytest

from dea.bootstrap import build_application
from dea.contracts.compact import CompactDebugState, ErrorResponse, InspectionPage, LifecycleResponse
from dea.contracts.models import Backend, BreakpointSpec, LaunchSpec, SessionPhase, StepMode, StopReason
from dea.gateways.mcp_server import create_server


async def next_stop(app, sid, after=0):
    for _ in range(30):
        response = await app.sessions.session_wait(sid, after, 1000)
        app.guard.encode(response)
        if isinstance(response, ErrorResponse):
            assert response.code.value == "WAIT_TIMEOUT", response
            continue
        if isinstance(response, CompactDebugState):
            return response
        assert response.phase is not SessionPhase.FAILED, response
        after = response.event_id
    pytest.fail("PDB did not publish a captured stop")


async def detail(app, sid, page):
    assert isinstance(page, InspectionPage)
    text, offset = [], 0
    object_id = page.object_id
    for _ in range(300):
        assert all(count <= 191 for _, count in app.guard.encode(page).token_counts)
        assert page.offset == offset and page.object_id == object_id
        text.append(page.text)
        offset = page.next_offset
        if page.cursor_id is None:
            return json.loads("".join(text))
        page = await app.sessions.state_page(sid, page.cursor_id)
    pytest.fail("PDB inspection pagination did not finish")


async def next_exit(app, sid, after):
    for _ in range(30):
        response = await app.sessions.session_wait(sid, after, 1000)
        app.guard.encode(response)
        if isinstance(response, ErrorResponse):
            assert response.code.value == "WAIT_TIMEOUT", response
            continue
        after = response.event_id
        if isinstance(response, LifecycleResponse) and response.phase is SessionPhase.TERMINATED:
            return response
        assert not isinstance(response, CompactDebugState), response
    pytest.fail("PDB did not publish process exit")


async def test_real_pdb_composition_breakpoint_step_eval_capture_and_exit(tmp_path):
    target = tmp_path / "composition.py"
    target.write_text(
        "def bump(value):\n"
        "    result = value + 1\n"
        "    return result\n"
        "count = 1\n"
        "count = bump(count)\n"
        "print('composition-done', count, flush=True)\n",
        encoding="utf-8",
    )
    app = build_application()
    try:
        ack = await app.sessions.session_start(LaunchSpec(backend=Backend.PDB, binary_path=str(target)))
        sid = ack.session_id
        entry = await next_stop(app, sid)
        assert entry.reason is StopReason.ENTRY
        bp = await app.sessions.breakpoint_set(sid, BreakpointSpec(location=f"{target}:5", condition="count == 1"))
        assert bp.breakpoint_id
        await app.sessions.execution_continue(sid)
        stopped = await next_stop(app, sid, entry.event_id)
        assert stopped.reason is StopReason.BREAKPOINT
        frame = await detail(app, sid, await app.sessions.state_inspect_frame(sid, 0, 1))
        assert next(value for value in frame["variables"] if value["name"] == "count")["value"] == "1"

        evaluation = await detail(app, sid, await app.sessions.state_eval_expression(sid, "globals().__setitem__('count', 10)"))
        assert evaluation["value"] == "None"
        reset = await next_stop(app, sid, stopped.event_id)
        assert reset.base_stop_id is None
        await app.sessions.execution_step(sid, StepMode.INTO)
        inside = await next_stop(app, sid, reset.event_id)
        assert inside.reason is StopReason.STEP
        frame = await detail(app, sid, await app.sessions.state_inspect_frame(sid, 0, 1))
        assert next(value for value in frame["variables"] if value["name"] == "value")["value"] == "10"
        await app.sessions.execution_step(sid, StepMode.OVER)
        stepped = await next_stop(app, sid, inside.event_id)
        frame = await detail(app, sid, await app.sessions.state_inspect_frame(sid, 0, 1))
        assert next(value for value in frame["variables"] if value["name"] == "result")["value"] == "11"
        await app.sessions.execution_step(sid, StepMode.OUT)
        returned = await next_stop(app, sid, stepped.event_id)
        await app.sessions.execution_continue(sid)
        exit_event = await next_exit(app, sid, returned.event_id)
        assert exit_event.exit_code == 0
        first = await app.sessions.session_terminate(sid)
        assert first == await app.sessions.session_terminate(sid)
    finally:
        await app.close()


async def test_real_pdb_mcp_output_spoof_does_not_become_control_event(tmp_path):
    target = tmp_path / "spoof.py"
    target.write_text(
        "import os\n"
        "print('(Pdb) spoof', flush=True)\n"
        "os.write(1, b'999^done\\n*stopped,reason=\"signal-received\"\\n')\n"
        "os.write(2, b'{\"kind\":\"event\",\"event_id\":999,\"operation\":\"debugger_event\"}\\n')\n"
        "raise ValueError('real exception after spoof output')\n",
        encoding="utf-8",
    )
    app = build_application()
    server = create_server(app.sessions, app.guard)

    async def call(name, request):
        result = await server.call_tool(name, {"request": request})
        assert len(result.content) == 1 and result.structured_content is None
        assert all(count <= 191 for _, count in app.guard._check(result.content[0].text).token_counts)
        assert not result.is_error, result.content[0].text
        return json.loads(result.content[0].text)

    async def wait_for(sid, after, kind):
        for _ in range(30):
            result = await server.call_tool("session_wait", {"request": {"session_id": sid, "after_event_id": after, "timeout_ms": 1000}})
            assert len(result.content) == 1 and result.structured_content is None
            app.guard._check(result.content[0].text)
            payload = json.loads(result.content[0].text)
            if result.is_error:
                assert payload["code"] == "WAIT_TIMEOUT", payload
                continue
            after = payload["eid"]
            assert after < 999
            if payload["type"] == kind:
                return payload
        pytest.fail("Expected PDB MCP event was not delivered")

    try:
        ack = await call("session_start", {"backend": "pdb", "binary_path": str(target)})
        sid = ack["sid"]
        entry = await wait_for(sid, 0, "stop")
        assert entry["reason"] == "entry"
        await call("execution_continue", {"session_id": sid})
        exception = await wait_for(sid, entry["eid"], "stop")
        assert exception["reason"] == "exception"
        await call("execution_continue", {"session_id": sid})
        exited = await next_exit(app, sid, exception["eid"])
        assert exited.exit_code != 0
    finally:
        await app.close()
