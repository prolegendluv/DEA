"""Installed GDB through the frozen application composition boundary."""
import json
import os
import shutil
import subprocess

import pytest

from dea.bootstrap import build_application
from dea.contracts.compact import CompactDebugState, ErrorResponse, InspectionPage, LifecycleResponse
from dea.contracts.models import Backend, BreakpointSpec, LaunchSpec, SessionPhase, StopReason


async def wait_stop(app, sid, after=0):
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
    pytest.fail("GDB stop was not captured by session orchestration")


async def test_native_gdb_default_application_launch_capture_and_exit(tmp_path):
    compiler = shutil.which("gcc")
    if not compiler or not shutil.which("gdb"):
        pytest.skip("Native GDB and GCC required")
    source = tmp_path / "composition.c"
    source.write_text(
        "int bump(int number) {\n"
        "    int result = number + 1;\n"
        "    return result;\n"
        "}\n"
        "int main(void) { return bump(4) == 5 ? 0 : 1; }\n",
        encoding="utf-8",
    )
    binary = tmp_path / ("composition.exe" if os.name == "nt" else "composition")
    subprocess.run([compiler, "-g", "-O0", str(source), "-o", str(binary)],
                   check=True, capture_output=True, timeout=30)
    app = build_application()
    try:
        ack = await app.sessions.session_start(LaunchSpec(backend=Backend.GDB, binary_path=str(binary)))
        assert not isinstance(ack, ErrorResponse), ack
        entry = await wait_stop(app, ack.session_id)
        assert entry.reason is StopReason.ENTRY
        bp = await app.sessions.breakpoint_set(ack.session_id, BreakpointSpec(location="bump"))
        assert not isinstance(bp, ErrorResponse), bp
        await app.sessions.execution_continue(ack.session_id)
        stopped = await wait_stop(app, ack.session_id, entry.event_id)
        assert stopped.reason is StopReason.BREAKPOINT
        page = await app.sessions.state_inspect_frame(ack.session_id, 0, 1)
        chunks = []
        while True:
            assert isinstance(page, InspectionPage), page
            app.guard.encode(page)
            chunks.append(page.text)
            if page.cursor_id is None:
                break
            page = await app.sessions.state_page(ack.session_id, page.cursor_id)
        frame = json.loads("".join(chunks))
        assert any(value["name"] == "number" and value["value"] == "4" for value in frame["variables"])
        await app.sessions.execution_continue(ack.session_id)
        after = stopped.event_id
        for _ in range(30):
            event = await app.sessions.session_wait(ack.session_id, after, 1000)
            app.guard.encode(event)
            if isinstance(event, ErrorResponse):
                assert event.code.value == "WAIT_TIMEOUT", event
                continue
            assert isinstance(event, LifecycleResponse), event
            after = event.event_id
            assert event.phase is not SessionPhase.FAILED, event
            if event.phase is SessionPhase.TERMINATED:
                assert event.exit_code == 0
                break
        else:
            pytest.fail("GDB did not publish target exit")
    finally:
        await app.close()
