import json
import threading
import time

import pytest

from dea.adapters.lldb.helper import DebugError, Engine
from dea.contracts.models import RawSnapshot
from tests.lldb.doubles import Value, Values, make_api

SID = "0123456789abcdef"


@pytest.fixture
def engine():
    api, messages = make_api(), []
    engine = Engine(api, messages.append, SID)
    yield engine, api, messages
    api.process.detach_failure = False
    engine.close()


def launch(engine):
    return engine.dispatch("session_start", dict(backend="lldb", binary_path="C:/demo space/test.exe",
        args=["", "λ"], env=[dict(key="DEA_CONTROL_TOKEN", value="secret")], cwd="C:/demo space"), 2)


def wait_events(messages, count):
    deadline = time.monotonic() + 2
    while len(messages) < count and time.monotonic() < deadline:
        time.sleep(0.005)
    assert len(messages) >= count
    return [json.loads(message["body_json"]) for message in messages]


def test_launch_async_entry_and_safe_environment(engine, monkeypatch):
    native, api, messages = engine
    monkeypatch.setenv("DEA_CONTROL_TOKEN", "supervisor-secret")
    assert launch(native) == dict(request_id=2, accepted=True)
    events = wait_events(messages, 2)
    assert events[0]["kind"] == "started"
    assert events[1] == dict(event_id=2, kind="stopped", reason="entry", thread_id=17)
    assert api.asynchronous is True and api.init_files is False
    assert api.info.value == ["", "λ"]
    assert api.info.shell is False
    assert not any(item.startswith("DEA_CONTROL_") for item in api.info.env)


def test_snapshot_exact_registers_frames_and_memory(engine):
    native, api, _ = engine
    launch(native)
    body = native.dispatch("snapshot_capture", dict(stop_id=1, reason="entry", frame_index=1,
        max_depth=0, memory_regions=[dict(address=4096, size=3)]), 3)
    snapshot = RawSnapshot.model_validate_json(json.dumps(body))
    assert snapshot.thread_id == 17
    assert snapshot.variables[0].value == "42"
    assert snapshot.registers[0].value == "0x2a"
    assert snapshot.memory[0].data == b"zzz"
    assert snapshot.frames_complete and snapshot.variables_complete and snapshot.registers_complete
    assert len(snapshot.frames) == 2 and "frame:1" in snapshot.frame_context
    assert api.process.thread.selected == 1
    assert snapshot.frames[0].identity != snapshot.frames[1].identity


def test_aggregate_capture_and_unknown_do_not_call_summaries(engine):
    native, api, _ = engine
    launch(native)
    api.process.thread.frames[0].variables = Values(Value("data", None), Value("missing", valid=False))
    frame = native.dispatch("state_inspect_frame", dict(frame_index=0, max_depth=0), 3)
    assert frame["variables"][0]["value"] == "aggregate:0x00ff"
    assert frame["variables"][1]["value"] is None
    assert frame["variables"][1]["available"] is False


@pytest.mark.parametrize("mode", ["over", "into", "out"])
def test_steps_report_actual_plan_stop(engine, mode):
    native, api, messages = engine
    launch(native)
    wait_events(messages, 2)
    native.dispatch("execution_step", {"mode": mode}, 3)
    events = wait_events(messages, 4)
    assert events[-1]["reason"] == "step"
    assert api.process.steps == [mode]


@pytest.mark.parametrize("reason,expected", [("eStopReasonWatchpoint", "watchpoint"),
    ("eStopReasonBreakpoint", "breakpoint"), ("eStopReasonException", "exception"),
    ("eStopReasonSignal", "signal")])
def test_real_stop_reasons(engine, reason, expected):
    native, api, messages = engine
    launch(native)
    wait_events(messages, 2)
    api.process.thread.reason = getattr(api, reason)
    api.process.publish(api.eStateStopped)
    assert wait_events(messages, 3)[-1]["reason"] == expected


def test_interrupt_running_and_inspection_rejection(engine):
    native, api, messages = engine
    launch(native)
    wait_events(messages, 2)
    native.dispatch("execution_continue", {}, 3)
    wait_events(messages, 3)
    with pytest.raises(DebugError, match="INVALID_STATE"):
        native.dispatch("state_inspect_frame", dict(frame_index=0, max_depth=0), 4)
    native.dispatch("execution_interrupt", {}, 5)
    assert wait_events(messages, 4)[-1]["reason"] == "interrupt"


def test_breakpoint_path_condition_expression_and_partial_memory(engine):
    native, api, _ = engine
    launch(native)
    assert native.dispatch("breakpoint_set", dict(location="C:/space/demo.c:12", condition="x > 2"), 3)["verified"]
    assert api.target.breakpoints == [("C:/space/demo.c", 12)]
    assert api.target.condition == "x > 2"
    result = native.dispatch("state_eval_expression", {"expr": "x + 1"}, 4)
    assert result["value"] == "43"
    api.process.partial = True
    with pytest.raises(DebugError, match="INVALID_REQUEST"):
        native.dispatch("state_read_memory", dict(address=0, size=2), 5)


def test_attach_detach_failure_is_observable_and_never_kills_external_target(engine):
    native, api, messages = engine
    native.dispatch("session_attach", dict(backend="lldb", pid=1234), 2)
    wait_events(messages, 2)
    api.process.detach_failure = True
    with pytest.raises(DebugError, match="DETACH_FAILED"):
        native.dispatch("session_terminate", {"policy": "detach"}, 3)
    assert not api.process.killed
    api.process.detach_failure = False
    native.dispatch("session_terminate", {"policy": "detach"}, 4)
    assert api.process.detached and not api.process.killed


def test_exit_event_and_listener_cleanup(engine):
    native, api, messages = engine
    launch(native)
    wait_events(messages, 2)
    api.process.publish(api.eStateExited)
    assert wait_events(messages, 3)[-1] == dict(event_id=3, kind="exited", exit_code=9)
    native.close()
    assert not native.thread.is_alive() and api.destroyed


def test_launch_permission_failure_reports_capability(engine):
    native, api, _ = engine
    api.launch_failure = True
    with pytest.raises(DebugError, match="CAPABILITY_UNAVAILABLE"):
        launch(native)


def test_platform_entry_trap_and_long_expression_have_valid_contracts(engine):
    native, api, messages = engine
    api.process.thread.reason = api.eStopReasonException
    launch(native)
    assert wait_events(messages, 2)[-1]["reason"] == "entry"
    expr = "x" * 4096
    result = native.dispatch("state_eval_expression", {"expr": expr}, 3)
    assert result["name"] == expr
    assert len(result["identity"]) <= 4096
