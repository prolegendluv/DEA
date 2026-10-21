"""Published request examples and measured trace payloads stay executable."""
import json
from pathlib import Path
import re

from dea.bootstrap import build_application
from dea.contracts.compact import CompactDebugState
from dea.contracts.wire import WireGuard
from dea.gateways.mcp_server import REQUEST_MODELS, create_server


async def test_tool_descriptions_publish_valid_single_line_request_examples():
    app = build_application()
    try:
        tools = await create_server(app.sessions, app.guard).list_tools()
        assert {tool.name for tool in tools} == set(REQUEST_MODELS)
        for tool in tools:
            examples = [line.strip().removeprefix("Example: ")
                        for line in tool.description.splitlines()
                        if line.strip().startswith("Example: ")]
            assert len(examples) == 1, tool.name
            example = json.loads(examples[0])
            assert set(example) == {"request"}, tool.name
            REQUEST_MODELS[tool.name].model_validate_json(json.dumps(example["request"]))
            assert tool.input_schema["required"] == ["request"]
    finally:
        await app.close()


def test_readme_trace_payloads_match_canonical_wire_and_published_token_counts():
    readme = (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")
    section = re.search(r"^## Real Agent Trace\n(.*?)(?=^## |\Z)", readme, re.M | re.S)
    assert section is not None
    wires = re.findall(r"```json\n([^\n]+)\n```", section[1])
    counts = re.findall(r"\*\*`cl100k_base`: (\d+) tokens; `o200k_base`: (\d+) tokens\*\*", section[1])
    assert len(wires) == len(counts) == 2
    guard = WireGuard()
    states = []
    for wire, expected in zip(wires, counts, strict=True):
        state = CompactDebugState.model_validate_json(wire)
        checked = guard.encode(state)
        assert checked.text == wire
        assert checked.token_counts == (("cl100k_base", int(expected[0])), ("o200k_base", int(expected[1])))
        states.append(state)
    hit, step = states
    assert hit.stop_id == 2 and hit.reason.value == "breakpoint"
    assert step.stop_id == 3 and step.base_stop_id == 2 and step.reason.value == "step"
    assert hit.session_id == step.session_id
    assert any(delta.name == "item" and delta.operation == "set"
               and delta.before == "4096" and delta.after == "4095" for delta in step.variable_deltas)
