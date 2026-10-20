import json

import pytest
from mcp.types import TextContent

from dea.bootstrap import build_application
from dea.contracts.compact import InspectionPage
from dea.contracts.models import DeaError, ErrorCode
from dea.contracts.wire import WireGuard
from dea.gateways.mcp_server import create_server
from tests.support.fakes import FakeSessions, SID


def unpack(result):
    assert len(result.content) == 1
    assert isinstance(result.content[0], TextContent)
    assert result.structured_content is None
    payload = json.loads(result.content[0].text)
    assert result.is_error == (payload["type"] == "error")
    return payload


@pytest.mark.asyncio
async def test_tools_publish_strict_schemas_without_duplicate_output():
    server = create_server(FakeSessions(), WireGuard())
    tools = await server.list_tools()
    assert len(tools) == 13
    for tool in tools:
        assert tool.output_schema is None
        assert tool.input_schema["type"] == "object"


@pytest.mark.asyncio
async def test_real_mcp_calls_share_a_service_instance():
    sessions = FakeSessions()
    server = create_server(sessions, WireGuard())
    first = unpack(await server.call_tool("session_start", {"request": {"backend": "gdb", "binary_path": "fake"}}))
    second = unpack(await server.call_tool("execution_step", {"request": {"session_id": first["sid"], "mode": "over"}}))
    third = unpack(await server.call_tool("execution_continue", {"request": {"session_id": first["sid"]}}))
    assert first["sid"] == second["sid"] == third["sid"] == SID
    assert [call[0] for call in sessions.calls] == ["start", "step", "continue"]
    assert [first["rid"], second["rid"], third["rid"]] == [1, 2, 3]


@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", [
    {"request": {"session_id": SID, "timeout_ms": "100"}},
    {"request": {"session_id": SID, "timeout_ms": True}},
    {"request": {"session_id": SID, "timeout_ms": 30001}},
    {"request": {"session_id": SID, "surprise": "🪲" * 5000}},
    {"request": {"session_id": "invalid"}},
])
async def test_sdk_validation_errors_are_also_capped(arguments):
    sessions = FakeSessions()
    guard = WireGuard()
    server = create_server(sessions, guard)
    result = await server.call_tool("session_wait", arguments)
    assert unpack(result)["code"] == ErrorCode.INVALID_REQUEST.value
    assert not sessions.calls
    assert all(count <= 191 for _, count in guard._check(result.content[0].text).token_counts)


@pytest.mark.asyncio
async def test_stub_error_is_valid_json_and_capped():
    class StubSessions(FakeSessions):
        async def session_start(self, spec):
            raise DeaError(ErrorCode.NOT_IMPLEMENTED)

    server = create_server(StubSessions(), WireGuard())
    result = await server.call_tool("session_start", {"request": {"backend": "gdb", "binary_path": "fake"}})
    assert unpack(result)["code"] == ErrorCode.NOT_IMPLEMENTED.value


@pytest.mark.asyncio
async def test_wait_timeout_does_not_issue_interrupt():
    sessions = FakeSessions()
    server = create_server(sessions, WireGuard())
    await server.call_tool("session_start", {"request": {"backend": "gdb", "binary_path": "fake"}})
    result = await server.call_tool("session_wait", {"request": {"session_id": SID, "timeout_ms": 0}})
    assert unpack(result)["code"] == ErrorCode.WAIT_TIMEOUT.value
    assert sessions.started
    assert [name for name, _ in sessions.calls] == ["start", "wait"]


@pytest.mark.asyncio
async def test_oversized_service_result_becomes_serialization_error():
    class OversizedSessions(FakeSessions):
        async def state_page(self, session_id, cursor_id):
            return InspectionPage(session_id=SID, stop_id=1, object_id=SID,
                                  offset=0, next_offset=1000, text="🪲" * 1000)

    server = create_server(OversizedSessions(), WireGuard())
    result = await server.call_tool("state_page", {"request": {"session_id": SID, "cursor_id": SID}})
    assert unpack(result)["code"] == ErrorCode.SERIALIZATION_FAILED.value


@pytest.mark.asyncio
async def test_internal_exception_details_do_not_enter_tool_payload():
    class BrokenSessions(FakeSessions):
        async def session_start(self, spec):
            raise RuntimeError("internal-details-" * 1000)

    server = create_server(BrokenSessions(), WireGuard())
    result = await server.call_tool("session_start", {"request": {"backend": "gdb", "binary_path": "fake"}})
    assert unpack(result)["code"] == ErrorCode.INTERNAL_ERROR.value
    assert "internal-details" not in result.content[0].text


@pytest.mark.asyncio
async def test_stdio_server_initializes_without_native_debuggers():
    import asyncio
    import sys
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    async def smoke():
        params = StdioServerParameters(command=sys.executable, args=["-m", "dea", "serve"])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                tools = await client.list_tools()
                assert len(tools.tools) == 13
                # Invalid input is deterministic before any native runtime work.
                result = await client.call_tool("session_wait", {"request": {"session_id": "invalid"}})
                assert unpack(result)["code"] == ErrorCode.INVALID_REQUEST.value

    await asyncio.wait_for(smoke(), timeout=20)

