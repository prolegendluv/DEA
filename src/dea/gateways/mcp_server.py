"""Working MCP boundary around injectable services, including validation errors."""
import json
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from dea.contracts.compact import RESPONSE_ADAPTER, ToolResponse
from dea.contracts.models import (
    AttachSpec, BreakpointRequest, DeaError, ErrorCode, EvaluationRequest,
    FrameRequest, LaunchSpec, MemoryDiffRequest, PageRequest, SessionRequest,
    StepRequest, WaitRequest,
)
from dea.contracts.services import SessionService
from dea.contracts.wire import WireGuard

REQUEST_MODELS = {
    "session_start": LaunchSpec, "session_attach": AttachSpec,
    "breakpoint_set": BreakpointRequest, "execution_continue": SessionRequest,
    "execution_step": StepRequest, "execution_interrupt": SessionRequest,
    "state_inspect_frame": FrameRequest, "state_eval_expression": EvaluationRequest,
    "state_memory_diff": MemoryDiffRequest, "session_wait": WaitRequest,
    "state_page": PageRequest, "session_capabilities": SessionRequest,
    "session_terminate": SessionRequest,
}


def _result(text: str) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        is_error=json.loads(text)["type"] == "error",
    )


class CappedMCPServer(MCPServer):
    """Also cap SDK argument-validation failures that occur before the handler."""
    def __init__(self, guard: WireGuard, **kwargs: Any) -> None:
        self.guard = guard
        super().__init__(**kwargs)

    async def call_tool(self, name: str, arguments: dict[str, Any], context: Any = None) -> CallToolResult:
        # The SDK validates Python values. Establish the strict JSON boundary
        # first so JSON enum strings/arrays become enum instances/tuples,
        # without enabling numeric or boolean coercion.
        if name in REQUEST_MODELS:
            try:
                if not isinstance(arguments, dict) or set(arguments) != {"request"}:
                    return _result(self.guard.error(ErrorCode.INVALID_REQUEST).text)
                request = REQUEST_MODELS[name].model_validate_json(
                    json.dumps(arguments["request"], ensure_ascii=False, allow_nan=False)
                )
                arguments = {"request": request}
            except (ValidationError, ValueError, TypeError):
                return _result(self.guard.error(ErrorCode.INVALID_REQUEST).text)
        try:
            result = await super().call_tool(name, arguments, context)
            if (not isinstance(result, CallToolResult) or result.structured_content is not None
                    or len(result.content) != 1 or not isinstance(result.content[0], TextContent)):
                return _result(self.guard.fallback.text)
            validated = RESPONSE_ADAPTER.validate_json(result.content[0].text)
            return _result(self.guard.encode(validated).text)
        except UnexpectedToolError:
            return _result(self.guard.error(ErrorCode.INTERNAL_ERROR).text)
        except ToolError:
            return _result(self.guard.error(ErrorCode.INVALID_REQUEST).text)
        except Exception:
            return _result(self.guard.fallback.text)


def create_server(sessions: SessionService, guard: WireGuard, *,
                  on_close: Callable[[], Awaitable[None]] | None = None) -> CappedMCPServer:
    @asynccontextmanager
    async def lifespan(server: MCPServer):
        try:
            yield {}
        finally:
            await (on_close if on_close is not None else sessions.close)()

    server = CappedMCPServer(
        guard, name="DEA", version="0.1.0", lifespan=lifespan,
        instructions="Persistent debugger sessions. Read capabilities; await stop events before inspection.",
    )

    async def respond(call: Callable[[], Awaitable[ToolResponse]]) -> CallToolResult:
        try:
            return _result(guard.safe_encode(await call()).text)
        except DeaError as exc:
            return _result(guard.error(exc.code).text)
        except Exception:
            return _result(guard.error(ErrorCode.INTERNAL_ERROR).text)

    @server.tool(structured_output=False)
    async def session_start(request: LaunchSpec) -> CallToolResult:
        """Launch a target in a persistent DEA session; retain the returned session ID.

        Example: {"request":{"backend":"pdb","binary_path":"/absolute/path/to/buggy.py"}}
        """
        return await respond(lambda: sessions.session_start(request))

    @server.tool(structured_output=False)
    async def session_attach(request: AttachSpec) -> CallToolResult:
        """Attach GDB or LLDB to an existing process.

        Example: {"request":{"backend":"gdb","pid":1234,"binary_path":"/absolute/path/to/program"}}
        """
        return await respond(lambda: sessions.session_attach(request))

    @server.tool(structured_output=False)
    async def breakpoint_set(request: BreakpointRequest) -> CallToolResult:
        """Set a source/function breakpoint and optional condition; use the returned session ID.

        Example: {"request":{"session_id":"0123456789abcdef","spec":{"location":"/absolute/path/to/buggy.py:9","condition":"index == 4096"}}}
        """
        return await respond(lambda: sessions.breakpoint_set(request.session_id, request.spec))

    @server.tool(structured_output=False)
    async def execution_continue(request: SessionRequest) -> CallToolResult:
        """Resume execution; acknowledgement does not imply a stop.

        Example: {"request":{"session_id":"0123456789abcdef"}}
        """
        return await respond(lambda: sessions.execution_continue(request.session_id))

    @server.tool(structured_output=False)
    async def execution_step(request: StepRequest) -> CallToolResult:
        """Step over, into, or out; consume the resulting event separately.

        Example: {"request":{"session_id":"0123456789abcdef","mode":"over"}}
        """
        return await respond(lambda: sessions.execution_step(request.session_id, request.mode))

    @server.tool(structured_output=False)
    async def execution_interrupt(request: SessionRequest) -> CallToolResult:
        """Request interruption of a running target.

        Example: {"request":{"session_id":"0123456789abcdef"}}
        """
        return await respond(lambda: sessions.execution_interrupt(request.session_id))

    @server.tool(structured_output=False)
    async def state_inspect_frame(request: FrameRequest) -> CallToolResult:
        """Inspect a stopped frame through capped pages.

        Example: {"request":{"session_id":"0123456789abcdef","frame_index":0,"max_depth":1}}
        """
        return await respond(lambda: sessions.state_inspect_frame(request.session_id, request.frame_index, request.max_depth))

    @server.tool(structured_output=False)
    async def state_eval_expression(request: EvaluationRequest) -> CallToolResult:
        """Evaluate an expression in a stopped target; evaluation may have side effects.

        Example: {"request":{"session_id":"0123456789abcdef","expr":"item - index"}}
        """
        return await respond(lambda: sessions.state_eval_expression(request.session_id, request.expr))

    @server.tool(structured_output=False)
    async def state_memory_diff(request: MemoryDiffRequest) -> CallToolResult:
        """Compare previously configured memory regions against a retained stop.

        Example: {"request":{"session_id":"0123456789abcdef","since_step_id":2}}
        """
        return await respond(lambda: sessions.state_memory_diff(request.session_id, request.since_step_id))

    @server.tool(structured_output=False)
    async def session_wait(request: WaitRequest) -> CallToolResult:
        """Return the next journal event after eid; timeout leaves the target running.

        Example: {"request":{"session_id":"0123456789abcdef","after_event_id":4,"timeout_ms":1000}}
        """
        return await respond(lambda: sessions.session_wait(request.session_id, request.after_event_id, request.timeout_ms))

    @server.tool(structured_output=False)
    async def state_page(request: PageRequest) -> CallToolResult:
        """Continue immutable captured details; use the cursor returned by the preceding response.

        Example: {"request":{"session_id":"0123456789abcdef","cursor_id":"0000000000000004"}}
        """
        return await respond(lambda: sessions.state_page(request.session_id, request.cursor_id))

    @server.tool(structured_output=False)
    async def session_capabilities(request: SessionRequest) -> CallToolResult:
        """Read the capabilities of an existing debugger session.

        Example: {"request":{"session_id":"0123456789abcdef"}}
        """
        return await respond(lambda: sessions.session_capabilities(request.session_id))

    @server.tool(structured_output=False)
    async def session_terminate(request: SessionRequest) -> CallToolResult:
        """Terminate an owned target, or detach an attached target.

        Example: {"request":{"session_id":"0123456789abcdef"}}
        """
        return await respond(lambda: sessions.session_terminate(request.session_id))

    return server

