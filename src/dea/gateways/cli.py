"""Startup, schema export and diagnostics. Sessions belong to the MCP server."""
import argparse
import asyncio
import importlib.metadata
import json
import shutil
import sys


def _implementation_name(value) -> str:
    implementation = type(value)
    return f"{implementation.__module__}.{implementation.__qualname__}"


async def _doctor_report() -> dict:
    from dea.bootstrap import ADAPTER_FACTORIES, SystemClock, build_application
    from dea.contracts.adapter import AdapterContext, UnimplementedAdapter
    from dea.contracts.models import Backend, RuntimeLimits

    limits = RuntimeLimits()
    app = build_application(limits=limits)
    try:
        context = AdapterContext("0000000000000000", app.runtime, app.state, SystemClock(), limits)
        adapters = {}
        for backend, factory in ADAPTER_FACTORIES.items():
            adapter = factory(context)
            adapters[backend.value] = {
                "implementation": _implementation_name(adapter),
                "implemented": not isinstance(adapter, UnimplementedAdapter),
                "capabilities": adapter.capabilities().model_dump(mode="json"),
            }
        return {
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "dependencies": {name: importlib.metadata.version(name)
                             for name in ("pydantic", "tiktoken", "mcp")},
            "executables": {name: shutil.which(name) for name in ("gdb", "lldb")},
            "components": {name: _implementation_name(getattr(app, name))
                           for name in ("runtime", "sessions", "state", "guard")},
            "adapters_implemented": set(ADAPTER_FACTORIES) == set(Backend)
                and all(item["implemented"] for item in adapters.values()),
            "adapters": adapters,
            # Constructors report installation eligibility. Starting a session
            # performs backend initialization/ABI checks; doctor runs no target.
            "capability_scope": "installation_eligibility",
            "native_verification": "not_run",
            "tokenizers": [name for name, _ in app.guard.fallback.token_counts],
        }
    finally:
        await app.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dea")
    parser.add_argument("command", choices=("serve", "doctor", "schema"))
    options = parser.parse_args(argv)
    if options.command == "schema":
        from dea.contracts.compact import CompactDebugState
        print(json.dumps(CompactDebugState.model_json_schema(by_alias=True), indent=2, ensure_ascii=False, sort_keys=True))
        return 0
    if options.command == "doctor":
        print(json.dumps(asyncio.run(_doctor_report()), indent=2))
        return 0
    from dea.bootstrap import build_application
    from dea.gateways.mcp_server import create_server
    app = build_application()
    create_server(app.sessions, app.guard, on_close=app.close).run(transport="stdio")
    return 0

