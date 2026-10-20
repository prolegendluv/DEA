"""Startup, schema export and diagnostics. Sessions belong to the MCP server."""
import argparse
import importlib.metadata
import json
import shutil
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dea")
    parser.add_argument("command", choices=("serve", "doctor", "schema"))
    options = parser.parse_args(argv)
    if options.command == "schema":
        from dea.contracts.compact import CompactDebugState
        print(json.dumps(CompactDebugState.model_json_schema(by_alias=True), indent=2, ensure_ascii=False, sort_keys=True))
        return 0
    if options.command == "doctor":
        from dea.contracts.wire import WireGuard
        guard = WireGuard()
        print(json.dumps({
            "foundation": True, "python": sys.version.split()[0],
            "dependencies": {name: importlib.metadata.version(name) for name in ("pydantic", "tiktoken", "mcp")},
            "executables": {name: shutil.which(name) for name in ("gdb", "lldb")},
            "adapters_implemented": False,
            "tokenizers": [name for name, _ in guard.fallback.token_counts],
        }, indent=2))
        return 0
    from dea.bootstrap import build_application
    from dea.gateways.mcp_server import create_server
    app = build_application()
    create_server(app.sessions, app.guard, on_close=app.close).run(transport="stdio")
    return 0

