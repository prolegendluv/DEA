# DEA — Debug Everything Autonomously

A stateful debugger bridge for coding agents, with a strict 191-token response budget.

This repository is the **foundation skeleton**. Shared contracts, canonical serialization, the token guard, MCP tool registration, test doubles, and worker specifications are implemented. Native process management, session orchestration, snapshot packing, and GDB/LLDB/PDB integrations are explicitly unimplemented. Debugging calls return `NOT_IMPLEMENTED`.

Requires Python 3.12 or newer. The architecture targets Linux, macOS, and native Windows. Debugger availability and PTY support will be reported per backend/platform after their work packages pass integration tests.

## Install and inspect

```sh
python -m pip install -e ".[dev]"
dea doctor
dea schema
python -m pytest tests/contracts -q
python -m dea.contracts.ownership
```

Start the MCP server with `dea serve` or `python -m dea serve`. Stdio is reserved for MCP messages. Diagnostics belong on stderr. Sessions will belong to that long-running server process.

Example MCP configuration after installation:

```json
{
  "mcpServers": {
    "dea": {
      "command": "python",
      "args": ["-m", "dea", "serve"]
    }
  }
}
```

Use the Python executable from the environment in which DEA is installed. Configuration installation is manual; this project does not modify other applications' settings.

## Contract

Each MCP operation accepts a single `request` object. For example:

```json
{"request":{"backend":"gdb","binary_path":"/absolute/path/to/program","args":[]}}
```

Every tool result contains one text block with valid JSON and no duplicate structured output. Both `cl100k_base` and `o200k_base` must count at most 191 tokens in that JSON. The budget includes error codes, omission metadata, and continuation handles; it excludes MCP envelopes and tool definitions. Other model tokenizers can count differently.

Compact stops include only changed registers/variables and optional frame/location summaries. Retained snapshots preserve exact observed values. Omitted details are retrieved through bounded immutable pages when the state work package is implemented.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for boundaries and lifecycle decisions, [SPEC.md](SPEC.md) for frozen interfaces, and [TASKS.md](TASKS.md) for eight isolated implementation packages. The [Antigravity skill](skills/dea/SKILL.md) describes the future debugging workflow and the current foundation status.

## Scope

The planned adapters launch GDB, LLDB, and PDB sessions; GDB/LLDB also attach. PDB attach, remote debugging, reverse execution, a standalone session daemon, and automatic source patching are deferred. Debuggers are external prerequisites rather than bundled dependencies.

