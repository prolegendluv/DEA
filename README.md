# DEA — Debug Everything Autonomously

**Static tools read dead binaries. DEA debugs live processes—in ≤191 tokens per step.**

DEA is an MCP server that gives coding agents persistent, asynchronous control over
**GDB, LLDB, and PDB**. Set a conditional breakpoint, stop at the first bad value,
inspect a frame, and see exactly what changed when execution advances.

Raw debugger dumps can flood an agent's context window with **5,000+ tokens** of
hex, frames, arrays, and unchanged locals. DEA retains the captured state and sends
delta-compressed JSON: changed registers and variables, compact stop metadata,
and cursors for details. Agents spend their context on the failure.

## Raw output vs. a DEA delta

An illustrative excerpt beside the corresponding kind of compact response:

<table>
<tr><th>Raw Debugger Output</th><th>DEA CompactDebugState Delta JSON</th></tr>
<tr><td><pre>(gdb) info registers
rax  0x1000  4096
rbx  0xfff   4095
rsp  0x000000000061fd20
... more registers ...
(gdb) backtrace full
#0 checksum() at checksum.c:10
  index = 4096
  item = 4095
  total = 8386560
... more frames and locals ...</pre></td><td><pre>{
  "base": 3,
  "eid": 12,
  "reason": "step",
  "sid": "0123456789abcdef",
  "stop": 4,
  "type": "stop",
  "v": 1,
  "vars": [{
    "after": "4095",
    "before": "4096",
    "id": "item",
    "name": "item",
    "op": "set"
  }]
}</pre></td></tr>
</table>

The example uses illustrative IDs and omits unchanged values. Actual payloads are
canonical JSON on one line; the excerpt is not a measured compression benchmark.
Raw dump size depends on the target and requested debugger commands.

## A measured response budget

Every tool response must satisfy:

```text
max(tokens_cl100k_base(JSON), tokens_o200k_base(JSON)) <= 191
```

This is an executable bound on the final canonical JSON, enforced with both
pinned tokenizers by [WireGuard](src/dea/contracts/wire.py). It includes errors,
omission counts, hints, and cursor handles. Each MCP tool returns exactly one
JSON text block without duplicated structured output. MCP envelopes, initialization,
and tool definitions are outside the budget; other tokenizers may count differently.

DEA compares original captured values, preserves unknown observations, and resets
baselines when frame context changes. Large values and omitted changes live in
immutable, paginated details. JSON is never cut mid-record to meet the limit.

## Real Agent Trace

Captured from the real MCP stdio server (`python -m dea serve`) using the PDB
backend and `demos/python_offbyone/buggy.py` on Windows / Python 3.14.6. These
are the exact, unmodified canonical JSON strings delivered in MCP text blocks.
Every emitted field, including scoped delta IDs, paths, omission counts, and
cursor handles, is preserved. Optional fields absent below were absent in the
server response. Session/cursor handles belong to this captured run; new sessions
return their own handles.

### Conditional breakpoint hit — `stop: 2`

The conditional breakpoint stops before line 9 at `index == 4096`, without
single-stepping through the loop. Measured on the exact string below using DEA's
wire token counter: **`cl100k_base`: 173 tokens; `o200k_base`: 175 tokens**.

```json
{"cursor":"0000000000000004","eid":4,"frames":[{"at":{"file":"E:\\Projects\\stars\\demos\\python_offbyone\\buggy.py","fn":"checksum","line":9},"i":0}],"omitted":{"frames":1,"regs":0,"vars":0},"reason":"breakpoint","sid":"9a054a628c8d7973","stop":2,"type":"stop","v":1,"vars":[{"after":"4096","id":"thread:1/frame:2/local:index","name":"index","op":"add"},{"after":"4096","id":"thread:1/frame:2/local:item","name":"item","op":"add"},{"after":"8386560","id":"thread:1/frame:2/local:total","name":"total","op":"add"}]}
```

### Step over the corrupting assignment — `stop: 3`

Executing line 9 advances to line 10. The `base: 2` delta records `item` changing
from `4096` to `4095`. Measured on the exact string below using DEA's wire token
counter: **`cl100k_base`: 177 tokens; `o200k_base`: 179 tokens**.

```json
{"at":{"file":"E:\\Projects\\stars\\demos\\python_offbyone\\buggy.py","fn":"checksum","line":10},"base":2,"eid":6,"frames":[{"at":{"file":"E:\\Projects\\stars\\demos\\python_offbyone\\buggy.py","fn":"checksum","line":10},"i":0},{"at":{"file":"E:\\Projects\\stars\\demos\\python_offbyone\\buggy.py","fn":"<module>","line":15},"i":1}],"reason":"step","sid":"9a054a628c8d7973","stop":3,"thread":1,"type":"stop","v":1,"vars":[{"after":"4095","before":"4096","id":"thread:1/frame:2/local:item","name":"item","op":"set"}]}
```

Both payloads validate as `CompactDebugState` and round-trip through `WireGuard`
without changing a byte. Counts include the complete JSON payload and exclude
the MCP envelope. Both stops satisfy the 191-token budget under both encodings.

## Quickstart

Requires **Python 3.12+**. From a checkout of this repository:

```sh
pip install -e .
dea doctor
```

PDB uses the standard-library debugger. Install GDB separately for native targets;
LLDB needs a Python interpreter compatible with its local Python bindings.
`dea doctor` reports the live runtime/session/state classes, adapter implementations,
local installation eligibility, and both loaded tokenizers. An implemented adapter
can be unavailable locally. Doctor does not launch a target or certify native support.

### Connect your agent

Use the **absolute Python executable from the environment where DEA is installed**
in place of `/absolute/path/to/python`. On Windows, forward slashes work, for example
`C:/Python314/python.exe`. The client starts `python -m dea serve` and keeps that
server process alive across tool calls.

Use this MCP JSON entry with Claude Code, Cursor, or Antigravity:

```json
{
  "mcpServers": {
    "dea": {
      "command": "/absolute/path/to/python",
      "args": ["-m", "dea", "serve"]
    }
  }
}
```

| Client | Configuration |
| --- | --- |
| [Claude Code](https://code.claude.com/docs/en/mcp) | Add the JSON to project `.mcp.json`; the `dea` entry may include `"type": "stdio"`. |
| [Cursor](https://cursor.com/docs/mcp) | Add it to `.cursor/mcp.json`; set `"type": "stdio"` in the `dea` entry. |
| [Antigravity](https://antigravity.google/docs/mcp) | Open **Manage MCP Servers → View raw config** and add it to `mcp_config.json`. |
| Codex | Register the same launcher with the command below; Codex stores MCP configuration in TOML rather than the JSON format above. |

```sh
codex mcp add dea -- /absolute/path/to/python -m dea serve
```

For Claude Code, registration can also be done from its CLI:

```sh
claude mcp add --transport stdio --scope project dea -- /absolute/path/to/python -m dea serve
```

Every DEA tool accepts one `request` object. For example, `session_start` takes:

```json
{
  "request": {
    "backend": "pdb",
    "binary_path": "/absolute/path/to/DEA/demos/python_offbyone/buggy.py"
  }
}
```

Keep the returned session ID. Launch/continue/step acknowledgements mean the command
was accepted; use `session_wait` after the last event ID to observe a stop. Inspect
while stopped, follow `state_page` cursors for detail, and call `session_terminate`
when finished. Explicit expression evaluation can execute target code and resets
the affected baseline. A wait timeout leaves target execution unchanged.

## Backend status

| Backend | Status | Supported flow |
| --- | --- | --- |
| **GDB** | **Verified** on native Windows | Launch + attach/detach, MI async, conditional breakpoints, stepping, signals/watchpoint events, registers, memory, isolated target output. |
| **PDB** | **Verified** on native Windows / Python 3.14 | Launch, conditional breakpoints, stepping, locals, evaluation, exceptions, cooperative interruption, stdout/stderr isolation. |
| **LLDB** | **Adapter & helper implemented; requires local `lldb` Python bindings** | Async listener, launch/attach, frames, values, registers, and memory. Helper/protocol tests pass; native LLDB verification requires a compatible local installation. |

Recorded native coverage is Windows with CPython 3.14.6 and GDB 17.2. Linux and
macOS are target platforms; their native integrations are not claimed as verified
by this Windows run. See [GDB coverage](tests/gdb/COVERAGE.md),
[PDB coverage](tests/pdb/COVERAGE.md), and [LLDB coverage](tests/lldb/COVERAGE.md).

For a vendor LLDB installation, set `DEA_LLDB_PYTHON` to its compatible interpreter
and, if needed, `DEA_LLDB_MODULE_PATH` to the directory containing the `lldb`
package. ABI initialization runs outside the MCP interpreter during session startup.
Check `session_capabilities` after startup before requesting registers or memory.

Sessions live for the MCP server's lifetime. Owned processes are contained and
reaped; attached targets are detached. PDB attach/registers/raw memory, interactive
target terminal input, remote debugging, reverse execution, and automatic source
patching are outside the current public debugging flow.

## Try the 10,000-item off-by-one benchmark

The [included Python demo](demos/python_offbyone/README.md) silently undercounts a
checksum. It has no exception or useful stack trace, no randomness, and no timing
dependence:

```sh
python demos/python_offbyone/buggy.py
# 49994999
python demos/python_offbyone/fixed.py
# 49995000
```

Connect an agent to DEA and give it this task:

> Use DEA's PDB backend to debug `demos/python_offbyone/buggy.py` using its absolute
> path. The expected checksum is 49,995,000. Find the first incorrect item using a
> conditional breakpoint and captured locals. Evaluate a focused expression, step
> over the suspicious assignment, and show the compact delta that proves the bug.
> Terminate the session. Apply the smallest source fix with your editor, then run
> the program and compare it with the separate fixed reference. Establish the cause
> before reading `fixed.py`.

For a guided reproduction, set a conditional breakpoint on `item = index - 1`
with `index == 4096` (the 4097th iteration). Inspect `index`, `item`, and `total`;
evaluate `item - index`, await the baseline recapture, then step over. The `item`
delta from **4096 → 4095** reveals the corruption. The expected fix is documented
in the demo README, separately from its program source.

Run the same flow as executable integration checks, including the real MCP stdio
client/server path:

```sh
pip install -e ".[dev]"
python -m pytest tests/integration/test_pdb_python_offbyone.py tests/gateways/test_stdio_pdb_python_offbyone.py -q
```

This is a deterministic correctness/debugging benchmark; it makes no agent speed,
cost, or solve-rate claim.

## Validate the release

```sh
python -m dea.contracts.ownership
python -m pytest -q -ra
```

The suite covers contracts, bounded process I/O, lifecycle races, snapshot history,
dual-tokenizer packing, adapters, process cleanup, and real MCP/PDB integration.
Unavailable native prerequisites produce explicit skips. Passing API doubles is
not evidence that a missing native debugger works.

[Architecture](ARCHITECTURE.md) · [Frozen API specification](SPEC.md) ·
[Work-package ownership](TASKS.md) · [Python integration coverage](tests/integration/README.md)
