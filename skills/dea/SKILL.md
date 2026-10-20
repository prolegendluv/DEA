---
name: dea
description: Use DEA MCP tools for stateful debugger sessions, compact stop deltas, and bounded inspection of GDB, LLDB, and PDB targets.
---

# Debug Everything Autonomously

Foundation status: contracts and MCP tool registration exist; the native runtime, sessions, state packing and debugger adapters are implementation stubs. A `NOT_IMPLEMENTED` result means that work package is unfinished. Do not describe it as a successful debugging session.

Use an existing DEA MCP server connection so calls share session state. Start the server using `python -m dea serve` through the client's MCP configuration. Shell commands cannot independently address its sessions. `python -m dea doctor` reports dependency/executable presence; executable presence does not prove native adapter support.

## Debugging workflow

1. State a specific failure hypothesis and an observable value or stop condition that could disprove it.
2. Launch with `session_start` or attach using GDB/LLDB. Preserve the returned session ID. Check `session_capabilities` before requesting registers, memory or terminal behavior. PDB attach and native memory/register access are unavailable in v1.
3. Set a breakpoint or conditional breakpoint near the suspected divergence. Use frame inspection or explicit evaluation to narrow the hypothesis.
4. Continue/step acknowledgements mean accepted, not stopped. Use `session_wait` after the last event ID, then inspect only a stopped target. Waiting can time out without interrupting execution.
5. Read changed variables/registers from compact stop output. If details were omitted, follow the returned cursor with `state_page`; preserve page object IDs and offsets. Expired cursors are not evidence about current program state.
6. After `set_breakpoint` pacing hints, choose a condition, watch expression, or focused frame inspection instead of repeated unproductive single steps.
7. Verify the hypothesis against captured observations. Evaluate expressions deliberately because they can have side effects. Any code edits belong to the coding agent's normal editing workflow; DEA does not patch source automatically.
8. Terminate the session when finished. DEA terminates targets it launched and detaches targets it attached to.

All tools accept one `request` object. Tool payloads are valid JSON capped at 191 tokens under the two reference encodings. Do not request raw debugger dumps or assume omitted values are unchanged.

Read [the tool reference](references/tools.md) for payload examples and [state semantics](references/state.md) for baselines, event IDs and cursors.

