# Python-only WP8 integration coverage

Run from the repository root:

```powershell
python -m dea.contracts.ownership
python -m pytest tests/integration -q
python -m pytest -q -ra
```

Verified on native Windows with CPython 3.14.6:

- Deterministic buggy checksum repeated three times; fixed reference and the
  minimal patch applied to a temporary copy both return the correct checksum.
- Real PDB helper, runtime, session orchestrator and state engine through the
  existing public MCP tool handlers; no fake debugger or response results.
- Conditional breakpoint at zero-based index 4096, exact paginated locals,
  explicit evaluation and its baseline reset, step, and a compact `item` delta
  from 4096 to 4095 relative to the reset stop.
- Every returned JSON payload is strictly revalidated, canonically serialized,
  and checked by the existing guard against both tokenizers at <=191 tokens.
- Explicit and repeated termination plus normal exit in a separate smoke test.
  Pass-through spawn instrumentation records the actual process. Evaluation
  establishes that the PDB target executes inside that same owned helper PID.
  Cleanup awaits the public process wait operation and verifies native exit
  before application shutdown; Windows uses a retained process handle to
  avoid PID-reuse ambiguity. The demo creates no additional children.

Latest acceptance: integration **3 passed, 0 skipped, 0 failed**; full suite
**340 passed, 2 skipped, 0 failed**. Ownership validation passed.

Full-suite skips come from existing packages:

- Native LLDB: compatible LLDB Python bindings/interpreter unavailable.
- POSIX process-group/PTY scenario: Windows host; native ConPTY tests run instead.

The integration tests need no Package 7 skip: its existing MCP boundary is
wired and exercised in process. They do not claim a new stdio transport test.
The native PDB smoke explicitly skips if the current Python executable or
standard-library PDB is missing; other launch/protocol failures fail normally.
POSIX cleanup has an OS-level check but is not claimed as tested on this host.
C/C++, Rust, native attach/detach and other debugger demos remain outside this
Python-only slice.
