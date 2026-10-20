# PDB adapter verification

Verified natively on Windows with CPython 3.14.6. The helper uses the stdlib
`pdb.Pdb` settrace backend and the injected process manager's authenticated,
length-prefixed loopback connection. Neither target fd 1/fd 2 nor PDB prompts
are used for control.

Acceptance:

```powershell
python -m pytest tests/contracts tests/pdb -q -o cache_dir=.pytest_cache/pdb
```

Coverage includes real entry/conditional source/function breakpoint stops,
into/over/out, recursion, fresh identities after repeated frame lifetimes,
exact built-in locals and evaluation, exceptions and single execution/exit,
Unicode/empty argv, cwd/environment/main-module behavior, stdout/stderr
spoofing attempts using `os.write`, tight-loop cooperative interruption, honest
interruption delayed by blocking native calls, and shared cancellation-safe
termination. Composition tests exercise the frozen session/state/MCP wiring.
Protocol tests cover malformed lengths, UTF-8 and truncated records, response
correlation, stale/unknown IDs, send backpressure and deadlines, overflow,
cancellation, response model/session/stop validation, and oversized captures.

PDB attach, registers, raw memory and target PTY are explicitly unavailable.
Cooperative interruption is checked on Python trace events; blocking native
calls cannot stop until Python execution resumes. Objects whose exact value
cannot be observed without executing target code, excessively large/deep
containers, cycles, and values beyond the observation model's bound are marked
unavailable. Local-name coverage remains complete when all names are enumerated;
unknown values do not imply deletion. Captures exceeding the framed byte limit
return `HISTORY_UNAVAILABLE`, leaving the control connection usable. Use explicit
expressions such as `repr(obj)` when target-defined representation is desired.

The POSIX code path uses the same helper protocol and stdlib backend but has
not been executed on this Windows host. No POSIX native result is claimed.
