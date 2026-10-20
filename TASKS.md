# Eight isolated DEA work packages

The foundation freezes shared contracts and wiring so eight workers can develop independently. Implementation happens in the worker-owned roots below. These packages are specifications, not evidence that native debugger integrations are already complete.

## Rules shared by every worker

1. Read `SPEC.md`, `ARCHITECTURE.md`, and the applicable `src/dea/contracts` interfaces before editing.
2. Change only your listed roots. Add local fixtures under your own test root. Do not edit another worker's roots, root documentation, dependency declarations, `schemas`, `src/dea/contracts`, `src/dea/bootstrap.py`, `src/dea/__main__.py`, `tests/contracts`, `tests/support`, or a global `conftest.py`.
3. Preserve frozen constructors, exports, signatures and wire behavior. Develop against injected protocols/test doubles, without waiting for other implementations. Avoid importing another worker's concrete implementation.
4. Use standard-library platform APIs and already declared dependencies. Report any required dependency/contract change to the architect rather than editing shared files.
5. Add meaningful tests. Empty suites, placeholder success and skips in place of unit tests are incomplete work. Native tests may skip locally when a documented prerequisite is absent, but a release capability claim requires an actual passing native scenario.
6. Run your package command and the frozen foundation suite. Report changed paths, acceptance results, platform coverage and remaining limitations. Review changes with `worker_can_write(package, relative_path)` from `dea.contracts.ownership`.

Architect acceptance before dispatch:

```sh
python -m pip install -e ".[dev]"
python -m pytest tests/contracts -q
python -m dea.contracts.ownership
```

No worker modifies shared integration wiring. The architect integrates completed packages through the already frozen composition root. If a necessary shared change is discovered, the architect updates the contract once and redistributes it.

## WP1 — Async process and PTY runtime

**Allowed roots:** `src/dea/runtime/`, `tests/runtime/`.

**Frozen entry:** `AsyncProcessManager(limits)`, exported by `dea.runtime`. Implement `ProcessManager` and `ManagedProcess` protocols. Keep the pipe/PTY backend boundary inside this package.

**Copyable worker prompt:**

> Implement WP1 inside only its allowed roots. Build nonblocking process control with POSIX pipes/PTys and native Windows hidden pipes/ConPTY. Establish process-group or Job Object ownership before executing children. Use dedicated native I/O workers on Windows and bounded bridges to asyncio. Implement strict incremental helper framing from SPEC.md, one reader per stream, serialized writes, independent diagnostic draining, explicit control overflow, and idempotent cancellation-safe cleanup. Never invoke a shell or kill unrelated attached targets. Test against local child fixtures and injected scheduling; do not implement debugger parsers or session policy.

**Acceptance command:** `python -m pytest tests/runtime tests/contracts -q`

**Completion checks:**

- Fragmented UTF-8, fragmented prefixes/bodies, multiple records and truncated EOF behave correctly.
- Concurrent stdout/stderr floods and blocked writes do not block an event-loop heartbeat.
- Diagnostic ring loss is counted; control overflow is explicit.
- Timeout/cancellation/repeated close leave no owned child, I/O worker, PTY or handle alive.
- Separate POSIX and Windows native results are reported; unavailable capabilities fail explicitly.

## WP2 — Session orchestration and pacing

**Allowed roots:** `src/dea/sessions/`, `tests/sessions/`.

**Frozen entry:** `SessionManager(runtime, state, adapters, clock, limits)`, implementing `SessionService`.

**Copyable worker prompt:**

> Implement WP2 inside only its allowed roots. Add the bounded session registry, lifecycle transitions, launch/attach ownership policy, per-session command arbitration, event journals, independent stop capture and deadlines. Subscribe before execution and handle stop/exit before acknowledgements. Inspection requires STOPPED. Interrupt/terminate must remain available while a target runs. A wait timeout leaves execution unchanged; a command timeout invalidates correlation and requires recovery. Count consecutive non-diverging steps and budget the eight-step hint through the state service. Use injected adapter factories, state service, runtime and clock, with worker-local fakes as needed.

**Acceptance command:** `python -m pytest tests/sessions tests/contracts -q`

**Completion checks:**

- Launch/attach failure, immediate stops, unsolicited events, stale acknowledgements and exit races have deterministic outcomes.
- Two sessions progress independently and only one execution operation runs per session.
- Event reads are repeatable, bounded and gap-aware.
- The pacing threshold, resets, IP-only changes and continued hints are covered.
- Shutdown terminates owned targets, detaches attached targets, and reports detach failure.
- Registry/deadline limits come from `RuntimeLimits`; no unbounded dictionaries or queues.

## WP3 — Snapshot history, exact deltas and token packing

**Allowed roots:** `src/dea/state/`, `tests/state/`.

**Frozen entry:** `StateEngine(limits, clock, guard)`, implementing `StateService` and `MemoryHistory`.

**Copyable worker prompt:**

> Implement WP3 inside only its allowed roots. Store exact immutable captured snapshots separately from compact output. Compare scoped identities and full observed values, preserving unknown versus deleted semantics and context reset behavior. Implement memory comparison only for regions captured at both stops. Pack watched variables, other variables, registers and frames deterministically, with accurate omission counts and immutable detail cursors. Retry packing with WireGuard.encode until the exact final JSON fits both 191-token limits. Pages must make progress even for a single huge Unicode value, preserve replay identity and fail explicitly after TTL/eviction. Do not parse debugger output or modify the wire guard.

**Acceptance command:** `python -m pytest tests/state tests/contracts -q`

**Completion checks:**

- Add/change/remove, unchanged values, unavailable observations, incomplete captures and context switches are covered.
- Distinct full values with identical display prefixes remain distinguishable.
- Every stop/page/error path fits both tokenizers, including hints, extreme metadata and escaping.
- Multi-page reconstruction is exact; replay is idempotent and no page recaptures a live process.
- Count/byte limits, TTL and dependent cursor invalidation are enforced.
- Memory reads compare the requested baseline or return `HISTORY_UNAVAILABLE`.

## WP4 — GDB machine-interface adapter

**Allowed roots:** `src/dea/adapters/gdb/`, `tests/gdb/`.

**Frozen entry:** `GdbAdapter(context)`, exported by `dea.adapters.gdb`, implementing `BaseDebuggerAdapter`.

**Copyable worker prompt:**

> Implement WP4 inside only its allowed roots. Replace the GDB scaffold with an incremental MI grammar parser and adapter using injected runtime services. Keep command/result tokens separate from independently ordered asynchronous records. Implement launch, native attach, breakpoints, continue/step/interrupt, exact snapshots, frame inspection, evaluation, memory reads and ownership-aware termination. Use machine-readable operations and escape supplied data. Support the specified all-stop asynchronous execution model and capability-gated target I/O. Keep all context pruning and memory history comparison in shared state services. Add fixture-based parser tests plus optional installed-GDB integration tests.

**Acceptance command:** `python -m pytest tests/gdb tests/contracts -q`

**Completion checks:**

- At least 15 parser scenarios cover nested tuples/lists, repeated keys, C-string escaping, fragmented records, stream records and malformed input.
- Tokenless stops, signals/SIGSEGV, watchpoints, multithreaded notifications and exit-before-ack are covered.
- No target output or diagnostic text can be interpreted as a control record.
- Launch/attach detach and unavailable MI/PTY capabilities are tested.
- Initialization scripts/pagination do not interfere with protocol operation.

## WP5 — LLDB helper and adapter

**Allowed roots:** `src/dea/adapters/lldb/`, `tests/lldb/`.

**Frozen entry:** `LldbAdapter(context)`, exported by `dea.adapters.lldb`, implementing `BaseDebuggerAdapter`.

**Copyable worker prompt:**

> Implement WP5 inside only its allowed roots. Run LLDB in an isolated helper using an interpreter compatible with its Python bindings. Use SetAsync(True), an SBListener, and the frozen framed helper protocol with separate target/diagnostic I/O. Implement launch/native attach and the full adapter observation/control interface. Detect actual capabilities and report missing bindings, ABI mismatches, permissions or terminal support explicitly. Keep LLDB native objects inside the helper and return strict serializable observations. Use protocol/runtime doubles for deterministic tests and optional installed-LLDB native tests.

**Acceptance command:** `python -m pytest tests/lldb tests/contracts -q`

**Completion checks:**

- Importing the adapter does not require LLDB bindings in the MCP interpreter.
- Async event ordering, listener shutdown, thread/frame selection and exact memory reads are covered.
- Missing bindings, helper crash, timeout, malformed messages and failed detach are covered.
- Native platform/backend claims match successful smoke results, with explicit local skips otherwise.

## WP6 — Structured Python PDB helper and adapter

**Allowed roots:** `src/dea/adapters/pdb/`, `tests/pdb/`.

**Frozen entry:** `PdbAdapter(context)`, exported by `dea.adapters.pdb`, implementing `BaseDebuggerAdapter`.

**Copyable worker prompt:**

> Implement WP6 inside only its allowed roots. Build a pdb.Pdb helper with structured stop callbacks, independent framed control I/O and a command queue, without parsing human prompts. Implement launch, source/function breakpoints, conditions, continue/step/interrupt, frame/variable capture, evaluation, exception stops and owned termination. PDB attach, native registers and raw memory are unsupported in v1 and must return capability errors. Preserve target stdout/stderr as program output. Use cooperative interruption honestly; blocking native calls do not justify fabricated stopped states. Keep history/deltas out of this adapter.

**Acceptance command:** `python -m pytest tests/pdb tests/contracts -q`

**Completion checks:**

- Entry, conditional breakpoint, over/into/out, recursion, exception and exit paths are covered.
- Program output containing `(Pdb)` or protocol-looking JSON cannot spoof events.
- Frame locals and watch observations have stable scoped identities and explicit capture completeness.
- No unintended automatic restart occurs at program exit.
- Cooperative interruption, timeout recovery and unsupported operations are tested on native Windows and POSIX where available.

## WP7 — MCP gateway and Antigravity skill suite

**Allowed roots:** `src/dea/gateways/`, `skills/dea/`, `tests/gateways/`.

**Frozen entries:** `create_server(sessions, guard, *, on_close=None)` and `dea.gateways.cli.main(argv=None)`.

**Copyable worker prompt:**

> Complete WP7 inside only its allowed roots, preserving the working foundation MCP boundary and all 13 tool contracts. Verify strict JSON input handling and capped SDK validation/handler errors. Return exactly one canonical JSON text block without duplicate structured output. Keep the same injected session service for the server lifetime. Complete startup/doctor diagnostics and progressive-disclosure Antigravity instructions for hypothesis, breakpoint, event wait, delta inspection, bounded pagination and verification. Update foundation-status text only when the integrated implementation supports the claim. Do not add a standalone session daemon, raw debugger shell or automatic client configuration changes.

**Acceptance command:** `python -m pytest tests/gateways tests/contracts -q`

**Completion checks:**

- Repeated calls retain sessions; initialization, disconnect and shutdown clean up correctly.
- Every tool/error payload fits both tokenizers and has valid error flags.
- A real stdio MCP client initializes, lists tools and calls through the injected service.
- Tool schemas/examples match the single `request` object convention.
- Skills explain acknowledgement versus stop, cursor expiry, capabilities and pacing.
- Doctor distinguishes executable presence, helper compatibility and verified adapter capability.

## WP8 — Integration scenarios and deterministic demos

**Allowed roots:** `tests/integration/`, `demos/`.

**Frozen integration entry:** `build_application(...)`; native scenarios use the public MCP surface.

**Copyable worker prompt:**

> Implement WP8 inside only its allowed roots. Add deterministic C/C++, Rust and Python demo fixtures, local build/run instructions, and integration scenarios against the frozen public API. Build protocol-level scenarios against injected doubles while other workers are active, then exercise real adapters when available. Verify launch -> entry/breakpoint -> inspect -> step -> delta -> termination, and native attach -> inspect -> detach without target ownership transfer. Include process cleanup, capped responses and cursor reconstruction. Keep generated binaries in ignored build directories. Do not edit CI configuration, dependencies, root docs, shared fixtures or implementations.

**Acceptance command:** `python -m pytest tests/integration tests/contracts -q`

**Completion checks:**

- Include a deterministic native crash/invalid-value fixture, a thread-state fixture, and a Python exception fixture with expected observations.
- Demonstrations avoid timing-dependent assertions and terminate within bounded deadlines.
- Missing debugger/compiler prerequisites are explicit skips with reasons.
- Record platform/backend coverage locally under the allowed roots; native support is not inferred from mocks.
- Native runs verify no orphaned owned children and normal attach/detach preserves the external target.
- Collected tool responses pass both tokenizers; pages reconstruct the exact captured detail text.

