# DEA v1 frozen implementation specification

## Ownership and implementation status

The architect owns `pyproject.toml`, root documentation, `schemas`, `src/dea/contracts`, `src/dea/bootstrap.py`, `src/dea/__init__.py`, `src/dea/__main__.py`, `tests/contracts`, and `tests/support`. Workers may change only roots assigned in `dea.contracts.ownership.WORK_PACKAGES`.

Implemented: request/observation/response models, wire guard, composition root, MCP boundary, CLI diagnostics/schema export, test doubles, and foundation checks. Placeholder services and adapters raise `DeaError(NOT_IMPLEMENTED)`. Their empty close methods release no resources because the placeholders never create resources.

## Requests, constructors and public operations

All models inherit `StrictModel`: strict types, forbidden extras, frozen nested models and tuple collections. Python callers provide actual enum instances and tuples. JSON callers provide enum strings and arrays; JSON validation converts only their representation, without coercing numeric strings or booleans to integers. Binary fields use URL-safe base64 JSON serialization.

`LaunchSpec(backend, binary_path, args=(), env=(), cwd=None, io_mode='capture', stop_at_entry=True, memory_regions=())` launches a target. PDB's `binary_path` identifies the script; adapters choose a configured compatible Python interpreter. Native adapters launch the supplied executable. Preserve empty arguments and Unicode. Never invoke a shell to assemble debugger commands. Environment is inherited with explicit key/value overrides; avoid duplicate keys and use case-insensitive key comparison on Windows. Strip helper control credentials from target environments.

`AttachSpec(backend, pid, binary_path=None, memory_regions=())` attaches GDB/LLDB. Attach owns the helper/debugger but not the existing target. PDB attach returns `CAPABILITY_UNAVAILABLE` in v1. Stop at entry by default on launch; attach establishes and captures its first stopped state before inspection is permitted.

`BreakpointSpec(location, condition=None)` accepts a source `file:line` or function location and a debugger-native condition. Adapters quote/escape these as protocol data, not command-line concatenation. Evaluation is an explicit operation and may execute code or change state; invalidate affected baselines and recapture before returning further deltas. Do not automatically evaluate arbitrary user-defined repr/pretty-printers during ordinary captures when the debugger offers a non-executing representation.

Frozen constructor entry points:

```python
AsyncProcessManager(limits: RuntimeLimits)
StateEngine(limits: RuntimeLimits, clock: Clock, guard: WireGuard)
SessionManager(runtime: ProcessManager, state: StateService,
               adapters: Mapping[Backend, AdapterFactory], clock: Clock,
               limits: RuntimeLimits)
GdbAdapter(context: AdapterContext)
LldbAdapter(context: AdapterContext)
PdbAdapter(context: AdapterContext)
create_server(sessions: SessionService, guard: WireGuard, *, on_close=None)
build_application(*, runtime=None, state=None, sessions=None, clock=None, limits=None)
```

`AdapterContext` contains session ID, runtime, memory history, clock, and limits. `ADAPTER_FACTORIES` binds the three backends. Workers keep these names, exports, and signatures; report necessary contract changes to the architect.

Every MCP tool accepts exactly `{"request": {...}}`. Fields for each operation:

| Tool | Request fields |
|---|---|
| `session_start` | `LaunchSpec` fields |
| `session_attach` | `AttachSpec` fields |
| `breakpoint_set` | `session_id`, `spec: BreakpointSpec` |
| `execution_continue` | `session_id` |
| `execution_step` | `session_id`, `mode: over/into/out` |
| `execution_interrupt` | `session_id` |
| `state_inspect_frame` | `session_id`, `frame_index=0`, `max_depth=1` |
| `state_eval_expression` | `session_id`, `expr` |
| `state_memory_diff` | `session_id`, `since_step_id` |
| `session_wait` | `session_id`, `after_event_id=0`, `timeout_ms=1000` |
| `state_page` | `session_id`, `cursor_id` |
| `session_capabilities` | `session_id` |
| `session_terminate` | `session_id` |

Continue/step/start/attach return an accepted acknowledgement, not a synthetic stop. Journal entries are assigned session-local monotonic `eid` values. Capture stops use a separate monotonic `stop` sequence. `session_wait` returns the first retained entry with `eid > after_event_id`; it does not consume it. Waiting for an evicted event returns `HISTORY_UNAVAILABLE`, never silently skips a gap. Timeout returns `WAIT_TIMEOUT`. Exit is a lifecycle event, not a stop with invented register values.

`state_inspect_frame`, `state_eval_expression`, and `state_memory_diff` return the first capped inspection page; subsequent `state_page` calls advance through captured details. `session_capabilities` returns a capabilities payload. `session_terminate` acknowledges completed cleanup; repeated termination returns the same terminal acknowledgement while the session record is retained.

## Runtime and helper framing

`ProcessManager.spawn(ProcessSpec) -> ManagedProcess` creates only owned helper/debugger processes. `ProcessSpec.argv` is an argument vector, with an executable in element zero. Runtime owns `read() -> AsyncIterator[ProcessChunk]`, `write(bytes)`, `wait() -> int`, `interrupt()`, and idempotent `close()`. Process chunks preserve byte boundaries; parsers perform incremental decoding. One reader owns each stream; a serialized writer handles backpressure.

`ProcessSpec.helper_control=True` requests the dedicated framed helper connection. Runtime binds the endpoint before launch, injects `DEA_CONTROL_HOST`, `DEA_CONTROL_PORT`, and `DEA_CONTROL_TOKEN` into the helper environment, and completes the handshake within the startup timeout. `ManagedProcess.control` then exposes the frozen `HelperConnection` protocol: `messages() -> AsyncIterator[HelperMessage]`, `send(message)`, and idempotent `close()`. The default is `helper_control=False`, with `control=None`, used for GDB's MI pipes. LLDB/PDB workers use this injected connection without importing `runtime.framing` or other runtime implementation modules. Closing a managed process also closes its helper connection.

Each dedicated helper connection uses a four-byte unsigned network-order body length, followed by that many UTF-8 bytes of `HelperMessage` JSON. Body length must be 1..1,048,576 before allocation. EOF between messages is normal on expected shutdown; EOF inside a prefix/body is `PROTOCOL_ERROR`. Decode incrementally, allowing multiple messages per read. Invalid UTF-8, non-finite JSON constants, malformed envelopes and oversized records are fatal protocol errors.

`HelperMessage` fields: `version=1`, `kind=request|response|event`, `operation`, `body_json`, and exactly one correlation field. Requests/responses use `request_id`; events use `event_id`. `body_json` contains serialized JSON for the relevant strict model; raw memory bytes use base64. Both the outer message and its typed body must validate. The framed-byte bound includes the outer encoding and JSON escaping; the character bound alone is insufficient.

Operations are the adapter method names. Request bodies are the corresponding request model; parameterless operations use `{}`. Step body is `{"mode":"over"}`; frame body contains `frame_index` and `max_depth`; evaluation contains `expr`; memory read uses `MemoryRegion`; termination uses `{"policy":"detach"}` or `terminate_owned`. Responses use the declared adapter result model, or `{"code":"<ErrorCode>"}` with operation `error` and the matching request ID. Termination success uses `{}`. Events use operation `debugger_event` with a `DebuggerEvent` body and matching outer/inner event ID. Memory diff stays in the shared history service, not the helper protocol.

Use a loopback-only ephemeral local control endpoint with a random, single-use handshake token passed only to the helper. The first frame has operation `hello`, request ID 1, and body `{"token":"..."}`; the supervisor responds with an empty matching response before other operations. Normal request IDs begin at 2. Authentication mismatch closes the connection. Target stdout/stderr and debugger diagnostics never enter this channel. Disable debugger startup scripts that would interfere with protocol behavior.

For GDB, keep MI command/result correlation separate from asynchronous records. Parse nested grammar and escapes; a regex-only flat parser is insufficient. Do not infer target state from `^done`, `^running`, or the prompt. Prefer MI async mode and all-stop semantics in v1; reject unavailable async control capabilities explicitly. Never let an unsupported native terminal mode merge target bytes into the MI control channel.

For LLDB, the helper owns its `SBDebugger` lifetime and a listener for process events. Choose the Python interpreter matching LLDB bindings; failed ABI/import checks are a capability error. For PDB, a helper control reader queues commands while the debugged thread executes; stopped callbacks inspect frames and execute queued debugger actions. Cooperative interruption may wait for Python execution to reach a traceable point; timeout recovery must not claim success while the process remains running.

## State and response contract

`RawSnapshot` preserves session/stop/thread/frame context, reason, observations, frames, memory, and capture completeness. `RawValue.available=False` represents unknown/unreadable data; it is not a deletion. Compare full captured values keyed by identity. Register and variable names alone are not unique identities. Baseline reset produces additions only; use a missing `base` to signal reset. Scope switches, restarted processes, and evaluation-induced invalidation require appropriate reset/recapture.

Configure at most 16 non-overlapping memory regions totaling 64 KiB. A memory read is exact-length or an error; never pad partial reads. `BaseDebuggerAdapter.state_memory_diff` delegates to the injected history provider. Both requested and current stop must contain the same configured regions; otherwise return `HISTORY_UNAVAILABLE`. PDB returns `CAPABILITY_UNAVAILABLE`.

`CompactDebugState` wire fields: `type='stop'`, `v=1`, `sid`, `eid`, `stop`, optional `base`, `reason`, optional `thread`, optional `at`, `frames`, `regs`, `vars`, `omitted`, `cursor`, and `hint`. Empty collections and absent optionals are omitted. IDs/counters are bounded by 2^63-1; memory addresses use unsigned 64-bit bounds. Handle values are 16 lowercase hexadecimal characters, allocated without collision among live records. Overflow is an explicit error rather than counter wraparound.

At most five frames, eight register deltas, and eight variable deltas may appear; these are ceilings, not promised counts. Compact text fields are bounded by the model. `ValueDelta` has `id`, `name`, `op=add|set|del`, applicable `before`/`after`, and optional `bref`/`aref`. Missing before/after fields encode operation semantics; the target's Python `None` is the string representation `"None"`, not an unknown observation.

When names or values exceed display bounds, assign stable detail references instead of truncating silently. A short `<value>` display with distinct references preserves changes sharing an identical prefix. Referenced values and omitted entries require a cursor. Long scoped identities map to bounded stable IDs; keep their exact names in stored detail objects.

Packing order: mandatory stop/session/event metadata; watched-variable deltas; other variable deltas; register deltas; frame summaries. Keep items in stable identity/index order within each group. Location/thread are optional metadata and can be dropped to preserve the cap. Count omitted detail items after every removal. Preserve the pacing hint if present and reserve its space. The final metadata-only fallback carries omission counts and a cursor; the guard measures it before delivery.

Pages serialize an immutable detail object as text and return contiguous Unicode-character chunks: `type='page'`, `sid`, `stop`, `object`, `offset`, `next`, `text`, optional `cursor`. `next = offset + len(text)`. A continuation contains at least one character. First page starts at zero; each cursor resolves to the exact next position. Keep the original object ID while paging. Replaying a cursor is idempotent and returns the same page; its new cursor advances. Use the whole detail collection as one immutable canonical JSON text when a stop has multiple omitted objects. Expired/evicted cursors return `CURSOR_EXPIRED`.

`WireGuard.encode` round-trips response validation, serializes with sorted keys, no whitespace, UTF-8 and no non-finite values, then measures **both** pinned encodings. At most 191 tokens are permitted. `safe_encode` returns the fixed prevalidated `SERIALIZATION_FAILED` JSON on invalid/oversized output. The state packer uses `encode` to retry with fewer items; the gateway uses the fixed fallback only as a last boundary. Never slice JSON or guess token length. Error payloads expose fixed codes; detailed exceptions are not inserted into tool returns.

Protocol-envelope errors and tool-list schemas are outside the application-payload cap. All tool-call payloads, including SDK validation errors, are capped. Return one MCP text block without duplicate structured output or generated traceback text. The exported compact schema is regenerated with `dea schema`; its tokenizer budget is an executable invariant, not a JSON Schema `maxLength` claim.

## Defaults, lifecycle and pacing

| Limit | Default |
|---|---:|
| Framed protocol message | 1 MiB |
| Control event queue | 256 entries |
| Diagnostics ring | 1 MiB per session |
| Retained stop snapshots | 128 per session |
| Snapshot/detail/cursor storage | 16 MiB per session |
| Cursor TTL | 600 seconds from creation; no refresh on read |
| Startup timeout | 10 seconds |
| Command acceptance timeout | 5 seconds |
| Event wait | 1 second default; 0..30 seconds allowed |
| Session registry | 16 records, including retained terminal sessions |

Use monotonic time. TTL or oldest-first eviction removes dependent cursor records. Event journals retain at most 256 entries within the same storage budget; do not keep oversized duplicate raw data there. Stop journal entries reference retained snapshots, and unavailable snapshot details are explicit. Reject a single observation that cannot fit storage with `HISTORY_UNAVAILABLE`; do not create a dangling cursor. Retain terminal records and their acknowledgements while the registry has capacity. When a new session needs a slot, evict the oldest terminal record and its state; never evict an active session. At 16 active sessions, reject a new session with `RESOURCE_LIMIT`. An evicted session ID returns `SESSION_NOT_FOUND`.

Diagnostic overflow drops oldest diagnostic bytes and increments an internal loss counter. Control overflow fails the session and cleans up; it never drops state events silently. A timeout cancels pending command correlation and prevents stale replies from satisfying subsequent requests. Recovery interrupts and re-establishes state before allowing another mutation.

Eight consecutive step operations without breakpoint/watchpoint or exact watched-value divergence set `hint='set_breakpoint'` on the resulting stop. Keep issuing it on further non-diverging steps until reset. Unrelated variable/register changes, instruction-pointer updates, and frame movement do not establish watched divergence. The hint and all omission metadata must fit the same wire budget.

## Deferred work and release acceptance

No remote targets, PDB attach, reverse execution, standalone session daemon, auto-installing client configuration, or automatic source patching in this release. Native capability flags become true only after probing and tested operation. Local skips for absent tools are explicit; each advertised platform/backend capability needs a passing native integration test before release.

