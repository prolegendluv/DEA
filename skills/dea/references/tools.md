# DEA tool examples

These are tool argument objects, not standalone shell commands. They require implemented services behind the persistent MCP connection.

Launch with `session_start`:

```json
{"request":{"backend":"gdb","binary_path":"/absolute/path/to/program","args":[],"stop_at_entry":true}}
```

For PDB, use `backend: "pdb"` and the script path. For native Windows use an absolute Windows executable/script path, JSON-escaping backslashes.

Attach with `session_attach`:

```json
{"request":{"backend":"lldb","pid":12345}}
```

Set a conditional breakpoint with `breakpoint_set`:

```json
{"request":{"session_id":"0123456789abcdef","spec":{"location":"main.cpp:42","condition":"count == 10"}}}
```

Step with `execution_step`:

```json
{"request":{"session_id":"0123456789abcdef","mode":"over"}}
```

Wait with `session_wait`, using the last returned `eid`, not `stop`:

```json
{"request":{"session_id":"0123456789abcdef","after_event_id":2,"timeout_ms":1000}}
```

Inspect with `state_inspect_frame`:

```json
{"request":{"session_id":"0123456789abcdef","frame_index":0,"max_depth":1}}
```

Evaluate with `state_eval_expression`:

```json
{"request":{"session_id":"0123456789abcdef","expr":"count"}}
```

Read a continuation with `state_page`:

```json
{"request":{"session_id":"0123456789abcdef","cursor_id":"fedcba9876543210"}}
```

`session_capabilities`, `execution_continue`, `execution_interrupt`, and `session_terminate` take `{"request":{"session_id":"0123456789abcdef"}}`.

`state_memory_diff` takes `session_id` and `since_step_id`. Regions must have been configured in the launch/attach `memory_regions` list, with numeric `address` and `size`; later reads cannot reconstruct an uncaptured baseline.

