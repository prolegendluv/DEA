# LLDB adapter coverage

The native SB API lives in `helper.py`, executed by an isolated, compatible interpreter.
Set `DEA_LLDB_PYTHON` to the matching Python executable and optionally
`DEA_LLDB_MODULE_PATH` to the directory containing the vendor's `lldb` package.
The configured interpreter is authoritative: an import/ABI failure is a capability
error, never a fallback import inside the server.

Construction performs only an installation eligibility check, since the frozen
session service requires synchronous capabilities before starting an adapter.
The full extension/API probe runs in a worker thread under the startup deadline;
failed probes clear availability. Capability flags before first start describe
installation eligibility, not a verified native launch. Permission/backend failures
during launch/attach return `CAPABILITY_UNAVAILABLE`. Target PTY is explicitly
unsupported: captured program output and diagnostics remain outside control frames.

Deterministic SB doubles cover async launch/attach, listener selection and stop
reasons, entry traps, stepping, interruption, recursion/frame identities, exact
register/value/memory observations, failed detach, and listener cleanup. Protocol
tests cover fragmented UTF-8, bounded framing, non-finite/duplicate-key JSON,
correlation and exit-before-ack races, overflow, crashes, stale replies and timeouts.
An actual Python subprocess on the host exercises isolated helper imports, the
authenticated loopback handshake, typed snapshots and output isolation with SB
doubles; this is a real transport test, not evidence of native LLDB support.

`test_native.py` runs a real LLDB launch/capture/cleanup only when a compatible
LLDB installation is present, and otherwise reports an explicit prerequisite skip.
This Windows host has no usable LLDB Python bindings. Native LLDB launch/attach
on Windows, Linux and macOS therefore remain unverified here.

API references: [SBLaunchInfo](https://lldb.llvm.org/python_api/lldb.SBLaunchInfo.html),
[SBListener](https://lldb.llvm.org/python_api/lldb.SBListener.html),
[SBProcess](https://lldb.llvm.org/python_api/lldb.SBProcess.html),
[SBFrame](https://lldb.llvm.org/python_api/lldb.SBFrame.html).
