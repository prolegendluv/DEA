# WP4 GDB coverage

Native verification on this Windows host uses Python 3.14, GDB 17.2
(`x86_64-w64-mingw32`) and GCC from the installed UCRT toolchain. The native
tests compile isolated fixtures inside pytest temporary directories.

Passing real scenarios cover launch and entry; conditional function breakpoints;
frames, locals, registers, exact memory; step over/out; hardware watchpoints;
SIGSEGV; running interruption; empty/spaced/quoted/Unicode arguments; exit and
repeated cleanup; native attach and detach with the external process surviving.
The composition test additionally launches the frozen application and passes
through session/state services.

Target stdout and stderr share an inferior-only bounded byte ring. On Windows,
GDB opens a dedicated nonblocking-server duplex named pipe as its inferior tty;
POSIX uses an independently drained PTY. Neither sink feeds the MI parser.
Native fixture output includes valid tokenless stopped records and a forged
numbered acknowledgement. Tests prove these remain target bytes without
altering debugger events or command correlation. Public interactive PTY mode is
explicitly unavailable; capture mode has no target input API.

Parser tests cover nested tuples, value/result lists, repeated result keys,
escaped strings and UTF8 octets, byte fragmentation, prompts, malformed and
oversized records, stream records, and recursion limits. Scripted tests exercise
stop/exit before acknowledgement, independent watchpoint/signal events,
requested versus target-generated SIGINT/SIGTRAP, stale replies, blocked writes,
timeouts, cancellation, control overflow, diagnostic loss, detach failure,
recursive frame activation identities, malformed memory and non-Unicode values.

Frame activations include the selected frame's `$sp` (read without executing
target code). A changed stack pointer conservatively resets identity. Snapshot
stack summaries derive from the captured activation. Non-Unicode GDB byte
strings use a collision-protected `<dea:bytes>` JSON-escape representation.

POSIX/macOS native execution is not verified on this Windows host. Tests skip
only when GDB/compiler prerequisites are missing; attach permission restrictions
on other hosts are explicit failures, not silently advertised capabilities.
Register/memory flags become true only after required MI initialization passes.
Initial executable availability enables the frozen session manager to attempt
launch/attach. No register/memory data is fabricated after an inferior exit.

GDB v1 remains all-stop, one inferior and one event consumer. Public breakpoint
requests do not have a watchpoint kind; native watchpoint parsing/capture is
verified through the adapter's private MI command boundary without extending
the frozen schema. Normal attach/detach is verified; forcibly crashing a native
Windows debugger is not claimed to preserve external targets.
