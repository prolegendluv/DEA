# Runtime coverage recorded on 2026-10-20

Native host: Windows, CPython 3.14.6.

Implemented and exercised against real child processes:

- Hidden Windows pipes, suspended creation, Job Object assignment before resume.
- Unicode and empty arguments, environment overrides and working directories.
- Concurrent stdout/stderr flooding, bounded diagnostic loss, fatal control overflow.
- Blocked native-write cancellation with event-loop responsiveness.
- Cancellation during launch and authenticated-helper startup.
- Repeated/concurrent/cancelled close; all owned I/O/wait threads joined.
- Descendant termination when the process-group leader already exited.
- Real ConPTY input/output, SIGINT delivery, natural exit, output-flood shutdown.
- Stable native handle counts after warming asyncio's reusable executor threads.
- Authenticated single-use loopback helper endpoint, typed framed roundtrip,
  protocol/target-output separation, invalid authentication, startup timeout,
  truncated and unexpected EOF, expected exit EOF and queue overflow.
- Regression for a full one-slot write queue during close.

Protocol-only tests additionally cover every byte fragmentation boundary,
fragmented Unicode, multiple records, malformed lengths/envelopes/bodies,
duplicate keys, non-finite JSON constants and matching event correlations.

POSIX pipes/process groups/nonblocking PTY implementation is present. Its
explicit native POSIX scenario is skipped on Windows; Linux/macOS results must
be obtained on those hosts before advertising verified native support there.
Cross-platform native tests also run on POSIX when available.

Hidden Windows pipe children have no console CTRL_BREAK destination;
ManagedProcess.interrupt raises CAPABILITY_UNAVAILABLE for this transport.
Adapters interrupt through their debugger protocol. ConPTY interrupt is verified
against a real Python SIGINT handler.

The runtime preserves raw ProcessChunk byte boundaries. UTF-8 decoding of
unframed debugger/target streams belongs to their consumer; helper UTF-8 is
decoded only after its complete length-bounded frame has arrived.
