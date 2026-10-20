"""WP1: asyncio pipes, nonblocking PTYs, process-group cleanup.

Future implementation: start_new_session for owned process trees; one reader
per descriptor, incremental decoding in the parser, serialized writes and
SIGTERM/SIGKILL escalation only for owned groups. Treat PTY EIO as EOF where
appropriate. Never import this module unconditionally on native Windows.
"""

