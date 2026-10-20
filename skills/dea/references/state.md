# Interpreting compact state

`sid` identifies the server-owned session. `eid` advances on every journal event. `stop` advances only on stops; `base` identifies the snapshot used for a delta. Missing `base` means a reset baseline, whose observed values are additions.

`regs` and `vars` contain additions, changes or removals. A value omitted because it was not captured or was unreadable is unknown, not deleted. Empty delta collections mean no reported change within the capture's coverage; they do not prove that the entire process is unchanged.

Names and values can have detail references. Compare identities and references rather than shortened display prefixes. `omitted` counts details available through the `cursor`; follow pages only when those details can resolve the current hypothesis.

Page offsets count Unicode characters, not bytes. Join page text for the same object in offset order. Repeating a cursor returns the same immutable page; use its returned continuation to advance. `CURSOR_EXPIRED` means TTL/eviction invalidated the captured details. Fresh live inspection is a separate operation against a stopped target.

Stop and wait deadlines are different. `WAIT_TIMEOUT` leaves the target's execution unchanged. A command timeout requires server recovery; do not assume a subsequent acknowledgement belongs to the timed-out command.

