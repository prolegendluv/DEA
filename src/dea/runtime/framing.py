"""WP1: implement four-byte network-order length + UTF-8 HelperMessage JSON.

Reject lengths outside 1..limits.protocol_bytes before allocating a body.
Accept fragmented/multiple messages. Truncated EOF and malformed JSON are
PROTOCOL_ERROR. Control overflow is fatal; diagnostics use a separate ring.
"""

