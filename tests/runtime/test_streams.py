import asyncio
import pytest
from dea.contracts.models import DeaError, RuntimeLimits
from dea.runtime.streams import StreamBuffer


async def test_diagnostic_loss_and_interior_eviction_remain_bounded():
    failures = []
    buffer = StreamBuffer(RuntimeLimits(diagnostic_bytes=10), stdout_control=True, on_failure=failures.append)
    buffer.feed("stdout", b"control")
    for _ in range(10000):
        buffer.feed("stderr", b"abcdef")
    assert len(buffer._items) <= 4
    assert buffer._diagnostic_size == 10
    assert buffer.diagnostic_loss == 60000-10
    assert (await buffer.next()).data == b"control"
    rest = b""
    buffer.finish()
    while item := await buffer.next():
        rest += item.data
    assert rest == b"cdefabcdef"
    assert not failures


async def test_control_overflow_is_explicit_and_notifies_once():
    failures = []
    buffer = StreamBuffer(RuntimeLimits(control_events=2), stdout_control=True, on_failure=failures.append)
    buffer.feed("stdout", b"a")
    buffer.feed("stdout", b"b")
    buffer.feed("stdout", b"c")
    await asyncio.sleep(0)
    with pytest.raises(DeaError, match="CONTROL_OVERFLOW"):
        await buffer.next()
    assert len(failures) == 1


async def test_oversized_single_diagnostic_keeps_suffix_and_counts_loss():
    buffer = StreamBuffer(RuntimeLimits(diagnostic_bytes=3), stdout_control=False, on_failure=lambda e:None)
    buffer.feed("stdout", b"123456")
    assert (await buffer.next()).data == b"456"
    assert buffer.diagnostic_loss == 3
    buffer.finish()
    assert await buffer.next() is None


async def test_native_bridge_coalesces_notifications():
    buffer = StreamBuffer(RuntimeLimits(), stdout_control=False, on_failure=lambda e:None)
    for _ in range(10000):
        buffer.feed("stderr", b"x")
    assert buffer._scheduled
    await asyncio.sleep(0)
    assert not buffer._scheduled
    assert buffer._diagnostic_size == 10000
