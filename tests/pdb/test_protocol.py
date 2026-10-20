import asyncio
import json
import socket
import struct

import pytest

from dea.adapters.pdb import PdbAdapter
from dea.adapters.pdb.helper import Channel, StructuredPdb
from dea.contracts.adapter import AdapterContext
from dea.contracts.models import (
    Backend, CaptureRequest, CommandAck, DebuggerEvent, DeaError, ErrorCode,
    HelperMessage, LaunchSpec, RuntimeLimits, StopReason, TerminationPolicy,
)
from tests.support.fakes import FakeClock, FakeHistory, FakeProcess, FakeProcessManager

SID = '0123456789abcdef'


def fake_adapter(**limits):
    runtime = FakeProcessManager()
    adapter = PdbAdapter(AdapterContext(SID, runtime, FakeHistory(), FakeClock(), RuntimeLimits(**limits)))
    adapter.process = FakeProcess(helper_control=True)
    adapter._tasks = [asyncio.create_task(adapter._reader()), asyncio.create_task(adapter._drain())]
    return adapter


async def wait_sent(adapter, count):
    async with asyncio.timeout(2):
        while len(adapter.process.control.sent) < count:
            await asyncio.sleep(0)
    return adapter.process.control.sent[-1]


async def close_fake(adapter):
    adapter._terminal = True
    await adapter.session_terminate(TerminationPolicy.TERMINATE_OWNED)


async def test_response_correlation_and_stale_timeout_reply():
    a = fake_adapter(command_seconds=1)
    try:
        with pytest.raises(DeaError) as exc:
            await a.execution_continue()
        assert exc.value.code is ErrorCode.COMMAND_TIMEOUT
        stale = a.process.control.sent[-1]
        task = asyncio.create_task(a.execution_continue())
        current = await wait_sent(a, 2)
        a.process.control.feed(HelperMessage(kind='response', request_id=stale.request_id,
                                            operation=stale.operation, body_json=CommandAck(request_id=stale.request_id).model_dump_json()))
        await asyncio.sleep(0)
        assert not task.done()
        a.process.control.feed(HelperMessage(kind='response', request_id=current.request_id,
                                            operation=current.operation, body_json=CommandAck(request_id=current.request_id).model_dump_json()))
        assert (await task).request_id == current.request_id
    finally:
        await close_fake(a)


async def test_mismatched_operation_fails_pending_and_closes_process():
    a = fake_adapter()
    try:
        task = asyncio.create_task(a.execution_continue())
        request = await wait_sent(a, 1)
        a.process.control.feed(HelperMessage(kind='response', request_id=request.request_id,
                                            operation='state_inspect_frame', body_json='{}'))
        with pytest.raises(DeaError) as exc:
            await task
        assert exc.value.code is ErrorCode.PROTOCOL_ERROR
        event = await anext(a.events())
        assert event.error_code is ErrorCode.PROTOCOL_ERROR
        assert a.process.closed
    finally:
        await close_fake(a)


async def test_malformed_model_body_is_explicit_protocol_error():
    a = fake_adapter()
    try:
        task = asyncio.create_task(a.execution_continue())
        request = await wait_sent(a, 1)
        a.process.control.feed(HelperMessage(kind='response', request_id=request.request_id,
                                            operation=request.operation, body_json='{"request_id":"2"}'))
        with pytest.raises(DeaError) as exc:
            await task
        assert exc.value.code is ErrorCode.PROTOCOL_ERROR
    finally:
        await close_fake(a)


async def test_exit_before_ack_is_not_fabricated_success():
    a = fake_adapter()
    try:
        task = asyncio.create_task(a.execution_continue())
        await wait_sent(a, 1)
        event = DebuggerEvent(event_id=1, kind='exited', exit_code=3)
        a.process.control.feed(HelperMessage(kind='event', event_id=1, operation='debugger_event', body_json=event.model_dump_json()))
        with pytest.raises(DeaError) as exc:
            await task
        assert exc.value.code is ErrorCode.INVALID_STATE
        assert (await anext(a.events())).exit_code == 3
    finally:
        await close_fake(a)


async def test_control_overflow_is_observable():
    a = fake_adapter(control_events=1)
    try:
        for i in (1, 2):
            e = DebuggerEvent(event_id=i, kind='running')
            a.process.control.feed(HelperMessage(kind='event', event_id=i, operation='debugger_event', body_json=e.model_dump_json()))
        async with asyncio.timeout(2):
            while not a.process.closed:
                await asyncio.sleep(0)
        assert (await anext(a.events())).error_code is ErrorCode.CONTROL_OVERFLOW
    finally:
        await close_fake(a)


async def test_cancellation_forgets_request_id():
    a = fake_adapter()
    try:
        task = asyncio.create_task(a.execution_continue())
        await wait_sent(a, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not a._pending
    finally:
        await close_fake(a)


@pytest.mark.parametrize('size', [0, 1_048_577, 2**32-1])
def test_helper_rejects_frame_length_before_body_read(size):
    left, right = socket.socketpair()
    try:
        left.sendall(struct.pack('!I', size))
        with pytest.raises(ValueError):
            Channel(right).read()
    finally:
        left.close()
        right.close()


def test_helper_rejects_truncated_frame_and_invalid_utf8():
    for packet in [b'\0\0', struct.pack('!I', 5) + b'{}', struct.pack('!I', 1) + b'\xff']:
        left, right = socket.socketpair()
        try:
            left.sendall(packet)
            left.shutdown(socket.SHUT_WR)
            with pytest.raises((EOFError, ValueError)):
                Channel(right).read()
        finally:
            left.close()
            right.close()


def test_helper_roundtrip_and_oversized_response_fallback():
    left, right = socket.socketpair()
    try:
        source, sink = Channel(left, 512), Channel(right)
        request = HelperMessage(kind='request', request_id=2, operation='state_eval_expression', body_json='{}')
        source.reply(request, {'value': '\\' * 1000})
        response = sink.read()
        assert response.operation == 'error'
        assert json.loads(response.body_json) == {'code': 'HISTORY_UNAVAILABLE'}
    finally:
        left.close()
        right.close()

async def test_send_backpressure_has_command_deadline():
    a = fake_adapter(command_seconds=1)
    blocked = asyncio.Event()
    async def send(message):
        await blocked.wait()
    a.process.control.send = send
    try:
        with pytest.raises(DeaError) as exc:
            await a.execution_continue()
        assert exc.value.code is ErrorCode.COMMAND_TIMEOUT
        assert not a._pending
    finally:
        await close_fake(a)


async def test_wrong_inner_ack_id_rejected():
    a = fake_adapter()
    try:
        task = asyncio.create_task(a.execution_continue())
        request = await wait_sent(a, 1)
        a.process.control.feed(HelperMessage(kind='response', request_id=request.request_id,
                                            operation=request.operation, body_json=CommandAck(request_id=99).model_dump_json()))
        with pytest.raises(DeaError) as exc:
            await task
        assert exc.value.code is ErrorCode.PROTOCOL_ERROR
    finally:
        await close_fake(a)


async def test_wrong_capture_session_and_stop_rejected():
    from dea.contracts.models import RawSnapshot
    a = fake_adapter()
    try:
        task = asyncio.create_task(a.snapshot_capture(CaptureRequest(stop_id=1, reason=StopReason.ENTRY)))
        request = await wait_sent(a, 1)
        snapshot = RawSnapshot(session_id='ffffffffffffffff', stop_id=2, thread_id=1, frame_context='main', reason=StopReason.ENTRY)
        a.process.control.feed(HelperMessage(kind='response', request_id=request.request_id,
                                            operation=request.operation, body_json=snapshot.model_dump_json()))
        with pytest.raises(DeaError) as exc:
            await task
        assert exc.value.code is ErrorCode.PROTOCOL_ERROR
    finally:
        await close_fake(a)


async def test_unissued_reply_id_is_fatal():
    a = fake_adapter()
    try:
        a.process.control.feed(HelperMessage(kind='response', request_id=90,
                                            operation='execution_continue', body_json='{}'))
        event = await anext(a.events())
        assert event.error_code is ErrorCode.PROTOCOL_ERROR
    finally:
        await close_fake(a)


async def test_event_stream_has_one_subscriber():
    a = fake_adapter()
    stream = a.events()
    task = asyncio.create_task(anext(stream))
    try:
        await asyncio.sleep(0)
        with pytest.raises(DeaError) as exc:
            await anext(a.events())
        assert exc.value.code is ErrorCode.INVALID_STATE
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await stream.aclose()
        await close_fake(a)


def test_frame_identity_map_retires_returned_frames():
    import inspect
    class ChannelDouble:
        pass
    engine = StructuredPdb(ChannelDouble(), SID)
    def invoke():
        frame = inspect.currentframe()
        identity = engine.frame_identity(frame)
        engine.dispatch_return(frame, None)
        return identity, id(frame)
    # A bottom frame avoids an actual debugger return stop in this unit fixture.
    engine.reset()
    engine.botframe = inspect.currentframe()
    engine.set_continue()
    identities = []
    for _ in range(100):
        identity, key = invoke()
        identities.append(identity)
        assert key not in engine._frame_ids
    assert len(set(identities)) == 100
    assert not engine._frame_ids
