import json
import random

import pytest
from pydantic import ValidationError

from dea.contracts.compact import CompactDebugState, ErrorResponse, InspectionPage, OmissionCounts, ValueDelta
from dea.contracts.models import ErrorCode, StopReason
from dea.contracts.wire import FALLBACK_WIRE, TOKEN_LIMIT, TokenBudgetExceeded, WireGuard
from tests.support.fakes import SID


@pytest.fixture(scope="module")
def guard():
    return WireGuard()


def make_page(text):
    return InspectionPage(session_id=SID, stop_id=1, object_id=SID, offset=0,
                          next_offset=len(text), text=text)


@pytest.mark.parametrize("text", ["plain", '"\\\n\t', "漢字🪲e\u0301", "<|endoftext|>", "<|fim_prefix|>"])
def test_exact_serialization_and_special_text(guard, text):
    result = guard.encode(make_page(text))
    assert json.loads(result.text)["text"] == text
    assert result.text == json.dumps(json.loads(result.text), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert all(count <= TOKEN_LIMIT for _, count in result.token_counts)


def test_exact_191_boundary_and_192_rejection(guard):
    found = {}
    for length in range(1, 250):
        response = make_page("x " * length)
        try:
            encoded = guard.encode(response)
            count = max(value for _, value in encoded.token_counts)
        except TokenBudgetExceeded as exc:
            count = max(value for _, value in exc.counts)
        if count in (191, 192):
            found[count] = response
        if len(found) == 2:
            break
    assert set(found) == {191, 192}
    assert max(count for _, count in guard.encode(found[191]).token_counts) == 191
    with pytest.raises(TokenBudgetExceeded):
        guard.encode(found[192])


def test_oversized_output_fails_closed(guard):
    with pytest.raises(TokenBudgetExceeded):
        guard.encode(make_page("🪲" * 1000))
    assert guard.safe_encode(make_page("🪲" * 1000)).text == FALLBACK_WIRE


def test_baseline_fallback_with_maximal_metadata_fits(guard):
    state = CompactDebugState(session_id="f" * 16, event_id=2**63-1, stop_id=2**63-1,
                               base_stop_id=2**63-2, reason=StopReason.EXCEPTION,
                               omitted=OmissionCounts(registers=2**63-1, variables=2**63-1, frames=2**63-1),
                               cursor_id="f" * 16, hint="set_breakpoint")
    assert all(count <= 191 for _, count in guard.encode(state).token_counts)


def test_constructor_bypasses_cannot_escape_wire_validation(guard):
    invalid = ErrorResponse.model_construct(code="unexpected")
    with pytest.raises(ValidationError):
        guard.encode(invalid)
    assert guard.safe_encode(invalid).text == FALLBACK_WIRE


def test_all_fixed_errors_fit(guard):
    for code in ErrorCode:
        assert all(count <= 191 for _, count in guard.error(code).token_counts)


def test_invalid_unicode_cannot_escape(guard):
    with pytest.raises(ValidationError):
        make_page("\ud800")
    bypass = InspectionPage.model_construct(session_id=SID, stop_id=1, object_id=SID,
                                            offset=0, next_offset=1, text="\ud800")
    assert guard.safe_encode(bypass).text == FALLBACK_WIRE


def test_tokenizer_initialization_failure_prevents_startup(monkeypatch):
    from dea.contracts import wire
    wire._encoders.cache_clear()

    def unavailable(name):
        raise OSError("tokenizer data unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(wire.tiktoken, "get_encoding", unavailable)
        with pytest.raises(OSError, match="tokenizer data unavailable"):
            WireGuard()
    wire._encoders.cache_clear()


def test_random_unicode_payloads_are_capped_or_rejected(guard):
    rng = random.Random(831)
    alphabet = ['a', '漢', '🪲', '\\', '"', '\n', 'e\u0301', '<|endoftext|>']
    for _ in range(80):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 350)))
        result = guard.safe_encode(make_page(text))
        json.loads(result.text)
        assert all(count <= 191 for _, count in result.token_counts)

