"""The sole output boundary. No guessed token counts or JSON slicing."""
import json
from dataclasses import dataclass
from functools import lru_cache

import tiktoken

from .compact import ErrorResponse, RESPONSE_ADAPTER, ToolResponse
from .models import ErrorCode

TOKEN_LIMIT = 191
ENCODINGS = ("cl100k_base", "o200k_base")
FALLBACK_WIRE = '{"code":"SERIALIZATION_FAILED","type":"error"}'


class TokenBudgetExceeded(ValueError):
    def __init__(self, counts: tuple[tuple[str, int], ...]) -> None:
        self.counts = counts
        super().__init__("Response exceeds the 191-token wire budget")


@dataclass(frozen=True)
class WirePayload:
    text: str
    token_counts: tuple[tuple[str, int], ...]


@lru_cache(maxsize=1)
def _encoders() -> tuple[tiktoken.Encoding, ...]:
    # Initialization failure must propagate: serving without tokenizers is forbidden.
    return tuple(tiktoken.get_encoding(name) for name in ENCODINGS)


class WireGuard:
    def __init__(self) -> None:
        self._encodings = _encoders()
        self.fallback = self._check(FALLBACK_WIRE)
        RESPONSE_ADAPTER.validate_json(FALLBACK_WIRE)

    def _check(self, text: str) -> WirePayload:
        text.encode("utf-8", errors="strict")
        counts = tuple((enc.name, len(enc.encode(text, disallowed_special=()))) for enc in self._encodings)
        if any(count > TOKEN_LIMIT for _, count in counts):
            raise TokenBudgetExceeded(counts)
        return WirePayload(text, counts)

    def encode(self, response: ToolResponse) -> WirePayload:
        # Round-trip validation also catches model_construct/model_copy bypasses.
        validated = RESPONSE_ADAPTER.validate_json(
            response.model_dump_json(by_alias=True, exclude_none=True, warnings=False)
        )
        payload = validated.model_dump(mode="json", by_alias=True, exclude_none=True)
        wire = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)
        return self._check(wire)

    def safe_encode(self, response: ToolResponse) -> WirePayload:
        try:
            return self.encode(response)
        except Exception:
            return self.fallback

    def error(self, code: ErrorCode) -> WirePayload:
        return self.safe_encode(ErrorResponse(code=code))

