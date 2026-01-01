from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ProviderCall:
    provider_id: str
    max_tokens: int
    input_hash: str


@dataclass(frozen=True)
class ProviderCallResult:
    performed: bool
    success: bool
    duration_ms: int
    output_hash: str
    error_code: str | None = None


class Provider(Protocol):
    provider_id: str

    def execute(self, *, call: ProviderCall) -> ProviderCallResult:
        raise NotImplementedError

