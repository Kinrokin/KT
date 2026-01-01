from __future__ import annotations

from typing import Protocol

from council.providers.provider_schemas import ProviderRequestSchema, ProviderResponseSchema


class ProviderClient(Protocol):
    provider_id: str

    def invoke(self, *, request: ProviderRequestSchema) -> ProviderResponseSchema:
        ...

