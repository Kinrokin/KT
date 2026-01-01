from __future__ import annotations

from dataclasses import dataclass

from council.providers.base_provider import ProviderCall, ProviderCallResult
from council.providers.provider_schemas import (
    MODE_DRY_RUN,
    ProviderRequestSchema,
    ProviderResponseSchema,
    make_disabled_response,
)


@dataclass(frozen=True)
class DryRunProvider:
    provider_id: str = "dry_run"

    def execute(self, *, call: ProviderCall) -> ProviderCallResult:
        # No network, no provider SDKs, no fabricated outputs.
        return ProviderCallResult(performed=False, success=False, duration_ms=0, output_hash=("0" * 64))

    def invoke(self, *, request: ProviderRequestSchema) -> ProviderResponseSchema:
        req = request.to_dict()
        ProviderRequestSchema.validate(req)
        if req["mode"] != MODE_DRY_RUN:
            return make_disabled_response(request=request, error_code="DRY_RUN_ONLY")
        return make_disabled_response(request=request, error_code="DRY_RUN")
