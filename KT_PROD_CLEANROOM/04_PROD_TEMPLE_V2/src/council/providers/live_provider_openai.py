from __future__ import annotations

import os
from dataclasses import dataclass

from council.providers.provider_interface import ProviderClient
from council.providers.provider_schemas import ProviderRequestSchema, ProviderResponseSchema, make_disabled_response, make_fail_closed_response


@dataclass(frozen=True)
class OpenAIProvider:
    provider_id: str = "openai"

    def invoke(self, *, request: ProviderRequestSchema) -> ProviderResponseSchema:
        # C022 provides adapter scaffolding only. This module intentionally does not
        # perform network calls without a separate, explicit live-execution authorization.
        #
        # Fail-closed posture:
        # - Missing key => AUTH_MISSING
        # - Present key but live call not implemented in this concept => NOT_IMPLEMENTED
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            return make_fail_closed_response(request=request, error_code="AUTH_MISSING")
        return make_disabled_response(request=request, error_code="NOT_IMPLEMENTED")

