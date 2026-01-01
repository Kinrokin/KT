from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict

from council.providers.dry_run_provider import DryRunProvider
from council.providers.live_provider_openai import OpenAIProvider
from council.providers.provider_interface import ProviderClient
from council.providers.provider_schemas import ProviderRequestSchema, ProviderResponseSchema, make_disabled_response, make_fail_closed_response
from council.providers.live_provider_openai_hashed import LiveHashedOpenAIProvider
from council.providers.provider_schemas import ProviderCallReceipt


@dataclass(frozen=True)
class ProviderRegistry:
    # Deterministic allowlist map provider_id -> implementation
    providers: Dict[str, ProviderClient]

    @staticmethod
    def build_default() -> "ProviderRegistry":
        # Note: live providers are registered but remain disabled by default.
        providers: Dict[str, ProviderClient] = {
            "dry_run": DryRunProvider(),
            # Live-enabled provider implementations (registered but disabled by default).
            "openai": OpenAIProvider(),
            # Inventory-only providers: declared here but default to dry-run behavior until implemented.
            "gemini": DryRunProvider(),
            "cerebras": DryRunProvider(),
            "groq": DryRunProvider(),
            "deepseek": DryRunProvider(),
            "openrouter": DryRunProvider(),
            "huggingface": DryRunProvider(),
            "together": DryRunProvider(),
            "sambacloud": DryRunProvider(),
            "cloudflare": DryRunProvider(),
            "tavily": DryRunProvider(),
        }
        return ProviderRegistry(providers=providers)

    @staticmethod
    def live_enabled() -> bool:
        # Explicit off-switch (default false). Any non-empty "1/true/yes" enables.
        raw = os.environ.get("KT_PROVIDERS_ENABLED", "").strip().lower()
        return raw in {"1", "true", "yes"}

    def resolve(self, *, provider_id: str) -> ProviderClient:
        provider = self.providers.get(provider_id)
        if provider is None:
            raise ValueError("unknown_provider_id (fail-closed)")
        return provider

    def invoke(self, *, request: ProviderRequestSchema) -> ProviderResponseSchema:
        req = request.to_dict()
        ProviderRequestSchema.validate(req)
        provider_id = str(req["provider_id"])

        if provider_id != "dry_run" and not self.live_enabled():
            return make_disabled_response(request=request, error_code="PROVIDERS_DISABLED")

        provider = self.resolve(provider_id=provider_id)
        try:
            return provider.invoke(request=request)
        except Exception:
            return make_fail_closed_response(request=request, error_code="PROVIDER_ERROR")

    def invoke_live_hashed(
        self,
        *,
        provider_id: str,
        model: str,
        prompt: str,
        timeout_ms: int,
        temperature: float,
        kt_node_id: str,
        trace_id: str | None = None,
    ) -> ProviderCallReceipt:
        # Minimal, fail-closed routing for LIVE_HASHED lane.
        if provider_id == "openai":
            prov = LiveHashedOpenAIProvider()
            return prov.invoke_hashed(
                model=model,
                prompt=prompt,
                timeout_ms=timeout_ms,
                temperature=temperature,
                kt_node_id=kt_node_id,
            )
        raise RuntimeError(f"LIVE_HASHED provider not implemented (fail-closed): {provider_id!r}")

