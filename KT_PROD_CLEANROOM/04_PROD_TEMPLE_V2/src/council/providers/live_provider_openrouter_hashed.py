from __future__ import annotations

from dataclasses import dataclass

from council.providers.live_hashed_http_provider import LiveHashedHTTPChatProvider


@dataclass(frozen=True)
class LiveHashedOpenRouterProvider(LiveHashedHTTPChatProvider):
    provider_id: str = "openrouter"
    host: str = "openrouter.ai"
    path: str = "/api/v1/chat/completions"
    endpoint: str = "chat.completions"
    key_env_prefix: str = "OPENROUTER"
