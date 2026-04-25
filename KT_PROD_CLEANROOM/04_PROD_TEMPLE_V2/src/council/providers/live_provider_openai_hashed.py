from __future__ import annotations

from dataclasses import dataclass

from council.providers.live_hashed_http_provider import LiveHashedHTTPChatProvider


@dataclass(frozen=True)
class LiveHashedOpenAIProvider(LiveHashedHTTPChatProvider):
    provider_id: str = "openai"
    host: str = "api.openai.com"
    path: str = "/v1/chat/completions"
    endpoint: str = "chat.completions"
    key_env_prefix: str = "OPENAI"
