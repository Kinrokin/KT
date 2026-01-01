import os

import pytest

from council.council_router import execute_council_request, CouncilError


def test_missing_env_gates():
    # Ensure gates are enforced
    os.environ.pop("KT_PROVIDERS_ENABLED", None)
    os.environ.pop("KT_EXECUTION_LANE", None)
    payload = {"mode": "LIVE_HASHED", "request_type": "healthcheck", "provider_id": "openai", "model": "m", "prompt": "p"}
    with pytest.raises(CouncilError):
        execute_council_request(payload)


def test_provider_not_allowlisted():
    os.environ["KT_PROVIDERS_ENABLED"] = "1"
    os.environ["KT_EXECUTION_LANE"] = "LIVE_HASHED"
    payload = {"mode": "LIVE_HASHED", "request_type": "healthcheck", "provider_id": "not_allowed", "model": "m", "prompt": "p"}
    with pytest.raises(CouncilError):
        execute_council_request(payload)


def test_success_calls_registry_and_returns_receipt(monkeypatch):
    os.environ["KT_PROVIDERS_ENABLED"] = "1"
    os.environ["KT_EXECUTION_LANE"] = "LIVE_HASHED"

    class DummyReceipt:
        def to_dict(self):
            return {"model": "gpt-4.1-mini", "receipt_hash": "deadbeef"}

    class DummyRegistry:
        def invoke_live_hashed(self, **kwargs):
            return DummyReceipt()

    monkeypatch.setattr(
        "council.council_router.ProviderRegistry",
        type("P", (), {"build_default": staticmethod(lambda: DummyRegistry())}),
    )

    payload = {"mode": "LIVE_HASHED", "request_type": "healthcheck", "provider_id": "openai", "model": "gpt-4.1-mini", "prompt": "healthcheck"}
    out = execute_council_request(payload)
    assert out["status"] == "OK"
    assert out["receipt_hash"] == "deadbeef"
