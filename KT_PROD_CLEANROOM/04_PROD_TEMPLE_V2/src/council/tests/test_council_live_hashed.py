import os
from pathlib import Path

import pytest

from council.council_router import CouncilError, execute_council_request


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
    payload = {
        "mode": "LIVE_HASHED",
        "request_type": "healthcheck",
        "provider_id": "not_allowed",
        "model": "m",
        "prompt": "p",
        "export_root": ".pytest_wave2a/not_allowlisted",
    }
    out = execute_council_request(payload)
    assert out["status"] == "FAIL_CLOSED"
    assert out["provider_id"] == "not_allowed"
    assert out["failure_artifact_ref"]


def test_success_calls_registry_and_returns_receipt(monkeypatch, tmp_path: Path):
    os.environ["KT_PROVIDERS_ENABLED"] = "1"
    os.environ["KT_EXECUTION_LANE"] = "LIVE_HASHED"

    class DummyReceipt:
        def to_dict(self):
            return {
                "trace_id": "wave2a-success",
                "model": "gpt-4.1-mini",
                "receipt_hash": "deadbeef",
                "verdict": {"pass": True, "fail_reason": None},
            }

    class DummyRegistry:
        def invoke_live_hashed(self, **kwargs):
            return DummyReceipt()

    monkeypatch.setattr(
        "council.council_router.ProviderRegistry",
        type("P", (), {"build_default": staticmethod(lambda: DummyRegistry())}),
    )

    payload = {
        "mode": "LIVE_HASHED",
        "request_type": "healthcheck",
        "provider_id": "openai",
        "model": "gpt-4.1-mini",
        "prompt": "healthcheck",
        "export_root": str(tmp_path),
    }
    out = execute_council_request(payload)
    assert out["status"] == "OK"
    assert out["receipt_hash"] == "deadbeef"
    assert out["adapter_id"] == "council.openai.live_hashed.v1"
    assert Path(out["receipt_ref"]).exists()


def test_provider_verdict_fail_closed_writes_failure_artifact(monkeypatch, tmp_path: Path):
    os.environ["KT_PROVIDERS_ENABLED"] = "1"
    os.environ["KT_EXECUTION_LANE"] = "LIVE_HASHED"

    class DummyReceipt:
        def to_dict(self):
            return {
                "trace_id": "wave2a-failure",
                "model": "gpt-4.1-mini",
                "receipt_hash": "badc0de0",
                "verdict": {"pass": False, "fail_reason": "http_status=429"},
            }

    class DummyRegistry:
        def invoke_live_hashed(self, **kwargs):
            return DummyReceipt()

    monkeypatch.setattr(
        "council.council_router.ProviderRegistry",
        type("P", (), {"build_default": staticmethod(lambda: DummyRegistry())}),
    )

    payload = {
        "mode": "LIVE_HASHED",
        "request_type": "healthcheck",
        "provider_id": "openai",
        "model": "gpt-4.1-mini",
        "prompt": "healthcheck",
        "export_root": str(tmp_path),
    }
    out = execute_council_request(payload)
    assert out["status"] == "FAIL_CLOSED"
    assert out["receipt_hash"] == "badc0de0"
    assert out["failure_artifact_ref"]
    assert Path(out["receipt_ref"]).exists()
    assert Path(out["failure_artifact_ref"]).exists()
