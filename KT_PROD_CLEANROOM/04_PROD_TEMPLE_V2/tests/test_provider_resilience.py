from __future__ import annotations

import sys
from pathlib import Path


def _add_src_to_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src"
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from council.providers import provider_registry as registry_module  # noqa: E402
from council.providers.provider_registry import ProviderRegistry  # noqa: E402
from council.providers.provider_resilience import (  # noqa: E402
    LANE_LIVE_HASHED,
    LANE_REQUEST,
    ProviderResiliencePolicy,
    reset_resilience_state_for_tests,
    set_policy_override_for_tests,
)
from council.providers.provider_schemas import ProviderRequestSchema, make_ok_response  # noqa: E402


def _request(*, provider_id: str) -> ProviderRequestSchema:
    payload = {
        "schema_id": ProviderRequestSchema.SCHEMA_ID,
        "schema_version_hash": ProviderRequestSchema.SCHEMA_VERSION_HASH,
        "request_id": "0" * 64,
        "provider_id": provider_id,
        "model_id": "model-1",
        "input_hash": "1" * 64,
        "max_output_tokens": 8,
        "timeout_ms": 1000,
        "mode": "LIVE",
    }
    payload["request_id"] = ProviderRequestSchema.compute_request_id(payload)
    return ProviderRequestSchema.from_dict(payload)


class _FlakyProvider:
    provider_id = "flaky"

    def __init__(self) -> None:
        self.calls = 0

    def invoke(self, *, request: ProviderRequestSchema):
        self.calls += 1
        if self.calls == 1:
            raise TimeoutError("transient timeout")
        return make_ok_response(request=request, output_hash="a" * 64, output_bytes_len=4, latency_ms=1)


class _BrokenProvider:
    provider_id = "broken"

    def __init__(self) -> None:
        self.calls = 0

    def invoke(self, *, request: ProviderRequestSchema):
        self.calls += 1
        raise TimeoutError("persistent timeout")


class _StableProvider:
    def __init__(self, provider_id: str) -> None:
        self.provider_id = provider_id

    def invoke(self, *, request: ProviderRequestSchema):
        return make_ok_response(request=request, output_hash="b" * 64, output_bytes_len=4, latency_ms=1)


def test_provider_resilience_retries_with_backoff(monkeypatch) -> None:
    flaky = _FlakyProvider()
    delays: list[int] = []
    monkeypatch.setenv("KT_PROVIDERS_ENABLED", "1")
    monkeypatch.setattr(registry_module, "sleep_backoff", lambda delay_ms: delays.append(int(delay_ms)))
    reset_resilience_state_for_tests()
    set_policy_override_for_tests(
        provider_id="flaky",
        lane=LANE_REQUEST,
        policy=ProviderResiliencePolicy(2, 10, 2.0, 20, 2, 1000, 60_000, 10, 10),
    )
    try:
        reg = ProviderRegistry(providers={"flaky": flaky})
        response = reg.invoke(request=_request(provider_id="flaky")).to_dict()
        assert response["status"] == "OK"
        assert flaky.calls == 2
        assert delays == [10]
    finally:
        reset_resilience_state_for_tests()


def test_provider_resilience_opens_circuit_after_failure_threshold(monkeypatch) -> None:
    broken = _BrokenProvider()
    monkeypatch.setenv("KT_PROVIDERS_ENABLED", "1")
    reset_resilience_state_for_tests()
    set_policy_override_for_tests(
        provider_id="broken",
        lane=LANE_REQUEST,
        policy=ProviderResiliencePolicy(1, 10, 2.0, 20, 1, 5_000, 60_000, 10, 10),
    )
    try:
        reg = ProviderRegistry(providers={"broken": broken})
        first = reg.invoke(request=_request(provider_id="broken")).to_dict()
        second = reg.invoke(request=_request(provider_id="broken")).to_dict()
        assert first["status"] == "FAIL_CLOSED"
        assert first["error_code"] == "TIMEOUT"
        assert second["status"] == "FAIL_CLOSED"
        assert second["error_code"] == "CIRCUIT_OPEN"
        assert broken.calls == 1
    finally:
        reset_resilience_state_for_tests()


def test_provider_resilience_enforces_rate_and_quota_limits(monkeypatch) -> None:
    monkeypatch.setenv("KT_PROVIDERS_ENABLED", "1")
    reset_resilience_state_for_tests()
    set_policy_override_for_tests(
        provider_id="rate",
        lane=LANE_REQUEST,
        policy=ProviderResiliencePolicy(1, 10, 2.0, 20, 2, 1_000, 60_000, 1, 10),
    )
    set_policy_override_for_tests(
        provider_id="quota",
        lane=LANE_REQUEST,
        policy=ProviderResiliencePolicy(1, 10, 2.0, 20, 2, 1_000, 60_000, 10, 1),
    )
    try:
        rate_reg = ProviderRegistry(providers={"rate": _StableProvider("rate")})
        assert rate_reg.invoke(request=_request(provider_id="rate")).to_dict()["status"] == "OK"
        assert rate_reg.invoke(request=_request(provider_id="rate")).to_dict()["error_code"] == "RATE_LIMITED"

        quota_reg = ProviderRegistry(providers={"quota": _StableProvider("quota")})
        assert quota_reg.invoke(request=_request(provider_id="quota")).to_dict()["status"] == "OK"
        assert quota_reg.invoke(request=_request(provider_id="quota")).to_dict()["error_code"] == "QUOTA_EXCEEDED"
    finally:
        reset_resilience_state_for_tests()


def test_live_hashed_resilience_retries_with_backoff(monkeypatch) -> None:
    class FlakyLiveProvider:
        def __init__(self) -> None:
            self.calls = 0

        def invoke_hashed(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise TimeoutError("transient live timeout")

            class DummyReceipt:
                def to_dict(self):
                    return {
                        "trace_id": "wave2a-live-retry",
                        "provider_id": "openai",
                        "lane": "LIVE_HASHED",
                        "model": "gpt-4.1-mini",
                        "endpoint": "https://api.openai.com/v1/chat/completions",
                        "key_index": 0,
                        "key_count": 1,
                        "timing": {"t_start_ms": 1, "t_end_ms": 2, "latency_ms": 1},
                        "transport": {"host": "api.openai.com", "http_status": 200, "tls_cert_sha256": "a" * 64},
                        "provider_attestation": {"request_id": "req-1", "request_id_hash": "sha256:" + ("b" * 64)},
                        "usage": {"total_tokens": 1},
                        "payload": {"response_bytes_sha256": "sha256:" + ("c" * 64), "response_bytes_len": 2},
                        "verdict": {"pass": True, "fail_reason": None},
                        "receipt_id": "d" * 64,
                        "prev_receipt_hash": "GENESIS",
                        "receipt_hash": "d" * 64,
                    }

                @classmethod
                def from_dict(cls, payload):
                    obj = DummyReceipt()
                    obj.to_dict = lambda: payload
                    return obj

            return DummyReceipt()

    delays: list[int] = []
    monkeypatch.setenv("KT_PROVIDERS_ENABLED", "1")
    monkeypatch.setattr(registry_module, "sleep_backoff", lambda delay_ms: delays.append(int(delay_ms)))
    monkeypatch.setattr(
        "council.providers.live_provider_openai_hashed.LiveHashedOpenAIProvider",
        FlakyLiveProvider,
    )
    reset_resilience_state_for_tests()
    set_policy_override_for_tests(
        provider_id="openai",
        lane=LANE_LIVE_HASHED,
        policy=ProviderResiliencePolicy(2, 15, 2.0, 30, 2, 1000, 60_000, 10, 10),
    )
    try:
        reg = ProviderRegistry.build_default()
        receipt = reg.invoke_live_hashed(
            provider_id="openai",
            model="gpt-4.1-mini",
            prompt="Return exactly OK.",
            timeout_ms=1000,
            temperature=0.0,
            kt_node_id="wave2a-live-retry",
            trace_id="wave2a-live-retry",
        )
        assert receipt.to_dict()["receipt_hash"] == "d" * 64
        assert delays == [15]
    finally:
        reset_resilience_state_for_tests()


def test_live_hashed_fail_closed_receipt_records_failure_not_success(monkeypatch) -> None:
    class FailingVerdictProvider:
        def invoke_hashed(self, **kwargs):
            class DummyReceipt:
                def to_dict(self):
                    return {
                        "trace_id": "wave2a-live-fail-closed",
                        "provider_id": "openai",
                        "lane": "LIVE_HASHED",
                        "model": "gpt-4.1-mini",
                        "endpoint": "https://api.openai.com/v1/chat/completions",
                        "key_index": 0,
                        "key_count": 1,
                        "timing": {"t_start_ms": 1, "t_end_ms": 2, "latency_ms": 1},
                        "transport": {"host": "api.openai.com", "http_status": 401, "tls_cert_sha256": "a" * 64},
                        "provider_attestation": {"request_id": "req-1", "request_id_hash": "sha256:" + ("b" * 64)},
                        "usage": None,
                        "payload": {"response_bytes_sha256": "sha256:" + ("c" * 64), "response_bytes_len": 2},
                        "verdict": {"pass": False, "fail_reason": "http_status=401"},
                        "receipt_id": "d" * 64,
                        "prev_receipt_hash": "GENESIS",
                        "receipt_hash": "d" * 64,
                    }

            return DummyReceipt()

    failures: list[tuple[str, str]] = []
    successes: list[tuple[str, str]] = []

    monkeypatch.setenv("KT_PROVIDERS_ENABLED", "1")
    monkeypatch.setattr(
        "council.providers.live_provider_openai_hashed.LiveHashedOpenAIProvider",
        FailingVerdictProvider,
    )
    monkeypatch.setattr(registry_module, "record_failure", lambda *, provider_id, lane, now_ms=None: failures.append((provider_id, lane)))
    monkeypatch.setattr(registry_module, "record_success", lambda *, provider_id, lane: successes.append((provider_id, lane)))

    reset_resilience_state_for_tests()
    try:
        reg = ProviderRegistry.build_default()
        receipt = reg.invoke_live_hashed(
            provider_id="openai",
            model="gpt-4.1-mini",
            prompt="Return exactly OK.",
            timeout_ms=1000,
            temperature=0.0,
            kt_node_id="wave2a-live-fail-closed",
            trace_id="wave2a-live-fail-closed",
        )
        assert receipt.to_dict()["verdict"]["pass"] is False
        assert successes == []
        assert failures == [("openai", LANE_LIVE_HASHED)]
    finally:
        reset_resilience_state_for_tests()
