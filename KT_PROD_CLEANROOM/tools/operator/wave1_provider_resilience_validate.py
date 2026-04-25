from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


def _request(*, provider_id: str, mode: str = "LIVE") -> Any:
    from council.providers.provider_schemas import ProviderRequestSchema

    payload = {
        "schema_id": ProviderRequestSchema.SCHEMA_ID,
        "schema_version_hash": ProviderRequestSchema.SCHEMA_VERSION_HASH,
        "request_id": "0" * 64,
        "provider_id": provider_id,
        "model_id": "model-1",
        "input_hash": "1" * 64,
        "max_output_tokens": 16,
        "timeout_ms": 1000,
        "mode": mode,
    }
    payload["request_id"] = ProviderRequestSchema.compute_request_id(payload)
    return ProviderRequestSchema.from_dict(payload)


def build_wave1_provider_resilience_receipt() -> Dict[str, Any]:
    from council.providers import provider_registry as registry_module
    from council.providers.provider_registry import ProviderRegistry
    from council.providers.provider_resilience import (
        LANE_REQUEST,
        ProviderResiliencePolicy,
        reset_resilience_state_for_tests,
        set_policy_override_for_tests,
    )
    from council.providers.provider_schemas import make_ok_response

    class FlakyProvider:
        provider_id = "flaky"

        def __init__(self) -> None:
            self.calls = 0

        def invoke(self, *, request: Any) -> Any:
            self.calls += 1
            if self.calls == 1:
                raise TimeoutError("transient timeout")
            return make_ok_response(request=request, output_hash="a" * 64, output_bytes_len=12, latency_ms=3)

    class BrokenProvider:
        provider_id = "broken"

        def __init__(self) -> None:
            self.calls = 0

        def invoke(self, *, request: Any) -> Any:
            self.calls += 1
            raise TimeoutError("persistent timeout")

    class StableProvider:
        def __init__(self, provider_id: str) -> None:
            self.provider_id = provider_id
            self.calls = 0

        def invoke(self, *, request: Any) -> Any:
            self.calls += 1
            return make_ok_response(request=request, output_hash="b" * 64, output_bytes_len=8, latency_ms=2)

    delays: list[int] = []
    original_sleep_backoff = registry_module.sleep_backoff
    original_enabled = os.environ.get("KT_PROVIDERS_ENABLED")
    os.environ["KT_PROVIDERS_ENABLED"] = "1"

    reset_resilience_state_for_tests()
    registry_module.sleep_backoff = lambda delay_ms: delays.append(int(delay_ms))  # type: ignore[assignment]
    try:
        flaky = FlakyProvider()
        broken = BrokenProvider()
        rate_limited = StableProvider("rate")
        quota_limited = StableProvider("quota")

        set_policy_override_for_tests(
            provider_id="flaky",
            lane=LANE_REQUEST,
            policy=ProviderResiliencePolicy(2, 10, 2.0, 20, 2, 500, 60_000, 10, 10),
        )
        set_policy_override_for_tests(
            provider_id="broken",
            lane=LANE_REQUEST,
            policy=ProviderResiliencePolicy(1, 10, 2.0, 20, 1, 5_000, 60_000, 10, 10),
        )
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

        flaky_registry = ProviderRegistry(providers={"flaky": flaky})
        flaky_response = flaky_registry.invoke(request=_request(provider_id="flaky")).to_dict()

        broken_registry = ProviderRegistry(providers={"broken": broken})
        broken_first = broken_registry.invoke(request=_request(provider_id="broken")).to_dict()
        broken_second = broken_registry.invoke(request=_request(provider_id="broken")).to_dict()

        rate_registry = ProviderRegistry(providers={"rate": rate_limited})
        rate_first = rate_registry.invoke(request=_request(provider_id="rate")).to_dict()
        rate_second = rate_registry.invoke(request=_request(provider_id="rate")).to_dict()

        quota_registry = ProviderRegistry(providers={"quota": quota_limited})
        quota_first = quota_registry.invoke(request=_request(provider_id="quota")).to_dict()
        quota_second = quota_registry.invoke(request=_request(provider_id="quota")).to_dict()
    finally:
        registry_module.sleep_backoff = original_sleep_backoff  # type: ignore[assignment]
        reset_resilience_state_for_tests()
        if original_enabled is None:
            os.environ.pop("KT_PROVIDERS_ENABLED", None)
        else:
            os.environ["KT_PROVIDERS_ENABLED"] = original_enabled

    scenarios = [
        {
            "scenario_id": "retry_and_backoff_for_transient_timeout",
            "status": "PASS" if flaky_response["status"] == "OK" and flaky.calls == 2 and delays else "FAIL",
            "attempts": flaky.calls,
            "response_status": flaky_response["status"],
            "observed_backoff_ms": list(delays),
        },
        {
            "scenario_id": "circuit_breaker_opens_after_threshold",
            "status": "PASS"
            if broken_first["error_code"] == "TIMEOUT" and broken_second["error_code"] == "CIRCUIT_OPEN" and broken.calls == 1
            else "FAIL",
            "first_error_code": broken_first["error_code"],
            "second_error_code": broken_second["error_code"],
            "provider_calls": broken.calls,
        },
        {
            "scenario_id": "rate_limit_blocks_second_call_inside_window",
            "status": "PASS" if rate_first["status"] == "OK" and rate_second["error_code"] == "RATE_LIMITED" else "FAIL",
            "first_status": rate_first["status"],
            "second_error_code": rate_second["error_code"],
        },
        {
            "scenario_id": "process_quota_blocks_calls_above_cap",
            "status": "PASS" if quota_first["status"] == "OK" and quota_second["error_code"] == "QUOTA_EXCEEDED" else "FAIL",
            "first_status": quota_first["status"],
            "second_error_code": quota_second["error_code"],
        },
    ]

    failures = [row["scenario_id"] for row in scenarios if row["status"] != "PASS"]
    return {
        "schema_id": "kt.wave1.provider_resilience_base.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not failures else "FAIL",
        "scope_boundary": "Wave 1 provider resilience proves bounded timeout/retry/backoff, circuit-breaker, rate-limit, and quota primitives only.",
        "scenarios": scenarios,
        "failures": failures,
        "stronger_claim_not_made": [
            "adapter_activation_occurred",
            "semantic_router_opened",
            "broad_live_provider_fleet_activated",
            "externality_widened",
        ],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the Wave 1 provider resilience base without opening adapter or router scope.")
    parser.add_argument("--output", default="KT_PROD_CLEANROOM/reports/kt_wave1_provider_resilience_base.json")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    report = build_wave1_provider_resilience_receipt()
    out_path = Path(str(args.output)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()
    write_json_stable(out_path, report)
    print(json.dumps({"status": report["status"], "failures": report["failures"]}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
