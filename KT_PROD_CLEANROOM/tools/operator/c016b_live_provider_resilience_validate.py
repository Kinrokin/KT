from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.verification.attestation_hmac import sign_hmac


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
REPORT_REL = f"{REPORT_ROOT_REL}/post_wave5_c016b_resilience_pack.json"
PRECONDITION_REL = f"{REPORT_ROOT_REL}/post_wave5_c016a_success_matrix.json"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/post_wave5_c016b_live_provider_resilience"
TELEMETRY_REL = f"{REPORT_ROOT_REL}/post_wave5_c016b_runtime_telemetry.jsonl"


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_obj(obj: Any) -> str:
    return _sha256_text(_canonical_json(obj))


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _env_present(name: str) -> bool:
    return bool(str(os.environ.get(name, "")).strip())


def _signoffs_for_payload_hash(payload_hash: str) -> list[dict[str, str]]:
    signoffs: list[dict[str, str]] = []
    for key_id in ("SIGNER_A", "SIGNER_B"):
        env_name = f"KT_HMAC_KEY_{key_id}"
        key_value = str(os.environ.get(env_name, "")).strip()
        if not key_value:
            raise RuntimeError(f"missing {env_name} for C016B receipt signoff (fail-closed)")
        signature, fingerprint = sign_hmac(key_bytes=key_value.encode("utf-8"), key_id=key_id, payload_hash=payload_hash)
        signoffs.append(
            {
                "attestation_mode": "HMAC",
                "hmac_key_fingerprint": fingerprint,
                "hmac_signature": signature,
                "key_id": key_id,
                "payload_hash": payload_hash,
            }
        )
    return signoffs


def _load_c016a_precondition(root: Path) -> Dict[str, Any]:
    path = (root / PRECONDITION_REL).resolve()
    if not path.exists():
        return {
            "path_ref": PRECONDITION_REL,
            "status": "FAIL",
            "successful_provider_count": 0,
            "successful_provider_ids": [],
        }
    payload = _load_json(path)
    payload["path_ref"] = path.relative_to(root).as_posix()
    return payload


def _request_spec(provider_id: str) -> Dict[str, str]:
    if provider_id == "openai":
        return {
            "provider_id": "openai",
            "request_type": "healthcheck",
            "model": "gpt-4.1-mini",
            "prompt": "Reply with exactly OK.",
        }
    if provider_id == "openrouter":
        return {
            "provider_id": "openrouter",
            "request_type": "analysis",
            "model": "openai/gpt-4.1-mini",
            "prompt": "Reply with exactly OK.",
        }
    raise RuntimeError(f"unknown provider_id for C016B scenario: {provider_id!r}")


def _request_payload(*, provider_id: str, trace_id: str, export_root: Path) -> Dict[str, Any]:
    spec = _request_spec(provider_id)
    return {
        "mode": "LIVE_HASHED",
        "request_type": spec["request_type"],
        "provider_id": spec["provider_id"],
        "model": spec["model"],
        "prompt": spec["prompt"],
        "trace_id": trace_id,
        "export_root": str(export_root),
    }


def _receipt_summary(root: Path, output: Dict[str, Any]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "status": str(output.get("status", "")).strip() or "ERROR",
        "adapter_id": str(output.get("adapter_id", "")).strip(),
        "provider_id": str(output.get("provider_id", "")).strip(),
        "error": str(output.get("error", "")).strip(),
        "receipt_exists": False,
        "receipt_ref": str(output.get("receipt_ref", "")).strip(),
        "failure_artifact_exists": False,
        "failure_artifact_ref": str(output.get("failure_artifact_ref", "")).strip(),
    }

    receipt_ref = summary["receipt_ref"]
    if receipt_ref:
        receipt_path = Path(receipt_ref)
        summary["receipt_exists"] = receipt_path.exists()
        if receipt_path.exists():
            receipt = _load_json(receipt_path)
            summary["receipt_hash"] = str(receipt.get("receipt_hash", "")).strip()
            summary["receipt_rel"] = receipt_path.relative_to(root).as_posix()
            summary["http_status"] = int(receipt.get("transport", {}).get("http_status", 0))
            summary["latency_ms"] = int(receipt.get("timing", {}).get("latency_ms", 0))
            summary["verdict_pass"] = bool(receipt.get("verdict", {}).get("pass"))
            summary["verdict_fail_reason"] = str(receipt.get("verdict", {}).get("fail_reason", "")).strip()

    failure_ref = summary["failure_artifact_ref"]
    if failure_ref:
        failure_path = Path(failure_ref)
        summary["failure_artifact_exists"] = failure_path.exists()
        if failure_path.exists():
            failure = _load_json(failure_path)
            summary["failure_rel"] = failure_path.relative_to(root).as_posix()
            summary["failure_id"] = str(failure.get("failure_id", "")).strip()
            summary["failure_error_class"] = str(failure.get("error_class", "")).strip()
            summary["failure_bounded_reason"] = str(failure.get("bounded_reason", "")).strip()
    return summary


def _compute_receipt_hash(payload: Dict[str, Any]) -> str:
    material = {k: v for k, v in payload.items() if k not in {"receipt_id", "receipt_hash"}}
    return _sha256_text(_canonical_json(material))


def _ok_receipt(*, provider_id: str, model: str, trace_id: str, latency_ms: int = 1) -> Any:
    from council.providers.provider_schemas import ProviderCallReceipt

    payload: Dict[str, Any] = {
        "schema_id": ProviderCallReceipt.SCHEMA_ID,
        "schema_version_hash": ProviderCallReceipt.SCHEMA_VERSION_HASH,
        "trace_id": trace_id,
        "provider_id": provider_id,
        "lane": "LIVE_HASHED",
        "model": model,
        "endpoint": "chat.completions",
        "key_index": 0,
        "key_count": 1,
        "timing": {"t_start_ms": 1, "t_end_ms": 1 + int(latency_ms), "latency_ms": int(latency_ms)},
        "transport": {"host": f"{provider_id}.example.invalid", "http_status": 200, "tls_cert_sha256": "a" * 64},
        "provider_attestation": {"request_id": f"req-{provider_id}-{trace_id}", "request_id_hash": "sha256:" + ("b" * 64)},
        "usage": {"total_tokens": 1},
        "payload": {"response_bytes_sha256": "sha256:" + ("c" * 64), "response_bytes_len": 2},
        "verdict": {"pass": True, "fail_reason": None},
    }
    receipt_hash = _compute_receipt_hash(payload)
    payload["receipt_id"] = receipt_hash
    payload["prev_receipt_hash"] = "GENESIS"
    payload["receipt_hash"] = receipt_hash
    return ProviderCallReceipt.from_dict(payload)


def _fail_receipt(*, provider_id: str, model: str, trace_id: str, http_status: int, fail_reason: str) -> Any:
    from council.providers.provider_schemas import ProviderCallReceipt

    payload: Dict[str, Any] = {
        "schema_id": ProviderCallReceipt.SCHEMA_ID,
        "schema_version_hash": ProviderCallReceipt.SCHEMA_VERSION_HASH,
        "trace_id": trace_id,
        "provider_id": provider_id,
        "lane": "LIVE_HASHED",
        "model": model,
        "endpoint": "chat.completions",
        "key_index": 0,
        "key_count": 1,
        "timing": {"t_start_ms": 1, "t_end_ms": 2, "latency_ms": 1},
        "transport": {"host": f"{provider_id}.example.invalid", "http_status": int(http_status), "tls_cert_sha256": "d" * 64},
        "provider_attestation": {"request_id": f"req-{provider_id}-{trace_id}", "request_id_hash": "sha256:" + ("e" * 64)},
        "usage": None,
        "payload": {"response_bytes_sha256": "sha256:" + ("f" * 64), "response_bytes_len": 2},
        "verdict": {"pass": False, "fail_reason": fail_reason},
    }
    receipt_hash = _compute_receipt_hash(payload)
    payload["receipt_id"] = receipt_hash
    payload["prev_receipt_hash"] = "GENESIS"
    payload["receipt_hash"] = receipt_hash
    return ProviderCallReceipt.from_dict(payload)


@contextmanager
def _patched_attr(target: Any, name: str, value: Any):
    original = getattr(target, name)
    setattr(target, name, value)
    try:
        yield
    finally:
        setattr(target, name, original)


@contextmanager
def _live_lane_env(telemetry_path: Path):
    original_env = {
        name: os.environ.get(name)
        for name in ("KT_PROVIDERS_ENABLED", "KT_EXECUTION_LANE", "KT_NODE_ID", "KT_RUNTIME_TELEMETRY_PATH")
    }
    os.environ["KT_PROVIDERS_ENABLED"] = "1"
    os.environ["KT_EXECUTION_LANE"] = "LIVE_HASHED"
    os.environ["KT_NODE_ID"] = "post-wave5-c016b"
    os.environ["KT_RUNTIME_TELEMETRY_PATH"] = str(telemetry_path)
    try:
        yield
    finally:
        for name, value in original_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _normalized(row: Dict[str, Any]) -> Dict[str, Any]:
    keys = (
        "scenario_id",
        "status",
        "first_status",
        "second_status",
        "first_error",
        "second_error",
        "first_failure_error_class",
        "second_failure_error_class",
        "provider_invocations",
        "observed_backoff_ms",
        "verdict_fail_reason",
        "terminal_status",
        "terminal_error",
        "terminal_failure_error_class",
        "terminal_http_status",
        "terminal_verdict_pass",
        "receipt_preserved",
        "failure_artifact_preserved",
    )
    return {key: row.get(key) for key in keys if key in row}


def _run_fault_matrix(root: Path) -> Dict[str, Any]:
    from council import council_router as council_router_module
    from council.providers import live_provider_openai_hashed as openai_module
    from council.providers import live_provider_openrouter_hashed as openrouter_module
    from council.providers import provider_registry as registry_module
    from council.providers.provider_resilience import (
        LANE_LIVE_HASHED,
        ProviderResiliencePolicy,
        reset_resilience_state_for_tests,
        set_policy_override_for_tests,
    )

    execute_request = council_router_module.execute_council_request
    export_root = (root / EXPORT_ROOT_REL).resolve()
    telemetry_path = (root / TELEMETRY_REL).resolve()
    if export_root.exists():
        shutil.rmtree(export_root, ignore_errors=True)
    export_root.mkdir(parents=True, exist_ok=True)
    if telemetry_path.exists():
        telemetry_path.unlink()

    def scenario_transient_timeout(run_id: str) -> Dict[str, Any]:
        scenario_id = "transient_timeout_retry_backoff_to_success"
        scenario_root = export_root / run_id / scenario_id

        class FlakyOpenAIProvider:
            calls = 0

            def invoke_hashed(self, **kwargs):
                FlakyOpenAIProvider.calls += 1
                if FlakyOpenAIProvider.calls == 1:
                    raise TimeoutError("transient live timeout")
                return _ok_receipt(provider_id="openai", model=str(kwargs["model"]), trace_id=str(kwargs["trace_id"]), latency_ms=4)

        delays: list[int] = []
        reset_resilience_state_for_tests()
        set_policy_override_for_tests(
            provider_id="openai",
            lane=LANE_LIVE_HASHED,
            policy=ProviderResiliencePolicy(2, 15, 2.0, 30, 2, 1000, 60_000, 10, 10),
        )
        try:
            with _patched_attr(registry_module, "sleep_backoff", lambda delay_ms: delays.append(int(delay_ms))):
                with _patched_attr(openai_module, "LiveHashedOpenAIProvider", FlakyOpenAIProvider):
                    out = execute_request(
                        _request_payload(
                            provider_id="openai",
                            trace_id=f"{run_id}-{scenario_id}",
                            export_root=scenario_root,
                        )
                    )
            terminal = _receipt_summary(root, out)
            passed = (
                out.get("status") == "OK"
                and FlakyOpenAIProvider.calls == 2
                and delays == [15]
                and terminal.get("http_status") == 200
                and terminal.get("verdict_pass") is True
            )
            return {
                "scenario_id": scenario_id,
                "status": "PASS" if passed else "FAIL",
                "provider_id": "openai",
                "provider_invocations": FlakyOpenAIProvider.calls,
                "observed_backoff_ms": list(delays),
                "terminal_status": terminal.get("status"),
                "terminal_error": terminal.get("error"),
                "terminal_http_status": terminal.get("http_status"),
                "terminal_verdict_pass": terminal.get("verdict_pass"),
                "receipt_rel": terminal.get("receipt_rel", ""),
            }
        finally:
            reset_resilience_state_for_tests()

    def scenario_circuit_open(run_id: str) -> Dict[str, Any]:
        scenario_id = "persistent_timeout_opens_circuit"
        first_root = export_root / run_id / scenario_id / "first"
        second_root = export_root / run_id / scenario_id / "second"

        class BrokenOpenAIProvider:
            calls = 0

            def invoke_hashed(self, **kwargs):
                BrokenOpenAIProvider.calls += 1
                raise TimeoutError("persistent live timeout")

        reset_resilience_state_for_tests()
        set_policy_override_for_tests(
            provider_id="openai",
            lane=LANE_LIVE_HASHED,
            policy=ProviderResiliencePolicy(1, 10, 2.0, 20, 1, 5_000, 60_000, 10, 10),
        )
        try:
            with _patched_attr(openai_module, "LiveHashedOpenAIProvider", BrokenOpenAIProvider):
                first = execute_request(
                    _request_payload(provider_id="openai", trace_id=f"{run_id}-{scenario_id}-first", export_root=first_root)
                )
                second = execute_request(
                    _request_payload(provider_id="openai", trace_id=f"{run_id}-{scenario_id}-second", export_root=second_root)
                )
            first_summary = _receipt_summary(root, first)
            second_summary = _receipt_summary(root, second)
            passed = (
                first.get("status") == "FAIL_CLOSED"
                and "TIMEOUT" in str(first.get("error", ""))
                and second.get("status") == "FAIL_CLOSED"
                and "CIRCUIT_OPEN" in str(second.get("error", ""))
                and BrokenOpenAIProvider.calls == 1
                and first_summary.get("failure_artifact_exists") is True
                and second_summary.get("failure_artifact_exists") is True
            )
            return {
                "scenario_id": scenario_id,
                "status": "PASS" if passed else "FAIL",
                "provider_id": "openai",
                "provider_invocations": BrokenOpenAIProvider.calls,
                "first_status": first.get("status"),
                "first_error": first.get("error"),
                "first_failure_error_class": first_summary.get("failure_error_class", ""),
                "second_status": second.get("status"),
                "second_error": second.get("error"),
                "second_failure_error_class": second_summary.get("failure_error_class", ""),
            }
        finally:
            reset_resilience_state_for_tests()

    def scenario_rate_limit(run_id: str) -> Dict[str, Any]:
        scenario_id = "rate_limit_preflight_blocks_second_call"
        first_root = export_root / run_id / scenario_id / "first"
        second_root = export_root / run_id / scenario_id / "second"

        class StableOpenRouterProvider:
            calls = 0

            def invoke_hashed(self, **kwargs):
                StableOpenRouterProvider.calls += 1
                return _ok_receipt(provider_id="openrouter", model=str(kwargs["model"]), trace_id=str(kwargs["trace_id"]), latency_ms=3)

        reset_resilience_state_for_tests()
        set_policy_override_for_tests(
            provider_id="openrouter",
            lane=LANE_LIVE_HASHED,
            policy=ProviderResiliencePolicy(1, 10, 2.0, 20, 2, 1000, 60_000, 1, 10),
        )
        try:
            with _patched_attr(openrouter_module, "LiveHashedOpenRouterProvider", StableOpenRouterProvider):
                first = execute_request(
                    _request_payload(provider_id="openrouter", trace_id=f"{run_id}-{scenario_id}-first", export_root=first_root)
                )
                second = execute_request(
                    _request_payload(provider_id="openrouter", trace_id=f"{run_id}-{scenario_id}-second", export_root=second_root)
                )
            second_summary = _receipt_summary(root, second)
            passed = (
                first.get("status") == "OK"
                and second.get("status") == "FAIL_CLOSED"
                and "RATE_LIMITED" in str(second.get("error", ""))
                and StableOpenRouterProvider.calls == 1
                and second_summary.get("failure_artifact_exists") is True
            )
            return {
                "scenario_id": scenario_id,
                "status": "PASS" if passed else "FAIL",
                "provider_id": "openrouter",
                "provider_invocations": StableOpenRouterProvider.calls,
                "first_status": first.get("status"),
                "second_status": second.get("status"),
                "second_error": second.get("error"),
                "second_failure_error_class": second_summary.get("failure_error_class", ""),
            }
        finally:
            reset_resilience_state_for_tests()

    def scenario_quota(run_id: str) -> Dict[str, Any]:
        scenario_id = "quota_preflight_blocks_second_call"
        first_root = export_root / run_id / scenario_id / "first"
        second_root = export_root / run_id / scenario_id / "second"

        class StableQuotaProvider:
            calls = 0

            def invoke_hashed(self, **kwargs):
                StableQuotaProvider.calls += 1
                return _ok_receipt(provider_id="openrouter", model=str(kwargs["model"]), trace_id=str(kwargs["trace_id"]), latency_ms=2)

        reset_resilience_state_for_tests()
        set_policy_override_for_tests(
            provider_id="openrouter",
            lane=LANE_LIVE_HASHED,
            policy=ProviderResiliencePolicy(1, 10, 2.0, 20, 2, 1000, 60_000, 10, 1),
        )
        try:
            with _patched_attr(openrouter_module, "LiveHashedOpenRouterProvider", StableQuotaProvider):
                first = execute_request(
                    _request_payload(provider_id="openrouter", trace_id=f"{run_id}-{scenario_id}-first", export_root=first_root)
                )
                second = execute_request(
                    _request_payload(provider_id="openrouter", trace_id=f"{run_id}-{scenario_id}-second", export_root=second_root)
                )
            second_summary = _receipt_summary(root, second)
            passed = (
                first.get("status") == "OK"
                and second.get("status") == "FAIL_CLOSED"
                and "QUOTA_EXCEEDED" in str(second.get("error", ""))
                and StableQuotaProvider.calls == 1
                and second_summary.get("failure_artifact_exists") is True
            )
            return {
                "scenario_id": scenario_id,
                "status": "PASS" if passed else "FAIL",
                "provider_id": "openrouter",
                "provider_invocations": StableQuotaProvider.calls,
                "first_status": first.get("status"),
                "second_status": second.get("status"),
                "second_error": second.get("error"),
                "second_failure_error_class": second_summary.get("failure_error_class", ""),
            }
        finally:
            reset_resilience_state_for_tests()

    def scenario_malformed_response(run_id: str) -> Dict[str, Any]:
        scenario_id = "malformed_response_fail_closes"
        scenario_root = export_root / run_id / scenario_id

        class MalformedOpenAIProvider:
            calls = 0

            def invoke_hashed(self, **kwargs):
                MalformedOpenAIProvider.calls += 1
                raise RuntimeError("Provider response was not valid JSON (fail-closed)")

        reset_resilience_state_for_tests()
        set_policy_override_for_tests(
            provider_id="openai",
            lane=LANE_LIVE_HASHED,
            policy=ProviderResiliencePolicy(1, 10, 2.0, 20, 2, 1000, 60_000, 10, 10),
        )
        try:
            with _patched_attr(openai_module, "LiveHashedOpenAIProvider", MalformedOpenAIProvider):
                out = execute_request(
                    _request_payload(provider_id="openai", trace_id=f"{run_id}-{scenario_id}", export_root=scenario_root)
                )
            terminal = _receipt_summary(root, out)
            passed = (
                out.get("status") == "FAIL_CLOSED"
                and "PROVIDER_ERROR" in str(out.get("error", ""))
                and MalformedOpenAIProvider.calls == 1
                and terminal.get("failure_artifact_exists") is True
            )
            return {
                "scenario_id": scenario_id,
                "status": "PASS" if passed else "FAIL",
                "provider_id": "openai",
                "provider_invocations": MalformedOpenAIProvider.calls,
                "terminal_status": out.get("status"),
                "terminal_error": out.get("error"),
                "terminal_failure_error_class": terminal.get("failure_error_class", ""),
            }
        finally:
            reset_resilience_state_for_tests()

    def scenario_network_failure(run_id: str) -> Dict[str, Any]:
        scenario_id = "network_failure_retries_then_fail_closes"
        scenario_root = export_root / run_id / scenario_id

        class BrokenNetworkOpenRouterProvider:
            calls = 0

            def invoke_hashed(self, **kwargs):
                BrokenNetworkOpenRouterProvider.calls += 1
                raise OSError("simulated socket reset")

        delays: list[int] = []
        reset_resilience_state_for_tests()
        set_policy_override_for_tests(
            provider_id="openrouter",
            lane=LANE_LIVE_HASHED,
            policy=ProviderResiliencePolicy(2, 11, 2.0, 20, 2, 1000, 60_000, 10, 10),
        )
        try:
            with _patched_attr(registry_module, "sleep_backoff", lambda delay_ms: delays.append(int(delay_ms))):
                with _patched_attr(openrouter_module, "LiveHashedOpenRouterProvider", BrokenNetworkOpenRouterProvider):
                    out = execute_request(
                        _request_payload(provider_id="openrouter", trace_id=f"{run_id}-{scenario_id}", export_root=scenario_root)
                    )
            terminal = _receipt_summary(root, out)
            passed = (
                out.get("status") == "FAIL_CLOSED"
                and "NETWORK_ERROR" in str(out.get("error", ""))
                and BrokenNetworkOpenRouterProvider.calls == 2
                and delays == [11]
                and terminal.get("failure_artifact_exists") is True
            )
            return {
                "scenario_id": scenario_id,
                "status": "PASS" if passed else "FAIL",
                "provider_id": "openrouter",
                "provider_invocations": BrokenNetworkOpenRouterProvider.calls,
                "observed_backoff_ms": list(delays),
                "terminal_status": out.get("status"),
                "terminal_error": out.get("error"),
                "terminal_failure_error_class": terminal.get("failure_error_class", ""),
            }
        finally:
            reset_resilience_state_for_tests()

    def scenario_verdict_fail_closed(run_id: str) -> Dict[str, Any]:
        scenario_id = "verdict_fail_closed_preserves_receipt_and_failure_artifact"
        scenario_root = export_root / run_id / scenario_id

        class VerdictFailOpenAIProvider:
            calls = 0

            def invoke_hashed(self, **kwargs):
                VerdictFailOpenAIProvider.calls += 1
                return _fail_receipt(
                    provider_id="openai",
                    model=str(kwargs["model"]),
                    trace_id=str(kwargs["trace_id"]),
                    http_status=429,
                    fail_reason="http_status=429",
                )

        reset_resilience_state_for_tests()
        set_policy_override_for_tests(
            provider_id="openai",
            lane=LANE_LIVE_HASHED,
            policy=ProviderResiliencePolicy(1, 10, 2.0, 20, 2, 1000, 60_000, 10, 10),
        )
        try:
            with _patched_attr(openai_module, "LiveHashedOpenAIProvider", VerdictFailOpenAIProvider):
                out = execute_request(
                    _request_payload(provider_id="openai", trace_id=f"{run_id}-{scenario_id}", export_root=scenario_root)
                )
            terminal = _receipt_summary(root, out)
            passed = (
                out.get("status") == "FAIL_CLOSED"
                and VerdictFailOpenAIProvider.calls == 1
                and terminal.get("receipt_exists") is True
                and terminal.get("failure_artifact_exists") is True
                and terminal.get("verdict_fail_reason") == "http_status=429"
            )
            return {
                "scenario_id": scenario_id,
                "status": "PASS" if passed else "FAIL",
                "provider_id": "openai",
                "provider_invocations": VerdictFailOpenAIProvider.calls,
                "terminal_status": out.get("status"),
                "terminal_error": out.get("error"),
                "terminal_http_status": terminal.get("http_status"),
                "terminal_verdict_pass": terminal.get("verdict_pass"),
                "verdict_fail_reason": terminal.get("verdict_fail_reason"),
                "receipt_preserved": terminal.get("receipt_exists"),
                "failure_artifact_preserved": terminal.get("failure_artifact_exists"),
            }
        finally:
            reset_resilience_state_for_tests()

    scenario_functions = (
        scenario_transient_timeout,
        scenario_circuit_open,
        scenario_rate_limit,
        scenario_quota,
        scenario_malformed_response,
        scenario_network_failure,
        scenario_verdict_fail_closed,
    )

    def run_once(run_id: str) -> Dict[str, Any]:
        rows = [fn(run_id) for fn in scenario_functions]
        return {"run_id": run_id, "scenarios": rows}

    with _live_lane_env(telemetry_path):
        run_a = run_once("run_a")
        run_b = run_once("run_b")

    run_a_norm = [_normalized(row) for row in run_a["scenarios"]]
    run_b_norm = [_normalized(row) for row in run_b["scenarios"]]
    return {
        "export_root_ref": export_root.relative_to(root).as_posix(),
        "runtime_telemetry_ref": telemetry_path.relative_to(root).as_posix(),
        "runs": [run_a, run_b],
        "repeatability_status": "PASS" if run_a_norm == run_b_norm else "FAIL",
        "repeatability_reference": run_a_norm,
    }


def build_c016b_live_provider_resilience_receipt(
    *,
    root: Path,
    load_c016a: Optional[Callable[[Path], Dict[str, Any]]] = None,
    run_fault_matrix: Optional[Callable[[Path], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    precondition = (load_c016a or _load_c016a_precondition)(root)
    precondition_pass = str(precondition.get("status", "")).strip() == "PASS"

    matrix = (
        (run_fault_matrix or _run_fault_matrix)(root)
        if precondition_pass
        else {
            "export_root_ref": EXPORT_ROOT_REL,
            "runtime_telemetry_ref": TELEMETRY_REL,
            "runs": [],
            "repeatability_status": "FAIL",
            "repeatability_reference": [],
        }
    )

    runs = list(matrix.get("runs", []))
    scenario_rows = [row for run in runs for row in list(run.get("scenarios", []))]
    scenario_failures = [row.get("scenario_id") for row in scenario_rows if row.get("status") != "PASS"]
    repeatability_pass = str(matrix.get("repeatability_status", "")).strip() == "PASS"

    boundary_holds: list[str] = []
    if not precondition_pass:
        boundary_holds.append("C016A_SUCCESS_PRECONDITION_NOT_SATISFIED")
    if scenario_failures:
        boundary_holds.append("FAULT_MATRIX_HAS_FAILING_SCENARIOS")
    if precondition_pass and not repeatability_pass:
        boundary_holds.append("FAULT_MATRIX_REPEATABILITY_NOT_PROVEN")

    exact_remaining_forbidden_claims = [
        "Do not claim C016B closed unless all declared fault scenarios pass in repeatable LIVE_HASHED runs.",
        "Do not raise C006 or externality class from same-host fault injection evidence.",
        "Do not claim fleet-wide resilience beyond the canonical openai/openrouter LIVE_HASHED adapters exercised here.",
        "Do not widen into router, product, or comparative proof from this receipt.",
    ]

    status = "PASS" if precondition_pass and not scenario_failures and repeatability_pass else "FAIL"
    body = {
        "schema_id": "kt.operator.c016b_live_provider_resilience_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "scope_boundary": "C016B proves bounded timeout/backoff, circuit-breaker, rate-limit, quota, network-failure, malformed-response fail-closure, and verdict-failure truth separation on the canonical LIVE_HASHED lane only.",
        "c016a_precondition_ref": str(precondition.get("path_ref", PRECONDITION_REL)),
        "c016a_precondition_status": str(precondition.get("status", "")).strip(),
        "c016a_successful_provider_ids": list(precondition.get("successful_provider_ids", [])),
        "environment_presence": {
            "OPENAI_API_KEY": _env_present("OPENAI_API_KEY"),
            "OPENROUTER_API_KEY": _env_present("OPENROUTER_API_KEY"),
            "KT_HMAC_KEY_SIGNER_A": _env_present("KT_HMAC_KEY_SIGNER_A"),
            "KT_HMAC_KEY_SIGNER_B": _env_present("KT_HMAC_KEY_SIGNER_B"),
        },
        "export_root_ref": str(matrix.get("export_root_ref", EXPORT_ROOT_REL)),
        "runtime_telemetry_ref": str(matrix.get("runtime_telemetry_ref", TELEMETRY_REL)),
        "runs": runs,
        "repeatability_status": str(matrix.get("repeatability_status", "")),
        "repeatability_reference": list(matrix.get("repeatability_reference", [])),
        "scenario_failures": scenario_failures,
        "boundary_holds": boundary_holds,
        "c016b_delta": (
            "C016B_CLOSED_FOR_CANONICAL_LIVE_HASHED_RESILIENCE_PATH"
            if status == "PASS"
            else "C016B_NARROWED_TO_RESILIENCE_GAPS_WITH_RECEIPTED_FAULT_MATRIX"
        ),
        "stronger_claim_not_made": [
            "externality_upgraded",
            "cross_host_resilience_proven",
            "router_elevated",
            "product_truth_widened",
        ],
        "exact_remaining_forbidden_claims": exact_remaining_forbidden_claims,
    }
    payload_hash = _sha256_obj(body)
    return {
        **body,
        "payload_hash": payload_hash,
        "signoffs": _signoffs_for_payload_hash(payload_hash),
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate C016B resilience on the canonical LIVE_HASHED lane.")
    parser.add_argument("--output", default=REPORT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    receipt = build_c016b_live_provider_resilience_receipt(root=root)
    output_path = Path(str(args.output)).expanduser()
    if not output_path.is_absolute():
        output_path = (root / output_path).resolve()
    write_json_stable(output_path, receipt)
    print(
        json.dumps(
            {
                "c016b_delta": receipt["c016b_delta"],
                "repeatability_status": receipt["repeatability_status"],
                "status": receipt["status"],
            },
            sort_keys=True,
        )
    )
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
