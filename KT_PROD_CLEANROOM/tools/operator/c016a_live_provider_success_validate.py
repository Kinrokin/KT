from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.verification.attestation_hmac import sign_hmac


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/post_wave5_c016a_live_provider_success"
TELEMETRY_REL = "KT_PROD_CLEANROOM/reports/post_wave5_c016a_runtime_telemetry.jsonl"


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
            raise RuntimeError(f"missing {env_name} for C016A receipt signoff (fail-closed)")
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


def _provider_specs() -> list[dict[str, str]]:
    specs: list[dict[str, str]] = []
    if _env_present("OPENAI_API_KEY"):
        specs.append(
            {
                "provider_id": "openai",
                "request_type": "healthcheck",
                "model": "gpt-4.1-mini",
                "prompt": "Reply with exactly OK.",
                "trace_id": "post-wave5-c016a-openai-live",
            }
        )
    if _env_present("OPENROUTER_API_KEY"):
        specs.append(
            {
                "provider_id": "openrouter",
                "request_type": "analysis",
                "model": "openai/gpt-4.1-mini",
                "prompt": "Reply with exactly OK.",
                "trace_id": "post-wave5-c016a-openrouter-live",
            }
        )
    return specs


def _call_summary(
    *,
    root: Path,
    export_root: Path,
    payload: Dict[str, str],
    execute_request: Callable[[Dict[str, Any]], Dict[str, Any]],
) -> Dict[str, Any]:
    request_payload = {
        "mode": "LIVE_HASHED",
        "request_type": payload["request_type"],
        "provider_id": payload["provider_id"],
        "model": payload["model"],
        "prompt": payload["prompt"],
        "trace_id": payload["trace_id"],
        "export_root": str(export_root),
    }
    summary: Dict[str, Any] = {
        "adapter_id": "",
        "error": "",
        "failure_artifact_exists": False,
        "failure_artifact_ref": "",
        "provider_id": payload["provider_id"],
        "receipt_exists": False,
        "receipt_ref": "",
        "request_type": payload["request_type"],
        "status": "ERROR",
        "trace_id": payload["trace_id"],
    }
    try:
        out = execute_request(request_payload)
    except Exception as exc:  # noqa: BLE001
        summary["error"] = str(exc)
        return summary

    summary["adapter_id"] = str(out.get("adapter_id", "")).strip()
    summary["error"] = str(out.get("error", "")).strip()
    summary["receipt_ref"] = str(out.get("receipt_ref", "")).strip()
    summary["failure_artifact_ref"] = str(out.get("failure_artifact_ref", "")).strip()
    summary["status"] = str(out.get("status", "")).strip() or "ERROR"

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
            summary["failure_id"] = str(failure.get("failure_id", "")).strip()
            summary["failure_error_class"] = str(failure.get("error_class", "")).strip()
            summary["failure_rel"] = failure_path.relative_to(root).as_posix()
    return summary


def build_c016a_live_provider_success_receipt(
    *,
    root: Path,
    execute_request: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    if execute_request is None:
        from council.council_router import execute_council_request as execute_request_impl

        execute_request = execute_request_impl

    export_root = (root / EXPORT_ROOT_REL).resolve()
    telemetry_path = (root / TELEMETRY_REL).resolve()
    if export_root.exists():
        shutil.rmtree(export_root, ignore_errors=True)
    export_root.mkdir(parents=True, exist_ok=True)
    if telemetry_path.exists():
        telemetry_path.unlink()

    original_env = {
        name: os.environ.get(name)
        for name in ("KT_PROVIDERS_ENABLED", "KT_EXECUTION_LANE", "KT_NODE_ID", "KT_RUNTIME_TELEMETRY_PATH")
    }
    os.environ["KT_PROVIDERS_ENABLED"] = "1"
    os.environ["KT_EXECUTION_LANE"] = "LIVE_HASHED"
    os.environ["KT_NODE_ID"] = "post-wave5-c016a"
    os.environ["KT_RUNTIME_TELEMETRY_PATH"] = str(telemetry_path)

    try:
        provider_rows = [
            _call_summary(root=root, export_root=export_root, payload=spec, execute_request=execute_request)
            for spec in _provider_specs()
        ]
    finally:
        for name, value in original_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    successful_rows = [row for row in provider_rows if row.get("status") == "OK" and row.get("receipt_exists")]
    fail_closed_rows = [row for row in provider_rows if row.get("status") == "FAIL_CLOSED"]
    boundary_holds: list[str] = []
    if not provider_rows:
        boundary_holds.append("NO_LIVE_PROVIDER_KEYS_PRESENT_IN_ENV")
    if not successful_rows:
        boundary_holds.append("AUTHENTICATED_LIVE_PROVIDER_SUCCESS_NOT_YET_PROVEN")
    if any(int(row.get("http_status", 0)) == 401 for row in provider_rows):
        boundary_holds.append("UPSTREAM_PROVIDER_REJECTED_CURRENT_CREDENTIALS_WITH_HTTP_401")

    exact_remaining_forbidden_claims = [
        "C016A is not closed unless at least one LIVE_HASHED provider row returns status=OK with a provider receipt.",
        "Do not claim OpenAI or OpenRouter authenticated success while all observed rows remain FAIL_CLOSED.",
        "Do not raise C006 or externality class from same-host evidence.",
        "Do not widen into router, product, or comparative proof from this receipt.",
    ]

    body = {
        "schema_id": "kt.operator.c016a_live_provider_success_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if successful_rows else "FAIL",
        "scope_boundary": "C016A proves only authenticated live-provider success on the canonical LIVE_HASHED ABI lane and preserves exact failure rows when authentication is rejected.",
        "export_root_ref": export_root.relative_to(root).as_posix(),
        "runtime_telemetry_ref": telemetry_path.relative_to(root).as_posix(),
        "environment_presence": {
            "OPENAI_API_KEY": _env_present("OPENAI_API_KEY"),
            "OPENROUTER_API_KEY": _env_present("OPENROUTER_API_KEY"),
            "KT_HMAC_KEY_SIGNER_A": _env_present("KT_HMAC_KEY_SIGNER_A"),
            "KT_HMAC_KEY_SIGNER_B": _env_present("KT_HMAC_KEY_SIGNER_B"),
        },
        "provider_rows": provider_rows,
        "successful_provider_count": len(successful_rows),
        "successful_provider_ids": [str(row.get("provider_id", "")).strip() for row in successful_rows],
        "fail_closed_provider_ids": [str(row.get("provider_id", "")).strip() for row in fail_closed_rows],
        "boundary_holds": boundary_holds,
        "c016a_delta": (
            "C016A_CLOSED_FOR_CANONICAL_LIVE_HASHED_LANE"
            if successful_rows
            else "C016A_NARROWED_TO_UPSTREAM_AUTH_REJECTION_WITH_RECEIPTED_FAIL_CLOSED_ROWS"
        ),
        "stronger_claim_not_made": [
            "provider_resilience_repeatability_proven",
            "externality_upgraded",
            "router_elevated",
            "product_truth_widened",
        ],
        "exact_remaining_forbidden_claims": exact_remaining_forbidden_claims,
    }
    payload_hash = _sha256_obj(body)
    receipt = {
        **body,
        "payload_hash": payload_hash,
        "signoffs": _signoffs_for_payload_hash(payload_hash),
    }
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate C016A authenticated live-provider success on the canonical LIVE_HASHED lane.")
    parser.add_argument("--output", default=f"{REPORT_ROOT_REL}/post_wave5_c016a_success_matrix.json")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    receipt = build_c016a_live_provider_success_receipt(root=root)
    output_path = Path(str(args.output)).expanduser()
    if not output_path.is_absolute():
        output_path = (root / output_path).resolve()
    write_json_stable(output_path, receipt)
    print(
        json.dumps(
            {
                "c016a_delta": receipt["c016a_delta"],
                "status": receipt["status"],
                "successful_provider_count": receipt["successful_provider_count"],
            },
            sort_keys=True,
        )
    )
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
