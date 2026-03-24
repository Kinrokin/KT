from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"
for _path in (str(_CLEANROOM_ROOT), str(_SRC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/wave2a_adapter_activation"


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _runtime_registry(root: Path) -> Dict[str, Any]:
    return _load_json(root / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json")


def _quarantine_surface_ids(root: Path) -> set[str]:
    payload = _load_json(root / REPORT_ROOT_REL / "kt_wave0_quarantine_receipts.json")
    return {
        str(row.get("surface_id", "")).strip()
        for row in payload.get("rows", [])
        if isinstance(row, dict) and str(row.get("surface_id", "")).strip()
    }


def _classify_latency(latency_ms: int) -> str:
    value = int(latency_ms)
    if value < 500:
        return "sub_500ms"
    if value < 2000:
        return "500ms_to_2s"
    if value < 10000:
        return "2s_to_10s"
    return "10s_plus"


def _call_summary(*, root: Path, payload: Dict[str, Any]) -> Dict[str, Any]:
    from council.council_router import execute_council_request

    out = execute_council_request(payload)
    summary: Dict[str, Any] = {
        "provider_id": str(payload.get("provider_id", "")).strip(),
        "request_type": str(payload.get("request_type", "")).strip(),
        "adapter_id": str(out.get("adapter_id", "")).strip(),
        "status": str(out.get("status", "")).strip(),
        "receipt_ref": str(out.get("receipt_ref", "")).strip(),
        "failure_artifact_ref": str(out.get("failure_artifact_ref", "")).strip(),
        "error": str(out.get("error", "")).strip(),
    }
    receipt_ref = summary["receipt_ref"]
    if receipt_ref:
        receipt_path = Path(receipt_ref)
        summary["receipt_exists"] = receipt_path.exists()
        if receipt_path.exists():
            receipt = _load_json(receipt_path)
            summary["receipt_hash"] = str(receipt.get("receipt_hash", "")).strip()
            summary["http_status"] = int(receipt.get("transport", {}).get("http_status", 0))
            summary["replayability_class"] = str(receipt.get("lane", "")).strip()
            summary["latency_ms"] = int(receipt.get("timing", {}).get("latency_ms", 0))
            summary["latency_class"] = _classify_latency(summary["latency_ms"])
            summary["verdict_pass"] = bool(receipt.get("verdict", {}).get("pass"))
            summary["receipt_rel"] = receipt_path.relative_to(root).as_posix()
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


def build_wave2a_receipts(*, root: Path) -> Dict[str, Dict[str, Any]]:
    from council.providers.adapter_abi_runtime import load_active_adapter_manifests

    export_root = (root / EXPORT_ROOT_REL).resolve()
    telemetry_path = (root / REPORT_ROOT_REL / "kt_wave2a_runtime_telemetry.jsonl").resolve()
    if export_root.exists():
        shutil.rmtree(export_root, ignore_errors=True)
    export_root.mkdir(parents=True, exist_ok=True)
    if telemetry_path.exists():
        telemetry_path.unlink()

    original_env = {name: os.environ.get(name) for name in ("KT_PROVIDERS_ENABLED", "KT_EXECUTION_LANE", "KT_NODE_ID", "KT_RUNTIME_TELEMETRY_PATH")}
    os.environ["KT_PROVIDERS_ENABLED"] = "1"
    os.environ["KT_EXECUTION_LANE"] = "LIVE_HASHED"
    os.environ["KT_NODE_ID"] = "wave2a-validator"
    os.environ["KT_RUNTIME_TELEMETRY_PATH"] = str(telemetry_path)

    try:
        manifests = load_active_adapter_manifests()
        manifest_ids = sorted(manifests)
        registry = _runtime_registry(root)
        registry_entries = registry.get("adapters", {}).get("entries", [])
        active_registry_ids = sorted(
            str(row.get("adapter_id", "")).strip()
            for row in registry_entries
            if isinstance(row, dict) and str(row.get("status", "")).strip() == "ACTIVE"
        )
        quarantine_ids = _quarantine_surface_ids(root)

        openai_call = _call_summary(
            root=root,
            payload={
                "mode": "LIVE_HASHED",
                "request_type": "healthcheck",
                "provider_id": "openai",
                "model": "gpt-4.1-mini",
                "prompt": "Return exactly OK.",
                "trace_id": "wave2a-openai-live",
                "export_root": str(export_root),
            },
        )

        first_lane_truthful = bool(openai_call.get("receipt_exists")) and (
            openai_call["status"] == "OK" or bool(openai_call.get("failure_artifact_exists"))
        )

        openrouter_call = None
        second_provider_rule = "SKIPPED_FIRST_LANE_NOT_PROVEN"
        if first_lane_truthful:
            second_provider_rule = "ADDED_AFTER_FIRST_LANE_PROVED_RECEIPT_AND_BOUNDED_OUTCOME"
            openrouter_call = _call_summary(
                root=root,
                payload={
                    "mode": "LIVE_HASHED",
                    "request_type": "analysis",
                    "provider_id": "openrouter",
                    "model": "openai/gpt-4.1-mini",
                    "prompt": "Reply with the single token OK.",
                    "trace_id": "wave2a-openrouter-live",
                    "export_root": str(export_root),
                },
            )

        abi_mismatch_call = _call_summary(
            root=root,
            payload={
                "mode": "LIVE_HASHED",
                "request_type": "healthcheck",
                "provider_id": "not_allowed",
                "adapter_id": "council.openai.live_hashed.v1",
                "model": "gpt-4.1-mini",
                "prompt": "Return exactly OK.",
                "trace_id": "wave2a-abi-mismatch",
                "export_root": str(export_root),
            },
        )
    finally:
        for name, value in original_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    provider_rows = [openai_call]
    if openrouter_call is not None:
        provider_rows.append(openrouter_call)

    live_networked = [row for row in provider_rows if int(row.get("http_status", 0)) > 0 and bool(row.get("receipt_exists"))]
    successful_live = [row for row in provider_rows if row.get("status") == "OK"]
    fail_closed_live = [row for row in provider_rows if row.get("status") == "FAIL_CLOSED"]

    all_live_receipts = bool(provider_rows) and all(bool(row.get("receipt_exists")) for row in provider_rows)
    all_failures_artifacted = all(bool(row.get("failure_artifact_exists")) for row in fail_closed_live) and bool(
        abi_mismatch_call.get("failure_artifact_exists")
    )
    adapter_ids_seen = {str(row.get("adapter_id", "")).strip() for row in provider_rows if str(row.get("adapter_id", "")).strip()}
    no_quarantine_overlap = not bool(adapter_ids_seen & quarantine_ids)
    abi_compliance = manifest_ids == active_registry_ids and adapter_ids_seen.issubset(set(manifest_ids))

    coverage = {
        "declared_task_family_coverage": sorted({str(row.get("request_type", "")).strip() for row in provider_rows + [abi_mismatch_call]}),
        "failure_class_coverage": sorted(
            {
                str(row.get("failure_error_class", "")).strip()
                for row in provider_rows + [abi_mismatch_call]
                if str(row.get("failure_error_class", "")).strip()
            }
        ),
        "latency_class_coverage": sorted(
            {str(row.get("latency_class", "")).strip() for row in provider_rows if str(row.get("latency_class", "")).strip()}
        ),
        "replayability_class_coverage": sorted(
            {
                str(manifest.replayability_class).strip()
                for manifest in manifests.values()
                if str(manifest.replayability_class).strip()
            }
        ),
        "adversarial_probe_coverage": [
            "adapter_provider_mismatch_fail_closed",
        ],
    }

    boundary_holds: list[str] = []
    if not successful_live:
        boundary_holds.append("REMOTE_PROVIDER_AUTH_DID_NOT_YIELD_SUCCESSFUL_CURRENT_HEAD_INFERENCE")
    if any(int(row.get("http_status", 0)) == 401 for row in provider_rows):
        boundary_holds.append("REMOTE_PROVIDER_HTTP_401_VISIBLE_AND_NOT_OVERCLAIMED_AWAY")

    provider_failures: list[str] = []
    if not live_networked:
        provider_failures.append("no_live_networked_provider_call_observed")
    if not all_live_receipts:
        provider_failures.append("one_or_more_live_calls_missing_provider_receipt")
    if not all_failures_artifacted:
        provider_failures.append("one_or_more_fail_closed_paths_missing_failure_artifact")
    if not no_quarantine_overlap:
        provider_failures.append("active_provider_path_intersects_quarantined_surface")
    if not abi_compliance:
        provider_failures.append("adapter_manifest_ids_do_not_match_runtime_registry_active_entries")
    if abi_mismatch_call.get("status") != "FAIL_CLOSED":
        provider_failures.append("abi_mismatch_path_did_not_fail_closed")

    provider_report = {
        "schema_id": "kt.wave2a.provider_activation_receipts.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not provider_failures else "FAIL",
        "scope_boundary": "Wave 2A proves a narrow live provider-backed adapter lane with ABI-bound receipts and deterministic failure artifacts only.",
        "export_root_ref": export_root.relative_to(root).as_posix(),
        "runtime_telemetry_ref": telemetry_path.relative_to(root).as_posix(),
        "active_manifest_ids": manifest_ids,
        "active_runtime_registry_ids": active_registry_ids,
        "provider_rows": provider_rows,
        "abi_mismatch_probe": abi_mismatch_call,
        "coverage": coverage,
        "second_provider_rule": second_provider_rule,
        "boundary_holds": boundary_holds,
        "failures": provider_failures,
        "stronger_claim_not_made": [
            "semantic_router_opened",
            "organ_realization_opened",
            "product_or_commercial_language_widened",
            "broad_externality_widened",
            "successful_remote_inference_claimed_without_evidence",
        ],
    }

    adapter_failures: list[str] = []
    if len(active_registry_ids) < 2:
        adapter_failures.append("runtime_registry_active_adapter_count_below_two")
    if active_registry_ids != manifest_ids:
        adapter_failures.append("runtime_registry_active_entries_do_not_match_manifest_ids")
    if not live_networked:
        adapter_failures.append("no_real_live_provider_backed_adapter_lane_observed")

    adapter_report = {
        "schema_id": "kt.wave2a.adapter_activation_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not adapter_failures else "FAIL",
        "scope_boundary": "Wave 2A clears the zero-adapter state narrowly and truthfully without opening router elevation, organ realization, or product widening.",
        "adapter_zero_state_previous_contradiction": "C003_ADAPTER_CIVILIZATION_WITH_ZERO_ADAPTERS",
        "active_adapter_count": len(active_registry_ids),
        "active_adapter_ids": active_registry_ids,
        "adapter_manifest_paths": sorted(str(manifest.manifest_path.relative_to(root)).replace("\\", "/") for manifest in manifests.values()),
        "no_provider_path_routes_to_quarantined_organs": no_quarantine_overlap,
        "real_live_lane_observed": bool(live_networked),
        "successful_live_provider_count": len(successful_live),
        "boundary_holds": boundary_holds,
        "failures": adapter_failures,
        "stronger_claim_not_made": [
            "router_ambition_upgraded",
            "broad_runtime_capability_confirmed",
            "minimum_viable_civilization_run_executed",
            "product_truth_widened",
        ],
    }

    async_report = {
        "schema_id": "kt.wave2a.async_provider_or_spine_option_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "scope_boundary": "Wave 2A keeps provider execution narrow and synchronous at the canonical boundary.",
        "decision": "SYNC_BOUNDARY_ACCEPTED_FOR_FIRST_LIVE_ADAPTER_LANES",
        "notes": [
            "Wave 2A activates the first live adapter lanes without widening into router elevation or broader asynchronous orchestration.",
            "Async widening remains available for future waves if latency pressure or breadth justifies it.",
        ],
    }

    return {
        "provider_report": provider_report,
        "adapter_report": adapter_report,
        "async_report": async_report,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Wave 2A adapter ABI and provider activation on the narrow live lane.")
    parser.add_argument("--provider-output", default=f"{REPORT_ROOT_REL}/kt_wave2a_provider_activation_receipts.json")
    parser.add_argument("--adapter-output", default=f"{REPORT_ROOT_REL}/kt_wave2a_adapter_activation_receipt.json")
    parser.add_argument("--async-output", default=f"{REPORT_ROOT_REL}/kt_wave2a_async_provider_or_spine_option_receipt.json")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    reports = build_wave2a_receipts(root=root)
    outputs = {
        "provider_report": Path(str(args.provider_output)).expanduser(),
        "adapter_report": Path(str(args.adapter_output)).expanduser(),
        "async_report": Path(str(args.async_output)).expanduser(),
    }
    for key, path in outputs.items():
        if not path.is_absolute():
            outputs[key] = (root / path).resolve()
    write_json_stable(outputs["provider_report"], reports["provider_report"])
    write_json_stable(outputs["adapter_report"], reports["adapter_report"])
    write_json_stable(outputs["async_report"], reports["async_report"])
    failures = {
        "provider_failures": reports["provider_report"].get("failures", []),
        "adapter_failures": reports["adapter_report"].get("failures", []),
    }
    print(json.dumps({"status": "PASS" if not failures["provider_failures"] and not failures["adapter_failures"] else "FAIL", **failures}, sort_keys=True))
    return 0 if not failures["provider_failures"] and not failures["adapter_failures"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
