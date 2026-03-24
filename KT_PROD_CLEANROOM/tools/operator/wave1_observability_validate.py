from __future__ import annotations

import argparse
import importlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.claim_compiler import build_claim_compiler_receipt
from tools.operator.public_verifier import build_public_verifier_report
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
REQUIRED_FIELDS = (
    "trace_id",
    "span_id",
    "request_id",
    "surface_id",
    "zone",
    "event_type",
    "start_ts",
    "end_ts",
    "latency_ms",
    "provider_id",
    "budget_consumed",
    "policy_applied",
    "result_status",
    "receipt_ref",
    "failure_artifact_ref",
)


def _runtime_context() -> Dict[str, Any]:
    from core.invariants_gate import CONSTITUTION_VERSION_HASH
    from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH

    return {
        "envelope": {"input": ""},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
    }


def _load_jsonl(path: Path) -> list[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _validate_rows(rows: list[Dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for idx, row in enumerate(rows):
        missing = [field for field in REQUIRED_FIELDS if field not in row]
        if missing:
            failures.append(f"row_{idx}_missing_fields:{','.join(missing)}")
    return failures


def build_wave1_observability_receipt(*, root: Path) -> Dict[str, Any]:
    runtime_path = root / REPORT_ROOT_REL / "kt_wave1_runtime_observability.jsonl"
    toolchain_path = root / REPORT_ROOT_REL / "kt_wave1_toolchain_observability.jsonl"
    runtime_path.parent.mkdir(parents=True, exist_ok=True)
    if runtime_path.exists():
        runtime_path.unlink()
    if toolchain_path.exists():
        toolchain_path.unlink()

    os.environ["KT_RUNTIME_TELEMETRY_PATH"] = str(runtime_path)
    os.environ["KT_TOOLCHAIN_TELEMETRY_PATH"] = str(toolchain_path)

    from core import runtime_registry as rr
    from council.council_router import execute_fanout_request
    from core.import_truth_guard import ImportTruthGuard

    original_loader = rr.load_runtime_registry
    original_repo_root = rr._v2_repo_root
    entry_mod = importlib.import_module("kt.entrypoint")
    original_entry_loader = entry_mod.load_runtime_registry

    registry = original_loader()
    with tempfile.TemporaryDirectory() as td:
        temp_repo_root = Path(td).resolve()
        rr._v2_repo_root = lambda: temp_repo_root  # type: ignore[assignment]
        rr.load_runtime_registry = lambda: registry  # type: ignore[assignment]
        entry_mod.load_runtime_registry = lambda: registry  # type: ignore[assignment]
        try:
            spine_result = entry_mod.invoke(_runtime_context())
            fanout_result = execute_fanout_request(
                prompt="wave1 observability probe",
                provider_ids=["dry_run", "gemini"],
                model_id="model-1",
                trace_id="wave1-observability-fanout",
                export_root=temp_repo_root / "exports" / "router_traces",
            )
        finally:
            rr.load_runtime_registry = original_loader  # type: ignore[assignment]
            rr._v2_repo_root = original_repo_root  # type: ignore[assignment]
            entry_mod.load_runtime_registry = original_entry_loader  # type: ignore[assignment]
            ImportTruthGuard.uninstall_for_tests()

    verifier_report = build_public_verifier_report(root=root, telemetry_path=toolchain_path)
    claim_report = build_claim_compiler_receipt(root=root, telemetry_path=toolchain_path)

    runtime_rows = _load_jsonl(runtime_path)
    toolchain_rows = _load_jsonl(toolchain_path)
    failures = _validate_rows(runtime_rows) + _validate_rows(toolchain_rows)

    required_runtime_surfaces = {
        "core.spine.run",
        "council.providers.provider_registry.invoke",
    }
    required_toolchain_surfaces = {
        "tools.operator.public_verifier.build_public_verifier_report",
        "tools.operator.claim_compiler.build_claim_compiler_receipt",
    }
    runtime_surfaces = {str(row.get("surface_id", "")).strip() for row in runtime_rows}
    toolchain_surfaces = {str(row.get("surface_id", "")).strip() for row in toolchain_rows}
    missing_runtime = sorted(required_runtime_surfaces - runtime_surfaces)
    missing_toolchain = sorted(required_toolchain_surfaces - toolchain_surfaces)
    if missing_runtime:
        failures.append("missing_runtime_surfaces:" + ",".join(missing_runtime))
    if missing_toolchain:
        failures.append("missing_toolchain_surfaces:" + ",".join(missing_toolchain))

    os.environ.pop("KT_RUNTIME_TELEMETRY_PATH", None)
    os.environ.pop("KT_TOOLCHAIN_TELEMETRY_PATH", None)

    return {
        "schema_id": "kt.wave1.observability_schema_and_receipts.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not failures else "FAIL",
        "scope_boundary": "Wave 1 observability covers spine, provider invoke path, public verifier path, and claim compilation path only.",
        "runtime_observability_ref": str(runtime_path.relative_to(root)).replace("\\", "/"),
        "toolchain_observability_ref": str(toolchain_path.relative_to(root)).replace("\\", "/"),
        "runtime_event_count": len(runtime_rows),
        "toolchain_event_count": len(toolchain_rows),
        "runtime_surfaces_observed": sorted(runtime_surfaces),
        "toolchain_surfaces_observed": sorted(toolchain_surfaces),
        "spine_result_status": str(spine_result.get("status", "")).strip(),
        "fanout_provider_count": len(fanout_result),
        "public_verifier_status": str(verifier_report.get("status", "")).strip(),
        "claim_compiler_status": str(claim_report.get("status", "")).strip(),
        "failures": failures,
        "stronger_claim_not_made": [
            "adapter_activation_occurred",
            "router_elevation_occurred",
            "broad_externality_widened",
            "product_language_widened",
        ],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Wave 1 observability receipts across the canonical runtime and toolchain surfaces.")
    parser.add_argument("--output", default=f"{REPORT_ROOT_REL}/kt_wave1_observability_schema_and_receipts.json")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    report = build_wave1_observability_receipt(root=root)
    out_path = Path(str(args.output)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()
    write_json_stable(out_path, report)
    print(json.dumps({"status": report["status"], "runtime_event_count": report["runtime_event_count"], "toolchain_event_count": report["toolchain_event_count"]}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
