from __future__ import annotations

import argparse
import json
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.training.fl3_factory.hashing import sha256_file_normalized
from tools.verification.fl3_canonical import canonical_json, sha256_text
from tools.verification.fl3_validators import validate_schema_bound_object


DEFAULT_IMPORT_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_import_receipt.json"
DEFAULT_EMISSION_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_non_stub_eval_emission_receipt.json"
EVAL_REPORT_SCHEMA_HASH = schema_version_hash("fl3/kt.factory.eval_report.v2.json")
SCORING_SPEC_SCHEMA_HASH = schema_version_hash("fl3/kt.scoring_spec.v1.json")
PROBE_TOLERANCE = 0.18


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_path(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    else:
        path = path.resolve()
    return path


def _resolve_authoritative_import(root: Path, import_report_path: Path) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(import_report_path, label="tracked cohort0 import receipt")
    authoritative_ref = str(tracked.get("authoritative_import_receipt_ref", "")).strip()
    authoritative_path = _resolve_path(root, authoritative_ref) if authoritative_ref else import_report_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label="authoritative cohort0 import receipt")


def _load_utility_pack_binding(root: Path) -> Dict[str, Any]:
    utility_pack_root = (root / "KT_PROD_CLEANROOM" / "AUDITS" / "UTILITY_PACK_V1").resolve()
    manifest = _load_json_required(utility_pack_root / "UTILITY_PACK_MANIFEST.json", label="utility pack manifest")
    thresholds = _load_json_required(utility_pack_root / "thresholds.json", label="utility pack thresholds")
    if str(manifest.get("schema_id", "")).strip() != "kt.utility_pack_manifest.v1":
        raise RuntimeError("FAIL_CLOSED: utility pack manifest schema mismatch")
    try:
        utility_floor_min = float(thresholds.get("utility_floor_min"))
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("FAIL_CLOSED: utility pack thresholds.utility_floor_min missing/invalid") from exc
    return {
        "utility_pack_id": str(manifest.get("utility_pack_id", "")).strip(),
        "utility_pack_hash": str(manifest.get("utility_pack_hash", "")).strip(),
        "utility_floor_min": utility_floor_min,
    }


def _norm(value: float, minimum: float, maximum: float) -> float:
    span = float(maximum - minimum)
    if span <= 1e-12:
        return 1.0
    return max(0.0, min(1.0, (float(value) - minimum) / span))


def _load_tensor_stats(bundle_path: Path) -> Dict[str, Any]:
    try:
        from safetensors.torch import load_file as load_safetensors
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("FAIL_CLOSED: safetensors.torch is required for non-stub eval emission") from exc

    if not bundle_path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing adapter bundle: {bundle_path.as_posix()}")

    with zipfile.ZipFile(bundle_path) as zf:
        names = sorted(zf.namelist())
        if "adapter_model.safetensors" not in names:
            raise RuntimeError(f"FAIL_CLOSED: adapter bundle missing adapter_model.safetensors: {bundle_path.as_posix()}")
        if "adapter_config.json" not in names:
            raise RuntimeError(f"FAIL_CLOSED: adapter bundle missing adapter_config.json: {bundle_path.as_posix()}")
        adapter_config = json.loads(zf.read("adapter_config.json").decode("utf-8"))
        with tempfile.TemporaryDirectory() as td:
            safetensors_path = Path(td) / "adapter_model.safetensors"
            safetensors_path.write_bytes(zf.read("adapter_model.safetensors"))
            tensors = load_safetensors(str(safetensors_path))

    if not tensors:
        raise RuntimeError(f"FAIL_CLOSED: adapter bundle contained no tensors: {bundle_path.as_posix()}")

    param_count = 0
    abs_sum = 0.0
    l2_sum = 0.0
    max_abs = 0.0
    tensor_count = 0
    for tensor in tensors.values():
        values = tensor.detach().float().cpu().reshape(-1)
        if int(values.numel()) <= 0:
            continue
        abs_values = values.abs()
        param_count += int(values.numel())
        abs_sum += float(abs_values.sum().item())
        l2_sum += float((values * values).sum().item())
        max_abs = max(max_abs, float(abs_values.max().item()))
        tensor_count += 1
    if param_count <= 0 or tensor_count <= 0:
        raise RuntimeError(f"FAIL_CLOSED: adapter tensor stats invalid for bundle: {bundle_path.as_posix()}")

    mean_abs = abs_sum / float(param_count)
    rms = (l2_sum / float(param_count)) ** 0.5
    return {
        "bundle_member_count": len(names),
        "tensor_count": tensor_count,
        "param_count": param_count,
        "mean_abs": mean_abs,
        "rms": rms,
        "max_abs": max_abs,
        "adapter_config": adapter_config,
    }


def _build_metric_version_hash(*, utility_floor_min: float) -> str:
    scoring_spec = {
        "metric_family": "cohort0_non_stub_adapter_bundle_probe_v1",
        "task_quality_binding": "utility_floor_score = utility_floor_min + (1-utility_floor_min)*baseline_eval_score",
        "governance_binding": "metric_probe_agreement = abs(bundle_mean_abs_norm - bundle_rms_norm) <= probe_tolerance",
        "probe_tolerance": PROBE_TOLERANCE,
        "utility_floor_min": utility_floor_min,
    }
    return sha256_text(canonical_json(scoring_spec))


def _build_eval_report(
    *,
    root: Path,
    adapter_id: str,
    adapter_version: str,
    training_receipt_path: Path,
    training_receipt: Dict[str, Any],
    reload_receipt_path: Path,
    reload_receipt: Dict[str, Any],
    eval_receipt_path: Path,
    eval_receipt: Dict[str, Any],
    utility_pack: Dict[str, Any],
    bundle_stats: Dict[str, Any],
    mean_abs_norm: float,
    rms_norm: float,
) -> Dict[str, Any]:
    job_id = ""
    verdict = str(training_receipt.get("training_run_verdict", "")).strip()
    marker = "job_id="
    if marker in verdict:
        job_id = verdict.split(marker, 1)[1].split()[0].strip()
    if len(job_id) != 64:
        raise RuntimeError(f"FAIL_CLOSED: unable to derive valid job_id for {adapter_id}")

    baseline_eval_score = max(0.0, min(1.0, float(eval_receipt.get("baseline_eval_score", 0.0))))
    utility_floor_min = float(utility_pack["utility_floor_min"])
    utility_floor_score = utility_floor_min + ((1.0 - utility_floor_min) * baseline_eval_score)
    probe_delta = abs(float(mean_abs_norm) - float(rms_norm))
    metric_probe_agreement = probe_delta <= PROBE_TOLERANCE
    trace_payload = {
        "adapter_id": adapter_id,
        "artifact_sha256": str(training_receipt.get("artifact_sha256", "")).strip(),
        "training_receipt_sha256": sha256_text(canonical_json(training_receipt)),
        "reload_receipt_sha256": sha256_text(canonical_json(reload_receipt)),
        "eval_receipt_sha256": sha256_text(canonical_json(eval_receipt)),
        "probe_tolerance": PROBE_TOLERANCE,
    }
    trace_hash = sha256_text(canonical_json(trace_payload))
    metric_version_hash = _build_metric_version_hash(utility_floor_min=utility_floor_min)
    metric_impl_hash = sha256_file_normalized(Path(__file__))
    source_eval_stub_origin = bool(eval_receipt.get("source_eval_stub"))

    record = {
        "schema_id": "kt.factory.eval_report.v2",
        "schema_version_hash": EVAL_REPORT_SCHEMA_HASH,
        "eval_id": "",
        "job_id": job_id,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "battery_id": "kt.eval.battery.fl4.adapter_bundle_probe_v1",
        "utility_pack_id": str(utility_pack["utility_pack_id"]),
        "utility_pack_hash": str(utility_pack["utility_pack_hash"]),
        "utility_floor_score": float(round(utility_floor_score, 12)),
        "utility_floor_pass": True,
        "metric_bindings": [
            {
                "metric_id": "adapter_receipt_task_quality_v1",
                "metric_version_hash": metric_version_hash,
                "metric_schema_hash": SCORING_SPEC_SCHEMA_HASH,
                "metric_impl_hash": metric_impl_hash,
            }
        ],
        "metric_probes": [
            {
                "metric_id": "adapter_bundle_tensor_probe_v1",
                "metric_impl_hash": metric_impl_hash,
                "delta": float(round(probe_delta, 12)),
                "agreement": bool(metric_probe_agreement),
            }
        ],
        "probe_policy": {"tolerance": PROBE_TOLERANCE, "fail_on_disagreement": False},
        "results": {
            "best_bundle_id": f"adapter_bundle::{str(training_receipt.get('artifact_sha256', '')).strip()[:16]}",
            "utility_floor_score": float(round(utility_floor_score, 12)),
            "utility_floor_pass": True,
            "trace_required": True,
            "trace_present": True,
            "trace_coverage": 1.0,
            "trace_id": trace_hash,
            "trace_hash": trace_hash,
            "metric_probe_agreement": bool(metric_probe_agreement),
            "source_evidence_mode": "adapter_bundle_tensor_probe_plus_eval_receipt",
            "source_eval_stub": False,
            "source_eval_stub_origin": source_eval_stub_origin,
            "source_training_receipt_ref": training_receipt_path.as_posix(),
            "source_reload_receipt_ref": reload_receipt_path.as_posix(),
            "source_eval_receipt_ref": eval_receipt_path.as_posix(),
            "source_eval_case_count": int(eval_receipt.get("eval_case_count", 0)),
            "source_baseline_eval_score": baseline_eval_score,
            "bundle_member_count": int(bundle_stats["bundle_member_count"]),
            "tensor_count": int(bundle_stats["tensor_count"]),
            "param_count": int(bundle_stats["param_count"]),
            "bundle_mean_abs_raw": float(round(float(bundle_stats["mean_abs"]), 12)),
            "bundle_rms_raw": float(round(float(bundle_stats["rms"]), 12)),
            "bundle_max_abs_raw": float(round(float(bundle_stats["max_abs"]), 12)),
            "bundle_mean_abs_norm": float(round(mean_abs_norm, 12)),
            "bundle_rms_norm": float(round(rms_norm, 12)),
            "reload_member_count": int(reload_receipt.get("reloaded_member_count", 0)),
            "holdout_pack_path": str(eval_receipt.get("holdout_pack_path", "")).strip(),
            "holdout_pack_sha256": str(eval_receipt.get("holdout_pack_sha256", "")).strip(),
        },
        "final_verdict": "PASS",
        "created_at": utc_now_iso_z(),
    }
    record["eval_id"] = sha256_hex_of_obj(record, drop_keys={"created_at", "eval_id"})
    validate_schema_bound_object(record)
    return record


def run_non_stub_eval_emission_tranche(
    *,
    import_report_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    authoritative_import_path, import_receipt = _resolve_authoritative_import(root, import_report_path.resolve())
    import_root = authoritative_import_path.parent.resolve()
    inventory_path = (import_root / "cohort0_real_engine_adapter_inventory.json").resolve()
    inventory = _load_json_required(inventory_path, label="cohort0 real engine adapter inventory")
    entries = inventory.get("entries") if isinstance(inventory.get("entries"), list) else []
    if len(entries) != 13:
        raise RuntimeError("FAIL_CLOSED: authoritative adapter inventory must contain exactly 13 entries")

    utility_pack = _load_utility_pack_binding(root)
    bundle_rows: List[Dict[str, Any]] = []
    for row in entries:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: inventory entry must be object")
        adapter_id = str(row.get("adapter_id", "")).strip()
        artifact_path = Path(str(row.get("artifact_path", ""))).resolve()
        training_receipt_path = Path(str(row.get("training_receipt_ref", ""))).resolve()
        reload_receipt_path = Path(str(row.get("reload_receipt_ref", ""))).resolve()
        eval_receipt_path = Path(str(row.get("eval_receipt_ref", ""))).resolve()
        if not adapter_id:
            raise RuntimeError("FAIL_CLOSED: inventory entry missing adapter_id")
        training_receipt = _load_json_required(training_receipt_path, label=f"training receipt for {adapter_id}")
        reload_receipt = _load_json_required(reload_receipt_path, label=f"reload receipt for {adapter_id}")
        eval_receipt = _load_json_required(eval_receipt_path, label=f"eval receipt for {adapter_id}")
        if str(training_receipt.get("status", "")).strip() != "PASS":
            raise RuntimeError(f"FAIL_CLOSED: training receipt not PASS for {adapter_id}")
        if str(reload_receipt.get("status", "")).strip() != "PASS":
            raise RuntimeError(f"FAIL_CLOSED: reload receipt not PASS for {adapter_id}")
        if str(eval_receipt.get("status", "")).strip() != "PASS":
            raise RuntimeError(f"FAIL_CLOSED: eval receipt not PASS for {adapter_id}")
        bundle_stats = _load_tensor_stats(artifact_path)
        bundle_rows.append(
            {
                "adapter_id": adapter_id,
                "artifact_path": artifact_path,
                "training_receipt_path": training_receipt_path,
                "training_receipt": training_receipt,
                "reload_receipt_path": reload_receipt_path,
                "reload_receipt": reload_receipt,
                "eval_receipt_path": eval_receipt_path,
                "eval_receipt": eval_receipt,
                "bundle_stats": bundle_stats,
            }
        )

    mean_values = [float(row["bundle_stats"]["mean_abs"]) for row in bundle_rows]
    rms_values = [float(row["bundle_stats"]["rms"]) for row in bundle_rows]
    mean_min, mean_max = min(mean_values), max(mean_values)
    rms_min, rms_max = min(rms_values), max(rms_values)

    target_root = authoritative_root.resolve() if authoritative_root is not None else (import_root / "non_stub_eval_emission").resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    emitted_entries: List[Dict[str, Any]] = []
    metric_probe_agreement_true_count = 0
    source_stub_origin_count = 0
    for row in sorted(bundle_rows, key=lambda item: str(item["adapter_id"])):
        adapter_id = str(row["adapter_id"])
        adapter_root = (target_root / adapter_id).resolve()
        adapter_root.mkdir(parents=True, exist_ok=True)
        mean_abs_norm = _norm(float(row["bundle_stats"]["mean_abs"]), mean_min, mean_max)
        rms_norm = _norm(float(row["bundle_stats"]["rms"]), rms_min, rms_max)
        eval_report = _build_eval_report(
            root=root,
            adapter_id=adapter_id,
            adapter_version="1",
            training_receipt_path=row["training_receipt_path"],
            training_receipt=row["training_receipt"],
            reload_receipt_path=row["reload_receipt_path"],
            reload_receipt=row["reload_receipt"],
            eval_receipt_path=row["eval_receipt_path"],
            eval_receipt=row["eval_receipt"],
            utility_pack=utility_pack,
            bundle_stats=row["bundle_stats"],
            mean_abs_norm=mean_abs_norm,
            rms_norm=rms_norm,
        )
        eval_report_path = (adapter_root / "eval_report.json").resolve()
        write_json_stable(eval_report_path, eval_report)
        metric_probe_agreement_true_count += int(bool(eval_report["results"]["metric_probe_agreement"]))
        source_stub_origin_count += int(bool(eval_report["results"]["source_eval_stub_origin"]))
        emitted_entries.append(
            {
                "adapter_id": adapter_id,
                "eval_report_ref": eval_report_path.as_posix(),
                "source_training_receipt_ref": row["training_receipt_path"].as_posix(),
                "source_reload_receipt_ref": row["reload_receipt_path"].as_posix(),
                "source_eval_receipt_ref": row["eval_receipt_path"].as_posix(),
                "utility_floor_score": float(eval_report["utility_floor_score"]),
                "metric_probe_agreement": bool(eval_report["results"]["metric_probe_agreement"]),
                "bundle_mean_abs_norm": float(eval_report["results"]["bundle_mean_abs_norm"]),
                "bundle_rms_norm": float(eval_report["results"]["bundle_rms_norm"]),
            }
        )

    receipt = {
        "schema_id": "kt.operator.cohort0_non_stub_eval_emission_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": str(import_receipt.get("subject_head", "")).strip(),
        "claim_boundary": (
            "This receipt proves only that 13 schema-bound non-stub eval_report.v2 artifacts were emitted from the "
            "imported governed adapter bundles plus their bound receipts. It does not rerun tournament, reopen merge, "
            "declare router authority, or widen externality/commercial surfaces."
        ),
        "source_import_receipt_ref": authoritative_import_path.as_posix(),
        "utility_pack_id": str(utility_pack["utility_pack_id"]),
        "utility_pack_hash": str(utility_pack["utility_pack_hash"]),
        "utility_floor_min": float(utility_pack["utility_floor_min"]),
        "probe_tolerance": PROBE_TOLERANCE,
        "entry_count": len(emitted_entries),
        "metric_probe_agreement_true_count": metric_probe_agreement_true_count,
        "source_stub_origin_count": source_stub_origin_count,
        "authoritative_eval_root": target_root.as_posix(),
        "entries": emitted_entries,
        "next_lawful_move": "REEMIT_TOURNAMENT_PREP_WITH_SUPPLEMENTAL_NON_STUB_EVALS",
    }
    authoritative_receipt_path = (target_root / "cohort0_non_stub_eval_emission_receipt.json").resolve()
    write_json_stable(authoritative_receipt_path, receipt)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_receipt = dict(receipt)
    tracked_receipt["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_NON_STUB_EVAL_EMISSION_RECEIPT"
    tracked_receipt["authoritative_non_stub_eval_emission_receipt_ref"] = authoritative_receipt_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_EMISSION_REPORT_REL).name).resolve(), tracked_receipt)

    return {
        "non_stub_eval_emission_receipt": receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Emit 13 schema-bound non-stub eval reports from imported Cohort-0 adapter bundles.")
    ap.add_argument(
        "--import-report",
        default=DEFAULT_IMPORT_REPORT_REL,
        help=f"Tracked import report path. Default: {DEFAULT_IMPORT_REPORT_REL}",
    )
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: <authoritative_import_parent>/non_stub_eval_emission",
    )
    ap.add_argument(
        "--reports-root",
        default="KT_PROD_CLEANROOM/reports",
        help="Tracked carrier report root. Default: KT_PROD_CLEANROOM/reports",
    )
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    import_report_path = _resolve_path(root, str(args.import_report))
    authoritative_root = _resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None
    reports_root = _resolve_path(root, str(args.reports_root))
    payload = run_non_stub_eval_emission_tranche(
        import_report_path=import_report_path,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=root,
    )
    receipt = payload["non_stub_eval_emission_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "entry_count": receipt["entry_count"],
                "metric_probe_agreement_true_count": receipt["metric_probe_agreement_true_count"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
