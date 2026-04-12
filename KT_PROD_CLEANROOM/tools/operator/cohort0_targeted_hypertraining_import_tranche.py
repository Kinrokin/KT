from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_compact_z, utc_now_iso_z, write_json_stable


DEFAULT_STAGE_INPUT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_stage_input_receipt.json"
DEFAULT_STAGE_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_stage_input_manifest.json"
DEFAULT_KAGGLE_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_kaggle_packet.json"
DEFAULT_FREEZE_BOUNDARY_REL = "../KT_FORGE_STAGE/kaggle_stage_pack/kt-targeted-hypertraining-stage/contracts/stage_freeze_boundary.json"
DEFAULT_DATASET_MANIFEST_REL = "../KT_FORGE_STAGE/kaggle_stage_pack/kt-targeted-hypertraining-stage/datasets/cohort0_targeted_hypertraining_dataset_manifest.json"

DEFAULT_IMPORT_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_import_receipt.json"
DEFAULT_GRADE_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_grade_receipt.json"
DEFAULT_FOLLOWTHROUGH_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_followthrough_packet.json"

EXPECTED_TOP_LEVEL_FILES = (
    "adapter_lineage_manifest.json",
    "adapter_registry.json",
    "discovery_receipt.json",
    "preflight_receipt.json",
    "run_manifest.json",
    "run_summary.json",
    "stage_hash_validation_receipt.json",
    "targeted_hypertraining_run_receipt.json",
)

EXPECTED_ADAPTER_FILES = (
    "adapter_bundle.zip",
    "adapter_eval_receipt.json",
    "adapter_reload_receipt.json",
    "adapter_training_receipt.json",
    "dataset_hash_manifest.json",
    "eval_report.json",
    "job_dir_manifest.json",
    "reasoning_trace.json",
    "train_manifest.json",
    "train_receipt.json",
    "training_config.json",
    "training_report.json",
    "training_run_manifest.PASS.json",
    "verdict.txt",
)


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative_json(root: Path, path: Path, *, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(path.resolve(), label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    if not authoritative_ref:
        return path.resolve(), tracked
    authoritative_path = _resolve(root, authoritative_ref)
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    except Exception:  # noqa: BLE001
        return ""


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy_and_extract_bundle(*, bundle_zip: Path, authoritative_root: Path) -> Tuple[Path, Path]:
    imported_zip = (authoritative_root / bundle_zip.name).resolve()
    extract_root = (authoritative_root / "extracted").resolve()
    authoritative_root.mkdir(parents=True, exist_ok=True)
    shutil.copy2(bundle_zip, imported_zip)
    with zipfile.ZipFile(imported_zip) as zf:
        zf.extractall(extract_root)
    return imported_zip, extract_root


def _find_extracted_bundle_root(extract_root: Path) -> Path:
    dirs = [p.resolve() for p in extract_root.iterdir() if p.is_dir()]
    if len(dirs) != 1:
        raise RuntimeError("FAIL_CLOSED: expected exactly one top-level bundle root in extracted targeted hypertraining artifact")
    return dirs[0]


def _hash_tree(root: Path) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.relative_to(root).as_posix()):
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": _sha256_file(path),
                "bytes": int(path.stat().st_size),
            }
        )
    root_hash = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    return {
        "root": root.as_posix(),
        "file_count": len(entries),
        "entries": entries,
        "root_hash": root_hash,
    }


def _load_authoritative_adapter_ids(root: Path) -> List[str]:
    registry = _load_json_required(root / "KT_PROD_CLEANROOM" / "governance" / "adapter_registry.json", label="governance adapter registry")
    rows = list(registry.get("experimental_adapter_ids", [])) + list(registry.get("ratified_adapter_ids", []))
    adapter_ids = [str(x).strip() for x in rows if str(x).strip()]
    if len(adapter_ids) != 13 or len(set(adapter_ids)) != 13:
        raise RuntimeError("FAIL_CLOSED: governance adapter registry must resolve exactly 13 unique adapter ids")
    return adapter_ids


def _stage_row_map(stage_manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows = stage_manifest.get("dataset_rows") if isinstance(stage_manifest.get("dataset_rows"), list) else []
    result: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict):
            adapter_id = str(row.get("adapter_id", "")).strip()
            if adapter_id:
                result[adapter_id] = row
    return result


def _freeze_row_map(freeze_boundary: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows = freeze_boundary.get("dataset_rows") if isinstance(freeze_boundary.get("dataset_rows"), list) else []
    result: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict):
            adapter_id = str(row.get("adapter_id", "")).strip()
            if adapter_id:
                result[adapter_id] = row
    return result


def _stage_hash_row_map(stage_hash_validation: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows = stage_hash_validation.get("rows") if isinstance(stage_hash_validation.get("rows"), list) else []
    result: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict):
            adapter_id = str(row.get("adapter_id", "")).strip()
            if adapter_id:
                result[adapter_id] = row
    return result


def _find_manifest_row(run_manifest: Dict[str, Any], adapter_id: str) -> Dict[str, Any]:
    rows = run_manifest.get("artifact_hashes") if isinstance(run_manifest.get("artifact_hashes"), list) else []
    matches = [row for row in rows if isinstance(row, dict) and str(row.get("adapter_id", "")).strip() == adapter_id]
    if len(matches) != 1:
        raise RuntimeError(f"FAIL_CLOSED: expected exactly one run_manifest artifact row for {adapter_id}")
    return matches[0]


def _inventory_adapter(
    *,
    bundle_root: Path,
    adapter_id: str,
    stage_row: Dict[str, Any],
    freeze_row: Dict[str, Any],
    stage_hash_row: Dict[str, Any],
    run_manifest_row: Dict[str, Any],
) -> Dict[str, Any]:
    adapter_root = (bundle_root / "adapters" / adapter_id).resolve()
    if not adapter_root.is_dir():
        raise RuntimeError(f"FAIL_CLOSED: missing adapter root for {adapter_id}: {adapter_root.as_posix()}")

    for filename in EXPECTED_ADAPTER_FILES:
        candidate = adapter_root / filename
        if not candidate.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing {filename} for {adapter_id}: {candidate.as_posix()}")

    training_receipt_path = adapter_root / "adapter_training_receipt.json"
    reload_receipt_path = adapter_root / "adapter_reload_receipt.json"
    eval_receipt_path = adapter_root / "adapter_eval_receipt.json"
    eval_report_path = adapter_root / "eval_report.json"
    artifact_path = adapter_root / "adapter_bundle.zip"

    training = load_json(training_receipt_path)
    reload = load_json(reload_receipt_path)
    eval_receipt = load_json(eval_receipt_path)
    eval_report = load_json(eval_report_path)

    artifact_sha = _sha256_file(artifact_path)
    artifact_bytes = int(artifact_path.stat().st_size)
    trainer_module = str(((training.get("hf_lora") if isinstance(training.get("hf_lora"), dict) else {}) or {}).get("trainer", "")).strip()

    if str(training.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: training receipt not PASS for {adapter_id}")
    if str(reload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: reload receipt not PASS for {adapter_id}")
    if str(eval_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: eval receipt not PASS for {adapter_id}")
    if str(eval_report.get("final_verdict", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: eval_report final_verdict not PASS for {adapter_id}")
    if str(training.get("engine", "")).strip() != "hf_lora":
        raise RuntimeError(f"FAIL_CLOSED: training engine must be hf_lora for {adapter_id}")
    if str(training.get("training_mode", "")).strip() != "lora":
        raise RuntimeError(f"FAIL_CLOSED: training_mode must be lora for {adapter_id}")
    if trainer_module != "tools.training.phase2_train":
        raise RuntimeError(f"FAIL_CLOSED: trainer must be tools.training.phase2_train for {adapter_id}")
    if str(training.get("artifact_sha256", "")).strip() != artifact_sha:
        raise RuntimeError(f"FAIL_CLOSED: training artifact sha mismatch for {adapter_id}")
    if str(eval_receipt.get("artifact_sha256", "")).strip() != artifact_sha:
        raise RuntimeError(f"FAIL_CLOSED: eval receipt artifact sha mismatch for {adapter_id}")
    if str(run_manifest_row.get("artifact_sha256", "")).strip() != artifact_sha:
        raise RuntimeError(f"FAIL_CLOSED: run manifest artifact sha mismatch for {adapter_id}")
    if int(training.get("artifact_bytes", 0)) != artifact_bytes:
        raise RuntimeError(f"FAIL_CLOSED: training artifact_bytes mismatch for {adapter_id}")
    if int(reload.get("reloaded_member_count", 0)) <= 0:
        raise RuntimeError(f"FAIL_CLOSED: reload member count must be > 0 for {adapter_id}")
    if int(eval_receipt.get("eval_case_count", 0)) <= 0:
        raise RuntimeError(f"FAIL_CLOSED: eval_case_count must be > 0 for {adapter_id}")
    if bool(eval_receipt.get("source_eval_stub")):
        raise RuntimeError(f"FAIL_CLOSED: source_eval_stub must be false in eval receipt for {adapter_id}")
    if bool(eval_report.get("results", {}).get("source_eval_stub", False)):
        raise RuntimeError(f"FAIL_CLOSED: source_eval_stub must be false in eval report for {adapter_id}")
    if not bool(eval_report.get("results", {}).get("trace_present", False)):
        raise RuntimeError(f"FAIL_CLOSED: eval report trace_present must be true for {adapter_id}")
    if not bool(eval_report.get("utility_floor_pass", False)):
        raise RuntimeError(f"FAIL_CLOSED: utility_floor_pass must be true for {adapter_id}")

    dataset_sha = str(training.get("dataset_sha256", "")).strip()
    if dataset_sha != str(stage_row.get("sha256", "")).strip():
        raise RuntimeError(f"FAIL_CLOSED: stage manifest dataset sha mismatch for {adapter_id}")
    if dataset_sha != str(freeze_row.get("dataset_sha256", "")).strip():
        raise RuntimeError(f"FAIL_CLOSED: freeze boundary dataset sha mismatch for {adapter_id}")
    if dataset_sha != str(stage_hash_row.get("dataset_sha256", "")).strip():
        raise RuntimeError(f"FAIL_CLOSED: stage hash validation dataset sha mismatch for {adapter_id}")
    if dataset_sha != str(run_manifest_row.get("dataset_sha256", "")).strip():
        raise RuntimeError(f"FAIL_CLOSED: run manifest dataset sha mismatch for {adapter_id}")
    if int(stage_row.get("line_count", 0)) != int(freeze_row.get("line_count", 0)) or int(stage_row.get("line_count", 0)) != int(stage_hash_row.get("line_count", 0)):
        raise RuntimeError(f"FAIL_CLOSED: line_count mismatch across stage surfaces for {adapter_id}")

    return {
        "adapter_id": adapter_id,
        "family_id": str(stage_row.get("family_id", "")).strip(),
        "artifact_path": artifact_path.as_posix(),
        "artifact_sha256": artifact_sha,
        "artifact_bytes": artifact_bytes,
        "dataset_relpath": str(training.get("dataset_relpath", "")).strip(),
        "dataset_sha256": dataset_sha,
        "config_relpath": str(stage_row.get("config_relpath", "")).strip(),
        "config_sha256": str(stage_hash_row.get("config_sha256", "")).strip(),
        "line_count": int(stage_row.get("line_count", 0)),
        "trainer_module": trainer_module,
        "base_snapshot_id": str(training.get("base_snapshot_id", "")).strip(),
        "base_model_root_hash": str(training.get("base_model_root_hash", "")).strip(),
        "eval_case_count": int(eval_receipt.get("eval_case_count", 0)),
        "baseline_eval_score": float(eval_receipt.get("baseline_eval_score", 0.0)),
        "utility_floor_score": float(eval_report.get("utility_floor_score", 0.0)),
        "metric_probe_agreement": bool(eval_report.get("results", {}).get("metric_probe_agreement", False)),
        "trace_present": bool(eval_report.get("results", {}).get("trace_present", False)),
        "param_count": int(eval_report.get("results", {}).get("param_count", 0)),
        "targeted_hypertraining_files_complete": True,
    }


def _build_import_receipt(
    *,
    workspace_root: Path,
    bundle_zip: Path,
    imported_zip: Path,
    bundle_root: Path,
    stage_input_receipt: Dict[str, Any],
    run_manifest: Dict[str, Any],
    run_summary: Dict[str, Any],
    run_receipt: Dict[str, Any],
    adapter_inventory: List[Dict[str, Any]],
    authoritative_ids: List[str],
) -> Dict[str, Any]:
    current_head = _git_head(workspace_root)
    stage_freeze_head = str(stage_input_receipt.get("current_git_head", "")).strip()
    subject_head = str(run_manifest.get("subject_head", "")).strip() or str(stage_input_receipt.get("subject_head", "")).strip()
    same_freeze_head = bool(current_head and stage_freeze_head and current_head == stage_freeze_head)
    target_ids = [str(x).strip() for x in stage_input_receipt.get("target_lobe_ids", [])]
    carryforward_ids = [adapter_id for adapter_id in authoritative_ids if adapter_id not in target_ids]

    checks = [
        {"check_id": "bundle_zip_present_and_extracted", "pass": True},
        {"check_id": "run_manifest_status_pass", "pass": str(run_manifest.get("verdict", "")).strip() == "PASS"},
        {"check_id": "run_summary_status_pass", "pass": str(run_summary.get("status", "")).strip() == "PASS"},
        {"check_id": "run_receipt_status_pass", "pass": str(run_receipt.get("status", "")).strip() == "PASS"},
        {"check_id": "target_adapter_ids_match_stage_packet", "pass": [row["adapter_id"] for row in adapter_inventory] == target_ids},
        {"check_id": "all_targeted_adapter_receipt_families_complete", "pass": len(adapter_inventory) == len(target_ids)},
        {"check_id": "all_targeted_adapters_are_real_engine_phase2_hf_lora", "pass": all(row["trainer_module"] == "tools.training.phase2_train" for row in adapter_inventory)},
        {"check_id": "current_repo_head_matches_stage_freeze_head", "pass": same_freeze_head},
    ]

    return {
        "schema_id": "kt.operator.cohort0_targeted_hypertraining_import_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "receipt_role": (
            "CURRENT_STAGE_FREEZE_TARGETED_HYPERTRAINING_EVIDENCE"
            if same_freeze_head
            else "CARRIER_ONLY_TARGETED_HYPERTRAINING_EVIDENCE"
        ),
        "claim_boundary": (
            "This receipt proves only that the six-lobe targeted hypertraining Kaggle run is real, stage-bound, "
            "and complete enough for stronger-cycle evidence import. It does not by itself reopen the counted lane, "
            "rerun tournament, reopen merge, earn router superiority, or open Gate E/F."
        ),
        "source_bundle_zip_path": bundle_zip.as_posix(),
        "source_bundle_zip_sha256": _sha256_file(bundle_zip),
        "imported_bundle_zip_path": imported_zip.as_posix(),
        "imported_bundle_zip_sha256": _sha256_file(imported_zip),
        "bundle_root": bundle_root.as_posix(),
        "bundle_root_hash_tree": _hash_tree(bundle_root),
        "subject_head": subject_head,
        "stage_freeze_head": stage_freeze_head,
        "current_git_head": current_head,
        "subject_head_is_current_at_import": bool(subject_head and current_head and subject_head == current_head),
        "stage_freeze_head_is_current_at_import": same_freeze_head,
        "registry_id": str(run_manifest.get("registry_id", "")).strip(),
        "stage_input_posture": str(stage_input_receipt.get("stage_input_posture", "")).strip(),
        "target_lobe_ids": target_ids,
        "carryforward_control_ids": carryforward_ids,
        "adapter_count": len(adapter_inventory),
        "checks": checks,
        "next_lawful_move": "RECOMPOSE_13_ENTRANT_SUBSTRATE_FROM_TARGETED_AND_CONTROL_ENTRANTS",
    }


def _build_grade_receipt(
    *,
    import_receipt: Dict[str, Any],
    adapter_inventory: List[Dict[str, Any]],
) -> Dict[str, Any]:
    artifact_bytes = [row["artifact_bytes"] for row in adapter_inventory]
    utility_scores = [row["utility_floor_score"] for row in adapter_inventory]
    return {
        "schema_id": "kt.operator.cohort0_targeted_hypertraining_grade_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "grade": "PASS_AS_STRONGER_CYCLE_TARGETED_HYPERTRAINING_EVIDENCE",
        "claim_boundary": (
            "This grade proves only that six oracle-positive lobes were lawfully hypertrained on the frozen Kaggle packet "
            "and returned as non-stub stronger-cycle evidence. It does not claim that the downstream proof chain has already moved."
        ),
        "adapter_count": len(adapter_inventory),
        "engine_summary": {
            "hf_lora_adapter_count": len(adapter_inventory),
            "phase2_train_adapter_count": len(adapter_inventory),
            "artifact_bytes_min": min(artifact_bytes) if artifact_bytes else 0,
            "artifact_bytes_max": max(artifact_bytes) if artifact_bytes else 0,
            "artifact_bytes_total": sum(artifact_bytes),
        },
        "eval_summary": {
            "utility_floor_score_min": min(utility_scores) if utility_scores else 0.0,
            "utility_floor_score_max": max(utility_scores) if utility_scores else 0.0,
            "all_metric_probe_agreement": all(row["metric_probe_agreement"] for row in adapter_inventory),
            "all_trace_present": all(row["trace_present"] for row in adapter_inventory),
        },
        "ratification_effects": {
            "kaggle_targeted_hypertraining_return_verified": True,
            "targeted_stage_packet_executed_successfully": True,
            "stronger_cycle_evidence_family_available_for_composite_substrate": True,
            "direct_tournament_rerun_unblocked_without_recomposition": False,
            "router_superiority_earned": False,
        },
        "source_import_receipt_ref": DEFAULT_IMPORT_REPORT_REL,
        "source_subject_head": str(import_receipt.get("subject_head", "")).strip(),
    }


def _build_followthrough_packet(
    *,
    bundle_root: Path,
    import_receipt: Dict[str, Any],
    grade_receipt: Dict[str, Any],
    target_lobe_ids: List[str],
    authoritative_ids: List[str],
    adapter_inventory: List[Dict[str, Any]],
) -> Dict[str, Any]:
    carryforward_ids = [adapter_id for adapter_id in authoritative_ids if adapter_id not in target_lobe_ids]
    blockers = [
        "TARGETED_RUN_ONLY_UPDATES_6_OF_13_ENTRANTS",
        "COMPOSITE_13_ENTRANT_AUTHORITY_ROOT_NOT_YET_BOUND",
        "DOWNSTREAM_LOCAL_PROOF_CHAIN_STILL_EXPECTS_RECOMPOSED_13_ENTRANT_SUBSTRATE",
    ]
    return {
        "schema_id": "kt.operator.cohort0_targeted_hypertraining_followthrough_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "followthrough_posture": "TARGETED_HYPERTRAINING_IMPORTED__COMPOSITE_13_ENTRANT_SUBSTRATE_REQUIRED",
        "claim_boundary": (
            "This packet proves only that the six targeted stronger-cycle returns are imported and complete. "
            "It does not yet recompute the full 13-entrant substrate or claim downstream proof-chain movement."
        ),
        "subject_head": str(import_receipt.get("subject_head", "")).strip(),
        "targeted_hypertraining_grade": str(grade_receipt.get("grade", "")).strip(),
        "imported_targeted_lobe_ids": target_lobe_ids,
        "carryforward_control_ids": carryforward_ids,
        "carrier_surface_summary": {
            "bundle_root_ref": bundle_root.as_posix(),
            "imported_targeted_adapter_count": len(adapter_inventory),
            "imported_eval_report_count": len(list(bundle_root.rglob("eval_report.json"))),
            "imported_job_dir_manifest_count": len(list(bundle_root.rglob("job_dir_manifest.json"))),
            "imported_train_manifest_count": len(list(bundle_root.rglob("train_manifest.json"))),
            "imported_training_run_manifest_count": len(list(bundle_root.rglob("training_run_manifest.PASS.json"))),
            "transcript_count": len(list((bundle_root / "transcripts").glob("*.log"))) if (bundle_root / "transcripts").is_dir() else 0,
            "training_input_count": len(list((bundle_root / "training_inputs").glob("*.json"))) if (bundle_root / "training_inputs").is_dir() else 0,
        },
        "composite_substrate_requirement": {
            "required_total_entrant_count": 13,
            "updated_entrant_ids": target_lobe_ids,
            "carryforward_entrant_ids": carryforward_ids,
            "blockers": blockers,
            "next_lawful_move": "RECOMPOSE_13_ENTRANT_SUBSTRATE_FROM_TARGETED_AND_CONTROL_ENTRANTS",
        },
        "next_question": "Can we bind a recomposed 13-entrant authority root that swaps in these six stronger-cycle entrants and then rerun the local proof chain honestly?",
        "source_import_receipt_ref": DEFAULT_IMPORT_REPORT_REL,
        "source_grade_receipt_ref": DEFAULT_GRADE_REPORT_REL,
    }


def run_targeted_hypertraining_import_tranche(
    *,
    bundle_zip: Path,
    authoritative_root: Path,
    reports_root: Path,
    stage_input_receipt_path: Path,
    stage_manifest_path: Path,
    dataset_manifest_path: Path,
    kaggle_packet_path: Path,
    freeze_boundary_path: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    bundle_zip = bundle_zip.expanduser().resolve()
    if not bundle_zip.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing targeted hypertraining bundle zip: {bundle_zip.as_posix()}")

    stage_input_receipt_path, stage_input_receipt = _resolve_authoritative_json(
        root,
        stage_input_receipt_path,
        ref_field="authoritative_targeted_hypertraining_stage_input_receipt_ref",
        label="targeted hypertraining stage input receipt",
    )
    stage_manifest_path, stage_manifest = _resolve_authoritative_json(
        root,
        stage_manifest_path,
        ref_field="authoritative_targeted_hypertraining_stage_input_manifest_ref",
        label="targeted hypertraining stage manifest",
    )
    dataset_manifest = _load_json_required(dataset_manifest_path.resolve(), label="targeted hypertraining dataset manifest")
    kaggle_packet_path, kaggle_packet = _resolve_authoritative_json(
        root,
        kaggle_packet_path,
        ref_field="authoritative_targeted_hypertraining_kaggle_packet_ref",
        label="targeted hypertraining kaggle packet",
    )
    freeze_boundary = _load_json_required(freeze_boundary_path.resolve(), label="targeted hypertraining freeze boundary")

    imported_zip, extract_root = _copy_and_extract_bundle(bundle_zip=bundle_zip, authoritative_root=authoritative_root.resolve())
    bundle_root = _find_extracted_bundle_root(extract_root)

    for filename in EXPECTED_TOP_LEVEL_FILES:
        candidate = bundle_root / filename
        if not candidate.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing required bundle file: {candidate.as_posix()}")

    run_manifest = load_json(bundle_root / "run_manifest.json")
    run_summary = load_json(bundle_root / "run_summary.json")
    run_receipt = load_json(bundle_root / "targeted_hypertraining_run_receipt.json")
    stage_hash_validation = load_json(bundle_root / "stage_hash_validation_receipt.json")

    target_ids = [str(x).strip() for x in stage_input_receipt.get("target_lobe_ids", [])]
    if not target_ids or len(target_ids) != 6:
        raise RuntimeError("FAIL_CLOSED: stage input receipt must bind exactly 6 target lobe ids")
    if list(kaggle_packet.get("all_in_one_window", {}).get("target_lobe_ids", [])) != target_ids:
        raise RuntimeError("FAIL_CLOSED: kaggle packet target ids mismatch")
    if list(run_manifest.get("adapter_ids", [])) != target_ids:
        raise RuntimeError("FAIL_CLOSED: run manifest adapter ids do not match targeted lobe ids")
    if int(run_summary.get("adapter_count", 0)) != len(target_ids):
        raise RuntimeError("FAIL_CLOSED: run summary adapter_count mismatch")
    if int(run_receipt.get("adapter_count", 0)) != len(target_ids):
        raise RuntimeError("FAIL_CLOSED: run receipt adapter_count mismatch")
    if str(run_manifest.get("verdict", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: run manifest verdict must PASS")
    if str(run_summary.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: run summary status must PASS")
    if str(run_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: targeted hypertraining run receipt must PASS")

    if str(stage_hash_validation.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: stage hash validation receipt must PASS")
    if str(stage_hash_validation.get("current_git_head", "")).strip() != str(stage_input_receipt.get("current_git_head", "")).strip():
        raise RuntimeError("FAIL_CLOSED: stage hash validation current_git_head mismatch")
    if str(stage_hash_validation.get("subject_head", "")).strip() != str(stage_input_receipt.get("subject_head", "")).strip():
        raise RuntimeError("FAIL_CLOSED: stage hash validation subject_head mismatch")
    if str(stage_hash_validation.get("kaggle_packet_sha256", "")).strip() != _sha256_file(kaggle_packet_path.resolve()):
        raise RuntimeError("FAIL_CLOSED: stage hash validation kaggle_packet sha mismatch")
    if str(stage_hash_validation.get("freeze_boundary_sha256", "")).strip() != _sha256_file(freeze_boundary_path.resolve()):
        raise RuntimeError("FAIL_CLOSED: stage hash validation freeze boundary sha mismatch")
    if str(stage_hash_validation.get("dataset_manifest_sha256", "")).strip() != _sha256_file(dataset_manifest_path.resolve()):
        raise RuntimeError("FAIL_CLOSED: stage hash validation dataset manifest sha mismatch")

    if str(freeze_boundary.get("current_git_head", "")).strip() != str(stage_input_receipt.get("current_git_head", "")).strip():
        raise RuntimeError("FAIL_CLOSED: freeze boundary current_git_head mismatch")
    if str(freeze_boundary.get("contract_hashes", {}).get("kaggle_packet", "")).strip() != _sha256_file(kaggle_packet_path.resolve()):
        raise RuntimeError("FAIL_CLOSED: freeze boundary contract_hashes.kaggle_packet mismatch")
    if str(freeze_boundary.get("contract_hashes", {}).get("dataset_manifest", "")).strip() != _sha256_file(dataset_manifest_path.resolve()):
        raise RuntimeError("FAIL_CLOSED: freeze boundary contract_hashes.dataset_manifest mismatch")

    _ = kaggle_packet
    _ = dataset_manifest
    stage_rows = _stage_row_map(stage_manifest)
    freeze_rows = _freeze_row_map(freeze_boundary)
    stage_hash_rows = _stage_hash_row_map(stage_hash_validation)
    adapter_inventory = [
        _inventory_adapter(
            bundle_root=bundle_root,
            adapter_id=adapter_id,
            stage_row=stage_rows[adapter_id],
            freeze_row=freeze_rows[adapter_id],
            stage_hash_row=stage_hash_rows[adapter_id],
            run_manifest_row=_find_manifest_row(run_manifest, adapter_id),
        )
        for adapter_id in target_ids
    ]

    authoritative_ids = _load_authoritative_adapter_ids(root)
    import_receipt = _build_import_receipt(
        workspace_root=root,
        bundle_zip=bundle_zip,
        imported_zip=imported_zip,
        bundle_root=bundle_root,
        stage_input_receipt=stage_input_receipt,
        run_manifest=run_manifest,
        run_summary=run_summary,
        run_receipt=run_receipt,
        adapter_inventory=adapter_inventory,
        authoritative_ids=authoritative_ids,
    )
    grade_receipt = _build_grade_receipt(import_receipt=import_receipt, adapter_inventory=adapter_inventory)
    followthrough_packet = _build_followthrough_packet(
        bundle_root=bundle_root,
        import_receipt=import_receipt,
        grade_receipt=grade_receipt,
        target_lobe_ids=target_ids,
        authoritative_ids=authoritative_ids,
        adapter_inventory=adapter_inventory,
    )

    authoritative_files = {
        "adapter_inventory": authoritative_root / "cohort0_targeted_hypertraining_adapter_inventory.json",
        "import_receipt": authoritative_root / "cohort0_targeted_hypertraining_import_receipt.json",
        "grade_receipt": authoritative_root / "cohort0_targeted_hypertraining_grade_receipt.json",
        "followthrough_packet": authoritative_root / "cohort0_targeted_hypertraining_followthrough_packet.json",
    }
    write_json_stable(
        authoritative_files["adapter_inventory"],
        {
            "schema_id": "kt.operator.cohort0_targeted_hypertraining_adapter_inventory.v1",
            "generated_utc": utc_now_iso_z(),
            "adapter_count": len(adapter_inventory),
            "entries": adapter_inventory,
        },
    )
    write_json_stable(authoritative_files["import_receipt"], import_receipt)
    write_json_stable(authoritative_files["grade_receipt"], grade_receipt)
    write_json_stable(authoritative_files["followthrough_packet"], followthrough_packet)

    tracked_import = dict(import_receipt)
    tracked_import["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_TARGETED_HYPERTRAINING_IMPORT_RECEIPT"
    tracked_import["authoritative_targeted_hypertraining_import_receipt_ref"] = authoritative_files["import_receipt"].as_posix()

    tracked_grade = dict(grade_receipt)
    tracked_grade["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_TARGETED_HYPERTRAINING_GRADE_RECEIPT"
    tracked_grade["authoritative_targeted_hypertraining_grade_receipt_ref"] = authoritative_files["grade_receipt"].as_posix()

    tracked_follow = dict(followthrough_packet)
    tracked_follow["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_TARGETED_HYPERTRAINING_FOLLOWTHROUGH_PACKET"
    tracked_follow["authoritative_targeted_hypertraining_followthrough_packet_ref"] = authoritative_files["followthrough_packet"].as_posix()

    write_json_stable((reports_root / Path(DEFAULT_IMPORT_REPORT_REL).name).resolve(), tracked_import)
    write_json_stable((reports_root / Path(DEFAULT_GRADE_REPORT_REL).name).resolve(), tracked_grade)
    write_json_stable((reports_root / Path(DEFAULT_FOLLOWTHROUGH_REPORT_REL).name).resolve(), tracked_follow)

    return {
        "adapter_inventory": load_json(authoritative_files["adapter_inventory"]),
        "import_receipt": import_receipt,
        "grade_receipt": grade_receipt,
        "followthrough_packet": followthrough_packet,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Import and grade a six-lobe targeted hypertraining Kaggle return bundle.")
    ap.add_argument("--bundle-zip", required=True, help="Path to targeted hypertraining FULL_ARTIFACTS zip.")
    ap.add_argument("--stage-input-receipt", default=DEFAULT_STAGE_INPUT_RECEIPT_REL)
    ap.add_argument("--stage-manifest", default=DEFAULT_STAGE_MANIFEST_REL)
    ap.add_argument("--dataset-manifest", default=DEFAULT_DATASET_MANIFEST_REL)
    ap.add_argument("--kaggle-packet", default=DEFAULT_KAGGLE_PACKET_REL)
    ap.add_argument("--freeze-boundary", default=DEFAULT_FREEZE_BOUNDARY_REL)
    ap.add_argument("--authoritative-root", default="", help="Optional authoritative output root. Default: tmp/cohort0_targeted_hypertraining_import_<utc>/")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports", help="Directory that receives tracked carrier copies.")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    authoritative_root = (
        _resolve(root, str(args.authoritative_root))
        if str(args.authoritative_root).strip()
        else (root / "tmp" / f"cohort0_targeted_hypertraining_import_{utc_now_compact_z()}").resolve()
    )
    payload = run_targeted_hypertraining_import_tranche(
        bundle_zip=_resolve(root, str(args.bundle_zip)),
        authoritative_root=authoritative_root,
        reports_root=_resolve(root, str(args.reports_root)),
        stage_input_receipt_path=_resolve(root, str(args.stage_input_receipt)),
        stage_manifest_path=_resolve(root, str(args.stage_manifest)),
        dataset_manifest_path=_resolve(root, str(args.dataset_manifest)),
        kaggle_packet_path=_resolve(root, str(args.kaggle_packet)),
        freeze_boundary_path=_resolve(root, str(args.freeze_boundary)),
        workspace_root=root,
    )
    print(
        json.dumps(
            {
                "status": payload["import_receipt"]["status"],
                "grade": payload["grade_receipt"]["grade"],
                "followthrough_posture": payload["followthrough_packet"]["followthrough_posture"],
                "next_lawful_move": payload["followthrough_packet"]["composite_substrate_requirement"]["next_lawful_move"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
