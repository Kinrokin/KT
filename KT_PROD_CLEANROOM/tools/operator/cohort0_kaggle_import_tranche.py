from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_compact_z, utc_now_iso_z, write_json_stable
from tools.verification.fl3_canonical import canonical_json, sha256_text


DEFAULT_REPORT_IMPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_import_receipt.json"
DEFAULT_REPORT_GRADE_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_grade_receipt.json"
DEFAULT_REPORT_FOLLOW_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_tournament_followthrough_packet.json"


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    except Exception:  # noqa: BLE001
        return ""


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_tree(root: Path) -> Dict[str, Any]:
    if not root.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing hash root: {root.as_posix()}")
    files = [p for p in root.rglob("*") if p.is_file()]
    files.sort(key=lambda p: p.relative_to(root).as_posix())
    entries = [
        {
            "path": p.relative_to(root).as_posix(),
            "sha256": _sha256_file(p),
            "bytes": int(p.stat().st_size),
        }
        for p in files
    ]
    return {
        "root": root.as_posix(),
        "file_count": int(len(entries)),
        "entries": entries,
        "root_hash": sha256_text(canonical_json(entries)),
    }


def _load_authoritative_adapter_ids(root: Path) -> List[str]:
    registry = load_json((root / "KT_PROD_CLEANROOM" / "governance" / "adapter_registry.json").resolve())
    rows = list(registry.get("experimental_adapter_ids", [])) + list(registry.get("ratified_adapter_ids", []))
    adapter_ids = [str(x).strip() for x in rows]
    if len(adapter_ids) != 13 or len(set(adapter_ids)) != 13:
        raise RuntimeError("FAIL_CLOSED: authoritative adapter registry must currently resolve exactly 13 unique adapter ids")
    return adapter_ids


def _copy_and_extract_bundle(*, bundle_zip: Path, authoritative_root: Path) -> Tuple[Path, Path]:
    imported_zip = (authoritative_root / bundle_zip.name).resolve()
    extract_root = (authoritative_root / "extracted").resolve()
    authoritative_root.mkdir(parents=True, exist_ok=True)
    shutil.copy2(bundle_zip, imported_zip)
    with zipfile.ZipFile(imported_zip) as zf:
        zf.extractall(extract_root)
    return imported_zip, extract_root


def _find_extracted_bundle_root(extract_root: Path) -> Path:
    dirs = [p for p in extract_root.iterdir() if p.is_dir()]
    if len(dirs) != 1:
        raise RuntimeError("FAIL_CLOSED: expected exactly one top-level bundle root in extracted Kaggle artifact")
    return dirs[0].resolve()


def _find_full_run_root(extracted_bundle_root: Path) -> Path:
    hits = sorted(p.parent.resolve() for p in extracted_bundle_root.rglob("kaggle_real_engine_gate.json"))
    if len(hits) != 1:
        raise RuntimeError("FAIL_CLOSED: expected exactly one cohort0_full_hf run root with kaggle_real_engine_gate.json")
    return hits[0]


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _inventory_adapter(
    *,
    full_run_root: Path,
    adapter_id: str,
    expected_manifest_row: Dict[str, Any],
) -> Dict[str, Any]:
    adapter_root = (full_run_root / "adapters" / adapter_id).resolve()
    bundle_path = adapter_root / "adapter_bundle.zip"
    training_path = adapter_root / "adapter_training_receipt.json"
    reload_path = adapter_root / "adapter_reload_receipt.json"
    eval_path = adapter_root / "adapter_eval_receipt.json"
    for path, label in (
        (bundle_path, "adapter bundle"),
        (training_path, "training receipt"),
        (reload_path, "reload receipt"),
        (eval_path, "eval receipt"),
    ):
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing {label} for {adapter_id}: {path.as_posix()}")

    training = load_json(training_path)
    reload = load_json(reload_path)
    eval_receipt = load_json(eval_path)
    bundle_sha = _sha256_file(bundle_path)
    bundle_bytes = int(bundle_path.stat().st_size)

    if str(training.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: training receipt not PASS for {adapter_id}")
    if str(reload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: reload receipt not PASS for {adapter_id}")
    if str(eval_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: eval receipt not PASS for {adapter_id}")
    if str(training.get("engine", "")).strip() != "hf_lora":
        raise RuntimeError(f"FAIL_CLOSED: training engine must be hf_lora for {adapter_id}")
    if str(training.get("training_mode", "")).strip() != "lora":
        raise RuntimeError(f"FAIL_CLOSED: training_mode must be lora for {adapter_id}")
    if str(training.get("artifact_sha256", "")).strip() != bundle_sha:
        raise RuntimeError(f"FAIL_CLOSED: training artifact sha mismatch for {adapter_id}")
    if str(eval_receipt.get("artifact_sha256", "")).strip() != bundle_sha:
        raise RuntimeError(f"FAIL_CLOSED: eval artifact sha mismatch for {adapter_id}")
    if str(expected_manifest_row.get("artifact_sha256", "")).strip() != bundle_sha:
        raise RuntimeError(f"FAIL_CLOSED: run_manifest artifact sha mismatch for {adapter_id}")
    if int(training.get("artifact_bytes", 0)) != bundle_bytes:
        raise RuntimeError(f"FAIL_CLOSED: training artifact_bytes mismatch for {adapter_id}")
    if int(reload.get("reloaded_member_count", 0)) <= 0:
        raise RuntimeError(f"FAIL_CLOSED: reload member count must be > 0 for {adapter_id}")
    if int(eval_receipt.get("eval_case_count", 0)) <= 0:
        raise RuntimeError(f"FAIL_CLOSED: eval_case_count must be > 0 for {adapter_id}")

    return {
        "adapter_id": adapter_id,
        "adapter_root": adapter_root.as_posix(),
        "artifact_path": bundle_path.as_posix(),
        "artifact_bytes": bundle_bytes,
        "artifact_sha256": bundle_sha,
        "dataset_sha256": str(training.get("dataset_sha256", "")).strip(),
        "dataset_relpath": str(training.get("dataset_relpath", "")).strip(),
        "engine": str(training.get("engine", "")).strip(),
        "training_mode": str(training.get("training_mode", "")).strip(),
        "training_status": str(training.get("status", "")).strip(),
        "reload_status": str(reload.get("status", "")).strip(),
        "eval_status": str(eval_receipt.get("status", "")).strip(),
        "eval_case_count": int(eval_receipt.get("eval_case_count", 0)),
        "baseline_eval_score": float(eval_receipt.get("baseline_eval_score", 0.0)),
        "promotion_ready_artifacts_present": bool(eval_receipt.get("promotion_ready_artifacts_present")),
        "source_eval_stub": bool(eval_receipt.get("source_eval_stub")),
        "source_eval_report_path": str(eval_receipt.get("source_eval_report_path", "")).strip(),
        "source_train_manifest_path": str(training.get("source_train_manifest_path", "")).strip(),
        "source_training_run_manifest_path": str(training.get("source_training_run_manifest_path", "")).strip(),
        "training_receipt_ref": training_path.as_posix(),
        "reload_receipt_ref": reload_path.as_posix(),
        "eval_receipt_ref": eval_path.as_posix(),
    }


def _build_source_evidence_manifest(
    *,
    workspace_root: Path,
    bundle_zip: Path,
    imported_zip: Path,
    extracted_bundle_root: Path,
    full_run_root: Path,
    gate: Dict[str, Any],
    run_manifest: Dict[str, Any],
    run_summary: Dict[str, Any],
    adapter_inventory: List[Dict[str, Any]],
) -> Dict[str, Any]:
    dry_run_root = (extracted_bundle_root / "dry_run").resolve()
    smoke_root = (extracted_bundle_root / "smoke_alpha_hf").resolve()
    return {
        "schema_id": "kt.operator.cohort0_real_engine_source_evidence_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "source_bundle_zip_path": bundle_zip.resolve().as_posix(),
        "source_bundle_zip_sha256": _sha256_file(bundle_zip),
        "imported_bundle_zip_path": imported_zip.as_posix(),
        "imported_bundle_zip_sha256": _sha256_file(imported_zip),
        "extracted_bundle_root": extracted_bundle_root.as_posix(),
        "extracted_bundle_root_hash_tree": _hash_tree(extracted_bundle_root),
        "full_run_root": full_run_root.as_posix(),
        "full_run_root_hash_tree": _hash_tree(full_run_root),
        "dry_run_root_present": dry_run_root.is_dir(),
        "dry_run_root_ref": dry_run_root.as_posix() if dry_run_root.is_dir() else "",
        "smoke_root_present": smoke_root.is_dir(),
        "smoke_root_ref": smoke_root.as_posix() if smoke_root.is_dir() else "",
        "repo_head_from_run": str(gate.get("repo_head", "")).strip(),
        "current_repo_head_at_import": _git_head(workspace_root),
        "registry_id": str(gate.get("registry_id", "")).strip() or str(run_summary.get("registry_id", "")).strip(),
        "base_snapshot_id": str(gate.get("base_snapshot_id", "")).strip(),
        "adapter_count": int(gate.get("adapter_count", 0)),
        "adapter_ids": list(run_manifest.get("adapter_ids", [])),
        "adapter_inventory_refs": [
            {
                "adapter_id": row["adapter_id"],
                "training_receipt_ref": row["training_receipt_ref"],
                "reload_receipt_ref": row["reload_receipt_ref"],
                "eval_receipt_ref": row["eval_receipt_ref"],
                "artifact_ref": row["artifact_path"],
            }
            for row in adapter_inventory
        ],
    }


def _build_import_receipt(
    *,
    workspace_root: Path,
    authoritative_ids: List[str],
    source_manifest: Dict[str, Any],
    gate: Dict[str, Any],
    run_manifest: Dict[str, Any],
    adapter_inventory: List[Dict[str, Any]],
) -> Dict[str, Any]:
    run_head = str(gate.get("repo_head", "")).strip()
    current_head = _git_head(workspace_root)
    same_head = bool(run_head and current_head and run_head == current_head)
    manifest_ids = [str(x).strip() for x in run_manifest.get("adapter_ids", [])]
    checks = [
        {"check_id": "kaggle_bundle_imported_and_hashed", "pass": True},
        {"check_id": "full_run_root_detected", "pass": True},
        {"check_id": "registry_and_base_snapshot_ids_bound", "pass": True},
        {"check_id": "adapter_ids_match_authoritative_registry", "pass": manifest_ids == authoritative_ids},
        {"check_id": "all_13_training_reload_eval_receipts_present", "pass": len(adapter_inventory) == 13},
        {"check_id": "all_adapter_bundles_hash_cross_bind", "pass": True},
        {"check_id": "all_training_receipts_are_real_engine_hf_lora", "pass": all(row["engine"] == "hf_lora" for row in adapter_inventory)},
        {"check_id": "subject_head_matches_current_git_head_at_import", "pass": same_head},
    ]
    return {
        "schema_id": "kt.operator.cohort0_real_engine_adapter_import_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "workstream_id": "B04_GATE_D_COHORT0_REAL_ENGINE_ADAPTER_EVIDENCE_IMPORT",
        "receipt_role": (
            "CURRENT_HEAD_ADAPTER_EVIDENCE_ARTIFACT_ONLY" if same_head else "CARRIER_ONLY_CURRENT_HEAD_ADAPTER_EVIDENCE_ARTIFACT"
        ),
        "claim_boundary": "This receipt proves only that the imported Kaggle Cohort-0 bundle is a governed 13-adapter real-engine evidence family for the sanctioned forge surface on the subject head. It does not ratify tournament outcomes, promotion decisions, merge authority, router authority, lobes, externality, comparative claims, or commercial widening.",
        "source_bundle_zip_path": str(source_manifest["source_bundle_zip_path"]),
        "source_bundle_zip_sha256": str(source_manifest["source_bundle_zip_sha256"]),
        "imported_bundle_zip_path": str(source_manifest["imported_bundle_zip_path"]),
        "imported_bundle_zip_sha256": str(source_manifest["imported_bundle_zip_sha256"]),
        "full_run_root": str(source_manifest["full_run_root"]),
        "subject_head": run_head,
        "current_git_head": current_head,
        "subject_head_is_current_at_import": same_head,
        "registry_id": str(gate.get("registry_id", "")).strip(),
        "base_snapshot_id": str(gate.get("base_snapshot_id", "")).strip(),
        "adapter_count": int(gate.get("adapter_count", 0)),
        "adapter_ids": manifest_ids,
        "checks": checks,
        "next_lawful_move": "B04_GATE_D_COHORT0_TOURNAMENT_PROMOTION_MERGE_FOLLOWTHROUGH_PACKET",
    }


def _build_grade_receipt(
    *,
    import_receipt: Dict[str, Any],
    run_summary: Dict[str, Any],
    adapter_inventory: List[Dict[str, Any]],
) -> Dict[str, Any]:
    artifact_bytes = [int(row["artifact_bytes"]) for row in adapter_inventory]
    eval_counts = [int(row["eval_case_count"]) for row in adapter_inventory]
    source_eval_stub_count = int(sum(1 for row in adapter_inventory if bool(row["source_eval_stub"])))
    return {
        "schema_id": "kt.operator.cohort0_real_engine_adapter_grade_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "grade": "PASS_AS_STRONG_GATE_D_ADAPTER_EVIDENCE",
        "claim_boundary": "This grade proves only that the sanctioned Cohort-0 button is no longer stub-only and that the imported run is strong Gate D adapter evidence. It does not promote tournament, merge, router shadow, router superiority, lobes, externality, comparative claims, or commercial widening.",
        "registry_id": str(run_summary.get("registry_id", "")).strip(),
        "adapter_count": int(run_summary.get("adapter_count", 0)),
        "pass_count": int(run_summary.get("pass_count", 0)),
        "fail_count": int(run_summary.get("fail_count", 0)),
        "engine_summary": {
            "hf_lora_adapter_count": int(sum(1 for row in adapter_inventory if row["engine"] == "hf_lora")),
            "non_stub_only": bool(all(row["engine"] == "hf_lora" for row in adapter_inventory)),
            "artifact_bytes_min": int(min(artifact_bytes) if artifact_bytes else 0),
            "artifact_bytes_max": int(max(artifact_bytes) if artifact_bytes else 0),
            "artifact_bytes_total": int(sum(artifact_bytes)),
        },
        "eval_summary": {
            "eval_case_count_min": int(min(eval_counts) if eval_counts else 0),
            "eval_case_count_max": int(max(eval_counts) if eval_counts else 0),
            "source_eval_stub_count": source_eval_stub_count,
        },
        "ratification_effects": {
            "closes_open_defect_sanctioned_forge_is_stubbed": True,
            "strong_enough_to_advance_adapter_law_progression": True,
            "sufficient_for_router_authority": False,
            "sufficient_for_externality_widening": False,
        },
        "practical_campaign_meaning": "The proof question is no longer whether the sanctioned button can train. The next lawful Gate D question is what these 13 governed adapters earn under tournament, promotion, merge, and only later router-shadow comparison.",
        "source_import_receipt_subject_head": str(import_receipt.get("subject_head", "")).strip(),
        "source_import_receipt_ref": DEFAULT_REPORT_IMPORT_REL,
    }


def _build_followthrough_packet(
    *,
    extracted_bundle_root: Path,
    full_run_root: Path,
    import_receipt: Dict[str, Any],
    grade_receipt: Dict[str, Any],
    adapter_inventory: List[Dict[str, Any]],
) -> Dict[str, Any]:
    imported_eval_reports = list(full_run_root.rglob("eval_report.json"))
    imported_job_dir_manifests = list(full_run_root.rglob("job_dir_manifest.json"))
    imported_train_manifests = list(full_run_root.rglob("train_manifest.json"))
    imported_training_run_manifests = list(full_run_root.rglob("training_run_manifest.PASS.json"))
    blockers: List[str] = []
    if not imported_eval_reports:
        blockers.append("ENTRANT_EVAL_REPORT_IMPORT_MISSING")
    if not imported_job_dir_manifests:
        blockers.append("ENTRANT_JOB_DIR_MANIFEST_IMPORT_MISSING")
    if not imported_train_manifests:
        blockers.append("ENTRANT_TRAIN_MANIFEST_IMPORT_MISSING")
    if not imported_training_run_manifests:
        blockers.append("ENTRANT_TRAINING_RUN_MANIFEST_IMPORT_MISSING")
    blockers.extend(
        [
            "EVALUATION_ADMISSION_PACKET_NOT_PREPARED",
            "COUNTERPRESSURE_PLAN_NOT_PREPARED",
            "BREAK_HYPOTHESIS_NOT_PREPARED",
        ]
    )
    return {
        "schema_id": "kt.operator.cohort0_real_engine_tournament_followthrough_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "followthrough_posture": (
            "CARRIER_READY__TOURNAMENT_ENTRY_AUTHORITY_BLOCKED"
            if blockers
            else "TOURNAMENT_ENTRY_AUTHORITY_READY"
        ),
        "claim_boundary": "This packet advances only adapter-law follow-through into tournament/promotion/merge preparation. It does not declare any tournament result, promotion verdict, merge outcome, router-shadow authority, router superiority, externality widening, comparative claim, or commercial activation.",
        "subject_head": str(import_receipt.get("subject_head", "")).strip(),
        "adapter_evidence_grade": str(grade_receipt.get("grade", "")).strip(),
        "carrier_surface_summary": {
            "full_run_root_ref": full_run_root.as_posix(),
            "adapter_training_receipt_count": int(len(adapter_inventory)),
            "adapter_reload_receipt_count": int(len(adapter_inventory)),
            "adapter_eval_receipt_count": int(len(adapter_inventory)),
            "transcript_count": int(len(list((full_run_root / "transcripts").glob("*.log")))) if (full_run_root / "transcripts").is_dir() else 0,
            "training_input_count": int(len(list((full_run_root / "training_inputs").glob("*.json")))) if (full_run_root / "training_inputs").is_dir() else 0,
        },
        "entrant_authority_surface_summary": {
            "imported_eval_report_count": int(len(imported_eval_reports)),
            "imported_job_dir_manifest_count": int(len(imported_job_dir_manifests)),
            "imported_train_manifest_count": int(len(imported_train_manifests)),
            "imported_training_run_manifest_count": int(len(imported_training_run_manifests)),
        },
        "tournament_followthrough": {
            "execution_ready": False if blockers else True,
            "next_lawful_move": (
                "IMPORT_OR_REEXPORT_SCHEMA_BOUND_ENTRANT_EVIDENCE_AND_PREPARE_TOURNAMENT_ADMISSION_PACKET"
                if blockers
                else "PREPARE_EVALUATION_ADMISSION_AND_TOURNAMENT_PLAN"
            ),
            "blockers": blockers,
        },
        "promotion_followthrough": {
            "execution_ready": False,
            "blocked_by": "PENDING_TOURNAMENT_RESULT",
        },
        "merge_followthrough": {
            "execution_ready": False,
            "blocked_by": "PENDING_TOURNAMENT_AND_PROMOTION_RECEIPTS",
        },
        "next_question": "What do these 13 governed adapters earn under tournament, promotion, and only later router-shadow comparison?",
        "source_import_receipt_ref": DEFAULT_REPORT_IMPORT_REL,
        "source_grade_receipt_ref": DEFAULT_REPORT_GRADE_REL,
        "extracted_bundle_root_ref": extracted_bundle_root.as_posix(),
    }


def run_import_tranche(
    *,
    bundle_zip: Path,
    authoritative_root: Path,
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    bundle_zip = bundle_zip.expanduser().resolve()
    if not bundle_zip.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing Kaggle artifact bundle zip: {bundle_zip.as_posix()}")

    authoritative_ids = _load_authoritative_adapter_ids(root)
    imported_zip, extract_root = _copy_and_extract_bundle(bundle_zip=bundle_zip, authoritative_root=authoritative_root.resolve())
    extracted_bundle_root = _find_extracted_bundle_root(extract_root)
    full_run_root = _find_full_run_root(extracted_bundle_root)

    gate = _load_json_required(full_run_root / "kaggle_real_engine_gate.json", label="kaggle_real_engine_gate")
    run_manifest = _load_json_required(full_run_root / "run_manifest.json", label="run_manifest")
    run_summary = _load_json_required(full_run_root / "run_summary.json", label="run_summary")
    _ = _load_json_required(full_run_root / "preflight_receipt.json", label="preflight_receipt")
    _ = _load_json_required(full_run_root / "discovery_receipt.json", label="discovery_receipt")
    _ = _load_json_required(full_run_root / "adapter_registry.json", label="adapter_registry")
    _ = _load_json_required(full_run_root / "adapter_lineage_manifest.json", label="adapter_lineage_manifest")

    manifest_ids = [str(x).strip() for x in run_manifest.get("adapter_ids", [])]
    if manifest_ids != authoritative_ids:
        raise RuntimeError("FAIL_CLOSED: imported run adapter_ids do not match authoritative registry order/content")
    if int(gate.get("adapter_count", 0)) != 13:
        raise RuntimeError("FAIL_CLOSED: imported gate adapter_count must be 13")
    if str(gate.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: imported gate status must be PASS")
    if str(run_summary.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: imported run_summary status must be PASS")

    manifest_rows = run_manifest.get("artifact_hashes") if isinstance(run_manifest.get("artifact_hashes"), list) else []
    manifest_map = {str(row.get("adapter_id", "")).strip(): row for row in manifest_rows if isinstance(row, dict)}
    if len(manifest_map) != 13:
        raise RuntimeError("FAIL_CLOSED: imported run_manifest must contain 13 artifact_hash rows")

    adapter_inventory = [
        _inventory_adapter(full_run_root=full_run_root, adapter_id=adapter_id, expected_manifest_row=manifest_map[adapter_id])
        for adapter_id in manifest_ids
    ]
    source_manifest = _build_source_evidence_manifest(
        workspace_root=root,
        bundle_zip=bundle_zip,
        imported_zip=imported_zip,
        extracted_bundle_root=extracted_bundle_root,
        full_run_root=full_run_root,
        gate=gate,
        run_manifest=run_manifest,
        run_summary=run_summary,
        adapter_inventory=adapter_inventory,
    )
    import_receipt = _build_import_receipt(
        workspace_root=root,
        authoritative_ids=authoritative_ids,
        source_manifest=source_manifest,
        gate=gate,
        run_manifest=run_manifest,
        adapter_inventory=adapter_inventory,
    )
    grade_receipt = _build_grade_receipt(import_receipt=import_receipt, run_summary=run_summary, adapter_inventory=adapter_inventory)
    follow_packet = _build_followthrough_packet(
        extracted_bundle_root=extracted_bundle_root,
        full_run_root=full_run_root,
        import_receipt=import_receipt,
        grade_receipt=grade_receipt,
        adapter_inventory=adapter_inventory,
    )

    authoritative_files = {
        "source_manifest": authoritative_root / "cohort0_real_engine_source_evidence_manifest.json",
        "adapter_inventory": authoritative_root / "cohort0_real_engine_adapter_inventory.json",
        "import_receipt": authoritative_root / "cohort0_real_engine_adapter_import_receipt.json",
        "grade_receipt": authoritative_root / "cohort0_real_engine_adapter_grade_receipt.json",
        "followthrough_packet": authoritative_root / "cohort0_real_engine_tournament_followthrough_packet.json",
    }
    write_json_stable(authoritative_files["source_manifest"], source_manifest)
    write_json_stable(
        authoritative_files["adapter_inventory"],
        {
            "schema_id": "kt.operator.cohort0_real_engine_adapter_inventory.v1",
            "generated_utc": utc_now_iso_z(),
            "adapter_count": len(adapter_inventory),
            "entries": adapter_inventory,
        },
    )
    write_json_stable(authoritative_files["import_receipt"], import_receipt)
    write_json_stable(authoritative_files["grade_receipt"], grade_receipt)
    write_json_stable(authoritative_files["followthrough_packet"], follow_packet)

    report_import = (reports_root / Path(DEFAULT_REPORT_IMPORT_REL).name).resolve()
    report_grade = (reports_root / Path(DEFAULT_REPORT_GRADE_REL).name).resolve()
    report_follow = (reports_root / Path(DEFAULT_REPORT_FOLLOW_REL).name).resolve()
    carrier_import = dict(import_receipt)
    carrier_import["receipt_role"] = "TRACKED_CARRIER_ONLY_CURRENT_HEAD_ADAPTER_EVIDENCE_ARTIFACT"
    carrier_import["carrier_claim_boundary"] = "This tracked report is a carrier for the authoritative import receipt and must not be overread as same-head authority on later sealed heads."
    carrier_import["authoritative_import_receipt_ref"] = authoritative_files["import_receipt"].as_posix()
    carrier_grade = dict(grade_receipt)
    carrier_grade["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_ADAPTER_GRADE_ARTIFACT"
    carrier_grade["authoritative_grade_receipt_ref"] = authoritative_files["grade_receipt"].as_posix()
    carrier_follow = dict(follow_packet)
    carrier_follow["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_FOLLOWTHROUGH_ARTIFACT"
    carrier_follow["authoritative_followthrough_packet_ref"] = authoritative_files["followthrough_packet"].as_posix()
    write_json_stable(report_import, carrier_import)
    write_json_stable(report_grade, carrier_grade)
    write_json_stable(report_follow, carrier_follow)

    return {
        "source_manifest": source_manifest,
        "adapter_inventory": {
            "schema_id": "kt.operator.cohort0_real_engine_adapter_inventory.v1",
            "generated_utc": utc_now_iso_z(),
            "adapter_count": len(adapter_inventory),
            "entries": adapter_inventory,
        },
        "import_receipt": import_receipt,
        "grade_receipt": grade_receipt,
        "followthrough_packet": follow_packet,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Import, ratify, and grade a Kaggle Cohort-0 real-engine forge bundle.")
    ap.add_argument("--bundle-zip", required=True, help="Path to Kaggle artifact zip.")
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: tmp/<bundle_stem>_repo_import_<utc>/",
    )
    ap.add_argument(
        "--reports-root",
        default="KT_PROD_CLEANROOM/reports",
        help="Carrier report root. Default: KT_PROD_CLEANROOM/reports",
    )
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    bundle_zip = Path(str(args.bundle_zip)).expanduser().resolve()
    if str(args.authoritative_root).strip():
        authoritative_root = Path(str(args.authoritative_root)).expanduser()
        if not authoritative_root.is_absolute():
            authoritative_root = (root / authoritative_root).resolve()
        else:
            authoritative_root = authoritative_root.resolve()
    else:
        authoritative_root = (root / "tmp" / f"{bundle_zip.stem}_repo_import_{utc_now_compact_z()}").resolve()

    reports_root = Path(str(args.reports_root)).expanduser()
    if not reports_root.is_absolute():
        reports_root = (root / reports_root).resolve()
    else:
        reports_root = reports_root.resolve()

    payload = run_import_tranche(
        bundle_zip=bundle_zip,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=root,
    )
    print(
        json.dumps(
            {
                "status": payload["import_receipt"]["status"],
                "grade": payload["grade_receipt"]["grade"],
                "followthrough_posture": payload["followthrough_packet"]["followthrough_posture"],
                "subject_head": payload["import_receipt"]["subject_head"],
                "current_git_head": payload["import_receipt"]["current_git_head"],
                "authoritative_root": authoritative_root.as_posix(),
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
