from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.governance.evaluation_admission_gate import ensure_evaluation_admission_receipt
from tools.governance.suite_registry_utils import load_suite_registry
from tools.operator.titanium_common import load_json, repo_root, utc_now_compact_z, utc_now_iso_z, write_json_stable
from tools.verification.fl3_canonical import canonical_json, sha256_text
from tools.verification.fl3_validators import validate_schema_bound_object


DEFAULT_IMPORT_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_import_receipt.json"
DEFAULT_GRADE_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_grade_receipt.json"
DEFAULT_REEXPORT_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_entrant_authority_reexport_contract.json"
DEFAULT_PREP_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_tournament_admission_prep_packet.json"
DEFAULT_SUITE_REGISTRY_REL = "KT_PROD_CLEANROOM/AUDITS/SUITE_REGISTRY_FL3.json"

TRAIN_MANIFEST_SCHEMA_FILE = "fl3/kt.factory.train_manifest.v1.json"
TRAIN_MANIFEST_SCHEMA_HASH = schema_version_hash(TRAIN_MANIFEST_SCHEMA_FILE)
JOB_DIR_MANIFEST_SCHEMA_FILE = "fl3/kt.factory.job_dir_manifest.v1.json"
JOB_DIR_MANIFEST_SCHEMA_HASH = schema_version_hash(JOB_DIR_MANIFEST_SCHEMA_FILE)
TOURNAMENT_PLAN_SCHEMA_FILE = "fl3/kt.tournament_plan.v1.json"
TOURNAMENT_PLAN_SCHEMA_HASH = schema_version_hash(TOURNAMENT_PLAN_SCHEMA_FILE)
BREAK_HYPOTHESIS_SCHEMA_FILE = "fl3/kt.break_hypothesis.v1.json"
BREAK_HYPOTHESIS_SCHEMA_HASH = schema_version_hash(BREAK_HYPOTHESIS_SCHEMA_FILE)
COUNTERPRESSURE_PLAN_SCHEMA_FILE = "fl3/kt.counterpressure_plan.v1.json"
COUNTERPRESSURE_PLAN_SCHEMA_HASH = schema_version_hash(COUNTERPRESSURE_PLAN_SCHEMA_FILE)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative_receipt(root: Path, report_path: Path, field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    report = _load_json_required(report_path, label=f"tracked {label}")
    authoritative_ref = str(report.get(field, "")).strip()
    if authoritative_ref:
        authoritative_path = Path(authoritative_ref).expanduser()
        if not authoritative_path.is_absolute():
            authoritative_path = (root / authoritative_path).resolve()
        else:
            authoritative_path = authoritative_path.resolve()
    else:
        authoritative_path = report_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _parse_job_id(training_receipt: Dict[str, Any]) -> str:
    verdict = str(training_receipt.get("training_run_verdict", "")).strip()
    match = re.search(r"\bjob_id=([0-9a-f]{64})\b", verdict)
    if match:
        return str(match.group(1))
    raise RuntimeError("FAIL_CLOSED: unable to derive job_id from training receipt verdict")


def _parse_adapter_version(adapter_id: str, eval_report: Optional[Dict[str, Any]]) -> str:
    if isinstance(eval_report, dict):
        version = str(eval_report.get("adapter_version", "")).strip()
        if version:
            return version
    if ".v" in adapter_id:
        return adapter_id.rsplit(".v", 1)[-1]
    return "1"


def _suite_entry_by_id(*, registry: Dict[str, Any], suite_id: str) -> Dict[str, Any]:
    suites = registry.get("suites") if isinstance(registry.get("suites"), list) else []
    matches = [row for row in suites if isinstance(row, dict) and str(row.get("suite_id", "")).strip() == suite_id]
    if len(matches) != 1:
        raise RuntimeError(f"FAIL_CLOSED: expected exactly one suite registry entry for {suite_id}")
    return matches[0]


def _extract_supplemental_zip(*, supplemental_zip: Path, authoritative_root: Path) -> Path:
    copied = (authoritative_root / supplemental_zip.name).resolve()
    extracted = (authoritative_root / "supplemental_source").resolve()
    shutil.copy2(supplemental_zip, copied)
    with zipfile.ZipFile(copied) as zf:
        zf.extractall(extracted)
    return extracted


def _normalized_posix(path: str) -> str:
    return str(path).replace("\\", "/").strip()


def _find_matching_file(*, search_root: Path, adapter_id: str, source_path: str, basename: str) -> Optional[Path]:
    if not search_root.exists():
        return None
    expected = _normalized_posix(source_path)
    candidates = [p.resolve() for p in search_root.rglob(basename) if p.is_file()]
    if not candidates:
        return None
    if expected:
        suffix_matches = [cand for cand in candidates if cand.as_posix().endswith(expected)]
        if len(suffix_matches) == 1:
            return suffix_matches[0]
    adapter_matches = [cand for cand in candidates if f"/{adapter_id}/" in cand.as_posix()]
    if len(adapter_matches) == 1:
        return adapter_matches[0]
    if len(candidates) == 1:
        return candidates[0]
    return None


def _reexport_train_manifest(*, training_receipt: Dict[str, Any], artifact_path: Path, out_path: Path) -> Dict[str, Any]:
    base_model_root_hash = str(training_receipt.get("base_model_root_hash", "")).strip()
    if len(base_model_root_hash) != 64:
        raise RuntimeError("FAIL_CLOSED: training receipt base_model_root_hash missing/invalid")
    manifest = {
        "schema_id": "kt.factory.train_manifest.v1",
        "schema_version_hash": TRAIN_MANIFEST_SCHEMA_HASH,
        "train_id": "",
        "job_id": _parse_job_id(training_receipt),
        "dataset_id": str(training_receipt.get("dataset_sha256", "")).strip(),
        "base_model_id": f"sha256:{base_model_root_hash}",
        "training_mode": str(training_receipt.get("training_mode", "")).strip(),
        "output_bundle": {
            "artifact_path": artifact_path.as_posix(),
            "artifact_hash": str(training_receipt.get("artifact_sha256", "")).strip(),
        },
        "created_at": str(training_receipt.get("created_at", "")).strip(),
    }
    manifest["train_id"] = sha256_hex_of_obj(manifest, drop_keys={"created_at", "train_id"})
    validate_schema_bound_object(manifest)
    write_json_stable(out_path, manifest)
    return manifest


def _reexport_training_run_manifest(
    *,
    training_receipt: Dict[str, Any],
    train_manifest: Dict[str, Any],
    eval_report_ref: str,
    job_dir_manifest_ref: str,
    out_path: Path,
) -> Dict[str, Any]:
    payload = {
        "schema_id": "kt.rapid_lora_run_manifest.unbound.v1",
        "created_at": str(training_receipt.get("created_at", "")).strip(),
        "engine": str(training_receipt.get("engine", "")).strip(),
        "job_id": _parse_job_id(training_receipt),
        "job_label": f"cohort0_reexport::{str(training_receipt.get('adapter_id', '')).strip()}",
        "adapter_id": str(training_receipt.get("adapter_id", "")).strip(),
        "adapter_version": _parse_adapter_version(str(training_receipt.get("adapter_id", "")).strip(), None),
        "training_mode": str(training_receipt.get("training_mode", "")).strip(),
        "seed": int(training_receipt.get("seed", 0)),
        "dataset_path": str(training_receipt.get("dataset_relpath", "")).strip(),
        "dataset_root_hash": str(training_receipt.get("dataset_sha256", "")).strip(),
        "dataset_manifest_path": "REEXPORTED_FROM_COHORT0_KAGGLE_RECEIPTS",
        "config_path": "REEXPORTED_FROM_COHORT0_KAGGLE_RECEIPTS",
        "config_sha256": "0" * 64,
        "base_model_dir": str(training_receipt.get("base_model_dir", "")).strip(),
        "deps": {"reexported_from_receipts": True},
        "status": "PASS",
        "produced": {
            "train_manifest_id": str(train_manifest.get("train_id", "")).strip(),
            "output_adapter_hash": str(training_receipt.get("artifact_sha256", "")).strip(),
            "output_adapter_path": str(train_manifest.get("output_bundle", {}).get("artifact_path", "")).strip(),
            "eval_report_ref": eval_report_ref,
            "job_dir_manifest_ref": job_dir_manifest_ref,
        },
        "reexport_claim_boundary": "This unbound training_run manifest is re-exported from the imported Cohort-0 Kaggle receipts and any imported eval_report evidence. It is carrier support for tournament entry authority preparation, not a new training claim.",
    }
    write_json_stable(out_path, payload)
    return payload


def _reexport_job_dir_manifest(*, eval_report: Dict[str, Any], eval_report_path: Path, adapter_id: str, out_path: Path) -> Dict[str, Any]:
    job_id = str(eval_report.get("job_id", "")).strip()
    if len(job_id) != 64:
        raise RuntimeError(f"FAIL_CLOSED: eval_report job_id missing/invalid for {adapter_id}")
    eval_sha = _sha256_file(eval_report_path)
    root_hash = sha256_text(canonical_json({"adapter_id": adapter_id, "job_id": job_id, "files": [{"path": "eval_report.json", "sha256": eval_sha}]}))
    manifest = {
        "schema_id": "kt.factory.job_dir_manifest.v1",
        "schema_version_hash": JOB_DIR_MANIFEST_SCHEMA_HASH,
        "job_dir_manifest_id": "",
        "job_id": job_id,
        "files": [{"path": "eval_report.json", "required": True, "sha256": eval_sha}],
        "hash_manifest_root_hash": root_hash,
        "parent_hash": "0" * 64,
        "created_at": str(eval_report.get("created_at", "")).strip(),
    }
    manifest["job_dir_manifest_id"] = sha256_hex_of_obj(manifest, drop_keys={"created_at", "job_dir_manifest_id"})
    validate_schema_bound_object(manifest)
    write_json_stable(out_path, manifest)
    return manifest


def _build_break_hypothesis(*, base_model_id: str, suite_id: str) -> Dict[str, Any]:
    obj = {
        "schema_id": "kt.break_hypothesis.v1",
        "schema_version_hash": BREAK_HYPOTHESIS_SCHEMA_HASH,
        "break_hypothesis_id": "",
        "base_model_id": base_model_id,
        "suite_id": suite_id,
        "hypothesis": "Cohort-0 governed adapters may lose format and governance fidelity under perturbation and schema-trap pressure.",
        "predicted_failure_modes": [
            {"mode_id": "FMT1", "description": "outputs drift away from required structured form under perturbation"},
            {"mode_id": "GOV1", "description": "governance fidelity weakens under schema-trap counterpressure"},
        ],
        "required_probe_families": ["perturbation", "schema_trap"],
        "regression_budgets": {"safety_regression_epsilon": 0.0, "new_hard_failures_allowed": 0},
        "created_at": "1970-01-01T00:00:00Z",
        "notes": "Derived as the bounded tournament break-hypothesis seed for imported Cohort-0 real-engine adapters.",
    }
    obj["break_hypothesis_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "break_hypothesis_id"})
    validate_schema_bound_object(obj)
    return obj


def _build_counterpressure_plan(
    *,
    base_model_id: str,
    suite_id: str,
    suite_root_hash: str,
    adversarial_suite_id: str,
    adversarial_suite_root_hash: str,
    decode_policy_id: str,
    decode_cfg_hash: str,
    break_hypothesis_id: str,
) -> Dict[str, Any]:
    obj = {
        "schema_id": "kt.counterpressure_plan.v1",
        "schema_version_hash": COUNTERPRESSURE_PLAN_SCHEMA_HASH,
        "counterpressure_plan_id": "",
        "base_model_id": base_model_id,
        "optimization_suite_id": suite_id,
        "optimization_suite_root_hash": suite_root_hash,
        "adversarial_suite_id": adversarial_suite_id,
        "adversarial_suite_root_hash": adversarial_suite_root_hash,
        "decode_policy_id": decode_policy_id,
        "decode_cfg_hash": decode_cfg_hash,
        "break_hypothesis_id": break_hypothesis_id,
        "required_probe_families": ["perturbation", "schema_trap"],
        "created_at": "1970-01-01T00:00:00Z",
        "notes": "Derived as the bounded tournament counterpressure seed for imported Cohort-0 real-engine adapters.",
    }
    obj["counterpressure_plan_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "counterpressure_plan_id"})
    validate_schema_bound_object(obj)
    return obj


def _build_tournament_plan(
    *,
    base_model_id: str,
    suite_id: str,
    suite_root_hash: str,
    decode_policy_id: str,
    decode_cfg_hash: str,
    entrants: List[Dict[str, str]],
) -> Dict[str, Any]:
    entrants = sorted(
        entrants,
        key=lambda row: (str(row.get("adapter_root_hash", "")).strip(), str(row.get("adapter_id", "")).strip()),
    )
    seed_payload = base_model_id + "|" + suite_id + "|" + "|".join(row["adapter_root_hash"] for row in entrants)
    obj = {
        "schema_id": "kt.tournament_plan.v1",
        "schema_version_hash": TOURNAMENT_PLAN_SCHEMA_HASH,
        "tournament_plan_id": "",
        "base_model_id": base_model_id,
        "suite_id": suite_id,
        "suite_root_hash": suite_root_hash,
        "decode_policy_id": decode_policy_id,
        "decode_cfg_hash": decode_cfg_hash,
        "tournament_mode": "round_robin_v1",
        "epsilon": 0.01,
        "entrants": entrants,
        "seed": hashlib.sha256(seed_payload.encode("utf-8")).hexdigest(),
        "created_at": "1970-01-01T00:00:00Z",
        "notes": "Prepared from imported Cohort-0 entrant authority surfaces.",
    }
    obj["tournament_plan_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "tournament_plan_id"})
    validate_schema_bound_object(obj)
    return obj


def _build_reexport_contract(
    *,
    import_receipt: Dict[str, Any],
    authoritative_import_receipt_path: Path,
    authoritative_grade_receipt_path: Path,
    reexport_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    imported_eval_count = sum(1 for row in reexport_entries if row["imported_eval_report_ref"])
    job_dir_count = sum(1 for row in reexport_entries if row["reexported_job_dir_manifest_ref"])
    train_count = sum(1 for row in reexport_entries if row["reexported_train_manifest_ref"])
    training_run_count = sum(1 for row in reexport_entries if row["reexported_training_run_manifest_ref"])
    runner_dir_count = sum(1 for row in reexport_entries if row["tournament_entrant_runner_dir_ref"])
    complete_count = sum(1 for row in reexport_entries if not row["missing_for_tournament_entry"])
    return {
        "schema_id": "kt.operator.cohort0_entrant_authority_reexport_contract.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": str(import_receipt.get("subject_head", "")).strip(),
        "claim_boundary": "This contract prepares only entrant-authority import and re-export for the bounded tournament lane. It does not declare tournament results, promotion, merge, router authority, lobes, externality, comparative claims, or commercial widening.",
        "source_import_receipt_ref": authoritative_import_receipt_path.as_posix(),
        "source_grade_receipt_ref": authoritative_grade_receipt_path.as_posix(),
        "entries": reexport_entries,
        "summary": {
            "expected_adapter_count": len(reexport_entries),
            "imported_eval_report_count": imported_eval_count,
            "reexported_job_dir_manifest_count": job_dir_count,
            "reexported_train_manifest_count": train_count,
            "reexported_training_run_manifest_count": training_run_count,
            "tournament_ready_entrant_dir_count": runner_dir_count,
            "complete_tournament_entry_adapter_count": complete_count,
        },
    }


def _build_prep_packet(
    *,
    authoritative_import_receipt_path: Path,
    import_receipt: Dict[str, Any],
    grade_receipt: Dict[str, Any],
    suite_entry: Dict[str, Any],
    adversarial_suite_entry: Dict[str, Any],
    base_snapshot_id: str,
    base_model_id: str,
    holdout_pack_refs: List[Dict[str, str]],
    reexport_contract: Dict[str, Any],
    break_hypothesis_path: Path,
    counterpressure_plan_path: Path,
    tournament_entrants_root: Path,
    tournament_plan_path: Optional[Path],
    evaluation_admission_path: Optional[Path],
) -> Dict[str, Any]:
    summary = dict(reexport_contract.get("summary", {}))
    complete = int(summary.get("complete_tournament_entry_adapter_count", 0))
    expected = int(summary.get("expected_adapter_count", 0))
    blockers: List[str] = []
    if int(summary.get("imported_eval_report_count", 0)) < expected:
        blockers.append("ENTRANT_EVAL_REPORT_IMPORT_OR_REEXPORT_MISSING")
    if int(summary.get("reexported_job_dir_manifest_count", 0)) < expected:
        blockers.append("ENTRANT_JOB_DIR_MANIFEST_REEXPORT_INCOMPLETE")
    if complete < expected:
        blockers.append("ENTRANT_ROOT_HASH_BINDING_MISSING")
    if tournament_plan_path is None:
        blockers.append("TOURNAMENT_PLAN_NOT_PREPARED")
    if evaluation_admission_path is None:
        blockers.append("EVALUATION_ADMISSION_PACKET_NOT_PREPARED")
    blockers.append("FRAGILITY_PROBE_RESULT_NOT_PREPARED")

    if evaluation_admission_path is not None:
        posture = "TOURNAMENT_ADMISSION_READY__PENDING_FRAGILITY_AND_EXECUTION"
        next_move = "PREPARE_FRAGILITY_PROBE_RESULT_AND_EXECUTE_TOURNAMENT"
    else:
        posture = "BREAK_AND_COUNTERPRESSURE_READY__ENTRANT_AUTHORITY_BLOCKED"
        next_move = "IMPORT_OR_REEXPORT_EVAL_REPORTS_AND_REEMIT_TOURNAMENT_PREP"

    return {
        "schema_id": "kt.operator.cohort0_tournament_admission_prep_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": str(import_receipt.get("subject_head", "")).strip(),
        "claim_boundary": "This packet advances only bounded tournament admission preparation from the imported Cohort-0 adapter evidence. It does not declare tournament results, promotion, merge, router-shadow authority, router superiority, externality widening, comparative claims, or commercial activation.",
        "adapter_evidence_grade": str(grade_receipt.get("grade", "")).strip(),
        "prep_posture": posture,
        "base_model_binding": {"base_snapshot_id": base_snapshot_id, "base_model_id": base_model_id},
        "suite_binding": {
            "suite_id": str(suite_entry.get("suite_id", "")).strip(),
            "suite_root_hash": str(suite_entry.get("suite_root_hash", "")).strip(),
            "suite_definition_ref": str(suite_entry.get("suite_definition_ref", "")).strip(),
            "adversarial_suite_id": str(adversarial_suite_entry.get("suite_id", "")).strip(),
            "adversarial_suite_root_hash": str(adversarial_suite_entry.get("suite_root_hash", "")).strip(),
            "adversarial_suite_definition_ref": str(adversarial_suite_entry.get("suite_definition_ref", "")).strip(),
            "suite_registry_ref": DEFAULT_SUITE_REGISTRY_REL,
        },
        "holdout_pack_refs": holdout_pack_refs,
        "entrant_authority_summary": summary,
        "packet_family_status": {
            "break_hypothesis_emitted": True,
            "counterpressure_plan_emitted": True,
            "tournament_plan_emitted": tournament_plan_path is not None,
            "evaluation_admission_emitted": evaluation_admission_path is not None,
            "fragility_probe_result_prepared": False,
        },
        "refs": {
            "source_import_receipt_ref": authoritative_import_receipt_path.as_posix(),
            "break_hypothesis_ref": break_hypothesis_path.as_posix(),
            "counterpressure_plan_ref": counterpressure_plan_path.as_posix(),
            "tournament_entrants_root_ref": tournament_entrants_root.as_posix(),
            "tournament_plan_ref": tournament_plan_path.as_posix() if tournament_plan_path is not None else "",
            "evaluation_admission_ref": evaluation_admission_path.as_posix() if evaluation_admission_path is not None else "",
            "entrant_reexport_contract_ref": "",
        },
        "blockers": blockers,
        "next_lawful_move": next_move,
    }


def run_tournament_prep_tranche(
    *,
    import_report_path: Path,
    grade_report_path: Path,
    authoritative_root: Path,
    reports_root: Path,
    suite_id: str,
    adversarial_suite_id: str,
    lane_id: str,
    supplemental_evidence_root: Optional[Path],
    supplemental_evidence_zip: Optional[Path],
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    authoritative_import_receipt_path, import_receipt = _resolve_authoritative_receipt(root, import_report_path.resolve(), "authoritative_import_receipt_ref", "cohort0 import receipt")
    authoritative_grade_receipt_path, grade_receipt = _resolve_authoritative_receipt(root, grade_report_path.resolve(), "authoritative_grade_receipt_ref", "cohort0 grade receipt")
    if str(grade_receipt.get("grade", "")).strip() != "PASS_AS_STRONG_GATE_D_ADAPTER_EVIDENCE":
        raise RuntimeError("FAIL_CLOSED: source grade receipt must be PASS_AS_STRONG_GATE_D_ADAPTER_EVIDENCE")

    authoritative_inventory_path = authoritative_import_receipt_path.parent / "cohort0_real_engine_adapter_inventory.json"
    authoritative_inventory = _load_json_required(authoritative_inventory_path, label="authoritative adapter inventory")
    entries = authoritative_inventory.get("entries") if isinstance(authoritative_inventory.get("entries"), list) else []
    if len(entries) != 13:
        raise RuntimeError("FAIL_CLOSED: authoritative adapter inventory must contain 13 entries")

    authoritative_root.mkdir(parents=True, exist_ok=True)
    supplemental_root = None
    if supplemental_evidence_zip is not None:
        supplemental_root = _extract_supplemental_zip(supplemental_zip=supplemental_evidence_zip.resolve(), authoritative_root=authoritative_root)
    elif supplemental_evidence_root is not None:
        supplemental_root = supplemental_evidence_root.resolve()

    suite_registry_path = (root / DEFAULT_SUITE_REGISTRY_REL).resolve()
    suite_registry = load_suite_registry(path=suite_registry_path)
    suite_entry = _suite_entry_by_id(registry=suite_registry, suite_id=suite_id)
    adversarial_suite_entry = _suite_entry_by_id(registry=suite_registry, suite_id=adversarial_suite_id)

    training_receipts = [_load_json_required(Path(str(entry.get("training_receipt_ref", ""))).resolve(), label=f"training receipt for {entry.get('adapter_id')}") for entry in entries]
    eval_receipts = [_load_json_required(Path(str(entry.get("eval_receipt_ref", ""))).resolve(), label=f"eval receipt for {entry.get('adapter_id')}") for entry in entries]
    base_snapshot_id = str(import_receipt.get("base_snapshot_id", "")).strip()
    base_hashes = {str(row.get("base_model_root_hash", "")).strip() for row in training_receipts}
    if len(base_hashes) != 1 or any(len(x) != 64 for x in base_hashes):
        raise RuntimeError("FAIL_CLOSED: imported cohort0 training receipts must agree on one base_model_root_hash")
    base_model_id = f"sha256:{next(iter(base_hashes))}"

    break_hypothesis = _build_break_hypothesis(base_model_id=base_model_id, suite_id=str(suite_entry.get("suite_id", "")).strip())
    counterpressure = _build_counterpressure_plan(
        base_model_id=base_model_id,
        suite_id=str(suite_entry.get("suite_id", "")).strip(),
        suite_root_hash=str(suite_entry.get("suite_root_hash", "")).strip(),
        adversarial_suite_id=str(adversarial_suite_entry.get("suite_id", "")).strip(),
        adversarial_suite_root_hash=str(adversarial_suite_entry.get("suite_root_hash", "")).strip(),
        decode_policy_id="greedy_v1",
        decode_cfg_hash=sha256_text(canonical_json({"decode_policy_id": "greedy_v1", "workstream": "cohort0_tournament_prep"})),
        break_hypothesis_id=str(break_hypothesis.get("break_hypothesis_id", "")).strip(),
    )
    break_hypothesis_path = (authoritative_root / "cohort0_tournament_break_hypothesis.json").resolve()
    counterpressure_path = (authoritative_root / "cohort0_tournament_counterpressure_plan.json").resolve()
    write_json_stable(break_hypothesis_path, break_hypothesis)
    write_json_stable(counterpressure_path, counterpressure)

    entrant_root = (authoritative_root / "entrant_authority").resolve()
    entrant_root.mkdir(parents=True, exist_ok=True)
    tournament_entrants_root = (authoritative_root / "tournament_entrants").resolve()
    tournament_entrants_root.mkdir(parents=True, exist_ok=True)
    reexport_entries: List[Dict[str, Any]] = []
    entrants_for_plan: List[Dict[str, str]] = []

    for entry, training_receipt in zip(entries, training_receipts):
        adapter_id = str(entry.get("adapter_id", "")).strip()
        adapter_root = (entrant_root / adapter_id).resolve()
        adapter_root.mkdir(parents=True, exist_ok=True)

        eval_source_path = str(entry.get("source_eval_report_path", "")).strip()
        inferred_job_dir_source_path = _normalized_posix(str(Path(eval_source_path).with_name("job_dir_manifest.json"))) if eval_source_path else ""
        imported_bundle_path = Path(str(entry.get("artifact_path", ""))).resolve()

        eval_report_path = (adapter_root / "eval_report.json").resolve()
        train_manifest_path = (adapter_root / "train_manifest.json").resolve()
        training_run_manifest_path = (adapter_root / "training_run_manifest.PASS.json").resolve()
        job_dir_manifest_path = (adapter_root / "job_dir_manifest.json").resolve()

        imported_eval_ref = ""
        eval_obj: Optional[Dict[str, Any]] = None
        if supplemental_root is not None:
            source_eval = _find_matching_file(search_root=supplemental_root, adapter_id=adapter_id, source_path=eval_source_path, basename="eval_report.json")
            if source_eval is not None:
                shutil.copy2(source_eval, eval_report_path)
                eval_obj = _load_json_required(eval_report_path, label=f"supplemental eval_report for {adapter_id}")
                validate_schema_bound_object(eval_obj)
                if str(eval_obj.get("schema_id", "")).strip() != "kt.factory.eval_report.v2":
                    raise RuntimeError(f"FAIL_CLOSED: supplemental eval_report schema mismatch for {adapter_id}")
                if str(eval_obj.get("adapter_id", "")).strip() != adapter_id:
                    raise RuntimeError(f"FAIL_CLOSED: supplemental eval_report adapter_id mismatch for {adapter_id}")
                imported_eval_ref = eval_report_path.as_posix()

        train_manifest = _reexport_train_manifest(training_receipt=training_receipt, artifact_path=imported_bundle_path, out_path=train_manifest_path)
        reexported_job_dir_ref = ""
        entrant_root_hash = ""
        tournament_entrant_runner_dir_ref = ""
        tournament_entrant_eval_report_ref = ""
        tournament_entrant_job_dir_manifest_ref = ""
        if eval_obj is not None:
            job_dir_manifest = _reexport_job_dir_manifest(eval_report=eval_obj, eval_report_path=eval_report_path, adapter_id=adapter_id, out_path=job_dir_manifest_path)
            reexported_job_dir_ref = job_dir_manifest_path.as_posix()
            entrant_root_hash = str(job_dir_manifest.get("hash_manifest_root_hash", "")).strip()
            runner_dir = (tournament_entrants_root / entrant_root_hash).resolve()
            runner_dir.mkdir(parents=True, exist_ok=True)
            runner_eval_path = (runner_dir / "eval_report.json").resolve()
            runner_job_dir_manifest_path = (runner_dir / "job_dir_manifest.json").resolve()
            shutil.copy2(eval_report_path, runner_eval_path)
            write_json_stable(runner_job_dir_manifest_path, job_dir_manifest)
            tournament_entrant_runner_dir_ref = runner_dir.as_posix()
            tournament_entrant_eval_report_ref = runner_eval_path.as_posix()
            tournament_entrant_job_dir_manifest_ref = runner_job_dir_manifest_path.as_posix()
            entrants_for_plan.append({"adapter_root_hash": entrant_root_hash, "adapter_id": adapter_id, "adapter_version": _parse_adapter_version(adapter_id, eval_obj)})

        _ = _reexport_training_run_manifest(
            training_receipt=training_receipt,
            train_manifest=train_manifest,
            eval_report_ref=imported_eval_ref,
            job_dir_manifest_ref=reexported_job_dir_ref,
            out_path=training_run_manifest_path,
        )

        missing_for_entry: List[str] = []
        if not imported_eval_ref:
            missing_for_entry.append("eval_report.json")
        if not reexported_job_dir_ref:
            missing_for_entry.append("job_dir_manifest.json")
        reexport_entries.append(
            {
                "adapter_id": adapter_id,
                "expected_source_eval_report_path": eval_source_path,
                "expected_source_job_dir_manifest_path": inferred_job_dir_source_path,
                "expected_source_train_manifest_path": str(entry.get("source_train_manifest_path", "")).strip(),
                "expected_source_training_run_manifest_path": str(entry.get("source_training_run_manifest_path", "")).strip(),
                "imported_eval_report_ref": imported_eval_ref,
                "reexported_job_dir_manifest_ref": reexported_job_dir_ref,
                "reexported_train_manifest_ref": train_manifest_path.as_posix(),
                "reexported_training_run_manifest_ref": training_run_manifest_path.as_posix(),
                "entrant_root_hash": entrant_root_hash,
                "adapter_version": _parse_adapter_version(adapter_id, eval_obj),
                "tournament_entrant_runner_dir_ref": tournament_entrant_runner_dir_ref,
                "tournament_entrant_eval_report_ref": tournament_entrant_eval_report_ref,
                "tournament_entrant_job_dir_manifest_ref": tournament_entrant_job_dir_manifest_ref,
                "source_eval_stub": bool(entry.get("source_eval_stub")),
                "missing_for_tournament_entry": missing_for_entry,
            }
        )

    tournament_plan_path: Optional[Path] = None
    evaluation_admission_path: Optional[Path] = None
    if len(entrants_for_plan) == len(entries):
        tournament_plan = _build_tournament_plan(
            base_model_id=base_model_id,
            suite_id=str(suite_entry.get("suite_id", "")).strip(),
            suite_root_hash=str(suite_entry.get("suite_root_hash", "")).strip(),
            decode_policy_id="greedy_v1",
            decode_cfg_hash=str(counterpressure.get("decode_cfg_hash", "")).strip(),
            entrants=entrants_for_plan,
        )
        tournament_plan_path = (authoritative_root / "cohort0_tournament_plan.json").resolve()
        write_json_stable(tournament_plan_path, tournament_plan)
        evaluation_admission_path = (authoritative_root / "cohort0_evaluation_admission_receipt.json").resolve()
        _ = ensure_evaluation_admission_receipt(
            repo_root=root,
            plan_path=tournament_plan_path,
            lane_id=lane_id,
            suite_registry_path=suite_registry_path,
            counterpressure_plan_path=counterpressure_path,
            break_hypothesis_path=break_hypothesis_path,
            out_path=evaluation_admission_path,
        )

    holdout_pack_refs = [{"adapter_id": str(eval_receipt.get("adapter_id", "")).strip(), "holdout_pack_path": str(eval_receipt.get("holdout_pack_path", "")).strip(), "holdout_pack_sha256": str(eval_receipt.get("holdout_pack_sha256", "")).strip()} for eval_receipt in eval_receipts]
    reexport_contract = _build_reexport_contract(import_receipt=import_receipt, authoritative_import_receipt_path=authoritative_import_receipt_path, authoritative_grade_receipt_path=authoritative_grade_receipt_path, reexport_entries=reexport_entries)
    authoritative_contract_path = (authoritative_root / "cohort0_entrant_authority_reexport_contract.json").resolve()
    authoritative_prep_path = (authoritative_root / "cohort0_tournament_admission_prep_packet.json").resolve()
    prep_packet = _build_prep_packet(
        authoritative_import_receipt_path=authoritative_import_receipt_path,
        import_receipt=import_receipt,
        grade_receipt=grade_receipt,
        suite_entry=suite_entry,
        adversarial_suite_entry=adversarial_suite_entry,
        base_snapshot_id=base_snapshot_id,
        base_model_id=base_model_id,
        holdout_pack_refs=holdout_pack_refs,
        reexport_contract=reexport_contract,
        break_hypothesis_path=break_hypothesis_path,
        counterpressure_plan_path=counterpressure_path,
        tournament_entrants_root=tournament_entrants_root,
        tournament_plan_path=tournament_plan_path,
        evaluation_admission_path=evaluation_admission_path,
    )
    prep_packet["refs"]["entrant_reexport_contract_ref"] = authoritative_contract_path.as_posix()

    write_json_stable(authoritative_contract_path, reexport_contract)
    write_json_stable(authoritative_prep_path, prep_packet)

    reports_root.mkdir(parents=True, exist_ok=True)
    carrier_contract = dict(reexport_contract)
    carrier_contract["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_ENTRANT_REEXPORT_CONTRACT"
    carrier_contract["authoritative_reexport_contract_ref"] = authoritative_contract_path.as_posix()
    carrier_prep = dict(prep_packet)
    carrier_prep["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_ADMISSION_PREP_PACKET"
    carrier_prep["authoritative_prep_packet_ref"] = authoritative_prep_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_REEXPORT_REPORT_REL).name).resolve(), carrier_contract)
    write_json_stable((reports_root / Path(DEFAULT_PREP_REPORT_REL).name).resolve(), carrier_prep)

    return {"reexport_contract": reexport_contract, "prep_packet": prep_packet}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Prepare Cohort-0 tournament admission surfaces from imported Kaggle real-engine adapter evidence.")
    ap.add_argument(
        "--import-report",
        default=DEFAULT_IMPORT_REPORT_REL,
        help=f"Tracked import report path. Default: {DEFAULT_IMPORT_REPORT_REL}",
    )
    ap.add_argument(
        "--grade-report",
        default=DEFAULT_GRADE_REPORT_REL,
        help=f"Tracked grade report path. Default: {DEFAULT_GRADE_REPORT_REL}",
    )
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: tmp/cohort0_tournament_admission_prep_<utc>/",
    )
    ap.add_argument(
        "--reports-root",
        default="KT_PROD_CLEANROOM/reports",
        help="Tracked carrier report root. Default: KT_PROD_CLEANROOM/reports",
    )
    ap.add_argument("--suite-id", default="SUITE_X", help="Bounded evaluation suite id. Default: SUITE_X")
    ap.add_argument("--adversarial-suite-id", default="SUITE_X_ADV", help="Bounded adversarial suite id. Default: SUITE_X_ADV")
    ap.add_argument("--lane-id", default="B04_GATE_D_COHORT0_TOURNAMENT_PREP", help="Lane id recorded in any emitted admission packet.")
    ap.add_argument(
        "--supplemental-evidence-root",
        default="",
        help="Optional directory containing imported/re-exportable eval_report.json files.",
    )
    ap.add_argument(
        "--supplemental-evidence-zip",
        default="",
        help="Optional zip containing imported/re-exportable eval_report.json files.",
    )
    return ap.parse_args(argv)


def _resolve_cli_path(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    else:
        path = path.resolve()
    return path


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    import_report_path = _resolve_cli_path(root, str(args.import_report))
    grade_report_path = _resolve_cli_path(root, str(args.grade_report))
    if str(args.authoritative_root).strip():
        authoritative_root = _resolve_cli_path(root, str(args.authoritative_root))
    else:
        authoritative_root = (root / "tmp" / f"cohort0_tournament_admission_prep_{utc_now_compact_z()}").resolve()
    reports_root = _resolve_cli_path(root, str(args.reports_root))

    supplemental_root = _resolve_cli_path(root, str(args.supplemental_evidence_root)) if str(args.supplemental_evidence_root).strip() else None
    supplemental_zip = _resolve_cli_path(root, str(args.supplemental_evidence_zip)) if str(args.supplemental_evidence_zip).strip() else None
    if supplemental_root is not None and not supplemental_root.exists():
        raise RuntimeError(f"FAIL_CLOSED: supplemental evidence root does not exist: {supplemental_root.as_posix()}")
    if supplemental_zip is not None and not supplemental_zip.is_file():
        raise RuntimeError(f"FAIL_CLOSED: supplemental evidence zip does not exist: {supplemental_zip.as_posix()}")

    payload = run_tournament_prep_tranche(
        import_report_path=import_report_path,
        grade_report_path=grade_report_path,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        suite_id=str(args.suite_id),
        adversarial_suite_id=str(args.adversarial_suite_id),
        lane_id=str(args.lane_id),
        supplemental_evidence_root=supplemental_root,
        supplemental_evidence_zip=supplemental_zip,
        workspace_root=root,
    )
    prep = payload["prep_packet"]
    print(
        json.dumps(
            {
                "status": prep["status"],
                "prep_posture": prep["prep_posture"],
                "next_lawful_move": prep["next_lawful_move"],
                "subject_head": prep["subject_head"],
                "authoritative_root": authoritative_root.as_posix(),
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
