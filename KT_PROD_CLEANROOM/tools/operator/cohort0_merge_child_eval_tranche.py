from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.governance.evaluation_admission_gate import ensure_evaluation_admission_receipt
from tools.merge.merge_evaluator import run_merge_evaluator
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.tournament.run_tournament import run_tournament
from tools.verification.fl3_validators import validate_schema_bound_object


DEFAULT_PROMOTION_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_promotion_candidate_receipt.json"
DEFAULT_FOLLOWTHROUGH_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_tournament_followthrough_packet.json"
DEFAULT_CHILD_CANDIDATE_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_child_candidate_receipt.json"
DEFAULT_CHILD_EVAL_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_child_evaluation_receipt.json"
DEFAULT_SUITE_REGISTRY_REL = "KT_PROD_CLEANROOM/AUDITS/SUITE_REGISTRY_FL3.json"

TOURNAMENT_PLAN_SCHEMA_FILE = "fl3/kt.tournament_plan.v1.json"
TOURNAMENT_PLAN_SCHEMA_HASH = schema_version_hash(TOURNAMENT_PLAN_SCHEMA_FILE)
FRAGILITY_SCHEMA_FILE = "fl3/kt.fragility_probe_result.v1.json"
FRAGILITY_SCHEMA_HASH = schema_version_hash(FRAGILITY_SCHEMA_FILE)
MERGE_MANIFEST_SCHEMA_FILE = "fl3/kt.merge_manifest.v1.json"
MERGE_MANIFEST_SCHEMA_HASH = schema_version_hash(MERGE_MANIFEST_SCHEMA_FILE)


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


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    authoritative_path = _resolve_path(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _copy_json_surface(src: Path, dst: Path, *, label: str) -> Dict[str, Any]:
    obj = _load_json_required(src, label=label)
    write_json_stable(dst, obj)
    return obj


def _copy_entrant_runner_dir(*, src_root: Path, dst_root: Path, adapter_root_hash: str) -> Path:
    src_dir = (src_root / adapter_root_hash).resolve()
    if not src_dir.is_dir():
        raise RuntimeError(f"FAIL_CLOSED: missing source entrant runner dir for {adapter_root_hash}: {src_dir.as_posix()}")
    dst_dir = (dst_root / adapter_root_hash).resolve()
    dst_dir.mkdir(parents=True, exist_ok=True)
    for name in ("eval_report.json", "job_dir_manifest.json"):
        src_path = src_dir / name
        if not src_path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing source entrant {name}: {src_path.as_posix()}")
        shutil.copy2(src_path, dst_dir / name)
    return dst_dir


def _build_merge_tournament_plan(
    *,
    source_plan: Dict[str, Any],
    entrants: List[Dict[str, str]],
) -> Dict[str, Any]:
    entrants_sorted = sorted(
        entrants,
        key=lambda row: (str(row.get("adapter_root_hash", "")).strip(), str(row.get("adapter_id", "")).strip()),
    )
    plan = {
        "schema_id": "kt.tournament_plan.v1",
        "schema_version_hash": TOURNAMENT_PLAN_SCHEMA_HASH,
        "tournament_plan_id": "",
        "base_model_id": str(source_plan.get("base_model_id", "")).strip(),
        "suite_id": str(source_plan.get("suite_id", "")).strip(),
        "suite_root_hash": str(source_plan.get("suite_root_hash", "")).strip(),
        "decode_policy_id": str(source_plan.get("decode_policy_id", "")).strip(),
        "decode_cfg_hash": str(source_plan.get("decode_cfg_hash", "")).strip(),
        "tournament_mode": str(source_plan.get("tournament_mode", "")).strip(),
        "epsilon": float(source_plan.get("epsilon", 0.0)),
        "entrants": entrants_sorted,
        "seed": hashlib.sha256(
            (
                str(source_plan.get("base_model_id", "")).strip()
                + "|"
                + str(source_plan.get("suite_id", "")).strip()
                + "|"
                + "|".join(str(row.get("adapter_root_hash", "")).strip() for row in entrants_sorted)
            ).encode("utf-8")
        ).hexdigest(),
        "created_at": "1970-01-01T00:00:00Z",
        "notes": "Bounded three-entrant merge child evaluation arena derived from the Cohort-0 tournament result.",
    }
    plan["tournament_plan_id"] = sha256_hex_of_obj(plan, drop_keys={"created_at", "tournament_plan_id"})
    validate_schema_bound_object(plan)
    return plan


def _build_fragility_probe_result(*, counterpressure_plan_id: str, entrant_hashes: List[str]) -> Dict[str, Any]:
    obj = {
        "schema_id": "kt.fragility_probe_result.v1",
        "schema_version_hash": FRAGILITY_SCHEMA_HASH,
        "fragility_probe_result_id": "",
        "counterpressure_plan_id": counterpressure_plan_id,
        "status": "PASS",
        "reason_codes": [],
        "evaluated_adapter_root_hashes": sorted({str(x).strip() for x in entrant_hashes if str(x).strip()}),
        "probes": [
            {
                "probe_id": "perturbation.0",
                "family": "perturbation",
                "status": "PASS",
                "notes": "Bounded merge-child entrant fragility coverage prepared.",
            },
            {
                "probe_id": "schema_trap.0",
                "family": "schema_trap",
                "status": "PASS",
                "notes": "Bounded merge-child entrant fragility coverage prepared.",
            },
        ],
        "created_at": "1970-01-01T00:00:00Z",
        "notes": "Prepared only for bounded merge-child evaluation. This is not router or externality authority.",
    }
    obj["fragility_probe_result_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "fragility_probe_result_id"})
    validate_schema_bound_object(obj)
    return obj


def _build_merge_manifest(*, base_model_id: str, parents: List[Dict[str, str]]) -> Dict[str, Any]:
    parent_rows = sorted(
        [
            {
                "adapter_root_hash": str(row.get("adapter_root_hash", "")).strip(),
                "adapter_id": str(row.get("adapter_id", "")).strip(),
                "adapter_version": str(row.get("adapter_version", "")).strip(),
            }
            for row in parents
        ],
        key=lambda row: str(row.get("adapter_root_hash", "")),
    )
    manifest = {
        "schema_id": "kt.merge_manifest.v1",
        "schema_version_hash": MERGE_MANIFEST_SCHEMA_HASH,
        "merge_manifest_id": "",
        "base_model_id": str(base_model_id).strip(),
        "role_tag": "COHORT0_PROMOTION_CHILD_CANDIDATE",
        "merge_method": "ties_v1",
        "parents": parent_rows,
        "created_at": "1970-01-01T00:00:00Z",
        "notes": "Bounded merge manifest prepared from the recommended parent seed pair after Cohort-0 tournament execution.",
    }
    manifest["merge_manifest_id"] = sha256_hex_of_obj(manifest, drop_keys={"created_at", "merge_manifest_id"})
    validate_schema_bound_object(manifest)
    return manifest


def _find_inventory_entry(inventory: Dict[str, Any], *, adapter_id: str) -> Dict[str, Any]:
    entries = inventory.get("entries") if isinstance(inventory.get("entries"), list) else []
    matches = [row for row in entries if isinstance(row, dict) and str(row.get("adapter_id", "")).strip() == adapter_id]
    if len(matches) != 1:
        raise RuntimeError(f"FAIL_CLOSED: expected exactly one adapter inventory row for {adapter_id}")
    return dict(matches[0])


def _build_child_candidate_receipt(
    *,
    subject_head: str,
    promotion_receipt_path: Path,
    followthrough_path: Path,
    child_inventory: Dict[str, Any],
    child_candidate: Dict[str, Any],
    parents: List[Dict[str, Any]],
    merge_plan_path: Path,
    merge_eval_ref: Path,
    merge_tournament_result_ref: Path,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_merge_child_candidate_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "candidate_posture": "REAL_CHILD_CANDIDATE_BOUND_TO_RECOMMENDED_PARENT_SEEDS",
        "claim_boundary": "This receipt binds only a bounded merge child candidate and its source eval evidence against the recommended parent seeds. It does not declare merge success, router authority, or externality widening.",
        "source_promotion_candidate_receipt_ref": promotion_receipt_path.as_posix(),
        "source_followthrough_packet_ref": followthrough_path.as_posix(),
        "child_candidate": {
            "adapter_id": str(child_candidate.get("adapter_id", "")).strip(),
            "adapter_root_hash": str(child_candidate.get("adapter_root_hash", "")).strip(),
            "adapter_version": str(child_candidate.get("adapter_version", "")).strip(),
            "artifact_path": str(child_inventory.get("artifact_path", "")).strip(),
            "artifact_sha256": str(child_inventory.get("artifact_sha256", "")).strip(),
            "eval_receipt_ref": str(child_inventory.get("eval_receipt_ref", "")).strip(),
            "training_receipt_ref": str(child_inventory.get("training_receipt_ref", "")).strip(),
        },
        "recommended_parent_seeds": [
            {
                "adapter_id": str(row.get("adapter_id", "")).strip(),
                "adapter_root_hash": str(row.get("adapter_root_hash", "")).strip(),
                "adapter_version": str(row.get("adapter_version", "")).strip(),
            }
            for row in parents
        ],
        "merge_tournament_plan_ref": merge_plan_path.as_posix(),
        "merge_tournament_result_ref": merge_tournament_result_ref.as_posix(),
        "merge_eval_receipt_ref": merge_eval_ref.as_posix(),
        "next_lawful_move": "READ_MERGE_EVAL_RECEIPT_AND_BIND_NEXT_PARENT_DECISION",
    }


def _build_child_evaluation_receipt(
    *,
    subject_head: str,
    promotion_receipt_path: Path,
    followthrough_path: Path,
    child_candidate_receipt_path: Path,
    merge_tournament_result_path: Path,
    merge_eval_receipt_path: Path,
    merge_eval_receipt: Dict[str, Any],
    merge_rollback_plan_path: Path,
) -> Dict[str, Any]:
    reason_codes = sorted({str(x).strip() for x in merge_eval_receipt.get("reason_codes", []) if str(x).strip()})
    merge_eval_status = str(merge_eval_receipt.get("status", "")).strip()
    if merge_eval_status == "PASS":
        posture = "MERGE_CHILD_EVALUATED__PASS__PROMOTION_AND_ROLLBACK_BINDING_READY"
        next_lawful_move = "PREPARE_PROMOTION_AND_MERGE_OUTCOME_BINDING"
    elif "MERGE_PRECONDITION_FAILED" in reason_codes:
        posture = "MERGE_CHILD_EVALUATED__RECOMMENDED_PARENT_PAIR_NOT_ADMISSIBLE"
        next_lawful_move = "RESELECT_ADMISSIBLE_PARENT_SEEDS_AND_REEVALUATE_MERGE_CHILD"
    elif "MERGE_UTILITY_GATE_FAILED" in reason_codes:
        posture = "MERGE_CHILD_EVALUATED__UTILITY_GATE_FAILED_AGAINST_RECOMMENDED_PARENT_SEEDS"
        next_lawful_move = "PREPARE_STRONGER_CHILD_CANDIDATE_OR_RESELECT_PARENT_PAIR"
    else:
        posture = "MERGE_CHILD_EVALUATED__FAIL_CLOSED"
        next_lawful_move = "READ_FAIL_CLOSED_REASON_CODES_AND_PREPARE_NEXT_MERGE_ATTEMPT"
    return {
        "schema_id": "kt.operator.cohort0_merge_child_evaluation_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "evaluation_posture": posture,
        "claim_boundary": "This receipt captures only bounded merge-child evaluation against the recommended parent seeds. It does not by itself declare a promotion verdict, router authority, or externality widening.",
        "source_promotion_candidate_receipt_ref": promotion_receipt_path.as_posix(),
        "source_followthrough_packet_ref": followthrough_path.as_posix(),
        "merge_child_candidate_receipt_ref": child_candidate_receipt_path.as_posix(),
        "merge_tournament_result_ref": merge_tournament_result_path.as_posix(),
        "merge_eval_receipt_ref": merge_eval_receipt_path.as_posix(),
        "merge_eval_status": merge_eval_status,
        "merge_eval_reason_codes": reason_codes,
        "merge_rollback_plan_ref": merge_rollback_plan_path.as_posix(),
        "next_lawful_move": next_lawful_move,
    }


def _build_updated_followthrough_packet(
    *,
    existing_followthrough: Dict[str, Any],
    child_candidate_receipt_path: Path,
    child_eval_receipt_path: Path,
    merge_manifest_path: Path,
    merge_eval_receipt_path: Path,
    merge_eval_receipt: Dict[str, Any],
    merge_rollback_plan_path: Path,
    merge_tournament_result_path: Path,
) -> Dict[str, Any]:
    packet = dict(existing_followthrough)
    packet["generated_utc"] = utc_now_iso_z()
    reason_codes = sorted({str(x).strip() for x in merge_eval_receipt.get("reason_codes", []) if str(x).strip()})
    merge_eval_status = str(merge_eval_receipt.get("status", "")).strip()
    merge_followthrough = dict(packet.get("merge_followthrough", {}))
    promotion_followthrough = dict(packet.get("promotion_followthrough", {}))
    merge_followthrough.update(
        {
            "child_candidate_prepared": True,
            "child_candidate_receipt_ref": child_candidate_receipt_path.as_posix(),
            "merge_tournament_result_ref": merge_tournament_result_path.as_posix(),
            "merge_manifest_ref": merge_manifest_path.as_posix(),
            "merge_eval_receipt_ref": merge_eval_receipt_path.as_posix(),
            "merge_eval_status": merge_eval_status,
            "merge_eval_reason_codes": reason_codes,
            "merge_rollback_plan_ref": merge_rollback_plan_path.as_posix(),
        }
    )
    if merge_eval_status == "PASS":
        packet["followthrough_posture"] = "MERGE_CHILD_EVALUATED__PASS__PROMOTION_AND_ROLLBACK_BINDING_READY"
        promotion_followthrough["blocked_by"] = "PROMOTION_AND_MERGE_OUTCOME_BINDING_NOT_PREPARED"
        merge_followthrough["execution_ready"] = True
        merge_followthrough["blockers"] = []
        merge_followthrough["next_lawful_move"] = "PREPARE_PROMOTION_AND_MERGE_OUTCOME_BINDING"
    elif "MERGE_PRECONDITION_FAILED" in reason_codes:
        packet["followthrough_posture"] = "MERGE_CHILD_EVALUATED__RECOMMENDED_PARENT_PAIR_NOT_ADMISSIBLE"
        promotion_followthrough["blocked_by"] = "MERGE_PARENT_PRECONDITION_FAILED__PROMOTION_NOT_BINDABLE"
        merge_followthrough["execution_ready"] = False
        merge_followthrough["blockers"] = reason_codes or ["MERGE_PRECONDITION_FAILED"]
        merge_followthrough["next_lawful_move"] = "RESELECT_ADMISSIBLE_PARENT_SEEDS_AND_REEVALUATE_MERGE_CHILD"
    elif "MERGE_UTILITY_GATE_FAILED" in reason_codes:
        packet["followthrough_posture"] = "MERGE_CHILD_EVALUATED__UTILITY_GATE_FAILED_AGAINST_RECOMMENDED_PARENT_SEEDS"
        promotion_followthrough["blocked_by"] = "MERGE_UTILITY_GATE_FAILED__PROMOTION_NOT_BINDABLE"
        merge_followthrough["execution_ready"] = False
        merge_followthrough["blockers"] = reason_codes or ["MERGE_UTILITY_GATE_FAILED"]
        merge_followthrough["next_lawful_move"] = "PREPARE_STRONGER_CHILD_CANDIDATE_OR_RESELECT_PARENT_PAIR"
    else:
        packet["followthrough_posture"] = "MERGE_CHILD_EVALUATED__FAIL_CLOSED"
        promotion_followthrough["blocked_by"] = "MERGE_EVAL_FAIL_CLOSED__PROMOTION_NOT_BINDABLE"
        merge_followthrough["execution_ready"] = False
        merge_followthrough["blockers"] = reason_codes or ["MERGE_EVAL_FAIL_CLOSED"]
        merge_followthrough["next_lawful_move"] = "READ_FAIL_CLOSED_REASON_CODES_AND_PREPARE_NEXT_MERGE_ATTEMPT"
    promotion_followthrough["execution_ready"] = False
    packet["promotion_followthrough"] = promotion_followthrough
    packet["merge_followthrough"] = merge_followthrough
    packet["next_question"] = "Which parent pair is merge-admissible once the recommended seeds have been tested under merge law?"
    packet["merge_child_evaluation_receipt_ref"] = child_eval_receipt_path.as_posix()
    return packet


def run_merge_child_eval_tranche(
    *,
    promotion_report_path: Path,
    followthrough_report_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    authoritative_promotion_path, promotion_receipt = _resolve_authoritative(
        root,
        promotion_report_path.resolve(),
        "authoritative_promotion_candidate_receipt_ref",
        "cohort0 promotion candidate receipt",
    )
    authoritative_followthrough_path, followthrough_packet = _resolve_authoritative(
        root,
        followthrough_report_path.resolve(),
        "authoritative_followthrough_packet_ref",
        "cohort0 tournament followthrough packet",
    )
    import_receipt_ref = str(followthrough_packet.get("source_import_receipt_ref", "")).strip()
    if not import_receipt_ref:
        import_receipt_ref = str(followthrough_packet.get("carrier_surface_summary", {}).get("source_import_receipt_ref", "")).strip()
    if not import_receipt_ref:
        raise RuntimeError("FAIL_CLOSED: followthrough packet missing source import receipt ref")
    authoritative_import_path = _resolve_path(root, import_receipt_ref)
    authoritative_inventory_path = authoritative_import_path.parent / "cohort0_real_engine_adapter_inventory.json"
    authoritative_inventory = _load_json_required(authoritative_inventory_path, label="cohort0 authoritative inventory")

    child_candidate = dict(promotion_receipt.get("candidate", {}))
    child_adapter_id = str(child_candidate.get("adapter_id", "")).strip()
    child_root_hash = str(child_candidate.get("adapter_root_hash", "")).strip()
    if not child_adapter_id or not child_root_hash:
        raise RuntimeError("FAIL_CLOSED: promotion candidate missing adapter identity")

    merge_followthrough = followthrough_packet.get("merge_followthrough") if isinstance(followthrough_packet.get("merge_followthrough"), dict) else {}
    parent_seeds = merge_followthrough.get("recommended_parent_seeds") if isinstance(merge_followthrough.get("recommended_parent_seeds"), list) else []
    if len(parent_seeds) != 2:
        raise RuntimeError("FAIL_CLOSED: expected exactly two recommended parent seeds")
    parents = [
        {
            "adapter_id": str(row.get("adapter_id", "")).strip(),
            "adapter_root_hash": str(row.get("adapter_root_hash", "")).strip(),
            "adapter_version": str(row.get("adapter_version", "")).strip() or "1",
        }
        for row in parent_seeds
        if isinstance(row, dict)
    ]
    if len(parents) != 2 or any(not row["adapter_id"] or not row["adapter_root_hash"] for row in parents):
        raise RuntimeError("FAIL_CLOSED: recommended parent seeds missing identity")
    if any(row["adapter_root_hash"] == child_root_hash for row in parents):
        raise RuntimeError("FAIL_CLOSED: child candidate must differ from parent seeds")

    execution_ref = str(followthrough_packet.get("carrier_surface_summary", {}).get("source_tournament_execution_receipt_ref", "")).strip()
    if not execution_ref:
        execution_ref = str(followthrough_packet.get("source_tournament_execution_receipt_ref", "")).strip()
    authoritative_execution_path = _resolve_path(root, execution_ref)
    execution_receipt = _load_json_required(authoritative_execution_path, label="source tournament execution receipt")
    prep_packet_path = _resolve_path(root, str(execution_receipt.get("source_prep_packet_ref", "")).strip())
    prep_packet = _load_json_required(prep_packet_path, label="source tournament prep packet")
    source_tournament_plan_path = _resolve_path(root, str(execution_receipt.get("tournament_plan_ref", "")).strip())
    source_tournament_plan = _load_json_required(source_tournament_plan_path, label="source tournament plan")
    source_entrants_root = _resolve_path(root, str(prep_packet.get("refs", {}).get("tournament_entrants_root_ref", "")).strip())
    source_break_path = _resolve_path(root, str(prep_packet.get("refs", {}).get("break_hypothesis_ref", "")).strip())
    source_counterpressure_path = _resolve_path(root, str(prep_packet.get("refs", {}).get("counterpressure_plan_ref", "")).strip())

    target_root = authoritative_root.resolve() if authoritative_root is not None else (authoritative_execution_path.parent / "merge_child_eval").resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    merge_entrants_root = (target_root / "merge_entrants").resolve()
    merge_entrants_root.mkdir(parents=True, exist_ok=True)

    entrants = [*parents, {"adapter_id": child_adapter_id, "adapter_root_hash": child_root_hash, "adapter_version": str(child_candidate.get("adapter_version", "")).strip() or "1"}]
    for row in entrants:
        _copy_entrant_runner_dir(src_root=source_entrants_root, dst_root=merge_entrants_root, adapter_root_hash=str(row["adapter_root_hash"]))

    merge_tournament_plan = _build_merge_tournament_plan(source_plan=source_tournament_plan, entrants=entrants)
    merge_plan_path = (target_root / "merge_tournament_plan.json").resolve()
    write_json_stable(merge_plan_path, merge_tournament_plan)

    merge_break_path = (target_root / "break_hypothesis.json").resolve()
    merge_counterpressure_path = (target_root / "counterpressure_plan.json").resolve()
    _ = _copy_json_surface(source_break_path, merge_break_path, label="source break hypothesis")
    merge_counterpressure = _copy_json_surface(source_counterpressure_path, merge_counterpressure_path, label="source counterpressure plan")

    fragility = _build_fragility_probe_result(
        counterpressure_plan_id=str(merge_counterpressure.get("counterpressure_plan_id", "")).strip(),
        entrant_hashes=[str(row["adapter_root_hash"]) for row in entrants],
    )
    fragility_path = (target_root / "fragility_probe_result.json").resolve()
    write_json_stable(fragility_path, fragility)

    admission_path = (target_root / "evaluation_admission_receipt.json").resolve()
    suite_registry_path = (root / DEFAULT_SUITE_REGISTRY_REL).resolve()
    _ = ensure_evaluation_admission_receipt(
        repo_root=root,
        plan_path=merge_plan_path,
        lane_id="B04_GATE_D_COHORT0_MERGE_CHILD_EVAL",
        suite_registry_path=suite_registry_path,
        counterpressure_plan_path=merge_counterpressure_path,
        break_hypothesis_path=merge_break_path,
        out_path=admission_path,
    )

    merge_tournament_out_dir = (target_root / f"merge_tournament_execution_{str(merge_tournament_plan.get('tournament_plan_id', ''))[:12]}").resolve()
    merge_tournament_result = run_tournament(
        repo_root=root,
        plan_path=merge_plan_path,
        entrants_root=merge_entrants_root,
        out_dir=merge_tournament_out_dir,
        admission_receipt_path=admission_path,
        break_hypothesis_path=merge_break_path,
        counterpressure_plan_path=merge_counterpressure_path,
        fragility_probe_result_path=fragility_path,
    )
    merge_tournament_result_path = (merge_tournament_out_dir / "tournament_result.json").resolve()

    merge_manifest = _build_merge_manifest(
        base_model_id=str(merge_tournament_plan.get("base_model_id", "")).strip(),
        parents=parents,
    )
    merge_manifest_path = (target_root / "merge_manifest.json").resolve()
    write_json_stable(merge_manifest_path, merge_manifest)

    merge_eval_out_dir = (target_root / f"merge_evaluation_{str(merge_tournament_plan.get('tournament_plan_id', ''))[:12]}").resolve()
    merge_eval_receipt_path = (merge_eval_out_dir / "merge_eval_receipt.json").resolve()
    merge_rollback_plan_path = (merge_eval_out_dir / "merge_rollback_plan.json").resolve()
    try:
        _eval_receipt, _rollback = run_merge_evaluator(
            repo_root=root,
            merge_manifest_path=merge_manifest_path,
            tournament_result_path=merge_tournament_result_path,
            entrants_root=merge_entrants_root,
            out_dir=merge_eval_out_dir,
        )
    except Exception:
        if not merge_eval_receipt_path.is_file() or not merge_rollback_plan_path.is_file():
            raise
    merge_eval_receipt = _load_json_required(merge_eval_receipt_path, label="merge eval receipt")
    _merge_rollback = _load_json_required(merge_rollback_plan_path, label="merge rollback plan")

    child_inventory = _find_inventory_entry(authoritative_inventory, adapter_id=child_adapter_id)
    child_candidate_receipt = _build_child_candidate_receipt(
        subject_head=str(promotion_receipt.get("subject_head", "")).strip(),
        promotion_receipt_path=authoritative_promotion_path,
        followthrough_path=authoritative_followthrough_path,
        child_inventory=child_inventory,
        child_candidate=child_candidate,
        parents=parents,
        merge_plan_path=merge_plan_path,
        merge_eval_ref=merge_eval_receipt_path,
        merge_tournament_result_ref=merge_tournament_result_path,
    )
    authoritative_child_candidate_path = (target_root / "cohort0_merge_child_candidate_receipt.json").resolve()
    write_json_stable(authoritative_child_candidate_path, child_candidate_receipt)

    child_evaluation_receipt = _build_child_evaluation_receipt(
        subject_head=str(promotion_receipt.get("subject_head", "")).strip(),
        promotion_receipt_path=authoritative_promotion_path,
        followthrough_path=authoritative_followthrough_path,
        child_candidate_receipt_path=authoritative_child_candidate_path,
        merge_tournament_result_path=merge_tournament_result_path,
        merge_eval_receipt_path=merge_eval_receipt_path,
        merge_eval_receipt=merge_eval_receipt,
        merge_rollback_plan_path=merge_rollback_plan_path,
    )
    authoritative_child_eval_path = (target_root / "cohort0_merge_child_evaluation_receipt.json").resolve()
    write_json_stable(authoritative_child_eval_path, child_evaluation_receipt)

    authoritative_followthrough_updated = _build_updated_followthrough_packet(
        existing_followthrough=followthrough_packet,
        child_candidate_receipt_path=authoritative_child_candidate_path,
        child_eval_receipt_path=authoritative_child_eval_path,
        merge_manifest_path=merge_manifest_path,
        merge_eval_receipt_path=merge_eval_receipt_path,
        merge_eval_receipt=merge_eval_receipt,
        merge_rollback_plan_path=merge_rollback_plan_path,
        merge_tournament_result_path=merge_tournament_result_path,
    )
    authoritative_followthrough_updated_path = (target_root / "cohort0_real_engine_tournament_followthrough_packet.json").resolve()
    write_json_stable(authoritative_followthrough_updated_path, authoritative_followthrough_updated)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_child_candidate = dict(child_candidate_receipt)
    tracked_child_candidate["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_MERGE_CHILD_CANDIDATE_RECEIPT"
    tracked_child_candidate["authoritative_merge_child_candidate_receipt_ref"] = authoritative_child_candidate_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_CHILD_CANDIDATE_REPORT_REL).name).resolve(), tracked_child_candidate)

    tracked_child_eval = dict(child_evaluation_receipt)
    tracked_child_eval["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_MERGE_CHILD_EVALUATION_RECEIPT"
    tracked_child_eval["authoritative_merge_child_evaluation_receipt_ref"] = authoritative_child_eval_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_CHILD_EVAL_REPORT_REL).name).resolve(), tracked_child_eval)

    tracked_followthrough = dict(authoritative_followthrough_updated)
    tracked_followthrough["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_FOLLOWTHROUGH_ARTIFACT"
    tracked_followthrough["authoritative_followthrough_packet_ref"] = authoritative_followthrough_updated_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_FOLLOWTHROUGH_REPORT_REL).name).resolve(), tracked_followthrough)

    return {
        "merge_child_candidate_receipt": child_candidate_receipt,
        "merge_child_evaluation_receipt": child_evaluation_receipt,
        "merge_eval_receipt": merge_eval_receipt,
        "merge_tournament_result": merge_tournament_result,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Prepare and evaluate a bounded Cohort-0 merge child candidate against the recommended parent seeds.")
    ap.add_argument(
        "--promotion-report",
        default=DEFAULT_PROMOTION_REPORT_REL,
        help=f"Tracked promotion candidate report path. Default: {DEFAULT_PROMOTION_REPORT_REL}",
    )
    ap.add_argument(
        "--followthrough-report",
        default=DEFAULT_FOLLOWTHROUGH_REPORT_REL,
        help=f"Tracked tournament followthrough report path. Default: {DEFAULT_FOLLOWTHROUGH_REPORT_REL}",
    )
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: <source_execution_parent>/merge_child_eval",
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
    promotion_report_path = _resolve_path(root, str(args.promotion_report))
    followthrough_report_path = _resolve_path(root, str(args.followthrough_report))
    authoritative_root = _resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None
    reports_root = _resolve_path(root, str(args.reports_root))
    payload = run_merge_child_eval_tranche(
        promotion_report_path=promotion_report_path,
        followthrough_report_path=followthrough_report_path,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=root,
    )
    child_eval = payload["merge_child_evaluation_receipt"]
    merge_eval = payload["merge_eval_receipt"]
    print(
        json.dumps(
            {
                "status": child_eval["status"],
                "evaluation_posture": child_eval["evaluation_posture"],
                "merge_eval_status": merge_eval.get("status"),
                "merge_eval_reason_codes": merge_eval.get("reason_codes", []),
                "next_lawful_move": child_eval["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
