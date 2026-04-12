from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_RECOMPOSED_SUBSTRATE_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_13_entrant_substrate_receipt.json"
DEFAULT_ORACLE_PACKET_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_eval_packet.json"
DEFAULT_ORACLE_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_scorecard.json"
DEFAULT_STAGE_PACK_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_manifest.json"
DEFAULT_POLICY_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/route_policy_outcome_registry.json"

OUTCOME_ROUTE = "ROUTE_TO_SPECIALIST"
OUTCOME_STAY = "STAY_STATIC_BASELINE"
OUTCOME_ABSTAIN = "ABSTAIN_FOR_REVIEW"

BRIDGE_POSTURE_READY = "RECOMPOSED_PROMOTION_AND_MERGE_BOUND__ROUTER_SHADOW_SURFACES_EMITTED"
BRIDGE_POSTURE_HOLD = "RECOMPOSED_PROMOTION_AND_MERGE_BOUND__ROUTER_SHADOW_CEILING_HOLD"
NEXT_MOVE_R5 = "EXECUTE_RECOMPOSED_R5_ROUTER_PROOF"
NEXT_MOVE_HOLD = "REMAIN_AT_ROUTER_SHADOW_CEILING"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    authoritative_path = _resolve(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _resolve_subject_head(*, packets: Sequence[Dict[str, Any]]) -> str:
    subject_heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if not subject_heads:
        raise RuntimeError("FAIL_CLOSED: recomposed router shadow bridge could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: recomposed router shadow bridge requires one consistent subject head")
    return next(iter(subject_heads))


def _family_rows_by_id(stage_pack_manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows = stage_pack_manifest.get("family_rows")
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("FAIL_CLOSED: route bearing stage pack manifest missing family_rows")
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict):
            family_id = str(row.get("family_id", "")).strip()
            if family_id:
                out[family_id] = row
    return out


def _validate_inputs(
    *,
    recomposed_substrate: Dict[str, Any],
    followthrough: Dict[str, Any],
    promotion_outcome: Dict[str, Any],
    merge_outcome: Dict[str, Any],
    oracle_packet: Dict[str, Any],
    oracle_scorecard: Dict[str, Any],
    stage_pack_manifest: Dict[str, Any],
    policy_registry: Dict[str, Any],
) -> None:
    if str(recomposed_substrate.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed substrate receipt must PASS")
    if str(recomposed_substrate.get("recomposition_posture", "")).strip() != "RECOMPOSED_13_ENTRANT_SUBSTRATE_BOUND__TOURNAMENT_RERUN_ADMISSIBLE":
        raise RuntimeError("FAIL_CLOSED: recomposed substrate receipt posture mismatch")
    if str(followthrough.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed followthrough packet must PASS")
    if str(followthrough.get("followthrough_posture", "")).strip() != "PROMOTION_AND_MERGE_OUTCOME_BOUND__ROUTER_SHADOW_EVALUATION_REQUIRED":
        raise RuntimeError("FAIL_CLOSED: recomposed followthrough must require router shadow evaluation")
    if str(promotion_outcome.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: promotion outcome receipt must PASS")
    if str(promotion_outcome.get("promotion_posture", "")).strip() != "PROMOTION_OUTCOME_BOUND__MERGE_PASS_CHILD_READY_FOR_ROUTER_SHADOW_EVALUATION":
        raise RuntimeError("FAIL_CLOSED: promotion outcome posture mismatch")
    if str(merge_outcome.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: merge outcome receipt must PASS")
    if str(merge_outcome.get("merge_outcome_posture", "")).strip() != "MERGE_OUTCOME_BOUND__PASS__ROLLBACK_READY":
        raise RuntimeError("FAIL_CLOSED: merge outcome posture mismatch")
    if str(oracle_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: oracle local eval packet must PASS")
    case_results = oracle_packet.get("case_results")
    if not isinstance(case_results, list) or not case_results:
        raise RuntimeError("FAIL_CLOSED: oracle local eval packet missing case_results")
    if str(oracle_scorecard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: oracle local scorecard must PASS")
    if bool(oracle_scorecard.get("nonzero_route_divergence")) is not True:
        raise RuntimeError("FAIL_CLOSED: oracle local scorecard must prove nonzero route divergence")
    if str(stage_pack_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route bearing stage pack manifest must PASS")
    if str(policy_registry.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route policy registry must PASS")
    outcome_ids = [
        str(row.get("outcome_id", "")).strip()
        for row in policy_registry.get("outcomes", [])
        if isinstance(row, dict)
    ]
    if outcome_ids != [OUTCOME_ROUTE, OUTCOME_STAY, OUTCOME_ABSTAIN]:
        raise RuntimeError("FAIL_CLOSED: route policy registry outcomes must remain route/stay-static/abstain")


def _baseline_static_adapter_id(promotion_outcome: Dict[str, Any]) -> str:
    candidate = promotion_outcome.get("candidate")
    if not isinstance(candidate, dict):
        raise RuntimeError("FAIL_CLOSED: promotion outcome candidate missing")
    adapter_id = str(candidate.get("adapter_id", "")).strip()
    if not adapter_id:
        raise RuntimeError("FAIL_CLOSED: promotion outcome candidate adapter_id missing")
    return adapter_id


def _selection_case_row(*, case_result: Dict[str, Any], baseline_adapter_id: str) -> Dict[str, Any]:
    outcome = str(case_result.get("oracle_policy_outcome", "")).strip()
    selected_adapter_ids = [str(x).strip() for x in case_result.get("selected_adapter_ids", []) if str(x).strip()]
    return {
        "case_id": str(case_result.get("case_id", "")).strip(),
        "case_sha256": str(case_result.get("case_sha256", "")).strip(),
        "case_variant": str(case_result.get("case_variant", "")).strip(),
        "family_id": str(case_result.get("family_id", "")).strip(),
        "family_category": str(case_result.get("family_category", "")).strip(),
        "pack_visibility": str(case_result.get("pack_visibility", "")).strip(),
        "baseline_static_adapter_path": {
            "selected_adapter_ids": [baseline_adapter_id],
            "policy_outcome": OUTCOME_STAY,
        },
        "shadow_selection": {
            "policy_outcome": outcome,
            "selected_adapter_ids": selected_adapter_ids,
            "fallback_engaged": outcome == OUTCOME_ABSTAIN,
            "route_delta_vs_static": bool(case_result.get("divergence_from_static")),
            "route_justification": str(case_result.get("route_justification", "")).strip(),
            "static_baseline_reason": str(case_result.get("static_baseline_reason", "")).strip(),
            "abstention_reason": str(case_result.get("abstention_reason", "")).strip(),
            "review_handoff_rule": str(case_result.get("review_handoff_rule", "")).strip(),
        },
        "oracle_policy_outcome": outcome,
        "selected_adapter_ids": selected_adapter_ids,
        "divergence_from_static": bool(case_result.get("divergence_from_static")),
        "preregistered_expectation_satisfied": bool(case_result.get("preregistered_expectation_satisfied")),
        "safety_effect": str(case_result.get("safety_effect", "")).strip(),
    }


def _build_selection_receipt(
    *,
    subject_head: str,
    current_head: str,
    recomposed_substrate_path: Path,
    followthrough_path: Path,
    promotion_outcome_path: Path,
    merge_outcome_path: Path,
    oracle_packet_path: Path,
    oracle_packet: Dict[str, Any],
    policy_registry_path: Path,
    baseline_adapter_id: str,
) -> Dict[str, Any]:
    case_rows = [
        _selection_case_row(case_result=row, baseline_adapter_id=baseline_adapter_id)
        for row in oracle_packet.get("case_results", [])
        if isinstance(row, dict)
    ]
    route_case_count = sum(1 for row in case_rows if row["oracle_policy_outcome"] == OUTCOME_ROUTE)
    stay_case_count = sum(1 for row in case_rows if row["oracle_policy_outcome"] == OUTCOME_STAY)
    abstain_case_count = sum(1 for row in case_rows if row["oracle_policy_outcome"] == OUTCOME_ABSTAIN)
    route_delta_count = sum(1 for row in case_rows if bool(row["divergence_from_static"]))
    exact_path_match_count = stay_case_count
    exact_path_universality_broken = exact_path_match_count != len(case_rows)
    r5_admissible = route_delta_count > 0 and exact_path_universality_broken
    return {
        "schema_id": "kt.operator.cohort0_recomposed_router_selection_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "selection_posture": "RECOMPOSED_SHADOW_SELECTION_BOUND_TO_PROMOTION_AND_MERGE_SUBSTRATE",
        "claim_boundary": (
            "This receipt binds only recomposed router-shadow selection on the promotion-and-merge-bound 13-entrant substrate "
            "against the current static best adapter. It does not claim router superiority, learned-router cutover, or Gate E/F opening."
        ),
        "recomposed_substrate_receipt_ref": recomposed_substrate_path.as_posix(),
        "promotion_merge_followthrough_ref": followthrough_path.as_posix(),
        "promotion_outcome_binding_receipt_ref": promotion_outcome_path.as_posix(),
        "merge_outcome_binding_receipt_ref": merge_outcome_path.as_posix(),
        "oracle_local_eval_packet_ref": oracle_packet_path.as_posix(),
        "route_policy_outcome_registry_ref": policy_registry_path.as_posix(),
        "current_static_best_adapter_id": baseline_adapter_id,
        "case_count": len(case_rows),
        "route_case_count": route_case_count,
        "stay_static_case_count": stay_case_count,
        "abstain_case_count": abstain_case_count,
        "route_distribution_delta_count": route_delta_count,
        "exact_path_match_count": exact_path_match_count,
        "exact_path_universality_broken": exact_path_universality_broken,
        "r5_admissible": r5_admissible,
        "next_lawful_move": NEXT_MOVE_R5 if r5_admissible else NEXT_MOVE_HOLD,
        "case_rows": case_rows,
    }


def _build_shadow_matrix(
    *,
    subject_head: str,
    current_head: str,
    selection_receipt_path: Path,
    selection_receipt: Dict[str, Any],
    stage_pack_manifest_path: Path,
    stage_pack_manifest: Dict[str, Any],
) -> Dict[str, Any]:
    family_rows = _family_rows_by_id(stage_pack_manifest)
    rows: List[Dict[str, Any]] = []
    for case_row in selection_receipt.get("case_rows", []):
        family_id = str(case_row.get("family_id", "")).strip()
        family = family_rows.get(family_id, {})
        rows.append(
            {
                "case_id": str(case_row.get("case_id", "")).strip(),
                "family_id": family_id,
                "family_category": str(case_row.get("family_category", "")).strip(),
                "target_lobe_id": str(family.get("target_lobe_id", "")).strip(),
                "baseline_adapter_ids": list(case_row.get("baseline_static_adapter_path", {}).get("selected_adapter_ids", [])),
                "shadow_adapter_ids": list(case_row.get("selected_adapter_ids", [])),
                "shadow_policy_outcome": str(case_row.get("oracle_policy_outcome", "")).strip(),
                "exact_path_match": str(case_row.get("oracle_policy_outcome", "")).strip() == OUTCOME_STAY,
                "fallback_engaged": str(case_row.get("oracle_policy_outcome", "")).strip() == OUTCOME_ABSTAIN,
                "divergence_from_static": bool(case_row.get("divergence_from_static")),
            }
        )
    route_delta_count = sum(1 for row in rows if bool(row["divergence_from_static"]))
    exact_path_match_count = sum(1 for row in rows if bool(row["exact_path_match"]))
    exact_path_universality_broken = exact_path_match_count != len(rows)
    return {
        "schema_id": "kt.operator.cohort0_recomposed_router_shadow_eval_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "This matrix measures only recomposed router-shadow divergence versus the static alpha control on the recomposed substrate. "
            "It does not claim learned-router superiority or authorization."
        ),
        "selection_receipt_ref": selection_receipt_path.as_posix(),
        "stage_pack_manifest_ref": stage_pack_manifest_path.as_posix(),
        "case_count": len(rows),
        "exact_path_match_count": exact_path_match_count,
        "exact_path_universality_broken": exact_path_universality_broken,
        "route_distribution_delta_count": route_delta_count,
        "promotion_decision": {
            "canonical_router_unchanged": True,
            "learned_router_cutover_allowed": False,
            "shadow_promotable": False,
            "route_value_signal_present": route_delta_count > 0,
            "r5_admissible": route_delta_count > 0 and exact_path_universality_broken,
        },
        "rows": rows,
    }


def _build_route_health(
    *,
    subject_head: str,
    current_head: str,
    selection_receipt_path: Path,
    selection_receipt: Dict[str, Any],
    shadow_matrix_path: Path,
    shadow_matrix: Dict[str, Any],
) -> Dict[str, Any]:
    rows = list(shadow_matrix.get("rows", []))
    case_count = len(rows)
    exact_path_match_count = int(shadow_matrix.get("exact_path_match_count", 0))
    fallback_case_ids = [
        str(row.get("case_id", "")).strip()
        for row in rows
        if isinstance(row, dict) and bool(row.get("fallback_engaged"))
    ]
    routed_case_ids = [
        str(row.get("case_id", "")).strip()
        for row in rows
        if isinstance(row, dict) and str(row.get("shadow_policy_outcome", "")).strip() == OUTCOME_ROUTE
    ]
    unique_route_targets = sorted(
        {
            str(adapter_id).strip()
            for row in rows
            if isinstance(row, dict)
            for adapter_id in row.get("shadow_adapter_ids", [])
            if str(adapter_id).strip()
        }
    )
    shadow_match_rate = round(float(exact_path_match_count) / float(case_count), 4) if case_count else 0.0
    route_delta_count = int(shadow_matrix.get("route_distribution_delta_count", 0))
    family_counts: Dict[str, int] = {}
    for row in rows:
        family_id = str(row.get("family_id", "")).strip()
        if family_id:
            family_counts[family_id] = family_counts.get(family_id, 0) + 1
    return {
        "schema_id": "kt.operator.cohort0_recomposed_route_distribution_health.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "This report measures recomposed route divergence, fallback, and static-control preservation only. "
            "It does not claim superiority until ordered proof is executed."
        ),
        "selection_receipt_ref": selection_receipt_path.as_posix(),
        "shadow_eval_matrix_ref": shadow_matrix_path.as_posix(),
        "route_distribution_delta_count": route_delta_count,
        "shadow_match_rate": shadow_match_rate,
        "route_collapse_detected": len(unique_route_targets) <= 1 and len(routed_case_ids) > 0,
        "exact_path_universality_broken": bool(shadow_matrix.get("exact_path_universality_broken")),
        "stay_static_case_count": int(selection_receipt.get("stay_static_case_count", 0)),
        "route_case_count": int(selection_receipt.get("route_case_count", 0)),
        "abstain_case_count": int(selection_receipt.get("abstain_case_count", 0)),
        "fallback_case_ids": fallback_case_ids,
        "routed_case_ids": routed_case_ids,
        "unique_route_targets": unique_route_targets,
        "family_case_counts": family_counts,
        "r5_admissible": bool(selection_receipt.get("r5_admissible")),
    }


def _build_scorecard(
    *,
    subject_head: str,
    current_head: str,
    selection_receipt_path: Path,
    route_health_path: Path,
    route_health: Dict[str, Any],
    baseline_adapter_id: str,
) -> Dict[str, Any]:
    route_delta_count = int(route_health.get("route_distribution_delta_count", 0))
    exact_path_universality_broken = bool(route_health.get("exact_path_universality_broken"))
    r5_admissible = bool(route_health.get("r5_admissible"))
    learned_router_candidate_status = (
        "SHADOW_SIGNAL_PRESENT_BUT_NOT_YET_ORDERED_PROOF_RATIFIED" if r5_admissible else "NO_RECOMPOSED_R5_CANDIDATE_PRESENT"
    )
    return {
        "schema_id": "kt.operator.cohort0_recomposed_router_superiority_scorecard.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "This scorecard binds only recomposed shadow-stage route-bearing signal versus the static alpha control. "
            "It does not claim router superiority, learned-router authorization, or Gate E/F opening."
        ),
        "selection_receipt_ref": selection_receipt_path.as_posix(),
        "route_distribution_health_ref": route_health_path.as_posix(),
        "best_static_baseline": {
            "adapter_id": baseline_adapter_id,
            "status": "CANONICAL_STATIC_COMPARATOR_RETAINS_AUTHORITY",
        },
        "route_delta_summary": {
            "route_distribution_delta_count": route_delta_count,
            "exact_path_universality_broken": exact_path_universality_broken,
            "route_case_count": int(route_health.get("route_case_count", 0)),
            "stay_static_case_count": int(route_health.get("stay_static_case_count", 0)),
            "abstain_case_count": int(route_health.get("abstain_case_count", 0)),
            "unique_route_target_count": len(route_health.get("unique_route_targets", [])),
        },
        "learned_router_candidate": {
            "candidate_status": learned_router_candidate_status,
            "promotion_allowed": False,
            "eligibility_reason": (
                "Recomposed shadow shows route-bearing signal and breaks exact-path universality, but ordered proof has not yet been executed."
                if r5_admissible
                else "Recomposed shadow did not clear the minimum route-bearing signal needed for ordered proof escalation."
            ),
        },
        "router_superiority_earned": False,
        "exact_superiority_outcome": (
            "NOT_EARNED_RECOMPOSED_SHADOW_ONLY__R5_REQUIRED" if r5_admissible else "NOT_EARNED_RECOMPOSED_SHADOW_CEILING_HOLD"
        ),
        "r5_admissible": r5_admissible,
        "next_lawful_move": NEXT_MOVE_R5 if r5_admissible else NEXT_MOVE_HOLD,
    }


def _build_followthrough_packet(
    *,
    existing_followthrough: Dict[str, Any],
    bridge_posture: str,
    selection_receipt_path: Path,
    shadow_matrix_path: Path,
    route_health_path: Path,
    scorecard_path: Path,
    scorecard: Dict[str, Any],
    route_health: Dict[str, Any],
) -> Dict[str, Any]:
    packet = dict(existing_followthrough)
    packet["generated_utc"] = utc_now_iso_z()
    packet["followthrough_posture"] = bridge_posture
    packet["router_shadow_followthrough"] = {
        "execution_ready": True,
        "selection_receipt_ref": selection_receipt_path.as_posix(),
        "shadow_eval_matrix_ref": shadow_matrix_path.as_posix(),
        "route_distribution_health_ref": route_health_path.as_posix(),
        "router_superiority_scorecard_ref": scorecard_path.as_posix(),
        "route_distribution_delta_count": int(route_health.get("route_distribution_delta_count", 0)),
        "exact_path_universality_broken": bool(route_health.get("exact_path_universality_broken")),
        "r5_admissible": bool(scorecard.get("r5_admissible")),
        "next_lawful_move": str(scorecard.get("next_lawful_move", "")).strip(),
    }
    packet["router_shadow_rerun_admissible"] = True
    packet["r5_rerun_admissible"] = bool(scorecard.get("r5_admissible"))
    packet["next_lawful_move"] = str(scorecard.get("next_lawful_move", "")).strip()
    packet["next_question"] = "Does recomposed shadow evidence now justify recomposed R5 ordered proof against the static alpha comparator?"
    return packet


def _build_bridge_receipt(
    *,
    subject_head: str,
    current_head: str,
    recomposed_substrate_path: Path,
    followthrough_path: Path,
    promotion_outcome_path: Path,
    merge_outcome_path: Path,
    selection_receipt_path: Path,
    shadow_matrix_path: Path,
    route_health_path: Path,
    scorecard_path: Path,
    scorecard: Dict[str, Any],
    route_health: Dict[str, Any],
) -> Dict[str, Any]:
    r5_admissible = bool(scorecard.get("r5_admissible"))
    return {
        "schema_id": "kt.operator.cohort0_recomposed_router_shadow_bridge_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "binding_posture": BRIDGE_POSTURE_READY if r5_admissible else BRIDGE_POSTURE_HOLD,
        "claim_boundary": (
            "This receipt proves only that recomposed router-shadow surfaces have been rebound to the promotion-and-merge-bound "
            "13-entrant substrate. It does not claim router superiority, learned-router cutover, or Gate E/F opening."
        ),
        "recomposed_substrate_receipt_ref": recomposed_substrate_path.as_posix(),
        "promotion_merge_followthrough_ref": followthrough_path.as_posix(),
        "promotion_outcome_binding_receipt_ref": promotion_outcome_path.as_posix(),
        "merge_outcome_binding_receipt_ref": merge_outcome_path.as_posix(),
        "router_selection_receipt_ref": selection_receipt_path.as_posix(),
        "router_shadow_eval_matrix_ref": shadow_matrix_path.as_posix(),
        "route_distribution_health_ref": route_health_path.as_posix(),
        "router_superiority_scorecard_ref": scorecard_path.as_posix(),
        "route_distribution_delta_count": int(route_health.get("route_distribution_delta_count", 0)),
        "exact_path_universality_broken": bool(route_health.get("exact_path_universality_broken")),
        "r5_admissible": r5_admissible,
        "next_lawful_move": str(scorecard.get("next_lawful_move", "")).strip(),
    }


def run_recomposed_router_shadow_bridge_tranche(
    *,
    recomposed_substrate_report_path: Path,
    followthrough_report_path: Path,
    promotion_outcome_report_path: Path,
    merge_outcome_report_path: Path,
    oracle_packet_path: Path,
    oracle_scorecard_path: Path,
    stage_pack_manifest_path: Path,
    policy_registry_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_recomposed_substrate_path, recomposed_substrate = _resolve_authoritative(
        root, recomposed_substrate_report_path.resolve(), "authoritative_recomposed_13_entrant_substrate_receipt_ref", "recomposed substrate receipt"
    )
    authoritative_followthrough_path, followthrough = _resolve_authoritative(
        root, followthrough_report_path.resolve(), "authoritative_followthrough_packet_ref", "recomposed followthrough packet"
    )
    authoritative_promotion_outcome_path, promotion_outcome = _resolve_authoritative(
        root, promotion_outcome_report_path.resolve(), "authoritative_promotion_outcome_binding_receipt_ref", "promotion outcome receipt"
    )
    authoritative_merge_outcome_path, merge_outcome = _resolve_authoritative(
        root, merge_outcome_report_path.resolve(), "authoritative_merge_outcome_binding_receipt_ref", "merge outcome receipt"
    )
    authoritative_oracle_packet_path, oracle_packet = _resolve_authoritative(
        root, oracle_packet_path.resolve(), "authoritative_oracle_router_local_eval_packet_ref", "oracle local eval packet"
    )
    authoritative_oracle_scorecard_path, oracle_scorecard = _resolve_authoritative(
        root, oracle_scorecard_path.resolve(), "authoritative_oracle_router_local_scorecard_ref", "oracle local scorecard"
    )
    authoritative_stage_pack_manifest_path, stage_pack_manifest = _resolve_authoritative(
        root, stage_pack_manifest_path.resolve(), "authoritative_route_bearing_stage_pack_manifest_ref", "route bearing stage pack manifest"
    )
    authoritative_policy_registry_path, policy_registry = _resolve_authoritative(
        root, policy_registry_path.resolve(), "authoritative_route_policy_outcome_registry_ref", "route policy outcome registry"
    )

    _validate_inputs(
        recomposed_substrate=recomposed_substrate,
        followthrough=followthrough,
        promotion_outcome=promotion_outcome,
        merge_outcome=merge_outcome,
        oracle_packet=oracle_packet,
        oracle_scorecard=oracle_scorecard,
        stage_pack_manifest=stage_pack_manifest,
        policy_registry=policy_registry,
    )

    subject_head = _resolve_subject_head(
        packets=[
            recomposed_substrate,
            followthrough,
            promotion_outcome,
            merge_outcome,
            oracle_packet,
            oracle_scorecard,
            stage_pack_manifest,
        ]
    )
    baseline_adapter_id = _baseline_static_adapter_id(promotion_outcome)

    target_root = authoritative_root.resolve() if authoritative_root is not None else authoritative_followthrough_path.parent.resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    selection_receipt_path = (target_root / "cohort0_recomposed_router_selection_receipt.json").resolve()
    shadow_matrix_path = (target_root / "cohort0_recomposed_router_shadow_eval_matrix.json").resolve()
    route_health_path = (target_root / "cohort0_recomposed_route_distribution_health.json").resolve()
    scorecard_path = (target_root / "cohort0_recomposed_router_superiority_scorecard.json").resolve()
    bridge_receipt_path = (target_root / "cohort0_recomposed_router_shadow_bridge_receipt.json").resolve()
    followthrough_out_path = (target_root / "cohort0_recomposed_router_shadow_followthrough_packet.json").resolve()

    selection_receipt = _build_selection_receipt(
        subject_head=subject_head,
        current_head=current_head,
        recomposed_substrate_path=authoritative_recomposed_substrate_path,
        followthrough_path=authoritative_followthrough_path,
        promotion_outcome_path=authoritative_promotion_outcome_path,
        merge_outcome_path=authoritative_merge_outcome_path,
        oracle_packet_path=authoritative_oracle_packet_path,
        oracle_packet=oracle_packet,
        policy_registry_path=authoritative_policy_registry_path,
        baseline_adapter_id=baseline_adapter_id,
    )
    write_json_stable(selection_receipt_path, selection_receipt)

    shadow_matrix = _build_shadow_matrix(
        subject_head=subject_head,
        current_head=current_head,
        selection_receipt_path=selection_receipt_path,
        selection_receipt=selection_receipt,
        stage_pack_manifest_path=authoritative_stage_pack_manifest_path,
        stage_pack_manifest=stage_pack_manifest,
    )
    write_json_stable(shadow_matrix_path, shadow_matrix)

    route_health = _build_route_health(
        subject_head=subject_head,
        current_head=current_head,
        selection_receipt_path=selection_receipt_path,
        selection_receipt=selection_receipt,
        shadow_matrix_path=shadow_matrix_path,
        shadow_matrix=shadow_matrix,
    )
    write_json_stable(route_health_path, route_health)

    scorecard = _build_scorecard(
        subject_head=subject_head,
        current_head=current_head,
        selection_receipt_path=selection_receipt_path,
        route_health_path=route_health_path,
        route_health=route_health,
        baseline_adapter_id=baseline_adapter_id,
    )
    write_json_stable(scorecard_path, scorecard)

    followthrough_packet = _build_followthrough_packet(
        existing_followthrough=followthrough,
        bridge_posture=BRIDGE_POSTURE_READY if bool(scorecard.get("r5_admissible")) else BRIDGE_POSTURE_HOLD,
        selection_receipt_path=selection_receipt_path,
        shadow_matrix_path=shadow_matrix_path,
        route_health_path=route_health_path,
        scorecard_path=scorecard_path,
        scorecard=scorecard,
        route_health=route_health,
    )
    write_json_stable(followthrough_out_path, followthrough_packet)

    bridge_receipt = _build_bridge_receipt(
        subject_head=subject_head,
        current_head=current_head,
        recomposed_substrate_path=authoritative_recomposed_substrate_path,
        followthrough_path=authoritative_followthrough_path,
        promotion_outcome_path=authoritative_promotion_outcome_path,
        merge_outcome_path=authoritative_merge_outcome_path,
        selection_receipt_path=selection_receipt_path,
        shadow_matrix_path=shadow_matrix_path,
        route_health_path=route_health_path,
        scorecard_path=scorecard_path,
        scorecard=scorecard,
        route_health=route_health,
    )
    write_json_stable(bridge_receipt_path, bridge_receipt)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_selection = dict(selection_receipt)
    tracked_selection["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_SELECTION_RECEIPT"
    tracked_selection["authoritative_recomposed_router_selection_receipt_ref"] = selection_receipt_path.as_posix()
    write_json_stable((reports_root / "cohort0_recomposed_router_selection_receipt.json").resolve(), tracked_selection)

    tracked_shadow = dict(shadow_matrix)
    tracked_shadow["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_SHADOW_EVAL_MATRIX"
    tracked_shadow["authoritative_recomposed_router_shadow_eval_matrix_ref"] = shadow_matrix_path.as_posix()
    write_json_stable((reports_root / "cohort0_recomposed_router_shadow_eval_matrix.json").resolve(), tracked_shadow)

    tracked_health = dict(route_health)
    tracked_health["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTE_DISTRIBUTION_HEALTH"
    tracked_health["authoritative_recomposed_route_distribution_health_ref"] = route_health_path.as_posix()
    write_json_stable((reports_root / "cohort0_recomposed_route_distribution_health.json").resolve(), tracked_health)

    tracked_scorecard = dict(scorecard)
    tracked_scorecard["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_SUPERIORITY_SCORECARD"
    tracked_scorecard["authoritative_recomposed_router_superiority_scorecard_ref"] = scorecard_path.as_posix()
    write_json_stable((reports_root / "cohort0_recomposed_router_superiority_scorecard.json").resolve(), tracked_scorecard)

    tracked_followthrough = dict(followthrough_packet)
    tracked_followthrough["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_SHADOW_FOLLOWTHROUGH_PACKET"
    tracked_followthrough["authoritative_recomposed_router_shadow_followthrough_packet_ref"] = followthrough_out_path.as_posix()
    write_json_stable((reports_root / "cohort0_recomposed_router_shadow_followthrough_packet.json").resolve(), tracked_followthrough)

    tracked_bridge = dict(bridge_receipt)
    tracked_bridge["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_SHADOW_BRIDGE_RECEIPT"
    tracked_bridge["authoritative_recomposed_router_shadow_bridge_receipt_ref"] = bridge_receipt_path.as_posix()
    write_json_stable((reports_root / "cohort0_recomposed_router_shadow_bridge_receipt.json").resolve(), tracked_bridge)

    return {
        "router_selection_receipt": selection_receipt,
        "router_shadow_eval_matrix": shadow_matrix,
        "route_distribution_health": route_health,
        "router_superiority_scorecard": scorecard,
        "router_shadow_followthrough_packet": followthrough_packet,
        "router_shadow_bridge_receipt": bridge_receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Bind recomposed router-shadow surfaces to the promotion-and-merge-bound 13-entrant substrate.")
    ap.add_argument("--recomposed-substrate-report", default=DEFAULT_RECOMPOSED_SUBSTRATE_REPORT_REL)
    ap.add_argument("--followthrough-report", required=True)
    ap.add_argument("--promotion-outcome-report", required=True)
    ap.add_argument("--merge-outcome-report", required=True)
    ap.add_argument("--oracle-packet", default=DEFAULT_ORACLE_PACKET_REL)
    ap.add_argument("--oracle-scorecard", default=DEFAULT_ORACLE_SCORECARD_REL)
    ap.add_argument("--stage-pack-manifest", default=DEFAULT_STAGE_PACK_MANIFEST_REL)
    ap.add_argument("--policy-registry", default=DEFAULT_POLICY_REGISTRY_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_recomposed_router_shadow_bridge_tranche(
        recomposed_substrate_report_path=_resolve(root, str(args.recomposed_substrate_report)),
        followthrough_report_path=_resolve(root, str(args.followthrough_report)),
        promotion_outcome_report_path=_resolve(root, str(args.promotion_outcome_report)),
        merge_outcome_report_path=_resolve(root, str(args.merge_outcome_report)),
        oracle_packet_path=_resolve(root, str(args.oracle_packet)),
        oracle_scorecard_path=_resolve(root, str(args.oracle_scorecard)),
        stage_pack_manifest_path=_resolve(root, str(args.stage_pack_manifest)),
        policy_registry_path=_resolve(root, str(args.policy_registry)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["router_shadow_bridge_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "binding_posture": receipt["binding_posture"],
                "route_distribution_delta_count": receipt["route_distribution_delta_count"],
                "exact_path_universality_broken": receipt["exact_path_universality_broken"],
                "r5_admissible": receipt["r5_admissible"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
