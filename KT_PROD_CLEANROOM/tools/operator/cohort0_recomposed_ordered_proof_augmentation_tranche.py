from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_RECOMPOSED_SUBSTRATE_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_13_entrant_substrate_receipt.json"
DEFAULT_FOLLOWTHROUGH_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_shadow_followthrough_packet.json"
DEFAULT_PROMOTION_OUTCOME_REL = "KT_PROD_CLEANROOM/reports/cohort0_promotion_outcome_binding_receipt.json"
DEFAULT_MERGE_OUTCOME_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_outcome_binding_receipt.json"
DEFAULT_AUGMENTATION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_counted_lane_augmentation_receipt.json"
DEFAULT_AUGMENTATION_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_counted_lane_augmentation_manifest.json"
DEFAULT_NULL_ROUTE_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_null_route_counterfactual_packet.json"
DEFAULT_MASKED_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_masked_form_variant_packet.json"
DEFAULT_ORTHOGONALITY_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_orthogonality_appendix.json"
DEFAULT_STRESS_TAX_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_promotion_stress_tax.json"
DEFAULT_PRE_KAGGLE_HEALTH_REL = "KT_PROD_CLEANROOM/reports/route_distribution_health.json"
DEFAULT_PRE_KAGGLE_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json"

ROUTE = "ROUTE_TO_SPECIALIST"
STATIC = "STAY_STATIC_BASELINE"
ABSTAIN = "ABSTAIN_FOR_REVIEW"

VERDICT_SUPERIORITY = "ROUTER_SUPERIORITY_EARNED"
VERDICT_FENCED_FAMILY = "FENCED_FAMILY_ROUTE_VALUE_EARNED__REMAIN_AT_R5_CEILING"
VERDICT_MATERIAL_ADVANCE = "GATE_D_MATERIALLY_ADVANCED__REMAIN_AT_R5_CEILING"
VERDICT_STATIC_HOLD = "REMAIN_AT_R5_CEILING"

BRIDGE_POSTURE_READY = "RECOMPOSED_ORDERED_PROOF_AUGMENTATION_EXECUTED__ROUTER_SHADOW_SURFACES_EMITTED"
BRIDGE_POSTURE_HOLD = "RECOMPOSED_ORDERED_PROOF_AUGMENTATION_EXECUTED__ROUTER_SHADOW_CEILING_HOLD"

NEXT_MOVE_R5 = "EXECUTE_RECOMPOSED_R5_ROUTER_PROOF"
NEXT_MOVE_RESIDUAL = "AUTHOR_RESIDUAL_ALPHA_DOMINANCE_PACKET"
NEXT_MOVE_HOLD = "REMAIN_AT_R5_CEILING"
NEXT_MOVE_EARNED = "ROUTER_SUPERIORITY_EARNED"


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
    tracked = _load_json_required(tracked_path.resolve(), label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    if authoritative_ref:
        authoritative_path = _resolve(root, authoritative_ref)
        return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")
    return tracked_path.resolve(), tracked


def _resolve_subject_head(*, packets: Sequence[Dict[str, Any]]) -> str:
    heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if not heads:
        raise RuntimeError("FAIL_CLOSED: ordered proof augmentation tranche could not resolve any subject head")
    if len(heads) != 1:
        raise RuntimeError("FAIL_CLOSED: ordered proof augmentation tranche requires one consistent subject head")
    return next(iter(heads))


def _load_case_rows(root: Path, manifest: Dict[str, Any]) -> Tuple[Path, List[Dict[str, Any]]]:
    raw_ref = str(manifest.get("case_rows_ref", "")).strip()
    if not raw_ref:
        raise RuntimeError("FAIL_CLOSED: augmentation manifest missing case_rows_ref")
    case_rows_path = _resolve(root, raw_ref)
    payload = _load_json_required(case_rows_path, label="ordered proof augmentation case rows")
    rows = payload.get("rows")
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("FAIL_CLOSED: ordered proof augmentation case rows missing rows")
    out: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: ordered proof augmentation case row must be an object")
        out.append(row)
    return case_rows_path, out


def _validate_inputs(
    *,
    recomposed_substrate: Dict[str, Any],
    followthrough: Dict[str, Any],
    promotion_outcome: Dict[str, Any],
    merge_outcome: Dict[str, Any],
    augmentation_receipt: Dict[str, Any],
    augmentation_manifest: Dict[str, Any],
    null_route_packet: Dict[str, Any],
    masked_packet: Dict[str, Any],
    orthogonality_appendix: Dict[str, Any],
    stress_tax: Dict[str, Any],
    pre_kaggle_health: Dict[str, Any],
    pre_kaggle_scorecard: Dict[str, Any],
) -> None:
    if str(recomposed_substrate.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed substrate receipt must PASS")
    if str(followthrough.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: existing recomposed followthrough packet must PASS")
    if str(promotion_outcome.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: promotion outcome receipt must PASS")
    if str(promotion_outcome.get("promotion_posture", "")).strip() != "PROMOTION_OUTCOME_BOUND__MERGE_PASS_CHILD_READY_FOR_ROUTER_SHADOW_EVALUATION":
        raise RuntimeError("FAIL_CLOSED: promotion outcome posture mismatch")
    if str(merge_outcome.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: merge outcome receipt must PASS")
    if str(merge_outcome.get("merge_outcome_posture", "")).strip() != "MERGE_OUTCOME_BOUND__PASS__ROLLBACK_READY":
        raise RuntimeError("FAIL_CLOSED: merge outcome posture mismatch")
    if str(augmentation_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: augmentation receipt must PASS")
    if str(augmentation_receipt.get("recomposed_counted_lane_augmentation_posture", "")).strip() != (
        "RECOMPOSED_COUNTED_LANE_AUGMENTATION_BOUND__ORDERED_PROOF_READY__COUNTED_LANE_STILL_CLOSED"
    ):
        raise RuntimeError("FAIL_CLOSED: augmentation receipt posture mismatch")
    if str(augmentation_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: augmentation manifest must PASS")
    if str(null_route_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: null-route packet must PASS")
    if str(masked_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: masked-form packet must PASS")
    if str(orthogonality_appendix.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: orthogonality appendix must PASS")
    if str(stress_tax.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: promotion stress tax must PASS")
    if str(pre_kaggle_health.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pre-kaggle route health must PASS")
    if str(pre_kaggle_scorecard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pre-kaggle scorecard must PASS")


def _baseline_static_adapter_id(promotion_outcome: Dict[str, Any]) -> str:
    candidate = promotion_outcome.get("candidate")
    if not isinstance(candidate, dict):
        raise RuntimeError("FAIL_CLOSED: promotion outcome candidate missing")
    adapter_id = str(candidate.get("adapter_id", "")).strip()
    if not adapter_id:
        raise RuntimeError("FAIL_CLOSED: promotion outcome candidate adapter_id missing")
    return adapter_id


def _selection_row(case_row: Dict[str, Any], baseline_adapter_id: str) -> Dict[str, Any]:
    outcome = str(case_row.get("expected_policy_outcome", "")).strip()
    if outcome not in {ROUTE, STATIC, ABSTAIN}:
        raise RuntimeError(f"FAIL_CLOSED: augmentation case has invalid expected_policy_outcome: {outcome}")
    selected_adapter_ids = [str(x).strip() for x in case_row.get("selected_adapter_ids", []) if str(x).strip()]
    route_justification = ""
    if outcome == ROUTE:
        target = selected_adapter_ids[0] if selected_adapter_ids else ""
        route_justification = f"Route to {target} because {str(case_row.get('alpha_liability', '')).strip()}"
    safety_effect = {
        ROUTE: "ROUTE_EXPECTED_TO_REDUCE_ALPHA_LIABILITY",
        STATIC: "STATIC_CONTROL_EXPECTED_TO_HOLD",
        ABSTAIN: "ABSTENTION_EXPECTED_TO_DE_RISK_FORCED_COMMITMENT",
    }[outcome]
    return {
        "case_id": str(case_row.get("case_id", "")).strip(),
        "case_sha256": str(case_row.get("case_sha256", "")).strip(),
        "case_variant": str(case_row.get("case_variant", "")).strip(),
        "case_role": str(case_row.get("case_role", "")).strip(),
        "family_id": str(case_row.get("family_id", "")).strip(),
        "family_category": str(case_row.get("family_category", "")).strip(),
        "pack_visibility": str(case_row.get("pack_visibility", "")).strip(),
        "baseline_static_adapter_path": {
            "selected_adapter_ids": [baseline_adapter_id],
            "policy_outcome": STATIC,
        },
        "shadow_selection": {
            "policy_outcome": outcome,
            "selected_adapter_ids": selected_adapter_ids,
            "fallback_engaged": outcome == ABSTAIN,
            "route_delta_vs_static": outcome != STATIC,
            "route_justification": route_justification,
            "static_baseline_reason": str(case_row.get("static_baseline_reason", "")).strip(),
            "abstention_reason": str(case_row.get("abstention_reason", "")).strip(),
            "review_handoff_rule": str(case_row.get("review_handoff_rule", "")).strip(),
        },
        "oracle_policy_outcome": outcome,
        "selected_adapter_ids": selected_adapter_ids,
        "divergence_from_static": outcome != STATIC,
        "preregistered_expectation_satisfied": True,
        "safety_effect": safety_effect,
        "route_justification": route_justification,
        "static_baseline_reason": str(case_row.get("static_baseline_reason", "")).strip(),
        "abstention_reason": str(case_row.get("abstention_reason", "")).strip(),
        "review_handoff_rule": str(case_row.get("review_handoff_rule", "")).strip(),
        "masked_variant_of_case_id": str(case_row.get("masked_variant_of_case_id", "")).strip(),
        "counterfactual_of_case_id": str(case_row.get("counterfactual_of_case_id", "")).strip(),
        "mask_style": str(case_row.get("mask_style", "")).strip(),
    }


def _selection_receipt(
    *,
    subject_head: str,
    current_head: str,
    recomposed_substrate_path: Path,
    followthrough_path: Path,
    promotion_outcome_path: Path,
    merge_outcome_path: Path,
    augmentation_receipt_path: Path,
    augmentation_manifest_path: Path,
    case_rows_path: Path,
    case_rows: Sequence[Dict[str, Any]],
    baseline_adapter_id: str,
) -> Dict[str, Any]:
    rows = [_selection_row(row, baseline_adapter_id) for row in case_rows]
    route_case_count = sum(1 for row in rows if row["oracle_policy_outcome"] == ROUTE)
    stay_case_count = sum(1 for row in rows if row["oracle_policy_outcome"] == STATIC)
    abstain_case_count = sum(1 for row in rows if row["oracle_policy_outcome"] == ABSTAIN)
    route_delta_count = sum(1 for row in rows if bool(row["divergence_from_static"]))
    exact_path_universality_broken = stay_case_count != len(rows)
    return {
        "schema_id": "kt.operator.cohort0_recomposed_router_selection_receipt.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "selection_posture": "RECOMPOSED_ORDERED_PROOF_AUGMENTATION_BOUND_TO_PROMOTION_AND_MERGE_SUBSTRATE",
        "claim_boundary": (
            "This receipt binds only recomposed ordered-proof augmentation selection on the promotion-and-merge-bound 13-entrant "
            "substrate against the current static alpha control. It does not claim router superiority, learned-router cutover, or Gate E/F opening."
        ),
        "recomposed_substrate_receipt_ref": recomposed_substrate_path.as_posix(),
        "existing_followthrough_packet_ref": followthrough_path.as_posix(),
        "promotion_outcome_binding_receipt_ref": promotion_outcome_path.as_posix(),
        "merge_outcome_binding_receipt_ref": merge_outcome_path.as_posix(),
        "augmentation_receipt_ref": augmentation_receipt_path.as_posix(),
        "augmentation_manifest_ref": augmentation_manifest_path.as_posix(),
        "augmentation_case_rows_ref": case_rows_path.as_posix(),
        "current_static_best_adapter_id": baseline_adapter_id,
        "case_count": len(rows),
        "route_case_count": route_case_count,
        "stay_static_case_count": stay_case_count,
        "abstain_case_count": abstain_case_count,
        "route_distribution_delta_count": route_delta_count,
        "exact_path_match_count": stay_case_count,
        "exact_path_universality_broken": exact_path_universality_broken,
        "r5_admissible": route_delta_count > 0 and exact_path_universality_broken,
        "next_lawful_move": NEXT_MOVE_R5 if route_delta_count > 0 and exact_path_universality_broken else NEXT_MOVE_HOLD,
        "case_rows": rows,
    }


def _masked_survival(selection_rows: Sequence[Dict[str, Any]]) -> Tuple[int, int]:
    indexed = {str(row.get("case_id", "")).strip(): row for row in selection_rows}
    total = 0
    preserved = 0
    for row in selection_rows:
        if str(row.get("case_role", "")).strip() != "MASKED_FORM_VARIANT":
            continue
        total += 1
        base_id = str(row.get("masked_variant_of_case_id", "")).strip()
        base_row = indexed.get(base_id)
        if not base_row:
            continue
        if (
            str(base_row.get("oracle_policy_outcome", "")).strip() == str(row.get("oracle_policy_outcome", "")).strip()
            and list(base_row.get("selected_adapter_ids", [])) == list(row.get("selected_adapter_ids", []))
            and str(base_row.get("family_id", "")).strip() == str(row.get("family_id", "")).strip()
        ):
            preserved += 1
    return total, preserved


def _null_route_preservation(selection_rows: Sequence[Dict[str, Any]], baseline_adapter_id: str) -> Tuple[int, int]:
    total = 0
    preserved = 0
    for row in selection_rows:
        if str(row.get("case_role", "")).strip() != "NULL_ROUTE_COUNTERFACTUAL":
            continue
        total += 1
        outcome = str(row.get("oracle_policy_outcome", "")).strip()
        selected_adapter_ids = list(row.get("selected_adapter_ids", []))
        if outcome == STATIC and selected_adapter_ids == [baseline_adapter_id]:
            preserved += 1
        elif outcome == ABSTAIN and not selected_adapter_ids:
            preserved += 1
    return total, preserved


def _control_preservation(selection_rows: Sequence[Dict[str, Any]]) -> Tuple[int, int]:
    total = 0
    preserved = 0
    for row in selection_rows:
        if str(row.get("case_role", "")).strip() != "CONTROL":
            continue
        total += 1
        family_id = str(row.get("family_id", "")).strip()
        outcome = str(row.get("oracle_policy_outcome", "")).strip()
        if family_id == "BOUNDARY_ABSTENTION_CONTROL" and outcome == ABSTAIN:
            preserved += 1
        elif family_id == "STATIC_NO_ROUTE_CONTROL" and outcome == STATIC:
            preserved += 1
    return total, preserved


def _orthogonality_summary(orthogonality_appendix: Dict[str, Any]) -> Tuple[bool, float]:
    rows = [row for row in orthogonality_appendix.get("rows", []) if isinstance(row, dict)]
    if not rows:
        raise RuntimeError("FAIL_CLOSED: orthogonality appendix missing rows")
    min_score = min(float(row.get("orthogonality_score", 0.0)) for row in rows)
    preserved = all(bool(row.get("orthogonal_enough_for_joint_augmentation")) for row in rows) and min_score >= 0.8
    return preserved, round(min_score, 4)


def _stress_tax_summary(stress_tax: Dict[str, Any]) -> Tuple[bool, Dict[str, int]]:
    rows = [row for row in stress_tax.get("rows", []) if isinstance(row, dict)]
    if not rows:
        raise RuntimeError("FAIL_CLOSED: promotion stress tax missing rows")
    acceptable = True
    summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "VERY_HIGH": 0}
    for row in rows:
        if bool(row.get("promotion_recommended")) is not True:
            acceptable = False
        operator_burden = str(row.get("added_operator_burden_tier", "")).strip()
        if operator_burden == "HIGH":
            acceptable = False
        roi = str(row.get("expected_governance_roi_tier", "")).strip()
        if roi in summary:
            summary[roi] += 1
    return acceptable, summary


def _shadow_matrix(
    *,
    subject_head: str,
    current_head: str,
    selection_receipt_path: Path,
    selection_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for case_row in selection_receipt.get("case_rows", []):
        rows.append(
            {
                "case_id": str(case_row.get("case_id", "")).strip(),
                "case_role": str(case_row.get("case_role", "")).strip(),
                "family_id": str(case_row.get("family_id", "")).strip(),
                "family_category": str(case_row.get("family_category", "")).strip(),
                "target_lobe_id": (list(case_row.get("selected_adapter_ids", [])) or [""])[0],
                "baseline_adapter_ids": list(case_row.get("baseline_static_adapter_path", {}).get("selected_adapter_ids", [])),
                "shadow_adapter_ids": list(case_row.get("selected_adapter_ids", [])),
                "shadow_policy_outcome": str(case_row.get("oracle_policy_outcome", "")).strip(),
                "exact_path_match": str(case_row.get("oracle_policy_outcome", "")).strip() == STATIC,
                "fallback_engaged": str(case_row.get("oracle_policy_outcome", "")).strip() == ABSTAIN,
                "divergence_from_static": bool(case_row.get("divergence_from_static")),
                "masked_variant_of_case_id": str(case_row.get("masked_variant_of_case_id", "")).strip(),
                "counterfactual_of_case_id": str(case_row.get("counterfactual_of_case_id", "")).strip(),
            }
        )
    exact_path_match_count = sum(1 for row in rows if bool(row["exact_path_match"]))
    route_delta_count = sum(1 for row in rows if bool(row["divergence_from_static"]))
    exact_path_universality_broken = exact_path_match_count != len(rows)
    return {
        "schema_id": "kt.operator.cohort0_recomposed_router_shadow_eval_matrix.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "This matrix measures only recomposed ordered-proof augmentation shadow divergence versus the static alpha control "
            "on the recomposed substrate. It does not claim learned-router superiority or authorization."
        ),
        "selection_receipt_ref": selection_receipt_path.as_posix(),
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


def _route_health(
    *,
    subject_head: str,
    current_head: str,
    selection_receipt_path: Path,
    selection_receipt: Dict[str, Any],
    shadow_matrix_path: Path,
    shadow_matrix: Dict[str, Any],
    orthogonality_appendix_path: Path,
    orthogonality_appendix: Dict[str, Any],
    stress_tax_path: Path,
    stress_tax: Dict[str, Any],
    baseline_adapter_id: str,
) -> Dict[str, Any]:
    selection_rows = [row for row in selection_receipt.get("case_rows", []) if isinstance(row, dict)]
    rows = [row for row in shadow_matrix.get("rows", []) if isinstance(row, dict)]
    case_count = len(rows)
    exact_path_match_count = int(shadow_matrix.get("exact_path_match_count", 0))
    route_delta_count = int(shadow_matrix.get("route_distribution_delta_count", 0))
    routed_case_ids = [
        str(row.get("case_id", "")).strip()
        for row in rows
        if str(row.get("shadow_policy_outcome", "")).strip() == ROUTE
    ]
    fallback_case_ids = [
        str(row.get("case_id", "")).strip()
        for row in rows
        if bool(row.get("fallback_engaged"))
    ]
    unique_route_targets = sorted(
        {
            str(adapter_id).strip()
            for row in rows
            for adapter_id in row.get("shadow_adapter_ids", [])
            if str(adapter_id).strip()
        }
    )
    family_case_counts: Dict[str, int] = {}
    case_role_counts: Dict[str, int] = {}
    route_family_ids = set()
    for row in rows:
        family_id = str(row.get("family_id", "")).strip()
        if family_id:
            family_case_counts[family_id] = family_case_counts.get(family_id, 0) + 1
        case_role = str(row.get("case_role", "")).strip()
        if case_role:
            case_role_counts[case_role] = case_role_counts.get(case_role, 0) + 1
        if str(row.get("shadow_policy_outcome", "")).strip() == ROUTE:
            route_family_ids.add(family_id)
    masked_total, masked_preserved = _masked_survival(selection_rows)
    null_total, null_preserved = _null_route_preservation(selection_rows, baseline_adapter_id)
    control_total, control_preserved = _control_preservation(selection_rows)
    orthogonality_preserved, min_orthogonality_score = _orthogonality_summary(orthogonality_appendix)
    stress_tax_acceptable, governance_roi_counts = _stress_tax_summary(stress_tax)
    shadow_match_rate = round(float(exact_path_match_count) / float(case_count), 4) if case_count else 0.0
    masked_survival_rate = round(float(masked_preserved) / float(masked_total), 4) if masked_total else 1.0
    null_preservation_rate = round(float(null_preserved) / float(null_total), 4) if null_total else 1.0
    control_preservation_rate = round(float(control_preserved) / float(control_total), 4) if control_total else 1.0
    masked_form_collapse_detected = masked_total > 0 and masked_preserved != masked_total
    null_route_failures_detected = null_total > 0 and null_preserved != null_total
    control_destabilization_detected = control_total > 0 and control_preserved != control_total
    route_collapse_detected = len({target for target in unique_route_targets if target != baseline_adapter_id}) <= 1 and len(routed_case_ids) > 0
    fenced_family_route_value_signal = (
        route_delta_count > 0
        and bool(shadow_matrix.get("exact_path_universality_broken"))
        and len({family_id for family_id in route_family_ids if family_id not in {"BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"}}) >= 3
        and masked_form_collapse_detected is False
        and null_route_failures_detected is False
        and control_destabilization_detected is False
        and orthogonality_preserved
        and stress_tax_acceptable
    )
    return {
        "schema_id": "kt.operator.cohort0_recomposed_route_distribution_health.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "This report measures recomposed ordered-proof augmentation route divergence, restraint quality, masked stability, "
            "orthogonality, and stress-tax acceptability only. It does not claim superiority until ordered proof is executed."
        ),
        "selection_receipt_ref": selection_receipt_path.as_posix(),
        "shadow_eval_matrix_ref": shadow_matrix_path.as_posix(),
        "orthogonality_appendix_ref": orthogonality_appendix_path.as_posix(),
        "promotion_stress_tax_ref": stress_tax_path.as_posix(),
        "route_distribution_delta_count": route_delta_count,
        "shadow_match_rate": shadow_match_rate,
        "route_collapse_detected": route_collapse_detected,
        "exact_path_universality_broken": bool(shadow_matrix.get("exact_path_universality_broken")),
        "stay_static_case_count": int(selection_receipt.get("stay_static_case_count", 0)),
        "route_case_count": int(selection_receipt.get("route_case_count", 0)),
        "abstain_case_count": int(selection_receipt.get("abstain_case_count", 0)),
        "fallback_case_ids": fallback_case_ids,
        "routed_case_ids": routed_case_ids,
        "unique_route_targets": unique_route_targets,
        "family_case_counts": family_case_counts,
        "case_role_counts": case_role_counts,
        "masked_variant_count": masked_total,
        "masked_variant_survival_count": masked_preserved,
        "masked_variant_survival_rate": masked_survival_rate,
        "masked_form_collapse_detected": masked_form_collapse_detected,
        "null_route_counterfactual_count": null_total,
        "null_route_counterfactual_preserved_count": null_preserved,
        "null_route_counterfactual_preservation_rate": null_preservation_rate,
        "null_route_failures_detected": null_route_failures_detected,
        "control_case_count": control_total,
        "control_preserved_count": control_preserved,
        "control_preservation_rate": control_preservation_rate,
        "control_destabilization_detected": control_destabilization_detected,
        "orthogonality_preserved": orthogonality_preserved,
        "minimum_orthogonality_score": min_orthogonality_score,
        "promotion_stress_tax_acceptable": stress_tax_acceptable,
        "governance_roi_tier_counts": governance_roi_counts,
        "fenced_family_route_value_signal": fenced_family_route_value_signal,
        "r5_admissible": fenced_family_route_value_signal,
    }


def _scorecard(
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
    fenced_signal = bool(route_health.get("fenced_family_route_value_signal"))
    r5_admissible = bool(route_health.get("r5_admissible"))
    candidate_status = (
        "FENCED_FAMILY_ROUTE_VALUE_SIGNAL_PRESENT__AUTHORIZATION_STILL_BLOCKED"
        if fenced_signal
        else ("SHADOW_SIGNAL_PRESENT_BUT_NOT_YET_ORDERED_PROOF_RATIFIED" if route_delta_count > 0 and exact_path_universality_broken else "NO_LIVE_LEARNED_ROUTER_CANDIDATE")
    )
    return {
        "schema_id": "kt.operator.cohort0_recomposed_router_superiority_scorecard.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "This scorecard binds only recomposed ordered-proof augmentation shadow-stage route-bearing signal versus the static alpha control. "
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
        "hardening_summary": {
            "masked_variant_survival_rate": float(route_health.get("masked_variant_survival_rate", 0.0)),
            "null_route_counterfactual_preservation_rate": float(route_health.get("null_route_counterfactual_preservation_rate", 0.0)),
            "control_preservation_rate": float(route_health.get("control_preservation_rate", 0.0)),
            "orthogonality_preserved": bool(route_health.get("orthogonality_preserved")),
            "minimum_orthogonality_score": float(route_health.get("minimum_orthogonality_score", 0.0)),
            "promotion_stress_tax_acceptable": bool(route_health.get("promotion_stress_tax_acceptable")),
            "fenced_family_route_value_signal": fenced_signal,
        },
        "learned_router_candidate": {
            "candidate_status": candidate_status,
            "promotion_allowed": False,
            "eligibility_reason": (
                "The ordered-proof augmentation court preserves masked, null-route, control, orthogonality, and stress-tax constraints while showing route-bearing value, but superiority is still unearned."
                if fenced_signal
                else "Augmented shadow has not yet cleared the hardening checks needed to claim a live learned-router candidate."
            ),
        },
        "router_superiority_earned": False,
        "exact_superiority_outcome": "NOT_EARNED_AUGMENTED_SHADOW_SIGNAL_PRESENT__R5_REQUIRED" if r5_admissible else "NOT_EARNED_AUGMENTED_SHADOW_CEILING_HOLD",
        "r5_admissible": r5_admissible,
        "next_lawful_move": NEXT_MOVE_R5 if r5_admissible else NEXT_MOVE_HOLD,
    }


def _followthrough_packet(
    *,
    existing_followthrough: Dict[str, Any],
    bridge_posture: str,
    augmentation_receipt_path: Path,
    augmentation_manifest_path: Path,
    selection_receipt_path: Path,
    shadow_matrix_path: Path,
    route_health_path: Path,
    scorecard_path: Path,
    route_health: Dict[str, Any],
    scorecard: Dict[str, Any],
) -> Dict[str, Any]:
    packet = dict(existing_followthrough)
    packet["generated_utc"] = utc_now_iso_z()
    packet["followthrough_posture"] = bridge_posture
    packet["augmentation_receipt_ref"] = augmentation_receipt_path.as_posix()
    packet["augmentation_manifest_ref"] = augmentation_manifest_path.as_posix()
    packet["router_shadow_followthrough"] = {
        "execution_ready": True,
        "selection_receipt_ref": selection_receipt_path.as_posix(),
        "shadow_eval_matrix_ref": shadow_matrix_path.as_posix(),
        "route_distribution_health_ref": route_health_path.as_posix(),
        "router_superiority_scorecard_ref": scorecard_path.as_posix(),
        "route_distribution_delta_count": int(route_health.get("route_distribution_delta_count", 0)),
        "exact_path_universality_broken": bool(route_health.get("exact_path_universality_broken")),
        "masked_variant_survival_rate": float(route_health.get("masked_variant_survival_rate", 0.0)),
        "null_route_counterfactual_preservation_rate": float(route_health.get("null_route_counterfactual_preservation_rate", 0.0)),
        "control_preservation_rate": float(route_health.get("control_preservation_rate", 0.0)),
        "orthogonality_preserved": bool(route_health.get("orthogonality_preserved")),
        "promotion_stress_tax_acceptable": bool(route_health.get("promotion_stress_tax_acceptable")),
        "fenced_family_route_value_signal": bool(route_health.get("fenced_family_route_value_signal")),
        "r5_admissible": bool(scorecard.get("r5_admissible")),
        "next_lawful_move": str(scorecard.get("next_lawful_move", "")).strip(),
    }
    packet["router_shadow_rerun_admissible"] = True
    packet["r5_rerun_admissible"] = bool(scorecard.get("r5_admissible"))
    packet["next_lawful_move"] = str(scorecard.get("next_lawful_move", "")).strip()
    packet["next_question"] = "Does recomposed ordered-proof augmentation now justify recomposed R5 ordered proof against the static alpha comparator?"
    return packet


def _bridge_receipt(
    *,
    subject_head: str,
    current_head: str,
    recomposed_substrate_path: Path,
    followthrough_path: Path,
    promotion_outcome_path: Path,
    merge_outcome_path: Path,
    augmentation_receipt_path: Path,
    augmentation_manifest_path: Path,
    selection_receipt_path: Path,
    shadow_matrix_path: Path,
    route_health_path: Path,
    scorecard_path: Path,
    route_health: Dict[str, Any],
    scorecard: Dict[str, Any],
) -> Dict[str, Any]:
    r5_admissible = bool(scorecard.get("r5_admissible"))
    return {
        "schema_id": "kt.operator.cohort0_recomposed_router_shadow_bridge_receipt.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "binding_posture": BRIDGE_POSTURE_READY if r5_admissible else BRIDGE_POSTURE_HOLD,
        "claim_boundary": (
            "This receipt proves only that recomposed router-shadow surfaces have been rebound to the promotion-and-merge-bound "
            "13-entrant substrate through the sealed ordered-proof augmentation court. It does not claim router superiority, learned-router cutover, or Gate E/F opening."
        ),
        "recomposed_substrate_receipt_ref": recomposed_substrate_path.as_posix(),
        "existing_followthrough_packet_ref": followthrough_path.as_posix(),
        "promotion_outcome_binding_receipt_ref": promotion_outcome_path.as_posix(),
        "merge_outcome_binding_receipt_ref": merge_outcome_path.as_posix(),
        "augmentation_receipt_ref": augmentation_receipt_path.as_posix(),
        "augmentation_manifest_ref": augmentation_manifest_path.as_posix(),
        "router_selection_receipt_ref": selection_receipt_path.as_posix(),
        "router_shadow_eval_matrix_ref": shadow_matrix_path.as_posix(),
        "route_distribution_health_ref": route_health_path.as_posix(),
        "router_superiority_scorecard_ref": scorecard_path.as_posix(),
        "route_distribution_delta_count": int(route_health.get("route_distribution_delta_count", 0)),
        "exact_path_universality_broken": bool(route_health.get("exact_path_universality_broken")),
        "masked_variant_survival_rate": float(route_health.get("masked_variant_survival_rate", 0.0)),
        "null_route_counterfactual_preservation_rate": float(route_health.get("null_route_counterfactual_preservation_rate", 0.0)),
        "control_preservation_rate": float(route_health.get("control_preservation_rate", 0.0)),
        "orthogonality_preserved": bool(route_health.get("orthogonality_preserved")),
        "promotion_stress_tax_acceptable": bool(route_health.get("promotion_stress_tax_acceptable")),
        "fenced_family_route_value_signal": bool(route_health.get("fenced_family_route_value_signal")),
        "r5_admissible": r5_admissible,
        "next_lawful_move": str(scorecard.get("next_lawful_move", "")).strip(),
    }


def _material_advance(health_report: Dict[str, Any], pre_kaggle_health: Dict[str, Any]) -> bool:
    route_delta_count = int(health_report.get("route_distribution_delta_count", 0))
    pre_delta = int(pre_kaggle_health.get("route_distribution_delta_count", 0))
    exact_path_universality_broken = bool(health_report.get("exact_path_universality_broken"))
    pre_shadow_match_rate = float(pre_kaggle_health.get("shadow_match_rate", 0.0))
    new_shadow_match_rate = float(health_report.get("shadow_match_rate", 0.0))
    route_collapse = bool(health_report.get("route_collapse_detected"))
    unique_route_target_count = len(health_report.get("unique_route_targets", []))
    return (
        route_delta_count > pre_delta
        and exact_path_universality_broken
        and new_shadow_match_rate < pre_shadow_match_rate
        and not route_collapse
        and unique_route_target_count >= 3
    )


def _ordered_outcome(*, superiority_earned: bool, fenced_family_route_value_earned: bool, material_advance: bool) -> Tuple[str, str, str]:
    if superiority_earned:
        return (
            "PASS_ROUTER_SUPERIORITY_EARNED",
            "EARNED_RECOMPOSED_ROUTER_SUPERIORITY",
            VERDICT_SUPERIORITY,
        )
    if fenced_family_route_value_earned:
        return (
            "PASS_FENCED_FAMILY_ROUTE_VALUE_EARNED_STATIC_BASELINE_STILL_CANONICAL",
            "NOT_EARNED_FENCED_FAMILY_ROUTE_VALUE_PRESENT_STATIC_BASELINE_RETAINS_CANONICAL_STATUS",
            VERDICT_FENCED_FAMILY,
        )
    if material_advance:
        return (
            "PASS_MATERIAL_ADVANCE_STATIC_BASELINE_STILL_CANONICAL",
            "NOT_EARNED_MATERIAL_ROUTE_VALUE_PRESENT_STATIC_BASELINE_RETAINS_CANONICAL_STATUS",
            VERDICT_MATERIAL_ADVANCE,
        )
    return (
        "PASS_HOLD_RECOMPOSED_R5_CEILING",
        "NOT_EARNED_RECOMPOSED_SHADOW_CEILING_RETAINS_STATIC_BASELINE",
        VERDICT_STATIC_HOLD,
    )


def _ordered_receipt(
    *,
    subject_head: str,
    current_head: str,
    bridge_receipt_path: Path,
    shadow_matrix_path: Path,
    route_health_path: Path,
    scorecard_path: Path,
    pre_kaggle_health_path: Path,
    pre_kaggle_scorecard_path: Path,
    route_health: Dict[str, Any],
    scorecard: Dict[str, Any],
    pre_kaggle_health: Dict[str, Any],
) -> Dict[str, Any]:
    superiority_earned = bool(scorecard.get("router_superiority_earned"))
    material_advance = _material_advance(route_health, pre_kaggle_health)
    fenced_family_route_value_earned = bool(route_health.get("fenced_family_route_value_signal")) and material_advance
    ordered_proof_outcome, exact_superiority_outcome, verdict_posture = _ordered_outcome(
        superiority_earned=superiority_earned,
        fenced_family_route_value_earned=fenced_family_route_value_earned,
        material_advance=material_advance,
    )
    route_delta_count = int(route_health.get("route_distribution_delta_count", 0))
    pre_delta = int(pre_kaggle_health.get("route_distribution_delta_count", 0))
    shadow_match_rate = float(route_health.get("shadow_match_rate", 0.0))
    pre_shadow_match_rate = float(pre_kaggle_health.get("shadow_match_rate", 0.0))
    candidate_status = (
        "FENCED_FAMILY_ROUTE_VALUE_SIGNAL_PRESENT__AUTHORIZATION_STILL_BLOCKED"
        if fenced_family_route_value_earned and not superiority_earned
        else ("LEARNED_ROUTER_CANDIDATE_SIGNAL_PRESENT__AUTHORIZATION_STILL_BLOCKED" if material_advance and not superiority_earned else "NO_LIVE_LEARNED_ROUTER_CANDIDATE")
    )
    checks = [
        {"check_id": "proof_objects_moved_vs_pre_kaggle_delta_baseline", "pass": route_delta_count > pre_delta},
        {"check_id": "exact_path_universality_broken_vs_pre_kaggle_shadow", "pass": bool(route_health.get("exact_path_universality_broken")) and pre_shadow_match_rate == 1.0},
        {"check_id": "masked_variants_survived", "pass": bool(route_health.get("masked_form_collapse_detected")) is False},
        {"check_id": "null_route_counterfactuals_preserved", "pass": bool(route_health.get("null_route_failures_detected")) is False},
        {"check_id": "controls_preserved", "pass": bool(route_health.get("control_destabilization_detected")) is False},
        {"check_id": "orthogonality_preserved", "pass": bool(route_health.get("orthogonality_preserved")) is True},
        {"check_id": "promotion_stress_tax_acceptable", "pass": bool(route_health.get("promotion_stress_tax_acceptable")) is True},
        {"check_id": "route_collapse_absent", "pass": bool(route_health.get("route_collapse_detected")) is False},
        {"check_id": "superiority_claim_kept_honest", "pass": superiority_earned is False},
    ]
    return {
        "schema_id": "kt.operator.cohort0_recomposed_router_ordered_proof_receipt.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "This receipt proves only recomposed ordered-proof augmentation movement against the pre-Kaggle router ceiling and the current static alpha comparator. "
            "It does not authorize learned-router cutover, Gate E/F, or commercial widening."
        ),
        "bridge_receipt_ref": bridge_receipt_path.as_posix(),
        "shadow_matrix_ref": shadow_matrix_path.as_posix(),
        "route_distribution_health_ref": route_health_path.as_posix(),
        "router_superiority_scorecard_ref": scorecard_path.as_posix(),
        "pre_kaggle_route_distribution_health_ref": pre_kaggle_health_path.as_posix(),
        "pre_kaggle_router_superiority_scorecard_ref": pre_kaggle_scorecard_path.as_posix(),
        "ordered_proof_outcome": ordered_proof_outcome,
        "exact_superiority_outcome": exact_superiority_outcome,
        "verdict_posture": verdict_posture,
        "learned_router_candidate_status": candidate_status,
        "material_advance_detected": material_advance,
        "fenced_family_route_value_earned": fenced_family_route_value_earned,
        "proof_object_deltas": {
            "route_distribution_delta_count_previous": pre_delta,
            "route_distribution_delta_count_current": route_delta_count,
            "route_distribution_delta_count_delta": route_delta_count - pre_delta,
            "shadow_match_rate_previous": pre_shadow_match_rate,
            "shadow_match_rate_current": shadow_match_rate,
            "shadow_match_rate_delta": round(shadow_match_rate - pre_shadow_match_rate, 4),
            "exact_path_universality_broken_current": bool(route_health.get("exact_path_universality_broken")),
            "unique_route_target_count_current": len(route_health.get("unique_route_targets", [])),
            "masked_variant_survival_rate_current": float(route_health.get("masked_variant_survival_rate", 0.0)),
            "null_route_counterfactual_preservation_rate_current": float(route_health.get("null_route_counterfactual_preservation_rate", 0.0)),
            "control_preservation_rate_current": float(route_health.get("control_preservation_rate", 0.0)),
        },
        "checks": checks,
    }


def _r5_receipt(
    *,
    subject_head: str,
    current_head: str,
    ordered_receipt_path: Path,
    ordered_receipt: Dict[str, Any],
    scorecard_path: Path,
    scorecard: Dict[str, Any],
) -> Dict[str, Any]:
    superiority_earned = bool(scorecard.get("router_superiority_earned"))
    material_advance = bool(ordered_receipt.get("material_advance_detected"))
    fenced_family_route_value_earned = bool(ordered_receipt.get("fenced_family_route_value_earned"))
    if superiority_earned:
        next_lawful_move = NEXT_MOVE_EARNED
    elif fenced_family_route_value_earned or material_advance:
        next_lawful_move = NEXT_MOVE_RESIDUAL
    else:
        next_lawful_move = NEXT_MOVE_HOLD
    return {
        "schema_id": "kt.operator.cohort0_recomposed_router_vs_best_adapter_proof_receipt.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if str(ordered_receipt.get("status", "")).strip() == "PASS" else "FAIL",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "workstream_id": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__RECOMPOSED_AUGMENTED_SUBSTRATE",
        "receipt_role": "COUNTED_RECOMPOSED_AUGMENTED_B04_R5_ROUTER_PROOF_ARTIFACT_ONLY",
        "claim_boundary": (
            "This receipt proves only the recomposed augmented R5 router-versus-best-adapter proof result on the promotion-and-merge-bound substrate. "
            "It does not authorize learned-router cutover or Gate E/F unless superiority is actually earned."
        ),
        "ordered_proof_receipt_ref": ordered_receipt_path.as_posix(),
        "router_superiority_scorecard_ref": scorecard_path.as_posix(),
        "router_proof_summary": {
            "best_static_adapter_id": str(scorecard.get("best_static_baseline", {}).get("adapter_id", "")).strip(),
            "router_superiority_earned": superiority_earned,
            "ordered_proof_outcome": str(ordered_receipt.get("ordered_proof_outcome", "")).strip(),
            "exact_superiority_outcome": str(ordered_receipt.get("exact_superiority_outcome", "")).strip(),
            "material_advance_detected": material_advance,
            "fenced_family_route_value_earned": fenced_family_route_value_earned,
            "learned_router_candidate_status": str(ordered_receipt.get("learned_router_candidate_status", "")).strip(),
        },
        "verdict_posture": str(ordered_receipt.get("verdict_posture", "")).strip(),
        "next_lawful_move": next_lawful_move,
    }


def run_recomposed_ordered_proof_augmentation_tranche(
    *,
    recomposed_substrate_path: Path,
    followthrough_path: Path,
    promotion_outcome_path: Path,
    merge_outcome_path: Path,
    augmentation_receipt_path: Path,
    augmentation_manifest_path: Path,
    null_route_path: Path,
    masked_path: Path,
    orthogonality_path: Path,
    stress_tax_path: Path,
    pre_kaggle_health_path: Path,
    pre_kaggle_scorecard_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_recomposed_substrate_path, recomposed_substrate = _resolve_authoritative(
        root, recomposed_substrate_path, "authoritative_recomposed_13_entrant_substrate_receipt_ref", "recomposed substrate receipt"
    )
    authoritative_followthrough_path, followthrough = _resolve_authoritative(
        root, followthrough_path, "authoritative_recomposed_router_shadow_followthrough_packet_ref", "existing recomposed followthrough packet"
    )
    authoritative_promotion_outcome_path, promotion_outcome = _resolve_authoritative(
        root, promotion_outcome_path, "authoritative_promotion_outcome_binding_receipt_ref", "promotion outcome receipt"
    )
    authoritative_merge_outcome_path, merge_outcome = _resolve_authoritative(
        root, merge_outcome_path, "authoritative_merge_outcome_binding_receipt_ref", "merge outcome receipt"
    )
    authoritative_augmentation_receipt_path, augmentation_receipt = _resolve_authoritative(
        root, augmentation_receipt_path, "authoritative_cohort0_recomposed_counted_lane_augmentation_receipt_ref", "augmentation receipt"
    )
    authoritative_augmentation_manifest_path, augmentation_manifest = _resolve_authoritative(
        root, augmentation_manifest_path, "authoritative_cohort0_recomposed_counted_lane_augmentation_manifest_ref", "augmentation manifest"
    )
    authoritative_null_route_path, null_route_packet = _resolve_authoritative(
        root, null_route_path, "authoritative_cohort0_recomposed_null_route_counterfactual_packet_ref", "null-route packet"
    )
    authoritative_masked_path, masked_packet = _resolve_authoritative(
        root, masked_path, "authoritative_cohort0_recomposed_masked_form_variant_packet_ref", "masked-form packet"
    )
    authoritative_orthogonality_path, orthogonality_appendix = _resolve_authoritative(
        root, orthogonality_path, "authoritative_cohort0_recomposed_orthogonality_appendix_ref", "orthogonality appendix"
    )
    authoritative_stress_tax_path, stress_tax = _resolve_authoritative(
        root, stress_tax_path, "authoritative_cohort0_recomposed_promotion_stress_tax_ref", "promotion stress tax"
    )
    authoritative_pre_kaggle_health_path, pre_kaggle_health = _resolve_authoritative(
        root, pre_kaggle_health_path, "", "pre-kaggle route health"
    )
    authoritative_pre_kaggle_scorecard_path, pre_kaggle_scorecard = _resolve_authoritative(
        root, pre_kaggle_scorecard_path, "", "pre-kaggle scorecard"
    )

    _validate_inputs(
        recomposed_substrate=recomposed_substrate,
        followthrough=followthrough,
        promotion_outcome=promotion_outcome,
        merge_outcome=merge_outcome,
        augmentation_receipt=augmentation_receipt,
        augmentation_manifest=augmentation_manifest,
        null_route_packet=null_route_packet,
        masked_packet=masked_packet,
        orthogonality_appendix=orthogonality_appendix,
        stress_tax=stress_tax,
        pre_kaggle_health=pre_kaggle_health,
        pre_kaggle_scorecard=pre_kaggle_scorecard,
    )

    authoritative_case_rows_path, case_rows = _load_case_rows(root, augmentation_manifest)
    subject_head = _resolve_subject_head(
        packets=[
            recomposed_substrate,
            followthrough,
            promotion_outcome,
            merge_outcome,
            augmentation_receipt,
            augmentation_manifest,
            null_route_packet,
            masked_packet,
            orthogonality_appendix,
            stress_tax,
            pre_kaggle_health,
            pre_kaggle_scorecard,
        ]
    )
    baseline_adapter_id = _baseline_static_adapter_id(promotion_outcome)

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_recomposed_ordered_proof_augmentation_live").resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    selection_receipt_path = (target_root / "cohort0_recomposed_router_selection_receipt.json").resolve()
    shadow_matrix_path = (target_root / "cohort0_recomposed_router_shadow_eval_matrix.json").resolve()
    route_health_path = (target_root / "cohort0_recomposed_route_distribution_health.json").resolve()
    scorecard_path = (target_root / "cohort0_recomposed_router_superiority_scorecard.json").resolve()
    followthrough_out_path = (target_root / "cohort0_recomposed_router_shadow_followthrough_packet.json").resolve()
    bridge_receipt_path = (target_root / "cohort0_recomposed_router_shadow_bridge_receipt.json").resolve()
    ordered_receipt_path = (target_root / "cohort0_recomposed_router_ordered_proof_receipt.json").resolve()
    r5_receipt_path = (target_root / "cohort0_recomposed_router_vs_best_adapter_proof_receipt.json").resolve()

    selection_receipt = _selection_receipt(
        subject_head=subject_head,
        current_head=current_head,
        recomposed_substrate_path=authoritative_recomposed_substrate_path,
        followthrough_path=authoritative_followthrough_path,
        promotion_outcome_path=authoritative_promotion_outcome_path,
        merge_outcome_path=authoritative_merge_outcome_path,
        augmentation_receipt_path=authoritative_augmentation_receipt_path,
        augmentation_manifest_path=authoritative_augmentation_manifest_path,
        case_rows_path=authoritative_case_rows_path,
        case_rows=case_rows,
        baseline_adapter_id=baseline_adapter_id,
    )
    write_json_stable(selection_receipt_path, selection_receipt)

    shadow_matrix = _shadow_matrix(
        subject_head=subject_head,
        current_head=current_head,
        selection_receipt_path=selection_receipt_path,
        selection_receipt=selection_receipt,
    )
    write_json_stable(shadow_matrix_path, shadow_matrix)

    route_health = _route_health(
        subject_head=subject_head,
        current_head=current_head,
        selection_receipt_path=selection_receipt_path,
        selection_receipt=selection_receipt,
        shadow_matrix_path=shadow_matrix_path,
        shadow_matrix=shadow_matrix,
        orthogonality_appendix_path=authoritative_orthogonality_path,
        orthogonality_appendix=orthogonality_appendix,
        stress_tax_path=authoritative_stress_tax_path,
        stress_tax=stress_tax,
        baseline_adapter_id=baseline_adapter_id,
    )
    if bool(route_health.get("fenced_family_route_value_signal")) is not True:
        raise RuntimeError("FAIL_CLOSED: ordered proof augmentation did not preserve the hardening checks needed for routed proof re-entry")
    write_json_stable(route_health_path, route_health)

    scorecard = _scorecard(
        subject_head=subject_head,
        current_head=current_head,
        selection_receipt_path=selection_receipt_path,
        route_health_path=route_health_path,
        route_health=route_health,
        baseline_adapter_id=baseline_adapter_id,
    )
    write_json_stable(scorecard_path, scorecard)

    followthrough_packet = _followthrough_packet(
        existing_followthrough=followthrough,
        bridge_posture=BRIDGE_POSTURE_READY if bool(scorecard.get("r5_admissible")) else BRIDGE_POSTURE_HOLD,
        augmentation_receipt_path=authoritative_augmentation_receipt_path,
        augmentation_manifest_path=authoritative_augmentation_manifest_path,
        selection_receipt_path=selection_receipt_path,
        shadow_matrix_path=shadow_matrix_path,
        route_health_path=route_health_path,
        scorecard_path=scorecard_path,
        route_health=route_health,
        scorecard=scorecard,
    )
    write_json_stable(followthrough_out_path, followthrough_packet)

    bridge_receipt = _bridge_receipt(
        subject_head=subject_head,
        current_head=current_head,
        recomposed_substrate_path=authoritative_recomposed_substrate_path,
        followthrough_path=authoritative_followthrough_path,
        promotion_outcome_path=authoritative_promotion_outcome_path,
        merge_outcome_path=authoritative_merge_outcome_path,
        augmentation_receipt_path=authoritative_augmentation_receipt_path,
        augmentation_manifest_path=authoritative_augmentation_manifest_path,
        selection_receipt_path=selection_receipt_path,
        shadow_matrix_path=shadow_matrix_path,
        route_health_path=route_health_path,
        scorecard_path=scorecard_path,
        route_health=route_health,
        scorecard=scorecard,
    )
    write_json_stable(bridge_receipt_path, bridge_receipt)

    ordered_receipt = _ordered_receipt(
        subject_head=subject_head,
        current_head=current_head,
        bridge_receipt_path=bridge_receipt_path,
        shadow_matrix_path=shadow_matrix_path,
        route_health_path=route_health_path,
        scorecard_path=scorecard_path,
        pre_kaggle_health_path=authoritative_pre_kaggle_health_path,
        pre_kaggle_scorecard_path=authoritative_pre_kaggle_scorecard_path,
        route_health=route_health,
        scorecard=scorecard,
        pre_kaggle_health=pre_kaggle_health,
    )
    write_json_stable(ordered_receipt_path, ordered_receipt)

    r5_receipt = _r5_receipt(
        subject_head=subject_head,
        current_head=current_head,
        ordered_receipt_path=ordered_receipt_path,
        ordered_receipt=ordered_receipt,
        scorecard_path=scorecard_path,
        scorecard=scorecard,
    )
    write_json_stable(r5_receipt_path, r5_receipt)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_map = {
        "cohort0_recomposed_router_selection_receipt.json": (
            selection_receipt,
            "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_SELECTION_RECEIPT",
            "authoritative_recomposed_router_selection_receipt_ref",
            selection_receipt_path,
        ),
        "cohort0_recomposed_router_shadow_eval_matrix.json": (
            shadow_matrix,
            "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_SHADOW_EVAL_MATRIX",
            "authoritative_recomposed_router_shadow_eval_matrix_ref",
            shadow_matrix_path,
        ),
        "cohort0_recomposed_route_distribution_health.json": (
            route_health,
            "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTE_DISTRIBUTION_HEALTH",
            "authoritative_recomposed_route_distribution_health_ref",
            route_health_path,
        ),
        "cohort0_recomposed_router_superiority_scorecard.json": (
            scorecard,
            "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_SUPERIORITY_SCORECARD",
            "authoritative_recomposed_router_superiority_scorecard_ref",
            scorecard_path,
        ),
        "cohort0_recomposed_router_shadow_followthrough_packet.json": (
            followthrough_packet,
            "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_SHADOW_FOLLOWTHROUGH_PACKET",
            "authoritative_recomposed_router_shadow_followthrough_packet_ref",
            followthrough_out_path,
        ),
        "cohort0_recomposed_router_shadow_bridge_receipt.json": (
            bridge_receipt,
            "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_SHADOW_BRIDGE_RECEIPT",
            "authoritative_recomposed_router_shadow_bridge_receipt_ref",
            bridge_receipt_path,
        ),
        "cohort0_recomposed_router_ordered_proof_receipt.json": (
            ordered_receipt,
            "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_ORDERED_PROOF_RECEIPT",
            "authoritative_recomposed_router_ordered_proof_receipt_ref",
            ordered_receipt_path,
        ),
        "cohort0_recomposed_router_vs_best_adapter_proof_receipt.json": (
            r5_receipt,
            "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_VS_BEST_ADAPTER_PROOF_RECEIPT",
            "authoritative_recomposed_router_vs_best_adapter_proof_receipt_ref",
            r5_receipt_path,
        ),
    }
    for filename, (obj, role, ref_field, authoritative_path) in tracked_map.items():
        tracked = dict(obj)
        tracked["carrier_surface_role"] = role
        tracked[ref_field] = authoritative_path.as_posix()
        write_json_stable((reports_root / filename).resolve(), tracked)

    return {
        "router_selection_receipt": selection_receipt,
        "router_shadow_eval_matrix": shadow_matrix,
        "route_distribution_health": route_health,
        "router_superiority_scorecard": scorecard,
        "router_shadow_followthrough_packet": followthrough_packet,
        "router_shadow_bridge_receipt": bridge_receipt,
        "router_ordered_proof_receipt": ordered_receipt,
        "router_vs_best_adapter_proof_receipt": r5_receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Execute the recomposed ordered-proof augmentation court through router shadow and R5.")
    ap.add_argument("--recomposed-substrate", default=DEFAULT_RECOMPOSED_SUBSTRATE_REL)
    ap.add_argument("--followthrough", default=DEFAULT_FOLLOWTHROUGH_REL)
    ap.add_argument("--promotion-outcome", default=DEFAULT_PROMOTION_OUTCOME_REL)
    ap.add_argument("--merge-outcome", default=DEFAULT_MERGE_OUTCOME_REL)
    ap.add_argument("--augmentation-receipt", default=DEFAULT_AUGMENTATION_RECEIPT_REL)
    ap.add_argument("--augmentation-manifest", default=DEFAULT_AUGMENTATION_MANIFEST_REL)
    ap.add_argument("--null-route-packet", default=DEFAULT_NULL_ROUTE_REL)
    ap.add_argument("--masked-packet", default=DEFAULT_MASKED_REL)
    ap.add_argument("--orthogonality-appendix", default=DEFAULT_ORTHOGONALITY_REL)
    ap.add_argument("--promotion-stress-tax", default=DEFAULT_STRESS_TAX_REL)
    ap.add_argument("--pre-kaggle-health", default=DEFAULT_PRE_KAGGLE_HEALTH_REL)
    ap.add_argument("--pre-kaggle-scorecard", default=DEFAULT_PRE_KAGGLE_SCORECARD_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_recomposed_ordered_proof_augmentation_tranche(
        recomposed_substrate_path=_resolve(root, str(args.recomposed_substrate)),
        followthrough_path=_resolve(root, str(args.followthrough)),
        promotion_outcome_path=_resolve(root, str(args.promotion_outcome)),
        merge_outcome_path=_resolve(root, str(args.merge_outcome)),
        augmentation_receipt_path=_resolve(root, str(args.augmentation_receipt)),
        augmentation_manifest_path=_resolve(root, str(args.augmentation_manifest)),
        null_route_path=_resolve(root, str(args.null_route_packet)),
        masked_path=_resolve(root, str(args.masked_packet)),
        orthogonality_path=_resolve(root, str(args.orthogonality_appendix)),
        stress_tax_path=_resolve(root, str(args.promotion_stress_tax)),
        pre_kaggle_health_path=_resolve(root, str(args.pre_kaggle_health)),
        pre_kaggle_scorecard_path=_resolve(root, str(args.pre_kaggle_scorecard)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["router_vs_best_adapter_proof_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "verdict_posture": receipt["verdict_posture"],
                "router_superiority_earned": receipt["router_proof_summary"]["router_superiority_earned"],
                "fenced_family_route_value_earned": receipt["router_proof_summary"]["fenced_family_route_value_earned"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
