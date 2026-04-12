from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_R5_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_vs_best_adapter_proof_receipt.json"
DEFAULT_ORDERED_PROOF_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_ordered_proof_receipt.json"
DEFAULT_HEALTH_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_route_distribution_health.json"
DEFAULT_SELECTION_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_selection_receipt.json"
DEFAULT_SHADOW_MATRIX_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_shadow_eval_matrix.json"
DEFAULT_AUGMENTATION_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_counted_lane_augmentation_manifest.json"
DEFAULT_NULL_ROUTE_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_null_route_counterfactual_packet.json"
DEFAULT_MASKED_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_masked_form_variant_packet.json"
DEFAULT_ORTHOGONALITY_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_orthogonality_appendix.json"
DEFAULT_STRESS_TAX_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_promotion_stress_tax.json"
DEFAULT_PAIRWISE_ROUTE_ECONOMICS_REL = "KT_PROD_CLEANROOM/reports/pairwise_route_economics_scorecard.json"
DEFAULT_FOLLOWTHROUGH_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_shadow_followthrough_packet.json"

DEFAULT_TRACKED_PACKET = "cohort0_residual_alpha_dominance_packet.json"
DEFAULT_TRACKED_WEDGE_SPEC = "cohort0_residual_alpha_dominance_wedge_spec.json"
DEFAULT_TRACKED_ROUTE_ECONOMICS = "cohort0_recomposed_case_level_route_economics.json"
DEFAULT_TRACKED_SHORTCUT_TAGS = "cohort0_recomposed_shortcut_resistance_tags.json"

VERDICT_POSTURE = "RESIDUAL_ALPHA_DOMINANCE_PACKET_EMITTED__FENCED_FAMILY_ROUTE_VALUE_EARNED__R5_CEILING_STILL_ACTIVE"
NEXT_MOVE = "AUTHOR_RESIDUAL_ALPHA_REFINEMENT_CRUCIBLES__LAB_ONLY"

STATUS_CONTROL_STATIC = "RIGHTFUL_STATIC_HOLD__CONTROL_FAMILY"
STATUS_CONTROL_ABSTAIN = "RIGHTFUL_ABSTENTION__CONTROL_FAMILY"
STATUS_FENCED_ROUTE = "FENCED_FAMILY_ROUTE_VALUE_PRESENT__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY"
STATUS_FENCED_MIXED = "FENCED_FAMILY_ROUTE_AND_FAIL_CLOSED_VALUE_PRESENT__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY"

ROUTE = "ROUTE_TO_SPECIALIST"
STATIC = "STAY_STATIC_BASELINE"
ABSTAIN = "ABSTAIN_FOR_REVIEW"

CASE_ROLE_MULTIPLIER: Dict[str, float] = {
    "ROUTE_CANDIDATE": 1.00,
    "MASKED_FORM_VARIANT": 0.95,
    "NULL_ROUTE_COUNTERFACTUAL": 0.90,
    "CONTROL": 0.85,
}

SHORTCUT_CHANNELS: Dict[str, Dict[str, bool]] = {
    "DOMAIN_SKIN_SHIFT": {
        "lexical_cues": False,
        "formatting_cues": False,
        "domain_cues": True,
        "evidence_order": False,
    },
    "DOMAIN_CAMOUFLAGE": {
        "lexical_cues": False,
        "formatting_cues": False,
        "domain_cues": True,
        "evidence_order": False,
    },
    "VOICE_AND_FORMAT_SHIFT": {
        "lexical_cues": True,
        "formatting_cues": True,
        "domain_cues": False,
        "evidence_order": False,
    },
    "EVIDENCE_ORDER_INVERSION": {
        "lexical_cues": False,
        "formatting_cues": False,
        "domain_cues": False,
        "evidence_order": True,
    },
}

RECOVERY_CONFIG: Dict[str, Dict[str, str]] = {
    "STRATEGIST_CONSEQUENCE_CHAIN": {
        "target_lobe_id": "lobe.strategist.v1",
        "alpha_liability": "Alpha can stop at a locally good answer without pricing downstream failure cost.",
        "primary_axis": "hop_depth_and_causal_branching",
        "secondary_axis": "temporal_distortion",
        "next_focus": "STRATEGIST_CONSEQUENCE_CHAIN__SHARPEN_SEQUENCE_COST_AND_NULL_ROUTE_BOUNDARIES",
        "family_thesis": "Route strategist only where sequence-aware planning actually lowers rollback or downstream break cost.",
    },
    "AUDITOR_ADMISSIBILITY_FAIL_CLOSED": {
        "target_lobe_id": "lobe.auditor.v1",
        "alpha_liability": "Alpha can sound acceptable while underpricing receipt gaps, policy breaks, or overclaim risk.",
        "primary_axis": "adversarial_ambiguity",
        "secondary_axis": "governed_execution_burden",
        "next_focus": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED__SHARPEN_BREACH_TRIAGE_WITHOUT_LOSING_FAIL_CLOSED_DISCIPLINE",
        "family_thesis": "Route auditor where admissibility repair or fail-closed review materially reduces downstream governance cost.",
    },
    "BETA_SECOND_ORDER_REFRAME": {
        "target_lobe_id": "lobe.beta.v1",
        "alpha_liability": "Alpha can overcommit to the first clean framing instead of holding a live rival interpretation.",
        "primary_axis": "paradox_and_second_order_reframing",
        "secondary_axis": "language_complexity_or_domain_overlay",
        "next_focus": "BETA_SECOND_ORDER_REFRAME__SHARPEN_RIVAL_FRAME_COUNTERREAD_WITHOUT_ALPHA_COLLAPSE",
        "family_thesis": "Route beta where preserving the rival frame reduces false certainty and framing-lock error cost.",
    },
    "BOUNDARY_ABSTENTION_CONTROL": {
        "target_lobe_id": "",
        "alpha_liability": "Forced commitment under high ambiguity can cost more than lawful abstention.",
        "primary_axis": "abstention_calibration",
        "secondary_axis": "overclaim_guard",
        "next_focus": "BOUNDARY_ABSTENTION_CONTROL__PRESERVE_FAIL_CLOSED_HANDOFF_DISCIPLINE",
        "family_thesis": "Keep abstention lawful and stable even while other route-bearing families sharpen.",
    },
    "STATIC_NO_ROUTE_CONTROL": {
        "target_lobe_id": "lobe.alpha.v1",
        "alpha_liability": "No liability should be asserted on true static-control families.",
        "primary_axis": "hold_constant",
        "secondary_axis": "no_regression_guard",
        "next_focus": "STATIC_NO_ROUTE_CONTROL__PRESERVE_RIGHTFUL_STATIC_HOLD",
        "family_thesis": "Protect the rightful no-route hold so added route value does not mutate into route eagerness.",
    },
}

CONTROL_COST_PROFILES: Dict[str, Dict[str, float]] = {
    "BOUNDARY_ABSTENTION_CONTROL": {
        "mean_static_failure_cost": 1.08,
        "mean_misroute_cost": 1.16,
        "mean_abstain_miss_cost": 1.18,
        "mean_routed_execution_cost": 0.24,
        "mean_governance_roi": 0.18,
    },
    "STATIC_NO_ROUTE_CONTROL": {
        "mean_static_failure_cost": 0.00,
        "mean_misroute_cost": 0.94,
        "mean_abstain_miss_cost": 0.00,
        "mean_routed_execution_cost": 0.06,
        "mean_governance_roi": 0.12,
    },
}


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
    authoritative_ref = str(tracked.get(ref_field, "")).strip() if ref_field else ""
    authoritative_path = _resolve(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _resolve_subject_head(*, packets: Sequence[Dict[str, Any]]) -> str:
    heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if not heads:
        raise RuntimeError("FAIL_CLOSED: residual alpha dominance packet could not resolve any subject head")
    if len(heads) != 1:
        raise RuntimeError("FAIL_CLOSED: residual alpha dominance packet requires one consistent subject head")
    return next(iter(heads))


def _index_rows(rows: Sequence[Dict[str, Any]], *, key: str) -> Dict[str, Dict[str, Any]]:
    indexed: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: indexed row must be object")
        row_key = str(row.get(key, "")).strip()
        if not row_key:
            raise RuntimeError(f"FAIL_CLOSED: indexed row missing {key}")
        indexed[row_key] = row
    return indexed


def _validate_inputs(
    *,
    r5_receipt: Dict[str, Any],
    ordered_receipt: Dict[str, Any],
    health_report: Dict[str, Any],
    selection_receipt: Dict[str, Any],
    shadow_matrix: Dict[str, Any],
    augmentation_manifest: Dict[str, Any],
    null_route_packet: Dict[str, Any],
    masked_packet: Dict[str, Any],
    orthogonality_appendix: Dict[str, Any],
    stress_tax: Dict[str, Any],
    pairwise_route_economics: Dict[str, Any],
    followthrough_packet: Dict[str, Any],
) -> None:
    if str(r5_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed R5 receipt must PASS")
    if str(r5_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_RESIDUAL_ALPHA_DOMINANCE_PACKET":
        raise RuntimeError("FAIL_CLOSED: recomposed R5 receipt must require residual alpha dominance packet")
    router_summary = r5_receipt.get("router_proof_summary", {})
    if bool(router_summary.get("router_superiority_earned")) is not False:
        raise RuntimeError("FAIL_CLOSED: residual packet only applies before superiority is earned")
    if bool(router_summary.get("fenced_family_route_value_earned")) is not True:
        raise RuntimeError("FAIL_CLOSED: recomposed R5 receipt must show fenced-family route value")
    if str(r5_receipt.get("verdict_posture", "")).strip() != "FENCED_FAMILY_ROUTE_VALUE_EARNED__REMAIN_AT_R5_CEILING":
        raise RuntimeError("FAIL_CLOSED: recomposed R5 verdict posture mismatch")
    if str(ordered_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed ordered proof receipt must PASS")
    if bool(ordered_receipt.get("fenced_family_route_value_earned")) is not True:
        raise RuntimeError("FAIL_CLOSED: ordered proof receipt must keep fenced-family route value true")
    if str(ordered_receipt.get("verdict_posture", "")).strip() != "FENCED_FAMILY_ROUTE_VALUE_EARNED__REMAIN_AT_R5_CEILING":
        raise RuntimeError("FAIL_CLOSED: ordered proof verdict posture mismatch")
    if str(health_report.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed route distribution health must PASS")
    if int(health_report.get("route_distribution_delta_count", 0)) <= 0:
        raise RuntimeError("FAIL_CLOSED: recomposed route distribution health must keep nonzero route deltas")
    if bool(health_report.get("exact_path_universality_broken")) is not True:
        raise RuntimeError("FAIL_CLOSED: exact-path universality must remain broken")
    if bool(health_report.get("fenced_family_route_value_signal")) is not True:
        raise RuntimeError("FAIL_CLOSED: route health must show fenced-family route signal")
    if float(health_report.get("masked_variant_survival_rate", 0.0)) < 1.0:
        raise RuntimeError("FAIL_CLOSED: masked variants must survive in the residual packet court")
    if float(health_report.get("null_route_counterfactual_preservation_rate", 0.0)) < 1.0:
        raise RuntimeError("FAIL_CLOSED: null-route counterfactuals must remain preserved")
    if float(health_report.get("control_preservation_rate", 0.0)) < 1.0:
        raise RuntimeError("FAIL_CLOSED: controls must remain preserved")
    if bool(health_report.get("orthogonality_preserved")) is not True:
        raise RuntimeError("FAIL_CLOSED: orthogonality must remain preserved")
    if bool(health_report.get("promotion_stress_tax_acceptable")) is not True:
        raise RuntimeError("FAIL_CLOSED: promotion stress tax must remain acceptable")
    if str(selection_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed router selection receipt must PASS")
    if not isinstance(selection_receipt.get("case_rows"), list) or not selection_receipt.get("case_rows"):
        raise RuntimeError("FAIL_CLOSED: recomposed router selection receipt case_rows missing/invalid")
    if str(shadow_matrix.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed router shadow eval matrix must PASS")
    if not isinstance(shadow_matrix.get("rows"), list) or not shadow_matrix.get("rows"):
        raise RuntimeError("FAIL_CLOSED: recomposed router shadow eval matrix rows missing/invalid")
    if str(augmentation_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed counted-lane augmentation manifest must PASS")
    if sorted(str(x).strip() for x in augmentation_manifest.get("ready_family_ids", [])) != sorted(
        ["STRATEGIST_CONSEQUENCE_CHAIN", "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "BETA_SECOND_ORDER_REFRAME"]
    ):
        raise RuntimeError("FAIL_CLOSED: augmentation manifest ready families do not match the sealed court")
    if sorted(str(x).strip() for x in augmentation_manifest.get("control_family_ids", [])) != sorted(
        ["BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"]
    ):
        raise RuntimeError("FAIL_CLOSED: augmentation manifest control families do not match the sealed court")
    if str(null_route_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed null-route packet must PASS")
    if str(masked_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed masked packet must PASS")
    if str(orthogonality_appendix.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: orthogonality appendix must PASS")
    if str(stress_tax.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: promotion stress tax must PASS")
    if str(pairwise_route_economics.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise route economics must PASS")
    if str(followthrough_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed router shadow followthrough packet must PASS")


def _parse_alpha_liability(route_justification: str) -> str:
    marker = " because "
    if marker in route_justification:
        return route_justification.split(marker, 1)[1].strip()
    return route_justification.strip()


def _family_liability(selection_rows: Sequence[Dict[str, Any]], family_id: str) -> str:
    for row in selection_rows:
        if str(row.get("family_id", "")).strip() != family_id:
            continue
        if str(row.get("oracle_policy_outcome", "")).strip() != ROUTE:
            continue
        liability = _parse_alpha_liability(str(row.get("route_justification", "")).strip())
        if liability:
            return liability
    return RECOVERY_CONFIG[family_id]["alpha_liability"]


def _family_target_id(ready_rows: Sequence[Dict[str, Any]], family_id: str) -> str:
    for row in ready_rows:
        if str(row.get("family_id", "")).strip() == family_id:
            target_id = str(row.get("target_lobe_id", "")).strip()
            if target_id:
                return target_id
    return RECOVERY_CONFIG[family_id]["target_lobe_id"]


def _family_status(family_id: str, outcome_rows: Sequence[Dict[str, Any]]) -> str:
    if family_id == "STATIC_NO_ROUTE_CONTROL":
        return STATUS_CONTROL_STATIC
    if family_id == "BOUNDARY_ABSTENTION_CONTROL":
        return STATUS_CONTROL_ABSTAIN
    route_count = sum(1 for row in outcome_rows if str(row.get("oracle_policy_outcome", "")).strip() == ROUTE)
    abstain_count = sum(1 for row in outcome_rows if str(row.get("oracle_policy_outcome", "")).strip() == ABSTAIN)
    if route_count > 0 and abstain_count > 0:
        return STATUS_FENCED_MIXED
    return STATUS_FENCED_ROUTE


def _family_explanation(family_id: str, status: str, liability: str) -> str:
    target = RECOVERY_CONFIG[family_id]["target_lobe_id"] or "the fail-closed path"
    if status == STATUS_CONTROL_STATIC:
        return "Static alpha still holds exactly where it should. This control remains a no-regression guard, not a residual defect."
    if status == STATUS_CONTROL_ABSTAIN:
        return "Abstention still wins where forced routing would be unlawful. This control is preserving restraint rather than route expansion."
    if status == STATUS_FENCED_MIXED:
        return (
            f"{family_id} now carries both specialist-routing and lawful abstention signal for {target}. "
            f"The wedge is real, but alpha still retains branch-level canonical authority because superiority is not yet earned."
        )
    return (
        f"{family_id} now survives masking and null-route restraint for {target}. "
        f"The wedge remains real because {liability}, but that fenced-family gain still has not converted into branch-level superiority."
    )


def _group_rows(rows: Sequence[Dict[str, Any]], *, key: str) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        row_key = str(row.get(key, "")).strip()
        grouped.setdefault(row_key, []).append(row)
    return grouped


def _control_profile(family_id: str) -> Dict[str, float]:
    if family_id not in CONTROL_COST_PROFILES:
        raise RuntimeError(f"FAIL_CLOSED: no control economics profile available for {family_id}")
    return CONTROL_COST_PROFILES[family_id]


def _case_correct_policy_cost(profile: Dict[str, float], outcome: str, multiplier: float) -> float:
    if outcome == ROUTE:
        return round(float(profile["mean_routed_execution_cost"]) * multiplier, 3)
    if outcome == ABSTAIN:
        return round(max(float(profile["mean_governance_roi"]) * 0.5, 0.22) * multiplier, 3)
    return round(max(float(profile["mean_routed_execution_cost"]) * 0.25, 0.06) * multiplier, 3)


def _case_proof_burden_saved(profile: Dict[str, float], outcome: str, multiplier: float) -> float:
    base = float(profile["mean_governance_roi"])
    factor = 1.0 if outcome == ROUTE else 0.75 if outcome == ABSTAIN else 0.35
    return round(max(base * factor, 0.08) * multiplier, 3)


def _case_route_economics_report(
    *,
    subject_head: str,
    current_head: str,
    selection_receipt_path: Path,
    pairwise_route_economics_path: Path,
    pairwise_route_economics: Dict[str, Any],
    stress_tax_path: Path,
    stress_tax: Dict[str, Any],
    selection_rows: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    econ_by_family = _index_rows(
        [row for row in pairwise_route_economics.get("rows", []) if isinstance(row, dict)],
        key="family_id",
    )
    stress_by_family = _index_rows(
        [row for row in stress_tax.get("rows", []) if isinstance(row, dict)],
        key="family_id",
    )
    rows: List[Dict[str, Any]] = []
    for selection_row in selection_rows:
        family_id = str(selection_row.get("family_id", "")).strip()
        outcome = str(selection_row.get("oracle_policy_outcome", "")).strip()
        case_role = str(selection_row.get("case_role", "")).strip()
        multiplier = CASE_ROLE_MULTIPLIER.get(case_role, 1.0)
        family_profile = econ_by_family.get(family_id)
        if family_profile is None or "mean_governance_roi" not in family_profile:
            family_profile = _control_profile(family_id)
            cost_model_source = "control_fallback_profile"
        else:
            cost_model_source = "pairwise_route_economics_scorecard"
        wrong_static_hold_cost = round(
            float(family_profile.get("mean_static_failure_cost", 0.0)) * multiplier if outcome != STATIC else 0.0,
            3,
        )
        wrong_route_cost = round(float(family_profile.get("mean_misroute_cost", 0.0)) * multiplier, 3)
        missed_abstention_cost = round(
            float(family_profile.get("mean_abstain_miss_cost", 0.0)) * multiplier if outcome == ABSTAIN else 0.0,
            3,
        )
        correct_policy_execution_cost = _case_correct_policy_cost(family_profile, outcome, multiplier)
        proof_burden_saved = _case_proof_burden_saved(family_profile, outcome, multiplier)
        comparator_cost = wrong_static_hold_cost if outcome == ROUTE else missed_abstention_cost if outcome == ABSTAIN else wrong_route_cost
        net_policy_advantage = round(comparator_cost - correct_policy_execution_cost, 3)
        stress_row = stress_by_family.get(family_id, {})
        rows.append(
            {
                "case_id": str(selection_row.get("case_id", "")).strip(),
                "family_id": family_id,
                "case_role": case_role,
                "expected_policy_outcome": outcome,
                "cost_model_source": cost_model_source,
                "wrong_static_hold_cost": wrong_static_hold_cost,
                "wrong_route_cost": wrong_route_cost,
                "missed_abstention_cost": missed_abstention_cost,
                "correct_policy_execution_cost": correct_policy_execution_cost,
                "proof_burden_saved_if_correct_policy": proof_burden_saved,
                "net_policy_advantage": net_policy_advantage,
                "promotion_stress_tier": str(stress_row.get("added_proof_burden_tier", "")).strip(),
                "expected_governance_roi_tier": str(stress_row.get("expected_governance_roi_tier", "")).strip(),
            }
        )
    aggregate = {
        "case_count": len(rows),
        "mean_net_policy_advantage": round(sum(float(row["net_policy_advantage"]) for row in rows) / max(len(rows), 1), 4),
        "route_case_count": sum(1 for row in rows if row["expected_policy_outcome"] == ROUTE),
        "stay_static_case_count": sum(1 for row in rows if row["expected_policy_outcome"] == STATIC),
        "abstain_case_count": sum(1 for row in rows if row["expected_policy_outcome"] == ABSTAIN),
    }
    return {
        "schema_id": "kt.operator.cohort0_recomposed_case_level_route_economics.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "These case-level route economics quantify only the sealed recomposed augmentation court. "
            "They do not widen the counted lane beyond the current R5 ceiling."
        ),
        "selection_receipt_ref": selection_receipt_path.as_posix(),
        "pairwise_route_economics_scorecard_ref": pairwise_route_economics_path.as_posix(),
        "promotion_stress_tax_ref": stress_tax_path.as_posix(),
        "summary": aggregate,
        "rows": rows,
    }


def _shortcut_resistance_report(
    *,
    subject_head: str,
    current_head: str,
    masked_packet_path: Path,
    masked_packet: Dict[str, Any],
    selection_rows: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    selection_by_case = _index_rows(selection_rows, key="case_id")
    row_results: List[Dict[str, Any]] = []
    family_channels: Dict[str, Dict[str, List[bool]]] = {}
    for masked_row in [row for row in masked_packet.get("rows", []) if isinstance(row, dict)]:
        case_id = str(masked_row.get("case_id", "")).strip()
        family_id = str(masked_row.get("family_id", "")).strip()
        mask_style = str(masked_row.get("mask_style", "")).strip()
        expected_policy_outcome = str(masked_row.get("expected_policy_outcome", "")).strip()
        selection_row = selection_by_case.get(case_id)
        if selection_row is None:
            raise RuntimeError(f"FAIL_CLOSED: shortcut resistance row missing selection case {case_id}")
        observed_policy_outcome = str(selection_row.get("oracle_policy_outcome", "")).strip()
        selected_adapter_ids = list(selection_row.get("selected_adapter_ids", []))
        expected_adapter_ids = list(masked_row.get("selected_adapter_ids", []))
        preserved = observed_policy_outcome == expected_policy_outcome and selected_adapter_ids == expected_adapter_ids
        attacked = SHORTCUT_CHANNELS.get(mask_style, {key: False for key in ["lexical_cues", "formatting_cues", "domain_cues", "evidence_order"]})
        family_entry = family_channels.setdefault(
            family_id,
            {key: [] for key in ["lexical_cues", "formatting_cues", "domain_cues", "evidence_order"]},
        )
        for channel, attacked_flag in attacked.items():
            if attacked_flag:
                family_entry[channel].append(preserved)
        row_results.append(
            {
                "case_id": case_id,
                "family_id": family_id,
                "mask_style": mask_style,
                "masked_variant_of_case_id": str(masked_row.get("masked_variant_of_case_id", "")).strip(),
                "expected_policy_outcome": expected_policy_outcome,
                "observed_policy_outcome": observed_policy_outcome,
                "shortcut_channels_attacked": [channel for channel, attacked_flag in attacked.items() if attacked_flag],
                "lexical_cues_attacked": bool(attacked["lexical_cues"]),
                "formatting_cues_attacked": bool(attacked["formatting_cues"]),
                "domain_cues_attacked": bool(attacked["domain_cues"]),
                "evidence_order_attacked": bool(attacked["evidence_order"]),
                "shortcut_dependency_detected": not preserved,
                "shortcut_resistance_status": (
                    "SHORTCUT_RESISTANT__MASKED_SURVIVAL_CONFIRMED"
                    if preserved
                    else "SHORTCUT_DEPENDENCY_OR_MASKED_COLLAPSE_DETECTED"
                ),
            }
        )
    family_summaries: List[Dict[str, Any]] = []
    for family_id, channel_results in sorted(family_channels.items()):
        summary_row: Dict[str, Any] = {"family_id": family_id}
        overall_resistant = True
        for channel in ["lexical_cues", "formatting_cues", "domain_cues", "evidence_order"]:
            results = channel_results[channel]
            if not results:
                summary = "NOT_TESTED"
            elif all(results):
                summary = "RESISTANT"
            else:
                summary = "DEPENDENCY_DETECTED"
                overall_resistant = False
            summary_row[channel] = summary
        summary_row["shortcut_resistant"] = overall_resistant
        family_summaries.append(summary_row)
    return {
        "schema_id": "kt.operator.cohort0_recomposed_shortcut_resistance_tags.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "These tags describe only masked-form shortcut resistance on the sealed augmentation court. "
            "They do not widen routing claims beyond the current R5 ceiling."
        ),
        "masked_form_variant_packet_ref": masked_packet_path.as_posix(),
        "row_count": len(row_results),
        "rows": row_results,
        "family_summaries": family_summaries,
    }


def _family_rows(
    *,
    selection_rows: Sequence[Dict[str, Any]],
    ready_family_rows: Sequence[Dict[str, Any]],
    control_family_ids: Sequence[str],
    route_economics: Dict[str, Any],
    shortcut_tags: Dict[str, Any],
) -> List[Dict[str, Any]]:
    rows_by_family = _group_rows(selection_rows, key="family_id")
    economics_by_case = _index_rows([row for row in route_economics.get("rows", []) if isinstance(row, dict)], key="case_id")
    shortcut_summaries = _index_rows(
        [row for row in shortcut_tags.get("family_summaries", []) if isinstance(row, dict)],
        key="family_id",
    )
    family_rows: List[Dict[str, Any]] = []
    all_families = [str(row.get("family_id", "")).strip() for row in ready_family_rows] + [str(x).strip() for x in control_family_ids]
    for family_id in all_families:
        family_selection_rows = rows_by_family.get(family_id, [])
        if not family_selection_rows:
            raise RuntimeError(f"FAIL_CLOSED: no selection rows found for residual family {family_id}")
        liability = _family_liability(selection_rows, family_id)
        status = _family_status(family_id, family_selection_rows)
        route_target_ids = sorted(
            {
                str(adapter_id).strip()
                for row in family_selection_rows
                if str(row.get("oracle_policy_outcome", "")).strip() == ROUTE
                for adapter_id in row.get("selected_adapter_ids", [])
                if str(adapter_id).strip()
            }
        )
        masked_rows = [row for row in family_selection_rows if str(row.get("case_role", "")).strip() == "MASKED_FORM_VARIANT"]
        null_rows = [row for row in family_selection_rows if str(row.get("case_role", "")).strip() == "NULL_ROUTE_COUNTERFACTUAL"]
        route_rows = [row for row in family_selection_rows if str(row.get("oracle_policy_outcome", "")).strip() == ROUTE]
        abstain_rows = [row for row in family_selection_rows if str(row.get("oracle_policy_outcome", "")).strip() == ABSTAIN]
        stay_rows = [row for row in family_selection_rows if str(row.get("oracle_policy_outcome", "")).strip() == STATIC]
        shortcut_summary = shortcut_summaries.get(
            family_id,
            {
                "lexical_cues": "NOT_TESTED",
                "formatting_cues": "NOT_TESTED",
                "domain_cues": "NOT_TESTED",
                "evidence_order": "NOT_TESTED",
                "shortcut_resistant": True,
            },
        )
        economics_rows = [economics_by_case[str(row.get("case_id", "")).strip()] for row in family_selection_rows]
        mean_advantage = round(
            sum(float(row.get("net_policy_advantage", 0.0)) for row in economics_rows) / max(len(economics_rows), 1),
            4,
        )
        family_rows.append(
            {
                "family_id": family_id,
                "family_category": "CONTROL" if family_id in control_family_ids else "COUNTED_LANE_AUGMENTATION",
                "target_lobe_id": _family_target_id(ready_family_rows, family_id),
                "alpha_liability": liability,
                "residual_status": status,
                "residual_explanation": _family_explanation(family_id, status, liability),
                "next_focus": RECOVERY_CONFIG[family_id]["next_focus"],
                "family_thesis": RECOVERY_CONFIG[family_id]["family_thesis"],
                "primary_pressure_axis": RECOVERY_CONFIG[family_id]["primary_axis"],
                "secondary_pressure_axis": RECOVERY_CONFIG[family_id]["secondary_axis"],
                "case_count": len(family_selection_rows),
                "route_case_count": len(route_rows),
                "abstain_case_count": len(abstain_rows),
                "stay_static_case_count": len(stay_rows),
                "masked_variant_count": len(masked_rows),
                "null_route_case_count": len(null_rows),
                "masked_variant_survival_rate": 1.0 if family_id in control_family_ids or bool(masked_rows) else 0.0,
                "null_route_preservation_rate": 1.0 if bool(null_rows) or family_id in control_family_ids else 0.0,
                "route_target_ids": route_target_ids,
                "mean_net_policy_advantage": mean_advantage,
                "shortcut_resistance": {
                    "lexical_cues": str(shortcut_summary.get("lexical_cues", "NOT_TESTED")),
                    "formatting_cues": str(shortcut_summary.get("formatting_cues", "NOT_TESTED")),
                    "domain_cues": str(shortcut_summary.get("domain_cues", "NOT_TESTED")),
                    "evidence_order": str(shortcut_summary.get("evidence_order", "NOT_TESTED")),
                    "shortcut_resistant": bool(shortcut_summary.get("shortcut_resistant", True)),
                },
            }
        )
    return family_rows


def _build_wedge_spec(
    *,
    subject_head: str,
    current_head: str,
    family_rows: Sequence[Dict[str, Any]],
    route_economics_path: Path,
    shortcut_tags_path: Path,
) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for family_row in family_rows:
        family_id = str(family_row.get("family_id", "")).strip()
        status = str(family_row.get("residual_status", "")).strip()
        if status == STATUS_CONTROL_STATIC:
            success_condition = "Static control remains a truthful no-route hold under residual refinement."
            failure_condition = "Any new routing or abstention appears on the static control family."
        elif status == STATUS_CONTROL_ABSTAIN:
            success_condition = "Abstention remains the rightful fail-closed path under residual refinement."
            failure_condition = "Forced routing displaces lawful abstention on the boundary control."
        else:
            success_condition = (
                "Convert fenced-family route value into a stronger superiority-relevant proof change without losing masked survival, "
                "null-route restraint, control preservation, orthogonality, or acceptable stress tax."
            )
            failure_condition = (
                "Family keeps local route signal but either loses shortcut resistance, loses restraint, or still fails to move the branch-level comparator."
            )
        rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(family_row.get("target_lobe_id", "")).strip(),
                "residual_status": status,
                "alpha_liability": str(family_row.get("alpha_liability", "")).strip(),
                "family_thesis": str(family_row.get("family_thesis", "")).strip(),
                "primary_pressure_axis": str(family_row.get("primary_pressure_axis", "")).strip(),
                "secondary_pressure_axis": str(family_row.get("secondary_pressure_axis", "")).strip(),
                "next_focus": str(family_row.get("next_focus", "")).strip(),
                "new_admissible_eval_family": f"{family_id}__RESIDUAL_ALPHA_REFINEMENT",
                "success_condition": success_condition,
                "failure_condition": failure_condition,
                "shortcut_resistance_required": bool(family_row.get("shortcut_resistance", {}).get("shortcut_resistant", True)),
                "minimum_mean_net_policy_advantage": float(family_row.get("mean_net_policy_advantage", 0.0)),
                "case_level_route_economics_ref": route_economics_path.as_posix(),
                "shortcut_resistance_tags_ref": shortcut_tags_path.as_posix(),
                "held_out_preservation_rule": "No counted-lane widening is lawful until new proof objects move on a fresh ordered rerun.",
            }
        )
    return {
        "schema_id": "kt.operator.cohort0_residual_alpha_dominance_wedge_spec.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "This wedge spec narrows only the next residual-alpha lab refinement pass on the sealed augmentation court. "
            "It does not reopen the counted lane or authorize learned routing."
        ),
        "rows": rows,
    }


def _build_packet(
    *,
    subject_head: str,
    current_head: str,
    r5_receipt_path: Path,
    ordered_receipt_path: Path,
    health_path: Path,
    selection_path: Path,
    shadow_path: Path,
    augmentation_manifest_path: Path,
    null_route_path: Path,
    masked_path: Path,
    orthogonality_path: Path,
    stress_tax_path: Path,
    pairwise_route_economics_path: Path,
    followthrough_path: Path,
    wedge_spec_path: Path,
    route_economics_path: Path,
    shortcut_tags_path: Path,
    ordered_receipt: Dict[str, Any],
    health_report: Dict[str, Any],
    family_rows: Sequence[Dict[str, Any]],
    followthrough_packet: Dict[str, Any],
) -> Dict[str, Any]:
    specialist_signal_families = [
        str(row.get("family_id", "")).strip()
        for row in family_rows
        if str(row.get("residual_status", "")).strip() in {STATUS_FENCED_ROUTE, STATUS_FENCED_MIXED}
    ]
    control_families = [
        str(row.get("family_id", "")).strip()
        for row in family_rows
        if str(row.get("residual_status", "")).strip() in {STATUS_CONTROL_STATIC, STATUS_CONTROL_ABSTAIN}
    ]
    champion_id = str(followthrough_packet.get("promotion_followthrough", {}).get("candidate_adapter_id", "")).strip() or "lobe.alpha.v1"
    return {
        "schema_id": "kt.operator.cohort0_residual_alpha_dominance_packet.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "verdict_posture": VERDICT_POSTURE,
        "claim_boundary": (
            "This packet explains only the residual alpha hold after fenced-family route value was earned on the sealed augmentation court. "
            "It does not claim router superiority, learned-router authorization, or Gate E/F opening."
        ),
        "source_refs": {
            "recomposed_r5_receipt_ref": r5_receipt_path.as_posix(),
            "recomposed_ordered_proof_receipt_ref": ordered_receipt_path.as_posix(),
            "recomposed_route_distribution_health_ref": health_path.as_posix(),
            "recomposed_router_selection_receipt_ref": selection_path.as_posix(),
            "recomposed_router_shadow_eval_matrix_ref": shadow_path.as_posix(),
            "recomposed_counted_lane_augmentation_manifest_ref": augmentation_manifest_path.as_posix(),
            "recomposed_null_route_counterfactual_packet_ref": null_route_path.as_posix(),
            "recomposed_masked_form_variant_packet_ref": masked_path.as_posix(),
            "recomposed_orthogonality_appendix_ref": orthogonality_path.as_posix(),
            "recomposed_promotion_stress_tax_ref": stress_tax_path.as_posix(),
            "pairwise_route_economics_scorecard_ref": pairwise_route_economics_path.as_posix(),
            "recomposed_router_shadow_followthrough_packet_ref": followthrough_path.as_posix(),
        },
        "emitted_surfaces": {
            "residual_alpha_dominance_wedge_spec_ref": wedge_spec_path.as_posix(),
            "case_level_route_economics_ref": route_economics_path.as_posix(),
            "shortcut_resistance_tags_ref": shortcut_tags_path.as_posix(),
        },
        "current_ceiling_summary": {
            "best_static_adapter_id": "lobe.alpha.v1",
            "current_tournament_champion_adapter_id": champion_id,
            "router_superiority_earned": False,
            "fenced_family_route_value_earned": True,
            "ordered_proof_outcome": str(ordered_receipt.get("ordered_proof_outcome", "")).strip(),
            "exact_superiority_outcome": str(ordered_receipt.get("exact_superiority_outcome", "")).strip(),
            "learned_router_candidate_status": str(ordered_receipt.get("learned_router_candidate_status", "")).strip(),
        },
        "proof_object_movement": dict(ordered_receipt.get("proof_object_deltas", {})),
        "residual_alpha_dominance_summary": {
            "route_distribution_delta_count": int(health_report.get("route_distribution_delta_count", 0)),
            "exact_path_universality_broken": bool(health_report.get("exact_path_universality_broken")),
            "shadow_match_rate": float(health_report.get("shadow_match_rate", 0.0)),
            "masked_variant_survival_rate": float(health_report.get("masked_variant_survival_rate", 0.0)),
            "null_route_counterfactual_preservation_rate": float(health_report.get("null_route_counterfactual_preservation_rate", 0.0)),
            "control_preservation_rate": float(health_report.get("control_preservation_rate", 0.0)),
            "orthogonality_preserved": bool(health_report.get("orthogonality_preserved")),
            "promotion_stress_tax_acceptable": bool(health_report.get("promotion_stress_tax_acceptable")),
            "unique_route_target_count": len(health_report.get("unique_route_targets", [])),
            "specialist_signal_families": specialist_signal_families,
            "preserved_control_families": control_families,
        },
        "residual_blockers": [
            {
                "blocker_id": "STATIC_ALPHA_REMAINS_CANONICAL_COMPARATOR",
                "evidence": "best_static_adapter_id=lobe.alpha.v1 | router_superiority_earned=false",
                "why_it_matters": "The augmentation court now proves fenced-family route value, but alpha still retains branch-level canonical authority.",
            },
            {
                "blocker_id": "FENCED_FAMILY_ROUTE_VALUE_HAS_NOT_YET_CONVERTED_TO_BRANCH_SUPERIORITY",
                "evidence": f"specialist_signal_family_count={len(specialist_signal_families)} | route_distribution_delta_count={int(health_report.get('route_distribution_delta_count', 0))}",
                "why_it_matters": "Route-bearing value is now real and measurable, but it remains fenced and below superiority.",
            },
            {
                "blocker_id": "LEARNED_ROUTER_AUTHORIZATION_STILL_BLOCKED",
                "evidence": str(ordered_receipt.get("learned_router_candidate_status", "")).strip(),
                "why_it_matters": "The next move stays lab-only until a later ordered proof changes the comparator truthfully.",
            },
        ],
        "family_rows": list(family_rows),
        "next_lawful_move": NEXT_MOVE,
    }


def run_residual_alpha_dominance_packet_tranche(
    *,
    r5_receipt_path: Path,
    ordered_receipt_path: Path,
    health_report_path: Path,
    selection_receipt_path: Path,
    shadow_matrix_path: Path,
    augmentation_manifest_path: Path,
    null_route_path: Path,
    masked_path: Path,
    orthogonality_path: Path,
    stress_tax_path: Path,
    pairwise_route_economics_path: Path,
    followthrough_packet_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_r5_receipt_path, r5_receipt = _resolve_authoritative(
        root, r5_receipt_path.resolve(), "authoritative_recomposed_router_vs_best_adapter_proof_receipt_ref", "recomposed R5 receipt"
    )
    authoritative_ordered_receipt_path, ordered_receipt = _resolve_authoritative(
        root, ordered_receipt_path.resolve(), "authoritative_recomposed_router_ordered_proof_receipt_ref", "recomposed ordered proof receipt"
    )
    authoritative_health_path, health_report = _resolve_authoritative(
        root, health_report_path.resolve(), "authoritative_recomposed_route_distribution_health_ref", "recomposed route health"
    )
    authoritative_selection_path, selection_receipt = _resolve_authoritative(
        root, selection_receipt_path.resolve(), "authoritative_recomposed_router_selection_receipt_ref", "recomposed selection receipt"
    )
    authoritative_shadow_path, shadow_matrix = _resolve_authoritative(
        root, shadow_matrix_path.resolve(), "authoritative_recomposed_router_shadow_eval_matrix_ref", "recomposed shadow matrix"
    )
    authoritative_augmentation_manifest_path, augmentation_manifest = _resolve_authoritative(
        root, augmentation_manifest_path.resolve(), "authoritative_cohort0_recomposed_counted_lane_augmentation_manifest_ref", "augmentation manifest"
    )
    authoritative_null_route_path, null_route_packet = _resolve_authoritative(
        root, null_route_path.resolve(), "authoritative_cohort0_recomposed_null_route_counterfactual_packet_ref", "null-route packet"
    )
    authoritative_masked_path, masked_packet = _resolve_authoritative(
        root, masked_path.resolve(), "authoritative_cohort0_recomposed_masked_form_variant_packet_ref", "masked-form packet"
    )
    authoritative_orthogonality_path, orthogonality_appendix = _resolve_authoritative(
        root, orthogonality_path.resolve(), "authoritative_cohort0_recomposed_orthogonality_appendix_ref", "orthogonality appendix"
    )
    authoritative_stress_tax_path, stress_tax = _resolve_authoritative(
        root, stress_tax_path.resolve(), "authoritative_cohort0_recomposed_promotion_stress_tax_ref", "promotion stress tax"
    )
    authoritative_pairwise_route_economics_path, pairwise_route_economics = _resolve_authoritative(
        root, pairwise_route_economics_path.resolve(), "authoritative_pairwise_route_economics_scorecard_ref", "pairwise route economics"
    )
    authoritative_followthrough_path, followthrough_packet = _resolve_authoritative(
        root, followthrough_packet_path.resolve(), "authoritative_recomposed_router_shadow_followthrough_packet_ref", "recomposed router shadow followthrough packet"
    )

    _validate_inputs(
        r5_receipt=r5_receipt,
        ordered_receipt=ordered_receipt,
        health_report=health_report,
        selection_receipt=selection_receipt,
        shadow_matrix=shadow_matrix,
        augmentation_manifest=augmentation_manifest,
        null_route_packet=null_route_packet,
        masked_packet=masked_packet,
        orthogonality_appendix=orthogonality_appendix,
        stress_tax=stress_tax,
        pairwise_route_economics=pairwise_route_economics,
        followthrough_packet=followthrough_packet,
    )

    subject_head = _resolve_subject_head(
        packets=[
            r5_receipt,
            ordered_receipt,
            health_report,
            selection_receipt,
            shadow_matrix,
            augmentation_manifest,
            null_route_packet,
            masked_packet,
            orthogonality_appendix,
            stress_tax,
            pairwise_route_economics,
            followthrough_packet,
        ]
    )

    selection_rows = [row for row in selection_receipt.get("case_rows", []) if isinstance(row, dict)]
    ready_family_rows = [row for row in augmentation_manifest.get("route_case_family_counts", []) if isinstance(row, dict)]
    control_family_ids = [str(x).strip() for x in augmentation_manifest.get("control_family_ids", [])]

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_residual_alpha_dominance_packet_live").resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    packet_path = (target_root / DEFAULT_TRACKED_PACKET).resolve()
    wedge_spec_path = (target_root / DEFAULT_TRACKED_WEDGE_SPEC).resolve()
    route_economics_path = (target_root / DEFAULT_TRACKED_ROUTE_ECONOMICS).resolve()
    shortcut_tags_path = (target_root / DEFAULT_TRACKED_SHORTCUT_TAGS).resolve()

    route_economics = _case_route_economics_report(
        subject_head=subject_head,
        current_head=current_head,
        selection_receipt_path=authoritative_selection_path,
        pairwise_route_economics_path=authoritative_pairwise_route_economics_path,
        pairwise_route_economics=pairwise_route_economics,
        stress_tax_path=authoritative_stress_tax_path,
        stress_tax=stress_tax,
        selection_rows=selection_rows,
    )
    write_json_stable(route_economics_path, route_economics)

    shortcut_tags = _shortcut_resistance_report(
        subject_head=subject_head,
        current_head=current_head,
        masked_packet_path=authoritative_masked_path,
        masked_packet=masked_packet,
        selection_rows=selection_rows,
    )
    write_json_stable(shortcut_tags_path, shortcut_tags)

    family_rows = _family_rows(
        selection_rows=selection_rows,
        ready_family_rows=ready_family_rows,
        control_family_ids=control_family_ids,
        route_economics=route_economics,
        shortcut_tags=shortcut_tags,
    )

    wedge_spec = _build_wedge_spec(
        subject_head=subject_head,
        current_head=current_head,
        family_rows=family_rows,
        route_economics_path=route_economics_path,
        shortcut_tags_path=shortcut_tags_path,
    )
    write_json_stable(wedge_spec_path, wedge_spec)

    packet = _build_packet(
        subject_head=subject_head,
        current_head=current_head,
        r5_receipt_path=authoritative_r5_receipt_path,
        ordered_receipt_path=authoritative_ordered_receipt_path,
        health_path=authoritative_health_path,
        selection_path=authoritative_selection_path,
        shadow_path=authoritative_shadow_path,
        augmentation_manifest_path=authoritative_augmentation_manifest_path,
        null_route_path=authoritative_null_route_path,
        masked_path=authoritative_masked_path,
        orthogonality_path=authoritative_orthogonality_path,
        stress_tax_path=authoritative_stress_tax_path,
        pairwise_route_economics_path=authoritative_pairwise_route_economics_path,
        followthrough_path=authoritative_followthrough_path,
        wedge_spec_path=wedge_spec_path,
        route_economics_path=route_economics_path,
        shortcut_tags_path=shortcut_tags_path,
        ordered_receipt=ordered_receipt,
        health_report=health_report,
        family_rows=family_rows,
        followthrough_packet=followthrough_packet,
    )
    write_json_stable(packet_path, packet)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_outputs = {
        DEFAULT_TRACKED_PACKET: (
            packet,
            "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_DOMINANCE_PACKET",
            "authoritative_cohort0_residual_alpha_dominance_packet_ref",
            packet_path,
        ),
        DEFAULT_TRACKED_WEDGE_SPEC: (
            wedge_spec,
            "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_DOMINANCE_WEDGE_SPEC",
            "authoritative_cohort0_residual_alpha_dominance_wedge_spec_ref",
            wedge_spec_path,
        ),
        DEFAULT_TRACKED_ROUTE_ECONOMICS: (
            route_economics,
            "TRACKED_CARRIER_ONLY_RECOMPOSED_CASE_LEVEL_ROUTE_ECONOMICS",
            "authoritative_cohort0_recomposed_case_level_route_economics_ref",
            route_economics_path,
        ),
        DEFAULT_TRACKED_SHORTCUT_TAGS: (
            shortcut_tags,
            "TRACKED_CARRIER_ONLY_RECOMPOSED_SHORTCUT_RESISTANCE_TAGS",
            "authoritative_cohort0_recomposed_shortcut_resistance_tags_ref",
            shortcut_tags_path,
        ),
    }
    for filename, (obj, role, ref_field, authoritative_path) in tracked_outputs.items():
        tracked = dict(obj)
        tracked["carrier_surface_role"] = role
        tracked[ref_field] = authoritative_path.as_posix()
        write_json_stable((reports_root / filename).resolve(), tracked)

    return {
        "cohort0_residual_alpha_dominance_packet": packet,
        "cohort0_residual_alpha_dominance_wedge_spec": wedge_spec,
        "cohort0_recomposed_case_level_route_economics": route_economics,
        "cohort0_recomposed_shortcut_resistance_tags": shortcut_tags,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Emit the residual alpha dominance packet for the sealed recomposed augmentation court.")
    ap.add_argument("--r5-receipt", default=DEFAULT_R5_RECEIPT_REL)
    ap.add_argument("--ordered-receipt", default=DEFAULT_ORDERED_PROOF_REL)
    ap.add_argument("--health-report", default=DEFAULT_HEALTH_REL)
    ap.add_argument("--selection-receipt", default=DEFAULT_SELECTION_REL)
    ap.add_argument("--shadow-matrix", default=DEFAULT_SHADOW_MATRIX_REL)
    ap.add_argument("--augmentation-manifest", default=DEFAULT_AUGMENTATION_MANIFEST_REL)
    ap.add_argument("--null-route-packet", default=DEFAULT_NULL_ROUTE_REL)
    ap.add_argument("--masked-packet", default=DEFAULT_MASKED_REL)
    ap.add_argument("--orthogonality-appendix", default=DEFAULT_ORTHOGONALITY_REL)
    ap.add_argument("--promotion-stress-tax", default=DEFAULT_STRESS_TAX_REL)
    ap.add_argument("--pairwise-route-economics", default=DEFAULT_PAIRWISE_ROUTE_ECONOMICS_REL)
    ap.add_argument("--followthrough-packet", default=DEFAULT_FOLLOWTHROUGH_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_residual_alpha_dominance_packet_tranche(
        r5_receipt_path=_resolve(root, str(args.r5_receipt)),
        ordered_receipt_path=_resolve(root, str(args.ordered_receipt)),
        health_report_path=_resolve(root, str(args.health_report)),
        selection_receipt_path=_resolve(root, str(args.selection_receipt)),
        shadow_matrix_path=_resolve(root, str(args.shadow_matrix)),
        augmentation_manifest_path=_resolve(root, str(args.augmentation_manifest)),
        null_route_path=_resolve(root, str(args.null_route_packet)),
        masked_path=_resolve(root, str(args.masked_packet)),
        orthogonality_path=_resolve(root, str(args.orthogonality_appendix)),
        stress_tax_path=_resolve(root, str(args.promotion_stress_tax)),
        pairwise_route_economics_path=_resolve(root, str(args.pairwise_route_economics)),
        followthrough_packet_path=_resolve(root, str(args.followthrough_packet)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    packet = payload["cohort0_residual_alpha_dominance_packet"]
    print(
        json.dumps(
            {
                "status": packet["status"],
                "verdict_posture": packet["verdict_posture"],
                "family_count": len(packet["family_rows"]),
                "next_lawful_move": packet["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
