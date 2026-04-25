from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_hardened_ceiling_verdict_packet.json"
DEFAULT_LIMITATIONS_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_current_substrate_limitations_report.json"
DEFAULT_REENTRY_BLOCK_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_reentry_block_contract.json"
DEFAULT_REDESIGN_WORK_ORDER_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_redesign_campaign_work_order.json"
DEFAULT_THEOREM_TARGET_REL = "KT_PROD_CLEANROOM/reports/cohort0_gate_d_next_theorem_target.json"
DEFAULT_MICRO_COURTS_REL = "KT_PROD_CLEANROOM/reports/cohort0_successor_frozen_micro_courts_manifest.json"
DEFAULT_REPORTABILITY_EVAL_COURT_REL = "KT_PROD_CLEANROOM/reports/reportability_bridge_eval_court.json"
DEFAULT_REPORTABILITY_TRAINING_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/reportability_bridge_training_manifest.json"
DEFAULT_REPORTABILITY_MUTATION_PACK_REL = "KT_PROD_CLEANROOM/reports/reportability_bridge_holdout_mutation_pack.json"
DEFAULT_CAUSAL_INTERVENTION_MATRIX_REL = "KT_PROD_CLEANROOM/reports/causal_route_consequence_intervention_matrix.json"
DEFAULT_ROUTE_ABLATION_HARNESS_REL = "KT_PROD_CLEANROOM/reports/route_ablation_harness.json"
DEFAULT_REPORTS_ROOT_REL = "KT_PROD_CLEANROOM/reports"

DEFAULT_MIXED_AXIS_EXECUTION_RECEIPT_REL = (
    "tmp/cohort0_residual_alpha_refinement_domain_overlay_x_adversarial_ambiguity_mixed_axis_local_execution_bridge_live/"
    "cohort0_residual_alpha_refinement_mixed_axis_execution_receipt.json"
)
DEFAULT_MIXED_AXIS_SCORECARD_REL = (
    "tmp/cohort0_residual_alpha_refinement_domain_overlay_x_adversarial_ambiguity_mixed_axis_local_execution_bridge_live/"
    "cohort0_residual_alpha_refinement_mixed_axis_route_consequence_scorecard.json"
)
DEFAULT_MIXED_AXIS_SHORTCUT_RECHECK_REL = (
    "tmp/cohort0_residual_alpha_refinement_domain_overlay_x_adversarial_ambiguity_mixed_axis_local_execution_bridge_live/"
    "cohort0_residual_alpha_refinement_mixed_axis_shortcut_recheck.json"
)
DEFAULT_MIXED_AXIS_TRANSFER_ELIGIBILITY_REL = (
    "tmp/cohort0_residual_alpha_refinement_domain_overlay_x_adversarial_ambiguity_mixed_axis_local_execution_bridge_live/"
    "cohort0_residual_alpha_refinement_mixed_axis_transfer_eligibility.json"
)

EXPECTED_SUBJECT_HEAD = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"
EXPECTED_FINAL_VERDICT_ID = "GATE_D_NOT_CLEARED__CURRENT_SAME_HEAD_LANE_HARDENED_CEILING"
EXPECTED_PRIMARY_MOVE = "EXECUTE_REPORTABILITY_BRIDGE_REALIZATION_CAMPAIGN__PRIMARY"
EXPECTED_SECONDARY_MOVE = "EXECUTE_CAUSAL_ROUTE_CONSEQUENCE_HARNESS_CAMPAIGN__SECONDARY"
EXPECTED_FOCUSED_AXIS_ID = "domain_overlay_cross_domain_contamination__x__adversarial_ambiguity"
EXPECTED_FOCUSED_FAMILY_ID = "REPLACEMENT_WITNESS__RIVAL_FRAME_COUNTERREAD_BOUNDARY_GOVERNOR"

OUTPUT_TRANCHE_MANIFEST = "cohort0_first_successor_evidence_tranche_manifest.json"
OUTPUT_MICRO_COURT_LOCK_RECEIPT = "cohort0_successor_frozen_micro_courts_locked_receipt.json"
OUTPUT_REPORTABILITY_VARIANT_MANIFEST = "reportability_bridge_variant_manifest_v1.json"
OUTPUT_CAUSAL_LAUNCH_MANIFEST = "causal_route_consequence_intervention_launch_manifest.json"
OUTPUT_SETUP_RECEIPT = "cohort0_first_successor_evidence_setup_receipt.json"
OUTPUT_REPORT = "COHORT0_FIRST_SUCCESSOR_EVIDENCE_SETUP_REPORT.md"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: {label} must be a JSON object: {path.as_posix()}")
    return payload


def _ensure_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


def _require_same_subject_head(packets: Sequence[Dict[str, Any]]) -> str:
    heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if len(heads) != 1:
        raise RuntimeError("FAIL_CLOSED: first successor evidence setup requires one same-head authority line")
    return next(iter(heads))


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _row_by_family(rows: Sequence[Dict[str, Any]], family_id: str, *, label: str) -> Dict[str, Any]:
    for row in rows:
        if str(row.get("family_id", "")).strip() == family_id:
            return row
    raise RuntimeError(f"FAIL_CLOSED: missing {label} row for family_id={family_id}")


def _validate_live_state(
    *,
    verdict_packet: Dict[str, Any],
    limitations_report: Dict[str, Any],
    reentry_block: Dict[str, Any],
    redesign_work_order: Dict[str, Any],
    theorem_target: Dict[str, Any],
    micro_courts_manifest: Dict[str, Any],
    reportability_eval_court: Dict[str, Any],
    reportability_training_manifest: Dict[str, Any],
    reportability_mutation_pack: Dict[str, Any],
    causal_intervention_matrix: Dict[str, Any],
    route_ablation_harness: Dict[str, Any],
    mixed_axis_execution_receipt: Dict[str, Any],
    mixed_axis_scorecard: Dict[str, Any],
    mixed_axis_shortcut_recheck: Dict[str, Any],
    mixed_axis_transfer_eligibility: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (limitations_report, "current substrate limitations report"),
        (reentry_block, "gate d reentry block contract"),
        (redesign_work_order, "gate d redesign campaign work order"),
        (theorem_target, "gate d next theorem target"),
        (micro_courts_manifest, "successor frozen micro-courts manifest"),
        (reportability_eval_court, "reportability bridge eval court"),
        (reportability_training_manifest, "reportability bridge training manifest"),
        (reportability_mutation_pack, "reportability bridge holdout mutation pack"),
        (causal_intervention_matrix, "causal route consequence intervention matrix"),
        (route_ablation_harness, "route ablation harness"),
        (mixed_axis_execution_receipt, "mixed-axis execution receipt"),
        (mixed_axis_scorecard, "mixed-axis route consequence scorecard"),
        (mixed_axis_shortcut_recheck, "mixed-axis shortcut recheck"),
        (mixed_axis_transfer_eligibility, "mixed-axis transfer eligibility"),
    ):
        _ensure_pass(payload, label=label)

    if str(verdict_packet.get("final_verdict_id", "")).strip() != EXPECTED_FINAL_VERDICT_ID:
        raise RuntimeError("FAIL_CLOSED: verdict packet final verdict mismatch")
    if not bool(verdict_packet.get("current_lane_closed", False)):
        raise RuntimeError("FAIL_CLOSED: current same-head lane must remain closed")
    if bool(verdict_packet.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: same-head counted reentry must remain blocked")
    if str(verdict_packet.get("next_lawful_move", "")).strip() != EXPECTED_PRIMARY_MOVE:
        raise RuntimeError("FAIL_CLOSED: verdict packet primary move mismatch")
    if str(verdict_packet.get("secondary_parallel_move", "")).strip() != EXPECTED_SECONDARY_MOVE:
        raise RuntimeError("FAIL_CLOSED: verdict packet secondary move mismatch")

    if str(reentry_block.get("reentry_status", "")).strip() != "BLOCKED__CURRENT_LANE_HARDENED_CEILING":
        raise RuntimeError("FAIL_CLOSED: reentry block contract mismatch")

    if str(mixed_axis_execution_receipt.get("focused_axis_id", "")).strip() != EXPECTED_FOCUSED_AXIS_ID:
        raise RuntimeError("FAIL_CLOSED: mixed-axis execution receipt focused axis mismatch")
    if str(mixed_axis_execution_receipt.get("focused_family_id", "")).strip() != EXPECTED_FOCUSED_FAMILY_ID:
        raise RuntimeError("FAIL_CLOSED: mixed-axis execution receipt focused family mismatch")
    if bool(mixed_axis_execution_receipt.get("route_consequence_earned", True)):
        raise RuntimeError("FAIL_CLOSED: mixed-axis execution receipt must keep route consequence false")
    if bool(mixed_axis_execution_receipt.get("reason_report_generalization_earned", True)):
        raise RuntimeError("FAIL_CLOSED: mixed-axis execution receipt must keep reason report false")

    if str(mixed_axis_scorecard.get("focused_axis_id", "")).strip() != EXPECTED_FOCUSED_AXIS_ID:
        raise RuntimeError("FAIL_CLOSED: mixed-axis scorecard focused axis mismatch")
    if str(mixed_axis_scorecard.get("focused_family_id", "")).strip() != EXPECTED_FOCUSED_FAMILY_ID:
        raise RuntimeError("FAIL_CLOSED: mixed-axis scorecard focused family mismatch")
    if bool(mixed_axis_scorecard.get("best_static_path_measurably_beaten_or_safely_derisked", True)):
        raise RuntimeError("FAIL_CLOSED: mixed-axis scorecard must keep best static path unbeaten")

    if str(micro_courts_manifest.get("schema_id", "")).strip() != "kt.operator.cohort0_successor_frozen_micro_courts_manifest.v1":
        raise RuntimeError("FAIL_CLOSED: successor frozen micro-courts manifest schema mismatch")
    if str(reportability_eval_court.get("schema_id", "")).strip() != "kt.operator.reportability_bridge_eval_court.v1":
        raise RuntimeError("FAIL_CLOSED: reportability bridge eval court schema mismatch")
    if str(causal_intervention_matrix.get("schema_id", "")).strip() != "kt.operator.causal_route_consequence_intervention_matrix.v1":
        raise RuntimeError("FAIL_CLOSED: causal route consequence intervention matrix schema mismatch")


def _derive_fail_geometry(
    *,
    limitations_report: Dict[str, Any],
    mixed_axis_execution_receipt: Dict[str, Any],
    mixed_axis_scorecard: Dict[str, Any],
    mixed_axis_shortcut_recheck: Dict[str, Any],
    mixed_axis_transfer_eligibility: Dict[str, Any],
) -> Dict[str, Any]:
    scorecard_rows = mixed_axis_scorecard.get("rows", [])
    shortcut_rows = mixed_axis_shortcut_recheck.get("rows", [])
    transfer_rows = mixed_axis_transfer_eligibility.get("rows", [])
    if not isinstance(scorecard_rows, list) or not isinstance(shortcut_rows, list) or not isinstance(transfer_rows, list):
        raise RuntimeError("FAIL_CLOSED: mixed-axis scorecard, shortcut recheck, and transfer eligibility rows must be lists")

    focused_scorecard_row = _row_by_family(scorecard_rows, EXPECTED_FOCUSED_FAMILY_ID, label="mixed-axis scorecard")
    focused_shortcut_row = _row_by_family(shortcut_rows, EXPECTED_FOCUSED_FAMILY_ID, label="mixed-axis shortcut recheck")
    focused_transfer_row = _row_by_family(transfer_rows, EXPECTED_FOCUSED_FAMILY_ID, label="mixed-axis transfer eligibility")

    if bool(focused_shortcut_row.get("proof_of_shortcut_drop", True)):
        raise RuntimeError("FAIL_CLOSED: focused shortcut row must keep shortcut drop unproven")
    shortcut_channels = list(focused_shortcut_row.get("shortcut_dependency_channels_present", []))
    if not shortcut_channels or "domain_cues" not in shortcut_channels or "evidence_order" not in shortcut_channels:
        raise RuntimeError("FAIL_CLOSED: focused shortcut row must preserve domain_cues and evidence_order exposure")
    attacked_channels = list(focused_shortcut_row.get("attacked_shortcut_channels", []))
    nonprimary_channels = list(focused_shortcut_row.get("nonprimary_shortcut_channels_present_by_law", []))
    if "domain_cues" not in attacked_channels:
        raise RuntimeError("FAIL_CLOSED: focused shortcut row must show domain_cues attacked")
    if "evidence_order" not in nonprimary_channels:
        raise RuntimeError("FAIL_CLOSED: focused shortcut row must preserve evidence_order as nonprimary by law")
    if bool(focused_transfer_row.get("shortcut_resistance_verified", True)):
        raise RuntimeError("FAIL_CLOSED: focused transfer row must keep shortcut resistance unverified")

    support_lab_hold_family_ids = [
        family_id
        for family_id in mixed_axis_execution_receipt.get("lab_hold_family_ids", [])
        if str(family_id).strip() and str(family_id).strip() != EXPECTED_FOCUSED_FAMILY_ID
    ]
    if not support_lab_hold_family_ids:
        raise RuntimeError("FAIL_CLOSED: expected supporting lab hold family ids to remain available")

    control_guard_rows = [row for row in transfer_rows if bool(row.get("control_family", False))]
    if len(control_guard_rows) < 2:
        raise RuntimeError("FAIL_CLOSED: expected at least two control guard rows")

    holdout_metrics = dict(mixed_axis_execution_receipt.get("route_head_holdout_metrics", {}))
    if float(holdout_metrics.get("reason_accuracy", 1.0)) != 0.0:
        raise RuntimeError("FAIL_CLOSED: expected zero holdout reason accuracy in frozen fail geometry")
    if float(holdout_metrics.get("action_accuracy", 0.0)) != 1.0:
        raise RuntimeError("FAIL_CLOSED: expected perfect holdout action accuracy in frozen fail geometry")
    if float(holdout_metrics.get("why_not_accuracy", 0.0)) != 1.0:
        raise RuntimeError("FAIL_CLOSED: expected perfect holdout why-not accuracy in frozen fail geometry")

    control_guard_family_ids = [str(row.get("family_id", "")).strip() for row in control_guard_rows if str(row.get("family_id", "")).strip()]
    mutation_dimensions = ["lexical_shell", "domain_label", "evidence_order", "ambiguity_framing", "distractor_structure"]

    return {
        "primary_fail_family_id": EXPECTED_FOCUSED_FAMILY_ID,
        "focused_axis_id": EXPECTED_FOCUSED_AXIS_ID,
        "support_lab_hold_family_ids": support_lab_hold_family_ids,
        "control_guard_family_ids": control_guard_family_ids,
        "shortcut_dependency_channels_present": shortcut_channels,
        "attacked_shortcut_channels": attacked_channels,
        "nonprimary_shortcut_channels_present_by_law": nonprimary_channels,
        "holdout_surface": holdout_metrics,
        "policy_vs_reason_verdict_id": mixed_axis_scorecard.get("policy_vs_reason_verdict_id", ""),
        "policy_vs_reason_verdict_text": mixed_axis_scorecard.get("policy_vs_reason_verdict_text", ""),
        "baseline_mean_net_policy_advantage_floor": focused_scorecard_row.get("baseline_mean_net_policy_advantage_floor"),
        "focused_survival_verdict": focused_transfer_row.get("survival_verdict", ""),
        "focused_transfer_candidate_status": focused_transfer_row.get("transfer_candidate_status", ""),
        "missing_mechanism_hypotheses": list(limitations_report.get("missing_mechanism_hypotheses", [])),
        "specific_current_limitations": list(limitations_report.get("specific_current_limitations", [])),
        "mutation_dimensions": mutation_dimensions,
    }


def _build_micro_courts(geometry: Dict[str, Any]) -> List[Dict[str, Any]]:
    common_pass_conditions = [
        "reportability_lift",
        "no_action_regression",
        "no_why_not_regression",
        "proof_facing_route_delta_under_intervention",
    ]
    return [
        {
            "micro_court_id": "RW_REASON_HOLDOUT_CORE",
            "court_role": "PRIMARY_REASON_GENERALIZATION_FAIL_GEOMETRY",
            "family_scope": [geometry["primary_fail_family_id"]],
            "locked_failure_signature": geometry["holdout_surface"],
            "locked_shortcut_channels": geometry["shortcut_dependency_channels_present"],
            "pass_conditions": common_pass_conditions,
            "required_interventions": [],
            "mutation_dimensions": [],
        },
        {
            "micro_court_id": "RW_MUTATION_CLONE_PRESSURE",
            "court_role": "PRIMARY_FAIL_GEOMETRY_MUTATION_TRANSFER",
            "family_scope": [geometry["primary_fail_family_id"]],
            "locked_failure_signature": geometry["holdout_surface"],
            "locked_shortcut_channels": geometry["shortcut_dependency_channels_present"],
            "pass_conditions": common_pass_conditions,
            "required_interventions": [],
            "mutation_dimensions": geometry["mutation_dimensions"],
        },
        {
            "micro_court_id": "RW_ROUTE_CONSEQUENCE_INTERVENTION_PANEL",
            "court_role": "PRIMARY_INTERVENTIONAL_ROUTE_CONSEQUENCE_PANEL",
            "family_scope": [geometry["primary_fail_family_id"]],
            "locked_failure_signature": geometry["holdout_surface"],
            "locked_shortcut_channels": geometry["shortcut_dependency_channels_present"],
            "pass_conditions": common_pass_conditions,
            "required_interventions": [
                "forced_wrong_route",
                "random_route",
                "forced_static_hold",
                "abstain_disabled",
                "witness_ablation",
                "oracle_route_upper_bound",
            ],
            "mutation_dimensions": geometry["mutation_dimensions"],
        },
        {
            "micro_court_id": "BOUNDARY_ABSTENTION_CONTROL_GUARD",
            "court_role": "CONTROL_GUARD__ABSTENTION_BOUNDARY",
            "family_scope": ["BOUNDARY_ABSTENTION_CONTROL"],
            "locked_failure_signature": geometry["holdout_surface"],
            "control_guard": True,
            "pass_conditions": common_pass_conditions,
            "required_interventions": [],
            "mutation_dimensions": [],
        },
        {
            "micro_court_id": "STATIC_NO_ROUTE_CONTROL_GUARD",
            "court_role": "CONTROL_GUARD__RIGHTFUL_STATIC_HOLD",
            "family_scope": ["STATIC_NO_ROUTE_CONTROL"],
            "locked_failure_signature": geometry["holdout_surface"],
            "control_guard": True,
            "pass_conditions": common_pass_conditions,
            "required_interventions": [],
            "mutation_dimensions": [],
        },
    ]


def _build_reportability_variants(geometry: Dict[str, Any], micro_courts: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    micro_court_ids = [court["micro_court_id"] for court in micro_courts]
    typed_output_fields = [
        "route_correctness_judgment",
        "action_judgment",
        "why_not_judgment",
        "reason_object",
        "evidence_basis",
        "counterfactual_contrast",
        "confidence_calibration",
    ]
    base = {
        "focused_family_id": geometry["primary_fail_family_id"],
        "frozen_micro_court_ids": micro_court_ids,
        "typed_output_fields": typed_output_fields,
        "success_gates": [
            "typed_admissible_reason_lift_on_frozen_fail_geometry",
            "no_action_regression",
            "no_why_not_regression",
            "mutation_robustness",
        ],
    }
    return [
        {
            **base,
            "variant_id": "RB_TYPED_CAUSAL_SCHEMA_BRIDGE_V1",
            "mechanism_class": "TYPED_CAUSAL_SCHEMA_EMISSION",
            "objective": "Emit typed reason objects instead of freeform prose on the frozen fail geometry.",
            "training_intents": [
                "typed causal schema emission",
                "slot-stable reason object production",
                "family-local holdout calibration",
            ],
        },
        {
            **base,
            "variant_id": "RB_COUNTERFACTUAL_EVIDENCE_OBJECT_BRIDGE_V1",
            "mechanism_class": "COUNTERFACTUAL_REASON_FAITHFULNESS_BRIDGE",
            "objective": "Bind reasons to evidence and counterfactual contrast so reportability stays causal rather than decorative.",
            "training_intents": [
                "counterfactual reason-faithfulness checks",
                "evidence-citation fidelity",
                "typed contrast object emission",
            ],
        },
        {
            **base,
            "variant_id": "RB_CALIBRATED_REASON_REFUSAL_BRIDGE_V1",
            "mechanism_class": "CALIBRATED_LAWFUL_REFUSAL_BRIDGE",
            "objective": "Prefer explicit lawful refusal over fake reason objects when the bridge cannot emit an admissible causal report.",
            "training_intents": [
                "confidence calibration",
                "low-confidence lawful refusal",
                "route/policy/reason surface separation",
            ],
        },
    ]


def _build_intervention_wave(geometry: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "intervention_id": "FORCED_WRONG_ROUTE_PRIMARY",
            "bound_micro_court_id": "RW_ROUTE_CONSEQUENCE_INTERVENTION_PANEL",
            "focused_family_id": geometry["primary_fail_family_id"],
            "goal": "Make wrong-route penalties visible on the primary fail family.",
        },
        {
            "intervention_id": "RANDOM_ROUTE_NEGATIVE_CONTROL_PRIMARY",
            "bound_micro_court_id": "RW_ROUTE_CONSEQUENCE_INTERVENTION_PANEL",
            "focused_family_id": geometry["primary_fail_family_id"],
            "goal": "Check whether route texture survives a random-route baseline without true route consequence.",
        },
        {
            "intervention_id": "ORACLE_ROUTE_UPPER_BOUND_PRIMARY",
            "bound_micro_court_id": "RW_ROUTE_CONSEQUENCE_INTERVENTION_PANEL",
            "focused_family_id": geometry["primary_fail_family_id"],
            "goal": "Measure whether headroom exists if route assignment were perfect.",
        },
        {
            "intervention_id": "WITNESS_ABLATION_PRIMARY",
            "bound_micro_court_id": "RW_ROUTE_CONSEQUENCE_INTERVENTION_PANEL",
            "focused_family_id": geometry["primary_fail_family_id"],
            "goal": "Test whether the current witness is causally load-bearing.",
        },
        {
            "intervention_id": "FORCED_STATIC_HOLD_CONTROL_SPINE",
            "bound_micro_court_id": "STATIC_NO_ROUTE_CONTROL_GUARD",
            "focused_family_id": "STATIC_NO_ROUTE_CONTROL",
            "goal": "Keep rightful static hold measurable while successor variants move.",
        },
        {
            "intervention_id": "ABSTAIN_DISABLED_BOUNDARY_SPINE",
            "bound_micro_court_id": "BOUNDARY_ABSTENTION_CONTROL_GUARD",
            "focused_family_id": "BOUNDARY_ABSTENTION_CONTROL",
            "goal": "Measure whether abstention degradation appears under route-consequence pressure.",
        },
    ]


def _build_markdown_report(tranche_manifest: Dict[str, Any], outputs: Sequence[str]) -> str:
    lines: List[str] = []
    lines.append("# COHORT0 First Successor Evidence Setup Report")
    lines.append("")
    lines.append(f"- Generated UTC: `{tranche_manifest['generated_utc']}`")
    lines.append(f"- Subject head: `{tranche_manifest['subject_head']}`")
    lines.append(f"- Primary fail family: `{tranche_manifest['frozen_fail_geometry']['primary_fail_family_id']}`")
    lines.append(f"- Next lawful move remains: `{tranche_manifest['live_authority_snapshot']['next_lawful_move']}`")
    lines.append("")
    lines.append("## What This Setup Did")
    lines.append("")
    for item in tranche_manifest["completed_now"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Frozen Micro-Courts")
    lines.append("")
    for court in tranche_manifest["locked_micro_court_ids"]:
        lines.append(f"- `{court}`")
    lines.append("")
    lines.append("## Claim Boundary")
    lines.append("")
    lines.append(tranche_manifest["claim_boundary"])
    lines.append("")
    lines.append("## Files Emitted By This Tranche")
    lines.append("")
    for rel in outputs:
        lines.append(f"- `{rel}`")
    lines.append("")
    return "\n".join(lines)


def run_first_successor_evidence_setup_tranche(
    *,
    verdict_packet_path: Path,
    limitations_report_path: Path,
    reentry_block_path: Path,
    redesign_work_order_path: Path,
    theorem_target_path: Path,
    micro_courts_manifest_path: Path,
    reportability_eval_court_path: Path,
    reportability_training_manifest_path: Path,
    reportability_mutation_pack_path: Path,
    causal_intervention_matrix_path: Path,
    route_ablation_harness_path: Path,
    mixed_axis_execution_receipt_path: Path,
    mixed_axis_scorecard_path: Path,
    mixed_axis_shortcut_recheck_path: Path,
    mixed_axis_transfer_eligibility_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    root = repo_root().resolve()
    reports_root = reports_root.resolve()
    reports_root.mkdir(parents=True, exist_ok=True)

    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    limitations_report = _load_json_required(limitations_report_path, label="current substrate limitations report")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    redesign_work_order = _load_json_required(redesign_work_order_path, label="gate d redesign campaign work order")
    theorem_target = _load_json_required(theorem_target_path, label="gate d next theorem target")
    micro_courts_manifest = _load_json_required(micro_courts_manifest_path, label="successor frozen micro-courts manifest")
    reportability_eval_court = _load_json_required(reportability_eval_court_path, label="reportability bridge eval court")
    reportability_training_manifest = _load_json_required(reportability_training_manifest_path, label="reportability bridge training manifest")
    reportability_mutation_pack = _load_json_required(reportability_mutation_pack_path, label="reportability bridge holdout mutation pack")
    causal_intervention_matrix = _load_json_required(causal_intervention_matrix_path, label="causal route consequence intervention matrix")
    route_ablation_harness = _load_json_required(route_ablation_harness_path, label="route ablation harness")
    mixed_axis_execution_receipt = _load_json_required(mixed_axis_execution_receipt_path, label="mixed-axis execution receipt")
    mixed_axis_scorecard = _load_json_required(mixed_axis_scorecard_path, label="mixed-axis route consequence scorecard")
    mixed_axis_shortcut_recheck = _load_json_required(mixed_axis_shortcut_recheck_path, label="mixed-axis shortcut recheck")
    mixed_axis_transfer_eligibility = _load_json_required(mixed_axis_transfer_eligibility_path, label="mixed-axis transfer eligibility")

    _validate_live_state(
        verdict_packet=verdict_packet,
        limitations_report=limitations_report,
        reentry_block=reentry_block,
        redesign_work_order=redesign_work_order,
        theorem_target=theorem_target,
        micro_courts_manifest=micro_courts_manifest,
        reportability_eval_court=reportability_eval_court,
        reportability_training_manifest=reportability_training_manifest,
        reportability_mutation_pack=reportability_mutation_pack,
        causal_intervention_matrix=causal_intervention_matrix,
        route_ablation_harness=route_ablation_harness,
        mixed_axis_execution_receipt=mixed_axis_execution_receipt,
        mixed_axis_scorecard=mixed_axis_scorecard,
        mixed_axis_shortcut_recheck=mixed_axis_shortcut_recheck,
        mixed_axis_transfer_eligibility=mixed_axis_transfer_eligibility,
    )

    subject_head = _require_same_subject_head(
        [
            verdict_packet,
            limitations_report,
            reentry_block,
            redesign_work_order,
            theorem_target,
            micro_courts_manifest,
            reportability_eval_court,
            reportability_training_manifest,
            reportability_mutation_pack,
            causal_intervention_matrix,
            route_ablation_harness,
            mixed_axis_execution_receipt,
            mixed_axis_scorecard,
            mixed_axis_shortcut_recheck,
            mixed_axis_transfer_eligibility,
        ]
    )
    if subject_head != EXPECTED_SUBJECT_HEAD:
        raise RuntimeError("FAIL_CLOSED: unexpected subject head for first successor evidence setup")

    frozen_geometry = _derive_fail_geometry(
        limitations_report=limitations_report,
        mixed_axis_execution_receipt=mixed_axis_execution_receipt,
        mixed_axis_scorecard=mixed_axis_scorecard,
        mixed_axis_shortcut_recheck=mixed_axis_shortcut_recheck,
        mixed_axis_transfer_eligibility=mixed_axis_transfer_eligibility,
    )
    locked_micro_courts = _build_micro_courts(frozen_geometry)
    reportability_variants = _build_reportability_variants(frozen_geometry, locked_micro_courts)
    intervention_wave = _build_intervention_wave(frozen_geometry)

    live_authority_snapshot = {
        "final_verdict_id": verdict_packet["final_verdict_id"],
        "current_lane_closed": verdict_packet["current_lane_closed"],
        "same_head_counted_reentry_admissible_now": verdict_packet["same_head_counted_reentry_admissible_now"],
        "next_lawful_move": verdict_packet["next_lawful_move"],
        "secondary_parallel_move": verdict_packet["secondary_parallel_move"],
    }

    authority_refs = {
        "verdict_packet_ref": verdict_packet_path.as_posix(),
        "limitations_report_ref": limitations_report_path.as_posix(),
        "reentry_block_ref": reentry_block_path.as_posix(),
        "redesign_work_order_ref": redesign_work_order_path.as_posix(),
        "theorem_target_ref": theorem_target_path.as_posix(),
        "mixed_axis_execution_receipt_ref": mixed_axis_execution_receipt_path.as_posix(),
        "mixed_axis_scorecard_ref": mixed_axis_scorecard_path.as_posix(),
        "mixed_axis_shortcut_recheck_ref": mixed_axis_shortcut_recheck_path.as_posix(),
        "mixed_axis_transfer_eligibility_ref": mixed_axis_transfer_eligibility_path.as_posix(),
    }

    updated_micro_courts_manifest = dict(micro_courts_manifest)
    updated_micro_courts_manifest.update(
        {
            "execution_status": "LOCKED__READY_FOR_FIRST_SUCCESSOR_VARIANTS",
            "locked_from_source_geometry": True,
            "locked_micro_courts": locked_micro_courts,
            "support_lab_hold_family_ids": frozen_geometry["support_lab_hold_family_ids"],
            "control_guard_family_ids": frozen_geometry["control_guard_family_ids"],
            "focused_family_id": frozen_geometry["primary_fail_family_id"],
            "focused_axis_id": frozen_geometry["focused_axis_id"],
            "policy_vs_reason_verdict_id": frozen_geometry["policy_vs_reason_verdict_id"],
            "policy_vs_reason_verdict_text": frozen_geometry["policy_vs_reason_verdict_text"],
            "setup_refs": {
                "mixed_axis_execution_receipt_ref": mixed_axis_execution_receipt_path.as_posix(),
                "mixed_axis_scorecard_ref": mixed_axis_scorecard_path.as_posix(),
                "mixed_axis_shortcut_recheck_ref": mixed_axis_shortcut_recheck_path.as_posix(),
                "mixed_axis_transfer_eligibility_ref": mixed_axis_transfer_eligibility_path.as_posix(),
            },
        }
    )

    updated_reportability_eval_court = dict(reportability_eval_court)
    updated_reportability_eval_court.update(
        {
            "execution_status": "SETUP_BOUND__READY_FOR_FIRST_VARIANTS",
            "focused_family_id": frozen_geometry["primary_fail_family_id"],
            "focused_axis_id": frozen_geometry["focused_axis_id"],
            "frozen_micro_court_ids": [court["micro_court_id"] for court in locked_micro_courts],
            "support_lab_hold_family_ids": frozen_geometry["support_lab_hold_family_ids"],
            "typed_output_fields": [
                "route_correctness_judgment",
                "action_judgment",
                "why_not_judgment",
                "reason_object",
                "evidence_basis",
                "counterfactual_contrast",
                "confidence_calibration",
            ],
            "holdout_failure_signature": frozen_geometry["holdout_surface"],
            "setup_refs": {
                "locked_micro_courts_manifest_ref": (reports_root / "cohort0_successor_frozen_micro_courts_manifest.json").resolve().as_posix(),
                "variant_manifest_ref": (reports_root / OUTPUT_REPORTABILITY_VARIANT_MANIFEST).resolve().as_posix(),
            },
        }
    )

    updated_reportability_training_manifest = dict(reportability_training_manifest)
    updated_reportability_training_manifest.update(
        {
            "execution_status": "SETUP_BOUND__READY_FOR_FIRST_VARIANTS",
            "focused_family_id": frozen_geometry["primary_fail_family_id"],
            "variant_ids": [variant["variant_id"] for variant in reportability_variants],
            "frozen_micro_court_ids": [court["micro_court_id"] for court in locked_micro_courts],
            "support_lab_hold_family_ids": frozen_geometry["support_lab_hold_family_ids"],
            "setup_refs": {
                "variant_manifest_ref": (reports_root / OUTPUT_REPORTABILITY_VARIANT_MANIFEST).resolve().as_posix(),
                "mutation_pack_ref": (reports_root / "reportability_bridge_holdout_mutation_pack.json").resolve().as_posix(),
            },
        }
    )

    updated_reportability_mutation_pack = dict(reportability_mutation_pack)
    updated_reportability_mutation_pack.update(
        {
            "execution_status": "SETUP_BOUND__READY_FOR_FIRST_VARIANTS",
            "focused_family_id": frozen_geometry["primary_fail_family_id"],
            "locked_micro_court_id": "RW_MUTATION_CLONE_PRESSURE",
            "first_wave_pack_ids": [
                "MUTATION_WAVE__LEXICAL_SHELL",
                "MUTATION_WAVE__DOMAIN_LABEL",
                "MUTATION_WAVE__EVIDENCE_ORDER",
                "MUTATION_WAVE__DISTRACTOR_STRUCTURE",
                "MUTATION_WAVE__AMBIGUITY_FRAMING",
            ],
            "setup_refs": {
                "variant_manifest_ref": (reports_root / OUTPUT_REPORTABILITY_VARIANT_MANIFEST).resolve().as_posix(),
                "locked_micro_courts_manifest_ref": (reports_root / "cohort0_successor_frozen_micro_courts_manifest.json").resolve().as_posix(),
            },
        }
    )

    updated_causal_intervention_matrix = dict(causal_intervention_matrix)
    updated_causal_intervention_matrix.update(
        {
            "execution_status": "SETUP_BOUND__READY_FOR_INTERVENTION_RUNS",
            "focused_family_id": frozen_geometry["primary_fail_family_id"],
            "focused_axis_id": frozen_geometry["focused_axis_id"],
            "support_lab_hold_family_ids": frozen_geometry["support_lab_hold_family_ids"],
            "control_guard_family_ids": frozen_geometry["control_guard_family_ids"],
            "locked_micro_court_id": "RW_ROUTE_CONSEQUENCE_INTERVENTION_PANEL",
            "setup_refs": {
                "intervention_launch_manifest_ref": (reports_root / OUTPUT_CAUSAL_LAUNCH_MANIFEST).resolve().as_posix(),
                "locked_micro_courts_manifest_ref": (reports_root / "cohort0_successor_frozen_micro_courts_manifest.json").resolve().as_posix(),
            },
        }
    )

    updated_route_ablation_harness = dict(route_ablation_harness)
    updated_route_ablation_harness.update(
        {
            "execution_status": "SETUP_BOUND__READY_FOR_INTERVENTION_RUNS",
            "focused_family_id": frozen_geometry["primary_fail_family_id"],
            "control_guard_family_ids": frozen_geometry["control_guard_family_ids"],
            "support_lab_hold_family_ids": frozen_geometry["support_lab_hold_family_ids"],
            "setup_refs": {
                "intervention_launch_manifest_ref": (reports_root / OUTPUT_CAUSAL_LAUNCH_MANIFEST).resolve().as_posix(),
                "locked_micro_courts_manifest_ref": (reports_root / "cohort0_successor_frozen_micro_courts_manifest.json").resolve().as_posix(),
            },
        }
    )

    locked_micro_courts_receipt = {
        "schema_id": "kt.operator.cohort0_successor_frozen_micro_courts_locked_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "claim_boundary": (
            "This receipt locks the frozen fail geometry for successor evidence work. "
            "It does not claim that any reportability or route-consequence variant has been executed."
        ),
        "execution_status": "LOCKED__READY_FOR_FIRST_SUCCESSOR_VARIANTS",
        "focused_family_id": frozen_geometry["primary_fail_family_id"],
        "control_guard_family_ids": frozen_geometry["control_guard_family_ids"],
        "support_lab_hold_family_ids": frozen_geometry["support_lab_hold_family_ids"],
        "locked_micro_court_ids": [court["micro_court_id"] for court in locked_micro_courts],
        "holdout_surface": frozen_geometry["holdout_surface"],
        "source_refs": authority_refs,
    }

    reportability_variant_manifest = {
        "schema_id": "kt.operator.reportability_bridge_variant_manifest.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "claim_boundary": (
            "This manifest instantiates the first reportability-bridge variants against the locked successor court. "
            "It does not claim any variant success or Gate D movement."
        ),
        "execution_status": "AUTHORIZED__NOT_EXECUTED",
        "focused_family_id": frozen_geometry["primary_fail_family_id"],
        "support_lab_hold_family_ids": frozen_geometry["support_lab_hold_family_ids"],
        "control_guard_family_ids": frozen_geometry["control_guard_family_ids"],
        "variants": reportability_variants,
        "source_refs": authority_refs,
    }

    causal_launch_manifest = {
        "schema_id": "kt.operator.causal_route_consequence_intervention_launch_manifest.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "claim_boundary": (
            "This launch manifest instantiates the first intervention wave for the successor causal harness. "
            "It does not claim any executed route-consequence result."
        ),
        "execution_status": "AUTHORIZED__NOT_EXECUTED",
        "focused_family_id": frozen_geometry["primary_fail_family_id"],
        "support_lab_hold_family_ids": frozen_geometry["support_lab_hold_family_ids"],
        "control_guard_family_ids": frozen_geometry["control_guard_family_ids"],
        "minimum_success_signals": [
            "wrong_route_penalty_visible",
            "route_vs_static_economics_visible",
            "one_fenced_family_route_consequence_signal_nonzero",
        ],
        "intervention_wave": intervention_wave,
        "source_refs": authority_refs,
    }

    tranche_manifest = {
        "schema_id": "kt.operator.cohort0_first_successor_evidence_tranche_manifest.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": verdict_packet.get("current_git_head", ""),
        "subject_head": subject_head,
        "claim_boundary": (
            "This tranche sets up first successor evidence only. It locks frozen micro-courts and instantiates "
            "first reportability-bridge and causal-harness manifests without claiming theorem movement."
        ),
        "execution_status": "SETUP_BOUND__FIRST_SUCCESSOR_EVIDENCE_NOT_YET_EXECUTED",
        "live_authority_snapshot": live_authority_snapshot,
        "frozen_fail_geometry": frozen_geometry,
        "locked_micro_court_ids": [court["micro_court_id"] for court in locked_micro_courts],
        "completed_now": [
            "Locked the frozen successor micro-courts from hardened-ceiling fail geometry.",
            "Bound the reportability bridge eval/training surfaces to the locked fail geometry.",
            "Instantiated the first reportability-bridge variant manifest.",
            "Instantiated the first causal route-consequence intervention launch manifest.",
            "Kept Gate D readjudication dormant and same-head reentry blocked.",
        ],
        "next_execution_order": [
            "execute_locked_reportability_bridge_variants",
            "execute_causal_route_consequence_intervention_wave",
            "emit_first_successor_dominance_packet_from_executed_evidence_only",
        ],
        "source_refs": authority_refs,
    }

    setup_receipt = {
        "schema_id": "kt.operator.cohort0_first_successor_evidence_setup_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "claim_boundary": (
            "This receipt records first-successor-evidence setup only. No reportability variant execution, no causal harness execution, "
            "no Gate D movement, and no Gate E movement are claimed."
        ),
        "setup_status": "PASS__FIRST_SUCCESSOR_EVIDENCE_SETUP_BOUND",
        "focused_family_id": frozen_geometry["primary_fail_family_id"],
        "locked_micro_court_count": len(locked_micro_courts),
        "reportability_variant_count": len(reportability_variants),
        "intervention_count": len(intervention_wave),
        "gate_d_reopened": False,
        "gate_e_open": False,
        "same_head_counted_reentry_admissible_now": False,
        "next_lawful_move": EXPECTED_PRIMARY_MOVE,
        "secondary_parallel_move": EXPECTED_SECONDARY_MOVE,
        "source_refs": {
            **authority_refs,
            "tranche_manifest_ref": (reports_root / OUTPUT_TRANCHE_MANIFEST).resolve().as_posix(),
            "locked_micro_courts_receipt_ref": (reports_root / OUTPUT_MICRO_COURT_LOCK_RECEIPT).resolve().as_posix(),
            "reportability_variant_manifest_ref": (reports_root / OUTPUT_REPORTABILITY_VARIANT_MANIFEST).resolve().as_posix(),
            "causal_launch_manifest_ref": (reports_root / OUTPUT_CAUSAL_LAUNCH_MANIFEST).resolve().as_posix(),
        },
    }

    artifact_payloads: Dict[str, Dict[str, Any]] = {
        "cohort0_successor_frozen_micro_courts_manifest.json": updated_micro_courts_manifest,
        "reportability_bridge_eval_court.json": updated_reportability_eval_court,
        "reportability_bridge_training_manifest.json": updated_reportability_training_manifest,
        "reportability_bridge_holdout_mutation_pack.json": updated_reportability_mutation_pack,
        "causal_route_consequence_intervention_matrix.json": updated_causal_intervention_matrix,
        "route_ablation_harness.json": updated_route_ablation_harness,
        OUTPUT_MICRO_COURT_LOCK_RECEIPT: locked_micro_courts_receipt,
        OUTPUT_REPORTABILITY_VARIANT_MANIFEST: reportability_variant_manifest,
        OUTPUT_CAUSAL_LAUNCH_MANIFEST: causal_launch_manifest,
        OUTPUT_TRANCHE_MANIFEST: tranche_manifest,
        OUTPUT_SETUP_RECEIPT: setup_receipt,
    }

    output_paths: List[str] = []
    for filename, payload in artifact_payloads.items():
        path = (reports_root / filename).resolve()
        write_json_stable(path, payload)
        output_paths.append(f"KT_PROD_CLEANROOM/reports/{filename}")

    report_markdown = _build_markdown_report(tranche_manifest, output_paths)
    report_path = (reports_root / OUTPUT_REPORT).resolve()
    _write_text(report_path, report_markdown)
    output_paths.append(f"KT_PROD_CLEANROOM/reports/{OUTPUT_REPORT}")

    return {
        "tranche_manifest": tranche_manifest,
        "outputs": output_paths,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lock first-successor-evidence setup surfaces from the live hardened-ceiling fail geometry."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--limitations-report", default=DEFAULT_LIMITATIONS_REPORT_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--redesign-work-order", default=DEFAULT_REDESIGN_WORK_ORDER_REL)
    parser.add_argument("--theorem-target", default=DEFAULT_THEOREM_TARGET_REL)
    parser.add_argument("--micro-courts-manifest", default=DEFAULT_MICRO_COURTS_REL)
    parser.add_argument("--reportability-eval-court", default=DEFAULT_REPORTABILITY_EVAL_COURT_REL)
    parser.add_argument("--reportability-training-manifest", default=DEFAULT_REPORTABILITY_TRAINING_MANIFEST_REL)
    parser.add_argument("--reportability-mutation-pack", default=DEFAULT_REPORTABILITY_MUTATION_PACK_REL)
    parser.add_argument("--causal-intervention-matrix", default=DEFAULT_CAUSAL_INTERVENTION_MATRIX_REL)
    parser.add_argument("--route-ablation-harness", default=DEFAULT_ROUTE_ABLATION_HARNESS_REL)
    parser.add_argument("--mixed-axis-execution-receipt", default=DEFAULT_MIXED_AXIS_EXECUTION_RECEIPT_REL)
    parser.add_argument("--mixed-axis-scorecard", default=DEFAULT_MIXED_AXIS_SCORECARD_REL)
    parser.add_argument("--mixed-axis-shortcut-recheck", default=DEFAULT_MIXED_AXIS_SHORTCUT_RECHECK_REL)
    parser.add_argument("--mixed-axis-transfer-eligibility", default=DEFAULT_MIXED_AXIS_TRANSFER_ELIGIBILITY_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_first_successor_evidence_setup_tranche(
        verdict_packet_path=_resolve(root, str(args.verdict_packet)),
        limitations_report_path=_resolve(root, str(args.limitations_report)),
        reentry_block_path=_resolve(root, str(args.reentry_block)),
        redesign_work_order_path=_resolve(root, str(args.redesign_work_order)),
        theorem_target_path=_resolve(root, str(args.theorem_target)),
        micro_courts_manifest_path=_resolve(root, str(args.micro_courts_manifest)),
        reportability_eval_court_path=_resolve(root, str(args.reportability_eval_court)),
        reportability_training_manifest_path=_resolve(root, str(args.reportability_training_manifest)),
        reportability_mutation_pack_path=_resolve(root, str(args.reportability_mutation_pack)),
        causal_intervention_matrix_path=_resolve(root, str(args.causal_intervention_matrix)),
        route_ablation_harness_path=_resolve(root, str(args.route_ablation_harness)),
        mixed_axis_execution_receipt_path=_resolve(root, str(args.mixed_axis_execution_receipt)),
        mixed_axis_scorecard_path=_resolve(root, str(args.mixed_axis_scorecard)),
        mixed_axis_shortcut_recheck_path=_resolve(root, str(args.mixed_axis_shortcut_recheck)),
        mixed_axis_transfer_eligibility_path=_resolve(root, str(args.mixed_axis_transfer_eligibility)),
        reports_root=_resolve(root, str(args.reports_root)),
    )
    tranche_manifest = payload["tranche_manifest"]
    print(
        {
            "status": tranche_manifest["status"],
            "setup_status": tranche_manifest["execution_status"],
            "focused_family_id": tranche_manifest["frozen_fail_geometry"]["primary_fail_family_id"],
            "locked_micro_court_count": len(tranche_manifest["locked_micro_court_ids"]),
            "next_lawful_move": tranche_manifest["live_authority_snapshot"]["next_lawful_move"],
            "output_count": len(payload["outputs"]),
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
