from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_gate_d_successor_execution_charter_tranche as successor_charter
from tools.operator import cohort0_lane_a_promoted_survivor_execution_tranche as lane_a_exec
from tools.operator import cohort0_lane_b_family_level_bridge_harness_tranche as lane_b_exec
from tools.operator import (
    cohort0_successor_family_side_anti_selection_closure_wave_tranche as family_side_closure_wave,
)
from tools.operator import cohort0_successor_full_gate_d_readjudication_authorization_screen_tranche as full_auth_screen
from tools.operator import cohort0_successor_reentry_prep_packet_tranche as prep_packet_tranche
from tools.operator import cohort0_successor_route_consequence_severity_escalation_wave_tranche as severity_wave
from tools.operator import cohort0_successor_third_surface_breadth_witness_wave_tranche as third_surface_wave
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_READJUDICATION_MANIFEST_REL = (
    f"KT_PROD_CLEANROOM/reports/{successor_charter.OUTPUT_READJUDICATION_MANIFEST}"
)
DEFAULT_PREP_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{prep_packet_tranche.OUTPUT_PACKET}"
DEFAULT_LANE_A_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{lane_a_exec.OUTPUT_SCORECARD}"
DEFAULT_LANE_B_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_SCORECARD}"
DEFAULT_CROSS_LANE_COMPARATIVE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_COMPARATIVE_PACKET}"
DEFAULT_FAMILY_SIDE_CLOSURE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{family_side_closure_wave.OUTPUT_PACKET}"
DEFAULT_FAMILY_SIDE_CLOSURE_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{family_side_closure_wave.OUTPUT_RECEIPT}"
DEFAULT_SEVERITY_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{severity_wave.OUTPUT_PACKET}"
DEFAULT_SEVERITY_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{severity_wave.OUTPUT_RECEIPT}"
DEFAULT_THIRD_SURFACE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{third_surface_wave.OUTPUT_PACKET}"
DEFAULT_THIRD_SURFACE_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{third_surface_wave.OUTPUT_RECEIPT}"
DEFAULT_FULL_AUTH_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{full_auth_screen.OUTPUT_PACKET}"
DEFAULT_FULL_AUTH_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{full_auth_screen.OUTPUT_RECEIPT}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_PACKET = "cohort0_successor_full_gate_d_readjudication_packet.json"
OUTPUT_RECEIPT = "cohort0_successor_full_gate_d_readjudication_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_FULL_GATE_D_READJUDICATION_REPORT.md"

EXECUTION_STATUS = "PASS__SUCCESSOR_FULL_GATE_D_READJUDICATION_CONVENED"
OUTCOME_CLEARED = "GATE_D_CLEARED__SUCCESSOR_LINE"
OUTCOME_NOT_CLEARED = "GATE_D_NOT_CLEARED__SUCCESSOR_LINE_READJUDICATED"
OUTCOME_DEFERRED = "DEFERRED__COURT_DEFECT_IDENTIFIED"
NEXT_MOVE_CLEARED = "CONVENE_GATE_E_PRECONDITION_MONITOR__POST_SUCCESSOR_GATE_D_CLEAR"
NEXT_MOVE_NOT_CLEARED = "MAINTAIN_SUCCESSOR_GATE_D_NOT_CLEARED_POSTURE__SUCCESSOR_LINE_READJUDICATED"
NEXT_MOVE_DEFERRED = "FIX_COURT_DEFECT_AND_RECONVENE_SUCCESSOR_GATE_D_READJUDICATION"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


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
        raise RuntimeError("FAIL_CLOSED: successor full readjudication requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    readjudication_manifest: Dict[str, Any],
    prep_packet: Dict[str, Any],
    lane_a_scorecard: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    cross_lane_comparative_packet: Dict[str, Any],
    family_side_closure_packet: Dict[str, Any],
    family_side_closure_receipt: Dict[str, Any],
    severity_packet: Dict[str, Any],
    severity_receipt: Dict[str, Any],
    third_surface_packet: Dict[str, Any],
    third_surface_receipt: Dict[str, Any],
    full_auth_packet: Dict[str, Any],
    full_auth_receipt: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (readjudication_manifest, "successor gate d readjudication manifest"),
        (prep_packet, "successor reentry-prep packet"),
        (lane_a_scorecard, "lane a scorecard"),
        (lane_b_scorecard, "lane b scorecard"),
        (cross_lane_comparative_packet, "cross-lane comparative packet"),
        (family_side_closure_packet, "family-side anti-selection closure packet"),
        (family_side_closure_receipt, "family-side anti-selection closure receipt"),
        (severity_packet, "severity escalation packet"),
        (severity_receipt, "severity escalation receipt"),
        (third_surface_packet, "third-surface breadth packet"),
        (third_surface_receipt, "third-surface breadth receipt"),
        (full_auth_packet, "full readjudication authorization packet"),
        (full_auth_receipt, "full readjudication authorization receipt"),
    ):
        _ensure_pass(payload, label=label)

    if str(verdict_packet.get("final_verdict_id", "")).strip() != setup_tranche.EXPECTED_FINAL_VERDICT_ID:
        raise RuntimeError("FAIL_CLOSED: hardened ceiling verdict id mismatch")
    if not bool(verdict_packet.get("current_lane_closed", False)):
        raise RuntimeError("FAIL_CLOSED: current same-head lane must remain historically closed")
    if str(reentry_block.get("reentry_status", "")).strip() != "BLOCKED__CURRENT_LANE_HARDENED_CEILING":
        raise RuntimeError("FAIL_CLOSED: hardened-ceiling reentry block must remain in force as history")
    if str(readjudication_manifest.get("execution_status", "")).strip() != "AUTHORIZED__NOT_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: successor readjudication manifest must still be in authorized-not-executed state")
    if str(full_auth_receipt.get("execution_status", "")).strip() != full_auth_screen.EXECUTION_STATUS:
        raise RuntimeError("FAIL_CLOSED: full readjudication authorization screen must exist before convening court")
    if str(full_auth_packet.get("full_successor_gate_d_readjudication_authorization_screen_status", "")).strip() not in {
        full_auth_screen.STATUS_AUTHORIZED,
        full_auth_screen.STATUS_DEFERRED_ANTI_SELECTION,
        full_auth_screen.STATUS_DEFERRED_GENERIC,
    }:
        raise RuntimeError("FAIL_CLOSED: full authorization screen status is unrecognized")


def _bool_all(*values: bool) -> bool:
    return all(bool(value) for value in values)


def _determine_outcome(
    *,
    findings: Dict[str, Any],
    full_auth_receipt: Dict[str, Any],
    full_auth_packet: Dict[str, Any],
) -> str:
    if not bool(full_auth_receipt.get("full_successor_gate_d_readjudication_authorized_now", False)):
        return OUTCOME_DEFERRED

    if _bool_all(
        findings.get("selected_bridge_locked", False),
        findings.get("same_head_comparator_locked", False),
        findings.get("lane_a_numeric_benchmark_holds", False),
        findings.get("lane_a_route_consequence_nonzero", False),
        findings.get("lane_a_static_displacement_visible", False),
        findings.get("lane_b_materially_distinct_family_holds", False),
        findings.get("lane_b_route_consequence_visible", False),
        findings.get("reserve_and_anti_selection_closed", False),
        findings.get("severity_closure_retained", False),
        findings.get("third_surface_breadth_retained", False),
        findings.get("controls_preserved", False),
        findings.get("one_fenced_family_against_best_static_path_earned", False),
        findings.get("no_remaining_authorization_defects", False),
    ):
        return OUTCOME_CLEARED

    if bool(full_auth_packet.get("remaining_bounded_defects", [])) or bool(
        full_auth_packet.get("remaining_authorization_predicates", [])
    ):
        return OUTCOME_DEFERRED

    return OUTCOME_NOT_CLEARED


def _build_outputs(
    *,
    subject_head: str,
    verdict_packet: Dict[str, Any],
    prep_packet: Dict[str, Any],
    lane_a_scorecard: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    cross_lane_comparative_packet: Dict[str, Any],
    family_side_closure_packet: Dict[str, Any],
    severity_packet: Dict[str, Any],
    third_surface_packet: Dict[str, Any],
    full_auth_packet: Dict[str, Any],
    full_auth_receipt: Dict[str, Any],
    source_refs: Dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    selected_core = dict(prep_packet.get("selected_successor_core", {}))
    lane_a_metrics = dict(lane_a_scorecard.get("full_panel_metrics", {}))
    lane_b_metrics = dict(lane_b_scorecard.get("overall_metrics", {}))
    comparative_read = dict(cross_lane_comparative_packet.get("comparative_read", {}))
    family_metrics = dict(family_side_closure_packet.get("overall_metrics", {}))
    severity_totals = dict(severity_packet.get("severity_escalated_totals", {}))
    third_surface_candidate = dict(third_surface_packet.get("third_surface_candidate", {}))
    third_surface_metrics = dict(third_surface_packet.get("third_surface_reserve_metrics", {}))
    full_harness = dict(selected_core.get("fixed_harness_global_totals", {}))

    findings = {
        "selected_bridge_locked": str(selected_core.get("lead_bridge_candidate_id", "")).strip()
        == "RB_COUNTERFACTUAL_EVIDENCE_OBJECT_BRIDGE_V1",
        "same_head_comparator_locked": str(selected_core.get("same_head_comparator_mode", "")).strip()
        == "LOCKED__STATIC_ALPHA_COMPARATOR",
        "lane_a_numeric_benchmark_holds": (
            bool(lane_a_scorecard.get("full_bridge_hold", False))
            and float(lane_a_metrics.get("selected_bridge_reason_exact_accuracy", 0.0)) >= 1.0
            and float(lane_a_metrics.get("selected_bridge_reason_admissible_accuracy", 0.0)) >= 1.0
            and float(lane_a_metrics.get("action_accuracy", 0.0)) >= 1.0
            and float(lane_a_metrics.get("why_not_accuracy", 0.0)) >= 1.0
        ),
        "lane_a_route_consequence_nonzero": (
            bool(lane_a_scorecard.get("local_route_consequence_signal_nonzero", False))
            and float(lane_a_metrics.get("total_wrong_route_cost", 0.0)) > 0.0
        ),
        "lane_a_static_displacement_visible": float(lane_a_metrics.get("total_wrong_static_hold_cost", 0.0)) > 0.0,
        "lane_b_materially_distinct_family_holds": (
            bool(comparative_read.get("lane_b_now_executed_on_materially_distinct_family_surface", False))
            and float(lane_b_metrics.get("bridge_reason_exact_accuracy", 0.0)) >= 1.0
            and float(lane_b_metrics.get("bridge_reason_admissible_accuracy", 0.0)) >= 1.0
            and float(lane_b_metrics.get("selected_adapter_alignment_rate", 0.0)) >= 1.0
            and int(lane_b_scorecard.get("hydrated_family_count", 0)) >= 2
        ),
        "lane_b_route_consequence_visible": float(lane_b_metrics.get("route_consequence_visible_rate", 0.0)) >= 1.0,
        "reserve_and_anti_selection_closed": (
            bool(prep_packet.get("reserve_challenge_closure_section", {}).get("reserve_challenges_pass", False))
            and bool(family_side_closure_packet.get("anti_selection_wave_beyond_reserve_closed", False))
            and bool(family_side_closure_packet.get("family_side_anti_selection_defect_closed", False))
            and float(family_metrics.get("selected_bridge_reason_exact_accuracy", 0.0)) >= 1.0
            and float(family_metrics.get("selected_bridge_reason_admissible_accuracy", 0.0)) >= 1.0
            and float(family_metrics.get("route_consequence_visible_rate", 0.0)) >= 1.0
        ),
        "severity_closure_retained": (
            bool(severity_packet.get("severity_escalation_route_consequence_wave_closed", False))
            and bool(severity_packet.get("route_consequence_remains_nonzero_under_severity", False))
            and bool(severity_packet.get("static_hold_control_stays_clean_under_severity", False))
            and float(severity_totals.get("forced_wrong_route_total_cost", 0.0)) > 0.0
            and float(severity_totals.get("witness_ablation_total_cost", 0.0)) > 0.0
            and float(severity_totals.get("static_hold_control_total_cost", 1.0)) == 0.0
        ),
        "third_surface_breadth_retained": (
            bool(third_surface_packet.get("third_surface_breadth_witness_closed", False))
            and bool(third_surface_candidate.get("novelty_gate_pass", False))
            and bool(third_surface_candidate.get("distinct_from_promoted_family_lane", False))
            and not bool(third_surface_candidate.get("current_ring_overlap_detected", True))
            and not bool(third_surface_candidate.get("legacy_ring_overlap_detected", True))
            and float(third_surface_metrics.get("bridge_reason_exact_accuracy", 0.0)) >= 1.0
            and float(third_surface_metrics.get("bridge_reason_admissible_accuracy", 0.0)) >= 1.0
            and float(third_surface_metrics.get("route_consequence_visible_rate", 0.0)) >= 1.0
        ),
        "controls_preserved": (
            verdict_packet.get("branch_truth", {}).get("controls_preserved", False)
            and float(lane_a_metrics.get("action_accuracy", 0.0)) >= 1.0
            and float(lane_b_metrics.get("action_accuracy", 0.0)) >= 1.0
            and float(full_harness.get("static_hold_control_total_cost", 1.0)) == 0.0
        ),
        "one_fenced_family_against_best_static_path_earned": (
            float(lane_a_metrics.get("total_wrong_route_cost", 0.0)) > 0.0
            and float(lane_a_metrics.get("total_wrong_static_hold_cost", 0.0)) > 0.0
            and bool(comparative_read.get("dominance_surface_broadening_visible", False))
        ),
        "no_remaining_authorization_defects": (
            not bool(full_auth_packet.get("remaining_bounded_defects", []))
            and not bool(full_auth_packet.get("remaining_authorization_predicates", []))
        ),
    }

    outcome = _determine_outcome(
        findings=findings,
        full_auth_receipt=full_auth_receipt,
        full_auth_packet=full_auth_packet,
    )

    gate_d_cleared = outcome == OUTCOME_CLEARED
    next_lawful_move = (
        NEXT_MOVE_CLEARED
        if outcome == OUTCOME_CLEARED
        else (NEXT_MOVE_NOT_CLEARED if outcome == OUTCOME_NOT_CLEARED else NEXT_MOVE_DEFERRED)
    )
    counted_verdict_posture = (
        "GATE_D_CLEARED__SUCCESSOR_LINE__GATE_E_STILL_CLOSED"
        if gate_d_cleared
        else (
            "GATE_D_NOT_CLEARED__SUCCESSOR_LINE_READJUDICATED__SUCCESSOR_BUNDLE_BOUND"
            if outcome == OUTCOME_NOT_CLEARED
            else "DEFERRED__COURT_DEFECT_IDENTIFIED__SUCCESSOR_LINE"
        )
    )

    packet = {
        "schema_id": "kt.operator.cohort0_successor_full_gate_d_readjudication_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This court packet decides only the full successor Gate D readjudication question on the same-head court. "
            "It does not open Gate E, widen into broader KT narration, or erase the older hardened-ceiling history."
        ),
        "execution_status": EXECUTION_STATUS,
        "governing_boundary": {
            "gate_d_currently_closed_before_ruling": True,
            "same_head_counted_reentry_blocked_before_ruling": True,
            "gate_e_still_closed_before_ruling": True,
            "successor_readjudication_only": True,
            "prior_hardened_ceiling_history_preserved": True,
        },
        "active_core": {
            "lead_bridge_candidate_id": selected_core.get("lead_bridge_candidate_id", ""),
            "secondary_bridge_candidate_id": selected_core.get("secondary_bridge_candidate_id", ""),
            "guardrail_bridge_candidate_id": selected_core.get("guardrail_bridge_candidate_id", ""),
            "same_head_comparator_mode": selected_core.get("same_head_comparator_mode", ""),
            "counted_boundary_status_before_ruling": selected_core.get("counted_boundary_status", ""),
            "fixed_harness_global_totals": full_harness,
        },
        "lane_a_evidence_spine": {
            "promoted_survivor_ids": list(prep_packet.get("lane_a_evidence_spine", {}).get("promoted_survivor_ids", [])),
            "full_bridge_hold": bool(lane_a_scorecard.get("full_bridge_hold", False)),
            "full_panel_metrics": lane_a_metrics,
            "reserve_challenge_summary": dict(
                prep_packet.get("lane_a_evidence_spine", {}).get("reserve_challenge_summary", {})
            ),
            "local_numeric_cost_panel_available": True,
        },
        "lane_b_evidence_spine": {
            "hydrated_payload_provenance": dict(
                prep_packet.get("lane_b_evidence_spine", {}).get("hydrated_payload_provenance", {})
            ),
            "overall_metrics": lane_b_metrics,
            "family_metrics": list(lane_b_scorecard.get("family_metrics", [])),
            "reserve_challenge_summary": dict(
                prep_packet.get("lane_b_evidence_spine", {}).get("reserve_challenge_summary", {})
            ),
            "family_distinctness_and_novelty_support": dict(
                prep_packet.get("lane_b_evidence_spine", {}).get("family_distinctness_and_novelty_support", {})
            ),
        },
        "cross_lane_breadth_spine": {
            "cross_lane_comparative_read": comparative_read,
            "severity_packet": {
                "route_consequence_remains_nonzero_under_severity": severity_packet.get(
                    "route_consequence_remains_nonzero_under_severity", False
                ),
                "severity_escalated_totals": severity_totals,
                "static_hold_control_stays_clean_under_severity": severity_packet.get(
                    "static_hold_control_stays_clean_under_severity", False
                ),
            },
            "third_surface_witness": {
                "candidate": third_surface_candidate,
                "metrics": third_surface_metrics,
            },
            "family_side_anti_selection_closure": {
                "admitted_family_ids": list(family_side_closure_packet.get("admitted_family_ids", [])),
                "overall_metrics": family_metrics,
                "bounded_defects_remaining": list(
                    family_side_closure_packet.get("bounded_defects_remaining", [])
                ),
            },
            "full_authorization_screen_cleared": bool(
                full_auth_receipt.get("full_successor_gate_d_readjudication_authorized_now", False)
            ),
        },
        "adjudication_question": (
            "Does the bound successor evidence bundle now justify a same-head Gate D outcome adjudication "
            "because routed plurality has become causally consequential over the best static path strongly enough "
            "to beat or safely displace that path under the locked court?"
        ),
        "allowed_outcomes": [
            OUTCOME_CLEARED,
            OUTCOME_NOT_CLEARED,
            OUTCOME_DEFERRED,
        ],
        "adjudication_findings": findings,
        "readjudication_outcome": outcome,
        "source_refs": source_refs,
        "subject_head": subject_head,
    }

    receipt = {
        "schema_id": "kt.operator.cohort0_successor_full_gate_d_readjudication_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "readjudication_outcome": outcome,
        "counted_verdict_id": outcome,
        "counted_verdict_posture": counted_verdict_posture,
        "exact_superiority_outcome": (
            "EARNED__SUCCESSOR_LINE_BEATS_OR_SAFELY_DISPLACES_BEST_STATIC_PATH"
            if gate_d_cleared
            else (
                "NOT_EARNED__SUCCESSOR_LINE_READJUDICATED_STATIC_PATH_RETAINS_CANONICAL_STATUS"
                if outcome == OUTCOME_NOT_CLEARED
                else "DEFERRED__COURT_DEFECT_IDENTIFIED"
            )
        ),
        "ordered_proof_outcome": (
            "PASS__SUCCESSOR_LINE_ROUTE_CONSEQUENCE_EARNED_STATIC_PATH_DISPLACED_OR_SAFELY_DERISKED"
            if gate_d_cleared
            else (
                "PASS__SUCCESSOR_LINE_READJUDICATED_STATIC_PATH_RETAINS_CANONICAL_STATUS"
                if outcome == OUTCOME_NOT_CLEARED
                else "DEFERRED__COURT_DEFECT_IDENTIFIED"
            )
        ),
        "router_superiority_earned": gate_d_cleared,
        "controls_preserved": bool(findings["controls_preserved"]),
        "control_preservation_rate": 1.0 if findings["controls_preserved"] else 0.0,
        "masked_variant_survival_rate": 1.0
        if float(lane_a_scorecard.get("masked_companion_metrics", {}).get("selected_bridge_reason_exact_accuracy", 0.0))
        >= 1.0
        else 0.0,
        "null_route_counterfactual_preservation_rate": 1.0
        if float(full_harness.get("static_hold_control_total_cost", 1.0)) == 0.0
        else 0.0,
        "orthogonality_preserved": bool(findings["controls_preserved"]),
        "route_consequence_earned": bool(findings["one_fenced_family_against_best_static_path_earned"]),
        "same_head_counted_reentry_admissible_now": gate_d_cleared,
        "gate_d_officially_cleared": gate_d_cleared,
        "gate_d_reopened": gate_d_cleared,
        "gate_e_open": False,
        "current_same_head_lane_hardened_ceiling_history_preserved": True,
        "full_successor_gate_d_readjudication_authorized_now": bool(
            full_auth_receipt.get("full_successor_gate_d_readjudication_authorized_now", False)
        ),
        "next_lawful_move": next_lawful_move,
        "subject_head": subject_head,
    }
    return {"packet": packet, "receipt": receipt}


def _build_report(*, packet: Dict[str, Any], receipt: Dict[str, Any]) -> str:
    findings = dict(packet.get("adjudication_findings", {}))
    return (
        "# Cohort0 Successor Full Gate D Readjudication Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Readjudication outcome: `{receipt.get('readjudication_outcome', '')}`\n"
        f"- Counted verdict posture: `{receipt.get('counted_verdict_posture', '')}`\n"
        f"- Router superiority earned: `{receipt.get('router_superiority_earned', False)}`\n"
        f"- Route consequence earned: `{receipt.get('route_consequence_earned', False)}`\n"
        f"- Counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', False)}`\n"
        f"- Gate D officially cleared: `{receipt.get('gate_d_officially_cleared', False)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', False)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Adjudication Findings\n"
        f"- Selected bridge locked: `{findings.get('selected_bridge_locked', False)}`\n"
        f"- Same-head comparator locked: `{findings.get('same_head_comparator_locked', False)}`\n"
        f"- Lane A numeric benchmark holds: `{findings.get('lane_a_numeric_benchmark_holds', False)}`\n"
        f"- Lane A route consequence nonzero: `{findings.get('lane_a_route_consequence_nonzero', False)}`\n"
        f"- Lane A static displacement visible: `{findings.get('lane_a_static_displacement_visible', False)}`\n"
        f"- Lane B materially distinct family holds: `{findings.get('lane_b_materially_distinct_family_holds', False)}`\n"
        f"- Lane B route consequence visible: `{findings.get('lane_b_route_consequence_visible', False)}`\n"
        f"- Reserve and anti-selection closed: `{findings.get('reserve_and_anti_selection_closed', False)}`\n"
        f"- Severity closure retained: `{findings.get('severity_closure_retained', False)}`\n"
        f"- Third-surface breadth retained: `{findings.get('third_surface_breadth_retained', False)}`\n"
        f"- Controls preserved: `{findings.get('controls_preserved', False)}`\n"
        f"- One fenced family against best static path earned: `{findings.get('one_fenced_family_against_best_static_path_earned', False)}`\n"
        f"- No remaining authorization defects: `{findings.get('no_remaining_authorization_defects', False)}`\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    readjudication_manifest_path: Path,
    prep_packet_path: Path,
    lane_a_scorecard_path: Path,
    lane_b_scorecard_path: Path,
    cross_lane_comparative_packet_path: Path,
    family_side_closure_packet_path: Path,
    family_side_closure_receipt_path: Path,
    severity_packet_path: Path,
    severity_receipt_path: Path,
    third_surface_packet_path: Path,
    third_surface_receipt_path: Path,
    full_auth_packet_path: Path,
    full_auth_receipt_path: Path,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    readjudication_manifest = _load_json_required(
        readjudication_manifest_path, label="successor gate d readjudication manifest"
    )
    prep_packet = _load_json_required(prep_packet_path, label="successor reentry-prep packet")
    lane_a_scorecard = _load_json_required(lane_a_scorecard_path, label="lane a scorecard")
    lane_b_scorecard = _load_json_required(lane_b_scorecard_path, label="lane b scorecard")
    cross_lane_comparative_packet = _load_json_required(
        cross_lane_comparative_packet_path, label="cross-lane comparative packet"
    )
    family_side_closure_packet = _load_json_required(
        family_side_closure_packet_path, label="family-side anti-selection closure packet"
    )
    family_side_closure_receipt = _load_json_required(
        family_side_closure_receipt_path, label="family-side anti-selection closure receipt"
    )
    severity_packet = _load_json_required(severity_packet_path, label="severity escalation packet")
    severity_receipt = _load_json_required(severity_receipt_path, label="severity escalation receipt")
    third_surface_packet = _load_json_required(third_surface_packet_path, label="third-surface breadth packet")
    third_surface_receipt = _load_json_required(third_surface_receipt_path, label="third-surface breadth receipt")
    full_auth_packet = _load_json_required(full_auth_packet_path, label="full auth packet")
    full_auth_receipt = _load_json_required(full_auth_receipt_path, label="full auth receipt")

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        readjudication_manifest=readjudication_manifest,
        prep_packet=prep_packet,
        lane_a_scorecard=lane_a_scorecard,
        lane_b_scorecard=lane_b_scorecard,
        cross_lane_comparative_packet=cross_lane_comparative_packet,
        family_side_closure_packet=family_side_closure_packet,
        family_side_closure_receipt=family_side_closure_receipt,
        severity_packet=severity_packet,
        severity_receipt=severity_receipt,
        third_surface_packet=third_surface_packet,
        third_surface_receipt=third_surface_receipt,
        full_auth_packet=full_auth_packet,
        full_auth_receipt=full_auth_receipt,
    )
    subject_head = _require_same_subject_head(
        (
            verdict_packet,
            reentry_block,
            readjudication_manifest,
            prep_packet,
            lane_a_scorecard,
            lane_b_scorecard,
            cross_lane_comparative_packet,
            family_side_closure_packet,
            family_side_closure_receipt,
            severity_packet,
            severity_receipt,
            third_surface_packet,
            third_surface_receipt,
            full_auth_packet,
            full_auth_receipt,
        )
    )

    source_refs = {
        "verdict_packet_ref": verdict_packet_path.as_posix(),
        "reentry_block_ref": reentry_block_path.as_posix(),
        "readjudication_manifest_ref": readjudication_manifest_path.as_posix(),
        "prep_packet_ref": prep_packet_path.as_posix(),
        "lane_a_scorecard_ref": lane_a_scorecard_path.as_posix(),
        "lane_b_scorecard_ref": lane_b_scorecard_path.as_posix(),
        "cross_lane_comparative_packet_ref": cross_lane_comparative_packet_path.as_posix(),
        "family_side_closure_packet_ref": family_side_closure_packet_path.as_posix(),
        "family_side_closure_receipt_ref": family_side_closure_receipt_path.as_posix(),
        "severity_packet_ref": severity_packet_path.as_posix(),
        "severity_receipt_ref": severity_receipt_path.as_posix(),
        "third_surface_packet_ref": third_surface_packet_path.as_posix(),
        "third_surface_receipt_ref": third_surface_receipt_path.as_posix(),
        "full_auth_packet_ref": full_auth_packet_path.as_posix(),
        "full_auth_receipt_ref": full_auth_receipt_path.as_posix(),
    }
    outputs = _build_outputs(
        subject_head=subject_head,
        verdict_packet=verdict_packet,
        prep_packet=prep_packet,
        lane_a_scorecard=lane_a_scorecard,
        lane_b_scorecard=lane_b_scorecard,
        cross_lane_comparative_packet=cross_lane_comparative_packet,
        family_side_closure_packet=family_side_closure_packet,
        severity_packet=severity_packet,
        third_surface_packet=third_surface_packet,
        full_auth_packet=full_auth_packet,
        full_auth_receipt=full_auth_receipt,
        source_refs=source_refs,
    )

    reports_root.mkdir(parents=True, exist_ok=True)
    packet_path = reports_root / OUTPUT_PACKET
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(packet_path, outputs["packet"])
    write_json_stable(receipt_path, outputs["receipt"])
    _write_text(report_path, _build_report(packet=outputs["packet"], receipt=outputs["receipt"]))

    return {
        "status": "PASS",
        "execution_status": outputs["receipt"]["execution_status"],
        "readjudication_outcome": outputs["receipt"]["readjudication_outcome"],
        "gate_d_officially_cleared": outputs["receipt"]["gate_d_officially_cleared"],
        "gate_d_reopened": outputs["receipt"]["gate_d_reopened"],
        "gate_e_open": outputs["receipt"]["gate_e_open"],
        "next_lawful_move": outputs["receipt"]["next_lawful_move"],
        "output_count": 3,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Convene the full successor Gate D readjudication court.")
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--readjudication-manifest", default=DEFAULT_READJUDICATION_MANIFEST_REL)
    parser.add_argument("--prep-packet", default=DEFAULT_PREP_PACKET_REL)
    parser.add_argument("--lane-a-scorecard", default=DEFAULT_LANE_A_SCORECARD_REL)
    parser.add_argument("--lane-b-scorecard", default=DEFAULT_LANE_B_SCORECARD_REL)
    parser.add_argument("--cross-lane-comparative-packet", default=DEFAULT_CROSS_LANE_COMPARATIVE_PACKET_REL)
    parser.add_argument("--family-side-closure-packet", default=DEFAULT_FAMILY_SIDE_CLOSURE_PACKET_REL)
    parser.add_argument("--family-side-closure-receipt", default=DEFAULT_FAMILY_SIDE_CLOSURE_RECEIPT_REL)
    parser.add_argument("--severity-packet", default=DEFAULT_SEVERITY_PACKET_REL)
    parser.add_argument("--severity-receipt", default=DEFAULT_SEVERITY_RECEIPT_REL)
    parser.add_argument("--third-surface-packet", default=DEFAULT_THIRD_SURFACE_PACKET_REL)
    parser.add_argument("--third-surface-receipt", default=DEFAULT_THIRD_SURFACE_RECEIPT_REL)
    parser.add_argument("--full-auth-packet", default=DEFAULT_FULL_AUTH_PACKET_REL)
    parser.add_argument("--full-auth-receipt", default=DEFAULT_FULL_AUTH_RECEIPT_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        readjudication_manifest_path=_resolve(root, args.readjudication_manifest),
        prep_packet_path=_resolve(root, args.prep_packet),
        lane_a_scorecard_path=_resolve(root, args.lane_a_scorecard),
        lane_b_scorecard_path=_resolve(root, args.lane_b_scorecard),
        cross_lane_comparative_packet_path=_resolve(root, args.cross_lane_comparative_packet),
        family_side_closure_packet_path=_resolve(root, args.family_side_closure_packet),
        family_side_closure_receipt_path=_resolve(root, args.family_side_closure_receipt),
        severity_packet_path=_resolve(root, args.severity_packet),
        severity_receipt_path=_resolve(root, args.severity_receipt),
        third_surface_packet_path=_resolve(root, args.third_surface_packet),
        third_surface_receipt_path=_resolve(root, args.third_surface_receipt),
        full_auth_packet_path=_resolve(root, args.full_auth_packet),
        full_auth_receipt_path=_resolve(root, args.full_auth_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "readjudication_outcome",
        "gate_d_officially_cleared",
        "gate_d_reopened",
        "gate_e_open",
        "next_lawful_move",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
