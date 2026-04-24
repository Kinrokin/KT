from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_cross_lane_reentry_prep_screening_tranche as cross_lane_screen
from tools.operator import cohort0_first_successor_evidence_setup_tranche as setup_tranche
from tools.operator import cohort0_lane_a_promoted_survivor_execution_tranche as lane_a_exec
from tools.operator import cohort0_lane_b_family_level_bridge_harness_tranche as lane_b_exec
from tools.operator import cohort0_lane_b_stage_pack_hydration_tranche as lane_b_hydration
from tools.operator import cohort0_successor_anti_selection_stress_wave_tranche as anti_selection_wave
from tools.operator import (
    cohort0_successor_family_side_anti_selection_closure_wave_tranche as family_side_closure_wave,
)
from tools.operator import cohort0_successor_full_gate_d_readjudication_authorization_screen_tranche as full_auth_screen
from tools.operator import cohort0_successor_gate_d_narrow_admissibility_review_tranche as narrow_review
from tools.operator import cohort0_successor_gate_d_reentry_admissibility_screen_tranche as admissibility_screen
from tools.operator import cohort0_successor_full_gate_d_readjudication_tranche as full_readjudication
from tools.operator import cohort0_gate_e_precondition_monitor_tranche as gate_e_monitor
from tools.operator import cohort0_gate_e_admissibility_scope_packet_tranche as gate_e_scope
from tools.operator import cohort0_gate_e_post_clear_contradiction_audit_tranche as gate_e_audit
from tools.operator import cohort0_gate_e_admissibility_screen_tranche as gate_e_screen
from tools.operator import cohort0_gate_e_comparator_governance_binding_packet_tranche as gate_e_binding_packet
from tools.operator import cohort0_gate_e_comparator_governance_binding_screen_tranche as gate_e_binding_screen
from tools.operator import cohort0_gate_f_common as gate_f_common
from tools.operator import cohort0_gate_f_one_narrow_wedge_review_tranche as gate_f_review
from tools.operator import (
    cohort0_gate_f_post_close_live_product_truth_tranche as gate_f_live_product_truth,
)
from tools.operator import cohort0_post_f_broad_canonical_reaudit_tranche as post_f_reaudit
from tools.operator import cohort0_successor_route_consequence_severity_escalation_wave_tranche as severity_wave
from tools.operator import cohort0_successor_reentry_prep_packet_tranche as prep_packet_tranche
from tools.operator import cohort0_successor_third_surface_breadth_witness_wave_tranche as third_surface_wave
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_VERDICT_PACKET_REL = setup_tranche.DEFAULT_VERDICT_PACKET_REL
DEFAULT_REENTRY_BLOCK_REL = setup_tranche.DEFAULT_REENTRY_BLOCK_REL
DEFAULT_LANE_A_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{lane_a_exec.OUTPUT_RECEIPT}"
DEFAULT_LANE_A_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{lane_a_exec.OUTPUT_SCORECARD}"
DEFAULT_LANE_B_HYDRATION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_hydration.OUTPUT_HYDRATION_RECEIPT}"
DEFAULT_LANE_B_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_RECEIPT}"
DEFAULT_LANE_B_SCORECARD_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_SCORECARD}"
DEFAULT_CROSS_LANE_COMPARATIVE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{lane_b_exec.OUTPUT_COMPARATIVE_PACKET}"
DEFAULT_CROSS_LANE_SCREEN_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{cross_lane_screen.OUTPUT_SCREENING_PACKET}"
DEFAULT_CROSS_LANE_SCREEN_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{cross_lane_screen.OUTPUT_RECEIPT}"
DEFAULT_PREP_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{prep_packet_tranche.OUTPUT_PACKET}"
DEFAULT_PREP_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{prep_packet_tranche.OUTPUT_RECEIPT}"
DEFAULT_ADMISSIBILITY_SCREEN_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{admissibility_screen.OUTPUT_PACKET}"
DEFAULT_ADMISSIBILITY_SCREEN_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{admissibility_screen.OUTPUT_RECEIPT}"
DEFAULT_NARROW_REVIEW_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{narrow_review.OUTPUT_PACKET}"
DEFAULT_NARROW_REVIEW_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{narrow_review.OUTPUT_RECEIPT}"
DEFAULT_SEVERITY_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{severity_wave.OUTPUT_PACKET}"
DEFAULT_SEVERITY_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{severity_wave.OUTPUT_RECEIPT}"
DEFAULT_ANTI_SELECTION_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{anti_selection_wave.OUTPUT_PACKET}"
DEFAULT_ANTI_SELECTION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{anti_selection_wave.OUTPUT_RECEIPT}"
DEFAULT_FAMILY_SIDE_CLOSURE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{family_side_closure_wave.OUTPUT_PACKET}"
DEFAULT_FAMILY_SIDE_CLOSURE_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{family_side_closure_wave.OUTPUT_RECEIPT}"
DEFAULT_THIRD_SURFACE_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{third_surface_wave.OUTPUT_PACKET}"
DEFAULT_THIRD_SURFACE_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{third_surface_wave.OUTPUT_RECEIPT}"
DEFAULT_FULL_AUTH_SCREEN_PACKET_REL = f"KT_PROD_CLEANROOM/reports/{full_auth_screen.OUTPUT_PACKET}"
DEFAULT_FULL_AUTH_SCREEN_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{full_auth_screen.OUTPUT_RECEIPT}"
DEFAULT_FULL_READJUDICATION_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{full_readjudication.OUTPUT_RECEIPT}"
DEFAULT_GATE_E_MONITOR_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_monitor.OUTPUT_RECEIPT}"
DEFAULT_GATE_E_SCOPE_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_scope.OUTPUT_RECEIPT}"
DEFAULT_GATE_E_AUDIT_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_audit.OUTPUT_RECEIPT}"
DEFAULT_GATE_E_SCREEN_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_screen.OUTPUT_RECEIPT}"
DEFAULT_GATE_E_BINDING_PACKET_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_binding_packet.OUTPUT_RECEIPT}"
DEFAULT_GATE_E_BINDING_SCREEN_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_e_binding_screen.OUTPUT_RECEIPT}"
DEFAULT_GATE_F_REVIEW_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_f_review.OUTPUT_RECEIPT}"
DEFAULT_GATE_F_LIVE_PRODUCT_TRUTH_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{gate_f_live_product_truth.OUTPUT_RECEIPT}"
DEFAULT_POST_F_REAUDIT_RECEIPT_REL = f"KT_PROD_CLEANROOM/reports/{post_f_reaudit.OUTPUT_RECEIPT}"
DEFAULT_REPORTS_ROOT_REL = setup_tranche.DEFAULT_REPORTS_ROOT_REL

OUTPUT_BLOCKER_LEDGER = "cohort0_successor_full_readjudication_authorization_blocker_ledger.json"
OUTPUT_PREDICATE_BOARD = "cohort0_successor_master_predicate_board.json"
OUTPUT_PACKET = "cohort0_successor_master_orchestrator_packet.json"
OUTPUT_RECEIPT = "cohort0_successor_master_orchestrator_receipt.json"
OUTPUT_REPORT = "COHORT0_SUCCESSOR_MASTER_ORCHESTRATOR_REPORT.md"

EXECUTION_STATUS = "PASS__SUCCESSOR_MASTER_ORCHESTRATOR_BOUND_AND_EVALUATED"
CURRENT_POSTURE = "NARROW_SUCCESSOR_GATE_D_ADMISSIBILITY_CONFIRMED__LIMITED_REVIEW_ONLY"
AUTHORIZED_POSTURE = "FULL_SUCCESSOR_GATE_D_READJUDICATION_AUTHORIZED__STILL_NOT_GATE_D_REOPENED"
CLEARED_POSTURE = "GATE_D_CLEARED__SUCCESSOR_LINE__GATE_E_STILL_CLOSED"
GATE_E_OPEN_POSTURE = "GATE_E_OPEN__POST_SUCCESSOR_GATE_D_CLEAR"
READJUDICATED_NOT_CLEARED_POSTURE = "GATE_D_NOT_CLEARED__SUCCESSOR_LINE_READJUDICATED"
FULL_AUTHORIZATION_SCREEN_STATUS = "DEFERRED__INSUFFICIENT_EVIDENCE"
FULL_GATE_D_STATUS = "BLOCKED_PENDING_SUCCESSOR_FULL_GATE_D_READJUDICATION_AUTHORIZATION"
GATE_E_STATUS = "BLOCKED_PENDING_SUCCESSOR_GATE_D"
NEXT_LAWFUL_MOVE = (
    "EXECUTE_READY_SUCCESSOR_EVIDENCE_WAVES_IN_PARALLEL__SEVERITY_ANTI_SELECTION_THIRD_SURFACE"
)

PREDICATE_ANTI_SELECTION = "anti_selection_wave_beyond_reserve_executed"
PREDICATE_SEVERITY = "severity_escalation_route_consequence_wave_executed"
PREDICATE_THIRD_SURFACE = "third_surface_breadth_witness_executed"
PREDICATE_FULL_AUTH_SCREEN = "full_successor_gate_d_readjudication_authorization_screen_executed"


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


def _load_json_optional(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: optional JSON must be an object when present: {path.as_posix()}")
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: optional JSON must have status PASS when present: {path.as_posix()}")
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
        raise RuntimeError("FAIL_CLOSED: successor master orchestrator requires one same-head authority line")
    return next(iter(heads))


def _validate_inputs(
    *,
    verdict_packet: Dict[str, Any],
    reentry_block: Dict[str, Any],
    lane_a_receipt: Dict[str, Any],
    lane_a_scorecard: Dict[str, Any],
    lane_b_hydration_receipt: Dict[str, Any],
    lane_b_receipt: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    cross_lane_comparative_packet: Dict[str, Any],
    cross_lane_screen_packet: Dict[str, Any],
    cross_lane_screen_receipt: Dict[str, Any],
    prep_packet: Dict[str, Any],
    prep_receipt: Dict[str, Any],
    admissibility_screen_packet: Dict[str, Any],
    admissibility_screen_receipt: Dict[str, Any],
    narrow_review_packet: Dict[str, Any],
    narrow_review_receipt: Dict[str, Any],
) -> None:
    for payload, label in (
        (verdict_packet, "hardened ceiling verdict packet"),
        (reentry_block, "gate d reentry block contract"),
        (lane_a_receipt, "lane a receipt"),
        (lane_a_scorecard, "lane a scorecard"),
        (lane_b_hydration_receipt, "lane b hydration receipt"),
        (lane_b_receipt, "lane b family receipt"),
        (lane_b_scorecard, "lane b family scorecard"),
        (cross_lane_comparative_packet, "cross-lane comparative packet"),
        (cross_lane_screen_packet, "cross-lane reentry-prep screening packet"),
        (cross_lane_screen_receipt, "cross-lane reentry-prep screening receipt"),
        (prep_packet, "successor reentry-prep packet"),
        (prep_receipt, "successor reentry-prep receipt"),
        (admissibility_screen_packet, "successor admissibility screen packet"),
        (admissibility_screen_receipt, "successor admissibility screen receipt"),
        (narrow_review_packet, "narrow admissibility review packet"),
        (narrow_review_receipt, "narrow admissibility review receipt"),
    ):
        _ensure_pass(payload, label=label)

    if str(verdict_packet.get("final_verdict_id", "")).strip() != setup_tranche.EXPECTED_FINAL_VERDICT_ID:
        raise RuntimeError("FAIL_CLOSED: verdict packet final verdict mismatch")
    if not bool(verdict_packet.get("current_lane_closed", False)):
        raise RuntimeError("FAIL_CLOSED: current same-head lane must remain closed")
    if bool(verdict_packet.get("same_head_counted_reentry_admissible_now", True)):
        raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked")
    if str(reentry_block.get("reentry_status", "")).strip() != "BLOCKED__CURRENT_LANE_HARDENED_CEILING":
        raise RuntimeError("FAIL_CLOSED: reentry block must remain active")

    if str(lane_a_receipt.get("execution_status", "")).strip() != "PASS__LANE_A_PROMOTED_SURVIVOR_FULL_EXECUTION":
        raise RuntimeError("FAIL_CLOSED: Lane A benchmark evidence must exist")
    if str(lane_b_hydration_receipt.get("execution_status", "")).strip() != "PASS__LANE_B_STAGE_PACK_HYDRATION_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: Lane B hydration must exist")
    if not bool(lane_b_hydration_receipt.get("lane_b_case_execution_available_after_hydration", False)):
        raise RuntimeError("FAIL_CLOSED: Lane B case execution must remain available after hydration")
    if str(lane_b_receipt.get("execution_status", "")).strip() != "PASS__LANE_B_FAMILY_LEVEL_BRIDGE_HARNESS_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: Lane B family-level execution must exist")
    if str(cross_lane_comparative_packet.get("execution_status", "")).strip() != "PASS__CROSS_LANE_COMPARATIVE_PACKET_EMITTED":
        raise RuntimeError("FAIL_CLOSED: cross-lane comparative packet must exist")
    if str(cross_lane_screen_receipt.get("execution_status", "")).strip() != "PASS__CROSS_LANE_REENTRY_PREP_SCREEN_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: cross-lane reentry-prep screening must exist")
    if not bool(cross_lane_screen_receipt.get("successor_reentry_prep_packet_authorized", False)):
        raise RuntimeError("FAIL_CLOSED: successor reentry-prep must remain authorized")
    if str(prep_receipt.get("execution_status", "")).strip() != "PASS__SUCCESSOR_REENTRY_PREP_PACKET_AUTHORED":
        raise RuntimeError("FAIL_CLOSED: successor reentry-prep packet must exist")
    if str(admissibility_screen_receipt.get("execution_status", "")).strip() != "PASS__SUCCESSOR_GATE_D_REENTRY_ADMISSIBILITY_SCREEN_EXECUTED":
        raise RuntimeError("FAIL_CLOSED: successor admissibility screen must exist")
    if not bool(admissibility_screen_receipt.get("narrow_successor_gate_d_admissibility_review_authorized", False)):
        raise RuntimeError("FAIL_CLOSED: narrow admissibility review must remain authorized")
    if str(narrow_review_receipt.get("execution_status", "")).strip() != "PASS__SUCCESSOR_GATE_D_NARROW_ADMISSIBILITY_REVIEW_CONVENED":
        raise RuntimeError("FAIL_CLOSED: narrow admissibility review must exist")
    if not bool(narrow_review_receipt.get("narrow_successor_gate_d_admissibility_confirmed", False)):
        raise RuntimeError("FAIL_CLOSED: narrow admissibility must remain confirmed")

    if str(narrow_review_packet.get("review_outcome", "")).strip() != narrow_review.OUTCOME_CONFIRMED:
        raise RuntimeError("FAIL_CLOSED: narrow review outcome must remain limited-review confirmation")
    if bool(narrow_review_packet.get("full_successor_gate_d_readjudication_authorized_now", True)):
        raise RuntimeError("FAIL_CLOSED: full Gate D readjudication must not be authorized yet")
    if bool(admissibility_screen_packet.get("full_successor_gate_d_readjudication_authorized_now", True)):
        raise RuntimeError("FAIL_CLOSED: admissibility screen must not authorize full readjudication")

    comparative_read = dict(cross_lane_comparative_packet.get("comparative_read", {}))
    if not bool(comparative_read.get("lane_a_remains_numeric_benchmark_witness", False)):
        raise RuntimeError("FAIL_CLOSED: Lane A must remain numeric benchmark witness")
    if not bool(comparative_read.get("lane_b_now_executed_on_materially_distinct_family_surface", False)):
        raise RuntimeError("FAIL_CLOSED: Lane B must remain materially distinct executed family surface")

    for payload in (
        lane_a_receipt,
        lane_b_hydration_receipt,
        lane_b_receipt,
        cross_lane_screen_receipt,
        prep_receipt,
        admissibility_screen_receipt,
        narrow_review_receipt,
    ):
        if bool(payload.get("same_head_counted_reentry_admissible_now", True)):
            raise RuntimeError("FAIL_CLOSED: counted reentry must remain blocked")
        if bool(payload.get("gate_d_reopened", True)):
            raise RuntimeError("FAIL_CLOSED: Gate D must remain closed")
        if bool(payload.get("gate_e_open", True)):
            raise RuntimeError("FAIL_CLOSED: Gate E must remain closed")


def _ranked_missing_authorization_predicates(
    *,
    predicates: Dict[str, Any],
    anti_selection_receipt: Optional[Dict[str, Any]],
    full_auth_screen_receipt: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    rank = 1

    if not bool(predicates.get(PREDICATE_SEVERITY, False)):
        items.append(
            {
                "rank": rank,
                "predicate_id": PREDICATE_SEVERITY,
                "status": "MISSING",
                "why_it_matters": "Gate D is a route-consequence court, so harsher consequence durability remains the highest-value missing escalation proof.",
                "next_tranche": "EXECUTE_SUCCESSOR_ROUTE_CONSEQUENCE_SEVERITY_ESCALATION_WAVE__FIXED_HARNESS",
            }
        )
        rank += 1

    if not bool(predicates.get(PREDICATE_ANTI_SELECTION, False)):
        items.append(
            {
                "rank": rank,
                "predicate_id": PREDICATE_ANTI_SELECTION,
                "status": "MISSING",
                "why_it_matters": "Reserve challenges passed, but anti-selection durability beyond promoted survivors and reserves still has a bounded family-side depth defect.",
                "next_tranche": (
                    str(anti_selection_receipt.get("next_lawful_move", "")).strip()
                    if isinstance(anti_selection_receipt, dict)
                    else "EXECUTE_SUCCESSOR_ANTI_SELECTION_STRESS_WAVE__POST_NARROW_ADMISSIBILITY"
                ),
            }
        )
        rank += 1

    if not bool(predicates.get(PREDICATE_THIRD_SURFACE, False)):
        items.append(
            {
                "rank": rank,
                "predicate_id": PREDICATE_THIRD_SURFACE,
                "status": "MISSING",
                "why_it_matters": "A third clean breadth witness is not yet established beyond the current mutation lane and materially distinct family lane.",
                "next_tranche": "EXECUTE_SUCCESSOR_THIRD_SURFACE_BREADTH_WITNESS_WAVE",
            }
        )
        rank += 1

    if not bool(predicates.get(PREDICATE_FULL_AUTH_SCREEN, False)):
        items.append(
            {
                "rank": rank,
                "predicate_id": PREDICATE_FULL_AUTH_SCREEN,
                "status": "MISSING",
                "why_it_matters": "No full successor Gate D readjudication authorization screen has yet closed the post-limited-review escalation bundle.",
                "next_tranche": (
                    str(full_auth_screen_receipt.get("next_lawful_move", "")).strip()
                    if isinstance(full_auth_screen_receipt, dict)
                    else "EXECUTE_SUCCESSOR_FULL_GATE_D_READJUDICATION_AUTHORIZATION_SCREEN"
                ),
            }
        )

    return items


def _build_predicate_board(
    *,
    lane_a_scorecard: Dict[str, Any],
    lane_b_scorecard: Dict[str, Any],
    cross_lane_comparative_packet: Dict[str, Any],
    cross_lane_screen_receipt: Dict[str, Any],
    prep_receipt: Dict[str, Any],
    prep_packet: Dict[str, Any],
    admissibility_screen_packet: Dict[str, Any],
    admissibility_screen_receipt: Dict[str, Any],
    narrow_review_packet: Dict[str, Any],
    narrow_review_receipt: Dict[str, Any],
    severity_receipt: Optional[Dict[str, Any]],
    anti_selection_receipt: Optional[Dict[str, Any]],
    family_side_closure_receipt: Optional[Dict[str, Any]],
    third_surface_receipt: Optional[Dict[str, Any]],
    full_auth_screen_receipt: Optional[Dict[str, Any]],
    full_readjudication_receipt: Optional[Dict[str, Any]],
    gate_e_monitor_receipt: Optional[Dict[str, Any]],
    gate_e_scope_receipt: Optional[Dict[str, Any]],
    gate_e_audit_receipt: Optional[Dict[str, Any]],
    gate_e_screen_receipt: Optional[Dict[str, Any]],
    gate_e_binding_packet_receipt: Optional[Dict[str, Any]],
    gate_e_binding_screen_receipt: Optional[Dict[str, Any]],
    gate_f_review_receipt: Optional[Dict[str, Any]],
    gate_f_live_product_truth_receipt: Optional[Dict[str, Any]],
    post_f_reaudit_receipt: Optional[Dict[str, Any]],
    subject_head: str,
) -> Dict[str, Any]:
    comparative_read = dict(cross_lane_comparative_packet.get("comparative_read", {}))
    screen_findings = dict(admissibility_screen_packet.get("screen_findings", {}))
    narrow_findings = dict(narrow_review_packet.get("review_findings", {}))
    full_harness = dict(prep_packet.get("selected_successor_core", {}).get("fixed_harness_global_totals", {}))

    anti_selection_closed = bool(
        isinstance(anti_selection_receipt, dict)
        and anti_selection_receipt.get("anti_selection_wave_beyond_reserve_closed", False)
    ) or bool(
        isinstance(family_side_closure_receipt, dict)
        and family_side_closure_receipt.get("anti_selection_wave_beyond_reserve_closed", False)
    )
    same_head_counted_reentry_admissible_now = bool(
        isinstance(full_readjudication_receipt, dict)
        and full_readjudication_receipt.get("same_head_counted_reentry_admissible_now", False)
    )
    gate_d_reopened = bool(
        isinstance(full_readjudication_receipt, dict) and full_readjudication_receipt.get("gate_d_reopened", False)
    )
    gate_e_open = bool(
        gate_e_screen_receipt.get("gate_e_open", False)
        if isinstance(gate_e_screen_receipt, dict)
        else (
            gate_e_monitor_receipt.get("gate_e_open", False)
            if isinstance(gate_e_monitor_receipt, dict)
            else False
        )
    )
    gate_f_narrow_wedge_confirmed = bool(
        isinstance(gate_f_review_receipt, dict)
        and gate_f_review_receipt.get("gate_f_narrow_wedge_confirmed", False)
    )
    gate_f_open = bool(
        isinstance(gate_f_review_receipt, dict) and gate_f_review_receipt.get("gate_f_open", False)
    )
    gate_f_live_product_truth_frozen = bool(
        isinstance(gate_f_live_product_truth_receipt, dict)
        and str(gate_f_live_product_truth_receipt.get("current_product_posture", "")).strip()
        == gate_f_common.GATE_F_CONFIRMED_POSTURE
    )
    post_f_broad_canonical_reaudit_passed = bool(
        isinstance(post_f_reaudit_receipt, dict)
        and str(post_f_reaudit_receipt.get("reaudit_outcome", "")).strip() == post_f_reaudit.OUTCOME_PASS
    )
    predicates = {
        "same_head_counted_reentry_blocked": not same_head_counted_reentry_admissible_now,
        "gate_d_closed": not gate_d_reopened,
        "gate_e_open": gate_e_open,
        "gate_e_closed": not gate_e_open,
        "gate_f_narrow_wedge_confirmed": gate_f_narrow_wedge_confirmed,
        "gate_f_live_product_truth_frozen": gate_f_live_product_truth_frozen,
        "gate_f_open": gate_f_open,
        "post_f_broad_canonical_reaudit_passed": post_f_broad_canonical_reaudit_passed,
        "minimum_path_complete_through_gate_f": gate_f_narrow_wedge_confirmed and gate_f_live_product_truth_frozen,
        "lane_a_numeric_benchmark_executed": str(lane_a_scorecard.get("execution_status", "")).strip()
        == "PASS__LANE_A_PROMOTED_SURVIVOR_FULL_EXECUTION",
        "lane_b_payload_hydrated": True,
        "lane_b_materially_distinct_family_executed": bool(
            comparative_read.get("lane_b_now_executed_on_materially_distinct_family_surface", False)
        ),
        "cross_lane_comparative_packet_emitted": str(cross_lane_comparative_packet.get("execution_status", "")).strip()
        == "PASS__CROSS_LANE_COMPARATIVE_PACKET_EMITTED",
        "reserve_challenges_pass": bool(cross_lane_screen_receipt.get("reserve_challenges_pass", False)),
        "successor_reentry_prep_packet_authorized": bool(
            cross_lane_screen_receipt.get("successor_reentry_prep_packet_authorized", False)
        ),
        "successor_reentry_prep_packet_authored": bool(
            prep_receipt.get("successor_reentry_prep_packet_authored", False)
        ),
        "selected_bridge_cross_lane_hold": bool(screen_findings.get("selected_bridge_cross_lane_hold", False)),
        "route_consequence_cross_lane_nonzero": bool(
            screen_findings.get("route_consequence_cross_lane_nonzero", False)
        ),
        "dominance_broadening_visible": bool(screen_findings.get("dominance_broadening_visible", False)),
        "materially_distinct_family_lane_executed": bool(
            screen_findings.get("materially_distinct_family_lane_executed", False)
        ),
        "fixed_harness_stable": bool(screen_findings.get("fixed_harness_stable", False)),
        "narrow_admissibility_review_authorized": bool(
            admissibility_screen_receipt.get("narrow_successor_gate_d_admissibility_review_authorized", False)
        ),
        "narrow_admissibility_confirmed": bool(
            narrow_review_receipt.get("narrow_successor_gate_d_admissibility_confirmed", False)
        ),
        "limited_review_scope_only": str(narrow_review_packet.get("review_scope", "")).strip()
        == "NARROW_SUCCESSOR_GATE_D_ADMISSIBILITY_ONLY",
        "proof_bundle_complete_for_narrow_review": not bool(narrow_review_packet.get("bounded_defects_remaining", [])),
        "lead_bridge_locked": str(prep_packet.get("selected_successor_core", {}).get("lead_bridge_candidate_id", "")).strip()
        == cross_lane_comparative_packet.get("lane_a_benchmark", {}).get("execution_status", "").replace(
            "PASS__LANE_A_PROMOTED_SURVIVOR_FULL_EXECUTION", "RB_COUNTERFACTUAL_EVIDENCE_OBJECT_BRIDGE_V1"
        ),
        PREDICATE_ANTI_SELECTION: anti_selection_closed,
        "family_side_anti_selection_defect_closed": bool(
            isinstance(family_side_closure_receipt, dict)
            and family_side_closure_receipt.get("family_side_anti_selection_defect_closed", False)
        ),
        PREDICATE_SEVERITY: bool(
            isinstance(severity_receipt, dict)
            and severity_receipt.get("severity_escalation_route_consequence_wave_closed", False)
        ),
        PREDICATE_THIRD_SURFACE: bool(
            isinstance(third_surface_receipt, dict)
            and third_surface_receipt.get("third_surface_breadth_witness_closed", False)
        ),
        PREDICATE_FULL_AUTH_SCREEN: bool(
            isinstance(full_auth_screen_receipt, dict)
            and full_auth_screen_receipt.get("full_successor_gate_d_readjudication_authorization_screen_executed", False)
        ),
        "full_successor_gate_d_readjudication_authorized_now": bool(
            isinstance(full_auth_screen_receipt, dict)
            and full_auth_screen_receipt.get("full_successor_gate_d_readjudication_authorized_now", False)
        ),
        "successor_full_gate_d_readjudication_executed": bool(
            isinstance(full_readjudication_receipt, dict)
            and full_readjudication_receipt.get("execution_status", "") == full_readjudication.EXECUTION_STATUS
        ),
        "gate_d_reopened": gate_d_reopened,
        "same_head_counted_reentry_admissible_now": same_head_counted_reentry_admissible_now,
        "gate_e_precondition_monitor_executed": bool(
            isinstance(gate_e_monitor_receipt, dict)
            and gate_e_monitor_receipt.get("execution_status", "") == gate_e_monitor.EXECUTION_STATUS
        ),
        "gate_e_lawful_consideration_authorized_now": bool(
            isinstance(gate_e_monitor_receipt, dict)
            and gate_e_monitor_receipt.get("gate_e_lawful_consideration_authorized_now", False)
        ),
        "gate_e_admissibility_scope_packet_executed": bool(
            isinstance(gate_e_scope_receipt, dict)
            and gate_e_scope_receipt.get("execution_status", "") == gate_e_scope.EXECUTION_STATUS
        ),
        "gate_e_admissibility_screen_authorized_now": bool(
            isinstance(gate_e_scope_receipt, dict)
            and gate_e_scope_receipt.get("gate_e_admissibility_screen_authorized_now", False)
        ),
        "gate_e_post_clear_contradiction_audit_executed": bool(
            isinstance(gate_e_audit_receipt, dict)
            and gate_e_audit_receipt.get("execution_status", "") == gate_e_audit.EXECUTION_STATUS
        ),
        "gate_e_post_clear_live_authority_contradiction_free": bool(
            isinstance(gate_e_audit_receipt, dict)
            and gate_e_audit_receipt.get("post_clear_live_authority_contradiction_free", False)
        ),
        "gate_e_admissibility_screen_executed": bool(
            isinstance(gate_e_screen_receipt, dict)
            and gate_e_screen_receipt.get("execution_status", "") == gate_e_screen.EXECUTION_STATUS
        ),
        "gate_e_named_binding_defect_from_screen": bool(
            isinstance(gate_e_screen_receipt, dict)
            and gate_e_screen_receipt.get("named_bounded_defect_id", "")
            == gate_e_binding_packet.PREDICATE_GATE_E_BINDING
        ),
        "gate_e_comparator_governance_binding_packet_executed": bool(
            isinstance(gate_e_binding_packet_receipt, dict)
            and gate_e_binding_packet_receipt.get("execution_status", "") == gate_e_binding_packet.EXECUTION_STATUS
        ),
        gate_e_binding_packet.PREDICATE_GATE_E_BINDING: bool(
            isinstance(gate_e_binding_packet_receipt, dict)
            and gate_e_binding_packet_receipt.get(gate_e_binding_packet.PREDICATE_GATE_E_BINDING, False)
        ),
        "gate_e_comparator_governance_binding_screen_executed": bool(
            isinstance(gate_e_binding_screen_receipt, dict)
            and gate_e_binding_screen_receipt.get("execution_status", "") == gate_e_binding_screen.EXECUTION_STATUS
        ),
        "gate_e_binding_confirmed": bool(
            isinstance(gate_e_binding_screen_receipt, dict)
            and gate_e_binding_screen_receipt.get("gate_e_binding_confirmed", False)
        ),
    }
    predicates["lead_bridge_locked"] = (
        str(prep_packet.get("selected_successor_core", {}).get("lead_bridge_candidate_id", "")).strip()
        == "RB_COUNTERFACTUAL_EVIDENCE_OBJECT_BRIDGE_V1"
    )

    if gate_e_open:
        current_posture = GATE_E_OPEN_POSTURE
    elif bool(predicates.get("gate_d_reopened", False)):
        current_posture = CLEARED_POSTURE
    elif isinstance(full_readjudication_receipt, dict) and str(
        full_readjudication_receipt.get("readjudication_outcome", "")
    ).strip() == full_readjudication.OUTCOME_NOT_CLEARED:
        current_posture = READJUDICATED_NOT_CLEARED_POSTURE
    elif bool(predicates.get("full_successor_gate_d_readjudication_authorized_now", False)):
        current_posture = AUTHORIZED_POSTURE
    else:
        current_posture = CURRENT_POSTURE
    return {
        "schema_id": "kt.operator.cohort0_successor_master_predicate_board.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This board is a predicate engine for the successor DAG only. "
            "It does not by itself authorize counted reentry, reopen Gate D, or open Gate E, "
            "but it may reflect downstream lawful receipts that have already done so."
        ),
        "execution_status": EXECUTION_STATUS,
        "current_branch_posture": current_posture,
        "current_product_posture": (
            gate_f_common.GATE_F_CONFIRMED_POSTURE if gate_f_live_product_truth_frozen else ""
        ),
        "selected_successor_core": {
            "lead_bridge_candidate_id": prep_packet.get("selected_successor_core", {}).get("lead_bridge_candidate_id", ""),
            "secondary_bridge_candidate_id": prep_packet.get("selected_successor_core", {}).get(
                "secondary_bridge_candidate_id", ""
            ),
            "guardrail_bridge_candidate_id": prep_packet.get("selected_successor_core", {}).get(
                "guardrail_bridge_candidate_id", ""
            ),
            "fixed_harness_global_totals": full_harness,
        },
        "predicates": predicates,
        "review_findings": narrow_findings,
        "subject_head": subject_head,
    }


def _build_blocker_ledger(
    *,
    predicate_board: Dict[str, Any],
    narrow_review_packet: Dict[str, Any],
    anti_selection_receipt: Optional[Dict[str, Any]],
    full_auth_screen_receipt: Optional[Dict[str, Any]],
    full_readjudication_receipt: Optional[Dict[str, Any]],
    gate_e_monitor_receipt: Optional[Dict[str, Any]],
    gate_e_scope_receipt: Optional[Dict[str, Any]],
    gate_e_audit_receipt: Optional[Dict[str, Any]],
    gate_e_screen_receipt: Optional[Dict[str, Any]],
    gate_e_binding_packet_receipt: Optional[Dict[str, Any]],
    gate_e_binding_screen_receipt: Optional[Dict[str, Any]],
    gate_f_review_receipt: Optional[Dict[str, Any]],
    gate_f_live_product_truth_receipt: Optional[Dict[str, Any]],
    post_f_reaudit_receipt: Optional[Dict[str, Any]],
    source_refs: Dict[str, str],
    subject_head: str,
) -> Dict[str, Any]:
    predicates = dict(predicate_board.get("predicates", {}))
    missing = _ranked_missing_authorization_predicates(
        predicates=predicates,
        anti_selection_receipt=anti_selection_receipt,
        full_auth_screen_receipt=full_auth_screen_receipt,
    )
    if bool(predicates.get("gate_e_open", False)):
        current_scope = GATE_E_OPEN_POSTURE
    elif bool(predicates.get("gate_d_reopened", False)):
        current_scope = CLEARED_POSTURE
    elif isinstance(full_readjudication_receipt, dict) and str(
        full_readjudication_receipt.get("readjudication_outcome", "")
    ).strip() == full_readjudication.OUTCOME_NOT_CLEARED:
        current_scope = READJUDICATED_NOT_CLEARED_POSTURE
    elif bool(predicates.get("full_successor_gate_d_readjudication_authorized_now", False)):
        current_scope = AUTHORIZED_POSTURE
    else:
        current_scope = CURRENT_POSTURE
    full_auth_status = (
        str(full_auth_screen_receipt.get("full_successor_gate_d_readjudication_authorization_screen_status", "")).strip()
        if isinstance(full_auth_screen_receipt, dict)
        else FULL_AUTHORIZATION_SCREEN_STATUS
    )
    full_authorized = bool(predicates.get("full_successor_gate_d_readjudication_authorized_now", False))
    top_level_status = "CLEARED" if full_authorized else "ACTIVE"
    top_level_why_active = (
        (
            "Full successor Gate D readjudication has been executed and the authorization-stage blocker remains cleared."
            if isinstance(full_readjudication_receipt, dict)
            else "All full successor Gate D readjudication authorization predicates are now satisfied."
        )
        if full_authorized
        else (
            "The full authorization screen has executed and still returns a bounded anti-selection defect."
            if isinstance(full_auth_screen_receipt, dict)
            else (
                "The current authority line confirms limited-review posture only. "
                "The narrow review has no bounded defects within its own scope, but the escalation-specific predicates "
                "required beyond narrow admissibility are still unproven."
            )
        )
    )
    return {
        "schema_id": "kt.operator.cohort0_successor_full_readjudication_authorization_blocker_ledger.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This ledger explains the state of full successor Gate D readjudication authorization and any remaining blockers. "
            "It does not by itself open Gate E, even when downstream lawful receipts have already cleared Gate D "
            "or lawfully advanced Gate E scope-setting."
        ),
        "execution_status": EXECUTION_STATUS,
        "current_authority_scope": current_scope,
        "top_level_blocker": {
            "blocker_id": "FULL_SUCCESSOR_GATE_D_READJUDICATION_AUTHORIZATION_NOT_EARNED",
            "status": top_level_status,
            "why_active": top_level_why_active,
        },
        "narrow_review_scope_result": {
            "review_outcome": narrow_review_packet.get("review_outcome", ""),
            "bounded_defects_remaining": list(narrow_review_packet.get("bounded_defects_remaining", [])),
            "full_successor_gate_d_readjudication_authorized_now": bool(
                predicates.get("full_successor_gate_d_readjudication_authorized_now", False)
            ),
        },
        "full_authorization_screen_status": full_auth_status,
        "ranked_missing_authorization_predicates": missing,
        "currently_satisfied_authorization_support": [
            key
            for key in (
                "lane_a_numeric_benchmark_executed",
                "lane_b_materially_distinct_family_executed",
                "reserve_challenges_pass",
                "selected_bridge_cross_lane_hold",
                "route_consequence_cross_lane_nonzero",
                "dominance_broadening_visible",
                "fixed_harness_stable",
                "narrow_admissibility_confirmed",
                PREDICATE_SEVERITY,
                PREDICATE_THIRD_SURFACE,
                PREDICATE_FULL_AUTH_SCREEN,
            )
            if bool(predicates.get(key, False))
        ],
        "next_parallel_evidence_nodes_ready_now": [
            item["next_tranche"]
            for item in missing
            if item["predicate_id"] in (PREDICATE_SEVERITY, PREDICATE_ANTI_SELECTION, PREDICATE_THIRD_SURFACE)
        ],
        "next_gated_court_after_closure": (
            str(gate_e_screen_receipt.get("next_lawful_move", "")).strip()
            if isinstance(gate_e_screen_receipt, dict) and bool(gate_e_screen_receipt.get("gate_e_open", False))
            else (
            str(gate_e_monitor_receipt.get("next_lawful_move", "")).strip()
            if isinstance(gate_e_monitor_receipt, dict)
            else (
                str(full_readjudication_receipt.get("next_lawful_move", "")).strip()
                if isinstance(full_readjudication_receipt, dict)
                else (
                    str(full_auth_screen_receipt.get("next_lawful_move", "")).strip()
                    if isinstance(full_auth_screen_receipt, dict)
                    else "EXECUTE_SUCCESSOR_FULL_GATE_D_READJUDICATION_AUTHORIZATION_SCREEN"
                )
            )
            )
        ),
        "source_refs": source_refs,
        "subject_head": subject_head,
    }


def _node(
    *,
    node_id: str,
    node_type: str,
    dependencies: Sequence[str],
    status: str,
    receipt_ref: str = "",
    missing_predicates: Optional[Sequence[str]] = None,
    next_tranche: str = "",
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "node_id": node_id,
        "node_type": node_type,
        "dependencies": list(dependencies),
        "status": status,
    }
    if receipt_ref:
        payload["receipt_ref"] = receipt_ref
    if missing_predicates:
        payload["missing_predicates"] = list(missing_predicates)
    if next_tranche:
        payload["next_tranche"] = next_tranche
    return payload


def _evidence_node_status(*, predicate_closed: bool, receipt_present: bool) -> str:
    if predicate_closed:
        return "SATISFIED__PASS"
    if receipt_present:
        return "EXECUTED__BOUNDED_DEFECT_REMAINS"
    return "READY__NOT_EXECUTED"


def _gate_e_monitor_node_status(*, predicates: Dict[str, Any], gate_e_monitor_receipt: Optional[Dict[str, Any]]) -> str:
    if isinstance(gate_e_monitor_receipt, dict):
        if bool(gate_e_monitor_receipt.get("gate_e_lawful_consideration_authorized_now", False)):
            return "SATISFIED__POST_SUCCESSOR_GATE_D_CLEAR__STILL_GATE_E_CLOSED"
        return "EXECUTED__PRECONDITION_DEFECT_IDENTIFIED"
    if bool(predicates.get("gate_d_reopened", False)):
        return "AUTHORIZED__POST_SUCCESSOR_GATE_D_CLEAR"
    return GATE_E_STATUS


def _gate_e_scope_node_status(*, predicates: Dict[str, Any], gate_e_scope_receipt: Optional[Dict[str, Any]]) -> str:
    if isinstance(gate_e_scope_receipt, dict):
        if bool(gate_e_scope_receipt.get("gate_e_admissibility_screen_authorized_now", False)):
            return "SATISFIED__GATE_E_ADMISSIBILITY_SCREEN_AUTHORIZED__STILL_NOT_OPEN"
        return "EXECUTED__DEFERRED__GATE_E_SCOPE_PREDICATES_MISSING"
    if bool(predicates.get("gate_e_lawful_consideration_authorized_now", False)):
        return "AUTHORIZED__POST_MONITOR__SCOPE_PACKET_MAY_BE_AUTHORED"
    return "BLOCKED_PENDING_GATE_E_PRECONDITION_MONITOR"


def _gate_e_audit_node_status(*, predicates: Dict[str, Any], gate_e_audit_receipt: Optional[Dict[str, Any]]) -> str:
    if isinstance(gate_e_audit_receipt, dict):
        if bool(gate_e_audit_receipt.get("post_clear_live_authority_contradiction_free", False)):
            return "SATISFIED__NO_LIVE_AUTHORITY_CONTRADICTION"
        return "EXECUTED__CONTRADICTION_DETECTED"
    if bool(predicates.get("gate_e_admissibility_scope_packet_executed", False)):
        return "READY__NOT_EXECUTED"
    return "BLOCKED_PENDING_GATE_E_SCOPE_PACKET"


def _gate_e_screen_node_status(*, predicates: Dict[str, Any], gate_e_screen_receipt: Optional[Dict[str, Any]]) -> str:
    if isinstance(gate_e_screen_receipt, dict):
        if bool(gate_e_screen_receipt.get("gate_e_open", False)):
            return "SATISFIED__GATE_E_OPEN__SUCCESSOR_LINE"
        if str(gate_e_screen_receipt.get("screen_outcome", "")).strip() == gate_e_screen.OUTCOME_BOUNDED_DEFECT:
            return "EXECUTED__BOUNDED_DEFECT_IDENTIFIED"
        return "DEFERRED__MISSING_GATE_E_SCOPE_PREDICATES"
    if bool(predicates.get("gate_e_admissibility_screen_authorized_now", False)) and bool(
        predicates.get("gate_e_post_clear_live_authority_contradiction_free", False)
    ):
        return "AUTHORIZED__GATE_E_SCREEN_MAY_BE_CONVENED"
    if bool(predicates.get("gate_e_admissibility_screen_authorized_now", False)):
        return "BLOCKED_PENDING_GATE_E_POST_CLEAR_CONTRADICTION_AUDIT"
    return "BLOCKED_PENDING_GATE_E_SCOPE_PACKET"


def _gate_e_binding_packet_node_status(
    *, predicates: Dict[str, Any], gate_e_binding_packet_receipt: Optional[Dict[str, Any]]
) -> str:
    if isinstance(gate_e_binding_packet_receipt, dict):
        if bool(gate_e_binding_packet_receipt.get(gate_e_binding_packet.PREDICATE_GATE_E_BINDING, False)):
            return "SATISFIED__GATE_E_BINDING_PACKET_BOUND__STILL_NOT_OPEN"
        return "EXECUTED__GATE_E_BINDING_PACKET_INCOMPLETE"
    if bool(predicates.get("gate_e_named_binding_defect_from_screen", False)):
        return "AUTHORIZED__GATE_E_BINDING_PACKET_MAY_BE_AUTHORED"
    return "BLOCKED_PENDING_GATE_E_SCREEN_DEFECT_IDENTIFICATION"


def _gate_e_binding_screen_node_status(
    *, predicates: Dict[str, Any], gate_e_binding_screen_receipt: Optional[Dict[str, Any]]
) -> str:
    if isinstance(gate_e_binding_screen_receipt, dict):
        if bool(gate_e_binding_screen_receipt.get("gate_e_binding_confirmed", False)):
            return "SATISFIED__GATE_E_BINDING_CONFIRMED__ADMISSIBILITY_REVIEW_MAY_BE_CONVENED"
        if str(gate_e_binding_screen_receipt.get("binding_outcome", "")).strip() == gate_e_binding_screen.OUTCOME_INCOMPLETE:
            return "EXECUTED__GATE_E_BINDING_INCOMPLETE__BOUNDED_DEFECT_REMAINS"
        return "DEFERRED__SPECIFIC_BINDING_PREDICATE_MISSING"
    if bool(predicates.get(gate_e_binding_packet.PREDICATE_GATE_E_BINDING, False)):
        return "AUTHORIZED__GATE_E_BINDING_SCREEN_MAY_BE_CONVENED"
    return "BLOCKED_PENDING_GATE_E_BINDING_PACKET"


def _build_packet(
    *,
    blocker_ledger: Dict[str, Any],
    predicate_board: Dict[str, Any],
    severity_receipt: Optional[Dict[str, Any]],
    anti_selection_receipt: Optional[Dict[str, Any]],
    family_side_closure_receipt: Optional[Dict[str, Any]],
    third_surface_receipt: Optional[Dict[str, Any]],
    full_auth_screen_receipt: Optional[Dict[str, Any]],
    full_readjudication_receipt: Optional[Dict[str, Any]],
    gate_e_monitor_receipt: Optional[Dict[str, Any]],
    gate_e_scope_receipt: Optional[Dict[str, Any]],
    gate_e_audit_receipt: Optional[Dict[str, Any]],
    gate_e_screen_receipt: Optional[Dict[str, Any]],
    gate_e_binding_packet_receipt: Optional[Dict[str, Any]],
    gate_e_binding_screen_receipt: Optional[Dict[str, Any]],
    gate_f_review_receipt: Optional[Dict[str, Any]],
    gate_f_live_product_truth_receipt: Optional[Dict[str, Any]],
    post_f_reaudit_receipt: Optional[Dict[str, Any]],
    source_refs: Dict[str, str],
    subject_head: str,
) -> Dict[str, Any]:
    predicates = dict(predicate_board.get("predicates", {}))
    severity_receipt_ref = source_refs.get("severity_receipt_ref", "")
    anti_selection_receipt_ref = source_refs.get("anti_selection_receipt_ref", "")
    family_side_closure_receipt_ref = source_refs.get("family_side_closure_receipt_ref", "")
    third_surface_receipt_ref = source_refs.get("third_surface_receipt_ref", "")
    full_auth_screen_receipt_ref = source_refs.get("full_auth_screen_receipt_ref", "")
    gate_e_monitor_receipt_ref = source_refs.get("gate_e_monitor_receipt_ref", "")
    gate_e_scope_receipt_ref = source_refs.get("gate_e_scope_receipt_ref", "")
    gate_e_audit_receipt_ref = source_refs.get("gate_e_audit_receipt_ref", "")
    gate_e_screen_receipt_ref = source_refs.get("gate_e_screen_receipt_ref", "")
    gate_e_binding_packet_receipt_ref = source_refs.get("gate_e_binding_packet_receipt_ref", "")
    gate_e_binding_screen_receipt_ref = source_refs.get("gate_e_binding_screen_receipt_ref", "")
    gate_f_review_receipt_ref = source_refs.get("gate_f_review_receipt_ref", "")
    gate_f_live_product_truth_receipt_ref = source_refs.get("gate_f_live_product_truth_receipt_ref", "")
    post_f_reaudit_receipt_ref = source_refs.get("post_f_reaudit_receipt_ref", "")
    full_auth_screen_status = (
        str(full_auth_screen_receipt.get("full_successor_gate_d_readjudication_authorization_screen_status", "")).strip()
        if isinstance(full_auth_screen_receipt, dict)
        else FULL_AUTHORIZATION_SCREEN_STATUS
    )
    full_auth_screen_missing = (
        list(full_auth_screen_receipt.get("remaining_authorization_predicates", []))
        if isinstance(full_auth_screen_receipt, dict)
        else [item.get("predicate_id", "") for item in blocker_ledger.get("ranked_missing_authorization_predicates", [])]
    )
    if bool(predicates.get("gate_e_open", False)):
        current_posture = GATE_E_OPEN_POSTURE
    elif bool(predicates.get("gate_d_reopened", False)):
        current_posture = CLEARED_POSTURE
    elif isinstance(full_readjudication_receipt, dict) and str(
        full_readjudication_receipt.get("readjudication_outcome", "")
    ).strip() == full_readjudication.OUTCOME_NOT_CLEARED:
        current_posture = READJUDICATED_NOT_CLEARED_POSTURE
    elif bool(predicates.get("full_successor_gate_d_readjudication_authorized_now", False)):
        current_posture = AUTHORIZED_POSTURE
    else:
        current_posture = CURRENT_POSTURE
    evidence_nodes = [
        _node(
            node_id="lane_a_promoted_survivor_execution",
            node_type="evidence",
            dependencies=[],
            status="SATISFIED__PASS",
            receipt_ref=source_refs["lane_a_receipt_ref"],
        ),
        _node(
            node_id="lane_b_stage_pack_hydration",
            node_type="evidence",
            dependencies=[],
            status="SATISFIED__PASS",
            receipt_ref=source_refs["lane_b_hydration_receipt_ref"],
        ),
        _node(
            node_id="lane_b_family_level_bridge_harness_execution",
            node_type="evidence",
            dependencies=["lane_b_stage_pack_hydration", "lane_a_promoted_survivor_execution"],
            status="SATISFIED__PASS",
            receipt_ref=source_refs["lane_b_receipt_ref"],
        ),
        _node(
            node_id="successor_route_consequence_severity_escalation_wave",
            node_type="evidence",
            dependencies=["successor_gate_d_narrow_admissibility_review"],
            status=_evidence_node_status(
                predicate_closed=bool(predicates.get(PREDICATE_SEVERITY, False)),
                receipt_present=isinstance(severity_receipt, dict),
            ),
            receipt_ref=severity_receipt_ref,
            missing_predicates=[] if bool(predicates.get(PREDICATE_SEVERITY, False)) else [PREDICATE_SEVERITY],
            next_tranche="EXECUTE_SUCCESSOR_ROUTE_CONSEQUENCE_SEVERITY_ESCALATION_WAVE__FIXED_HARNESS",
        ),
        _node(
            node_id="successor_anti_selection_stress_wave",
            node_type="evidence",
            dependencies=["successor_gate_d_narrow_admissibility_review"],
            status=_evidence_node_status(
                predicate_closed=bool(predicates.get(PREDICATE_ANTI_SELECTION, False)),
                receipt_present=isinstance(family_side_closure_receipt, dict) or isinstance(anti_selection_receipt, dict),
            ),
            receipt_ref=family_side_closure_receipt_ref or anti_selection_receipt_ref,
            missing_predicates=[] if bool(predicates.get(PREDICATE_ANTI_SELECTION, False)) else [PREDICATE_ANTI_SELECTION],
            next_tranche=(
                str(family_side_closure_receipt.get("next_lawful_move", "")).strip()
                if isinstance(family_side_closure_receipt, dict)
                else (
                    str(anti_selection_receipt.get("next_lawful_move", "")).strip()
                    if isinstance(anti_selection_receipt, dict)
                    else "EXECUTE_SUCCESSOR_ANTI_SELECTION_STRESS_WAVE__POST_NARROW_ADMISSIBILITY"
                )
            ),
        ),
        _node(
            node_id="successor_family_side_anti_selection_closure_wave",
            node_type="evidence",
            dependencies=["successor_anti_selection_stress_wave"],
            status=(
                "SATISFIED__PASS"
                if bool(
                    isinstance(family_side_closure_receipt, dict)
                    and family_side_closure_receipt.get("anti_selection_wave_beyond_reserve_closed", False)
                )
                else (
                    "EXECUTED__BOUNDED_DEFECT_REMAINS"
                    if isinstance(family_side_closure_receipt, dict)
                    else "READY__NOT_EXECUTED"
                )
            ),
            receipt_ref=family_side_closure_receipt_ref,
            missing_predicates=[] if bool(predicates.get(PREDICATE_ANTI_SELECTION, False)) else [PREDICATE_ANTI_SELECTION],
            next_tranche=(
                str(family_side_closure_receipt.get("next_lawful_move", "")).strip()
                if isinstance(family_side_closure_receipt, dict)
                else "EXECUTE_SUCCESSOR_FAMILY_SIDE_ANTI_SELECTION_CLOSURE_WAVE"
            ),
        ),
        _node(
            node_id="successor_third_surface_breadth_witness_wave",
            node_type="evidence",
            dependencies=["successor_gate_d_narrow_admissibility_review"],
            status=_evidence_node_status(
                predicate_closed=bool(predicates.get(PREDICATE_THIRD_SURFACE, False)),
                receipt_present=isinstance(third_surface_receipt, dict),
            ),
            receipt_ref=third_surface_receipt_ref,
            missing_predicates=[] if bool(predicates.get(PREDICATE_THIRD_SURFACE, False)) else [PREDICATE_THIRD_SURFACE],
            next_tranche="EXECUTE_SUCCESSOR_THIRD_SURFACE_BREADTH_WITNESS_WAVE",
        ),
        _node(
            node_id="gate_e_post_clear_contradiction_audit",
            node_type="evidence",
            dependencies=["gate_e_admissibility_scope_packet"],
            status=_gate_e_audit_node_status(
                predicates=predicates,
                gate_e_audit_receipt=gate_e_audit_receipt,
            ),
            receipt_ref=gate_e_audit_receipt_ref,
            missing_predicates=(
                []
                if isinstance(gate_e_audit_receipt, dict)
                or bool(predicates.get("gate_e_admissibility_scope_packet_executed", False))
                else ["gate_e_admissibility_scope_packet_executed"]
            ),
            next_tranche=(
                str(gate_e_audit_receipt.get("next_lawful_move", "")).strip()
                if isinstance(gate_e_audit_receipt, dict)
                else gate_e_scope.NEXT_LAWFUL_MOVE
            ),
        ),
    ]
    claim_nodes = [
        _node(
            node_id="cross_lane_reentry_prep_screening",
            node_type="court",
            dependencies=["lane_a_promoted_survivor_execution", "lane_b_family_level_bridge_harness_execution"],
            status="AUTHORIZED__SATISFIED_AND_ALREADY_EMITTED",
            receipt_ref=source_refs["cross_lane_screen_receipt_ref"],
        ),
        _node(
            node_id="successor_reentry_prep_packet",
            node_type="court",
            dependencies=["cross_lane_reentry_prep_screening"],
            status="AUTHORIZED__SATISFIED_AND_ALREADY_EMITTED",
            receipt_ref=source_refs["prep_receipt_ref"],
        ),
        _node(
            node_id="successor_gate_d_reentry_admissibility_screen",
            node_type="court",
            dependencies=["successor_reentry_prep_packet"],
            status="AUTHORIZED__SATISFIED_AND_ALREADY_EMITTED",
            receipt_ref=source_refs["admissibility_screen_receipt_ref"],
        ),
        _node(
            node_id="successor_gate_d_narrow_admissibility_review",
            node_type="court",
            dependencies=["successor_gate_d_reentry_admissibility_screen"],
            status="AUTHORIZED__SATISFIED_AND_ALREADY_EMITTED",
            receipt_ref=source_refs["narrow_review_receipt_ref"],
        ),
        _node(
            node_id="successor_full_gate_d_readjudication_authorization_screen",
            node_type="court",
            dependencies=[
                "successor_route_consequence_severity_escalation_wave",
                "successor_anti_selection_stress_wave",
                "successor_third_surface_breadth_witness_wave",
            ],
            status=full_auth_screen_status,
            receipt_ref=full_auth_screen_receipt_ref,
            missing_predicates=full_auth_screen_missing,
            next_tranche=(
                str(full_auth_screen_receipt.get("next_lawful_move", "")).strip()
                if isinstance(full_auth_screen_receipt, dict)
                else "EXECUTE_SUCCESSOR_FULL_GATE_D_READJUDICATION_AUTHORIZATION_SCREEN"
            ),
        ),
        _node(
            node_id="successor_full_gate_d_readjudication",
            node_type="constitutional_court",
            dependencies=["successor_full_gate_d_readjudication_authorization_screen"],
            status=(
                "SATISFIED__GATE_D_CLEARED__SUCCESSOR_LINE"
                if isinstance(full_readjudication_receipt, dict)
                and bool(full_readjudication_receipt.get("gate_d_officially_cleared", False))
                else (
                    "SATISFIED__GATE_D_NOT_CLEARED__SUCCESSOR_LINE_READJUDICATED"
                    if isinstance(full_readjudication_receipt, dict)
                    and str(full_readjudication_receipt.get("readjudication_outcome", "")).strip()
                    == full_readjudication.OUTCOME_NOT_CLEARED
                    else (
                        "EXECUTED__DEFERRED__COURT_DEFECT_IDENTIFIED"
                        if isinstance(full_readjudication_receipt, dict)
                        else (
                            "AUTHORIZED__FULL_SUCCESSOR_GATE_D_READJUDICATION_MAY_BE_CONVENED"
                            if bool(predicates.get("full_successor_gate_d_readjudication_authorized_now", False))
                            else FULL_GATE_D_STATUS
                        )
                    )
                )
            ),
            receipt_ref=source_refs.get("full_readjudication_receipt_ref", ""),
            missing_predicates=(
                []
                if isinstance(full_readjudication_receipt, dict)
                or bool(predicates.get("full_successor_gate_d_readjudication_authorized_now", False))
                else ["full_successor_gate_d_readjudication_authorized_now"]
            ),
        ),
        _node(
            node_id="gate_e_precondition_monitor",
            node_type="constitutional_court",
            dependencies=["successor_full_gate_d_readjudication"],
            status=_gate_e_monitor_node_status(
                predicates=predicates,
                gate_e_monitor_receipt=gate_e_monitor_receipt,
            ),
            receipt_ref=gate_e_monitor_receipt_ref,
            missing_predicates=(
                []
                if isinstance(gate_e_monitor_receipt, dict) or bool(predicates.get("gate_d_reopened", False))
                else ["gate_d_reopened"]
            ),
            next_tranche=(
                str(gate_e_monitor_receipt.get("next_lawful_move", "")).strip()
                if isinstance(gate_e_monitor_receipt, dict)
                else gate_e_monitor.NEXT_LAWFUL_MOVE
            ),
        ),
        _node(
            node_id="gate_e_admissibility_scope_packet",
            node_type="constitutional_court",
            dependencies=["gate_e_precondition_monitor"],
            status=_gate_e_scope_node_status(
                predicates=predicates,
                gate_e_scope_receipt=gate_e_scope_receipt,
            ),
            receipt_ref=gate_e_scope_receipt_ref,
            missing_predicates=(
                []
                if isinstance(gate_e_scope_receipt, dict) or bool(predicates.get("gate_e_lawful_consideration_authorized_now", False))
                else ["gate_e_lawful_consideration_authorized_now"]
            ),
            next_tranche=(
                str(gate_e_scope_receipt.get("next_lawful_move", "")).strip()
                if isinstance(gate_e_scope_receipt, dict)
                else gate_e_scope.NEXT_LAWFUL_MOVE
            ),
        ),
        _node(
            node_id="gate_e_admissibility_screen",
            node_type="constitutional_court",
            dependencies=["gate_e_admissibility_scope_packet", "gate_e_post_clear_contradiction_audit"],
            status=_gate_e_screen_node_status(
                predicates=predicates,
                gate_e_screen_receipt=gate_e_screen_receipt,
            ),
            receipt_ref=gate_e_screen_receipt_ref,
            missing_predicates=(
                []
                if isinstance(gate_e_screen_receipt, dict)
                else (
                    ["gate_e_post_clear_live_authority_contradiction_free"]
                    if bool(predicates.get("gate_e_admissibility_screen_authorized_now", False))
                    and not bool(predicates.get("gate_e_post_clear_live_authority_contradiction_free", False))
                    else (
                        []
                        if bool(predicates.get("gate_e_admissibility_screen_authorized_now", False))
                        else ["gate_e_admissibility_scope_packet_executed"]
                    )
                )
            ),
            next_tranche=(
                (
                    str(gate_e_binding_screen_receipt.get("next_lawful_move", "")).strip()
                    if isinstance(gate_e_binding_screen_receipt, dict)
                    else (
                        str(gate_e_binding_packet_receipt.get("next_lawful_move", "")).strip()
                        if isinstance(gate_e_binding_packet_receipt, dict)
                        else (
                            str(gate_e_screen_receipt.get("next_lawful_move", "")).strip()
                            if isinstance(gate_e_screen_receipt, dict)
                            else gate_e_scope.NEXT_LAWFUL_MOVE
                        )
                    )
                )
            ),
        ),
        _node(
            node_id="gate_e_comparator_governance_binding_packet",
            node_type="constitutional_court",
            dependencies=["gate_e_admissibility_screen"],
            status=_gate_e_binding_packet_node_status(
                predicates=predicates,
                gate_e_binding_packet_receipt=gate_e_binding_packet_receipt,
            ),
            receipt_ref=gate_e_binding_packet_receipt_ref,
            missing_predicates=(
                []
                if isinstance(gate_e_binding_packet_receipt, dict)
                or bool(predicates.get("gate_e_named_binding_defect_from_screen", False))
                else ["gate_e_named_binding_defect_from_screen"]
            ),
            next_tranche=(
                str(gate_e_binding_packet_receipt.get("next_lawful_move", "")).strip()
                if isinstance(gate_e_binding_packet_receipt, dict)
                else "AUTHOR_GATE_E_COMPARATOR_GOVERNANCE_BINDING_PACKET__POST_GATE_E_SCREEN"
            ),
        ),
        _node(
            node_id="gate_e_comparator_governance_binding_screen",
            node_type="constitutional_court",
            dependencies=["gate_e_comparator_governance_binding_packet", "gate_e_post_clear_contradiction_audit"],
            status=_gate_e_binding_screen_node_status(
                predicates=predicates,
                gate_e_binding_screen_receipt=gate_e_binding_screen_receipt,
            ),
            receipt_ref=gate_e_binding_screen_receipt_ref,
            missing_predicates=(
                []
                if isinstance(gate_e_binding_screen_receipt, dict)
                or bool(predicates.get(gate_e_binding_packet.PREDICATE_GATE_E_BINDING, False))
                else [gate_e_binding_packet.PREDICATE_GATE_E_BINDING]
            ),
            next_tranche=(
                str(gate_e_binding_screen_receipt.get("next_lawful_move", "")).strip()
                if isinstance(gate_e_binding_screen_receipt, dict)
                else gate_e_binding_packet.NEXT_LAWFUL_MOVE
            ),
        ),
        _node(
            node_id="gate_f_one_narrow_wedge_review",
            node_type="product_court",
            dependencies=["gate_e_admissibility_screen"],
            status=(
                "SATISFIED__GATE_F_ONE_NARROW_WEDGE_CONFIRMED"
                if bool(predicates.get("gate_f_narrow_wedge_confirmed", False))
                else (
                    "EXECUTED__GATE_F_NARROW_WEDGE_NOT_CONFIRMED"
                    if isinstance(gate_f_review_receipt, dict)
                    else (
                        "AUTHORIZED__GATE_F_NARROW_WEDGE_REVIEW_MAY_BE_CONVENED"
                        if bool(predicates.get("gate_e_open", False))
                        else "BLOCKED_PENDING_GATE_E_OPEN"
                    )
                )
            ),
            receipt_ref=gate_f_review_receipt_ref,
            missing_predicates=[] if bool(predicates.get("gate_e_open", False)) else ["gate_e_open"],
            next_tranche=(
                gate_f_common.NEXT_MOVE_FREEZE_LIVE_PRODUCT_TRUTH
                if bool(predicates.get("gate_f_narrow_wedge_confirmed", False))
                else "CONVENE_GATE_F_ONE_NARROW_WEDGE_REVIEW"
            ),
        ),
        _node(
            node_id="gate_f_post_close_live_product_truth",
            node_type="product_court",
            dependencies=["gate_f_one_narrow_wedge_review"],
            status=(
                "SATISFIED__GATE_F_LIVE_PRODUCT_TRUTH_FROZEN"
                if bool(predicates.get("gate_f_live_product_truth_frozen", False))
                else (
                    "AUTHORIZED__GATE_F_LIVE_PRODUCT_TRUTH_MAY_BE_FROZEN"
                    if bool(predicates.get("gate_f_narrow_wedge_confirmed", False))
                    else "BLOCKED_PENDING_GATE_F_ONE_NARROW_WEDGE_CONFIRMATION"
                )
            ),
            receipt_ref=gate_f_live_product_truth_receipt_ref,
            missing_predicates=(
                []
                if bool(predicates.get("gate_f_narrow_wedge_confirmed", False))
                else ["gate_f_narrow_wedge_confirmed"]
            ),
            next_tranche=(
                str(gate_f_live_product_truth_receipt.get("next_lawful_move", "")).strip()
                if isinstance(gate_f_live_product_truth_receipt, dict)
                    else gate_f_common.NEXT_MOVE_FREEZE_LIVE_PRODUCT_TRUTH
            ),
        ),
        _node(
            node_id="post_f_broad_canonical_reaudit",
            node_type="constitutional_court",
            dependencies=["gate_f_post_close_live_product_truth"],
            status=(
                "SATISFIED__POST_F_BROAD_CANONICAL_REAUDIT_PASS"
                if bool(predicates.get("post_f_broad_canonical_reaudit_passed", False))
                else (
                    "AUTHORIZED__POST_F_BROAD_CANONICAL_REAUDIT_MAY_BE_CONVENED"
                    if bool(predicates.get("gate_f_live_product_truth_frozen", False))
                    else "BLOCKED_PENDING_GATE_F_LIVE_PRODUCT_TRUTH_FREEZE"
                )
            ),
            receipt_ref=post_f_reaudit_receipt_ref,
            missing_predicates=(
                []
                if bool(predicates.get("gate_f_live_product_truth_frozen", False))
                else ["gate_f_live_product_truth_frozen"]
            ),
            next_tranche=(
                str(post_f_reaudit_receipt.get("next_lawful_move", "")).strip()
                if isinstance(post_f_reaudit_receipt, dict)
                else gate_f_common.NEXT_MOVE_POST_F_REAUDIT
            ),
        ),
    ]
    current_product_posture = (
        gate_f_common.GATE_F_CONFIRMED_POSTURE
        if bool(predicates.get("gate_f_live_product_truth_frozen", False))
        else ""
    )
    return {
        "schema_id": "kt.operator.cohort0_successor_master_orchestrator_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This master orchestrator runs the successor line as a DAG: evidence nodes may run wide, "
            "but claim-bearing courts remain predicate-gated and may only emit bounded lawful receipts. "
            "It does not by itself authorize counted reentry, reopen Gate D, or open Gate E, "
            "but it may reflect downstream lawful receipts that have already done so."
        ),
        "execution_status": EXECUTION_STATUS,
        "current_branch_posture": current_posture,
        "current_product_posture": current_product_posture,
        "dag_mode": "PARALLEL_EVIDENCE__GATED_COURTS__HARD_PREDICATES",
        "evidence_nodes": evidence_nodes,
        "claim_nodes": claim_nodes,
        "predicate_board_ref": source_refs["predicate_board_ref"],
        "blocker_ledger_ref": source_refs["blocker_ledger_ref"],
        "ready_parallel_evidence_nodes": blocker_ledger.get("next_parallel_evidence_nodes_ready_now", []),
        "next_lawful_move": (
            str(post_f_reaudit_receipt.get("next_lawful_move", "")).strip()
            if isinstance(post_f_reaudit_receipt, dict)
            and str(post_f_reaudit_receipt.get("reaudit_outcome", "")).strip() == post_f_reaudit.OUTCOME_PASS
            else (
                str(gate_f_live_product_truth_receipt.get("next_lawful_move", "")).strip()
                if isinstance(gate_f_live_product_truth_receipt, dict)
                else (
                    gate_f_common.NEXT_MOVE_FREEZE_LIVE_PRODUCT_TRUTH
                    if isinstance(gate_f_review_receipt, dict)
                    and bool(gate_f_review_receipt.get("gate_f_narrow_wedge_confirmed", False))
                    else (
                        str(gate_e_screen_receipt.get("next_lawful_move", "")).strip()
                        if isinstance(gate_e_screen_receipt, dict) and bool(gate_e_screen_receipt.get("gate_e_open", False))
                        else (
                            str(gate_e_binding_screen_receipt.get("next_lawful_move", "")).strip()
                            if isinstance(gate_e_binding_screen_receipt, dict)
                            else (
                                str(gate_e_binding_packet_receipt.get("next_lawful_move", "")).strip()
                                if isinstance(gate_e_binding_packet_receipt, dict)
                                else (
                                    str(gate_e_screen_receipt.get("next_lawful_move", "")).strip()
                                    if isinstance(gate_e_screen_receipt, dict)
                                    else (
                                        str(gate_e_audit_receipt.get("next_lawful_move", "")).strip()
                                        if isinstance(gate_e_audit_receipt, dict)
                                        and not bool(gate_e_audit_receipt.get("post_clear_live_authority_contradiction_free", False))
                                        else (
                                            str(gate_e_scope_receipt.get("next_lawful_move", "")).strip()
                                            if isinstance(gate_e_scope_receipt, dict)
                                            else (
                                                str(gate_e_monitor_receipt.get("next_lawful_move", "")).strip()
                                                if isinstance(gate_e_monitor_receipt, dict)
                                                else (
                                                    str(full_readjudication_receipt.get("next_lawful_move", "")).strip()
                                                    if isinstance(full_readjudication_receipt, dict)
                                                    else (
                                                        str(full_auth_screen_receipt.get("next_lawful_move", "")).strip()
                                                        if isinstance(full_auth_screen_receipt, dict)
                                                        else NEXT_LAWFUL_MOVE
                                                    )
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ),
        "full_successor_gate_d_readjudication_authorized_now": bool(
            predicates.get("full_successor_gate_d_readjudication_authorized_now", False)
        ),
        "same_head_counted_reentry_admissible_now": bool(
            predicates.get("same_head_counted_reentry_admissible_now", False)
        ),
        "gate_d_reopened": bool(predicates.get("gate_d_reopened", False)),
        "gate_e_open": bool(
            gate_e_screen_receipt.get("gate_e_open", False)
            if isinstance(gate_e_screen_receipt, dict)
            else (
            gate_e_monitor_receipt.get("gate_e_open", False)
            if isinstance(gate_e_monitor_receipt, dict)
            else False
            )
        ),
        "gate_f_narrow_wedge_confirmed": bool(predicates.get("gate_f_narrow_wedge_confirmed", False)),
        "gate_f_open": bool(predicates.get("gate_f_open", False)),
        "minimum_path_complete_through_gate_f": bool(predicates.get("minimum_path_complete_through_gate_f", False)),
        "post_f_broad_canonical_reaudit_passed": bool(predicates.get("post_f_broad_canonical_reaudit_passed", False)),
        "source_refs": source_refs,
        "subject_head": subject_head,
    }


def _build_receipt(*, packet: Dict[str, Any], subject_head: str) -> Dict[str, Any]:
    claim_nodes = list(packet.get("claim_nodes", []))
    full_auth_node = next(
        (node for node in claim_nodes if node.get("node_id") == "successor_full_gate_d_readjudication_authorization_screen"),
        {},
    )
    return {
        "schema_id": "kt.operator.cohort0_successor_master_orchestrator_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": packet["claim_boundary"],
        "execution_status": packet["execution_status"],
        "current_branch_posture": packet["current_branch_posture"],
        "current_product_posture": packet.get("current_product_posture", ""),
        "full_successor_gate_d_readjudication_authorization_screen_status": str(full_auth_node.get("status", "")).strip(),
        "full_successor_gate_d_readjudication_authorized_now": packet["full_successor_gate_d_readjudication_authorized_now"],
        "same_head_counted_reentry_admissible_now": packet["same_head_counted_reentry_admissible_now"],
        "gate_d_reopened": packet["gate_d_reopened"],
        "gate_e_open": packet["gate_e_open"],
        "gate_f_narrow_wedge_confirmed": packet.get("gate_f_narrow_wedge_confirmed", False),
        "gate_f_open": packet.get("gate_f_open", False),
        "minimum_path_complete_through_gate_f": packet.get("minimum_path_complete_through_gate_f", False),
        "post_f_broad_canonical_reaudit_passed": packet.get("post_f_broad_canonical_reaudit_passed", False),
        "next_lawful_move": packet["next_lawful_move"],
        "subject_head": subject_head,
    }


def _build_report(
    *,
    predicate_board: Dict[str, Any],
    blocker_ledger: Dict[str, Any],
    packet: Dict[str, Any],
    receipt: Dict[str, Any],
) -> str:
    missing_lines = "\n".join(
        f"- `{item.get('predicate_id', '')}` -> `{item.get('next_tranche', '')}`"
        for item in blocker_ledger.get("ranked_missing_authorization_predicates", [])
    )
    ready_lines = "\n".join(f"- `{item}`" for item in packet.get("ready_parallel_evidence_nodes", []))
    return (
        "# Cohort0 Successor Master Orchestrator Report\n\n"
        f"- Execution status: `{receipt.get('execution_status', '')}`\n"
        f"- Current branch posture: `{receipt.get('current_branch_posture', '')}`\n"
        f"- Current product posture: `{receipt.get('current_product_posture', '')}`\n"
        f"- Full Gate D readjudication authorization screen status: `{receipt.get('full_successor_gate_d_readjudication_authorization_screen_status', '')}`\n"
        f"- Full successor Gate D readjudication authorized now: `{receipt.get('full_successor_gate_d_readjudication_authorized_now', False)}`\n"
        f"- Counted reentry admissible now: `{receipt.get('same_head_counted_reentry_admissible_now', False)}`\n"
        f"- Gate D reopened: `{receipt.get('gate_d_reopened', False)}`\n"
        f"- Gate E open: `{receipt.get('gate_e_open', False)}`\n"
        f"- Gate F narrow wedge confirmed: `{receipt.get('gate_f_narrow_wedge_confirmed', False)}`\n"
        f"- Post-F broad canonical re-audit passed: `{receipt.get('post_f_broad_canonical_reaudit_passed', False)}`\n"
        f"- Next lawful move: `{receipt.get('next_lawful_move', '')}`\n\n"
        "## Satisfied Core Predicates\n"
        f"- Narrow admissibility confirmed: `{predicate_board.get('predicates', {}).get('narrow_admissibility_confirmed', False)}`\n"
        f"- Selected bridge cross-lane hold: `{predicate_board.get('predicates', {}).get('selected_bridge_cross_lane_hold', False)}`\n"
        f"- Route consequence cross-lane nonzero: `{predicate_board.get('predicates', {}).get('route_consequence_cross_lane_nonzero', False)}`\n"
        f"- Dominance broadening visible: `{predicate_board.get('predicates', {}).get('dominance_broadening_visible', False)}`\n"
        f"- Reserve challenges pass: `{predicate_board.get('predicates', {}).get('reserve_challenges_pass', False)}`\n"
        f"- Fixed harness stable: `{predicate_board.get('predicates', {}).get('fixed_harness_stable', False)}`\n\n"
        "## Missing Authorization Predicates\n"
        f"{missing_lines}\n\n"
        "## Ready Parallel Evidence Nodes\n"
        f"{ready_lines}\n"
    )


def run(
    *,
    verdict_packet_path: Path,
    reentry_block_path: Path,
    lane_a_receipt_path: Path,
    lane_a_scorecard_path: Path,
    lane_b_hydration_receipt_path: Path,
    lane_b_receipt_path: Path,
    lane_b_scorecard_path: Path,
    cross_lane_comparative_packet_path: Path,
    cross_lane_screen_packet_path: Path,
    cross_lane_screen_receipt_path: Path,
    prep_packet_path: Path,
    prep_receipt_path: Path,
    admissibility_screen_packet_path: Path,
    admissibility_screen_receipt_path: Path,
    narrow_review_packet_path: Path,
    narrow_review_receipt_path: Path,
    severity_packet_path: Optional[Path] = None,
    severity_receipt_path: Optional[Path] = None,
    anti_selection_packet_path: Optional[Path] = None,
    anti_selection_receipt_path: Optional[Path] = None,
    family_side_closure_packet_path: Optional[Path] = None,
    family_side_closure_receipt_path: Optional[Path] = None,
    third_surface_packet_path: Optional[Path] = None,
    third_surface_receipt_path: Optional[Path] = None,
    full_auth_screen_packet_path: Optional[Path] = None,
    full_auth_screen_receipt_path: Optional[Path] = None,
    full_readjudication_receipt_path: Optional[Path] = None,
    gate_e_monitor_receipt_path: Optional[Path] = None,
    gate_e_scope_receipt_path: Optional[Path] = None,
    gate_e_audit_receipt_path: Optional[Path] = None,
    gate_e_screen_receipt_path: Optional[Path] = None,
    gate_e_binding_packet_receipt_path: Optional[Path] = None,
    gate_e_binding_screen_receipt_path: Optional[Path] = None,
    gate_f_review_receipt_path: Optional[Path] = None,
    gate_f_live_product_truth_receipt_path: Optional[Path] = None,
    post_f_reaudit_receipt_path: Optional[Path] = None,
    reports_root: Path,
) -> Dict[str, Any]:
    verdict_packet = _load_json_required(verdict_packet_path, label="hardened ceiling verdict packet")
    reentry_block = _load_json_required(reentry_block_path, label="gate d reentry block contract")
    lane_a_receipt = _load_json_required(lane_a_receipt_path, label="lane a receipt")
    lane_a_scorecard = _load_json_required(lane_a_scorecard_path, label="lane a scorecard")
    lane_b_hydration_receipt = _load_json_required(lane_b_hydration_receipt_path, label="lane b hydration receipt")
    lane_b_receipt = _load_json_required(lane_b_receipt_path, label="lane b family receipt")
    lane_b_scorecard = _load_json_required(lane_b_scorecard_path, label="lane b family scorecard")
    cross_lane_comparative_packet = _load_json_required(
        cross_lane_comparative_packet_path, label="cross-lane comparative packet"
    )
    cross_lane_screen_packet = _load_json_required(
        cross_lane_screen_packet_path, label="cross-lane reentry-prep screening packet"
    )
    cross_lane_screen_receipt = _load_json_required(
        cross_lane_screen_receipt_path, label="cross-lane reentry-prep screening receipt"
    )
    prep_packet = _load_json_required(prep_packet_path, label="successor reentry-prep packet")
    prep_receipt = _load_json_required(prep_receipt_path, label="successor reentry-prep receipt")
    admissibility_screen_packet = _load_json_required(
        admissibility_screen_packet_path, label="successor admissibility screen packet"
    )
    admissibility_screen_receipt = _load_json_required(
        admissibility_screen_receipt_path, label="successor admissibility screen receipt"
    )
    narrow_review_packet = _load_json_required(narrow_review_packet_path, label="narrow admissibility review packet")
    narrow_review_receipt = _load_json_required(
        narrow_review_receipt_path, label="narrow admissibility review receipt"
    )
    severity_packet = _load_json_optional(severity_packet_path) if severity_packet_path else None
    severity_receipt = _load_json_optional(severity_receipt_path) if severity_receipt_path else None
    anti_selection_packet = _load_json_optional(anti_selection_packet_path) if anti_selection_packet_path else None
    anti_selection_receipt = _load_json_optional(anti_selection_receipt_path) if anti_selection_receipt_path else None
    family_side_closure_packet = _load_json_optional(family_side_closure_packet_path) if family_side_closure_packet_path else None
    family_side_closure_receipt = _load_json_optional(family_side_closure_receipt_path) if family_side_closure_receipt_path else None
    third_surface_packet = _load_json_optional(third_surface_packet_path) if third_surface_packet_path else None
    third_surface_receipt = _load_json_optional(third_surface_receipt_path) if third_surface_receipt_path else None
    full_auth_screen_packet = _load_json_optional(full_auth_screen_packet_path) if full_auth_screen_packet_path else None
    full_auth_screen_receipt = _load_json_optional(full_auth_screen_receipt_path) if full_auth_screen_receipt_path else None
    full_readjudication_receipt = (
        _load_json_optional(full_readjudication_receipt_path) if full_readjudication_receipt_path else None
    )
    gate_e_monitor_receipt = _load_json_optional(gate_e_monitor_receipt_path) if gate_e_monitor_receipt_path else None
    gate_e_scope_receipt = _load_json_optional(gate_e_scope_receipt_path) if gate_e_scope_receipt_path else None
    gate_e_audit_receipt = _load_json_optional(gate_e_audit_receipt_path) if gate_e_audit_receipt_path else None
    gate_e_screen_receipt = _load_json_optional(gate_e_screen_receipt_path) if gate_e_screen_receipt_path else None
    gate_e_binding_packet_receipt = (
        _load_json_optional(gate_e_binding_packet_receipt_path) if gate_e_binding_packet_receipt_path else None
    )
    gate_e_binding_screen_receipt = (
        _load_json_optional(gate_e_binding_screen_receipt_path) if gate_e_binding_screen_receipt_path else None
    )
    gate_f_review_receipt = _load_json_optional(gate_f_review_receipt_path) if gate_f_review_receipt_path else None
    gate_f_live_product_truth_receipt = (
        _load_json_optional(gate_f_live_product_truth_receipt_path) if gate_f_live_product_truth_receipt_path else None
    )
    post_f_reaudit_receipt = _load_json_optional(post_f_reaudit_receipt_path) if post_f_reaudit_receipt_path else None

    _validate_inputs(
        verdict_packet=verdict_packet,
        reentry_block=reentry_block,
        lane_a_receipt=lane_a_receipt,
        lane_a_scorecard=lane_a_scorecard,
        lane_b_hydration_receipt=lane_b_hydration_receipt,
        lane_b_receipt=lane_b_receipt,
        lane_b_scorecard=lane_b_scorecard,
        cross_lane_comparative_packet=cross_lane_comparative_packet,
        cross_lane_screen_packet=cross_lane_screen_packet,
        cross_lane_screen_receipt=cross_lane_screen_receipt,
        prep_packet=prep_packet,
        prep_receipt=prep_receipt,
        admissibility_screen_packet=admissibility_screen_packet,
        admissibility_screen_receipt=admissibility_screen_receipt,
        narrow_review_packet=narrow_review_packet,
        narrow_review_receipt=narrow_review_receipt,
    )
    head_packets: List[Dict[str, Any]] = [
        verdict_packet,
        reentry_block,
        lane_a_receipt,
        lane_a_scorecard,
        lane_b_hydration_receipt,
        lane_b_receipt,
        lane_b_scorecard,
        cross_lane_comparative_packet,
        cross_lane_screen_packet,
        cross_lane_screen_receipt,
        prep_packet,
        prep_receipt,
        admissibility_screen_packet,
        admissibility_screen_receipt,
        narrow_review_packet,
        narrow_review_receipt,
    ]
    for optional_payload in (
        severity_packet,
        severity_receipt,
        anti_selection_packet,
        anti_selection_receipt,
        family_side_closure_packet,
        family_side_closure_receipt,
        third_surface_packet,
        third_surface_receipt,
        full_auth_screen_packet,
        full_auth_screen_receipt,
        full_readjudication_receipt,
        gate_e_monitor_receipt,
        gate_e_scope_receipt,
        gate_e_audit_receipt,
        gate_e_screen_receipt,
        gate_e_binding_packet_receipt,
        gate_e_binding_screen_receipt,
        gate_f_review_receipt,
        gate_f_live_product_truth_receipt,
        post_f_reaudit_receipt,
    ):
        if isinstance(optional_payload, dict):
            head_packets.append(optional_payload)
    subject_head = _require_same_subject_head(head_packets)

    predicate_board = _build_predicate_board(
        lane_a_scorecard=lane_a_scorecard,
        lane_b_scorecard=lane_b_scorecard,
        cross_lane_comparative_packet=cross_lane_comparative_packet,
        cross_lane_screen_receipt=cross_lane_screen_receipt,
        prep_receipt=prep_receipt,
        prep_packet=prep_packet,
        admissibility_screen_packet=admissibility_screen_packet,
        admissibility_screen_receipt=admissibility_screen_receipt,
        narrow_review_packet=narrow_review_packet,
        narrow_review_receipt=narrow_review_receipt,
        severity_receipt=severity_receipt,
        anti_selection_receipt=anti_selection_receipt,
        family_side_closure_receipt=family_side_closure_receipt,
        third_surface_receipt=third_surface_receipt,
        full_auth_screen_receipt=full_auth_screen_receipt,
        full_readjudication_receipt=full_readjudication_receipt,
        gate_e_monitor_receipt=gate_e_monitor_receipt,
        gate_e_scope_receipt=gate_e_scope_receipt,
        gate_e_audit_receipt=gate_e_audit_receipt,
        gate_e_screen_receipt=gate_e_screen_receipt,
        gate_e_binding_packet_receipt=gate_e_binding_packet_receipt,
        gate_e_binding_screen_receipt=gate_e_binding_screen_receipt,
        gate_f_review_receipt=gate_f_review_receipt,
        gate_f_live_product_truth_receipt=gate_f_live_product_truth_receipt,
        post_f_reaudit_receipt=post_f_reaudit_receipt,
        subject_head=subject_head,
    )

    reports_root.mkdir(parents=True, exist_ok=True)
    predicate_board_path = reports_root / OUTPUT_PREDICATE_BOARD
    write_json_stable(predicate_board_path, predicate_board)

    source_refs = {
        "verdict_packet_ref": verdict_packet_path.as_posix(),
        "reentry_block_ref": reentry_block_path.as_posix(),
        "lane_a_receipt_ref": lane_a_receipt_path.as_posix(),
        "lane_a_scorecard_ref": lane_a_scorecard_path.as_posix(),
        "lane_b_hydration_receipt_ref": lane_b_hydration_receipt_path.as_posix(),
        "lane_b_receipt_ref": lane_b_receipt_path.as_posix(),
        "lane_b_scorecard_ref": lane_b_scorecard_path.as_posix(),
        "cross_lane_comparative_packet_ref": cross_lane_comparative_packet_path.as_posix(),
        "cross_lane_screen_packet_ref": cross_lane_screen_packet_path.as_posix(),
        "cross_lane_screen_receipt_ref": cross_lane_screen_receipt_path.as_posix(),
        "prep_packet_ref": prep_packet_path.as_posix(),
        "prep_receipt_ref": prep_receipt_path.as_posix(),
        "admissibility_screen_packet_ref": admissibility_screen_packet_path.as_posix(),
        "admissibility_screen_receipt_ref": admissibility_screen_receipt_path.as_posix(),
        "narrow_review_packet_ref": narrow_review_packet_path.as_posix(),
        "narrow_review_receipt_ref": narrow_review_receipt_path.as_posix(),
        "predicate_board_ref": predicate_board_path.resolve().as_posix(),
    }
    if severity_packet_path and isinstance(severity_packet, dict):
        source_refs["severity_packet_ref"] = severity_packet_path.as_posix()
    if severity_receipt_path and isinstance(severity_receipt, dict):
        source_refs["severity_receipt_ref"] = severity_receipt_path.as_posix()
    if anti_selection_packet_path and isinstance(anti_selection_packet, dict):
        source_refs["anti_selection_packet_ref"] = anti_selection_packet_path.as_posix()
    if anti_selection_receipt_path and isinstance(anti_selection_receipt, dict):
        source_refs["anti_selection_receipt_ref"] = anti_selection_receipt_path.as_posix()
    if family_side_closure_packet_path and isinstance(family_side_closure_packet, dict):
        source_refs["family_side_closure_packet_ref"] = family_side_closure_packet_path.as_posix()
    if family_side_closure_receipt_path and isinstance(family_side_closure_receipt, dict):
        source_refs["family_side_closure_receipt_ref"] = family_side_closure_receipt_path.as_posix()
    if third_surface_packet_path and isinstance(third_surface_packet, dict):
        source_refs["third_surface_packet_ref"] = third_surface_packet_path.as_posix()
    if third_surface_receipt_path and isinstance(third_surface_receipt, dict):
        source_refs["third_surface_receipt_ref"] = third_surface_receipt_path.as_posix()
    if full_auth_screen_packet_path and isinstance(full_auth_screen_packet, dict):
        source_refs["full_auth_screen_packet_ref"] = full_auth_screen_packet_path.as_posix()
    if full_auth_screen_receipt_path and isinstance(full_auth_screen_receipt, dict):
        source_refs["full_auth_screen_receipt_ref"] = full_auth_screen_receipt_path.as_posix()
    if full_readjudication_receipt_path and isinstance(full_readjudication_receipt, dict):
        source_refs["full_readjudication_receipt_ref"] = full_readjudication_receipt_path.as_posix()
    if gate_e_monitor_receipt_path and isinstance(gate_e_monitor_receipt, dict):
        source_refs["gate_e_monitor_receipt_ref"] = gate_e_monitor_receipt_path.as_posix()
    if gate_e_scope_receipt_path and isinstance(gate_e_scope_receipt, dict):
        source_refs["gate_e_scope_receipt_ref"] = gate_e_scope_receipt_path.as_posix()
    if gate_e_audit_receipt_path and isinstance(gate_e_audit_receipt, dict):
        source_refs["gate_e_audit_receipt_ref"] = gate_e_audit_receipt_path.as_posix()
    if gate_e_screen_receipt_path and isinstance(gate_e_screen_receipt, dict):
        source_refs["gate_e_screen_receipt_ref"] = gate_e_screen_receipt_path.as_posix()
    if gate_e_binding_packet_receipt_path and isinstance(gate_e_binding_packet_receipt, dict):
        source_refs["gate_e_binding_packet_receipt_ref"] = gate_e_binding_packet_receipt_path.as_posix()
    if gate_e_binding_screen_receipt_path and isinstance(gate_e_binding_screen_receipt, dict):
        source_refs["gate_e_binding_screen_receipt_ref"] = gate_e_binding_screen_receipt_path.as_posix()
    if gate_f_review_receipt_path and isinstance(gate_f_review_receipt, dict):
        source_refs["gate_f_review_receipt_ref"] = gate_f_review_receipt_path.as_posix()
    if gate_f_live_product_truth_receipt_path and isinstance(gate_f_live_product_truth_receipt, dict):
        source_refs["gate_f_live_product_truth_receipt_ref"] = gate_f_live_product_truth_receipt_path.as_posix()
    if post_f_reaudit_receipt_path and isinstance(post_f_reaudit_receipt, dict):
        source_refs["post_f_reaudit_receipt_ref"] = post_f_reaudit_receipt_path.as_posix()

    blocker_ledger = _build_blocker_ledger(
        predicate_board=predicate_board,
        narrow_review_packet=narrow_review_packet,
        anti_selection_receipt=anti_selection_receipt,
        full_auth_screen_receipt=full_auth_screen_receipt,
        full_readjudication_receipt=full_readjudication_receipt,
        gate_e_monitor_receipt=gate_e_monitor_receipt,
        gate_e_scope_receipt=gate_e_scope_receipt,
        gate_e_audit_receipt=gate_e_audit_receipt,
        gate_e_screen_receipt=gate_e_screen_receipt,
        gate_e_binding_packet_receipt=gate_e_binding_packet_receipt,
        gate_e_binding_screen_receipt=gate_e_binding_screen_receipt,
        gate_f_review_receipt=gate_f_review_receipt,
        gate_f_live_product_truth_receipt=gate_f_live_product_truth_receipt,
        post_f_reaudit_receipt=post_f_reaudit_receipt,
        source_refs=source_refs,
        subject_head=subject_head,
    )
    blocker_ledger_path = reports_root / OUTPUT_BLOCKER_LEDGER
    write_json_stable(blocker_ledger_path, blocker_ledger)
    source_refs["blocker_ledger_ref"] = blocker_ledger_path.resolve().as_posix()

    packet = _build_packet(
        blocker_ledger=blocker_ledger,
        predicate_board=predicate_board,
        severity_receipt=severity_receipt,
        anti_selection_receipt=anti_selection_receipt,
        family_side_closure_receipt=family_side_closure_receipt,
        third_surface_receipt=third_surface_receipt,
        full_auth_screen_receipt=full_auth_screen_receipt,
        full_readjudication_receipt=full_readjudication_receipt,
        gate_e_monitor_receipt=gate_e_monitor_receipt,
        gate_e_scope_receipt=gate_e_scope_receipt,
        gate_e_audit_receipt=gate_e_audit_receipt,
        gate_e_screen_receipt=gate_e_screen_receipt,
        gate_e_binding_packet_receipt=gate_e_binding_packet_receipt,
        gate_e_binding_screen_receipt=gate_e_binding_screen_receipt,
        gate_f_review_receipt=gate_f_review_receipt,
        gate_f_live_product_truth_receipt=gate_f_live_product_truth_receipt,
        post_f_reaudit_receipt=post_f_reaudit_receipt,
        source_refs=source_refs,
        subject_head=subject_head,
    )
    receipt = _build_receipt(packet=packet, subject_head=subject_head)

    packet_path = reports_root / OUTPUT_PACKET
    receipt_path = reports_root / OUTPUT_RECEIPT
    report_path = reports_root / OUTPUT_REPORT

    write_json_stable(packet_path, packet)
    write_json_stable(receipt_path, receipt)
    _write_text(
        report_path,
        _build_report(
            predicate_board=predicate_board,
            blocker_ledger=blocker_ledger,
            packet=packet,
            receipt=receipt,
        ),
    )

    return {
        "status": "PASS",
        "execution_status": EXECUTION_STATUS,
        "current_branch_posture": receipt["current_branch_posture"],
        "current_product_posture": receipt.get("current_product_posture", ""),
        "full_successor_gate_d_readjudication_authorization_screen_status": receipt[
            "full_successor_gate_d_readjudication_authorization_screen_status"
        ],
        "ready_parallel_evidence_node_count": len(packet.get("ready_parallel_evidence_nodes", [])),
        "next_lawful_move": receipt["next_lawful_move"],
        "output_count": 5,
        "receipt_path": receipt_path.as_posix(),
        "subject_head": subject_head,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the successor DAG-style master orchestrator with parallel evidence readiness and predicate-gated courts."
    )
    parser.add_argument("--verdict-packet", default=DEFAULT_VERDICT_PACKET_REL)
    parser.add_argument("--reentry-block", default=DEFAULT_REENTRY_BLOCK_REL)
    parser.add_argument("--lane-a-receipt", default=DEFAULT_LANE_A_RECEIPT_REL)
    parser.add_argument("--lane-a-scorecard", default=DEFAULT_LANE_A_SCORECARD_REL)
    parser.add_argument("--lane-b-hydration-receipt", default=DEFAULT_LANE_B_HYDRATION_RECEIPT_REL)
    parser.add_argument("--lane-b-receipt", default=DEFAULT_LANE_B_RECEIPT_REL)
    parser.add_argument("--lane-b-scorecard", default=DEFAULT_LANE_B_SCORECARD_REL)
    parser.add_argument("--cross-lane-comparative-packet", default=DEFAULT_CROSS_LANE_COMPARATIVE_PACKET_REL)
    parser.add_argument("--cross-lane-screen-packet", default=DEFAULT_CROSS_LANE_SCREEN_PACKET_REL)
    parser.add_argument("--cross-lane-screen-receipt", default=DEFAULT_CROSS_LANE_SCREEN_RECEIPT_REL)
    parser.add_argument("--prep-packet", default=DEFAULT_PREP_PACKET_REL)
    parser.add_argument("--prep-receipt", default=DEFAULT_PREP_RECEIPT_REL)
    parser.add_argument("--admissibility-screen-packet", default=DEFAULT_ADMISSIBILITY_SCREEN_PACKET_REL)
    parser.add_argument("--admissibility-screen-receipt", default=DEFAULT_ADMISSIBILITY_SCREEN_RECEIPT_REL)
    parser.add_argument("--narrow-review-packet", default=DEFAULT_NARROW_REVIEW_PACKET_REL)
    parser.add_argument("--narrow-review-receipt", default=DEFAULT_NARROW_REVIEW_RECEIPT_REL)
    parser.add_argument("--severity-packet", default=DEFAULT_SEVERITY_PACKET_REL)
    parser.add_argument("--severity-receipt", default=DEFAULT_SEVERITY_RECEIPT_REL)
    parser.add_argument("--anti-selection-packet", default=DEFAULT_ANTI_SELECTION_PACKET_REL)
    parser.add_argument("--anti-selection-receipt", default=DEFAULT_ANTI_SELECTION_RECEIPT_REL)
    parser.add_argument("--family-side-closure-packet", default=DEFAULT_FAMILY_SIDE_CLOSURE_PACKET_REL)
    parser.add_argument("--family-side-closure-receipt", default=DEFAULT_FAMILY_SIDE_CLOSURE_RECEIPT_REL)
    parser.add_argument("--third-surface-packet", default=DEFAULT_THIRD_SURFACE_PACKET_REL)
    parser.add_argument("--third-surface-receipt", default=DEFAULT_THIRD_SURFACE_RECEIPT_REL)
    parser.add_argument("--full-auth-screen-packet", default=DEFAULT_FULL_AUTH_SCREEN_PACKET_REL)
    parser.add_argument("--full-auth-screen-receipt", default=DEFAULT_FULL_AUTH_SCREEN_RECEIPT_REL)
    parser.add_argument("--full-readjudication-receipt", default=DEFAULT_FULL_READJUDICATION_RECEIPT_REL)
    parser.add_argument("--gate-e-monitor-receipt", default=DEFAULT_GATE_E_MONITOR_RECEIPT_REL)
    parser.add_argument("--gate-e-scope-receipt", default=DEFAULT_GATE_E_SCOPE_RECEIPT_REL)
    parser.add_argument("--gate-e-audit-receipt", default=DEFAULT_GATE_E_AUDIT_RECEIPT_REL)
    parser.add_argument("--gate-e-screen-receipt", default=DEFAULT_GATE_E_SCREEN_RECEIPT_REL)
    parser.add_argument("--gate-e-binding-packet-receipt", default=DEFAULT_GATE_E_BINDING_PACKET_RECEIPT_REL)
    parser.add_argument("--gate-e-binding-screen-receipt", default=DEFAULT_GATE_E_BINDING_SCREEN_RECEIPT_REL)
    parser.add_argument("--gate-f-review-receipt", default=DEFAULT_GATE_F_REVIEW_RECEIPT_REL)
    parser.add_argument("--gate-f-live-product-truth-receipt", default=DEFAULT_GATE_F_LIVE_PRODUCT_TRUTH_RECEIPT_REL)
    parser.add_argument("--post-f-reaudit-receipt", default=DEFAULT_POST_F_REAUDIT_RECEIPT_REL)
    parser.add_argument("--reports-root", default=DEFAULT_REPORTS_ROOT_REL)
    args = parser.parse_args(argv)

    root = repo_root()
    result = run(
        verdict_packet_path=_resolve(root, args.verdict_packet),
        reentry_block_path=_resolve(root, args.reentry_block),
        lane_a_receipt_path=_resolve(root, args.lane_a_receipt),
        lane_a_scorecard_path=_resolve(root, args.lane_a_scorecard),
        lane_b_hydration_receipt_path=_resolve(root, args.lane_b_hydration_receipt),
        lane_b_receipt_path=_resolve(root, args.lane_b_receipt),
        lane_b_scorecard_path=_resolve(root, args.lane_b_scorecard),
        cross_lane_comparative_packet_path=_resolve(root, args.cross_lane_comparative_packet),
        cross_lane_screen_packet_path=_resolve(root, args.cross_lane_screen_packet),
        cross_lane_screen_receipt_path=_resolve(root, args.cross_lane_screen_receipt),
        prep_packet_path=_resolve(root, args.prep_packet),
        prep_receipt_path=_resolve(root, args.prep_receipt),
        admissibility_screen_packet_path=_resolve(root, args.admissibility_screen_packet),
        admissibility_screen_receipt_path=_resolve(root, args.admissibility_screen_receipt),
        narrow_review_packet_path=_resolve(root, args.narrow_review_packet),
        narrow_review_receipt_path=_resolve(root, args.narrow_review_receipt),
        severity_packet_path=_resolve(root, args.severity_packet),
        severity_receipt_path=_resolve(root, args.severity_receipt),
        anti_selection_packet_path=_resolve(root, args.anti_selection_packet),
        anti_selection_receipt_path=_resolve(root, args.anti_selection_receipt),
        family_side_closure_packet_path=_resolve(root, args.family_side_closure_packet),
        family_side_closure_receipt_path=_resolve(root, args.family_side_closure_receipt),
        third_surface_packet_path=_resolve(root, args.third_surface_packet),
        third_surface_receipt_path=_resolve(root, args.third_surface_receipt),
        full_auth_screen_packet_path=_resolve(root, args.full_auth_screen_packet),
        full_auth_screen_receipt_path=_resolve(root, args.full_auth_screen_receipt),
        full_readjudication_receipt_path=_resolve(root, args.full_readjudication_receipt),
        gate_e_monitor_receipt_path=_resolve(root, args.gate_e_monitor_receipt),
        gate_e_scope_receipt_path=_resolve(root, args.gate_e_scope_receipt),
        gate_e_audit_receipt_path=_resolve(root, args.gate_e_audit_receipt),
        gate_e_screen_receipt_path=_resolve(root, args.gate_e_screen_receipt),
        gate_e_binding_packet_receipt_path=_resolve(root, args.gate_e_binding_packet_receipt),
        gate_e_binding_screen_receipt_path=_resolve(root, args.gate_e_binding_screen_receipt),
        gate_f_review_receipt_path=_resolve(root, args.gate_f_review_receipt),
        gate_f_live_product_truth_receipt_path=_resolve(root, args.gate_f_live_product_truth_receipt),
        post_f_reaudit_receipt_path=_resolve(root, args.post_f_reaudit_receipt),
        reports_root=_resolve(root, args.reports_root),
    )
    for key in (
        "status",
        "execution_status",
        "current_branch_posture",
        "current_product_posture",
        "full_successor_gate_d_readjudication_authorization_screen_status",
        "ready_parallel_evidence_node_count",
        "next_lawful_move",
        "output_count",
        "receipt_path",
        "subject_head",
    ):
        print(f"{key}={result[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
