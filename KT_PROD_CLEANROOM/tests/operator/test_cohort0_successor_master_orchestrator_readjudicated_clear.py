from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_successor_master_orchestrator_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _claim_node(packet: dict, node_id: str) -> dict:
    return next(node for node in packet.get("claim_nodes", []) if node.get("node_id") == node_id)


def test_successor_master_orchestrator_reflects_cleared_gate_d_after_readjudication(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    subject_head = tranche.setup_tranche.EXPECTED_SUBJECT_HEAD

    _write_json(
        reports / "cohort0_gate_d_hardened_ceiling_verdict_packet.json",
        {
            "status": "PASS",
            "subject_head": subject_head,
            "final_verdict_id": tranche.setup_tranche.EXPECTED_FINAL_VERDICT_ID,
            "current_lane_closed": True,
            "same_head_counted_reentry_admissible_now": False,
        },
    )
    _write_json(
        reports / "cohort0_gate_d_reentry_block_contract.json",
        {
            "status": "PASS",
            "subject_head": subject_head,
            "reentry_status": "BLOCKED__CURRENT_LANE_HARDENED_CEILING",
        },
    )
    _write_json(
        reports / tranche.lane_a_exec.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": "PASS__LANE_A_PROMOTED_SURVIVOR_FULL_EXECUTION",
            "same_head_counted_reentry_admissible_now": False,
            "gate_d_reopened": False,
            "gate_e_open": False,
        },
    )
    _write_json(
        reports / tranche.lane_a_exec.OUTPUT_SCORECARD,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": "PASS__LANE_A_PROMOTED_SURVIVOR_FULL_EXECUTION",
        },
    )
    _write_json(
        reports / tranche.lane_b_hydration.OUTPUT_HYDRATION_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": "PASS__LANE_B_STAGE_PACK_HYDRATION_EXECUTED",
            "lane_b_case_execution_available_after_hydration": True,
            "same_head_counted_reentry_admissible_now": False,
            "gate_d_reopened": False,
            "gate_e_open": False,
        },
    )
    _write_json(
        reports / tranche.lane_b_exec.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": "PASS__LANE_B_FAMILY_LEVEL_BRIDGE_HARNESS_EXECUTED",
            "same_head_counted_reentry_admissible_now": False,
            "gate_d_reopened": False,
            "gate_e_open": False,
        },
    )
    _write_json(
        reports / tranche.lane_b_exec.OUTPUT_SCORECARD,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": "PASS__LANE_B_FAMILY_LEVEL_BRIDGE_HARNESS_EXECUTED",
        },
    )
    _write_json(
        reports / tranche.lane_b_exec.OUTPUT_COMPARATIVE_PACKET,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": "PASS__CROSS_LANE_COMPARATIVE_PACKET_EMITTED",
            "comparative_read": {
                "lane_a_remains_numeric_benchmark_witness": True,
                "lane_b_now_executed_on_materially_distinct_family_surface": True,
                "dominance_surface_broadening_visible": True,
                "lane_b_bridge_quality_near_lane_a_levels": True,
            },
        },
    )
    _write_json(
        reports / tranche.cross_lane_screen.OUTPUT_SCREENING_PACKET,
        {"status": "PASS", "subject_head": subject_head, "execution_status": "PASS__CROSS_LANE_REENTRY_PREP_SCREEN_EXECUTED"},
    )
    _write_json(
        reports / tranche.cross_lane_screen.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": "PASS__CROSS_LANE_REENTRY_PREP_SCREEN_EXECUTED",
            "reserve_challenges_pass": True,
            "successor_reentry_prep_packet_authorized": True,
            "same_head_counted_reentry_admissible_now": False,
            "gate_d_reopened": False,
            "gate_e_open": False,
        },
    )
    _write_json(
        reports / tranche.prep_packet_tranche.OUTPUT_PACKET,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "selected_successor_core": {
                "lead_bridge_candidate_id": "RB_COUNTERFACTUAL_EVIDENCE_OBJECT_BRIDGE_V1",
                "secondary_bridge_candidate_id": "RB_TYPED_CAUSAL_SCHEMA_BRIDGE_V1",
                "guardrail_bridge_candidate_id": "RB_CALIBRATED_REASON_REFUSAL_BRIDGE_V1",
                "fixed_harness_global_totals": {
                    "forced_wrong_route_total_cost": 46.461,
                    "witness_ablation_total_cost": 34.261,
                    "static_hold_control_total_cost": 0.0,
                },
            },
        },
    )
    _write_json(
        reports / tranche.prep_packet_tranche.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": "PASS__SUCCESSOR_REENTRY_PREP_PACKET_AUTHORED",
            "successor_reentry_prep_packet_authored": True,
            "same_head_counted_reentry_admissible_now": False,
            "gate_d_reopened": False,
            "gate_e_open": False,
        },
    )
    _write_json(
        reports / tranche.admissibility_screen.OUTPUT_PACKET,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "screen_findings": {
                "selected_bridge_cross_lane_hold": True,
                "route_consequence_cross_lane_nonzero": True,
                "dominance_broadening_visible": True,
                "materially_distinct_family_lane_executed": True,
                "reserve_challenges_pass": True,
                "fixed_harness_stable": True,
            },
            "full_successor_gate_d_readjudication_authorized_now": False,
        },
    )
    _write_json(
        reports / tranche.admissibility_screen.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": "PASS__SUCCESSOR_GATE_D_REENTRY_ADMISSIBILITY_SCREEN_EXECUTED",
            "narrow_successor_gate_d_admissibility_review_authorized": True,
            "same_head_counted_reentry_admissible_now": False,
            "gate_d_reopened": False,
            "gate_e_open": False,
        },
    )
    _write_json(
        reports / tranche.narrow_review.OUTPUT_PACKET,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "review_scope": "NARROW_SUCCESSOR_GATE_D_ADMISSIBILITY_ONLY",
            "review_outcome": tranche.narrow_review.OUTCOME_CONFIRMED,
            "bounded_defects_remaining": [],
            "review_findings": {
                "selected_bridge_cross_lane_hold": True,
                "route_consequence_cross_lane_nonzero": True,
                "dominance_broadening_visible": True,
                "materially_distinct_family_lane_executed": True,
                "reserve_challenges_pass": True,
                "fixed_harness_stable": True,
            },
            "full_successor_gate_d_readjudication_authorized_now": False,
        },
    )
    _write_json(
        reports / tranche.narrow_review.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": "PASS__SUCCESSOR_GATE_D_NARROW_ADMISSIBILITY_REVIEW_CONVENED",
            "narrow_successor_gate_d_admissibility_confirmed": True,
            "same_head_counted_reentry_admissible_now": False,
            "gate_d_reopened": False,
            "gate_e_open": False,
        },
    )
    _write_json(
        reports / tranche.severity_wave.OUTPUT_PACKET,
        {"status": "PASS", "subject_head": subject_head},
    )
    _write_json(
        reports / tranche.severity_wave.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": tranche.severity_wave.EXECUTION_STATUS,
            "severity_escalation_route_consequence_wave_closed": True,
        },
    )
    _write_json(
        reports / tranche.anti_selection_wave.OUTPUT_PACKET,
        {"status": "PASS", "subject_head": subject_head, "bounded_defects_remaining": []},
    )
    _write_json(
        reports / tranche.anti_selection_wave.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": tranche.anti_selection_wave.EXECUTION_STATUS,
            "anti_selection_wave_beyond_reserve_closed": True,
        },
    )
    _write_json(
        reports / tranche.family_side_closure_wave.OUTPUT_PACKET,
        {"status": "PASS", "subject_head": subject_head, "bounded_defects_remaining": []},
    )
    _write_json(
        reports / tranche.family_side_closure_wave.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": tranche.family_side_closure_wave.EXECUTION_STATUS,
            "anti_selection_wave_beyond_reserve_closed": True,
            "family_side_anti_selection_defect_closed": True,
            "bounded_defects_remaining": [],
        },
    )
    _write_json(
        reports / tranche.third_surface_wave.OUTPUT_PACKET,
        {"status": "PASS", "subject_head": subject_head},
    )
    _write_json(
        reports / tranche.third_surface_wave.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": tranche.third_surface_wave.EXECUTION_STATUS,
            "third_surface_breadth_witness_closed": True,
        },
    )
    _write_json(
        reports / tranche.full_auth_screen.OUTPUT_PACKET,
        {"status": "PASS", "subject_head": subject_head},
    )
    _write_json(
        reports / tranche.full_auth_screen.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": tranche.full_auth_screen.EXECUTION_STATUS,
            "full_successor_gate_d_readjudication_authorization_screen_executed": True,
            "full_successor_gate_d_readjudication_authorized_now": True,
            "full_successor_gate_d_readjudication_authorization_screen_status": tranche.full_auth_screen.STATUS_AUTHORIZED,
            "next_lawful_move": tranche.full_auth_screen.NEXT_MOVE_AUTHORIZED,
        },
    )
    _write_json(
        reports / tranche.full_readjudication.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": tranche.full_readjudication.EXECUTION_STATUS,
            "readjudication_outcome": tranche.full_readjudication.OUTCOME_CLEARED,
            "gate_d_officially_cleared": True,
            "same_head_counted_reentry_admissible_now": True,
            "gate_d_reopened": True,
            "gate_e_open": False,
            "next_lawful_move": tranche.full_readjudication.NEXT_MOVE_CLEARED,
        },
    )

    result = tranche.run(
        verdict_packet_path=reports / "cohort0_gate_d_hardened_ceiling_verdict_packet.json",
        reentry_block_path=reports / "cohort0_gate_d_reentry_block_contract.json",
        lane_a_receipt_path=reports / tranche.lane_a_exec.OUTPUT_RECEIPT,
        lane_a_scorecard_path=reports / tranche.lane_a_exec.OUTPUT_SCORECARD,
        lane_b_hydration_receipt_path=reports / tranche.lane_b_hydration.OUTPUT_HYDRATION_RECEIPT,
        lane_b_receipt_path=reports / tranche.lane_b_exec.OUTPUT_RECEIPT,
        lane_b_scorecard_path=reports / tranche.lane_b_exec.OUTPUT_SCORECARD,
        cross_lane_comparative_packet_path=reports / tranche.lane_b_exec.OUTPUT_COMPARATIVE_PACKET,
        cross_lane_screen_packet_path=reports / tranche.cross_lane_screen.OUTPUT_SCREENING_PACKET,
        cross_lane_screen_receipt_path=reports / tranche.cross_lane_screen.OUTPUT_RECEIPT,
        prep_packet_path=reports / tranche.prep_packet_tranche.OUTPUT_PACKET,
        prep_receipt_path=reports / tranche.prep_packet_tranche.OUTPUT_RECEIPT,
        admissibility_screen_packet_path=reports / tranche.admissibility_screen.OUTPUT_PACKET,
        admissibility_screen_receipt_path=reports / tranche.admissibility_screen.OUTPUT_RECEIPT,
        narrow_review_packet_path=reports / tranche.narrow_review.OUTPUT_PACKET,
        narrow_review_receipt_path=reports / tranche.narrow_review.OUTPUT_RECEIPT,
        severity_packet_path=reports / tranche.severity_wave.OUTPUT_PACKET,
        severity_receipt_path=reports / tranche.severity_wave.OUTPUT_RECEIPT,
        anti_selection_packet_path=reports / tranche.anti_selection_wave.OUTPUT_PACKET,
        anti_selection_receipt_path=reports / tranche.anti_selection_wave.OUTPUT_RECEIPT,
        family_side_closure_packet_path=reports / tranche.family_side_closure_wave.OUTPUT_PACKET,
        family_side_closure_receipt_path=reports / tranche.family_side_closure_wave.OUTPUT_RECEIPT,
        third_surface_packet_path=reports / tranche.third_surface_wave.OUTPUT_PACKET,
        third_surface_receipt_path=reports / tranche.third_surface_wave.OUTPUT_RECEIPT,
        full_auth_screen_packet_path=reports / tranche.full_auth_screen.OUTPUT_PACKET,
        full_auth_screen_receipt_path=reports / tranche.full_auth_screen.OUTPUT_RECEIPT,
        full_readjudication_receipt_path=reports / tranche.full_readjudication.OUTPUT_RECEIPT,
        reports_root=reports,
    )

    assert result["status"] == "PASS"
    assert result["current_branch_posture"] == tranche.CLEARED_POSTURE
    assert result["next_lawful_move"] == tranche.full_readjudication.NEXT_MOVE_CLEARED

    packet = json.loads((reports / tranche.OUTPUT_PACKET).read_text(encoding="utf-8"))
    receipt = json.loads((reports / tranche.OUTPUT_RECEIPT).read_text(encoding="utf-8"))
    assert (
        _claim_node(packet, "successor_full_gate_d_readjudication")["status"]
        == "SATISFIED__GATE_D_CLEARED__SUCCESSOR_LINE"
    )
    assert _claim_node(packet, "gate_e_precondition_monitor")["status"] == "AUTHORIZED__POST_SUCCESSOR_GATE_D_CLEAR"
    assert (
        _claim_node(packet, "gate_e_admissibility_scope_packet")["status"]
        == "BLOCKED_PENDING_GATE_E_PRECONDITION_MONITOR"
    )
    assert receipt["gate_d_reopened"] is True
    assert receipt["same_head_counted_reentry_admissible_now"] is True
    predicate_board = json.loads((reports / tranche.OUTPUT_PREDICATE_BOARD).read_text(encoding="utf-8"))
    assert predicate_board["predicates"]["same_head_counted_reentry_blocked"] is False
    assert predicate_board["predicates"]["gate_d_closed"] is False
    assert "may reflect downstream lawful receipts" in packet["claim_boundary"]
