from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_successor_master_orchestrator_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_successor_master_orchestrator_reflects_gate_e_open_after_gate_e_screen(tmp_path: Path) -> None:
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
    for rel, payload in (
        (
            tranche.lane_a_exec.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": "PASS__LANE_A_PROMOTED_SURVIVOR_FULL_EXECUTION",
                "same_head_counted_reentry_admissible_now": False,
                "gate_d_reopened": False,
                "gate_e_open": False,
            },
        ),
        (
            tranche.lane_a_exec.OUTPUT_SCORECARD,
            {"status": "PASS", "subject_head": subject_head, "execution_status": "PASS__LANE_A_PROMOTED_SURVIVOR_FULL_EXECUTION"},
        ),
        (
            tranche.lane_b_hydration.OUTPUT_HYDRATION_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": "PASS__LANE_B_STAGE_PACK_HYDRATION_EXECUTED",
                "lane_b_case_execution_available_after_hydration": True,
                "same_head_counted_reentry_admissible_now": False,
                "gate_d_reopened": False,
                "gate_e_open": False,
            },
        ),
        (
            tranche.lane_b_exec.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": "PASS__LANE_B_FAMILY_LEVEL_BRIDGE_HARNESS_EXECUTED",
                "same_head_counted_reentry_admissible_now": False,
                "gate_d_reopened": False,
                "gate_e_open": False,
            },
        ),
        (
            tranche.lane_b_exec.OUTPUT_SCORECARD,
            {"status": "PASS", "subject_head": subject_head, "execution_status": "PASS__LANE_B_FAMILY_LEVEL_BRIDGE_HARNESS_EXECUTED"},
        ),
        (
            tranche.lane_b_exec.OUTPUT_COMPARATIVE_PACKET,
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
        ),
        (
            tranche.cross_lane_screen.OUTPUT_SCREENING_PACKET,
            {"status": "PASS", "subject_head": subject_head, "execution_status": "PASS__CROSS_LANE_REENTRY_PREP_SCREEN_EXECUTED"},
        ),
        (
            tranche.cross_lane_screen.OUTPUT_RECEIPT,
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
        ),
        (
            tranche.prep_packet_tranche.OUTPUT_PACKET,
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
        ),
        (
            tranche.prep_packet_tranche.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": "PASS__SUCCESSOR_REENTRY_PREP_PACKET_AUTHORED",
                "successor_reentry_prep_packet_authored": True,
                "same_head_counted_reentry_admissible_now": False,
                "gate_d_reopened": False,
                "gate_e_open": False,
            },
        ),
        (
            tranche.admissibility_screen.OUTPUT_PACKET,
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
        ),
        (
            tranche.admissibility_screen.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": "PASS__SUCCESSOR_GATE_D_REENTRY_ADMISSIBILITY_SCREEN_EXECUTED",
                "narrow_successor_gate_d_admissibility_review_authorized": True,
                "same_head_counted_reentry_admissible_now": False,
                "gate_d_reopened": False,
                "gate_e_open": False,
            },
        ),
        (
            tranche.narrow_review.OUTPUT_PACKET,
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
        ),
        (
            tranche.narrow_review.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": "PASS__SUCCESSOR_GATE_D_NARROW_ADMISSIBILITY_REVIEW_CONVENED",
                "narrow_successor_gate_d_admissibility_confirmed": True,
                "same_head_counted_reentry_admissible_now": False,
                "gate_d_reopened": False,
                "gate_e_open": False,
            },
        ),
        (
            tranche.severity_wave.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": tranche.severity_wave.EXECUTION_STATUS,
                "severity_escalation_route_consequence_wave_closed": True,
            },
        ),
        (
            tranche.anti_selection_wave.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": tranche.anti_selection_wave.EXECUTION_STATUS,
                "anti_selection_wave_beyond_reserve_closed": True,
            },
        ),
        (
            tranche.family_side_closure_wave.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": tranche.family_side_closure_wave.EXECUTION_STATUS,
                "anti_selection_wave_beyond_reserve_closed": True,
                "family_side_anti_selection_defect_closed": True,
                "bounded_defects_remaining": [],
            },
        ),
        (
            tranche.third_surface_wave.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": tranche.third_surface_wave.EXECUTION_STATUS,
                "third_surface_breadth_witness_closed": True,
            },
        ),
        (
            tranche.full_auth_screen.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": tranche.full_auth_screen.EXECUTION_STATUS,
                "full_successor_gate_d_readjudication_authorization_screen_executed": True,
                "full_successor_gate_d_readjudication_authorized_now": True,
                "full_successor_gate_d_readjudication_authorization_screen_status": tranche.full_auth_screen.STATUS_AUTHORIZED,
                "next_lawful_move": tranche.full_auth_screen.NEXT_MOVE_AUTHORIZED,
            },
        ),
        (
            tranche.full_readjudication.OUTPUT_RECEIPT,
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
        ),
        (
            tranche.gate_e_monitor.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": tranche.gate_e_monitor.EXECUTION_STATUS,
                "gate_e_lawful_consideration_authorized_now": True,
                "gate_e_open": False,
                "next_lawful_move": tranche.gate_e_monitor.NEXT_LAWFUL_MOVE,
            },
        ),
        (
            tranche.gate_e_scope.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": tranche.gate_e_scope.EXECUTION_STATUS,
                "gate_e_admissibility_screen_authorized_now": True,
                "gate_e_open": False,
                "next_lawful_move": tranche.gate_e_scope.NEXT_LAWFUL_MOVE,
            },
        ),
        (
            tranche.gate_e_audit.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": tranche.gate_e_audit.EXECUTION_STATUS,
                "post_clear_live_authority_contradiction_free": True,
                "next_lawful_move": "RECONVENE_GATE_E_ADMISSIBILITY_SCREEN__POST_BINDING_CONFIRMATION",
            },
        ),
        (
            tranche.gate_e_screen.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": tranche.gate_e_screen.EXECUTION_STATUS,
                "screen_outcome": tranche.gate_e_screen.OUTCOME_OPEN,
                "gate_e_open": True,
                "next_lawful_move": tranche.gate_e_screen.NEXT_LAWFUL_MOVE_OPEN,
            },
        ),
        (
            tranche.gate_e_binding_packet.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": tranche.gate_e_binding_packet.EXECUTION_STATUS,
                tranche.gate_e_binding_packet.PREDICATE_GATE_E_BINDING: True,
                tranche.gate_e_binding_packet.ARTIFACT_READY_PREDICATE: True,
                "next_lawful_move": tranche.gate_e_binding_packet.NEXT_LAWFUL_MOVE,
            },
        ),
        (
            tranche.gate_e_binding_screen.OUTPUT_RECEIPT,
            {
                "status": "PASS",
                "subject_head": subject_head,
                "execution_status": tranche.gate_e_binding_screen.EXECUTION_STATUS,
                "gate_e_binding_confirmed": True,
                tranche.gate_e_binding_packet.PREDICATE_GATE_E_BINDING: True,
                "next_lawful_move": tranche.gate_e_binding_screen.NEXT_MOVE_CONFIRMED,
            },
        ),
    ):
        _write_json(reports / rel, payload)

    # Optional packets expected when paired receipts are supplied.
    for rel in (
        tranche.severity_wave.OUTPUT_PACKET,
        tranche.anti_selection_wave.OUTPUT_PACKET,
        tranche.family_side_closure_wave.OUTPUT_PACKET,
        tranche.third_surface_wave.OUTPUT_PACKET,
        tranche.full_auth_screen.OUTPUT_PACKET,
    ):
        _write_json(reports / rel, {"status": "PASS", "subject_head": subject_head})

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
        gate_e_monitor_receipt_path=reports / tranche.gate_e_monitor.OUTPUT_RECEIPT,
        gate_e_scope_receipt_path=reports / tranche.gate_e_scope.OUTPUT_RECEIPT,
        gate_e_audit_receipt_path=reports / tranche.gate_e_audit.OUTPUT_RECEIPT,
        gate_e_screen_receipt_path=reports / tranche.gate_e_screen.OUTPUT_RECEIPT,
        gate_e_binding_packet_receipt_path=reports / tranche.gate_e_binding_packet.OUTPUT_RECEIPT,
        gate_e_binding_screen_receipt_path=reports / tranche.gate_e_binding_screen.OUTPUT_RECEIPT,
        reports_root=reports,
    )

    assert result["status"] == "PASS"
    assert result["current_branch_posture"] == tranche.GATE_E_OPEN_POSTURE
    assert result["next_lawful_move"] == tranche.gate_e_screen.NEXT_LAWFUL_MOVE_OPEN

    receipt = json.loads((reports / tranche.OUTPUT_RECEIPT).read_text(encoding="utf-8"))
    predicate_board = json.loads((reports / tranche.OUTPUT_PREDICATE_BOARD).read_text(encoding="utf-8"))
    blocker_ledger = json.loads((reports / tranche.OUTPUT_BLOCKER_LEDGER).read_text(encoding="utf-8"))
    assert receipt["gate_e_open"] is True
    assert predicate_board["predicates"]["gate_e_open"] is True
    assert blocker_ledger["current_authority_scope"] == tranche.GATE_E_OPEN_POSTURE
