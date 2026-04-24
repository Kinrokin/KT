from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_successor_full_gate_d_readjudication_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_successor_full_gate_d_readjudication_clears_gate_d_when_successor_bundle_is_closed(tmp_path: Path) -> None:
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
            "branch_truth": {"controls_preserved": True},
        },
    )
    _write_json(
        reports / "cohort0_gate_d_reentry_block_contract.json",
        {"status": "PASS", "subject_head": subject_head, "reentry_status": "BLOCKED__CURRENT_LANE_HARDENED_CEILING"},
    )
    _write_json(
        reports / "cohort0_successor_gate_d_readjudication_manifest.json",
        {"status": "PASS", "subject_head": subject_head, "execution_status": "AUTHORIZED__NOT_EXECUTED"},
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
                "same_head_comparator_mode": "LOCKED__STATIC_ALPHA_COMPARATOR",
                "counted_boundary_status": "BLOCKED__CURRENT_LANE_HARDENED_CEILING",
                "fixed_harness_global_totals": {
                    "forced_wrong_route_total_cost": 46.461,
                    "witness_ablation_total_cost": 34.261,
                    "static_hold_control_total_cost": 0.0,
                },
            },
            "reserve_challenge_closure_section": {"reserve_challenges_pass": True},
            "lane_a_evidence_spine": {
                "promoted_survivor_ids": ["A", "B"],
                "reserve_challenge_summary": {"bridge_hold": True},
            },
            "lane_b_evidence_spine": {
                "hydrated_payload_provenance": {"visible_case_count": 8, "held_out_case_count": 2},
                "reserve_challenge_summary": {"bridge_reason_exact_accuracy": 1.0},
                "family_distinctness_and_novelty_support": {"rejected_overlap_items": []},
            },
        },
    )
    _write_json(
        reports / tranche.lane_a_exec.OUTPUT_SCORECARD,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "full_bridge_hold": True,
            "local_route_consequence_signal_nonzero": True,
            "masked_companion_metrics": {"selected_bridge_reason_exact_accuracy": 1.0},
            "full_panel_metrics": {
                "action_accuracy": 1.0,
                "why_not_accuracy": 1.0,
                "selected_bridge_reason_exact_accuracy": 1.0,
                "selected_bridge_reason_admissible_accuracy": 1.0,
                "total_wrong_route_cost": 11.054,
                "total_wrong_static_hold_cost": 8.358,
            },
        },
    )
    _write_json(
        reports / tranche.lane_b_exec.OUTPUT_SCORECARD,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "hydrated_family_count": 2,
            "overall_metrics": {
                "action_accuracy": 1.0,
                "bridge_reason_exact_accuracy": 1.0,
                "bridge_reason_admissible_accuracy": 1.0,
                "route_consequence_visible_rate": 1.0,
                "selected_adapter_alignment_rate": 1.0,
            },
            "family_metrics": [],
        },
    )
    _write_json(
        reports / tranche.lane_b_exec.OUTPUT_COMPARATIVE_PACKET,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "comparative_read": {
                "lane_b_now_executed_on_materially_distinct_family_surface": True,
                "dominance_surface_broadening_visible": True,
            },
        },
    )
    _write_json(
        reports / tranche.family_side_closure_wave.OUTPUT_PACKET,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "anti_selection_wave_beyond_reserve_closed": True,
            "family_side_anti_selection_defect_closed": True,
            "overall_metrics": {
                "selected_bridge_reason_exact_accuracy": 1.0,
                "selected_bridge_reason_admissible_accuracy": 1.0,
                "route_consequence_visible_rate": 1.0,
            },
            "admitted_family_ids": ["AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "STRATEGIST_CONSEQUENCE_CHAIN"],
            "bounded_defects_remaining": [],
        },
    )
    _write_json(
        reports / tranche.family_side_closure_wave.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": tranche.family_side_closure_wave.EXECUTION_STATUS,
        },
    )
    _write_json(
        reports / tranche.severity_wave.OUTPUT_PACKET,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "severity_escalation_route_consequence_wave_closed": True,
            "route_consequence_remains_nonzero_under_severity": True,
            "static_hold_control_stays_clean_under_severity": True,
            "severity_escalated_totals": {
                "forced_wrong_route_total_cost": 62.7,
                "witness_ablation_total_cost": 44.5,
                "static_hold_control_total_cost": 0.0,
            },
        },
    )
    _write_json(
        reports / tranche.severity_wave.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": tranche.severity_wave.EXECUTION_STATUS,
        },
    )
    _write_json(
        reports / tranche.third_surface_wave.OUTPUT_PACKET,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "third_surface_breadth_witness_closed": True,
            "third_surface_candidate": {
                "novelty_gate_pass": True,
                "distinct_from_promoted_family_lane": True,
                "current_ring_overlap_detected": False,
                "legacy_ring_overlap_detected": False,
            },
            "third_surface_reserve_metrics": {
                "bridge_reason_exact_accuracy": 1.0,
                "bridge_reason_admissible_accuracy": 1.0,
                "route_consequence_visible_rate": 1.0,
            },
        },
    )
    _write_json(
        reports / tranche.third_surface_wave.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": tranche.third_surface_wave.EXECUTION_STATUS,
        },
    )
    _write_json(
        reports / tranche.full_auth_screen.OUTPUT_PACKET,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "full_successor_gate_d_readjudication_authorization_screen_status": tranche.full_auth_screen.STATUS_AUTHORIZED,
            "remaining_authorization_predicates": [],
            "remaining_bounded_defects": [],
        },
    )
    _write_json(
        reports / tranche.full_auth_screen.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": tranche.full_auth_screen.EXECUTION_STATUS,
            "full_successor_gate_d_readjudication_authorized_now": True,
        },
    )

    result = tranche.run(
        verdict_packet_path=reports / "cohort0_gate_d_hardened_ceiling_verdict_packet.json",
        reentry_block_path=reports / "cohort0_gate_d_reentry_block_contract.json",
        readjudication_manifest_path=reports / "cohort0_successor_gate_d_readjudication_manifest.json",
        prep_packet_path=reports / tranche.prep_packet_tranche.OUTPUT_PACKET,
        lane_a_scorecard_path=reports / tranche.lane_a_exec.OUTPUT_SCORECARD,
        lane_b_scorecard_path=reports / tranche.lane_b_exec.OUTPUT_SCORECARD,
        cross_lane_comparative_packet_path=reports / tranche.lane_b_exec.OUTPUT_COMPARATIVE_PACKET,
        family_side_closure_packet_path=reports / tranche.family_side_closure_wave.OUTPUT_PACKET,
        family_side_closure_receipt_path=reports / tranche.family_side_closure_wave.OUTPUT_RECEIPT,
        severity_packet_path=reports / tranche.severity_wave.OUTPUT_PACKET,
        severity_receipt_path=reports / tranche.severity_wave.OUTPUT_RECEIPT,
        third_surface_packet_path=reports / tranche.third_surface_wave.OUTPUT_PACKET,
        third_surface_receipt_path=reports / tranche.third_surface_wave.OUTPUT_RECEIPT,
        full_auth_packet_path=reports / tranche.full_auth_screen.OUTPUT_PACKET,
        full_auth_receipt_path=reports / tranche.full_auth_screen.OUTPUT_RECEIPT,
        reports_root=reports,
    )

    assert result["status"] == "PASS"
    assert result["readjudication_outcome"] == tranche.OUTCOME_CLEARED
    assert result["gate_d_officially_cleared"] is True
    assert result["gate_d_reopened"] is True
    assert result["gate_e_open"] is False

    receipt = json.loads((reports / tranche.OUTPUT_RECEIPT).read_text(encoding="utf-8"))
    assert receipt["same_head_counted_reentry_admissible_now"] is True
    assert receipt["gate_d_officially_cleared"] is True
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_CLEARED
