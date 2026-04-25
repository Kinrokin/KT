from __future__ import annotations

from tools.operator import cohort0_gate_f_common as gate_f_common
from tools.operator import cohort0_post_f_broad_canonical_reaudit_tranche as post_f_reaudit
from tools.operator import cohort0_successor_master_orchestrator_tranche as tranche


def test_successor_master_orchestrator_reflects_post_f_product_truth_and_reaudit() -> None:
    predicate_board = {
        "predicates": {
            "gate_e_open": True,
            "gate_d_reopened": True,
            "same_head_counted_reentry_admissible_now": True,
            "full_successor_gate_d_readjudication_authorized_now": True,
            "gate_f_narrow_wedge_confirmed": True,
            "gate_f_live_product_truth_frozen": True,
            "gate_f_open": False,
            "minimum_path_complete_through_gate_f": True,
            "post_f_broad_canonical_reaudit_passed": True,
        }
    }
    blocker_ledger = {
        "next_parallel_evidence_nodes_ready_now": [],
        "ranked_missing_authorization_predicates": [],
    }

    packet = tranche._build_packet(
        blocker_ledger=blocker_ledger,
        predicate_board=predicate_board,
        severity_receipt=None,
        anti_selection_receipt=None,
        family_side_closure_receipt=None,
        third_surface_receipt=None,
        full_auth_screen_receipt={
            "full_successor_gate_d_readjudication_authorization_screen_status": tranche.full_auth_screen.STATUS_AUTHORIZED
        },
        full_readjudication_receipt={"next_lawful_move": tranche.full_readjudication.NEXT_MOVE_CLEARED},
        gate_e_monitor_receipt=None,
        gate_e_scope_receipt=None,
        gate_e_audit_receipt=None,
        gate_e_screen_receipt={"gate_e_open": True, "next_lawful_move": tranche.gate_e_screen.NEXT_LAWFUL_MOVE_OPEN},
        gate_e_binding_packet_receipt=None,
        gate_e_binding_screen_receipt=None,
        gate_f_review_receipt={"gate_f_narrow_wedge_confirmed": True, "gate_f_open": False},
        gate_f_live_product_truth_receipt={"current_product_posture": gate_f_common.GATE_F_CONFIRMED_POSTURE},
        post_f_reaudit_receipt={
            "reaudit_outcome": post_f_reaudit.OUTCOME_PASS,
            "next_lawful_move": gate_f_common.NEXT_MOVE_POST_F_EXPANSION,
        },
        source_refs={
            "predicate_board_ref": "predicate.json",
            "blocker_ledger_ref": "blocker.json",
            "lane_a_receipt_ref": "lane_a.json",
            "lane_b_hydration_receipt_ref": "lane_b_hydration.json",
            "lane_b_receipt_ref": "lane_b.json",
            "cross_lane_screen_receipt_ref": "cross_lane_screen.json",
            "prep_receipt_ref": "prep.json",
            "admissibility_screen_receipt_ref": "admissibility.json",
            "narrow_review_receipt_ref": "narrow_review.json",
        },
        subject_head="head-123",
    )
    receipt = tranche._build_receipt(packet=packet, subject_head="head-123")

    assert packet["current_branch_posture"] == tranche.GATE_E_OPEN_POSTURE
    assert packet["current_product_posture"] == gate_f_common.GATE_F_CONFIRMED_POSTURE
    assert packet["gate_f_narrow_wedge_confirmed"] is True
    assert packet["post_f_broad_canonical_reaudit_passed"] is True
    assert packet["next_lawful_move"] == gate_f_common.NEXT_MOVE_POST_F_EXPANSION
    assert receipt["current_product_posture"] == gate_f_common.GATE_F_CONFIRMED_POSTURE
    assert receipt["minimum_path_complete_through_gate_f"] is True
    assert receipt["post_f_broad_canonical_reaudit_passed"] is True
