from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_gate_e_post_clear_contradiction_audit_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_gate_e_post_clear_contradiction_audit_passes_on_live_clear_scope_stack(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    subject_head = tranche.full_readjudication.setup_tranche.EXPECTED_SUBJECT_HEAD

    _write_json(
        reports / tranche.full_readjudication.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "readjudication_outcome": tranche.full_readjudication.OUTCOME_CLEARED,
            "same_head_counted_reentry_admissible_now": True,
            "gate_d_reopened": True,
            "gate_e_open": False,
        },
    )
    _write_json(
        reports / tranche.post_clear_branch_law.OUTPUT_PACKET,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "canonical_live_branch_status": {
                "gate_d_cleared_on_successor_line": True,
                "gate_d_reopened": True,
                "gate_e_open": False,
            },
        },
    )
    _write_json(
        reports / tranche.post_clear_branch_law.OUTPUT_RECEIPT,
        {"status": "PASS", "subject_head": subject_head, "gate_d_cleared_on_successor_line": True},
    )
    _write_json(reports / tranche.supersession_note.OUTPUT_NOTE, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / tranche.supersession_note.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "successor_line_supersedes_prior_same_head_failure_for_live_branch_posture": True,
        },
    )
    _write_json(reports / tranche.gate_e_monitor.OUTPUT_PACKET, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / tranche.gate_e_monitor.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "gate_e_lawful_consideration_authorized_now": True,
            "gate_e_open": False,
        },
    )
    _write_json(reports / tranche.gate_e_scope.OUTPUT_PACKET, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / tranche.gate_e_scope.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": tranche.gate_e_scope.EXECUTION_STATUS,
            "gate_e_admissibility_screen_authorized_now": True,
            "gate_e_open": False,
            "next_lawful_move": tranche.gate_e_scope.NEXT_LAWFUL_MOVE,
        },
    )
    _write_json(
        reports / "cohort0_successor_master_orchestrator_packet.json",
        {
            "status": "PASS",
            "subject_head": subject_head,
            "claim_nodes": [
                {
                    "node_id": "gate_e_precondition_monitor",
                    "status": "SATISFIED__POST_SUCCESSOR_GATE_D_CLEAR__STILL_GATE_E_CLOSED",
                },
                {
                    "node_id": "gate_e_admissibility_scope_packet",
                    "status": "SATISFIED__GATE_E_ADMISSIBILITY_SCREEN_AUTHORIZED__STILL_NOT_OPEN",
                },
            ],
        },
    )
    _write_json(
        reports / "cohort0_successor_master_orchestrator_receipt.json",
        {
            "status": "PASS",
            "subject_head": subject_head,
            "current_branch_posture": tranche.EXPECTED_CLEAR_POSTURE,
            "next_lawful_move": tranche.gate_e_scope.NEXT_LAWFUL_MOVE,
        },
    )
    _write_json(
        reports / "cohort0_successor_master_predicate_board.json",
        {
            "status": "PASS",
            "subject_head": subject_head,
            "predicates": {
                "same_head_counted_reentry_blocked": False,
                "gate_d_closed": False,
                "gate_e_closed": True,
                "gate_e_precondition_monitor_executed": True,
                "gate_e_admissibility_scope_packet_executed": True,
                "gate_e_admissibility_screen_authorized_now": True,
            },
        },
    )

    result = tranche.run(
        full_readjudication_receipt_path=reports / tranche.full_readjudication.OUTPUT_RECEIPT,
        post_clear_packet_path=reports / tranche.post_clear_branch_law.OUTPUT_PACKET,
        post_clear_receipt_path=reports / tranche.post_clear_branch_law.OUTPUT_RECEIPT,
        supersession_note_path=reports / tranche.supersession_note.OUTPUT_NOTE,
        supersession_receipt_path=reports / tranche.supersession_note.OUTPUT_RECEIPT,
        gate_e_monitor_packet_path=reports / tranche.gate_e_monitor.OUTPUT_PACKET,
        gate_e_monitor_receipt_path=reports / tranche.gate_e_monitor.OUTPUT_RECEIPT,
        gate_e_scope_packet_path=reports / tranche.gate_e_scope.OUTPUT_PACKET,
        gate_e_scope_receipt_path=reports / tranche.gate_e_scope.OUTPUT_RECEIPT,
        orchestrator_packet_path=reports / "cohort0_successor_master_orchestrator_packet.json",
        orchestrator_receipt_path=reports / "cohort0_successor_master_orchestrator_receipt.json",
        predicate_board_path=reports / "cohort0_successor_master_predicate_board.json",
        reports_root=reports,
    )

    assert result["status"] == "PASS"
    assert result["audit_outcome"] == tranche.OUTCOME_CLEAN_CLOSED
    assert result["post_clear_live_authority_contradiction_free"] is True
    receipt = json.loads((reports / tranche.OUTPUT_RECEIPT).read_text(encoding="utf-8"))
    assert receipt["remaining_open_contradictions"] == []
    assert receipt["next_lawful_move"] == tranche.NEXT_LAWFUL_MOVE


def test_gate_e_post_clear_contradiction_audit_passes_on_live_open_stack(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    subject_head = tranche.full_readjudication.setup_tranche.EXPECTED_SUBJECT_HEAD

    _write_json(
        reports / tranche.full_readjudication.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "readjudication_outcome": tranche.full_readjudication.OUTCOME_CLEARED,
            "same_head_counted_reentry_admissible_now": True,
            "gate_d_reopened": True,
            "gate_e_open": False,
        },
    )
    _write_json(
        reports / tranche.post_clear_branch_law.OUTPUT_PACKET,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "canonical_live_branch_status": {
                "gate_d_cleared_on_successor_line": True,
                "gate_d_reopened": True,
                "gate_e_open": False,
            },
        },
    )
    _write_json(
        reports / tranche.post_clear_branch_law.OUTPUT_RECEIPT,
        {"status": "PASS", "subject_head": subject_head, "gate_d_cleared_on_successor_line": True},
    )
    _write_json(reports / tranche.supersession_note.OUTPUT_NOTE, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / tranche.supersession_note.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "successor_line_supersedes_prior_same_head_failure_for_live_branch_posture": True,
        },
    )
    _write_json(reports / tranche.gate_e_monitor.OUTPUT_PACKET, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / tranche.gate_e_monitor.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "gate_e_lawful_consideration_authorized_now": True,
            "gate_e_open": False,
        },
    )
    _write_json(reports / tranche.gate_e_scope.OUTPUT_PACKET, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / tranche.gate_e_scope.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "execution_status": tranche.gate_e_scope.EXECUTION_STATUS,
            "gate_e_admissibility_screen_authorized_now": True,
            "gate_e_open": False,
            "next_lawful_move": tranche.gate_e_scope.NEXT_LAWFUL_MOVE,
        },
    )
    _write_json(
        reports / "cohort0_successor_master_orchestrator_packet.json",
        {
            "status": "PASS",
            "subject_head": subject_head,
            "claim_nodes": [
                {
                    "node_id": "gate_e_precondition_monitor",
                    "status": "SATISFIED__POST_SUCCESSOR_GATE_D_CLEAR__STILL_GATE_E_CLOSED",
                },
                {
                    "node_id": "gate_e_admissibility_scope_packet",
                    "status": "SATISFIED__GATE_E_ADMISSIBILITY_SCREEN_AUTHORIZED__STILL_NOT_OPEN",
                },
                {
                    "node_id": "gate_e_admissibility_screen",
                    "status": tranche.GATE_E_OPEN_SCREEN_STATUS,
                },
            ],
        },
    )
    _write_json(
        reports / "cohort0_successor_master_orchestrator_receipt.json",
        {
            "status": "PASS",
            "subject_head": subject_head,
            "current_branch_posture": tranche.GATE_E_OPEN_POSTURE,
            "gate_e_open": True,
            "next_lawful_move": tranche.GATE_E_OPEN_NEXT_MOVE,
        },
    )
    _write_json(
        reports / "cohort0_successor_master_predicate_board.json",
        {
            "status": "PASS",
            "subject_head": subject_head,
            "predicates": {
                "same_head_counted_reentry_blocked": False,
                "gate_d_closed": False,
                "gate_e_open": True,
                "gate_e_closed": False,
                "gate_e_precondition_monitor_executed": True,
                "gate_e_admissibility_scope_packet_executed": True,
                "gate_e_admissibility_screen_authorized_now": True,
                "gate_e_admissibility_screen_executed": True,
            },
        },
    )

    result = tranche.run(
        full_readjudication_receipt_path=reports / tranche.full_readjudication.OUTPUT_RECEIPT,
        post_clear_packet_path=reports / tranche.post_clear_branch_law.OUTPUT_PACKET,
        post_clear_receipt_path=reports / tranche.post_clear_branch_law.OUTPUT_RECEIPT,
        supersession_note_path=reports / tranche.supersession_note.OUTPUT_NOTE,
        supersession_receipt_path=reports / tranche.supersession_note.OUTPUT_RECEIPT,
        gate_e_monitor_packet_path=reports / tranche.gate_e_monitor.OUTPUT_PACKET,
        gate_e_monitor_receipt_path=reports / tranche.gate_e_monitor.OUTPUT_RECEIPT,
        gate_e_scope_packet_path=reports / tranche.gate_e_scope.OUTPUT_PACKET,
        gate_e_scope_receipt_path=reports / tranche.gate_e_scope.OUTPUT_RECEIPT,
        orchestrator_packet_path=reports / "cohort0_successor_master_orchestrator_packet.json",
        orchestrator_receipt_path=reports / "cohort0_successor_master_orchestrator_receipt.json",
        predicate_board_path=reports / "cohort0_successor_master_predicate_board.json",
        reports_root=reports,
    )

    assert result["status"] == "PASS"
    assert result["audit_outcome"] == tranche.OUTCOME_CLEAN_OPEN
    assert result["post_clear_live_authority_contradiction_free"] is True
    receipt = json.loads((reports / tranche.OUTPUT_RECEIPT).read_text(encoding="utf-8"))
    assert receipt["remaining_open_contradictions"] == []
    assert receipt["next_lawful_move"] == tranche.GATE_E_OPEN_NEXT_MOVE
