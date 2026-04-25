from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_gate_e_admissibility_screen_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_gate_e_admissibility_screen_returns_bounded_defect_when_binding_bundle_missing(tmp_path: Path) -> None:
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
    _write_json(reports / tranche.post_clear_branch_law.OUTPUT_PACKET, {"status": "PASS", "subject_head": subject_head})
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
            "gate_e_admissibility_screen_authorized_now": True,
            "gate_e_open": False,
            "next_lawful_move": tranche.gate_e_scope.NEXT_LAWFUL_MOVE,
        },
    )
    _write_json(reports / tranche.gate_e_audit.OUTPUT_PACKET, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / tranche.gate_e_audit.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "post_clear_live_authority_contradiction_free": True,
        },
    )
    _write_json(reports / "cohort0_successor_master_orchestrator_packet.json", {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / "cohort0_successor_master_orchestrator_receipt.json",
        {
            "status": "PASS",
            "subject_head": subject_head,
            "current_branch_posture": tranche.EXPECTED_CLEAR_POSTURE,
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
        gate_e_audit_packet_path=reports / tranche.gate_e_audit.OUTPUT_PACKET,
        gate_e_audit_receipt_path=reports / tranche.gate_e_audit.OUTPUT_RECEIPT,
        orchestrator_packet_path=reports / "cohort0_successor_master_orchestrator_packet.json",
        orchestrator_receipt_path=reports / "cohort0_successor_master_orchestrator_receipt.json",
        reports_root=reports,
    )

    assert result["status"] == "PASS"
    assert result["screen_outcome"] == tranche.OUTCOME_BOUNDED_DEFECT
    assert result["named_bounded_defect_id"] == tranche.PREDICATE_GATE_E_BINDING
    assert result["gate_e_open"] is False

    ledger = json.loads((reports / tranche.OUTPUT_BLOCKER_LEDGER).read_text(encoding="utf-8"))
    receipt = json.loads((reports / tranche.OUTPUT_RECEIPT).read_text(encoding="utf-8"))
    assert ledger["ranked_missing_predicates"][0]["predicate_id"] == tranche.PREDICATE_GATE_E_BINDING
    assert receipt["next_lawful_move"] == tranche.NEXT_LAWFUL_MOVE_DEFECT


def test_gate_e_admissibility_screen_requires_binding_screen_not_just_binding_packet(tmp_path: Path) -> None:
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
    _write_json(reports / tranche.post_clear_branch_law.OUTPUT_PACKET, {"status": "PASS", "subject_head": subject_head})
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
            "gate_e_admissibility_screen_authorized_now": True,
            "gate_e_open": False,
            "next_lawful_move": tranche.gate_e_scope.NEXT_LAWFUL_MOVE,
        },
    )
    _write_json(reports / tranche.gate_e_audit.OUTPUT_PACKET, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / tranche.gate_e_audit.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "post_clear_live_authority_contradiction_free": True,
        },
    )
    _write_json(reports / "cohort0_successor_master_orchestrator_packet.json", {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / "cohort0_successor_master_orchestrator_receipt.json",
        {
            "status": "PASS",
            "subject_head": subject_head,
            "current_branch_posture": tranche.EXPECTED_CLEAR_POSTURE,
        },
    )
    _write_json(
        reports / tranche.gate_e_binding_packet.OUTPUT_PACKET,
        {
            "status": "PASS",
            "subject_head": subject_head,
            tranche.PREDICATE_GATE_E_BINDING: True,
        },
    )
    _write_json(
        reports / tranche.gate_e_binding_packet.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            tranche.PREDICATE_GATE_E_BINDING: True,
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
        gate_e_audit_packet_path=reports / tranche.gate_e_audit.OUTPUT_PACKET,
        gate_e_audit_receipt_path=reports / tranche.gate_e_audit.OUTPUT_RECEIPT,
        orchestrator_packet_path=reports / "cohort0_successor_master_orchestrator_packet.json",
        orchestrator_receipt_path=reports / "cohort0_successor_master_orchestrator_receipt.json",
        gate_e_binding_packet_path=reports / tranche.gate_e_binding_packet.OUTPUT_PACKET,
        gate_e_binding_receipt_path=reports / tranche.gate_e_binding_packet.OUTPUT_RECEIPT,
        reports_root=reports,
    )

    assert result["status"] == "PASS"
    assert result["screen_outcome"] == tranche.OUTCOME_BOUNDED_DEFECT
    assert result["gate_e_open"] is False

    receipt = json.loads((reports / tranche.OUTPUT_RECEIPT).read_text(encoding="utf-8"))
    assert receipt["next_lawful_move"] == tranche.NEXT_LAWFUL_MOVE_BINDING_SCREEN
