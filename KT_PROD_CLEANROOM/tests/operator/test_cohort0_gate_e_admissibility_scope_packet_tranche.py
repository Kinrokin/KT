from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_gate_e_admissibility_scope_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_gate_e_scope_packet_authorizes_admissibility_screen_but_keeps_gate_closed(tmp_path: Path) -> None:
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
        orchestrator_packet_path=reports / "cohort0_successor_master_orchestrator_packet.json",
        orchestrator_receipt_path=reports / "cohort0_successor_master_orchestrator_receipt.json",
        reports_root=reports,
    )

    assert result["status"] == "PASS"
    assert result["scope_outcome"] == tranche.OUTCOME_SCREEN_AUTHORIZED
    assert result["gate_e_admissibility_screen_authorized_now"] is True
    assert result["gate_e_open"] is False

    receipt = json.loads((reports / tranche.OUTPUT_RECEIPT).read_text(encoding="utf-8"))
    assert receipt["next_lawful_move"] == tranche.NEXT_LAWFUL_MOVE
