from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_gate_e_precondition_monitor_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_gate_e_precondition_monitor_authorizes_consideration_but_keeps_gate_closed(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    subject_head = tranche.full_readjudication.setup_tranche.EXPECTED_SUBJECT_HEAD

    _write_json(
        reports / tranche.full_readjudication.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "readjudication_outcome": tranche.full_readjudication.OUTCOME_CLEARED,
            "gate_d_reopened": True,
            "gate_e_open": False,
        },
    )
    _write_json(reports / tranche.post_clear_branch_law.OUTPUT_PACKET, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / tranche.post_clear_branch_law.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "gate_d_cleared_on_successor_line": True,
        },
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

    result = tranche.run(
        full_readjudication_receipt_path=reports / tranche.full_readjudication.OUTPUT_RECEIPT,
        post_clear_packet_path=reports / tranche.post_clear_branch_law.OUTPUT_PACKET,
        post_clear_receipt_path=reports / tranche.post_clear_branch_law.OUTPUT_RECEIPT,
        supersession_note_path=reports / tranche.supersession_note.OUTPUT_NOTE,
        supersession_receipt_path=reports / tranche.supersession_note.OUTPUT_RECEIPT,
        reports_root=reports,
    )

    assert result["status"] == "PASS"
    assert result["gate_e_lawful_consideration_authorized_now"] is True
    assert result["gate_e_open"] is False

    receipt = json.loads((reports / tranche.OUTPUT_RECEIPT).read_text(encoding="utf-8"))
    assert receipt["monitor_outcome"] == tranche.MONITOR_OUTCOME
    assert receipt["next_lawful_move"] == tranche.NEXT_LAWFUL_MOVE
