from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_successor_gate_d_post_clear_supersession_note_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_post_clear_supersession_note_preserves_history_and_updates_live_authority(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    subject_head = tranche.full_readjudication.setup_tranche.EXPECTED_SUBJECT_HEAD

    _write_json(reports / tranche.post_clear_branch_law.OUTPUT_PACKET, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / tranche.post_clear_branch_law.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "gate_d_cleared_on_successor_line": True,
        },
    )
    _write_json(
        reports / tranche.full_readjudication.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "readjudication_outcome": tranche.full_readjudication.OUTCOME_CLEARED,
        },
    )
    _write_json(reports / "cohort0_successor_master_orchestrator_receipt.json", {"status": "PASS", "subject_head": subject_head})
    for rel in (
        tranche.DEFAULT_HISTORICAL_STATUS_SECTION_REL,
        tranche.DEFAULT_HISTORICAL_BLOCKER_BOARD_REL,
        tranche.DEFAULT_HISTORICAL_STATUS_AUDIT_REL,
    ):
        _write_json(tmp_path / rel, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        tmp_path / tranche.DEFAULT_HISTORICAL_OVERLAY_REL,
        {"schema_id": "kt.current_campaign_state_overlay.v1", "subject_head": subject_head},
    )

    result = tranche.run(
        post_clear_packet_path=reports / tranche.post_clear_branch_law.OUTPUT_PACKET,
        post_clear_receipt_path=reports / tranche.post_clear_branch_law.OUTPUT_RECEIPT,
        full_readjudication_receipt_path=reports / tranche.full_readjudication.OUTPUT_RECEIPT,
        orchestrator_receipt_path=reports / "cohort0_successor_master_orchestrator_receipt.json",
        historical_status_section_path=tmp_path / tranche.DEFAULT_HISTORICAL_STATUS_SECTION_REL,
        historical_blocker_board_path=tmp_path / tranche.DEFAULT_HISTORICAL_BLOCKER_BOARD_REL,
        historical_status_audit_path=tmp_path / tranche.DEFAULT_HISTORICAL_STATUS_AUDIT_REL,
        historical_overlay_path=tmp_path / tranche.DEFAULT_HISTORICAL_OVERLAY_REL,
        reports_root=reports,
    )

    assert result["status"] == "PASS"
    assert result["historical_failure_not_erased"] is True
    assert result["successor_line_supersedes_prior_same_head_failure_for_live_branch_posture"] is True

    receipt = json.loads((reports / tranche.OUTPUT_RECEIPT).read_text(encoding="utf-8"))
    assert receipt["historical_failure_not_erased"] is True
    assert receipt["successor_line_supersedes_prior_same_head_failure_for_live_branch_posture"] is True


def test_post_clear_supersession_note_tracks_open_state_authority_when_gate_e_is_open(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    subject_head = tranche.full_readjudication.setup_tranche.EXPECTED_SUBJECT_HEAD

    _write_json(reports / tranche.post_clear_branch_law.OUTPUT_PACKET, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        reports / tranche.post_clear_branch_law.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "gate_d_cleared_on_successor_line": True,
        },
    )
    _write_json(
        reports / tranche.full_readjudication.OUTPUT_RECEIPT,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "readjudication_outcome": tranche.full_readjudication.OUTCOME_CLEARED,
        },
    )
    _write_json(
        reports / "cohort0_successor_master_orchestrator_receipt.json",
        {
            "status": "PASS",
            "subject_head": subject_head,
            "current_branch_posture": tranche.post_clear_branch_law.OPEN_POSTURE,
            "next_lawful_move": tranche.GATE_E_OPEN_NEXT_MOVE,
        },
    )
    _write_json(
        reports / "cohort0_gate_e_admissibility_screen_receipt.json",
        {
            "status": "PASS",
            "subject_head": subject_head,
            "screen_outcome": tranche.GATE_E_OPEN_OUTCOME,
            "gate_e_open": True,
            "next_lawful_move": tranche.GATE_E_OPEN_NEXT_MOVE,
        },
    )
    for rel in (
        tranche.DEFAULT_HISTORICAL_STATUS_SECTION_REL,
        tranche.DEFAULT_HISTORICAL_BLOCKER_BOARD_REL,
        tranche.DEFAULT_HISTORICAL_STATUS_AUDIT_REL,
    ):
        _write_json(tmp_path / rel, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        tmp_path / tranche.DEFAULT_HISTORICAL_OVERLAY_REL,
        {"schema_id": "kt.current_campaign_state_overlay.v1", "subject_head": subject_head},
    )

    result = tranche.run(
        post_clear_packet_path=reports / tranche.post_clear_branch_law.OUTPUT_PACKET,
        post_clear_receipt_path=reports / tranche.post_clear_branch_law.OUTPUT_RECEIPT,
        full_readjudication_receipt_path=reports / tranche.full_readjudication.OUTPUT_RECEIPT,
        orchestrator_receipt_path=reports / "cohort0_successor_master_orchestrator_receipt.json",
        gate_e_screen_receipt_path=reports / "cohort0_gate_e_admissibility_screen_receipt.json",
        historical_status_section_path=tmp_path / tranche.DEFAULT_HISTORICAL_STATUS_SECTION_REL,
        historical_blocker_board_path=tmp_path / tranche.DEFAULT_HISTORICAL_BLOCKER_BOARD_REL,
        historical_status_audit_path=tmp_path / tranche.DEFAULT_HISTORICAL_STATUS_AUDIT_REL,
        historical_overlay_path=tmp_path / tranche.DEFAULT_HISTORICAL_OVERLAY_REL,
        reports_root=reports,
    )

    assert result["status"] == "PASS"
    receipt = json.loads((reports / tranche.OUTPUT_RECEIPT).read_text(encoding="utf-8"))
    note = json.loads((reports / tranche.OUTPUT_NOTE).read_text(encoding="utf-8"))
    assert receipt["next_lawful_move"] == tranche.GATE_E_OPEN_NEXT_MOVE
    assert str(reports / "cohort0_gate_e_admissibility_screen_receipt.json").replace("\\", "/") in [
        item.replace("\\", "/") for item in note["authoritative_live_surfaces_now"]
    ]
