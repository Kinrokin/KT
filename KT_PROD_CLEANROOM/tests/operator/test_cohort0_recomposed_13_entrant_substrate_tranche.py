from __future__ import annotations

from pathlib import Path

from tools.operator import cohort0_recomposed_13_entrant_substrate_tranche as tranche


def test_recomposed_followthrough_marks_tournament_ready() -> None:
    packet = tranche._recomposed_followthrough(
        prep_packet={"prep_posture": "TOURNAMENT_EXECUTION_READY", "next_lawful_move": "EXECUTE_TOURNAMENT"},
        updated_ids=["lobe.p2.v1", "lobe.child.v1"],
        control_ids=["lobe.alpha.v1"],
        reexport_contract_path=Path("D:/tmp/reexport.json"),
        prep_packet_path=Path("D:/tmp/prep.json"),
    )
    assert packet["status"] == "PASS"
    assert packet["followthrough_posture"] == "RECOMPOSED_13_ENTRANT_SUBSTRATE_BOUND__TOURNAMENT_EXECUTION_READY"
    assert packet["tournament_rerun_admissible"] is True
    assert packet["next_lawful_move"] == "EXECUTE_RECOMPOSED_TOURNAMENT"


def test_recomposed_followthrough_preserves_blockers_when_not_ready() -> None:
    packet = tranche._recomposed_followthrough(
        prep_packet={"prep_posture": "BREAK_AND_COUNTERPRESSURE_READY__ENTRANT_AUTHORITY_BLOCKED", "next_lawful_move": "IMPORT_OR_REEXPORT_EVAL_REPORTS_AND_REEMIT_TOURNAMENT_PREP", "blockers": ["X"]},
        updated_ids=["lobe.p2.v1", "lobe.child.v1"],
        control_ids=["lobe.alpha.v1"],
        reexport_contract_path=Path("D:/tmp/reexport.json"),
        prep_packet_path=Path("D:/tmp/prep.json"),
    )
    assert packet["tournament_rerun_admissible"] is False
    assert packet["blockers"] == ["X"]


def test_extract_prep_packet_accepts_current_prep_key() -> None:
    packet = tranche._extract_prep_packet({"prep_packet": {"prep_posture": "TOURNAMENT_EXECUTION_READY"}})
    assert packet["prep_posture"] == "TOURNAMENT_EXECUTION_READY"


def test_extract_prep_packet_accepts_legacy_tournament_key() -> None:
    packet = tranche._extract_prep_packet({"tournament_prep_packet": {"prep_posture": "TOURNAMENT_EXECUTION_READY"}})
    assert packet["prep_posture"] == "TOURNAMENT_EXECUTION_READY"
