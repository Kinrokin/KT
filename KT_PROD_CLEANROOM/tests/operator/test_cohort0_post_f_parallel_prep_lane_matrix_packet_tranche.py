from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_parallel_prep_lane_matrix_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_parallel_prep_lane_matrix_keeps_authoritative_lane_centralized(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(
        reports / "cohort0_post_f_track_03_human_review_packet.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_03_human_review_packet.v1",
            "status": "PASS",
            "authority_header": {
                "canonical_authority_branch": "main",
                "working_branch": tranche.REQUIRED_WORKING_BRANCH,
                "working_branch_non_authoritative_until_protected_merge": True,
                "gate_d_cleared_on_successor_line": True,
                "gate_e_open_on_successor_line": True,
                "gate_f_narrow_wedge_confirmed": True,
                "gate_f_open": False,
                "post_f_reaudit_passed": True,
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_human_review_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_03_human_review_receipt.v1",
            "status": "PASS",
            "working_branch_non_authoritative_until_protected_merge": True,
            "subject_head": "track03-head",
            "next_lawful_move": tranche.AUTHORITATIVE_NEXT_MOVE,
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_WORKING_BRANCH)
    monkeypatch.setattr(tranche, "_current_head", lambda root: "parallel-matrix-head")
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    result = tranche.run(
        reports_root=reports,
        human_review_packet_path=reports / "cohort0_post_f_track_03_human_review_packet.json",
        human_review_receipt_path=reports / "cohort0_post_f_track_03_human_review_receipt.json",
    )

    assert result["matrix_outcome"] == tranche.MATRIX_OUTCOME
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert packet["authoritative_lane_lock"]["parallel_prep_lanes_may_mutate_live_truth"] is False
    assert len(packet["parallel_lanes"]) == 4
    assert receipt["parallel_lane_count"] == 4
    assert receipt["next_lawful_move"] == tranche.AUTHORITATIVE_NEXT_MOVE
