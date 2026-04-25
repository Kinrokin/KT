from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_track_03_post_merge_closeout_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_post_merge_closeout_freezes_canonical_state_on_main(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(
        reports / "cohort0_post_f_track_03_protected_merge_and_canonical_promotion_decision_packet.json",
        {
            "schema_id": "decision-packet",
            "status": "PASS",
            "authority_header": {
                "gate_d_cleared_on_successor_line": True,
                "gate_e_open_on_successor_line": True,
                "gate_f_narrow_wedge_confirmed": True,
                "gate_f_open": False,
                "post_f_reaudit_passed": True,
            },
            "artifact_split_frozen": {
                "repo_merge_authoritative_truth_surfaces": ["a", "b"],
                "repo_merge_support_but_non_authoritative_surfaces": ["c"],
            },
            "package_promotion_lane_state": {
                "auto_promotion_candidate_count": 6,
                "review_approved_auto_skip_count": 3,
                "review_approved_out_of_scope_count": 2,
                "package_promotion_boundary": "explicit later step",
            },
            "post_merge_authoritative_fork": {
                "first_lane_to_promote": "truth_engine_contradiction_validator_scaffold",
                "ranked_prep_lane_promotions": [
                    {"lane_id": "truth_engine_contradiction_validator_scaffold"},
                    {"lane_id": "trust_zone_boundary_purification_scaffold"},
                ],
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_protected_merge_and_canonical_promotion_decision_receipt.json",
        {
            "schema_id": "decision-receipt",
            "status": "PASS",
            "decision_outcome": "MERGE_APPROVED__PACKAGE_PROMOTION_DEFERRED",
            "next_lawful_move": "EXECUTE_PROTECTED_MERGE_TO_MAIN__PACKAGE_PROMOTION_STILL_DEFERRED",
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: "main")
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_latest_first_parent_merge_commit", lambda root: "merge-sha")
    monkeypatch.setattr(tranche, "_git_commit_parents", lambda root, ref: ["merge-sha", "main-parent", "source-parent"])
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "source-parent")
    monkeypatch.setattr(tranche, "_git_message", lambda root, ref: "merge: canonicalize post-F Track 03 repo authority with package promotion deferred")

    result = tranche.run(
        reports_root=reports,
        decision_packet_path=reports / "cohort0_post_f_track_03_protected_merge_and_canonical_promotion_decision_packet.json",
        decision_receipt_path=reports / "cohort0_post_f_track_03_protected_merge_and_canonical_promotion_decision_receipt.json",
    )

    assert result["post_merge_status"] == tranche.POST_MERGE_STATUS
    snapshot = _load(reports / tranche.OUTPUT_SNAPSHOT)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert snapshot["track03_repo_authority_now_canonical"] is True
    assert snapshot["merge_commit"] == "merge-sha"
    assert snapshot["package_promotion_still_deferred"] is True
    assert snapshot["first_post_merge_authoritative_lane"] == "truth_engine_contradiction_validator_scaffold"
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
