from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_track_03_protected_merge_and_canonical_promotion_decision_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_protected_merge_decision_approves_merge_and_defers_package_promotion(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"

    _write_json(
        reports / "cohort0_post_f_track_03_merge_and_promotion_prep_packet.json",
        {
            "schema_id": "prep-packet",
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
            "exact_promoted_artifact_set": {
                "package_internal_auto_promotion_set": [{"path": "reports/a.json"}],
                "package_internal_review_approved_but_auto_skipped": [{"path": "docs/b.md"}],
                "review_approved_but_outside_current_stage_and_promote_scope": ["KT E2E Lawful Commitment Superiority Playbook.md"],
            },
            "merge_gate_matrix": {"clean_branch_required_now": True},
            "post_merge_authoritative_fork": {"first_lane_to_promote": "truth_engine_contradiction_validator_scaffold"},
            "exact_post_merge_truth_update": {
                "package_promotion_still_requires_explicit_step": True,
                "package_promotion_boundary": "merge first",
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_merge_and_promotion_prep_receipt.json",
        {
            "schema_id": "prep-receipt",
            "status": "PASS",
            "next_lawful_move": "CONVENE_POST_F_TRACK_03_PROTECTED_MERGE_AND_CANONICAL_PROMOTION_DECISION",
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_human_review_verdict_receipt.json",
        {
            "schema_id": "review-receipt",
            "status": "PASS",
            "review_outcome": "APPROVE_AS_IS",
            "subject_head": "subject-sha",
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_WORKING_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "main-sha" if ref == "main" else "head-sha")
    monkeypatch.setattr(tranche, "_git_merge_base", lambda root, left, right: "main-sha")
    monkeypatch.setattr(
        tranche,
        "_git_diff_name_only",
        lambda root, left, right: ["KT_PROD_CLEANROOM/reports/x.json", "KT_PROD_CLEANROOM/tools/operator/y.py"],
    )

    result = tranche.run(
        reports_root=reports,
        merge_prep_packet_path=reports / "cohort0_post_f_track_03_merge_and_promotion_prep_packet.json",
        merge_prep_receipt_path=reports / "cohort0_post_f_track_03_merge_and_promotion_prep_receipt.json",
        review_verdict_receipt_path=reports / "cohort0_post_f_track_03_human_review_verdict_receipt.json",
    )

    assert result["decision_outcome"] == tranche.OUTCOME_MERGE_APPROVED_DEFERRED
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    blockers = _load(reports / tranche.OUTPUT_BLOCKERS)

    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_MERGE_APPROVED_DEFERRED
    assert blockers["merge_blockers"] == []
    assert len(blockers["package_promotion_deferred_reasons"]) == 2
