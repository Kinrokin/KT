from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_track_03_human_review_court_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_track_03_human_review_court_approves_with_named_non_structural_edits(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    run_id = "run-20260424-152430-bb49da8"
    staging_root = tmp_path / "KT_PROD_CLEANROOM" / "runs" / "post_f_track_03" / run_id / "staging"

    _write_json(
        reports / "cohort0_post_f_track_03_human_review_packet.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_03_human_review_packet.v1",
            "status": "PASS",
            "track_identity": {"run_id": run_id},
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
            "review_required_files": [
                {"path": "KT E2E Lawful Commitment Superiority Playbook.md", "review_reason": "playbook"},
                {"path": "governance/RMR_SCHEMA_FREEZE.md", "review_reason": "schema"},
                {"path": "governance/commit_gating_rules.md", "review_reason": "gating"},
                {"path": "docs/publication_legal_pack.md", "review_reason": "publication"},
                {"path": "training/router_court_spec.md", "review_reason": "router"},
            ],
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_human_review_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_03_human_review_receipt.v1",
            "status": "PASS",
            "subject_head": "track03-head",
            "next_lawful_move": "CONVENE_POST_F_TRACK_03_HUMAN_REVIEW_COURT",
        },
    )

    _write_text(staging_root / "KT E2E Lawful Commitment Superiority Playbook.md", "clean playbook")
    _write_text(staging_root / "governance" / "RMR_SCHEMA_FREEZE.md", "clean schema law")
    _write_text(staging_root / "governance" / "commit_gating_rules.md", "clean gating rules")
    _write_text(staging_root / "docs" / "publication_legal_pack.md", "bad â€œquoteâ€\u009d and â†’ arrow")
    _write_text(staging_root / "training" / "router_court_spec.md", "bad â†’ arrow")

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_WORKING_BRANCH)
    monkeypatch.setattr(tranche, "_current_head", lambda root: "review-court-head")
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    result = tranche.run(
        reports_root=reports,
        human_review_packet_path=reports / "cohort0_post_f_track_03_human_review_packet.json",
        human_review_receipt_path=reports / "cohort0_post_f_track_03_human_review_receipt.json",
    )

    assert result["review_outcome"] == tranche.OUTCOME_APPROVE_NON_STRUCTURAL
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    blockers = _load(reports / tranche.OUTPUT_BLOCKERS)
    promotion = _load(reports / tranche.OUTPUT_PROMOTION)

    assert packet["review_outcome"] == tranche.OUTCOME_APPROVE_NON_STRUCTURAL
    assert len(blockers["non_structural_edit_queue"]) == 2
    assert promotion["promotion_recommendation"] == "PROMOTION_PREP_ALLOWED_AFTER_NAMED_NON_STRUCTURAL_EDITS"
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_APPROVE

