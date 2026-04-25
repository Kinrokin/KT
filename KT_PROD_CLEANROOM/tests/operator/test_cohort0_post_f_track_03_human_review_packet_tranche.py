from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_track_03_human_review_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_track_03_human_review_packet_freezes_review_surface(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    run_root = tmp_path / "KT_PROD_CLEANROOM" / "runs" / "post_f_track_03" / tranche.DEFAULT_RUN_ID

    _write_json(
        reports / "cohort0_post_f_track_03_final_summary_packet.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_03_final_summary_packet.v1",
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
        reports / "cohort0_post_f_track_03_final_summary_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_03_final_summary_receipt.v1",
            "status": "PASS",
            "working_branch_non_authoritative_until_protected_merge": True,
            "next_lawful_move": "AUTHOR_POST_F_TRACK_03_HUMAN_REVIEW_PACKET",
        },
    )
    _write_json(
        run_root / "artifacts" / "promotion_block_receipt.json",
        {
            "status": "BLOCKED",
            "multisig_threshold_satisfied": True,
            "block_reasons": [
                "Branch remains non-authoritative until merged to main.",
                "Playbook carries human_review_required: true and has not been explicitly reviewed in this execution turn.",
            ],
        },
    )
    _write_json(run_root / "artifacts" / "reconciliation_packet.json", {"status": "PASS_READY_FOR_VALIDATION"})
    _write_json(run_root / "artifacts" / "validation_matrix.json", {"status": "PASS"})
    _write_json(run_root / "artifacts" / "counted_path_receipt.json", {"status": "PASS"})
    _write_json(
        run_root / "staging" / "reports" / "cohort0_current_head_receipt.json",
        {
            "status": "PASS",
            "current_git_head": "track03-head",
            "current_branch": tranche.REQUIRED_WORKING_BRANCH,
        },
    )
    _write_json(
        run_root / "staging" / "staging" / "task_summary.json",
        {"next_steps": ["Review human_review_required documents before promotion."]},
    )
    _write_text(
        run_root / "staging" / "KT E2E Lawful Commitment Superiority Playbook.md",
        "---\nhuman_review_required: true\n---\nplaybook\n",
    )
    _write_text(run_root / "staging" / "governance" / "RMR_SCHEMA_FREEZE.md", "---\nhuman_review_required: true\n---\n")
    _write_text(run_root / "staging" / "governance" / "commit_gating_rules.md", "---\nhuman_review_required: true\n---\n")
    _write_text(run_root / "staging" / "docs" / "publication_legal_pack.md", "---\nhuman_review_required: true\n---\n")
    _write_text(run_root / "staging" / "training" / "router_court_spec.md", "---\nhuman_review_required: true\n---\n")
    bundle_path = run_root / "staging" / "bundle" / f"proof_bundle_{tranche.DEFAULT_RUN_ID}.tar.gz"
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.write_bytes(b"bundle")
    sig_path = run_root / "staging" / "signatures" / f"proof_bundle_{tranche.DEFAULT_RUN_ID}.sig"
    _write_text(sig_path, "sig")

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_WORKING_BRANCH)
    monkeypatch.setattr(tranche, "_current_head", lambda root: "review-packet-head")
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    result = tranche.run(
        reports_root=reports,
        final_summary_packet_path=reports / "cohort0_post_f_track_03_final_summary_packet.json",
        final_summary_receipt_path=reports / "cohort0_post_f_track_03_final_summary_receipt.json",
        run_root=run_root,
    )

    assert result["review_outcome"] == tranche.REVIEW_OUTCOME
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert packet["promotion_blockers"]["promotion_blocked"] is True
    assert len(packet["review_required_files"]) == 5
    assert packet["review_state_partition"]["review_complete"] is False
    assert packet["next_lawful_move"] == tranche.NEXT_MOVE
    assert receipt["review_required_file_count"] == 5

