from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_track_03_merge_and_promotion_prep_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_track_03_merge_and_promotion_prep_binds_merge_targets_and_artifact_sets(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    run_root = tmp_path / "KT_PROD_CLEANROOM" / "runs" / "post_f_track_03" / tranche.DEFAULT_RUN_ID
    staging = run_root / "staging"

    _write_json(
        reports / "cohort0_post_f_track_03_human_review_verdict_packet.json",
        {
            "schema_id": "verdict-packet",
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
            "review_scope": {
                "reviewed_files": [
                    "KT E2E Lawful Commitment Superiority Playbook.md",
                    "governance/RMR_SCHEMA_FREEZE.md",
                    "governance/commit_gating_rules.md",
                    "docs/publication_legal_pack.md",
                    "training/router_court_spec.md",
                ]
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_human_review_verdict_receipt.json",
        {
            "schema_id": "verdict-receipt",
            "status": "PASS",
            "review_outcome": "APPROVE_AS_IS",
            "subject_head": "track03-head",
            "next_lawful_move": "AUTHOR_POST_F_TRACK_03_MERGE_AND_PROMOTION_PREP_PACKET",
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_promotion_recommendation.json",
        {
            "schema_id": "promotion",
            "status": "PASS",
            "merge_allowed_after_review": True,
            "canonical_promotion_boundary": "merge first, promote later",
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_final_summary_packet.json",
        {
            "schema_id": "summary",
            "status": "PASS",
            "promotion_boundary": {"multisig_threshold_satisfied": True},
        },
    )
    _write_json(
        reports / "cohort0_post_f_parallel_prep_scaffold_receipt.json",
        {
            "schema_id": "prep",
            "status": "PASS",
            "outcome": "POST_F_PARALLEL_PREP_SCAFFOLDS_BOUND__NON_AUTHORITATIVE_OUTPUTS_ONLY",
        },
    )

    _write_text(
        staging / "scripts" / "stage_and_promote.sh",
        '#!/usr/bin/env bash\nselected = ["reports", "governance", "packet", "runtime", "docs"]\n',
    )
    _write_text(staging / "reports" / "cohort0_current_head_receipt.json", "{}")
    _write_text(staging / "governance" / "H1_EXPERIMENT_MANIFEST.json", "{}")
    _write_text(staging / "governance" / "multisig_approvals.json", "{}")
    _write_text(staging / "governance" / "RMR_SCHEMA_v1.json", "{}")
    _write_text(staging / "packet" / "residual_alpha_packet_spec.json", "{}")
    _write_text(staging / "runtime" / "minimal_lobe_shim.py", "print('ok')\n")
    _write_text(staging / "governance" / "RMR_SCHEMA_FREEZE.md", "---\nhuman_review_required: true\n---\n")
    _write_text(staging / "governance" / "commit_gating_rules.md", "---\nhuman_review_required: true\n---\n")
    _write_text(staging / "docs" / "publication_legal_pack.md", "---\nhuman_review_required: true\n---\n")

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_WORKING_BRANCH)
    monkeypatch.setattr(tranche, "_current_head", lambda root: "merge-prep-head")
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    result = tranche.run(
        reports_root=reports,
        review_verdict_packet_path=reports / "cohort0_post_f_track_03_human_review_verdict_packet.json",
        review_verdict_receipt_path=reports / "cohort0_post_f_track_03_human_review_verdict_receipt.json",
        promotion_recommendation_path=reports / "cohort0_post_f_track_03_promotion_recommendation.json",
        final_summary_packet_path=reports / "cohort0_post_f_track_03_final_summary_packet.json",
        prep_scaffold_receipt_path=reports / "cohort0_post_f_parallel_prep_scaffold_receipt.json",
        run_root=run_root,
    )

    assert result["prep_outcome"] == tranche.PREP_OUTCOME
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert packet["promotion_target_and_authority_rule"]["eligible_target_branch"] == "main"
    assert packet["exact_promoted_artifact_set"]["review_approved_but_outside_current_stage_and_promote_scope"] == [
        "KT E2E Lawful Commitment Superiority Playbook.md",
        "training/router_court_spec.md",
    ]
    assert len(packet["exact_promoted_artifact_set"]["package_internal_auto_promotion_set"]) == 6
    assert len(packet["exact_promoted_artifact_set"]["package_internal_review_approved_but_auto_skipped"]) == 3
    assert packet["post_merge_authoritative_fork"]["first_lane_to_promote"] == "truth_engine_contradiction_validator_scaffold"
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
