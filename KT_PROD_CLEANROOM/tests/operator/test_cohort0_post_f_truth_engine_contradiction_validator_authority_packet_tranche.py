from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_truth_engine_contradiction_validator_authority_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_truth_engine_authority_packet_promotes_only_ranked_lane(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(
        reports / "cohort0_post_f_track_03_post_merge_branch_snapshot.json",
        {
            "snapshot_type": "snapshot",
            "retained_non_authoritative_prep_lanes": [
                "trust_zone_boundary_purification_scaffold",
                "residual_proof_law_hardening_scaffold",
            ],
            "package_promotion_split": {
                "auto_promotion_candidate_count": 6,
                "review_approved_auto_skip_count": 3,
                "review_approved_out_of_scope_count": 2,
                "package_promotion_boundary": "explicit later step",
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
        {
            "schema_id": "closeout-receipt",
            "status": "PASS",
            "package_promotion_still_deferred": True,
            "first_post_merge_authoritative_lane": "truth_engine_contradiction_validator_scaffold",
            "next_lawful_move": "AUTHOR_POST_F_TRUTH_ENGINE_CONTRADICTION_VALIDATOR_AUTHORITY_PACKET",
        },
    )
    _write_json(
        reports / "cohort0_post_f_parallel_truth_engine_scope_packet.json",
        {
            "schema_id": "prep-scope",
            "status": "PASS",
            "lane_status": "AUTHORIZED__NON_AUTHORITATIVE_PREP_ONLY",
            "posture_enum": ["CANONICAL_MAIN_LIVE_TRUTH"],
            "truth_engine_contract": {"live_posture_must_be_receipt_derived": True},
            "contradiction_rules": ["rule-1"],
            "source_precedence_table": ["main first"],
            "stale_surface_exclusion_logic": {"exclude_untracked_authority": True},
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "main-head" if ref == "main" else "branch-head")
    monkeypatch.setattr(tranche, "_git_merge_base", lambda root, left, right: "main-head")

    result = tranche.run(
        reports_root=reports,
        post_merge_snapshot_path=reports / "cohort0_post_f_track_03_post_merge_branch_snapshot.json",
        post_merge_receipt_path=reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
        prep_truth_engine_scope_path=reports / "cohort0_post_f_parallel_truth_engine_scope_packet.json",
    )

    assert result["lane_outcome"] == tranche.LANE_OUTCOME
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    packet = _load(reports / tranche.OUTPUT_PACKET)

    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
    assert packet["preserved_boundaries"]["other_prep_lanes_remain_non_authoritative"] is True
    assert packet["lane_transition"]["promoted_lane_id"] == "truth_engine_contradiction_validator_scaffold"
