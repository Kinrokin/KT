from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_1_preflight_binds_current_head_and_claim_ceiling() -> None:
    receipt = read_json(ROOT / "reports" / "v17_7_1_preflight_repo_truth_receipt.json")
    head = read_json(ROOT / "reports" / "v17_7_1_current_head_receipt.json")
    claim = read_json(ROOT / "reports" / "v17_7_1_claim_ceiling_receipt.json")
    assert receipt["repo_truth_contradiction"] is False
    assert receipt["claim_ceiling_preserved"] is True
    assert head["current_head"]
    assert head["replay_subject_head"] == head["current_head"]
    assert head["head_binding_status"] == "PASS"
    assert head["historical_anchor_is_current_head_authority"] is False
    assert "head_matches_expected" not in head
    assert "v17_7_main_replay_head_expected" not in head
    assert claim["runtime_authority"] is False
    assert claim["promotion_authority"] is False
