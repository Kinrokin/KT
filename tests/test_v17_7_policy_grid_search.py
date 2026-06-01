from __future__ import annotations

from pathlib import Path

from scripts.v17_7_oats_sddr_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_policy_grid_search_finds_candidate_but_not_v18_ready_if_cv_fails() -> None:
    grid = read_json(ROOT / "reports" / "policy_grid_search_scorecard.json")
    status = read_json(ROOT / "reports" / "policy_effectiveness_status.json")
    assert grid["schema_id"] == "kt.v17_7.policy_grid_search_scorecard.v1"
    assert grid["grid_size"] >= 1000
    assert grid["best_scorecard"]["minimum_pass"] is True
    assert grid["best_scorecard"]["canary_correct"] > 161
    assert status["policy_status"] in {
        "INTERNAL_REPLAY_ONLY_NOT_CANARY_READY",
        "INTERNAL_REPLAY_ONLY_CANARY_SPEC_ELIGIBLE",
    }
