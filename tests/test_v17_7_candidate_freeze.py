from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_candidate_freeze_keeps_plus_one_diagnostic_only() -> None:
    policy = read_json(ROOT / "admission" / "v17_7_replay_only_candidate_policy.json")
    freeze = read_json(ROOT / "reports" / "v17_7_candidate_freeze_receipt.json")
    assert policy["candidate_score"] == 162
    assert policy["baseline_score"] == 161
    assert policy["runtime_authority"] is False
    assert policy["promotion_authority"] is False
    assert freeze["candidate_frozen"] is True
