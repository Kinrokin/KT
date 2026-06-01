from __future__ import annotations

from pathlib import Path

from scripts.v17_7_oats_sddr_common import read_json, read_jsonl


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_sddr_policy_replays_but_remains_internal_only() -> None:
    policy = read_json(ROOT / "admission" / "v17_7_best_oats_sddr_policy.json")
    decisions = read_jsonl(ROOT / "admission" / "sddr_route_decisions.jsonl")
    assert policy["schema_id"] == "kt.v17_7.sddr_policy_config.v1"
    assert policy["runtime_authority"] is False
    assert policy["promotion_authority"] is False
    assert policy.get("learned_router_superiority_claim", False) is False
    assert policy["scorecard"]["canary_correct"] >= 162
    assert policy["scorecard"]["canary_correct"] > policy["scorecard"]["v17_5_canary_correct"]
    assert len(decisions) == 260
    assert all(decision["claim_ceiling_preserved"] is True for decision in decisions)
