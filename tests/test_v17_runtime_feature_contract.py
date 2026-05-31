from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_runtime_feature_contract_is_pre_generation_only_and_claim_bounded():
    contract = json.loads((ROOT / "admission/v17_runtime_feature_contract.json").read_text(encoding="utf-8"))
    assert contract["route_decision_timing"] == "PRE_GENERATION_ONLY"
    assert contract["post_generation_quality_features_allowed"] is False
    assert contract["gold_or_answer_features_allowed"] is False
    assert contract["runtime_authority"] is False
    assert contract["promotion_authority"] is False
    assert contract["claim_ceiling_preserved"] is True
    assert "math_act_features" in contract["allowed_runtime_features"]
    assert "historical_route_habitat_priors" in contract["allowed_runtime_features"]
