from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_canary_policy_config_has_required_arms_thresholds_and_no_authority():
    config = json.loads((ROOT / "admission/v17_canary_policy_config.json").read_text(encoding="utf-8"))
    required = {
        "base_raw",
        "feature_bound_route",
        "label_bound_route",
        "best_static_adapter",
        "V16_shadow_replay_baseline",
        "V17_canary_policy",
        "oracle",
    }
    assert set(config["required_arms"]) == required
    assert config["activation_margin_sweep"] == [0.0, 0.03, 0.05, 0.07, 0.1]
    assert config["minimum_pass_bar"]["oracle_conversion_rate_gt"] == 0.3636363636
    assert config["minimum_pass_bar"]["base_preservation_rate_gte"] == 0.95
    assert config["minimum_pass_bar"]["harmful_activation_rate_lte"] == 0.10
    assert config["runtime_authority"] is False
    assert config["promotion_authority"] is False
    assert config["adapter_training_authorized"] is False
    assert config["claim_ceiling_preserved"] is True
