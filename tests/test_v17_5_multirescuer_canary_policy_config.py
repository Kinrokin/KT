from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_multirescuer_policy_uses_all_candidate_rescuers_without_promotion():
    policy = json.loads((ROOT / "admission/v17_5_multirescuer_canary_policy_config.json").read_text(encoding="utf-8"))
    assert policy["candidate_routes"] == [
        "base_raw",
        "base_kt_hat_compact",
        "math_act_adapter_global",
        "route_regret_policy_adapter_global",
        "formal_math_repair_adapter_global",
    ]
    assert policy["minimum_route_distribution"]["distinct_candidate_routes_required"] == 3
    assert policy["oracle_correctness_as_feature"] is False
    assert policy["runtime_authority"] is False
    assert policy["promotion_authority"] is False
    assert policy["adapter_training_authorized"] is False
    assert policy["learned_router_superiority_claim"] is False
