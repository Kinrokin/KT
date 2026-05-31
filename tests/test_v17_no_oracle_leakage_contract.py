from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = {
    "oracle_correct",
    "gold_answer",
    "post_hoc_correctness",
    "posthoc_winner",
    "arm_correctness",
    "benchmark_answer",
    "post_generation_output_quality",
}


def test_v17_forbidden_features_are_never_allowed_runtime_inputs():
    config = json.loads((ROOT / "admission/v17_canary_policy_config.json").read_text(encoding="utf-8"))
    contract = json.loads((ROOT / "admission/v17_runtime_feature_contract.json").read_text(encoding="utf-8"))
    route_value = json.loads((ROOT / "admission/v17_route_value_feature_contract.json").read_text(encoding="utf-8"))
    allowed = set(config.get("allowed_runtime_features", []))
    allowed |= set(contract.get("allowed_runtime_features", []))
    allowed |= set(route_value.get("allowed_source_feature_families", []))
    assert allowed.isdisjoint(FORBIDDEN)
    assert set(contract["forbidden_runtime_features"]) == FORBIDDEN
    assert contract["oracle_correctness_used_as_input_feature"] is False
