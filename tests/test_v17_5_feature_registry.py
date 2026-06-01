from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_feature_registry_v2_is_runtime_legal_and_blocks_oracle_features():
    registry = json.loads((ROOT / "admission/route_value_feature_registry_v2.json").read_text(encoding="utf-8"))
    feature_ids = {feature["feature_id"] for feature in registry["features"]}
    required = {
        "prompt_length",
        "choice_count",
        "numeric_density",
        "operation_cue_count",
        "quantity_cue_count",
        "multi_hop_signal",
        "temporal_signal",
        "external_knowledge_signal",
        "claim_boundary_signal",
        "evidence_grounding_signal",
        "contradiction_signal",
        "uncertainty_signal",
        "format_risk_signal",
        "answer_type_signal",
        "option_comparison_signal",
        "math_act_features",
        "route_cost_priors",
        "historical_route_habitat_priors",
    }
    assert required.issubset(feature_ids)
    assert all(feature["available_before_generation"] for feature in registry["features"])
    assert all(feature["runtime_legal"] for feature in registry["features"])
    assert "oracle_correct" in registry["forbidden_runtime_features"]
    assert "post_hoc_correctness" in registry["forbidden_runtime_features"]
