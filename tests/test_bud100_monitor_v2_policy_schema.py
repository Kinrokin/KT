from __future__ import annotations

import json
from pathlib import Path


def read_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_bud100_monitor_v2_policy_is_conservative_and_design_only() -> None:
    policy = read_json("admission/bud100_adaptive_monitor_v2_candidate_policy.json")
    schema = read_json("schemas/kt.bud100_monitor_v2_policy.schema.json")

    assert schema["properties"]["schema_id"]["const"] == "kt.bud100_monitor_v2_policy.v1"
    assert policy["schema_id"] == "kt.bud100_monitor_v2_policy.v1"
    assert policy["policy_id"] == "BUDGET_MONITOR_MATH_V2_CANDIDATE"
    assert policy["status"] == "DESIGN_ONLY_NO_PRODUCTION_AUTHORITY"
    assert policy["baseline"]["current_best"] == "A2_COT_512_FIXED"
    assert policy["multi_step_math"]["default_budget"] == 512
    assert policy["decision_order"][0]["rule_id"] == "COT512_DEFAULT_SAFE"
    assert policy["decision_order"][0]["action"] == "A2_COT_512_FIXED"
    assert policy["feature_legality"]["legal_predictive_downshift_model_bound"] is False
    assert "expected_answer" in policy["feature_legality"]["forbidden_features"]
    assert "posthoc_label_leak" in policy["feature_legality"]["forbidden_features"]
    assert policy["authority"]["runtime_authority"] is False
    assert policy["authority"]["training_authority"] is False
    assert policy["authority"]["production_prompt_mutation_authority"] is False


def test_bud100_monitor_v2_no_production_mutation_receipt() -> None:
    receipt = read_json("reports/bud100_monitor_v2_no_production_mutation_receipt.json")

    assert receipt["status"] == "PASS_NO_PRODUCTION_MUTATION"
    assert receipt["runtime_authority"] is False
    assert receipt["dataset_generation_authority"] is False
    assert receipt["training_authority"] is False
    assert receipt["promotion_authority"] is False
    assert receipt["adapter_mutation_authority"] is False
    assert receipt["production_prompt_mutation_authority"] is False
    assert receipt["claim_ceiling_preserved"] is True
