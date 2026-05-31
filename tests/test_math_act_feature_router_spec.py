import json
from pathlib import Path

ROOT = Path.cwd()


def test_math_act_feature_router_spec_is_pre_generation_and_label_blind():
    policy = json.loads((ROOT / "admission/math_act_feature_router_policy.json").read_text(encoding="utf-8"))
    assert "numeric_quantities" in policy["allowed_features"]
    assert "formal_calculation_language" in policy["allowed_features"]
    assert "dataset_name" in policy["forbidden_features"]
    assert "gold_answer" in policy["forbidden_features"]
    assert "pre_generation_feature_extraction_receipt" in policy["required_runtime_proof"]
    receipt = json.loads((ROOT / "reports/v14_math_act_feature_router_spec.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "SPEC_INSTALLED_RUNTIME_PROOF_PENDING"
    assert receipt["claim_ceiling_preserved"] is True
