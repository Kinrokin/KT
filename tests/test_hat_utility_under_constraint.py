from __future__ import annotations

from g32_test_utils import load_json


def test_hat_utility_under_constraint_is_runtime_required_not_authorized() -> None:
    scorecard = load_json("reports/hat_utility_under_constraint_scorecard.json")

    assert scorecard["schema_id"] == "kt.hat_utility_under_constraint.v1"
    assert scorecard["utility_gate_pass"] is False
    assert scorecard["compact_hat_global_authority"] == "NOT_AUTHORIZED"
    assert scorecard["status"] == "SPEC_READY_RUNTIME_MEASUREMENT_REQUIRED"
    assert scorecard["claim_ceiling_preserved"] is True
