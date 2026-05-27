from __future__ import annotations

from g32_test_utils import load_json


def test_v13_truth_pin_and_accountability_are_bound_to_claim_ceiling() -> None:
    truth = load_json("reports/v13_truth_pin_receipt.json")
    kernel = load_json("accountability/accountability_kernel_receipt.json")
    risk = load_json("accountability/self_deception_risk_scorecard.json")

    assert truth["schema_id"] == "kt.v13.truth_pin_receipt.v1"
    assert truth["claim_ceiling_status"] == "UNCHANGED"
    assert kernel["schema_id"] == "kt.accountability_kernel_receipt.v13"
    assert kernel["specialist_route_derivation_bound"] is True
    assert kernel["no_scaffold_runtime_gate_bound"] is True
    assert risk["niche_to_global_laundering_rate"] == 0.0
    assert risk["promotion_eligible"] is False


def test_formal_math_specialist_is_candidate_route_not_promotion_or_superiority() -> None:
    plan = load_json("reports/formal_math_specialist_router_plan.json")
    decision = load_json("reports/specialist_router_decision_contract.json")
    activation = load_json("reports/formal_math_specialist_activation_decision.json")

    assert plan["route_authority"] == "CANONICAL_CANDIDATE_ROUTE_RULE"
    assert plan["not_router_superiority"] is True
    assert plan["not_adapter_promotion"] is True
    assert decision["router_superiority_claim_authorized"] is False
    assert activation["activation_decision"] == "ALLOW_AS_CANDIDATE_ROUTE_RULE_FOR_NEXT_MEASURED_PACKET_ONLY"
    assert activation["claim_ceiling_preserved"] is True
