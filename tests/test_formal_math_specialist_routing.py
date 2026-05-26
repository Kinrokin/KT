from __future__ import annotations

from g32_test_utils import load_json


def test_formal_math_adapter_is_specialist_not_global_promotion() -> None:
    plan = load_json("reports/formal_math_specialist_router_plan.json")
    registry = load_json("reports/adapter_ecological_niche_registry.json")
    decision = load_json("reports/specialist_router_decision_contract.json")

    niche = registry["niches"][0]
    assert "formal_math_router_specialist" in plan["arms"]
    assert niche["adapter_id"] == "adapter_g3_formal_math_repair_adapter"
    assert niche["promotion_eligible"] is False
    assert "global_general_reasoning" in niche["blocked_task_families"]
    assert niche["verifier_required"] is True
    assert decision["fallback_route"] == "base_raw"
