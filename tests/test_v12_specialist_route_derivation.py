from __future__ import annotations

from g32_test_utils import load_json, required_schema_fields


def test_v12_specialist_route_derivation_replays_candidate_route_without_superiority_claim() -> None:
    receipt = load_json("reports/v12_specialist_route_derivation_receipt.json")

    assert receipt["schema_id"] == "kt.specialist_route_derivation_receipt.v1"
    assert receipt["base_raw_correct_count"] == 111
    assert receipt["base_raw_gsm8k_correct_count"] == 2
    assert receipt["formal_math_adapter_gsm8k_correct_count"] == 13
    assert receipt["formal_math_router_specialist_correct_count"] == 122
    assert receipt["formal_math_router_specialist_correct_count"] == 111 - 2 + 13
    assert receipt["route_status"] == "CANONICAL_CANDIDATE_ROUTE_RULE_NOT_LEARNED_ROUTER_SUPERIORITY"
    assert receipt["replay_status"].startswith("PASS")
    assert receipt["claim_ceiling_preserved"] is True


def test_specialist_route_derivation_schema_has_count_and_claim_fields() -> None:
    required = required_schema_fields("schemas/kt.specialist_route_derivation_receipt.schema.json")

    assert {
        "schema_id",
        "base_raw_correct_count",
        "formal_math_router_specialist_correct_count",
        "replay_status",
        "claim_ceiling_preserved",
    } <= required
