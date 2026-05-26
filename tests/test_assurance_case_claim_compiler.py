from __future__ import annotations

from g32_test_utils import load_json


def test_assurance_case_claim_compiler_keeps_claims_below_commercial_tier() -> None:
    receipt = load_json("reports/assurance_case_claim_compiler_receipt.json")

    assert receipt["highest_current_tier"] == "Tier 2"
    assert receipt["tier_5_claim_authorized"] is False
    assert "Tier 5" in receipt["evidence_tiers"]
