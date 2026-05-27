from __future__ import annotations

from g32_test_utils import load_json


def test_accountability_kernel_confesses_failure_and_preserves_claim_ceiling() -> None:
    kernel = load_json("accountability/accountability_kernel_receipt.json")
    failure = load_json("accountability/failure_confession_receipt.json")
    success = load_json("accountability/success_admissibility_receipt.json")
    risk = load_json("accountability/self_deception_risk_scorecard.json")

    assert kernel["schema_id"] in {"kt.accountability_kernel_receipt.v1", "kt.accountability_kernel_receipt.v13"}
    assert kernel["claim_ceiling_preserved"] is True
    assert kernel["self_deception_gate_pass"] is True
    assert any("base_raw" in item for item in failure["what_failed"])
    assert any("formal math" in item.lower() for item in success["known_limits"])
    assert risk["self_deception_risk_score"] == 0
    if risk["schema_id"].endswith(".v13"):
        assert risk["promotion_eligible"] is False
    else:
        assert risk["promotion_eligible"] is True
