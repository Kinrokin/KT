from __future__ import annotations

from g32_test_utils import load_json


def test_verified_candidate_selection_is_required_but_not_claimed_earned() -> None:
    receipt = load_json("reports/verifier_bounded_candidate_selection_receipt.json")

    assert receipt["verifier_bounded_candidate_selection_required"] is True
    assert receipt["status"] == "SCAFFOLD_EMITTED_NOT_EARNED"
    assert receipt["promotion_eligible"] is False
