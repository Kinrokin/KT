from __future__ import annotations

from g32_test_utils import load_json


def test_lobe_specialization_is_scaffolded_not_claimed() -> None:
    receipt = load_json("reports/lobe_specialization_scorecard.json")

    assert receipt["status"] == "SCAFFOLD_EMITTED_NOT_EARNED"
    assert receipt["promotion_eligible"] is False
    assert "negative_transfer_rate" in receipt["metrics"]
