from __future__ import annotations

from g32_test_utils import load_json


def test_clinical_phase_promotion_law_blocks_score_only_promotion() -> None:
    receipt = load_json("reports/clinical_promotion_receipt.json")

    assert receipt["promotion_authorized"] is False
    assert receipt["score_increase_alone_promotes"] is False
    assert len(receipt["promotion_ladder"]) == 4
