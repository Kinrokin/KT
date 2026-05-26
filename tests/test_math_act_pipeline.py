from __future__ import annotations

from g32_test_utils import load_json


def test_math_act_pipeline_blocks_generic_more_math() -> None:
    receipt = load_json("reports/math_act_pipeline_receipt.json")

    assert receipt["math_rows"] == 49
    assert receipt["generic_more_math_authorized"] is False
    assert receipt["latest_standing_best_recomputed_from_live_evidence"] is True
    assert all("verify_arithmetic" in row["math_act_stages"] for row in receipt["rows"])
