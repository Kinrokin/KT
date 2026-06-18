from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_stop50_rows_are_fresh_non_overlapping_gsm8k_425_475() -> None:
    receipt = json.loads((ROOT / "reports/ktstop50_row_policy.json").read_text(encoding="utf-8-sig"))
    assert receipt["status"] == "PASS_FRESH_NON_OVERLAPPING_50_ROW_DESIGN"
    assert receipt["row_policy"] == "openai/gsm8k:test[425:475]"
    assert receipt["row_count"] == 50
    assert receipt["overlap_with_prior_rows"] == 0
    assert [row["row_id"] for row in receipt["rows"]][:2] == ["gsm8k_test_425", "gsm8k_test_426"]
    assert receipt["rows"][-1]["row_id"] == "gsm8k_test_474"
