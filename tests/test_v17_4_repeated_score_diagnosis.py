from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_repeated_159_is_diagnosed_from_row_ids():
    receipt = json.loads((ROOT / "reports/v17_4_repeated_score_diagnosis.json").read_text(encoding="utf-8"))
    assert set(receipt["policy_correct_counts"].values()) == {159}
    assert receipt["policy_equivalence_determined_from_rows"] is True
    assert receipt["same_score_different_rows"] is True
    assert receipt["same_score_same_rows"] is False
    assert receipt["selected_row_count"]["V17_canary_policy"] == 110
    assert receipt["selected_row_count"]["feature_bound_route"] == 98
    assert receipt["status"] == "PASS"
