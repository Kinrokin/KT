from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_bpr_formula_is_recomputed_into_valid_probability_range():
    receipt = json.loads((ROOT / "reports/v17_4_bpr_formula_repair_receipt.json").read_text(encoding="utf-8"))
    assert receipt["reported_bpr_impossible"] is True
    assert receipt["reported_bpr"] > 1
    assert 0 <= receipt["recomputed_bpr"] <= 1
    assert receipt["recomputed_bpr"] >= 0.95
    assert receipt["valid_range"] is True
