from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_decision_prediction_counts_are_reconciled():
    receipt = json.loads((ROOT / "reports/v17_decision_prediction_consistency_receipt.json").read_text(encoding="utf-8"))
    counts = json.loads((ROOT / "reports/v17_source_count_reconciliation.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["prediction_rows"] == receipt["decision_rows"] == 260
    assert counts["benchmark_prediction_rows"] == counts["decision_rows"] == counts["scorecard_rows"] == 260
