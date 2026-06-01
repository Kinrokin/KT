from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_scorecard_source_authority_recomputes_failed_v17_from_rows():
    receipt = json.loads((ROOT / "reports/v17_scorecard_source_reconciliation_receipt.json").read_text(encoding="utf-8"))
    score = receipt["recomputed_scorecard"]
    assert receipt["status"] == "PASS"
    assert receipt["authority_order"][0] == "benchmark_predictions.jsonl recomputation"
    assert score["base_raw_correct"] == 143
    assert score["feature_bound_correct"] == 159
    assert score["canary_policy_correct"] == 153
    assert score["canary_policy_correct"] < score["feature_bound_correct"]
