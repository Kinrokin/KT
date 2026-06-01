from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_best_static_semantics_are_bound_to_source_count():
    receipt = json.loads((ROOT / "reports/v17_best_static_semantics_receipt.json").read_text(encoding="utf-8"))
    assert receipt["best_static_route"] == "best_static_adapter"
    assert receipt["best_static_correct"] == 160
    assert receipt["source_count_reconciled"] is True
    assert receipt["claim_ceiling_preserved"] is True
