from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_v16_review_binds_reconciled_shadow_metrics_without_authority():
    review = read_json("reports/v16_result_review_receipt.json")
    reconciliation = read_json("reports/v16_metric_reconciliation.json")
    authority_block = read_json("reports/v16_runtime_authority_block_receipt.json")

    assert review["status"] == "PASS"
    assert review["conflicts"] == []
    assert review["metrics"]["oracle_conversion_rate"] == 0.6363636363636364
    assert review["metrics"]["route_regret_closure"] == 0.42857142857142855
    assert reconciliation["reconciled_values"]["shadow_policy_correct"] == "171/260"
    assert authority_block["runtime_authority"] is False
    assert authority_block["promotion_authority"] is False
    assert authority_block["claim_ceiling_preserved"] is True
