from __future__ import annotations

from pathlib import Path

from scripts.v17_7_oats_sddr_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_cross_validation_blocks_overfit_before_v18() -> None:
    overfit = read_json(ROOT / "reports" / "overfit_risk_receipt.json")
    blocked = read_json(ROOT / "reports" / "v17_7_blocked_policy_search_receipt.json")
    next_runtime = read_json(ROOT / "reports" / "v17_7_next_runtime_recommendation.json")
    assert overfit["status"] == "FAIL"
    assert overfit["overfit_risk"] == "HIGH"
    assert overfit["failed_fold_count"] > 0
    assert blocked["outcome"] == "KTG3FULL_V17_7_BLOCKED__OVERFIT_RISK"
    assert next_runtime["run_v17_8_furnace_next"] is False
