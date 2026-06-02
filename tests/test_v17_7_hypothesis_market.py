from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_hypothesis_market_contains_required_hypotheses() -> None:
    market = read_json(ROOT / "reports" / "v17_7_hypothesis_market_receipt.json")
    ids = {row["hypothesis_id"] for row in market["hypotheses"]}
    assert len(ids) == 15
    assert "H6_sample_size_too_sparse" in ids
    assert "H12_feature_ablation_carries_gain" in ids
