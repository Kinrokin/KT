from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_1_multiple_comparison_correction_blocks_raw_best_score() -> None:
    receipt = read_json(ROOT / "reports" / "v17_7_1_multiple_comparison_correction_receipt.json")
    assert receipt["candidate_count"] >= 1000
    assert receipt["best_raw_gain"] == 1
    assert receipt["correction_pass"] is False
