from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_1_confidence_intervals_cover_required_metrics() -> None:
    scorecard = read_json(ROOT / "reports" / "v17_7_1_confidence_interval_scorecard.json")
    required = {"replay_score", "nested_cv_mean", "OCR", "BPR", "HAR", "perturbation_flip_rate", "feature_ablation_collapse", "worst_slice_loss"}
    assert required <= set(scorecard["intervals"])
    assert scorecard["improvement_interval_status"] == "OVERLAPS_BASELINE_OR_UNDERPOWERED"
