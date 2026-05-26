from __future__ import annotations

from g32_test_utils import load_json


def test_anti_goodhart_pairs_every_metric() -> None:
    scorecard = load_json("reports/anti_goodhart_scorecard.json")

    assert scorecard["all_metrics_have_anti_goodhart_pair"] is True
    for metric in ["VWPT", "TPC", "UCR", "HOR", "RR", "SY", "DD", "GAD"]:
        assert metric in scorecard["metric_pairs"]
        assert scorecard["metric_pairs"][metric]
