from __future__ import annotations

from g32_test_utils import load_json


def test_minimum_viable_signal_requires_measured_scans_and_positive_gain() -> None:
    mvs = load_json("reports/g32_minimum_viable_signal_receipt.json")
    passed = [row for row in mvs["rows"] if row["minimum_viable_signal_pass"]]

    assert mvs["pass"] is True
    assert passed
    for row in passed:
        checks = row["checks"]
        assert checks["benchmark_leakage_scan_pass"] is True
        assert checks["poison_trigger_scan_pass"] is True
        assert checks["negative_transfer_scan_pass"] is True
        assert checks["expected_target_metric_gain_pass"] is True
