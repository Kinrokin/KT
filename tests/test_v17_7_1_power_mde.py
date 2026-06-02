from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_1_power_mde_marks_plus_one_underpowered() -> None:
    receipt = read_json(ROOT / "reports" / "v17_7_1_power_and_mde_receipt.json")
    assert receipt["observed_effect_rows"] == 1
    assert receipt["minimum_detectable_effect_rows"] > receipt["observed_effect_rows"]
    assert receipt["power_status"] == "UNDERPOWERED_DIAGNOSTIC_ONLY"
