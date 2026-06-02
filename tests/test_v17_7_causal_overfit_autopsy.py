from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_causal_overfit_autopsy_is_row_level() -> None:
    autopsy = read_json(ROOT / "reports" / "v17_7_causal_overfit_autopsy.json")
    trace = read_json(ROOT / "reports" / "v17_7_row_level_causality_trace.json")
    assert autopsy["net_gain"] == 1
    assert autopsy["decision"] == "freeze_and_distill_scar_tissue"
    assert trace["row_count"] == 260
    assert {row["flip_class"] for row in trace["rows"]} >= {"wrong_to_right", "right_to_wrong", "same"}
