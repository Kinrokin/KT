from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_hat_and_math_act_nonselection_are_diagnosed():
    hat = json.loads((ROOT / "reports/v17_5_hat_nonselection_diagnosis.json").read_text(encoding="utf-8"))
    math_act = json.loads((ROOT / "reports/v17_5_math_act_nonselection_diagnosis.json").read_text(encoding="utf-8"))
    matrix = json.loads((ROOT / "reports/v17_5_nonselected_rescuer_opportunity_matrix.json").read_text(encoding="utf-8"))
    assert hat["hat_selection_count"] == 0
    assert math_act["math_act_selection_count"] == 0
    assert hat["hat_oracle_wins_count"] >= hat["hat_remaining_oracle_gap_wins_count"]
    assert math_act["math_act_oracle_wins_count"] >= math_act["math_act_remaining_oracle_gap_wins_count"]
    assert hat["nonselection_status"] in {"JUSTIFIED", "UNDERWEIGHTED", "UNKNOWN_BLOCKED"}
    assert math_act["nonselection_status"] in {"JUSTIFIED", "UNDERWEIGHTED", "UNKNOWN_BLOCKED"}
    assert matrix["status"] == "PASS"
