from __future__ import annotations

import json
from pathlib import Path


def read_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_bud100_monitor_v2_fixed512_comparison_keeps_baseline() -> None:
    comparison = read_json("reports/bud100_monitor_v2_vs_fixed512_comparison.json")
    autopsy = read_json("reports/bud100_monitor_v2_failure_autopsy.json")
    next_lane = read_json("reports/bud100_monitor_v2_next_lane_decision.json")

    assert comparison["status"] == "PASS_FIXED512_BASELINE_RETAINED"
    assert comparison["fixed512_dominant"] is True
    assert comparison["microfurnace_candidate"] is False
    assert comparison["next_lawful_move"] == "AUTHOR_BUD100_FIXED512_MATH_MODE_BASELINE_REPLAY_V1"
    assert autopsy["status"] == "PASS_NO_SAFE_DOWNSHIFT_FEATURE_BOUND"
    assert autopsy["damage_count"] == 0
    assert next_lane["selected_next_lawful_move"] == "AUTHOR_BUD100_FIXED512_MATH_MODE_BASELINE_REPLAY_V1"
    assert next_lane["runtime_authority"] is False


def test_bud100_monitor_v2_teacher_upper_bound_is_not_deployable() -> None:
    expected_gain = read_json("reports/bud100_monitor_v2_expected_gain_model.json")
    teacher = expected_gain["teacher_oracle_upper_bound"]

    assert expected_gain["status"] == "NO_DEPLOYABLE_GAIN_OBSERVED"
    assert teacher["status"] == "TEACHER_ONLY_LABEL_LEAK_NOT_DEPLOYABLE"
    assert teacher["correct"] == 91
    assert "posthoc" in teacher["reason_not_deployable"]
