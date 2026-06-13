from __future__ import annotations

import json
from pathlib import Path


def read_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_jsonl(path: str) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_bud100_monitor_v2_offline_replay_retains_fixed512_without_gain() -> None:
    scorecard = read_json("reports/bud100_monitor_v2_offline_replay_scorecard.json")

    assert scorecard["schema_id"] == "kt.bud100_monitor_v2_offline_replay.v1"
    assert scorecard["status"] == "PASS_NO_GAIN_FIXED512_RETAINED"
    assert scorecard["row_count"] == 100
    assert scorecard["correct"] == 91
    assert scorecard["accuracy"] == 0.91
    assert abs(scorecard["full_tokens_per_correct"] - 374.57142857142856) < 1e-9
    assert scorecard["selected_arm_counts"] == {"A2_COT_512_FIXED": 100}
    assert scorecard["damage_count_vs_fixed512"] == 0
    assert scorecard["token_saving_rows_vs_fixed512"] == 0
    assert scorecard["microfurnace_candidate"] is False


def test_bud100_monitor_v2_row_decisions_are_non_leaky() -> None:
    rows = read_jsonl("reports/bud100_monitor_v2_row_decisions.jsonl")

    assert len(rows) == 100
    assert {row["v2_selected_arm"] for row in rows} == {"A2_COT_512_FIXED"}
    assert {row["feature_legality"] for row in rows} == {"PASS_NO_LABEL_LEAK"}
    assert not any(row["v2_would_damage_vs_fixed512"] for row in rows)
    assert not any(row["v2_would_save_tokens_vs_fixed512"] for row in rows)
