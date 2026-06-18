from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def test_stop300_stratified_hash_sample_is_balanced_and_gold_free() -> None:
    manifest = read_json("admission/stop300_stratified_hash_selected_manifest.json")
    assert manifest["status"] == "PASS_100_100_100_STRATIFIED_HASH_SELECTION"
    assert manifest["row_count"] == 300
    assert manifest["stratum_counts"] == {"EASY": 100, "HARD": 100, "MEDIUM": 100}
    assert all("expected_answer" not in row for row in manifest["rows"])


def test_stop300_timing_panel_is_balanced_60() -> None:
    manifest = read_json("admission/stop300_timing_panel_manifest.json")
    assert manifest["status"] == "PASS_BALANCED_60_ROW_TIMING_PANEL"
    assert manifest["row_count"] == 60
    assert manifest["stratum_counts"] == {"EASY": 20, "HARD": 20, "MEDIUM": 20}


def test_stop300_risk_tolerance_is_preregistered_zero_damage() -> None:
    risk = read_json("admission/runtime_stop_risk_tolerance_contract.json")
    prereg = read_json("admission/stop300_preregistered_protocol.json")
    assert risk["observed_damage_tolerance"] == 0
    assert risk["one_sided_exact_95pct_damage_upper_bound_target"] == 0.01
    assert prereg["status"] == "PASS_PREREGISTERED_BEFORE_GENERATION"
