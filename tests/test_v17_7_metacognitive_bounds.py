from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_metacognitive_bounds_exist_before_perturbation() -> None:
    bounds = read_json(ROOT / "admission" / "v17_7_1_metacognitive_bounds.json")
    receipt = read_json(ROOT / "reports" / "v17_7_1_metacognitive_threshold_contract_receipt.json")
    assert bounds["max_hard_omega_spiral"] == 0.75
    assert receipt["status"] == "PASS"
    assert receipt["action"] in {"freeze_replay_only", "simplify_and_retest"}
