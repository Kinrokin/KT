from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_perturbation_validity_contract_blocks_gold_changes() -> None:
    contract = read_json(ROOT / "reports" / "v17_7_1_perturbation_validity_contract.json")
    scorecard = read_json(ROOT / "reports" / "v17_7_perturbation_invariance_scorecard.json")
    assert "changes gold answer" in contract["blocked_perturbations"]
    assert scorecard["perturbation_flip_rate"] <= 0.10
