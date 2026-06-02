from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_failure_manifold_blocks_promotion_authority() -> None:
    manifold = read_json(ROOT / "reports" / "v17_7_failure_manifold_map.json")
    instability = read_json(ROOT / "reports" / "v17_7_policy_instability_scorecard.json")
    assert "cv_generalization_delta" in manifold["axes"]
    assert manifold["promotion_authority"] is False
    assert instability["instability_status"] == "HIGH"
