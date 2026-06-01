from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_route_regret_overdominance_is_diagnosed_not_promoted():
    receipt = json.loads((ROOT / "reports/v17_5_route_regret_overselection_receipt.json").read_text(encoding="utf-8"))
    health = json.loads((ROOT / "reports/v17_5_route_dominance_health.json").read_text(encoding="utf-8"))
    assert receipt["route_regret_selection_count"] == 152
    assert 0 <= receipt["route_regret_precision"] <= 1
    assert 0 <= receipt["route_regret_recall_against_oracle"] <= 1
    assert receipt["route_regret_overdominance_flag"] is True
    assert "decrease_route_regret_prior" in receipt["recommended_threshold_patch"]
    assert health["route_regret_overdominance_flag"] is True
    assert health["claim_ceiling_preserved"] is True
