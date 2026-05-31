from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_activation_margin_sweep_plan_is_exact_and_non_authoritative():
    plan = json.loads((ROOT / "admission/v17_activation_margin_sweep_plan.json").read_text(encoding="utf-8"))
    assert plan["activation_margins"] == [0.0, 0.03, 0.05, 0.07, 0.1]
    assert {"OCR", "RRC", "BPR", "HAR", "OLR", "route_distribution_health"}.issubset(set(plan["metrics"]))
    assert plan["runtime_authority"] is False
    assert plan["promotion_authority"] is False
    assert plan["status"] == "PASS"
