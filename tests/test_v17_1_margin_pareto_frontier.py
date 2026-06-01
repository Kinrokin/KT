from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_margin_pareto_frontier_scores_required_metrics():
    frontier = json.loads((ROOT / "reports/v17_1_margin_pareto_frontier.json").read_text(encoding="utf-8"))
    assert frontier["status"] == "PASS"
    assert frontier["selected_margin"] == 0.10
    assert frontier["frontier_points"]
    for point in frontier["frontier_points"]:
        assert {"accuracy", "OCR", "BPR", "HAR", "OLR", "route_diversity", "tokens_per_correct"}.issubset(point)
