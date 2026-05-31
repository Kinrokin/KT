from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v16_route_distribution_health_is_not_empty():
    health = json.loads((ROOT / "reports/v16_route_distribution_health.json").read_text(encoding="utf-8"))
    assert health["status"] == "PASS"
    assert health["route_distribution"]
    assert health["route_entropy"] >= 0
