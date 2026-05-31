from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v16_route_distribution_health_is_not_empty():
    subprocess.run([sys.executable, "scripts/run_v16_crossroad_shadow.py"], cwd=ROOT, check=True)
    health = json.loads((ROOT / "reports/v16_route_distribution_health.json").read_text(encoding="utf-8"))
    assert health["status"] == "PASS"
    assert health["route_distribution"]
    assert health["route_entropy"] >= 0
