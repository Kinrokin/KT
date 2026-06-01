from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_degenerate_fallback_scan_blocks_all_base_overcorrection():
    scan = json.loads((ROOT / "reports/v17_1_degenerate_fallback_scan.json").read_text(encoding="utf-8"))
    assert scan["status"] == "PASS"
    assert scan["non_base_route_count"] >= scan["minimum_non_base_route_count"]
    assert scan["canary_policy_correct"] > scan["base_raw_correct"]
    assert scan["route_distribution_not_collapsed"] is True
