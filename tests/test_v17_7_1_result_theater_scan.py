from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_1_result_theater_scan_blocks_fake_success() -> None:
    scan = read_json(ROOT / "reports" / "v17_7_1_result_theater_scan.json")
    final = read_json(ROOT / "reports" / "v17_7_1_final_decision_receipt.json")
    assert scan["status"] == "PASS"
    assert all(scan["checks"].values())
    assert final["runtime_authority"] is False
    assert final["v18_runtime_authority"] is False
