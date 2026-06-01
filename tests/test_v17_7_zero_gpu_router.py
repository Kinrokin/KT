from __future__ import annotations

from pathlib import Path

from scripts.v17_7_oats_sddr_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_router_is_cpu_only_and_fast() -> None:
    receipt = read_json(ROOT / "reports" / "zero_gpu_router_validation_receipt.json")
    assert receipt["schema_id"] == "kt.v17_7.zero_gpu_router_validation_receipt.v1"
    assert receipt["status"] == "PASS"
    assert receipt["dependency_findings"] == []
    assert receipt["avg_route_latency_ms"] < 25
