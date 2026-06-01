from __future__ import annotations

from pathlib import Path

from scripts.v17_7_oats_sddr_common import oracle_leakage_adversarial, read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_oracle_leakage_gate_fails_closed() -> None:
    direct = oracle_leakage_adversarial()
    persisted = read_json(ROOT / "reports" / "oracle_leakage_adversarial_receipt.json")
    assert direct["status"] == "PASS"
    assert direct["failed_closed"] is True
    assert persisted["status"] == "PASS"
    assert persisted["failed_closed"] is True
