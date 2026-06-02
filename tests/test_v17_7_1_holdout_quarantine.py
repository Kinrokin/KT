from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_1_holdout_quarantine_is_not_used_for_search() -> None:
    manifest = read_json(ROOT / "admission" / "v17_7_1_holdout_quarantine_manifest.json")
    integrity = read_json(ROOT / "reports" / "v17_7_1_holdout_integrity_receipt.json")
    assert manifest["holdout_count"] > 0
    assert manifest["holdout_labels_inspected_during_policy_construction"] is False
    assert manifest["holdout_policy_search_used"] is False
    assert integrity["status"] == "PASS"
