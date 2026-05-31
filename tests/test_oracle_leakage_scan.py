import json
from pathlib import Path

ROOT = Path.cwd()


def test_oracle_leakage_scan_passes_and_forbids_oracle_input_features():
    obj = json.loads((ROOT / "reports/oracle_leakage_scan_receipt.json").read_text(encoding="utf-8"))
    assert obj["status"] == "PASS"
    assert obj["oracle_correctness_used_as_feature"] is False
    assert obj["forbidden_feature_hits"] == []
    registry = json.loads((ROOT / "admission/route_value_feature_registry.json").read_text(encoding="utf-8"))
    assert "oracle_correct" in registry["forbidden_features"]
