from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_6_runtime_feature_registry_blocks_oracle_leakage():
    receipt = json.loads((ROOT / "reports/v17_6_no_oracle_leakage_policy_receipt.json").read_text(encoding="utf-8"))
    registry = json.loads((ROOT / "admission/v17_6_runtime_feature_registry.json").read_text(encoding="utf-8"))
    forbidden = set(receipt["forbidden_runtime_features"])
    runtime_features = set(registry["runtime_legal_features"])
    assert receipt["status"] == "PASS"
    assert receipt["oracle_correctness_used_as_feature"] is False
    assert forbidden.isdisjoint(runtime_features)
    assert "oracle_correctness" in forbidden
    assert "gold_answer" in forbidden
