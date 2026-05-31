from __future__ import annotations

import json
from pathlib import Path

from scripts.v16_crossroad_shadow_common import scan_oracle_leakage


ROOT = Path(__file__).resolve().parents[1]


def test_oracle_leakage_scan_blocks_forbidden_runtime_features():
    policy = {
        "allowed_runtime_features": ["math_act_feature_trigger", "oracle_correct"],
    }
    rows = [
        {
            "row_id": "bad",
            "pre_generation_features": {"gold_answer": "42"},
            "oracle_correctness_used_as_feature": False,
        }
    ]
    receipt = scan_oracle_leakage(policy, rows)
    assert receipt["status"] == "FAIL"
    assert receipt["violations"]


def test_generated_oracle_leakage_receipt_passes_after_v16_run():
    if not (ROOT / "reports/v16_oracle_leakage_scan.json").exists():
        return
    receipt = json.loads((ROOT / "reports/v16_oracle_leakage_scan.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["oracle_leakage_rate"] == 0
