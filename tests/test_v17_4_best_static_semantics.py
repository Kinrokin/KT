from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_best_static_is_split_from_union_oracle_and_named_oracle():
    receipt = json.loads((ROOT / "reports/v17_4_best_static_semantics_receipt.json").read_text(encoding="utf-8"))
    assert receipt["best_static_semantically_corrupted_in_raw_scorecard"] is True
    assert receipt["best_single_static_arm"] == "formal_math_repair_adapter_global"
    assert receipt["best_single_static_arm_correct"] == 160
    assert receipt["union_oracle_static_arms_correct"] == 187
    assert receipt["named_oracle_correct"] == 187
    assert receipt["best_single_static_arm_correct"] < receipt["named_oracle_correct"]
