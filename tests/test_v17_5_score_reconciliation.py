from __future__ import annotations

import json
import math
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_5_score_reconciliation_recomputes_known_facts_from_rows():
    receipt = json.loads((ROOT / "reports/v17_5_score_reconciliation_receipt.json").read_text(encoding="utf-8"))
    scorecard = receipt["row_recomputed_scorecard"]
    assert receipt["status"] == "PASS"
    assert all(receipt["known_fact_checks"].values())
    assert scorecard["rows"] == 260
    assert scorecard["base_raw_correct"] == 143
    assert scorecard["feature_bound_correct"] == 159
    assert scorecard["best_single_static_arm"] == "formal_math_repair_adapter_global"
    assert scorecard["best_single_static_arm_correct"] == 160
    assert scorecard["canary_policy_correct"] == 161
    assert scorecard["oracle_correct"] == 187
    assert scorecard["remaining_oracle_gap"] == 26
    assert math.isclose(scorecard["BPR"], 0.972027972027972)
    assert math.isclose(scorecard["HAR"], 0.015384615384615385)
    assert math.isclose(scorecard["OCR"], 0.4090909090909091)


def test_v17_5_best_static_is_not_union_oracle():
    receipt = json.loads((ROOT / "reports/v17_5_best_static_semantics_receipt.json").read_text(encoding="utf-8"))
    assert receipt["best_single_static_arm"] == "formal_math_repair_adapter_global"
    assert receipt["best_single_static_arm_correct"] == 160
    assert receipt["union_oracle_correct"] == 187
    assert receipt["best_single_static_ne_union_oracle"] is True
