from __future__ import annotations

import json
from pathlib import Path


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_jsonl(path: str) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_kt512base_assessment_import_and_scorecard_are_bound() -> None:
    receipt = load_json("reports/kt512base_assessment_import_receipt.json")
    scorecard = load_json("reports/kt512base_scorecard_reconciliation.json")
    rows = load_jsonl("reports/kt512base_row_policy_matrix.jsonl")

    assert receipt["status"] == "PASS"
    assert receipt["sha256_matches_expected"] is True
    assert receipt["assessment_sha256"] == "127c77b5547eb1d6dd3e0c1f14946b416106148288c32ad31da3a9dec228a6bd"
    assert receipt["row_slice"] == "openai/gsm8k:test[125:325]"
    assert receipt["row_count"] == 200
    assert receipt["oracle_diagnostic_score"] == 1.0
    assert receipt["cot512_correct"] == 184
    assert receipt["cot256_correct"] == 137
    assert receipt["answer_only_correct"] == 30
    assert receipt["training_authority"] is False
    assert receipt["promotion_authority"] is False
    assert scorecard["status"] == "PASS"
    assert all(scorecard["checks"].values())
    assert len(rows) == 200


def test_kt512base_fixed512_baseline_is_control_not_production_mode() -> None:
    baseline = load_json("reports/kt512base_fixed512_baseline_receipt.json")

    assert baseline["status"] == "PASS_FIXED512_STRONG_BASELINE_CONFIRMED"
    assert baseline["arm_id"] == "A0_COT_512_FIXED_PRIMARY"
    assert baseline["correct"] == 184
    assert baseline["accuracy"] == 0.92
    assert "not production math mode" in baseline["interpretation"]
    assert baseline["runtime_authority"] is False
    assert baseline["claim_ceiling_preserved"] is True
