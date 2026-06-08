from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def read_jsonl(path: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def test_parser_canonicalizer_noop_preserves_current_scorer_row_by_row() -> None:
    receipt = read_json("reports/v17_7_4_answer_surface_audit_noop_invariant_receipt.json")
    rows = read_jsonl("reports/v17_7_4_parser_canonicalizer_noop_baseline_table.jsonl")

    assert receipt["status"] == "PASS"
    assert receipt["control_correct_preservation_rate"] == 1.0
    assert receipt["damage_to_control_correct"] == 0
    assert receipt["parser_net_accuracy_delta"] == 0
    assert rows
    assert all(row["noop_correct"] == row["baseline_correct"] for row in rows)
    assert all(row["selected_surface_id"] == "CURRENT_SCORER_NOOP_BYPASS" for row in rows)
    assert all(row["expected_answer_model_visible"] is False for row in rows)
    assert all(row["first_pass_mutated"] is False for row in rows)
