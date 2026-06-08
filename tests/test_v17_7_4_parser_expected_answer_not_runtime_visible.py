from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / "kt_system" / "eval" / "parser_canonicalizer_v17_7_4.py"


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def read_jsonl(path: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def test_parser_module_does_not_reference_expected_answer_or_gold_fields() -> None:
    source = PARSER.read_text(encoding="utf-8").lower()
    forbidden = [
        "gold_answer",
        "gold_label",
        "oracle_answer",
        "expected_hash",
        "expected_answer_hash",
    ]
    for token in forbidden:
        assert token not in source


def test_expected_answer_leakage_diff_passes_and_rows_hide_gold_from_runtime() -> None:
    leakage = read_json("reports/v17_7_4_parser_expected_answer_leakage_diff.json")
    rows = read_jsonl("reports/v17_7_4_parser_canonicalizer_row_table.jsonl")

    assert leakage["status"] == "PASS"
    assert leakage["expected_answer_fields_seen_by_runtime"] == []
    assert leakage["expected_answer_used_for_candidate_selection"] is False
    assert leakage["expected_answer_used_for_canonicalization"] is False
    assert all(row["expected_answer_model_visible"] is False for row in rows)
    assert all(row["expected_answer_used_for_candidate_selection"] is False for row in rows)
