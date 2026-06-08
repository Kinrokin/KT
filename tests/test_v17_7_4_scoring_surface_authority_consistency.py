from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run_builder() -> None:
    subprocess.run(
        [sys.executable, "scripts/review_v17_7_4_control_only_gsm8k_regression_parser_court.py"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )


def _json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def _jsonl(path: str) -> list[dict]:
    return [
        json.loads(line)
        for line in (ROOT / path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_scoring_surface_authority_matrix_has_no_unknown_surface_or_visible_answer_leak() -> None:
    _run_builder()

    audit = _json("reports/v17_7_4_scoring_surface_authority_audit.json")
    matrix = _jsonl("reports/v17_7_4_scoring_surface_authority_matrix.jsonl")
    contradictions = _jsonl("reports/v17_7_4_scoring_surface_contradiction_table.jsonl")

    assert audit["status"] == "PASS_WITH_RAW_OUTPUT_REGEX_SCORING_BOUND"
    assert audit["row_count"] == 100
    assert audit["unknown_surface_count"] == 0
    assert audit["expected_answer_model_visible"] is False
    assert len(matrix) == 100
    assert len(contradictions) == 25
    allowed_surfaces = {"PARSED_ANSWER", "VISIBLE_ANSWER", "FINAL_MARKER", "FIRST_LINE", "RAW_OUTPUT_REGEX"}
    assert {row["scorer_declared_surface"] for row in matrix} <= allowed_surfaces
    assert all(row["expected_answer_model_visible"] is False for row in matrix)
    assert all(row["scoring_surface_consistent"] is True for row in matrix)
    assert all(row["scorer_declared_surface"] != "UNKNOWN" for row in matrix)


def test_parser_failure_rows_are_currently_correct_not_global_wrongness_locus() -> None:
    _run_builder()

    matrix = _jsonl("reports/v17_7_4_scoring_surface_authority_matrix.jsonl")
    parser_table = _jsonl("reports/v17_7_4_parser_failure_subtype_table.jsonl")
    by_correctness = _json("reports/v17_7_4_parser_failure_by_correctness_table.json")
    owner_court = _json("reports/v17_7_4_control_only_gsm8k_failure_owner_court.json")

    parser_rows = [row for row in matrix if row["parser_format_failure"]]
    non_parser_wrong = [row for row in matrix if not row["parser_format_failure"] and not row["correct"]]

    assert len(parser_rows) == 22
    assert all(row["correct"] is True for row in parser_rows)
    assert len(parser_table) == 22
    assert all(row["raw_output_contains_expected_offline"] is True for row in parser_table)
    assert len(non_parser_wrong) == 72
    assert by_correctness["parser_format_failure_wrong"] == 0
    assert by_correctness["non_parser_failure_wrong"] == 72
    assert owner_court["main_wrongness_locus"] == "NON_PARSER_FAILURE_ROWS"
