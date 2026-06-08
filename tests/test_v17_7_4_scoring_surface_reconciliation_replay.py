from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run_builder() -> None:
    subprocess.run(
        [sys.executable, "scripts/replay_v17_7_4_official_scorer_on_gsm8k_extension.py"],
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


def test_official_scorer_replay_reproduces_bound_control_only_score() -> None:
    _run_builder()

    summary = _json("reports/v17_7_4_scoring_surface_reconciliation_replay_builder_summary.json")
    receipt = _json("reports/v17_7_4_official_scorer_replay_receipt.json")
    matrix = _jsonl("reports/v17_7_4_official_scorer_replay_matrix.jsonl")

    assert summary["outcome"] == "KT_SCORING_SURFACE_RECONCILIATION_REPLAY_COMPLETE__NEXT_EVIDENCE_LANE_DECIDED__CLAIM_CEILING_PRESERVED"
    assert summary["packet_path_if_any"] is None
    assert summary["next_lawful_move"] == "AUTHOR_GSM8K_CAPABILITY_GAP_AUTOPSY_V1"
    assert receipt["status"] == "PASS_REPRODUCED_28_OF_100"
    assert receipt["official_scorer_replay_correct"] == 28
    assert receipt["official_scorer_replay_total"] == 100
    assert receipt["row_mismatch_count"] == 0
    assert len(matrix) == 100
    assert all(row["row_replay_matches_current"] is True for row in matrix)
    assert all(row["official_scoring_surface"] == "RAW_OUTPUT_REGEX" for row in matrix)
    assert all(row["expected_answer_model_visible"] is False for row in matrix)


def test_surface_extraction_reconciles_every_row_without_expected_answer_visibility() -> None:
    _run_builder()

    receipt = _json("reports/v17_7_4_scoring_surface_extraction_receipt.json")
    rows = _jsonl("reports/v17_7_4_scoring_surface_replay_table.jsonl")

    assert receipt["status"] == "PASS"
    assert receipt["row_count"] == 100
    assert receipt["unknown_scoring_surface_count"] == 0
    assert receipt["scoring_surface_source_counts"] == {"RAW_OUTPUT_REGEX": 100}
    assert receipt["expected_answer_model_visible"] is False
    assert len(rows) == 100
    assert all(row["expected_answer_model_visible"] is False for row in rows)
    assert all(row["scoring_surface_source"] == "RAW_OUTPUT_REGEX" for row in rows)
    assert all(row["current_surface_used_for_scoring"] == "RAW_OUTPUT" for row in rows)
    assert all("expected_answer" not in row for row in rows)


def test_alternative_surface_replay_is_audit_only_and_does_not_authorize_parser_repair() -> None:
    _run_builder()

    summary = _json("reports/v17_7_4_alternative_surface_replay_summary.json")
    matrix = _jsonl("reports/v17_7_4_alternative_surface_replay_matrix.jsonl")

    assert summary["status"] == "PASS_AUDIT_ONLY"
    assert summary["alternative_surface_replay_audit_only"] is True
    assert summary["parser_repair_authorized"] is False
    assert summary["score_revision_authorized"] is False
    assert summary["policies"]["current_official_scorer"]["correct_count"] == 28
    assert summary["policies"]["raw_output_regex_only"]["correct_count"] == 28
    assert summary["policies"]["parsed_answer_only"]["damage_to_official_correct"] == 21
    assert summary["policies"]["visible_answer_only"]["damage_to_official_correct"] == 20
    assert all(row["policy_runtime_authority"] is False for row in matrix)
    assert all(row["admissible_for_runtime"] is False for row in matrix)


def test_contradiction_and_parser_courts_separate_reporting_defects_from_capability_gap() -> None:
    _run_builder()

    court = _json("reports/v17_7_4_scoring_surface_contradiction_court.json")
    parser = _json("reports/v17_7_4_parser_subtype_reconciliation_update.json")
    scorecard = _json("reports/v17_7_4_control_only_gsm8k_reconciled_scorecard.json")
    owner = _json("reports/v17_7_4_control_only_gsm8k_reconciled_owner_matrix.json")

    assert court["status"] == "PASS"
    assert court["score_source_unknown_count"] == 0
    assert court["owner_counts"]["PARSER_REPORTING_DEFECT"] == 22
    assert court["owner_counts"]["GENERATION_MATH_OWNED"] == 72
    assert court["parser_repair_authorized"] is False
    assert court["score_revision_authorized"] is False
    assert parser["status"] == "PASS"
    assert parser["parser_format_failure_rows"] == 22
    assert parser["parser_failures_officially_correct"] == 22
    assert parser["parser_failures_officially_wrong"] == 0
    assert parser["parser_failures_counted_as_math_failures"] == 0
    assert scorecard["status"] == "PASS_RECONCILED"
    assert scorecard["official_score"] == "28/100"
    assert scorecard["rows_with_unknown_score_surface"] == 0
    assert scorecard["rows_with_true_generation_math_failure_estimate"] == 72
    assert scorecard["parser_runtime_repair_authority"] is False
    assert scorecard["v3_rescue_runtime_authority"] is False
    assert scorecard["scratchpad_runtime_authority"] is False
    assert owner["next_owner_to_autopsy"] == "GSM8K_CAPABILITY_GAP"


def test_claim_boundary_and_epc_select_no_runtime_capability_gap_autopsy() -> None:
    _run_builder()

    claim = _json("reports/v17_7_4_scoring_surface_reconciliation_claim_boundary_receipt.json")
    epc = _json("reports/v17_7_4_epc_decision_after_scoring_surface_reconciliation.json")
    next_lane = _json("reports/v17_7_4_scoring_surface_reconciliation_next_lane.json")

    for receipt in [claim, epc, next_lane]:
        assert receipt["claim_ceiling_preserved"] is True
        assert receipt["runtime_authority"] is False
        assert receipt["promotion_authority"] is False
        assert receipt["router_superiority_claim"] is False
        assert receipt["g2_recovered_claim"] is False
        assert receipt["commercial_claim"] is False

    assert claim["runtime_packet_generated"] is False
    assert claim["score_revision_authorized"] is False
    assert epc["selected_next_lane"] == "AUTHOR_GSM8K_CAPABILITY_GAP_AUTOPSY_V1"
    assert epc["runtime_allowed_by_this_lane"] is False
    assert next_lane["status"] == "PASS_NO_RUNTIME_PACKET"
    assert next_lane["packet_path_if_any"] is None
    assert next_lane["kaggle_dataset_name_if_any"] is None
