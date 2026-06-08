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


def test_control_only_gsm8k_regression_parser_court_binds_runtime_and_metrics() -> None:
    _run_builder()

    summary = _json("reports/v17_7_4_control_only_gsm8k_regression_parser_court_builder_summary.json")
    runtime = _json("reports/v17_7_4_control_only_gsm8k_runtime_binding.json")
    scorecard = _json("reports/v17_7_4_control_only_gsm8k_scorecard_binding.json")
    tokens = _json("reports/v17_7_4_control_only_gsm8k_token_binding.json")
    frontier = _json("reports/v17_7_4_control_only_gsm8k_frontier_update.json")

    assert summary["outcome"] == "KT_CONTROL_ONLY_GSM8K_EXTENSION_REVIEWED__REGRESSION_PARSER_COURT_COMPLETE__CLAIM_CEILING_PRESERVED"
    assert summary["packet_path_if_any"] is None
    assert summary["kaggle_dataset_name_if_any"] is None
    assert summary["next_lawful_move"] == "AUTHOR_SCORING_SURFACE_RECONCILIATION_REPLAY_V1"
    assert runtime["status"] == "BOUND"
    assert runtime["row_count"] == 100
    assert runtime["measurement_status"] == "MODEL_GENERATED_AND_SCORED"
    assert scorecard["correct"] == 28
    assert scorecard["total"] == 100
    assert scorecard["accuracy"] == 0.28
    assert tokens["full_prompt_plus_output_tokens_per_correct"] == 347.464286
    assert tokens["visible_answer_tokens_per_correct"] == 3.571429
    assert tokens["verified_work_per_token"] == 0.002878
    assert frontier["status"] == "BLOCKED_REGRESSION_BOUND"
    assert frontier["generic_larger_furnace_label_not_authority"] is True


def test_control_only_gsm8k_parser_court_rejects_blanket_parser_or_scorer_owner() -> None:
    _run_builder()

    parser_court = _json("reports/v17_7_4_parser_failure_subtype_court.json")
    by_correctness = _json("reports/v17_7_4_parser_failure_by_correctness_table.json")
    repairability = _json("reports/v17_7_4_control_only_gsm8k_repairability_matrix.json")
    owner_court = _json("reports/v17_7_4_control_only_gsm8k_failure_owner_court.json")
    verifier_plan = _json("reports/v17_7_4_control_only_gsm8k_verifier_rescue_plan_review.json")

    assert parser_court["status"] == "PASS"
    assert parser_court["parser_format_failure_rows"] == 22
    assert parser_court["parser_format_failure_correct"] == 22
    assert parser_court["parser_format_failure_wrong"] == 0
    assert parser_court["non_parser_failure_wrong"] == 72
    assert parser_court["blanket_scorer_owned_allowed"] is False
    assert by_correctness["non_parser_failure_rows"] == 78
    assert by_correctness["non_parser_failure_correct"] == 6
    assert by_correctness["non_parser_failure_wrong"] == 72
    assert repairability["blanket_scorer_owned_corrected"] is True
    assert repairability["scorer_owned_is_not_global_owner"] is True
    assert repairability["parser_runtime_repair_authorized"] is False
    assert repairability["training_authorized"] is False
    assert owner_court["blanket_owner_vote_rejected"] == "SCORER_OWNED"
    assert owner_court["parser_repair_runtime_authorized"] is False
    assert verifier_plan["status"] == "PLAN_ONLY_NO_RUNTIME_AUTHORITY"
    assert verifier_plan["llm_verifier_rescue_allowed"] is False


def test_control_only_gsm8k_claim_boundary_and_epc_hold_runtime() -> None:
    _run_builder()

    claim = _json("reports/v17_7_4_control_only_gsm8k_claim_boundary_receipt.json")
    epc = _json("reports/v17_7_4_epc_decision_after_control_only_gsm8k_extension.json")
    next_lane = _json("reports/v17_7_4_control_only_gsm8k_next_lane.json")
    answer_format = _json("reports/v17_7_4_control_only_gsm8k_answer_format_contract_audit.json")
    final_marker = _json("reports/v17_7_4_final_marker_absence_receipt.json")

    for receipt in [claim, epc, next_lane, answer_format, final_marker]:
        assert receipt["claim_ceiling_preserved"] is True
        assert receipt["runtime_authority"] is False
        assert receipt["promotion_authority"] is False
        assert receipt["router_superiority_claim"] is False
        assert receipt["g2_recovered_claim"] is False
        assert receipt["commercial_claim"] is False

    assert claim["runtime_packet_generated"] is False
    assert claim["training_authorized"] is False
    assert epc["selected_next_lane"] == "AUTHOR_SCORING_SURFACE_RECONCILIATION_REPLAY_V1"
    assert epc["runtime_allowed_by_this_lane"] is False
    assert next_lane["status"] == "PASS_NO_RUNTIME_PACKET"
    assert next_lane["packet_path_if_any"] is None
    assert answer_format["final_marker_rows"] == 8
    assert answer_format["no_final_marker_rows"] == 92
    assert final_marker["final_marker_rate"] == 0.08
