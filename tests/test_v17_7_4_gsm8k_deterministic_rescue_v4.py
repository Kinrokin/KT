from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from kt_system.eval.gsm8k_deterministic_rescue_v4 import DeterministicRescueV4, SafeArithmeticEvaluator


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def read_jsonl(path: str) -> list[dict]:
    return [
        json.loads(line)
        for line in (ROOT / path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def run_builder() -> dict:
    completed = subprocess.run(
        [sys.executable, "scripts/replay_v17_7_4_gsm8k_deterministic_rescue_v4.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(completed.stdout)


def test_safe_arithmetic_evaluator_allows_only_explicit_arithmetic() -> None:
    evaluator = SafeArithmeticEvaluator()

    assert evaluator.evaluate("12 + 7") == "19"
    assert evaluator.evaluate("(3 + 5) * 2") == "16"
    assert evaluator.evaluate("3/4") == "3/4"
    assert evaluator.evaluate("$1,200 - 300") == "900"

    assert evaluator.evaluate("x + 1") is None
    assert evaluator.evaluate("__import__('os')") is None
    assert evaluator.evaluate("2 ** 3") is None
    assert evaluator.evaluate("12/0") is None
    assert evaluator.evaluate("5 apples + 3") is None


def test_rescue_extractor_emits_only_frozen_high_precision_candidates() -> None:
    rescuer = DeterministicRescueV4()

    explicit = rescuer.rescue_from_output("12 + 7 = 19")
    assert explicit.status == "RESCUE_CANDIDATE_EMITTED"
    assert explicit.candidate == "19"
    assert explicit.candidate_source == "MODEL_OUTPUT_EXPLICIT_ARITHMETIC_LINE"
    assert not explicit.answer_surface_audit_only

    unsafe = rescuer.rescue_from_output("I first computed 12 + 7 = 19, but that was not the final answer.")
    assert unsafe.status == "ABSTAIN_NO_DETERMINISTIC_RULE"
    assert unsafe.candidate is None

    audit_only = rescuer.rescue_from_output("Final answer: 42")
    assert audit_only.status == "ANSWER_SURFACE_CANDIDATE_AUDIT_ONLY"
    assert audit_only.candidate == "42"
    assert audit_only.answer_surface_audit_only

    no_search = rescuer.rescue_from_output("The numbers are 2, 3, and 5.")
    assert no_search.status == "ABSTAIN_NO_DETERMINISTIC_RULE"
    assert no_search.candidate is None

    trivial = rescuer.rescue_from_problem_text("What is 5 + 3?")
    assert trivial.status == "RESCUE_CANDIDATE_EMITTED"
    assert trivial.candidate == "8"

    broader_problem = rescuer.rescue_from_problem_text("5 + 3 is part of the problem, but then she doubles it.")
    assert broader_problem.status == "ABSTAIN_NO_FULLMATCH"
    assert broader_problem.candidate is None


def test_builder_replays_offline_and_preserves_no_runtime_authority() -> None:
    summary = run_builder()

    assert summary["outcome"] == (
        "KT_GSM8K_DETERMINISTIC_RESCUE_OFFLINE_REPLAY_COMPLETE__"
        "NEXT_LANE_DECIDED__CLAIM_CEILING_PRESERVED"
    )
    assert summary["deterministic_rescue_binding_status"] == "BOUND"
    assert summary["candidate_source_freeze_status"] == "PASS"
    assert summary["safe_arithmetic_evaluator_status"] == "PASS"
    assert summary["negative_control_status"] == "PASS"
    assert summary["offline_replay_status"] == "PASS"
    assert summary["cross_anchor_replay_status"] == "PASS_EXTENSION_REQUIRED_PRIOR_ANCHORS_REVIEW_ONLY"
    assert summary["rule_ablation_status"] == "PASS"
    assert summary["damage_to_official_correct"] == 0
    assert summary["rescued_official_wrong_count"] == 0
    assert summary["net_accuracy_delta"] == 0
    assert summary["deterministic_rescue_ceiling"] == "DETERMINISTIC_RESCUE_CEILING_LOW"
    assert summary["cost_model_status"] == "PASS"
    assert summary["packet_path_if_any"] is None
    assert summary["packet_sha256_if_any"] is None
    assert summary["kaggle_dataset_name_if_any"] is None
    assert summary["one_cell_runbook_if_any"] is None
    assert summary["claim_ceiling_status"] == "PRESERVED"
    assert summary["blockers"] == []
    assert summary["next_lawful_move"] == "AUTHOR_ACADEMY_REPAIR_PLAN_ONLY_NO_TRAINING"

    assert not summary["runtime_authority"]
    assert not summary["promotion_authority"]
    assert not summary["adapter_training_authorized"]
    assert not summary["router_training_authorized"]
    assert not summary["g2_recovered_claim"]
    assert not summary["gsm8k_recovery_claim"]
    assert not summary["router_superiority_claim"]


def test_replay_receipts_are_hash_only_and_zero_damage() -> None:
    replay = read_json("reports/v17_7_4_gsm8k_deterministic_rescue_offline_replay.json")
    assert replay["official_correct_count"] == 28
    assert replay["official_wrong_count"] == 72
    assert replay["rescue_candidate_count"] == 0
    assert replay["answer_surface_audit_candidate_count"] == 0
    assert replay["rescue_attempt_rate"] == 0.0
    assert replay["damage_to_official_correct"] == 0
    assert replay["control_correct_preservation_rate"] == 1.0
    assert replay["rescued_official_wrong_count"] == 0
    assert replay["net_accuracy_delta"] == 0
    assert replay["deterministic_rescue_ceiling"] == "DETERMINISTIC_RESCUE_CEILING_LOW"
    assert replay["abstention_rate"] == 1.0
    assert replay["runtime_packet_warranted"] is False

    rows = read_jsonl("reports/v17_7_4_gsm8k_deterministic_rescue_row_table.jsonl")
    assert len(rows) == 100
    assert all(row["candidate_extraction_frozen_before_scoring"] for row in rows)
    assert all(row["expected_answer_model_visible"] is False for row in rows)
    assert all(row["expected_answer_used_for_candidate_selection"] is False for row in rows)
    assert all(row["expected_answer_used_offline_only"] is True for row in rows)
    assert all(row["raw_output_text_committed"] is False for row in rows)
    assert all(row["runtime_authority"] is False for row in rows)
    assert all("expected_answer" not in row for row in rows)
    assert all("raw_output_text" not in row for row in rows)


def test_freeze_negative_controls_and_cost_model_stay_bounded() -> None:
    freeze = read_json("reports/v17_7_4_gsm8k_rescue_candidate_source_freeze.json")
    assert freeze["status"] == "PASS"
    assert freeze["frozen_before_expected_answer_comparison"] is True
    assert freeze["arbitrary_set_of_numbers_search_allowed"] is False
    assert freeze["natural_language_word_problem_parsing_allowed"] is False
    assert freeze["expected_answer_guided_candidate_selection_allowed"] is False

    negative = read_json("reports/v17_7_4_gsm8k_deterministic_rescue_negative_control_receipt.json")
    assert negative["status"] == "PASS"
    assert negative["negative_controls_pass"] is True
    assert negative["failed_count"] == 0

    cost = read_json("reports/v17_7_4_gsm8k_deterministic_rescue_cost_model.json")
    assert cost["status"] == "PASS"
    assert cost["added_model_tokens"] == 0
    assert cost["added_prompt_tokens"] == 0
    assert cost["added_generation_tokens"] == 0
    assert cost["full_tpc_model_side_changed"] is False
    assert cost["no_runtime_claim"] is True


def test_static_source_does_not_use_forbidden_rescue_surfaces() -> None:
    source = (ROOT / "kt_system/eval/gsm8k_deterministic_rescue_v4.py").read_text(encoding="utf-8")
    forbidden = [
        "sympy",
        "nltk",
        "spacy",
        "sklearn",
        "torch",
        "transformers",
        "peft",
        "eval(",
        "exec(",
        "parse_expr",
    ]
    for token in forbidden:
        assert token not in source
