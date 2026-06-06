from __future__ import annotations

from scripts import replay_v17_7_4_reprolock_oracle_offline_extraction as replay


def test_offline_extraction_invokes_no_model_generation_and_preserves_hash_only() -> None:
    rows = {
        "fixture": [
            {
                "sample_id": "gsm8k:test:1",
                "dataset": "gsm8k",
                "task_family": "formal_math",
                "arm_id": "A_true_known_good_math_act_byte_repro",
                "output_text": "Scratch says 12. Therefore the final answer is 42.",
                "expected_answer_hash": replay.sha256_text("42"),
                "parsed_answer": "12",
                "correct": False,
                "parser_format_failure": True,
                "final_answer_marker_present": True,
                "visible_answer_tokens": 1,
                "raw_output_tokens": 8,
                "full_prompt_plus_output_tokens": 30,
            }
        ]
    }

    replay_rows = replay.build_extraction_rows(rows)
    receipt, scorecard, parser_reduction, drift_reduction = replay.build_extraction_scorecards(replay_rows)

    assert receipt["model_generation_invoked"] is False
    assert receipt["expected_answer_visible_to_model"] is False
    assert replay_rows[0]["raw_output_text_committed"] is False
    assert replay_rows[0]["raw_output_hash"] == replay.sha256_text(rows["fixture"][0]["output_text"])
    assert replay_rows[0]["extracted_final_answer"] == "42"
    assert replay_rows[0]["replay_correct"] is True
    assert scorecard["full_system_TPC"] is None
    assert parser_reduction["status"] == "PASS"
    assert drift_reduction["status"] == "PASS"


def test_expected_answer_is_not_used_as_extraction_hint() -> None:
    raw = "I considered 99 first. Final answer: 17"
    extraction = replay.extract_final_answer_contract_v2(raw, "numeric")

    assert extraction["surface"] == "17"
    assert replay.expected_hash_match(extraction["surface"], replay.sha256_text("99")) is False
    assert replay.expected_hash_match(extraction["surface"], replay.sha256_text("17")) is True


def test_token_bridge_keeps_visible_output_and_full_tpc_separate() -> None:
    scorecard = {
        "per_arm": {
            "A_true_known_good_math_act_byte_repro": {
                "visible_tokens_per_correct_after": 1.0,
                "output_tokens_per_correct_after": 44.0,
            }
        }
    }
    bridge, table, boundary = replay.build_token_bridge(scorecard)

    assert bridge["current_visible_tpc_not_full_tpc"] is True
    assert bridge["g2_output_accounting_not_full_system"] is True
    assert table["rows"][0]["full_system_comparable"] is False
    assert table["rows"][2]["accounting_mode"] == "FULL_PROMPT_PLUS_OUTPUT_TOKENS_PER_CORRECT"
    assert "Current visible TPC is current full TPC." in boundary["forbidden_claims"]


def test_extraction_aware_route_v3_is_teacher_only() -> None:
    rows = [
        {
            "source_id": "fixture",
            "sample_id": "x1",
            "dataset": "gsm8k",
            "task_family": "formal_math",
            "arm_id": "A0_base_raw",
            "original_correct": True,
            "replay_correct": True,
            "output_tokens_original": 20,
            "visible_tokens_replay": 1,
        },
        {
            "source_id": "fixture",
            "sample_id": "x1",
            "dataset": "gsm8k",
            "task_family": "formal_math",
            "arm_id": "A_true_known_good_math_act_byte_repro",
            "original_correct": True,
            "replay_correct": True,
            "output_tokens_original": 40,
            "visible_tokens_replay": 1,
        },
    ]

    summary, table, gap = replay.build_extraction_aware_route_v3(rows)

    assert summary["status"] == "PASS_TEACHER_ONLY_NOT_RUNTIME"
    assert summary["runtime_authority"] is False
    assert table[0]["posthoc_only"] is True
    assert table[0]["runtime_admissible_proxy"] is False
    assert gap["micro_furnace_should_collect_route_features"] is True


def test_epc_cannot_authorize_training_or_promotion() -> None:
    scorecard = {
        "parser_failure_rate_before": 0.5,
        "parser_failure_rate_after": 0.1,
        "answer_format_drift_before": 0.5,
        "answer_format_drift_after": 0.1,
        "correctness_original": 0.8,
        "correctness_replay": 0.8,
    }
    decision, priority, next_lane, runtime_warranted = replay.build_epc_after_current(
        scorecard, {"status": "PASS_TEACHER_ONLY_NOT_RUNTIME"}
    )

    assert runtime_warranted is True
    assert decision["training_authorized"] is False
    assert decision["promotion_authority"] is False
    assert next_lane["no_training"] is True
    assert next_lane["no_promotion"] is True
    assert any(item["lane"] == "MICRO_FURNACE_25_WITH_FINAL_ANSWER_EXTRACTION_V2_ONLY" for item in priority["interventions"])
