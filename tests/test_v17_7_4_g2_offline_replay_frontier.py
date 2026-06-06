from __future__ import annotations

from scripts import replay_v17_7_4_g2_bound_raw_output_extraction as replay


def test_extraction_replay_uses_raw_text_without_model_generation() -> None:
    rows = [
        {
            "dataset": "gsm8k",
            "item_id": "gsm8k-1",
            "subject": "base_raw",
            "raw_prediction": "Step 1... Therefore the final answer is 42",
            "normalized_answer": "42",
            "normalized_prediction": "42",
            "correct": True,
            "new_tokens": 12,
            "extraction_ok": True,
        },
        {
            "dataset": "arc_challenge",
            "item_id": "arc-1",
            "subject": "base_raw",
            "raw_prediction": "The best option is C.",
            "normalized_answer": "C",
            "normalized_prediction": "C",
            "correct": True,
            "new_tokens": 2,
            "extraction_ok": True,
        },
    ]
    replay_rows = replay.build_extraction_rows(rows)
    receipt, scorecard, reduction = replay.build_extraction_scorecard(replay_rows)

    assert receipt["model_generation_invoked"] is False
    assert receipt["expected_answer_visible_to_model"] is False
    assert scorecard["full_system_TPC"] is None
    assert scorecard["replay_correct"] == 2
    assert reduction["status"] == "PASS"


def test_token_bridge_forbids_collapsing_g2_output_tpc_into_full_tpc() -> None:
    _, scorecard, _ = replay.build_extraction_scorecard([])
    bridge, table, boundary = replay.build_token_bridge(scorecard)

    assert bridge["status"] == "PASS"
    assert bridge["g2_3_74_accounting"] == "OUTPUT_NEW_TOKENS_PER_CORRECT"
    assert bridge["directly_comparable"] is False
    assert table["rows"][0]["full_system_comparable"] is False
    assert "G2 full-system compression recovered." in boundary["forbidden_claims"]


def test_frontier_definition_keeps_axes_separate() -> None:
    definition, dual_mode, registry = replay.build_frontiers()

    assert definition["status"] == "PASS"
    assert "verified_intelligence_frontier" in definition["frontiers"]
    assert "output_compression_frontier" in definition["frontiers"]
    assert "full_system_compression_frontier" in definition["frontiers"]
    assert definition["frontiers"]["full_system_compression_frontier"]["stages"][-1].startswith("F5:")
    assert dual_mode["no_mode_claims_global_superiority"] is True
    assert registry["target_order"][0] == "preserve_verified_intelligence"


def test_cheapest_correct_v2_is_teacher_only_and_blocks_runtime_features() -> None:
    rows = [
        {"dataset": "d", "item_id": "1", "subject": "a", "correct": True, "new_tokens": 10},
        {"dataset": "d", "item_id": "1", "subject": "b", "correct": True, "new_tokens": 2},
        {"dataset": "d", "item_id": "2", "subject": "a", "correct": False, "new_tokens": 1},
    ]
    summary, table, audit = replay.build_cheapest_correct_v2(rows)

    assert summary["status"] == "PASS_TEACHER_ONLY_NOT_RUNTIME"
    assert summary["runtime_authority"] is False
    assert table[0]["cheapest_correct_arm"] == "b"
    assert table[0]["posthoc_only"] is True
    assert "oracle_correctness_or_gold_answer" == table[0]["prohibited_runtime_feature"]
    assert "correct" in audit["posthoc_features_prohibited"]


def test_epc_next_lane_blocks_kaggle_runtime_packet() -> None:
    scorecard = {"status": "PASS"}
    frontier = {"status": "PASS"}
    sim = {"status": "PASS_TEACHER_ONLY_NOT_RUNTIME"}
    decision, priority, next_lane = replay.build_epc_next(scorecard, frontier, sim)

    assert decision["status"] == "PASS"
    assert decision["runtime_generation_authorized"] is False
    assert decision["training_authorized"] is False
    assert next_lane["next_lawful_move"] == "REVIEW_G2_OFFLINE_REPLAY_AND_EPC_DECISION"
    assert next_lane["no_kaggle_runtime_packet"] is True
    assert any(item["lane"] == "MICRO_FURNACE_25" and item.get("allowed") is False for item in priority["interventions"])
