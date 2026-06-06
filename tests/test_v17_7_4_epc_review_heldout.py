from __future__ import annotations

from scripts import review_v17_7_4_epc_after_offline_extraction as review


def test_harmful_extraction_blocks_global_runtime_integration() -> None:
    rows = [
        {
            "source_id": "fixture",
            "sample_id": "x1",
            "dataset": "gsm8k",
            "task_family": "formal_math",
            "arm_id": "A_true_known_good_math_act_byte_repro",
            "original_correct": True,
            "replay_correct": False,
            "extraction_ambiguous": True,
            "extraction_surface": "last_numeric_surface",
            "extraction_state": "EXTRACTED_NUMERIC",
            "answer_format_drift_original": True,
            "parser_failure_original": False,
        }
    ]
    scorecard = {"correctness_original": 1.0, "correctness_replay": 0.0}

    autopsy, eligibility, harm_rows, subset = review.build_extraction_autopsy(rows, scorecard)
    quarantine, subset_policy, _ = review.build_quarantine_receipts(eligibility, subset)

    assert autopsy["correct_to_incorrect_rows"] == 1
    assert eligibility["status"] == "NOT_RUNTIME_ELIGIBLE_REDUCED_CORRECTNESS"
    assert eligibility["global_runtime_integration_allowed"] is False
    assert quarantine["global_finalizer_extraction_quarantined"] is True
    assert subset_policy["global_runtime_authority"] is False
    assert harm_rows[0]["expected_answer_visible_to_model"] is False


def test_safe_subset_candidate_cannot_use_expected_answers() -> None:
    rows = [
        {
            "source_id": "fixture",
            "sample_id": f"x{i}",
            "dataset": "arc_challenge",
            "task_family": "science_reasoning",
            "arm_id": "A0_base_raw",
            "original_correct": False,
            "replay_correct": True,
            "extraction_ambiguous": False,
            "extraction_surface": "explicit_final_marker",
            "extraction_state": "EXTRACTED_EXPLICIT_FINAL",
            "answer_format_drift_original": False,
            "parser_failure_original": True,
        }
        for i in range(10)
    ]

    _, _, _, subset = review.build_extraction_autopsy(rows, {"correctness_original": 0.0, "correctness_replay": 1.0})

    assert subset["status"] == "SAFE_SUBSET_CANDIDATE_ONLY"
    assert subset["expected_answer_used_for_policy"] is False
    assert subset["runtime_authority"] is False
    assert subset["safe_buckets"][0]["runtime_features_only"] is True


def test_epc_does_not_authorize_packet_without_bound_heldout_source() -> None:
    eligibility = {"status": "NOT_RUNTIME_ELIGIBLE_REDUCED_CORRECTNESS"}
    subset = {"status": "NO_SAFE_SUBSET_FOUND"}
    heldout_design = {
        "status": "PASS_DESIGN_ONLY__HELDOUT_ROW_SOURCE_NOT_BOUND",
        "runtime_packet_authorizable": False,
    }

    decision, _, next_lane = review.build_epc_decision(eligibility, subset, heldout_design)

    assert decision["kaggle_packet_warranted_next"] is False
    assert decision["packet_type"] is None
    assert "HELDOUT_ROW_SOURCE_NOT_BOUND" in decision["blockers"]
    assert next_lane["packet_path_if_any"] is None


def test_epc_can_authorize_only_narrow_heldout_when_source_is_bound() -> None:
    eligibility = {"status": "NOT_RUNTIME_ELIGIBLE_REDUCED_CORRECTNESS"}
    subset = {"status": "NO_SAFE_SUBSET_FOUND"}
    heldout_design = {
        "status": "PASS_HELDOUT_PACKET_AUTHORIZABLE",
        "runtime_packet_authorizable": True,
    }

    decision, _, next_lane = review.build_epc_decision(eligibility, subset, heldout_design)

    assert decision["kaggle_packet_warranted_next"] is True
    assert decision["run_mode"] == "RUN_KTV1774_REPROLOCK_HELDOUT_GENERALIZATION_50"
    assert decision["training_authorized"] is False
    assert decision["promotion_authorized"] is False
    assert next_lane["no_g2_recovered_claim"] is True


def test_manifest_summary_excludes_diagnostic_rows_as_heldout_authority() -> None:
    diagnostic = {
        "exists": True,
        "row_count": 100,
        "holdout_statuses": ["TRAINING_SEARCH_DIAGNOSTIC"],
        "label_sources": ["SOURCE_SEED_SAMPLE_ID_DIAGNOSTIC_LABEL"],
    }

    assert review.heldout_source_is_bound(diagnostic) is False
