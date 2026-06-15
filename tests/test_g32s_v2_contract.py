from __future__ import annotations

from g32_test_utils import load_json, read_jsonl


def test_g32s_blocks_384_deployment_when_false_downshift_damage_exists() -> None:
    report = load_json("reports/g32s_384_false_downshift_by_stratum.json")
    candidate = load_json("reports/g32s_384_safe_stratum_candidate.json")
    rows = read_jsonl("reports/g32s_false384_causal_matrix.jsonl")

    assert report["status"] == "BLOCKS_384_DEPLOYMENT"
    assert report["false_downshift_damage"] == 7
    assert len(rows) == 7
    assert candidate["status"] == "CANDIDATE_ONLY_NOT_DEPLOYABLE"
    assert candidate["selector_deployment_authority"] is False


def test_g32s_binds_640_as_sentinel_only() -> None:
    report = load_json("reports/g32s_640_recovery_damage_by_stratum.json")
    continue_rows = read_jsonl("reports/g32s_continue_when_helpful_seed.jsonl")
    stop_rows = read_jsonl("reports/g32s_stop_before_overthink_seed.jsonl")

    assert report["status"] == "SENTINEL_ONLY"
    assert report["cot640_recovery_count"] == 4
    assert report["cot640_damage_count"] == 2
    assert len(continue_rows) == 4
    assert len(stop_rows) == 2
    assert report["selector_deployment_authority"] is False


def test_g32s_selector_seed_is_label_blind_and_replay_only() -> None:
    policy = load_json("policies/g32s_difficulty_aware_selector_v2.json")

    assert policy["status"] == "SEED_ONLY_NO_RUNTIME_AUTHORITY"
    assert "COT512_INSUFFICIENT" in policy["classes"]
    assert "row_id" in policy["forbidden_features"]
    assert "expected_answer" in policy["forbidden_features"]
    assert "measured_arm_correctness" in policy["forbidden_features"]
    assert "posthoc_correctness" in policy["forbidden_features"]
    assert policy["selector_deployment_authority"] is False


def test_g32s_selects_one_next_lane() -> None:
    next_lane = load_json("reports/g32s_next_lane_decision.json")

    assert next_lane["status"] == "PASS_SINGLE_NEXT_LANE_SELECTED"
    assert next_lane["selected_next_lawful_move"] == "AUTHOR_KTPARETO_COUNTERFACTUAL_MICROFURNACE_PACKET_V1"
    assert next_lane["training_authority"] is False
    assert next_lane["runtime_authority"] is False
