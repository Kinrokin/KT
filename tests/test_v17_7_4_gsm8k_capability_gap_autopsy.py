from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run_builder() -> None:
    subprocess.run(
        [sys.executable, "scripts/autopsy_v17_7_4_gsm8k_capability_gap.py"],
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


def _assert_claim_boundary(receipt: dict) -> None:
    assert receipt["claim_ceiling_preserved"] is True
    assert receipt["runtime_authority"] is False
    assert receipt["promotion_authority"] is False
    assert receipt["router_superiority_claim"] is False
    assert receipt["learned_router_superiority_claim"] is False
    assert receipt["g2_recovered_claim"] is False
    assert receipt["commercial_claim"] is False
    assert receipt["s_tier_claim"] is False
    assert receipt["seven_b_claim"] is False
    assert receipt["production_readiness_claim"] is False


def test_gsm8k_capability_gap_autopsy_binds_official_score_and_claim_ceiling() -> None:
    _run_builder()

    summary = _json("reports/v17_7_4_gsm8k_capability_gap_autopsy_builder_summary.json")
    predecessor = _json("reports/v17_7_4_gsm8k_capability_gap_predecessor_binding.json")
    score_lock = _json("reports/v17_7_4_gsm8k_official_score_lock.json")
    claim = _json("reports/v17_7_4_gsm8k_capability_gap_claim_boundary_receipt.json")

    assert summary["outcome"] == "KT_GSM8K_CAPABILITY_GAP_AUTOPSIED__NEXT_REPAIR_OR_DATA_LANE_DECIDED__CLAIM_CEILING_PRESERVED"
    assert summary["packet_path_if_any"] is None
    assert summary["packet_sha256_if_any"] is None
    assert summary["kaggle_dataset_name_if_any"] is None
    assert summary["one_cell_runbook_if_any"] is None
    assert summary["next_lawful_move"] == "AUTHOR_KTV1774_GSM8K_MAXTOKEN_SENSITIVITY_DESIGN_V1"
    assert predecessor["status"] == "BOUND"
    assert predecessor["official_scorer_replay_status"] == "PASS_REPRODUCED_28_OF_100"
    assert predecessor["official_score"] == "28/100"
    assert score_lock["status"] == "PASS"
    assert score_lock["official_correct"] == 28
    assert score_lock["official_total"] == 100
    assert score_lock["official_surface_policy"] == "RAW_OUTPUT_REGEX_SCORING_BOUND"
    assert score_lock["no_score_revision_authorized"] is True
    assert claim["runtime_packet_generated"] is False
    assert claim["training_authority"] is False
    assert claim["adapter_training_authorized"] is False
    assert claim["router_training_authorized"] is False

    for receipt in [summary, predecessor, score_lock, claim]:
        _assert_claim_boundary(receipt)


def test_gsm8k_row_topology_is_hash_only_and_deterministic() -> None:
    _run_builder()

    topology = _json("reports/v17_7_4_gsm8k_row_difficulty_topology.json")
    rows = _jsonl("reports/v17_7_4_gsm8k_row_difficulty_table.jsonl")

    assert topology["status"] == "PASS"
    assert topology["deterministic_features_only"] is True
    assert topology["extension_all"]["row_count"] == 100
    assert topology["extension_all"]["correct_count"] == 28
    assert topology["extension_all"]["wrong_count"] == 72
    assert len(rows) == 100

    forbidden_answer_fields = {"expected_answer", "gold_answer", "target_answer"}
    for row in rows:
        assert row["schema_id"] == "kt.v17_7_4.gsm8k_row_difficulty_row.v1"
        assert row["dataset"] == "gsm8k"
        assert row["expected_answer_model_visible"] is False
        assert "expected_answer_hash" in row
        assert not forbidden_answer_fields.intersection(row)
        assert row["runtime_authority"] is False
        assert row["router_training_authorized"] is False
        assert row["adapter_training_authorized"] is False


def test_gsm8k_failure_topology_protects_correct_rows_and_blocks_runtime_rescue() -> None:
    _run_builder()

    wrong = _json("reports/v17_7_4_gsm8k_wrong_row_failure_topology.json")
    correct = _json("reports/v17_7_4_gsm8k_correct_row_protection_topology.json")
    wrong_rows = _jsonl("reports/v17_7_4_gsm8k_wrong_row_autopsy.jsonl")
    correct_rows = _jsonl("reports/v17_7_4_gsm8k_correct_row_autopsy.jsonl")

    assert wrong["status"] == "PASS"
    assert wrong["wrong_row_count"] == 72
    assert wrong["expected_answers_hash_only"] is True
    assert wrong["runtime_rescue_authorized"] is False
    assert wrong["failure_topology_counts"] == {
        "MULTISTEP_STATE_TRACKING_ERROR": 20,
        "TRUNCATION_OR_BUDGET_ERROR": 51,
        "UNIT_OR_QUANTITY_TRACKING_ERROR": 1,
    }
    assert wrong["repairability_counts"] == {
        "ACADEMY_REPAIR_CANDIDATE_NO_TRAINING_AUTHORITY": 21,
        "MAX_TOKEN_SENSITIVITY_PLAN_ONLY": 51,
    }
    assert len(wrong_rows) == 72
    assert {row["repairability"] for row in wrong_rows} == {
        "ACADEMY_REPAIR_CANDIDATE_NO_TRAINING_AUTHORITY",
        "MAX_TOKEN_SENSITIVITY_PLAN_ONLY",
    }

    assert correct["status"] == "PASS"
    assert correct["correct_row_count"] == 28
    assert correct["rows_at_risk_from_common_surface_fixes"] == 28
    assert correct["damage_must_be_zero_for_future_promotion_style_claim"] is True
    assert correct["protection_law_counts"] == {"FORMAT_REPAIR_RISK_HIGH": 28}
    assert len(correct_rows) == 28
    assert {row["protection_law"] for row in correct_rows} == {"FORMAT_REPAIR_RISK_HIGH"}

    for receipt in [wrong, correct]:
        _assert_claim_boundary(receipt)


def test_gsm8k_sensitivity_and_repair_lanes_remain_plan_only() -> None:
    _run_builder()

    max_token = _json("reports/v17_7_4_gsm8k_max_token_sensitivity_offline_plan.json")
    verifier = _json("reports/v17_7_4_gsm8k_verifier_rescue_reassessment.json")
    academy = _json("reports/v17_7_4_gsm8k_academy_repairability_plan_no_training.json")
    epc = _json("reports/v17_7_4_epc_decision_after_gsm8k_capability_gap_autopsy.json")
    next_lane = _json("reports/v17_7_4_gsm8k_capability_gap_next_lane.json")

    assert max_token["status"] == "PLAN_ONLY_CANDIDATE_WEAK"
    assert max_token["future_microfurnace_allowed_by_this_lane"] is False
    assert max_token["truncation_proxy_rows"] == 67
    assert max_token["truncation_proxy_wrong_rate"] == 0.761194
    assert max_token["non_truncation_wrong_rate"] == 0.636364
    assert max_token["candidate_future_lane"] == "AUTHOR_KTV1774_GSM8K_MAXTOKEN_SENSITIVITY_DESIGN_V1"

    assert verifier["status"] == "PASS_OFFLINE_ONLY"
    assert verifier["runtime_verifier_rescue_authorized"] is False
    assert verifier["llm_verifier_rescue_allowed"] is False
    assert verifier["scratchpad_rescue_allowed"] is False
    assert verifier["nlp_word_problem_parser_allowed"] is False
    assert academy["status"] == "PLAN_ONLY_NO_TRAINING"
    assert academy["academy_run_authorized"] is False
    assert academy["training_authority"] is False

    assert epc["status"] == "PASS_DECIDED"
    assert epc["selected_next_lane"] == "AUTHOR_KTV1774_GSM8K_MAXTOKEN_SENSITIVITY_DESIGN_V1"
    assert epc["runtime_allowed_by_this_lane"] is False
    assert next_lane["status"] == "PASS_NO_RUNTIME_PACKET"
    assert next_lane["packet_path_if_any"] is None
    assert next_lane["runtime_authority"] is False

    for receipt in [max_token, verifier, academy, epc, next_lane]:
        _assert_claim_boundary(receipt)
