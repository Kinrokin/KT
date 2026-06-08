from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run_builder() -> None:
    subprocess.run(
        [sys.executable, "scripts/design_v17_7_4_gsm8k_maxtoken_sensitivity.py"],
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
    assert receipt["adapter_training_authorized"] is False
    assert receipt["router_training_authorized"] is False
    assert receipt["policy_optimization_authorized"] is False
    assert receipt["router_superiority_claim"] is False
    assert receipt["learned_router_superiority_claim"] is False
    assert receipt["g2_recovered_claim"] is False
    assert receipt["commercial_claim"] is False
    assert receipt["s_tier_claim"] is False
    assert receipt["seven_b_claim"] is False
    assert receipt["production_readiness_claim"] is False


def test_maxtoken_design_binds_capability_autopsy_and_blocks_packets() -> None:
    _run_builder()

    summary = _json("reports/v17_7_4_gsm8k_maxtoken_sensitivity_builder_summary.json")
    predecessor = _json("reports/v17_7_4_gsm8k_maxtoken_sensitivity_predecessor_binding.json")
    claim = _json("reports/v17_7_4_gsm8k_maxtoken_sensitivity_claim_boundary_receipt.json")

    assert summary["outcome"] == "KT_GSM8K_MAXTOKEN_SENSITIVITY_DESIGNED__NO_RUNTIME_PACKET_WARRANTED__CLAIM_CEILING_PRESERVED"
    assert summary["capability_gap_predecessor_status"] == "BOUND"
    assert summary["hypothesis_strength"] == "WEAK"
    assert summary["packet_path_if_any"] is None
    assert summary["packet_sha256_if_any"] is None
    assert summary["kaggle_dataset_name_if_any"] is None
    assert summary["one_cell_runbook_if_any"] is None
    assert summary["next_lawful_move"] == "AUTHOR_DETERMINISTIC_RESCUE_OFFLINE_REPLAY_V4"
    assert predecessor["status"] == "BOUND"
    assert predecessor["capability_gap_epc_selected_next_lane"] == "AUTHOR_KTV1774_GSM8K_MAXTOKEN_SENSITIVITY_DESIGN_V1"
    assert predecessor["official_score"] == "28/100"
    assert predecessor["prior_maxtoken_plan_status"] == "PLAN_ONLY_CANDIDATE_WEAK"
    assert claim["runtime_packet_generated"] is False
    assert claim["training_authority"] is False
    assert claim["prompt_change_allowed"] is False
    assert claim["adapter_change_allowed"] is False
    assert claim["model_change_allowed"] is False
    assert claim["scorer_change_allowed"] is False
    assert claim["parser_change_allowed"] is False

    for receipt in [summary, predecessor, claim]:
        _assert_claim_boundary(receipt)


def test_maxtoken_output_length_table_is_hash_only_and_deterministic() -> None:
    _run_builder()

    topology = _json("reports/v17_7_4_gsm8k_output_length_topology.json")
    rows = _jsonl("reports/v17_7_4_gsm8k_output_length_table.jsonl")
    trunc_rows = _jsonl("reports/v17_7_4_gsm8k_truncation_proxy_table.jsonl")

    assert topology["status"] == "PASS"
    assert topology["row_count"] == 100
    assert topology["max_new_tokens_config"] == 50
    assert topology["deterministic_proxies_only"] is True
    assert topology["raw_output_text_committed"] is False
    assert topology["suspected_truncation_proxy_rows"] == 67
    assert topology["non_truncation_proxy_rows"] == 33
    assert len(rows) == 100
    assert len(trunc_rows) == 67

    for row in rows:
        assert row["schema_id"] == "kt.v17_7_4.gsm8k_maxtoken_output_length_row.v1"
        assert row["dataset"] == "gsm8k"
        assert row["raw_output_text_committed"] is False
        assert "raw_output_text" not in row
        assert row["max_new_tokens_config"] == 50
        assert row["runtime_authority"] is False
        assert row["router_training_authorized"] is False
        assert row["adapter_training_authorized"] is False


def test_maxtoken_correlation_stays_weak_and_noncausal() -> None:
    _run_builder()

    correlation = _json("reports/v17_7_4_gsm8k_maxtoken_truncation_correlation.json")
    wrongness = _json("reports/v17_7_4_gsm8k_wrongness_vs_length.json")
    format_drift = _json("reports/v17_7_4_gsm8k_format_drift_vs_length.json")
    budget = _json("reports/v17_7_4_gsm8k_correctness_by_budget_bucket.json")

    assert correlation["status"] == "PASS"
    assert correlation["hypothesis_strength"] == "WEAK"
    assert correlation["causal_claim"] is False
    assert correlation["significance_claim"] is False
    assert correlation["statistics_mode"] == "COUNT_AND_RATE_ONLY"
    assert correlation["suspected_truncation_proxy_rows"] == 67
    assert correlation["suspected_truncation_proxy_wrong_rate"] == 0.761194
    assert correlation["non_truncation_proxy_rows"] == 33
    assert correlation["non_truncation_proxy_wrong_rate"] == 0.636364
    assert correlation["wrong_rate_delta"] == 0.12483
    assert wrongness["status"] == "PASS"
    assert format_drift["status"] == "PASS"
    assert budget["status"] == "PASS"
    assert budget["by_generation_budget_bucket"]["100_plus"]["row_count"] == 1

    for receipt in [correlation, wrongness, format_drift, budget]:
        _assert_claim_boundary(receipt)


def test_maxtoken_design_emits_only_design_and_epc_no_runtime() -> None:
    _run_builder()

    ladder = _json("reports/v17_7_4_gsm8k_maxtoken_sensitivity_ladder.json")
    memory = _json("reports/v17_7_4_gsm8k_maxtoken_memory_feasibility_plan.json")
    microfurnace = _json("reports/v17_7_4_gsm8k_maxtoken_microfurnace_design_only.json")
    epc_gate = _json("reports/v17_7_4_gsm8k_maxtoken_epc_runtime_gate.json")
    correct_rows = _json("reports/v17_7_4_gsm8k_maxtoken_correct_row_protection_plan.json")
    damage = _json("reports/v17_7_4_gsm8k_maxtoken_damage_gate.json")
    epc = _json("reports/v17_7_4_epc_decision_after_gsm8k_maxtoken_sensitivity_design.json")
    next_lane = _json("reports/v17_7_4_gsm8k_maxtoken_sensitivity_next_lane.json")

    assert ladder["status"] == "DESIGN_ONLY"
    assert ladder["baseline_max_new_tokens"] == 50
    assert [budget["max_new_tokens"] for budget in ladder["candidate_budgets"]] == [50, 82, 114, 178]
    assert ladder["prompt_adapter_model_tokenizer_scorer_parser_unchanged"] is True
    assert memory["status"] == "PASS_DESIGN_ONLY"
    assert memory["max_rows_for_pilot"] == 25
    assert memory["no_silent_smaller_model_or_base_only_fallback"] is True
    assert microfurnace["status"] == "DESIGN_ONLY_NOT_AUTHORIZED"
    assert microfurnace["runtime_authorized_by_this_lane"] is False
    assert epc_gate["status"] == "NO_RUNTIME_PACKET__MAXTOKEN_HYPOTHESIS_WEAK"
    assert epc_gate["runtime_allowed_by_this_lane"] is False
    assert epc_gate["packet_path_if_any"] is None
    assert correct_rows["official_correct_rows"] == 28
    assert correct_rows["damage_to_control_correct_must_equal_zero"] is True
    assert damage["damage_to_control_correct"] == 0
    assert damage["promotion_style_claim_allowed"] is False
    assert epc["selected_next_lane"] == "AUTHOR_DETERMINISTIC_RESCUE_OFFLINE_REPLAY_V4"
    assert epc["runtime_allowed_by_this_lane"] is False
    assert next_lane["status"] == "PASS_NO_RUNTIME_PACKET"
    assert next_lane["packet_path_if_any"] is None

    for receipt in [ladder, memory, microfurnace, epc_gate, correct_rows, damage, epc, next_lane]:
        _assert_claim_boundary(receipt)
