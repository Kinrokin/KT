from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
_SUMMARY: dict | None = None


REQUIRED_REPORTS = [
    "reports/v17_7_4_reverse_heal_sanitization_truth_pin.json",
    "reports/v17_7_4_reverse_heal_sanitization_predecessor_binding.json",
    "reports/v17_7_4_reverse_heal_sanitization_claim_boundary_receipt.json",
    "reports/v17_7_4_reverse_heal_boundary_receipt.json",
    "reports/v17_7_4_lab_vs_canonical_authority_policy.json",
    "reports/v17_7_4_audit_recursion_risk_policy.json",
    "reports/v17_7_4_math_corpus_sanitization_yield_gate.json",
    "reports/v17_7_4_math_corpus_sanitization_yield_table.jsonl",
    "reports/v17_7_4_math_corpus_salvage_decision.json",
    "reports/v17_7_4_math_row_trust_tier_policy.json",
    "reports/v17_7_4_math_row_trust_tier_assignment_table.jsonl",
    "reports/v17_7_4_math_capability_density_requirements.json",
    "reports/v17_7_4_math_capability_density_table.jsonl",
    "reports/v17_7_4_math_signal_density_targets.json",
    "reports/v17_7_4_math_doctrine_contamination_scan.json",
    "reports/v17_7_4_math_doctrine_contamination_table.jsonl",
    "reports/v17_7_4_math_doctrine_contamination_blocklist.json",
    "reports/v17_7_4_math_code_verified_crucible_requirement.json",
    "reports/v17_7_4_math_verification_class_map.json",
    "reports/v17_7_4_math_row_verifiable_invariant_policy.json",
    "reports/v17_7_4_formal_math_compression_suspension_receipt.json",
    "reports/v17_7_4_math_capability_first_mode.json",
    "reports/v17_7_4_math_compression_reopen_gate.json",
    "reports/v17_7_4_formal_math_niche_boundary_reaffirmation.json",
    "reports/v17_7_4_math_no_regression_replay_contract.json",
    "reports/v17_7_4_math_router_nonpromotion_receipt.json",
    "reports/v17_7_4_math_repair_curriculum_ladder.json",
    "reports/v17_7_4_math_curriculum_stage_requirements.json",
    "reports/v17_7_4_math_olympiad_future_only_receipt.json",
    "reports/v17_7_4_math_corpus_source_disposition_matrix.json",
    "reports/v17_7_4_math_corpus_source_whitelist_blacklist.json",
    "reports/v17_7_4_math_corpus_source_action_table.jsonl",
    "reports/v17_7_4_math_corpus_row_sanitization_requirements.json",
    "reports/v17_7_4_math_corpus_row_action_table.jsonl",
    "reports/v17_7_4_math_corpus_expected_answer_sanitization_plan.json",
    "reports/v17_7_4_math_corpus_answer_field_segregation_spec.json",
    "reports/v17_7_4_math_corpus_oracle_label_laundering_block.json",
    "reports/v17_7_4_math_corpus_dedup_sanitization_plan.json",
    "reports/v17_7_4_math_corpus_train_eval_firewall_plan.json",
    "reports/v17_7_4_math_corpus_overlap_blocklist.json",
    "reports/v17_7_4_math_corpus_format_normalization_plan.json",
    "reports/v17_7_4_math_corpus_answer_contract_target_spec.json",
    "reports/v17_7_4_math_corpus_reasoning_step_requirement_spec.json",
    "reports/v17_7_4_math_corpus_license_remediation_plan.json",
    "reports/v17_7_4_math_corpus_use_authority_remediation_table.jsonl",
    "reports/v17_7_4_historical_corpus_gap_remediation_plan.json",
    "reports/v17_7_4_historical_epoch_crucible_recovery_plan.json",
    "reports/v17_7_4_historical_training_prompt_template_recovery_plan.json",
    "reports/v17_7_4_math_dataset_blueprint_go_no_go_decision.json",
    "reports/v17_7_4_math_dataset_blueprint_handoff_requirements.json",
    "reports/v17_7_4_math_dataset_builder_forbidden_actions.json",
    "reports/v17_7_4_epc_decision_after_reverse_heal_sanitization_v2.json",
    "reports/v17_7_4_reverse_heal_sanitization_next_lane.json",
    "reports/v17_7_4_reverse_heal_intervention_queue.json",
    "KT_PROD_CLEANROOM/reports/v17_7_4_reverse_heal_math_sanitization_v2_ci_trigger_receipt.json",
]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def read_jsonl(path: str) -> list[dict]:
    return [
        json.loads(line)
        for line in (ROOT / path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def ensure_built() -> dict:
    global _SUMMARY
    if _SUMMARY is None:
        completed = subprocess.run(
            [sys.executable, "scripts/build_v17_7_4_reverse_heal_math_sanitization_v2.py"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        _SUMMARY = json.loads(completed.stdout)
    return _SUMMARY


def test_reverse_heal_builder_returns_single_bounded_decision() -> None:
    summary = ensure_built()

    assert summary["outcome"] == (
        "KT_REVERSE_HEAL_MATH_SANITIZATION_DECISION_BOUND__DATASET_BLUEPRINT_OR_BLOCKER_SELECTED__"
        "TRAINING_AUTHORITY_STILL_FALSE__CLAIM_CEILING_PRESERVED"
    )
    assert summary["reverse_heal_sanitization_binding_status"] == "BOUND_TO_MATH_CORPUS_QUALITY_AUDIT"
    assert summary["lab_vs_canonical_authority_status"] == "PASS"
    assert summary["audit_recursion_policy_status"] == "PASS"
    assert summary["sanitization_yield_gate_status"] == "FAIL_ABANDON_HISTORICAL_CORPUS_FOR_CLEAN_BLUEPRINT"
    assert summary["dataset_blueprint_go_no_go_status"] == "ABANDON_HISTORICAL_CORPUS_FOR_CLEAN_BLUEPRINT"
    assert summary["epc_next_lane_status"] == "PASS_DECIDED_NO_RUNTIME_PACKET"
    assert summary["next_lawful_move"] == "ABANDON_HISTORICAL_CORPUS_FOR_CLEAN_BLUEPRINT"
    assert summary["claim_ceiling_status"] == "PRESERVED"
    assert summary["blockers"] == []

    assert summary["runtime_authority"] is False
    assert summary["dataset_generation_authority"] is False
    assert summary["training_authority"] is False
    assert summary["promotion_authority"] is False
    assert summary["adapter_mutation_authority"] is False
    assert summary["packet_path_if_any"] is None
    assert summary["packet_sha256_if_any"] is None
    assert summary["kaggle_dataset_name_if_any"] is None
    assert summary["one_cell_runbook_if_any"] is None


def test_required_reverse_heal_reports_and_schemas_exist() -> None:
    ensure_built()
    for path in REQUIRED_REPORTS:
        assert (ROOT / path).exists(), path
    assert (ROOT / "schemas/kt.v17_7_4.math_row_trust_tier.schema.json").exists()
    assert (ROOT / "schemas/kt.v17_7_4.math_corpus_row_sanitization_action.schema.json").exists()


def test_yield_gate_abandons_historical_corpus_without_runtime_or_dataset() -> None:
    summary = ensure_built()
    gate = read_json("reports/v17_7_4_math_corpus_sanitization_yield_gate.json")
    decision = read_json("reports/v17_7_4_math_dataset_blueprint_go_no_go_decision.json")
    next_lane = read_json("reports/v17_7_4_reverse_heal_sanitization_next_lane.json")

    assert gate["status"] == "FAIL_ABANDON_HISTORICAL_CORPUS_FOR_CLEAN_BLUEPRINT"
    assert gate["selected_decision"] == "ABANDON_HISTORICAL_CORPUS_FOR_CLEAN_BLUEPRINT"
    assert gate["exact_one_next_decision"] is True
    assert gate["no_plan_more"] is True
    assert gate["doctrine_contamination_row_count"] > gate["quality_candidate_count"]
    assert gate["unknown_license_source_count"] > 0

    assert decision["decision"] == gate["selected_decision"]
    assert decision["dataset_blueprint_from_historical_corpus_go"] is False
    assert decision["clean_blueprint_go"] is True
    assert next_lane["selected_next_lane"] == gate["selected_decision"]

    generated_paths = [Path(path) for path in summary["files_changed"]]
    forbidden_prefixes = {"packets", "datasets", "runtime_inputs"}
    assert all(path.parts[0] not in forbidden_prefixes for path in generated_paths)
    assert all(path.suffix != ".safetensors" for path in generated_paths)
    assert summary["runtime_packet_generated"] is False
    assert summary["training_packet_generated"] is False
    assert summary["dataset_packet_generated"] is False
    assert summary["prompt_mutation_packet_generated"] is False
    assert summary["safetensors_generated"] is False


def test_row_trust_tiers_and_sanitization_actions_are_row_level_and_safe() -> None:
    ensure_built()
    quality_rows = read_jsonl("reports/v17_7_4_math_corpus_record_table.jsonl")
    tiers = read_jsonl("reports/v17_7_4_math_row_trust_tier_assignment_table.jsonl")
    actions = read_jsonl("reports/v17_7_4_math_corpus_row_action_table.jsonl")

    assert len(tiers) == len(quality_rows) == 8721
    assert len(actions) == len(quality_rows)
    allowed_tiers = {
        "T0_REJECT",
        "T1_FORMAT_ONLY",
        "T2_VERIFIED_NUMERIC",
        "T3_STEP_VERIFIED",
        "T4_HUMAN_VERIFIED_TRANSFER_READY",
    }
    assert {row["trust_tier"] for row in tiers}.issubset(allowed_tiers)
    assert any(row["trust_tier"] == "T0_REJECT" for row in tiers)
    assert all(row["training_authority"] is False for row in tiers[:500])
    assert all(row["expected_answer_model_visible"] is False for row in tiers[:500])
    assert all(row["dataset_generation_authority"] is False for row in actions[:500])


def test_contamination_density_source_and_license_surfaces_are_measured() -> None:
    ensure_built()
    contamination = read_json("reports/v17_7_4_math_doctrine_contamination_scan.json")
    contamination_rows = read_jsonl("reports/v17_7_4_math_doctrine_contamination_table.jsonl")
    density_rows = read_jsonl("reports/v17_7_4_math_capability_density_table.jsonl")
    source_matrix = read_json("reports/v17_7_4_math_corpus_source_disposition_matrix.json")
    source_actions = read_jsonl("reports/v17_7_4_math_corpus_source_action_table.jsonl")
    license_plan = read_json("reports/v17_7_4_math_corpus_license_remediation_plan.json")

    assert contamination["status"] == "PASS_SCAN_COMPLETE__CONTAMINATION_HIGH"
    assert contamination["contaminated_row_count"] == len(contamination_rows)
    assert contamination["contaminated_row_count"] > 0
    assert density_rows
    assert all("capability_density_score" in row for row in density_rows[:100])
    assert source_matrix["source_count"] == len(source_actions)
    assert source_matrix["zero_row_source_count"] > 0
    assert any(row["action"] == "EXCLUDE_NO_BOUND_ROWS" for row in source_actions)
    assert source_matrix["blacklist_count"] > 0
    assert license_plan["unknown_license_source_count"] > 0
    assert license_plan["historical_corpus_not_used_until_license_resolved"] is True


def test_math_repair_boundary_suspends_compression_and_blocks_promotion() -> None:
    ensure_built()
    suspension = read_json("reports/v17_7_4_formal_math_compression_suspension_receipt.json")
    capability_first = read_json("reports/v17_7_4_math_capability_first_mode.json")
    reopen = read_json("reports/v17_7_4_math_compression_reopen_gate.json")
    niche = read_json("reports/v17_7_4_formal_math_niche_boundary_reaffirmation.json")
    router = read_json("reports/v17_7_4_math_router_nonpromotion_receipt.json")
    olympiad = read_json("reports/v17_7_4_math_olympiad_future_only_receipt.json")

    assert suspension["formal_math_compression_suspended"] is True
    assert capability_first["capability_first_mode"] is True
    assert capability_first["compression_optimization_allowed_now"] is False
    assert reopen["compression_reopen_authority_now"] is False
    assert niche["formal_math_is_niche_bound"] is True
    assert niche["no_global_promotion"] is True
    assert router["route_promotion_authority"] is False
    assert router["learned_router_superiority_claim"] is False
    assert olympiad["olympiad_training_authority"] is False
