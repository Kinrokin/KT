from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
_SUMMARY: dict | None = None


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
            [sys.executable, "scripts/build_v17_7_4_math_corpus_quality_audit.py"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        _SUMMARY = json.loads(completed.stdout)
    return _SUMMARY


def test_builder_returns_quality_audit_success_without_authority_drift() -> None:
    summary = ensure_built()

    assert summary["outcome"] == (
        "KT_MATH_CORPUS_QUALITY_AUDITED__NEXT_DATA_OR_TRAINING_AUTHORITY_LANE_DECIDED__"
        "TRAINING_AUTHORITY_STILL_FALSE__CLAIM_CEILING_PRESERVED"
    )
    assert summary["math_corpus_quality_binding_status"] == "BOUND_TO_SOURCE_BINDING_RESULT"
    assert summary["parse_execution_status"] == "PASS"
    assert summary["corpus_inventory_status"] == "PASS"
    assert summary["lane_distribution_status"] == "PASS"
    assert summary["dedup_audit_status"] == "PASS"
    assert summary["leakage_audit_status"] == "PASS_AUDIT_ONLY"
    assert summary["format_alignment_status"] == "PASS_AUDIT_ONLY"
    assert summary["difficulty_distribution_status"] == "PASS_AUDIT_ONLY"
    assert summary["solution_quality_status"] == "PASS_AUDIT_ONLY"
    assert summary["verifier_compatibility_status"] == "PASS_AUDIT_ONLY"
    assert summary["license_use_authority_status"] == "PASS_AUDIT_ONLY"
    assert summary["quality_scorecard_status"] == "PASS"
    assert summary["historical_gap_report_status"] == "PARTIAL_BOUND_GAPS_REPORTED"
    assert summary["future_blueprint_requirements_status"] == "PASS_REQUIREMENTS_ONLY"
    assert summary["epc_next_lane_status"] == "PASS_NO_RUNTIME_PACKET"
    assert summary["next_lawful_move"] == "AUTHOR_MATH_CORPUS_SANITIZATION_PLAN_NO_DATASET_V1"
    assert summary["claim_ceiling_status"] == "PRESERVED"
    assert summary["blockers"] == []

    assert summary["runtime_authority"] is False
    assert summary["training_authority"] is False
    assert summary["promotion_authority"] is False
    assert summary["adapter_mutation_authority"] is False
    assert summary["packet_path_if_any"] is None
    assert summary["packet_sha256_if_any"] is None
    assert summary["kaggle_dataset_name_if_any"] is None
    assert summary["one_cell_runbook_if_any"] is None


def test_parse_execution_hashes_records_without_model_visible_answers() -> None:
    ensure_built()
    receipt = read_json("reports/v17_7_4_math_corpus_parse_execution_receipt.json")
    inventory = read_json("reports/v17_7_4_math_corpus_inventory.json")
    records = read_jsonl("reports/v17_7_4_math_corpus_record_table.jsonl")

    assert receipt["status"] == "PASS"
    assert receipt["expected_answer_values_written_to_logs"] is False
    assert inventory["record_count"] == len(records)
    assert inventory["record_count"] > 0
    assert inventory["parsed_source_count"] > 0
    assert inventory["current_bound_sources_separated"] is True
    assert inventory["historical_partial_sources_separated"] is True
    assert inventory["missing_unrecovered_sources_not_invented"] is True

    sample = records[:100]
    assert all(row["schema_id"] == "kt.v17_7_4.math_corpus_quality_record.v1" for row in sample)
    assert all(row["record_id_hash"] for row in sample)
    assert all(row["expected_answer_model_visible"] is False for row in sample)
    assert all(row["training_authority"] is False for row in sample)


def test_inventory_lane_distribution_and_quality_scorecard_are_measured() -> None:
    ensure_built()
    lane = read_json("reports/v17_7_4_math_corpus_lane_distribution.json")
    role = read_json("reports/v17_7_4_math_corpus_source_role_distribution.json")
    scorecard = read_json("reports/v17_7_4_math_corpus_quality_scorecard.json")
    grade = read_json("reports/v17_7_4_math_corpus_quality_grade.json")
    decision = read_json("reports/v17_7_4_math_corpus_training_readiness_decision.json")

    assert lane["status"] == "PASS"
    assert sum(lane["lane_counts"].values()) > 0
    assert lane["lane_counts"].get("ARITHMETIC_GSM8K", 0) > 0
    assert role["status"] == "PASS"
    assert role["record_role_counts"].get("TRAIN_CANDIDATE", 0) > 0
    assert role["record_role_counts"].get("EVAL_CANDIDATE", 0) > 0

    assert scorecard["status"] == "PASS"
    assert scorecard["overall_grade"] in {
        "A_READY_FOR_DATASET_BLUEPRINT",
        "B_READY_WITH_SANITIZATION",
        "C_AUDIT_ONLY_NEEDS_SOURCE_REPAIR",
        "D_NOT_TRAINING_READY",
        "F_UNUSABLE_FOR_TRAINING",
    }
    assert scorecard["training_readiness_decision"] == "TRAINING_AUTHORITY_FALSE__SANITIZATION_REQUIRED"
    assert scorecard["selected_next_lane"] == "AUTHOR_MATH_CORPUS_SANITIZATION_PLAN_NO_DATASET_V1"
    assert grade["selected_next_lane"] == scorecard["selected_next_lane"]
    assert decision["training_authority"] is False
    assert decision["training_readiness_claim"] is False


def test_dedup_overlap_leakage_and_license_remain_audit_only() -> None:
    ensure_built()
    dedup = read_json("reports/v17_7_4_math_corpus_dedup_audit.json")
    overlap = read_json("reports/v17_7_4_math_corpus_eval_overlap_audit.json")
    boundary = read_json("reports/v17_7_4_math_corpus_train_eval_boundary_audit.json")
    leakage = read_json("reports/v17_7_4_math_corpus_leakage_audit.json")
    visibility = read_jsonl("reports/v17_7_4_math_corpus_expected_answer_visibility_matrix.jsonl")
    license_audit = read_json("reports/v17_7_4_math_corpus_license_use_authority_audit.json")
    license_rows = read_jsonl("reports/v17_7_4_math_corpus_training_use_authority_matrix.jsonl")

    assert dedup["status"] == "PASS"
    assert dedup["record_count"] > 0
    assert overlap["status"] in {"NO_OVERLAP_DETECTED", "OVERLAP_DETECTED_AUDIT_ONLY"}
    assert overlap["future_training_use_requires_overlap_removal"] in {True, False}
    assert boundary["training_authority"] is False
    assert boundary["eval_rows_must_not_be_training_targets"] is True

    assert leakage["status"] == "PASS_AUDIT_ONLY"
    assert leakage["hard_blocker_triggered"] is False
    assert "NONE_DETECTED" in leakage["leakage_risk_counts"]
    assert all(row["expected_answer_model_visible"] is False for row in visibility[:100])

    assert license_audit["status"] == "PASS_AUDIT_ONLY"
    assert license_audit["no_unknown_license_source_training_ready"] is True
    assert license_rows
    assert all(row["future_training_allowed_now"] is False for row in license_rows[:100])


def test_format_difficulty_solution_verifier_and_future_requirements_exist() -> None:
    ensure_built()
    format_audit = read_json("reports/v17_7_4_math_corpus_format_alignment_audit.json")
    answer_contract = read_json("reports/v17_7_4_math_corpus_answer_contract_alignment.json")
    reasoning = read_json("reports/v17_7_4_math_corpus_reasoning_step_presence.json")
    difficulty = read_json("reports/v17_7_4_math_corpus_difficulty_distribution.json")
    gsm8k = read_json("reports/v17_7_4_math_corpus_gsm8k_feature_distribution.json")
    competition = read_json("reports/v17_7_4_math_corpus_competition_feature_distribution.json")
    solution = read_json("reports/v17_7_4_math_corpus_solution_quality_audit.json")
    verifier = read_json("reports/v17_7_4_math_corpus_verifier_compatibility.json")
    teacher = read_json("reports/v17_7_4_math_corpus_verifier_as_teacher_readiness.json")
    blueprint = read_json("reports/v17_7_4_math_future_dataset_blueprint_requirements.json")
    sanitization = read_json("reports/v17_7_4_math_future_sanitization_requirements.json")
    prereq = read_json("reports/v17_7_4_math_future_training_authority_prerequisites_update.json")

    assert format_audit["status"] == "PASS_AUDIT_ONLY"
    assert answer_contract["answer_contract_ready"] is False
    assert reasoning["status"] == "PASS_AUDIT_ONLY"
    assert difficulty["olympiad_sources_not_gsm8k_readiness"] is True
    assert gsm8k["gsm8k_foundation_requires_separate_balancing"] is True
    assert competition["competition_not_substitute_for_gsm8k_foundation"] is True
    assert solution["status"] == "PASS_AUDIT_ONLY"
    assert verifier["status"] == "PASS_AUDIT_ONLY"
    assert teacher["status"] == "NOT_READY_REQUIRES_SANITIZATION"
    assert blueprint["no_training_authority_now"] is True
    assert sanitization["status"] == "REQUIRED"
    assert prereq["status"] == "TRAINING_AUTHORITY_STILL_FALSE"


def test_historical_gaps_and_epc_next_lane_are_bound_without_runtime_packet() -> None:
    summary = ensure_built()
    h13 = read_json("reports/v17_7_4_historical_13_lobe_corpus_gap_report.json")
    epoch = read_json("reports/v17_7_4_historical_epoch_crucible_gap_report.json")
    delta = read_json("reports/v17_7_4_recursive_delta_source_gap_report.json")
    epc = read_json("reports/v17_7_4_epc_decision_after_math_corpus_quality_audit.json")
    next_lane = read_json("reports/v17_7_4_math_corpus_quality_audit_next_lane.json")
    queue = read_json("reports/v17_7_4_math_corpus_quality_intervention_queue.json")

    assert h13["status"] == "PARTIAL_BOUND"
    assert h13["no_invention"] is True
    assert epoch["status"] == "PARTIAL_BOUND"
    assert epoch["no_invention"] is True
    assert delta["status"] == "PARTIAL_BOUND"
    assert delta["no_invention"] is True

    assert epc["status"] == "PASS_DECIDED"
    assert epc["selected_next_lane"] == "AUTHOR_MATH_CORPUS_SANITIZATION_PLAN_NO_DATASET_V1"
    assert epc["runtime_allowed_by_this_lane"] is False
    assert epc["training_allowed_by_this_lane"] is False
    assert next_lane["status"] == "PASS_NO_RUNTIME_PACKET"
    assert next_lane["packet_path_if_any"] is None
    assert queue["queue"][0]["lane"] == epc["selected_next_lane"]

    generated_paths = [Path(path) for path in summary["files_changed"]]
    forbidden_prefixes = {"packets", "datasets", "runtime_inputs"}
    assert all(path.parts[0] not in forbidden_prefixes for path in generated_paths)
    assert all(path.suffix != ".safetensors" for path in generated_paths)
    assert summary["runtime_packet_generated"] is False
    assert summary["training_packet_generated"] is False
    assert summary["dataset_packet_generated"] is False
    assert summary["prompt_mutation_packet_generated"] is False
    assert summary["safetensors_generated"] is False
    assert summary["hf_upload_authorized"] is False
