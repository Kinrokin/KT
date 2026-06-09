from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
_SUMMARY: dict | None = None


REQUIRED_REPORTS = [
    "reports/v17_7_4_e2e_clean_slate_truth_pin.json",
    "reports/v17_7_4_e2e_anti_drift_ledger.json",
    "reports/v17_7_4_e2e_lab_vs_canonical_operating_law.json",
    "reports/v17_7_4_e2e_audit_recursion_breaker.json",
    "reports/v17_7_4_clean_slate_math_dataset_objective.json",
    "reports/v17_7_4_clean_slate_math_dataset_contract.json",
    "reports/v17_7_4_clean_slate_trust_tier_contract.json",
    "reports/v17_7_4_clean_slate_verification_class_contract.json",
    "reports/v17_7_4_clean_slate_curriculum_ladder.json",
    "reports/v17_7_4_clean_slate_capability_density_spec.json",
    "reports/v17_7_4_clean_slate_doctrine_contamination_policy.json",
    "reports/v17_7_4_clean_slate_source_license_requirements.json",
    "reports/v17_7_4_clean_slate_train_eval_firewall_contract.json",
    "reports/v17_7_4_clean_slate_answer_contract.json",
    "reports/v17_7_4_clean_slate_formal_math_compression_suspension_receipt.json",
    "reports/v17_7_4_clean_slate_niche_boundary_contract.json",
    "reports/v17_7_4_clean_slate_no_regression_control_set.json",
    "reports/v17_7_4_clean_slate_prompt_format_probe_dependency.json",
    "reports/v17_7_4_clean_slate_dataset_dry_run_validation_requirements.json",
    "reports/v17_7_4_clean_slate_dataset_blueprint_go_no_go_decision.json",
    "reports/v17_7_4_epc_decision_after_clean_slate_math_dataset_blueprint_v2.json",
    "KT_PROD_CLEANROOM/reports/v17_7_4_e2e_clean_slate_math_blueprint_v2_ci_trigger_receipt.json",
]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def ensure_built() -> dict:
    global _SUMMARY
    if _SUMMARY is None:
        completed = subprocess.run(
            [sys.executable, "scripts/build_v17_7_4_e2e_clean_slate_math_blueprint_v2.py"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        _SUMMARY = json.loads(completed.stdout)
    return _SUMMARY


def test_builder_binds_reverse_heal_decision_without_new_authority() -> None:
    summary = ensure_built()

    assert summary["outcome"] == (
        "KT_E2E_CLEAN_SLATE_MATH_BLUEPRINT_V2_BOUND__DRY_RUN_VALIDATION_READY__"
        "TRAINING_AUTHORITY_STILL_FALSE__CLAIM_CEILING_PRESERVED"
    )
    assert summary["e2e_clean_slate_binding_status"] == "BOUND_TO_REVERSE_HEAL_DECISION"
    assert summary["abandon_historical_corpus_receipt_status"] == "PASS_ABANDONED_FOR_TRAINING_USE"
    assert summary["dataset_blueprint_go_no_go_status"] == "GO_DRY_RUN_VALIDATION_ONLY"
    assert summary["epc_next_lane_status"] == "PASS_DECIDED_NO_RUNTIME_PACKET"
    assert summary["next_lawful_move"] == "AUTHOR_MATH_DATASET_DRY_RUN_VALIDATION_NO_TRAINING_V1"
    assert summary["claim_ceiling_status"] == "PRESERVED"
    assert summary["blockers"] == []

    for key in ("runtime_authority", "dataset_generation_authority", "training_authority", "promotion_authority", "adapter_mutation_authority"):
        assert summary[key] is False
    for key in ("packet_path_if_any", "packet_sha256_if_any", "kaggle_dataset_name_if_any", "one_cell_runbook_if_any"):
        assert summary[key] is None


def test_required_reports_schemas_and_scripts_exist() -> None:
    ensure_built()
    for path in REQUIRED_REPORTS:
        assert (ROOT / path).exists(), path
    for path in (
        "schemas/kt.v17_7_4.clean_slate_math_dataset_row.schema.json",
        "schemas/kt.v17_7_4.clean_slate_math_dataset_contract.schema.json",
        "schemas/kt.v17_7_4.clean_slate_dry_run_manifest.schema.json",
        "scripts/validate_clean_slate_blueprint_contract.py",
        "scripts/generate_clean_slate_dry_run_rows.py",
    ):
        assert (ROOT / path).exists(), path


def test_truth_pin_preserves_predecessor_metrics_and_abandons_historical_corpus() -> None:
    ensure_built()
    truth = read_json("reports/v17_7_4_e2e_clean_slate_truth_pin.json")
    contract = read_json("reports/v17_7_4_clean_slate_math_dataset_contract.json")
    decision = read_json("reports/v17_7_4_clean_slate_dataset_blueprint_go_no_go_decision.json")

    assert truth["binding_status"] == "BOUND_TO_REVERSE_HEAL_DECISION"
    assert truth["required_predecessor_metrics"]["input_row_count"] == 8721
    assert truth["required_predecessor_metrics"]["doctrine_contamination_row_count"] == 6540
    assert truth["required_predecessor_metrics"]["unknown_license_source_count"] == 5466
    assert truth["required_predecessor_metrics"]["quality_candidate_count"] == 0
    assert truth["historical_corpus_training_use"] == "ABANDONED"

    assert contract["historical_corpus_training_use"] == "ABANDONED"
    assert contract["dataset_generation_authority"] is False
    assert contract["training_authority"] is False
    assert decision["status"] == "GO_DRY_RUN_VALIDATION_ONLY"
    assert decision["real_dataset_generation_go"] is False
    assert decision["dry_run_validation_go"] is True


def test_dry_run_generator_and_validator_enforce_negative_controls(tmp_path: Path) -> None:
    ensure_built()
    rows_path = tmp_path / "dry_run_rows.jsonl"
    report_path = tmp_path / "dry_run_report.json"
    subprocess.run(
        [sys.executable, "scripts/generate_clean_slate_dry_run_rows.py", "--output", str(rows_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/validate_clean_slate_blueprint_contract.py",
            "--rows",
            str(rows_path),
            "--report",
            str(report_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    report = json.loads(completed.stdout)

    assert report["pass"] is True
    assert report["row_count"] == 101
    assert report["valid_candidate_count"] == 95
    assert report["invalid_row_count"] == 6
    assert report["t0_escape_count"] == 0
    assert report["false_positive_rate"] == 0
    assert report["false_negative_rate"] == 0
    assert report["split_hash_collision_count"] >= 1
    assert report["capability_density"] >= 0.30
    assert report["dataset_generation_authority"] is False
    assert report["training_authority"] is False


def test_policy_surfaces_block_doctrine_license_answer_and_split_laundering() -> None:
    ensure_built()
    doctrine = read_json("reports/v17_7_4_clean_slate_doctrine_contamination_policy.json")
    license_req = read_json("reports/v17_7_4_clean_slate_source_license_requirements.json")
    firewall = read_json("reports/v17_7_4_clean_slate_train_eval_firewall_contract.json")
    answer = read_json("reports/v17_7_4_clean_slate_answer_contract.json")

    assert doctrine["doctrine_terms_allowed_in_training_rows"] is False
    assert "router" in doctrine["banned_terms"]
    assert license_req["unknown_license_allowed"] is False
    assert license_req["source_url_or_origin_required"] is True
    assert firewall["problem_hash_split_collision_allowed"] is False
    assert firewall["hidden_labels_required"] is True
    assert answer["expected_answer_model_visible"] is False
    assert answer["model_prompt_may_include_answer"] is False


def test_no_runtime_dataset_packet_or_safetensor_artifacts_are_emitted() -> None:
    summary = ensure_built()
    forbidden_prefixes = {"packets", "datasets", "runtime_inputs"}
    for raw in summary["files_changed"]:
        path = Path(raw)
        assert path.parts[0] not in forbidden_prefixes
        assert path.suffix != ".safetensors"

    assert summary["kaggle_packet_generated"] is False
    assert summary["runtime_packet_generated"] is False
    assert summary["training_packet_generated"] is False
    assert summary["dataset_packet_generated"] is False
    assert summary["prompt_mutation_packet_generated"] is False
    assert summary["safetensors_generated"] is False


def test_math_boundaries_suspend_compression_and_keep_formal_math_niche_bound() -> None:
    ensure_built()
    suspension = read_json("reports/v17_7_4_clean_slate_formal_math_compression_suspension_receipt.json")
    niche = read_json("reports/v17_7_4_clean_slate_niche_boundary_contract.json")
    no_regression = read_json("reports/v17_7_4_clean_slate_no_regression_control_set.json")
    prompt_probe = read_json("reports/v17_7_4_clean_slate_prompt_format_probe_dependency.json")

    assert suspension["formal_math_compression_suspended"] is True
    assert suspension["compression_reopen_authority"] is False
    assert niche["formal_math_niche_bound"] is True
    assert niche["no_global_adapter_promotion"] is True
    assert niche["no_route_promotion"] is True
    assert no_regression["no_regression_required_before_training"] is True
    assert prompt_probe["prompt_format_probe_is_dependency"] is True
    assert prompt_probe["probe_authority_now"] is False
