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
            [sys.executable, "scripts/build_v17_7_4_math_corpus_source_binding.py"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        _SUMMARY = json.loads(completed.stdout)
    return _SUMMARY


def test_builder_returns_source_bound_no_training_success() -> None:
    summary = ensure_built()

    assert summary["outcome"] == (
        "KT_MATH_CORPUS_SOURCE_BOUND__QUALITY_AUDIT_READY__"
        "TRAINING_AUTHORITY_STILL_FALSE__CLAIM_CEILING_PRESERVED"
    )
    assert summary["math_corpus_source_binding_status"] == (
        "BOUND_CURRENT_REPAIR_AND_EVAL_SOURCES__HISTORICAL_13_LOBE_PARTIAL"
    )
    assert summary["source_search_status"] == "PASS"
    assert summary["source_candidate_index_status"] == "PASS"
    assert summary["source_authority_map_status"] == "PASS"
    assert summary["schema_inference_status"] == "PASS"
    assert summary["leakage_precheck_status"] == "PASS_PRECHECK_ONLY"
    assert summary["train_eval_boundary_precheck_status"] == "PASS_PRECHECK_ONLY"
    assert summary["quality_audit_readiness_status"] == "READY_FOR_BOUND_CURRENT_SOURCES"
    assert summary["historical_training_corpus_recovery_status"] == "PARTIAL_BOUND"
    assert summary["historical_epoch_crucible_source_status"] == "PARTIAL_BOUND"
    assert summary["epc_next_lane_status"] == "PASS_NO_RUNTIME_PACKET"
    assert summary["next_lawful_move"] == "AUTHOR_MATH_CORPUS_QUALITY_AUDIT_V1"
    assert summary["blockers"] == []
    assert summary["claim_ceiling_status"] == "PRESERVED"

    assert summary["runtime_authority"] is False
    assert summary["training_authority"] is False
    assert summary["promotion_authority"] is False
    assert summary["adapter_mutation_authority"] is False
    assert summary["packet_path_if_any"] is None
    assert summary["packet_sha256_if_any"] is None
    assert summary["kaggle_dataset_name_if_any"] is None
    assert summary["one_cell_runbook_if_any"] is None


def test_candidate_index_binds_current_repair_and_eval_sources() -> None:
    ensure_built()
    index = read_json("reports/v17_7_4_math_corpus_source_candidate_index.json")
    rows = read_jsonl("reports/v17_7_4_math_corpus_source_candidate_table.jsonl")
    paths = {row["path"] for row in rows}

    assert index["status"] == "PASS"
    assert index["candidate_count"] == len(rows)
    assert index["candidate_count"] > 0
    assert index["role_counts"]["TRAINING_CORPUS"] >= 1
    assert index["role_counts"]["ROW_MANIFEST"] >= 1
    assert index["relevance_counts"]["GSM8K"] >= 1
    assert index["likely_train_or_eval_counts"]["TRAIN"] >= 1
    assert index["likely_train_or_eval_counts"]["EVAL"] >= 1

    assert "data/g31_math_repair_corpus.jsonl" in paths
    assert "packets/ktg3_run_v1/G3_MATH_REPAIR_CORPUS.jsonl" in paths
    assert "admission/v17_7_4_control_only_gsm8k_extension_row_manifest.json" in paths
    assert all(row["repo_tracked"] for row in rows)
    assert all(row["sha256"] for row in rows)


def test_authority_map_keeps_sources_audit_only_or_eval_only() -> None:
    ensure_built()
    authority_map = read_json("reports/v17_7_4_math_corpus_source_authority_map.json")
    use_counts = authority_map["use_authority_counts"]

    assert authority_map["status"] == "PASS"
    assert authority_map["source_count"] > 0
    assert use_counts.get("AUDIT_ONLY", 0) > 0
    assert use_counts.get("EVAL_ONLY", 0) > 0
    assert "TRAINING_CANDIDATE_FUTURE_AUTHORITY_REQUIRED" not in use_counts
    assert all(row["training_authority"] is False for row in authority_map["rows"])
    assert all(row["license_status"] in {"UNKNOWN_LICENSE", "INTERNAL_ONLY", "KNOWN_ALLOWED", "RESTRICTED"} for row in authority_map["rows"])


def test_schema_inference_and_leakage_prechecks_are_precheck_only() -> None:
    ensure_built()
    schema_inference = read_json("reports/v17_7_4_math_corpus_schema_inference.json")
    parse = read_json("reports/v17_7_4_math_corpus_parse_readiness.json")
    leakage = read_json("reports/v17_7_4_math_corpus_leakage_precheck.json")
    boundary = read_json("reports/v17_7_4_math_corpus_train_eval_boundary_precheck.json")
    expected_map = read_json("reports/v17_7_4_math_corpus_expected_answer_field_map.json")

    assert schema_inference["status"] == "PASS"
    assert schema_inference["parse_readiness_counts"]["PARSE_READY"] >= 1
    assert parse["status"] == "PASS"
    assert parse["audit_ready"] is True
    assert parse["parse_ready_count"] >= 1

    assert leakage["status"] == "PASS_PRECHECK_ONLY"
    assert leakage["expected_answer_candidate_count"] >= 1
    assert leakage["expected_answer_values_model_visible_allowed"] is False
    assert leakage["future_overlap_hash_check_required"] is True
    assert boundary["status"] == "PASS_PRECHECK_ONLY"
    assert boundary["eval_rows_must_not_be_future_training_targets"] is True
    assert boundary["normalized_text_hash_strategy_required"] is True
    assert expected_map["status"] == "PASS"
    assert expected_map["fields_detected"]


def test_historical_recovery_is_partial_not_training_authority() -> None:
    ensure_built()
    historical = read_json("reports/v17_7_4_historical_math_training_corpus_recovery_status.json")
    lobe = read_json("reports/v17_7_4_historical_13_lobe_training_source_status.json")
    epoch = read_json("reports/v17_7_4_historical_epoch_crucible_source_status.json")
    quality = read_json("reports/v17_7_4_math_corpus_quality_audit_readiness.json")

    assert historical["status"] == "PARTIAL_BOUND"
    assert historical["current_repair_corpora_bound"] is True
    assert historical["no_invention"] is True
    assert lobe["status"] == "REFERENCED_NOT_FULLY_BOUND"
    assert lobe["tranche_configs_bound"] is True
    assert lobe["row_level_source_bound"] is False
    assert epoch["status"] == "PARTIAL_BOUND"
    assert quality["status"] == "READY_FOR_BOUND_CURRENT_SOURCES"
    assert quality["historical_13_lobe_exact_source_bound"] is False
    assert quality["selected_next_lane"] == "AUTHOR_MATH_CORPUS_QUALITY_AUDIT_V1"
    assert quality["training_authority"] is False


def test_no_forbidden_artifacts_or_authority_are_generated() -> None:
    summary = ensure_built()
    generated_paths = [Path(path) for path in summary["files_changed"]]
    forbidden_prefixes = ("packets", "datasets", "runtime_inputs")

    assert all(path.parts[0] not in forbidden_prefixes for path in generated_paths)
    assert all(path.suffix != ".safetensors" for path in generated_paths)
    assert all("hf_upload" not in path.as_posix().lower() for path in generated_paths)
    assert summary["runtime_packet_generated"] is False
    assert summary["training_packet_generated"] is False
    assert summary["dataset_packet_generated"] is False
    assert summary["safetensors_generated"] is False
    assert summary["hf_upload_authorized"] is False
    assert summary["corpus_quality_claim"] is False
    assert summary["dataset_readiness_claim"] is False
    assert summary["training_readiness_claim"] is False
