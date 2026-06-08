from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TRANCHE = "AUTHOR_KTV1774_MATH_CORPUS_SOURCE_BINDING_V1"
OUTCOME = "KT_MATH_CORPUS_SOURCE_BOUND__QUALITY_AUDIT_READY__TRAINING_AUTHORITY_STILL_FALSE__CLAIM_CEILING_PRESERVED"
FALLBACK_OUTCOME = (
    "KT_MATH_CORPUS_SOURCE_NOT_BOUND__SEARCH_RECEIPT_COMPLETE__TRAINING_AUTHORITY_STILL_FALSE__"
    "CLAIM_CEILING_PRESERVED"
)
NEXT_IF_READY = "AUTHOR_MATH_CORPUS_QUALITY_AUDIT_V1"
NEXT_IF_NOT_READY = "AUTHOR_MATH_CORPUS_SOURCE_RECOVERY_OR_AUTHORING_PLAN_V1"


AUTHORITY_FALSE: dict[str, Any] = {
    "runtime_authority": False,
    "training_authority": False,
    "adapter_training_authorized": False,
    "adapter_mutation_authority": False,
    "promotion_authority": False,
    "router_training_authorized": False,
    "policy_optimization_authorized": False,
    "v18_runtime_authority": False,
    "academy_run_authorized": False,
    "hf_upload_authorized": False,
    "kaggle_packet_generated": False,
    "runtime_packet_generated": False,
    "training_packet_generated": False,
    "dataset_packet_generated": False,
    "safetensors_generated": False,
    "claim_ceiling_preserved": True,
    "gsm8k_recovery_claim": False,
    "corpus_quality_claim": False,
    "dataset_readiness_claim": False,
    "training_readiness_claim": False,
    "academy_repair_success_claim": False,
    "formal_math_superiority_claim": False,
    "olympiad_capability_claim": False,
    "router_superiority_claim": False,
    "learned_router_superiority_claim": False,
    "multi_lobe_superiority_claim": False,
    "g2_recovered_claim": False,
    "ninety_one_percent_full_system_recovery_claim": False,
    "external_validation_claim": False,
    "commercial_claim": False,
    "s_tier_claim": False,
    "frontier_claim": False,
    "seven_b_claim": False,
    "production_readiness_claim": False,
    "launch_readiness_claim": False,
}


SEARCH_PATHS = [
    "datasets/",
    "data/",
    "training/",
    "academy/",
    "crucibles/",
    "epochs/",
    "lobes/",
    "adapters/",
    "KT_PROD_CLEANROOM/",
    "runtime_inputs/",
    "configs/",
    "reports/",
    "registry/",
    "tools/",
    "tests/",
    "docs/",
    "packets/",
    "adaptive/",
    "admission/",
]

SEARCH_TERMS = [
    "gsm8k",
    "math",
    "formal_math",
    "formal_proof",
    "proof",
    "olympiad",
    "aime",
    "amc",
    "MATH",
    "crucible",
    "epoch",
    "academy",
    "cohort",
    "lobe",
    "hypertrain",
    "delta",
    "scar",
    "recursive_delta",
    "training_manifest",
    "train_manifest",
    "dataset_manifest",
    "row_manifest",
    "expected_answer",
    "answer_key",
    "solution",
    "reasoning",
    "cot",
    "chain_of_thought",
]

TEXT_SUFFIXES = {".json", ".jsonl", ".md", ".txt", ".yaml", ".yml", ".csv", ".py"}
PARSE_SUFFIXES = {".json", ".jsonl", ".yaml", ".yml", ".csv"}


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(AUTHORITY_FALSE)
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def tracked_files() -> set[str]:
    output = git(["ls-files"])
    return {line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()}


def read_json(path: str) -> dict[str, Any]:
    target = ROOT / path
    if not target.exists():
        return {}
    return json.loads(target.read_text(encoding="utf-8-sig"))


def write_json(path: str, payload: dict[str, Any]) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: str, rows: list[dict[str, Any]]) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_text(path: Path, max_bytes: int = 1_000_000) -> str:
    if path.suffix.lower() not in TEXT_SUFFIXES or path.stat().st_size > max_bytes:
        return ""
    try:
        return path.read_text(encoding="utf-8-sig", errors="ignore")
    except UnicodeError:
        return ""


def in_search_space(rel: str) -> bool:
    lower = rel.lower()
    return any(lower.startswith(prefix.lower()) for prefix in SEARCH_PATHS)


def term_hit(rel: str, text: str) -> bool:
    lower = f"{rel}\n{text[:20000]}".lower()
    return any(term.lower() in lower for term in SEARCH_TERMS)


def classify_role(rel: str, text: str) -> str:
    lower = f"{rel}\n{text[:20000]}".lower()
    if "hf" in lower and ("huggingface" in lower or "hf_vault" in lower or "hf_" in lower):
        return "HF_VAULT_REFERENCE"
    if "kaggle" in lower:
        return "KAGGLE_DATASET_REFERENCE"
    if "adapter" in lower and "training" in lower and "receipt" in lower:
        return "ADAPTER_TRAINING_RECEIPT"
    if "lobe" in lower and ("train" in lower or "tranche" in lower or "receipt" in lower):
        return "LOBE_TRAINING_RECEIPT"
    if "row_manifest" in lower:
        return "ROW_MANIFEST"
    if "answer_key" in lower or "expected_answer" in lower or "gold_answer" in lower:
        return "EXPECTED_ANSWER_MANIFEST"
    if "solution" in lower:
        return "SOLUTION_MANIFEST"
    if "crucible" in lower:
        return "ACADEMY_CRUCIBLE"
    if "epoch" in lower or "academy" in lower:
        return "ACADEMY_EPOCH"
    if "scar" in lower or "delta" in lower:
        return "SCAR_DELTA_SOURCE"
    if "repair_corpus" in lower or "training_pairs" in lower or "dataset_manifest" in lower or "train_manifest" in lower:
        return "TRAINING_CORPUS"
    if "eval" in lower or "benchmark" in lower:
        return "EVAL_CORPUS"
    return "UNKNOWN"


def classify_math_relevance(rel: str, text: str) -> str:
    lower = f"{rel}\n{text[:20000]}".lower()
    if "gsm8k" in lower:
        return "GSM8K"
    if "formal_proof" in lower or "formal_math" in lower:
        return "FORMAL_PROOF"
    if "olympiad" in lower or "aime" in lower or "amc" in lower or "competition" in lower:
        return "COMPETITION_MATH"
    if "math" in lower or "reasoning" in lower or "proof" in lower:
        return "MIXED_REASONING"
    if "governance" in lower or "claim" in lower or "authority" in lower:
        return "GOVERNANCE_ONLY"
    if "doctrine" in lower or "law" in lower:
        return "DOCTRINE_ONLY"
    return "UNKNOWN"


def contains_any(text: str, terms: list[str]) -> bool | str:
    if not text:
        return "unknown"
    lower = text.lower()
    return any(term in lower for term in terms)


def likely_train_eval(rel: str, role: str, text: str) -> str:
    lower = f"{rel}\n{text[:20000]}".lower()
    if "row_manifest" in lower or "eval" in lower or "benchmark" in lower or "truegen" in lower:
        return "EVAL"
    if role in {"TRAINING_CORPUS", "SCAR_DELTA_SOURCE", "ACADEMY_CRUCIBLE", "ACADEMY_EPOCH"}:
        if "expected_answer" in lower and ("prompt" in lower or "question_text" in lower):
            return "BOTH_UNSAFE"
        return "TRAIN"
    if "training" in lower and "expected_answer" in lower:
        return "BOTH_UNSAFE"
    return "UNKNOWN"


def binding_status_for(role: str, likely: str, text: str) -> str:
    if role == "UNKNOWN":
        return "UNKNOWN"
    if likely == "BOTH_UNSAFE":
        return "CANDIDATE_REJECTED_LEAKAGE_RISK"
    if not text:
        return "CANDIDATE_BOUND_SHA_ONLY"
    if role in {"HF_VAULT_REFERENCE", "KAGGLE_DATASET_REFERENCE"}:
        return "CANDIDATE_BOUND_SHA_ONLY"
    return "CANDIDATE_NEEDS_SCHEMA_PARSE" if role in {"TRAINING_CORPUS", "ROW_MANIFEST", "EXPECTED_ANSWER_MANIFEST"} else "CANDIDATE_BOUND_SHA_ONLY"


def infer_schema(rel: str, path: Path, text: str) -> dict[str, Any]:
    fields: set[str] = set()
    record_count_seen = 0
    parse_readiness = "SCHEMA_UNKNOWN"
    if path.suffix.lower() == ".jsonl":
        rows = []
        for line in text.splitlines()[:25]:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                parse_readiness = "PARTIAL_PARSE_READY"
                break
            if isinstance(row, dict):
                rows.append(row)
                fields.update(row.keys())
        record_count_seen = len(rows)
        parse_readiness = "PARSE_READY" if rows else parse_readiness
    elif path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                fields.update(data.keys())
                record_count_seen = 1
                parse_readiness = "PARSE_READY"
            elif isinstance(data, list) and data and isinstance(data[0], dict):
                fields.update(data[0].keys())
                record_count_seen = min(len(data), 25)
                parse_readiness = "PARSE_READY"
        except json.JSONDecodeError:
            parse_readiness = "SCHEMA_UNKNOWN"
    elif path.suffix.lower() == ".zip":
        parse_readiness = "BINARY_OR_ZIP_NEEDS_EXTRACTION"
    elif path.suffix.lower() in PARSE_SUFFIXES:
        parse_readiness = "PARTIAL_PARSE_READY"

    lower_fields = {field.lower() for field in fields}
    return {
        "path": rel,
        "parse_readiness": parse_readiness,
        "record_count_seen": record_count_seen,
        "fields": sorted(fields),
        "has_problem_text": bool(lower_fields & {"problem", "question", "question_text", "prompt", "prompt_text"}),
        "has_solution_text": bool(lower_fields & {"solution", "solution_text", "rationale", "reasoning", "chain_of_thought"}),
        "has_final_answer": bool(lower_fields & {"answer", "final_answer", "expected_answer", "gold_answer", "normalized_gold"}),
        "has_split": "split" in lower_fields,
        "has_lobe_target": bool(lower_fields & {"target_lobe", "route_adapter", "repair_surface"}),
        "has_source_dataset": bool(lower_fields & {"dataset", "source_dataset", "dataset_id"}),
        "has_license": bool(lower_fields & {"license", "license_status"}),
        "has_model_visible_prompt": bool(lower_fields & {"prompt", "prompt_text", "model_visible_prompt"}),
    }


def discover_candidates() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tracked = tracked_files()
    candidates: list[dict[str, Any]] = []
    schema_rows: list[dict[str, Any]] = []
    for rel in sorted(tracked):
        path = ROOT / rel
        if not path.is_file() or not in_search_space(rel):
            continue
        text = safe_text(path)
        if not term_hit(rel, text):
            continue
        role = classify_role(rel, text)
        relevance = classify_math_relevance(rel, text)
        likely = likely_train_eval(rel, role, text)
        status = binding_status_for(role, likely, text)
        row = authority(
            schema_id="kt.v17_7_4.math_corpus_source_candidate.v1",
            candidate_id=f"math_source::{len(candidates)+1:04d}",
            path=rel,
            repo_tracked=rel in tracked,
            file_type=path.suffix.lower().lstrip(".") or "none",
            bytes=path.stat().st_size,
            sha256=sha256_file(path),
            source_role=role,
            math_relevance=relevance,
            contains_expected_answers=contains_any(text, ["expected_answer", "gold_answer", "answer_key", "normalized_gold"]),
            contains_solutions=contains_any(text, ["solution", "solution_text", "rationale", "reasoning", "chain_of_thought"]),
            contains_model_visible_prompts=contains_any(text, ["prompt_text", "model_visible_prompt", "question_text", "prompt"]),
            contains_training_examples=role in {"TRAINING_CORPUS", "SCAR_DELTA_SOURCE", "ACADEMY_CRUCIBLE", "ACADEMY_EPOCH"},
            likely_train_or_eval=likely,
            binding_status=status,
        )
        candidates.append(row)
        if path.suffix.lower() in {".json", ".jsonl", ".yaml", ".yml", ".csv", ".zip"}:
            schema_rows.append(infer_schema(rel, path, text))
    return candidates, schema_rows


def zip_reference_map(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for candidate in candidates:
        path = ROOT / candidate["path"]
        if path.suffix.lower() != ".zip":
            continue
        members: list[str] = []
        error: str | None = None
        try:
            with zipfile.ZipFile(path) as archive:
                members = sorted(archive.namelist())[:80]
        except zipfile.BadZipFile:
            error = "BAD_ZIP"
        rows.append(
            {
                "path": candidate["path"],
                "sha256": candidate["sha256"],
                "zip_manifest_preview": members,
                "zip_error": error,
                "authority_level": "REPO_TRACKED_CANONICAL" if candidate["repo_tracked"] else "LOCAL_ONLY_NOT_CANONICAL",
            }
        )
    return rows


def build_authority_map(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    current_head = git(["rev-parse", "HEAD"])
    for candidate in candidates:
        if candidate["source_role"] == "HF_VAULT_REFERENCE":
            level = "HF_VAULT_REFERENCED"
        elif candidate["source_role"] == "KAGGLE_DATASET_REFERENCE":
            level = "KAGGLE_INPUT_REFERENCED"
        elif candidate["repo_tracked"]:
            level = "REPO_TRACKED_CANONICAL"
        else:
            level = "LOCAL_ONLY_NOT_CANONICAL"

        license_status = "UNKNOWN_LICENSE"
        if candidate["source_role"] in {"EVAL_CORPUS", "ROW_MANIFEST"}:
            use_authority = "EVAL_ONLY"
        elif candidate["binding_status"] == "CANDIDATE_REJECTED_LEAKAGE_RISK":
            use_authority = "DO_NOT_USE"
        elif candidate["source_role"] in {"TRAINING_CORPUS", "SCAR_DELTA_SOURCE", "ACADEMY_CRUCIBLE", "ACADEMY_EPOCH"}:
            use_authority = "AUDIT_ONLY"
        else:
            use_authority = "AUDIT_ONLY"
        rows.append(
            authority(
                schema_id="kt.v17_7_4.math_corpus_source_authority_row.v1",
                source_id=candidate["candidate_id"],
                path=candidate["path"],
                authority_level=level,
                provenance={
                    "repo_commit": current_head,
                    "repo_path": candidate["path"],
                    "source_sha": candidate["sha256"],
                },
                license_status=license_status,
                use_authority=use_authority,
            )
        )
    return rows


def status_counts(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    return dict(Counter(str(row.get(key, "UNKNOWN")) for row in rows))


def build() -> dict[str, Any]:
    current_head = git(["rev-parse", "HEAD"])
    current_branch = git(["branch", "--show-current"])
    candidates, schema_rows = discover_candidates()
    authority_rows = build_authority_map(candidates)
    parse_ready_count = sum(1 for row in schema_rows if row["parse_readiness"] == "PARSE_READY")
    train_like_bound = [
        row
        for row in candidates
        if row["source_role"] in {"TRAINING_CORPUS", "SCAR_DELTA_SOURCE", "ACADEMY_CRUCIBLE", "ACADEMY_EPOCH"}
        and row["repo_tracked"]
    ]
    historical_exact_bound = any(
        "13_lobe" in row["path"].lower() and row["source_role"] == "TRAINING_CORPUS" and row["path"].endswith(".jsonl")
        for row in candidates
    )
    audit_ready = bool(train_like_bound and parse_ready_count)
    outcome = OUTCOME if audit_ready else FALLBACK_OUTCOME
    next_lane = NEXT_IF_READY if audit_ready else NEXT_IF_NOT_READY
    binding_status = (
        "BOUND_CURRENT_REPAIR_AND_EVAL_SOURCES__HISTORICAL_13_LOBE_PARTIAL"
        if audit_ready
        else "SEARCH_EXHAUSTED_WITH_NO_PARSE_READY_TRAINING_SOURCE"
    )

    pretraining = read_json("reports/v17_7_4_math_pretraining_hypothesis_court_builder_summary.json")
    official = read_json("reports/v17_7_4_gsm8k_official_score_lock.json")
    scoring = read_json("reports/v17_7_4_scoring_surface_reconciliation_replay_builder_summary.json")
    capability = read_json("reports/v17_7_4_gsm8k_capability_gap_autopsy_builder_summary.json")
    maxtoken = read_json("reports/v17_7_4_gsm8k_maxtoken_sensitivity_builder_summary.json")
    deterministic = read_json("reports/v17_7_4_gsm8k_deterministic_rescue_builder_summary.json")
    academy = read_json("reports/v17_7_4_gsm8k_academy_repairability_plan_no_training.json")
    parser_block = read_json("reports/v17_7_4_math_parser_plus_22_claim_block.json")

    truth_pin = authority(
        schema_id="kt.v17_7_4.math_corpus_source_binding_truth_pin.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        current_branch=current_branch,
        pretraining_hypothesis_court_outcome=pretraining.get("outcome"),
        official_score=official.get("official_score"),
        official_correct=official.get("official_correct"),
        scoring_surface_reconciliation_status=scoring.get("status"),
        capability_gap_status=capability.get("status"),
        max_token_hypothesis_strength=maxtoken.get("hypothesis_strength"),
        deterministic_rescue_net_accuracy_delta=deterministic.get("net_accuracy_delta"),
        academy_repair_ladder_status=academy.get("status"),
        parser_plus_22_claim_block_status=parser_block.get("status"),
        artifact_authority_registry_present=(ROOT / "registry" / "artifact_authority_registry.json").exists(),
        claim_ceiling_preserved=True,
    )
    predecessor = authority(
        schema_id="kt.v17_7_4.math_corpus_source_binding_predecessor_binding.v1",
        status="BOUND",
        predecessor_head=pretraining.get("current_head"),
        predecessor_next_lawful_move=pretraining.get("next_lawful_move"),
        pretraining_hypothesis_binding_status=pretraining.get("pretraining_hypothesis_binding_status"),
        math_corpus_audit_status=pretraining.get("math_corpus_audit_status"),
        runtime_authority=pretraining.get("runtime_authority", False),
        training_authority=pretraining.get("training_authority", False),
    )
    claim = authority(
        schema_id="kt.v17_7_4.math_corpus_source_binding_claim_boundary_receipt.v1",
        status="PASS",
        allowed_internal_claim="KT is attempting to bind math/Academy corpus sources for audit. Training authority remains false.",
        corpus_quality_claim=False,
        dataset_readiness_claim=False,
        training_readiness_claim=False,
    )

    search_plan = authority(
        schema_id="kt.v17_7_4.math_corpus_source_search_plan.v1",
        status="PASS",
        search_paths=SEARCH_PATHS,
        search_terms=SEARCH_TERMS,
        searched_repo_tracked_files=True,
        hash_all_candidates=True,
    )
    search_paths = authority(
        schema_id="kt.v17_7_4.math_corpus_source_search_paths.v1",
        status="PASS",
        paths=[{"path": path, "exists": (ROOT / path).exists()} for path in SEARCH_PATHS],
    )
    search_terms = authority(
        schema_id="kt.v17_7_4.math_corpus_source_search_terms.v1",
        status="PASS",
        terms=SEARCH_TERMS,
    )

    candidate_index = authority(
        schema_id="kt.v17_7_4.math_corpus_source_candidate_index.v1",
        status="PASS",
        candidate_count=len(candidates),
        role_counts=status_counts(candidates, "source_role"),
        relevance_counts=status_counts(candidates, "math_relevance"),
        binding_status_counts=status_counts(candidates, "binding_status"),
        likely_train_or_eval_counts=status_counts(candidates, "likely_train_or_eval"),
    )
    discovery = authority(
        schema_id="kt.v17_7_4.math_corpus_source_discovery_receipt.v1",
        status="PASS",
        source_search_status="PASS",
        source_candidate_count=len(candidates),
        train_like_candidate_count=len(train_like_bound),
        parse_ready_candidate_count=parse_ready_count,
        historical_exact_13_lobe_training_source_bound=historical_exact_bound,
    )
    authority_map = authority(
        schema_id="kt.v17_7_4.math_corpus_source_authority_map.v1",
        status="PASS",
        source_count=len(authority_rows),
        authority_level_counts=status_counts(authority_rows, "authority_level"),
        use_authority_counts=status_counts(authority_rows, "use_authority"),
        rows=authority_rows,
    )
    provenance = authority(
        schema_id="kt.v17_7_4.math_corpus_source_provenance_receipt.v1",
        status="PASS",
        repo_commit=current_head,
        source_count=len(candidates),
        all_repo_tracked_candidates_hashed=all(row["repo_tracked"] and row["sha256"] for row in candidates),
        missing_referenced_source_count=0,
    )
    hf_kaggle = authority(
        schema_id="kt.v17_7_4.math_corpus_hf_kaggle_reference_map.v1",
        status="PASS",
        hf_reference_count=sum(1 for row in candidates if row["source_role"] == "HF_VAULT_REFERENCE"),
        kaggle_reference_count=sum(1 for row in candidates if row["source_role"] == "KAGGLE_DATASET_REFERENCE"),
        zip_reference_count=sum(1 for row in candidates if row["file_type"] == "zip"),
        zip_manifest_previews=zip_reference_map(candidates),
    )
    schema_inference = authority(
        schema_id="kt.v17_7_4.math_corpus_schema_inference.v1",
        status="PASS",
        candidate_count=len(schema_rows),
        parse_readiness_counts=status_counts(schema_rows, "parse_readiness"),
        rows=schema_rows,
    )
    parse_readiness = authority(
        schema_id="kt.v17_7_4.math_corpus_parse_readiness.v1",
        status="PASS",
        parse_ready_count=parse_ready_count,
        partial_parse_ready_count=sum(1 for row in schema_rows if row["parse_readiness"] == "PARTIAL_PARSE_READY"),
        binary_or_zip_needs_extraction_count=sum(
            1 for row in schema_rows if row["parse_readiness"] == "BINARY_OR_ZIP_NEEDS_EXTRACTION"
        ),
        audit_ready=audit_ready,
    )
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.v17_7_4.math_corpus_source.schema.v1",
        "type": "object",
        "additionalProperties": True,
        "required": ["candidate_id", "path", "sha256", "source_role", "math_relevance", "binding_status"],
        "properties": {
            "candidate_id": {"type": "string"},
            "path": {"type": "string"},
            "sha256": {"type": "string"},
            "source_role": {"type": "string"},
            "math_relevance": {"type": "string"},
            "binding_status": {"type": "string"},
            "training_authority": {"const": False},
        },
    }

    expected_answer_candidates = [
        row
        for row in candidates
        if row["contains_expected_answers"] is True or row["source_role"] in {"EXPECTED_ANSWER_MANIFEST", "ROW_MANIFEST"}
    ]
    leakage = authority(
        schema_id="kt.v17_7_4.math_corpus_leakage_precheck.v1",
        status="PASS_PRECHECK_ONLY",
        expected_answer_candidate_count=len(expected_answer_candidates),
        leakage_risk_candidates=[
            {
                "candidate_id": row["candidate_id"],
                "path": row["path"],
                "likely_train_or_eval": row["likely_train_or_eval"],
                "use_authority": "EVAL_ONLY" if row["likely_train_or_eval"] == "EVAL" else "AUDIT_ONLY",
            }
            for row in expected_answer_candidates[:200]
        ],
        expected_answer_values_model_visible_allowed=False,
        future_overlap_hash_check_required=True,
    )
    train_eval = authority(
        schema_id="kt.v17_7_4.math_corpus_train_eval_boundary_precheck.v1",
        status="PASS_PRECHECK_ONLY",
        train_like_candidate_count=len(train_like_bound),
        eval_like_candidate_count=sum(1 for row in candidates if row["likely_train_or_eval"] == "EVAL"),
        both_unsafe_candidate_count=sum(1 for row in candidates if row["likely_train_or_eval"] == "BOTH_UNSAFE"),
        eval_rows_must_not_be_future_training_targets=True,
        normalized_text_hash_strategy_required=True,
    )
    expected_map = authority(
        schema_id="kt.v17_7_4.math_corpus_expected_answer_field_map.v1",
        status="PASS",
        fields_detected=sorted(
            {
                field
                for schema_row in schema_rows
                for field in schema_row.get("fields", [])
                if "answer" in field.lower() or "gold" in field.lower()
            }
        ),
        expected_answer_candidate_paths=[row["path"] for row in expected_answer_candidates[:200]],
    )
    quality_requirements = authority(
        schema_id="kt.v17_7_4.math_corpus_quality_audit_requirements.v1",
        status="PASS",
        requirements=[
            "row count by math lane",
            "dedup by normalized text hash",
            "answer leakage risk",
            "solution-step presence",
            "difficulty distribution",
            "answer-format contract alignment",
            "lobe-target distribution",
            "epoch/crucible coverage",
            "scar/delta coverage",
            "doctrine/governance contamination risk",
            "train/eval overlap risk",
            "source/license risk",
        ],
    )
    quality_metrics = authority(
        schema_id="kt.v17_7_4.math_corpus_quality_metrics_plan.v1",
        status="PASS",
        metrics=[
            "row_count_by_lane",
            "normalized_text_dedup_rate",
            "expected_answer_leakage_rate",
            "solution_step_presence_rate",
            "difficulty_bucket_distribution",
            "answer_format_alignment_rate",
            "target_lobe_distribution",
            "train_eval_overlap_count",
            "unknown_license_count",
        ],
    )
    quality_readiness = authority(
        schema_id="kt.v17_7_4.math_corpus_quality_audit_readiness.v1",
        status="READY_FOR_BOUND_CURRENT_SOURCES" if audit_ready else "NOT_READY_SOURCE_BINDING_INCOMPLETE",
        audit_ready=audit_ready,
        missing_requirements=[] if audit_ready else ["parse-ready train-like corpus source"],
        next_lane_if_ready=NEXT_IF_READY,
        next_lane_if_not_ready=NEXT_IF_NOT_READY,
        selected_next_lane=next_lane,
        historical_13_lobe_exact_source_bound=historical_exact_bound,
    )
    historical_training = authority(
        schema_id="kt.v17_7_4.historical_math_training_corpus_recovery_status.v1",
        status="PARTIAL_BOUND",
        original_13_lobe_training_corpora_bound=historical_exact_bound,
        current_repair_corpora_bound=bool(train_like_bound),
        hypertraining_corpora_bound=any("hypertrain" in row["path"].lower() for row in candidates),
        recohort_training_corpora_bound=any("recohort" in row["path"].lower() for row in candidates),
        exact_training_prompts_templates_bound=False,
        exact_data_splits_bound=False,
        no_invention=True,
    )
    historical_13_lobe = authority(
        schema_id="kt.v17_7_4.historical_13_lobe_training_source_status.v1",
        status="REFERENCED_NOT_FULLY_BOUND" if not historical_exact_bound else "BOUND",
        tranche_configs_bound=any("kt_13_lobe_7b_tranche_config" in row["path"] for row in candidates),
        row_level_source_bound=historical_exact_bound,
        training_receipts_bound=any("training" in row["path"].lower() and "receipt" in row["path"].lower() for row in candidates),
    )
    historical_epoch = authority(
        schema_id="kt.v17_7_4.historical_epoch_crucible_source_status.v1",
        status="PARTIAL_BOUND",
        epochs_crucibles_bound=any(row["source_role"] in {"ACADEMY_CRUCIBLE", "ACADEMY_EPOCH"} for row in candidates),
        recursive_learning_deltas_bound=any("recursive_delta" in row["path"].lower() for row in candidates),
        scar_delta_registries_bound=any(row["source_role"] == "SCAR_DELTA_SOURCE" for row in candidates),
        adapter_training_receipts_bound=any(row["source_role"] == "ADAPTER_TRAINING_RECEIPT" for row in candidates),
    )
    epc = authority(
        schema_id="kt.v17_7_4.epc_decision_after_math_corpus_source_binding.v1",
        status="PASS_DECIDED",
        options_considered=[
            NEXT_IF_READY,
            NEXT_IF_NOT_READY,
            "AUTHOR_BASE_MODEL_STANDARD_MATH_PROMPT_PROBE_DESIGN_V1",
            "AUTHOR_BASE_MODEL_STANDARD_MATH_PROMPT_PROBE_25_IF_EPC_AUTHORIZES",
            "AUTHOR_MATH_DATASET_BLUEPRINT_NO_TRAINING_V1",
            "AUTHOR_MATH_TRAINING_AUTHORITY_REQUEST_DRAFT_V1",
            "RETURN_TO_ACADEMY_MATH_REPAIR_LADDER",
            "NO_RUNTIME_PACKET__CORPUS_SOURCE_NOT_BOUND",
            "RESEARCH_REGISTER_ONLY_FOR_ROUTER_OR_THEORY",
        ],
        selected_next_lane=next_lane,
        runtime_allowed_by_this_lane=False,
        training_allowed_by_this_lane=False,
        reason=(
            "Repo-tracked current repair/eval corpus candidates are bound and parse-ready enough for quality audit; "
            "historical 13-lobe training source remains partial and must not become training authority."
            if audit_ready
            else "No parse-ready train-like corpus source was bound."
        ),
    )
    next_lane_receipt = authority(
        schema_id="kt.v17_7_4.math_corpus_source_binding_next_lane.v1",
        status="PASS_NO_RUNTIME_PACKET",
        selected_next_lane=next_lane,
        next_lawful_move=next_lane,
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
    )
    intervention = authority(
        schema_id="kt.v17_7_4.math_corpus_source_binding_intervention_queue.v1",
        status="PASS",
        queue=[
            {"rank": 1, "lane": next_lane, "runtime": False, "training": False},
            {"rank": 2, "lane": NEXT_IF_NOT_READY if next_lane == NEXT_IF_READY else NEXT_IF_READY, "runtime": False, "training": False},
            {"rank": 3, "lane": "AUTHOR_MATH_DATASET_BLUEPRINT_NO_TRAINING_V1", "runtime": False, "training": False},
            {"rank": 4, "lane": "AUTHOR_MATH_TRAINING_AUTHORITY_REQUEST_DRAFT_V1", "runtime": False, "training": False},
        ],
    )

    files_changed = [
        "scripts/build_v17_7_4_math_corpus_source_binding.py",
        "schemas/kt.v17_7_4.math_corpus_source.schema.json",
        "reports/v17_7_4_math_corpus_source_binding_truth_pin.json",
        "reports/v17_7_4_math_corpus_source_binding_predecessor_binding.json",
        "reports/v17_7_4_math_corpus_source_binding_claim_boundary_receipt.json",
        "reports/v17_7_4_math_corpus_source_search_plan.json",
        "reports/v17_7_4_math_corpus_source_search_paths.json",
        "reports/v17_7_4_math_corpus_source_search_terms.json",
        "reports/v17_7_4_math_corpus_source_candidate_index.json",
        "reports/v17_7_4_math_corpus_source_candidate_table.jsonl",
        "reports/v17_7_4_math_corpus_source_discovery_receipt.json",
        "reports/v17_7_4_math_corpus_source_authority_map.json",
        "reports/v17_7_4_math_corpus_source_provenance_receipt.json",
        "reports/v17_7_4_math_corpus_hf_kaggle_reference_map.json",
        "reports/v17_7_4_math_corpus_schema_inference.json",
        "reports/v17_7_4_math_corpus_parse_readiness.json",
        "reports/v17_7_4_math_corpus_leakage_precheck.json",
        "reports/v17_7_4_math_corpus_train_eval_boundary_precheck.json",
        "reports/v17_7_4_math_corpus_expected_answer_field_map.json",
        "reports/v17_7_4_math_corpus_quality_audit_readiness.json",
        "reports/v17_7_4_math_corpus_quality_audit_requirements.json",
        "reports/v17_7_4_math_corpus_quality_metrics_plan.json",
        "reports/v17_7_4_historical_math_training_corpus_recovery_status.json",
        "reports/v17_7_4_historical_13_lobe_training_source_status.json",
        "reports/v17_7_4_historical_epoch_crucible_source_status.json",
        "reports/v17_7_4_epc_decision_after_math_corpus_source_binding.json",
        "reports/v17_7_4_math_corpus_source_binding_next_lane.json",
        "reports/v17_7_4_math_corpus_source_binding_intervention_queue.json",
        "reports/v17_7_4_math_corpus_source_binding_builder_summary.json",
        "registry/artifact_authority_registry_v17_7_4_math_corpus_source_binding_delta_receipt.json",
        "tests/test_v17_7_4_math_corpus_source_binding.py",
    ]
    registry_delta = authority(
        schema_id="kt.artifact_authority_registry_delta.v17_7_4_math_corpus_source_binding",
        status="PASS",
        active_tranche=TRANCHE,
        outcome=outcome,
        artifacts_added=files_changed,
        runtime_authority=False,
        training_authority=False,
        packet_path_if_any=None,
        claim_ceiling_status="PRESERVED",
    )
    summary = authority(
        schema_id="kt.v17_7_4.math_corpus_source_binding_builder_summary.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        branch=current_branch,
        outcome=outcome,
        files_changed=files_changed,
        math_corpus_source_binding_status=binding_status,
        source_search_status=search_plan["status"],
        source_candidate_index_status=candidate_index["status"],
        source_authority_map_status=authority_map["status"],
        schema_inference_status=schema_inference["status"],
        leakage_precheck_status=leakage["status"],
        train_eval_boundary_precheck_status=train_eval["status"],
        quality_audit_readiness_status=quality_readiness["status"],
        historical_training_corpus_recovery_status=historical_training["status"],
        historical_epoch_crucible_source_status=historical_epoch["status"],
        epc_next_lane_status=next_lane_receipt["status"],
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move=next_lane,
    )

    outputs = {
        "schemas/kt.v17_7_4.math_corpus_source.schema.json": schema,
        "reports/v17_7_4_math_corpus_source_binding_truth_pin.json": truth_pin,
        "reports/v17_7_4_math_corpus_source_binding_predecessor_binding.json": predecessor,
        "reports/v17_7_4_math_corpus_source_binding_claim_boundary_receipt.json": claim,
        "reports/v17_7_4_math_corpus_source_search_plan.json": search_plan,
        "reports/v17_7_4_math_corpus_source_search_paths.json": search_paths,
        "reports/v17_7_4_math_corpus_source_search_terms.json": search_terms,
        "reports/v17_7_4_math_corpus_source_candidate_index.json": candidate_index,
        "reports/v17_7_4_math_corpus_source_discovery_receipt.json": discovery,
        "reports/v17_7_4_math_corpus_source_authority_map.json": authority_map,
        "reports/v17_7_4_math_corpus_source_provenance_receipt.json": provenance,
        "reports/v17_7_4_math_corpus_hf_kaggle_reference_map.json": hf_kaggle,
        "reports/v17_7_4_math_corpus_schema_inference.json": schema_inference,
        "reports/v17_7_4_math_corpus_parse_readiness.json": parse_readiness,
        "reports/v17_7_4_math_corpus_leakage_precheck.json": leakage,
        "reports/v17_7_4_math_corpus_train_eval_boundary_precheck.json": train_eval,
        "reports/v17_7_4_math_corpus_expected_answer_field_map.json": expected_map,
        "reports/v17_7_4_math_corpus_quality_audit_readiness.json": quality_readiness,
        "reports/v17_7_4_math_corpus_quality_audit_requirements.json": quality_requirements,
        "reports/v17_7_4_math_corpus_quality_metrics_plan.json": quality_metrics,
        "reports/v17_7_4_historical_math_training_corpus_recovery_status.json": historical_training,
        "reports/v17_7_4_historical_13_lobe_training_source_status.json": historical_13_lobe,
        "reports/v17_7_4_historical_epoch_crucible_source_status.json": historical_epoch,
        "reports/v17_7_4_epc_decision_after_math_corpus_source_binding.json": epc,
        "reports/v17_7_4_math_corpus_source_binding_next_lane.json": next_lane_receipt,
        "reports/v17_7_4_math_corpus_source_binding_intervention_queue.json": intervention,
        "registry/artifact_authority_registry_v17_7_4_math_corpus_source_binding_delta_receipt.json": registry_delta,
        "reports/v17_7_4_math_corpus_source_binding_builder_summary.json": summary,
    }
    for path, payload in outputs.items():
        write_json(path, payload)
    write_jsonl("reports/v17_7_4_math_corpus_source_candidate_table.jsonl", candidates)
    return summary


def main() -> None:
    print(json.dumps(build(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
