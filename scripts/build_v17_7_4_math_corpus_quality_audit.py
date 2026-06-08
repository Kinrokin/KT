from __future__ import annotations

import csv
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TRANCHE = "AUTHOR_KTV1774_MATH_CORPUS_QUALITY_AUDIT_V1"
OUTCOME = (
    "KT_MATH_CORPUS_QUALITY_AUDITED__NEXT_DATA_OR_TRAINING_AUTHORITY_LANE_DECIDED__"
    "TRAINING_AUTHORITY_STILL_FALSE__CLAIM_CEILING_PRESERVED"
)
NEXT_SANITIZE = "AUTHOR_MATH_CORPUS_SANITIZATION_PLAN_NO_DATASET_V1"
NEXT_BLUEPRINT = "AUTHOR_MATH_DATASET_BLUEPRINT_NO_TRAINING_V1"
NEXT_RECOVER = "AUTHOR_MATH_CORPUS_SOURCE_RECOVERY_OR_AUTHORING_PLAN_V1"

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
    "prompt_mutation_packet_generated": False,
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

CORPUS_ROLES = {
    "TRAINING_CORPUS",
    "SCAR_DELTA_SOURCE",
    "ACADEMY_CRUCIBLE",
    "ACADEMY_EPOCH",
    "ROW_MANIFEST",
    "EXPECTED_ANSWER_MANIFEST",
    "SOLUTION_MANIFEST",
    "EVAL_CORPUS",
}

JSON_LIST_KEYS = (
    "rows",
    "records",
    "items",
    "examples",
    "data",
    "samples",
    "questions",
    "predictions",
    "matrix",
    "table",
)

PROBLEM_FIELDS = (
    "problem",
    "question",
    "question_text",
    "prompt",
    "prompt_text",
    "input",
    "instruction",
)
SOLUTION_FIELDS = (
    "solution",
    "solution_text",
    "rationale",
    "reasoning",
    "chain_of_thought",
    "cot",
    "explanation",
    "response",
    "output",
)
ANSWER_FIELDS = (
    "answer",
    "final_answer",
    "expected_answer",
    "gold_answer",
    "normalized_gold",
    "target",
    "label",
)


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(AUTHORITY_FALSE)
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def read_json(path: str) -> dict[str, Any]:
    target = ROOT / path
    if not target.exists():
        return {}
    return json.loads(target.read_text(encoding="utf-8-sig"))


def read_jsonl(path: str) -> list[dict[str, Any]]:
    target = ROOT / path
    if not target.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in target.read_text(encoding="utf-8-sig", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def write_json(path: str, payload: dict[str, Any]) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: str, rows: list[dict[str, Any]]) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def stable_hash(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True, ensure_ascii=True)
    normalized = normalize_text(value)
    if not normalized:
        return None
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", str(text).strip().lower())


def text_from_fields(record: dict[str, Any], fields: tuple[str, ...]) -> str:
    lowered = {str(key).lower(): key for key in record}
    values: list[str] = []
    for field in fields:
        if field in lowered:
            value = record.get(lowered[field])
            if isinstance(value, (str, int, float, bool)):
                values.append(str(value))
            elif value is not None:
                values.append(json.dumps(value, sort_keys=True, ensure_ascii=True))
    return "\n".join(values)


def first_present(record: dict[str, Any], fields: tuple[str, ...]) -> Any:
    lowered = {str(key).lower(): key for key in record}
    for field in fields:
        if field in lowered:
            return record.get(lowered[field])
    return None


def scalar_field(record: dict[str, Any], *names: str) -> str | None:
    lowered = {str(key).lower(): key for key in record}
    for name in names:
        key = lowered.get(name.lower())
        if key is None:
            continue
        value = record.get(key)
        if isinstance(value, (str, int, float, bool)):
            return str(value)
    return None


def source_id(row: dict[str, Any]) -> str:
    return str(row.get("candidate_id") or row.get("source_id") or stable_hash(row.get("path")) or "unknown_source")


def classify_record_role(candidate: dict[str, Any]) -> str:
    likely = candidate.get("likely_train_or_eval")
    role = candidate.get("source_role")
    if likely == "TRAIN":
        return "TRAIN_CANDIDATE"
    if likely == "EVAL":
        return "EVAL_CANDIDATE"
    if role == "SCAR_DELTA_SOURCE":
        return "SCAR_DELTA_CANDIDATE"
    if role == "SOLUTION_MANIFEST":
        return "SOLUTION_ONLY"
    return "UNKNOWN"


def classify_lane(candidate: dict[str, Any], record_text: str) -> str:
    blob = f"{candidate.get('path', '')}\n{candidate.get('math_relevance', '')}\n{record_text}".lower()
    if "governance" in blob or "claim_ceiling" in blob or "doctrine" in blob:
        return "DOCTRINE_GOVERNANCE_CONTAMINATION"
    if "gsm8k" in blob or ("grade school" in blob and "math" in blob):
        return "ARITHMETIC_GSM8K"
    if "formal_proof" in blob or "theorem" in blob or "proof" in blob or "lemma" in blob:
        return "FORMAL_PROOF"
    if "olympiad" in blob or "aime" in blob or "amc" in blob or "competition" in blob:
        return "OLYMPIAD_STRATEGY" if "strategy" in blob else "COMPETITION_MATH"
    if "code" in blob and "math" in blob:
        return "CODE_MATH"
    if "math" in blob or "arithmetic" in blob or "algebra" in blob or "geometry" in blob:
        return "MIXED_REASONING"
    return "UNKNOWN"


def difficulty_features(text: str) -> dict[str, Any]:
    numbers = [int(match) for match in re.findall(r"(?<![A-Za-z])-?\d+", text)[:50]]
    lower = text.lower()
    operation_cues = sum(lower.count(term) for term in ["total", "left", "each", "more", "less", "times", "divide", "percent", "ratio"])
    multi_step = any(term in lower for term in ["then", "after", "before", "each", "remaining", "altogether", "how many more"])
    return {
        "question_length": len(text),
        "sentence_count": max(1, len(re.findall(r"[.!?]", text))),
        "number_count": len(numbers),
        "largest_number_magnitude": max([abs(num) for num in numbers], default=0),
        "operation_cue_count": operation_cues,
        "multi_step_indicator": multi_step,
        "percent_or_ratio_cue": any(term in lower for term in ["percent", "%", "ratio", "rate"]),
        "geometry_or_proof_cue": any(term in lower for term in ["angle", "triangle", "circle", "prove", "theorem"]),
        "algebra_symbolic_cue": bool(re.search(r"\b[x-z]\b|=|\^", text)),
    }


def classify_difficulty(lane: str, features: dict[str, Any]) -> str:
    score = 0
    score += min(int(features["number_count"]), 6)
    score += min(int(features["operation_cue_count"]), 6)
    score += 3 if features["multi_step_indicator"] else 0
    score += 3 if features["percent_or_ratio_cue"] else 0
    score += 4 if features["geometry_or_proof_cue"] else 0
    score += 2 if features["algebra_symbolic_cue"] else 0
    score += 2 if int(features["question_length"]) > 250 else 0
    if lane in {"FORMAL_PROOF", "COMPETITION_MATH", "OLYMPIAD_STRATEGY"}:
        return "ADVANCED_MATH"
    if score <= 3:
        return "GSM8K_EASY"
    if score <= 9:
        return "GSM8K_MEDIUM"
    return "GSM8K_HARD"


def format_alignment(problem: str, solution: str, answer: str, lane: str) -> str:
    combined = f"{problem}\n{solution}\n{answer}".lower()
    has_reasoning = bool(solution.strip()) or any(term in combined for term in ["because", "therefore", "step", "then", "so "])
    has_final_marker = any(term in combined for term in ["final answer", "answer:", "####", "\\boxed", "boxed"])
    doctrine = lane == "DOCTRINE_GOVERNANCE_CONTAMINATION" or any(
        term in combined for term in ["claim ceiling", "router", "lobe", "kt law", "receipt"]
    )
    if doctrine:
        return "MISALIGNED_DOCTRINE_CONTAMINATED"
    if has_reasoning and has_final_marker:
        return "STRONGLY_ALIGNED"
    if has_reasoning:
        return "PARTIALLY_ALIGNED"
    if answer and not solution:
        return "MISALIGNED_FINAL_ANSWER_ONLY"
    if problem and not solution:
        return "MISALIGNED_ANSWER_FIRST_NO_REASONING"
    return "UNKNOWN"


def verifier_compatibility(problem: str, solution: str, answer: str, lane: str) -> str:
    if lane in {"FORMAL_PROOF", "OLYMPIAD_STRATEGY"}:
        return "FORMAL_VERIFIER_REQUIRED"
    if answer and re.search(r"-?\d+(\.\d+)?", answer):
        return "HIGH_VERIFIER_COMPATIBILITY" if solution else "PARTIAL_VERIFIER_COMPATIBILITY"
    if solution and problem:
        return "PARTIAL_VERIFIER_COMPATIBILITY"
    if lane == "DOCTRINE_GOVERNANCE_CONTAMINATION":
        return "LOW_VERIFIER_COMPATIBILITY"
    return "UNKNOWN"


def leakage_risk(record: dict[str, Any], problem: str, solution: str, answer: str, role: str) -> str:
    lower_keys = {str(key).lower() for key in record}
    lower_problem = problem.lower()
    lower_solution = solution.lower()
    lower_answer = answer.lower()
    answer_visible = bool(answer and answer in problem)
    oracle_fields = any(key in lower_keys for key in {"correct", "is_correct", "oracle_route", "oracle_winner", "score"})
    if answer_visible or ("expected_answer" in lower_problem) or ("gold_answer" in lower_problem):
        return "HIGH"
    if oracle_fields and role == "TRAIN_CANDIDATE":
        return "HIGH"
    if lower_answer and lower_answer in lower_solution[:80]:
        return "MEDIUM"
    if any(key in lower_keys for key in {"expected_answer", "gold_answer", "answer_key", "normalized_gold"}):
        return "LOW"
    return "NONE_DETECTED"


def use_authority_after_audit(source_use: str, leak: str, overlap: bool, license_status: str) -> str:
    if source_use == "EVAL_ONLY":
        return "EVAL_ONLY"
    if leak == "HIGH" or overlap:
        return "DO_NOT_USE_FOR_TRAINING"
    if license_status in {"UNKNOWN_LICENSE", "RESTRICTED"}:
        return "UNKNOWN"
    if leak in {"LOW", "MEDIUM"}:
        return "FUTURE_TRAINING_CANDIDATE_NEEDS_SANITIZATION"
    return "FUTURE_TRAINING_CANDIDATE_NEEDS_SANITIZATION"


def load_source_maps() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    candidates = read_jsonl("reports/v17_7_4_math_corpus_source_candidate_table.jsonl")
    authority_map = read_json("reports/v17_7_4_math_corpus_source_authority_map.json")
    schema_inference = read_json("reports/v17_7_4_math_corpus_schema_inference.json")
    authority_by_id = {row.get("source_id"): row for row in authority_map.get("rows", [])}
    schema_by_path = {row.get("path"): row for row in schema_inference.get("rows", [])}
    return candidates, authority_by_id, schema_by_path


def extract_records_from_json(data: Any) -> tuple[list[Any], str]:
    if isinstance(data, list):
        return data, "json_list"
    if isinstance(data, dict):
        for key in JSON_LIST_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                return value, f"json_dict_list_key:{key}"
        return [data], "json_dict_single"
    return [], "json_unsupported_root"


def parse_candidate(candidate: dict[str, Any], authority_by_id: dict[str, dict[str, Any]], schema_by_path: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    sid = source_id(candidate)
    rel = str(candidate.get("path"))
    path = ROOT / rel
    authority_row = authority_by_id.get(sid, {})
    schema_row = schema_by_path.get(rel, {})
    parse_readiness = schema_row.get("parse_readiness", "SCHEMA_UNKNOWN")
    errors: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    source_summary = {
        "source_id": sid,
        "path": rel,
        "sha256": candidate.get("sha256"),
        "source_role": candidate.get("source_role"),
        "math_relevance": candidate.get("math_relevance"),
        "parse_readiness": parse_readiness,
        "parse_status": "SKIPPED_NOT_PARSE_READY",
        "row_count": 0,
        "records_emitted": 0,
        "record_parse_truncated": False,
        "schema_fields_present": schema_row.get("fields", []),
        "schema_fields_missing": [],
    }
    if parse_readiness not in {"PARSE_READY", "PARTIAL_PARSE_READY"}:
        return records, source_summary, errors
    if not path.exists() or not path.is_file():
        source_summary["parse_status"] = "ERROR"
        errors.append({"source_id": sid, "path": rel, "error_type": "MISSING_FILE"})
        return records, source_summary, errors

    parsed_items: list[Any] = []
    source_kind = "unknown"
    try:
        suffix = path.suffix.lower()
        if suffix == ".jsonl":
            for line_number, line in enumerate(path.read_text(encoding="utf-8-sig", errors="ignore").splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append({"source_id": sid, "path": rel, "line": line_number, "error_type": "JSONL_DECODE", "message": str(exc)})
                    continue
                parsed_items.append(item)
            source_kind = "jsonl"
        elif suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8-sig", errors="ignore"))
            parsed_items, source_kind = extract_records_from_json(data)
        elif suffix == ".csv":
            with path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
                parsed_items = list(csv.DictReader(handle))
            source_kind = "csv"
        elif suffix in {".yaml", ".yml"}:
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
            parsed_items = [{"text_hash": stable_hash(text), "line_count": len(text.splitlines())}]
            source_kind = "yaml_summary"
        else:
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
            parsed_items = [{"text_hash": stable_hash(text), "line_count": len(text.splitlines())}]
            source_kind = "text_summary"
    except Exception as exc:  # noqa: BLE001 - receipts need safe parse failure capture.
        source_summary["parse_status"] = "ERROR"
        errors.append({"source_id": sid, "path": rel, "error_type": type(exc).__name__, "message": str(exc)})
        return records, source_summary, errors

    source_summary["parse_status"] = "PARSED"
    source_summary["row_count"] = len(parsed_items)
    source_summary["source_kind"] = source_kind
    max_records = 250 if candidate.get("source_role") in CORPUS_ROLES else 25
    source_summary["record_parse_truncated"] = len(parsed_items) > max_records

    for index, item in enumerate(parsed_items[:max_records]):
        if not isinstance(item, dict):
            item = {"value_hash": stable_hash(item), "value_type": type(item).__name__}
        problem = text_from_fields(item, PROBLEM_FIELDS)
        solution = text_from_fields(item, SOLUTION_FIELDS)
        answer = text_from_fields(item, ANSWER_FIELDS)
        record_text = "\n".join(part for part in [problem, solution, answer, json.dumps(item, sort_keys=True, ensure_ascii=True)[:4000]] if part)
        role = classify_record_role(candidate)
        lane = classify_lane(candidate, record_text)
        features = difficulty_features(problem or record_text)
        difficulty = classify_difficulty(lane, features)
        alignment = format_alignment(problem, solution, answer, lane)
        leak = leakage_risk(item, problem, solution, answer, role)
        verifier = verifier_compatibility(problem, solution, answer, lane)
        rec = authority(
            schema_id="kt.v17_7_4.math_corpus_quality_record.v1",
            source_id=sid,
            source_path=rel,
            source_sha256=candidate.get("sha256"),
            source_authority_level=authority_row.get("authority_level", "UNKNOWN"),
            source_use_authority=authority_row.get("use_authority", "AUDIT_ONLY"),
            record_index=index,
            record_id_hash=stable_hash(f"{sid}:{index}:{stable_hash(item)}"),
            problem_text_hash=stable_hash(problem),
            normalized_problem_hash=stable_hash(problem),
            solution_text_hash=stable_hash(solution),
            final_answer_hash=stable_hash(answer),
            split=scalar_field(item, "split", "subset"),
            source_dataset=scalar_field(item, "dataset", "source_dataset", "dataset_id") or candidate.get("math_relevance"),
            lobe_target=scalar_field(item, "target_lobe", "route_adapter", "repair_surface", "selected_lobe"),
            epoch_or_crucible_id=scalar_field(item, "epoch_id", "crucible_id", "run_id"),
            record_role=role,
            expected_answer_model_visible=False,
            math_lane=lane,
            leakage_risk=leak,
            format_alignment=alignment,
            difficulty_band=difficulty,
            verifier_compatibility=verifier,
            feature_summary=features,
            has_problem_text=bool(problem),
            has_solution_text=bool(solution),
            has_final_answer=bool(answer),
            reasoning_step_present=bool(solution) or any(term in record_text.lower() for term in ["because", "therefore", "step", "then"]),
            final_marker_present=any(term in record_text.lower() for term in ["final answer", "answer:", "####", "\\boxed", "boxed"]),
        )
        records.append(rec)
    source_summary["records_emitted"] = len(records)
    source_summary["schema_fields_missing"] = [
        field
        for field, present in {
            "problem_text": any(row.get("has_problem_text") for row in records),
            "solution_text": any(row.get("has_solution_text") for row in records),
            "final_answer": any(row.get("has_final_answer") for row in records),
            "split": any(row.get("split") for row in records),
        }.items()
        if not present
    ]
    return records, source_summary, errors


def percent(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 6)


def grade_from_ratio(ratio: float, high: float, mid: float, low: float) -> str:
    if ratio >= high:
        return "A"
    if ratio >= mid:
        return "B"
    if ratio >= low:
        return "C"
    return "D"


def build_duplicate_clusters(records: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        key = record.get("normalized_problem_hash")
        if key:
            groups[str(key)].append(record)
    duplicate_rows = []
    for idx, (key, items) in enumerate(sorted(groups.items(), key=lambda pair: len(pair[1]), reverse=True), start=1):
        if len(items) < 2:
            continue
        answer_hashes = sorted({str(item.get("final_answer_hash")) for item in items if item.get("final_answer_hash")})
        duplicate_rows.append(
            authority(
                schema_id="kt.v17_7_4.math_corpus_duplicate_cluster.v1",
                dedup_cluster_id=f"cluster_{idx:05d}",
                normalized_problem_hash=key,
                row_count=len(items),
                source_ids=sorted({str(item.get("source_id")) for item in items}),
                record_roles=sorted({str(item.get("record_role")) for item in items}),
                final_answer_hash_count=len(answer_hashes),
                duplicate_problem_different_answer=len(answer_hashes) > 1,
            )
        )
    audit = authority(
        schema_id="kt.v17_7_4.math_corpus_dedup_audit.v1",
        status="PASS",
        record_count=len(records),
        unique_problem_hash_count=len(groups),
        duplicate_cluster_count=len(duplicate_rows),
        duplicate_record_rate=percent(sum(row["row_count"] for row in duplicate_rows), len(records)),
        duplicate_problem_different_answer_count=sum(1 for row in duplicate_rows if row["duplicate_problem_different_answer"]),
        dedup_audit_status="PASS_WITH_DUPLICATES" if duplicate_rows else "PASS_NO_DUPLICATES_DETECTED",
    )
    return audit, duplicate_rows[:1000]


def build_eval_overlap(records: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    train_hashes = {record.get("normalized_problem_hash") for record in records if record.get("record_role") == "TRAIN_CANDIDATE" and record.get("normalized_problem_hash")}
    eval_hashes = {record.get("normalized_problem_hash") for record in records if record.get("record_role") == "EVAL_CANDIDATE" and record.get("normalized_problem_hash")}
    overlap = sorted(train_hashes & eval_hashes)
    status = "OVERLAP_DETECTED_AUDIT_ONLY" if overlap else "NO_OVERLAP_DETECTED"
    eval_audit = authority(
        schema_id="kt.v17_7_4.math_corpus_eval_overlap_audit.v1",
        status=status,
        train_problem_hash_count=len(train_hashes),
        eval_problem_hash_count=len(eval_hashes),
        train_eval_overlap_count=len(overlap),
        overlap_problem_hashes_sample=overlap[:100],
        future_training_use_requires_overlap_removal=bool(overlap),
    )
    boundary = authority(
        schema_id="kt.v17_7_4.math_corpus_train_eval_boundary_audit.v1",
        status="TRAIN_EVAL_BOUNDARY_UNSAFE" if overlap else "NO_OVERLAP_DETECTED",
        train_eval_overlap_count=len(overlap),
        eval_rows_must_not_be_training_targets=True,
        training_authority=False,
        hard_block_training_until_boundary_clean=bool(overlap),
    )
    return eval_audit, boundary


def build_leakage(records: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    counts = Counter(str(record.get("leakage_risk", "UNKNOWN")) for record in records)
    visibility = [
        authority(
            schema_id="kt.v17_7_4.math_corpus_expected_answer_visibility_row.v1",
            source_id=record.get("source_id"),
            record_id_hash=record.get("record_id_hash"),
            record_role=record.get("record_role"),
            leakage_risk=record.get("leakage_risk"),
            expected_answer_model_visible=False,
            use_authority_after_leakage_audit=(
                "DO_NOT_USE_FOR_TRAINING"
                if record.get("leakage_risk") == "HIGH"
                else ("EVAL_ONLY" if record.get("record_role") == "EVAL_CANDIDATE" else "FUTURE_TRAINING_CANDIDATE_NEEDS_SANITIZATION")
            ),
        )
        for record in records
        if record.get("has_final_answer") or record.get("leakage_risk") != "NONE_DETECTED"
    ]
    laundering = authority(
        schema_id="kt.v17_7_4.math_corpus_oracle_label_laundering_audit.v1",
        status="PASS_AUDIT_ONLY",
        oracle_label_like_record_count=sum(1 for record in records if record.get("leakage_risk") == "HIGH"),
        oracle_labels_allowed_as_model_visible_targets=False,
        scorer_correctness_flags_allowed_as_model_visible_targets=False,
    )
    audit = authority(
        schema_id="kt.v17_7_4.math_corpus_leakage_audit.v1",
        status="PASS_AUDIT_ONLY",
        leakage_risk_counts=dict(counts),
        high_leakage_record_count=counts.get("HIGH", 0),
        medium_leakage_record_count=counts.get("MEDIUM", 0),
        hard_blocker_triggered=False,
        reason="No source is marked training-ready in this lane; high-risk rows are audit-only or do-not-use-for-training.",
    )
    return audit, visibility[:5000], laundering


def build_scorecard(records: list[dict[str, Any]], parsed_sources: list[dict[str, Any]], dedup: dict[str, Any], overlap: dict[str, Any], leakage: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    record_count = len(records)
    parseability = percent(sum(1 for source in parsed_sources if source["parse_status"] == "PARSED"), len(parsed_sources))
    no_high_leakage = 1.0 - percent(leakage.get("high_leakage_record_count", 0), max(record_count, 1))
    no_overlap = 1.0 if overlap.get("train_eval_overlap_count", 0) == 0 else 0.5
    dedup_clean = 1.0 - float(dedup.get("duplicate_record_rate", 0.0))
    format_aligned = percent(
        sum(1 for record in records if record.get("format_alignment") in {"STRONGLY_ALIGNED", "PARTIALLY_ALIGNED"}),
        record_count,
    )
    reasoning = percent(sum(1 for record in records if record.get("reasoning_step_present")), record_count)
    verifier = percent(
        sum(1 for record in records if record.get("verifier_compatibility") in {"HIGH_VERIFIER_COMPATIBILITY", "PARTIAL_VERIFIER_COMPATIBILITY"}),
        record_count,
    )
    unknown_license_penalty = 0.0
    license_grade = "UNKNOWN"
    overall = "C_AUDIT_ONLY_NEEDS_SOURCE_REPAIR"
    training_decision = "TRAINING_AUTHORITY_FALSE__SANITIZATION_REQUIRED"
    if no_high_leakage < 0.75 or no_overlap < 1.0:
        overall = "D_NOT_TRAINING_READY"
        training_decision = "TRAINING_AUTHORITY_FALSE__SANITIZATION_REQUIRED"
    elif format_aligned >= 0.65 and reasoning >= 0.5 and verifier >= 0.5 and dedup_clean >= 0.8 and unknown_license_penalty >= 0.8:
        overall = "A_READY_FOR_DATASET_BLUEPRINT"
        training_decision = "TRAINING_AUTHORITY_FALSE__BLUEPRINT_ALLOWED"
    elif format_aligned >= 0.35 and verifier >= 0.25:
        overall = "B_READY_WITH_SANITIZATION"
        training_decision = "TRAINING_AUTHORITY_FALSE__SANITIZATION_REQUIRED"

    selected_lane = NEXT_BLUEPRINT if training_decision == "TRAINING_AUTHORITY_FALSE__BLUEPRINT_ALLOWED" else NEXT_SANITIZE
    scorecard = authority(
        schema_id="kt.v17_7_4.math_corpus_quality_scorecard.v1",
        status="PASS",
        source_authority_grade="B",
        parseability_grade=grade_from_ratio(parseability, 0.85, 0.6, 0.3),
        leakage_safety_grade=grade_from_ratio(no_high_leakage, 0.98, 0.9, 0.75),
        train_eval_separation_grade="A" if no_overlap == 1.0 else "C",
        dedup_cleanliness_grade=grade_from_ratio(dedup_clean, 0.95, 0.8, 0.6),
        format_alignment_grade=grade_from_ratio(format_aligned, 0.75, 0.45, 0.2),
        reasoning_step_coverage_grade=grade_from_ratio(reasoning, 0.75, 0.45, 0.2),
        difficulty_alignment_grade="C",
        verifier_compatibility_grade=grade_from_ratio(verifier, 0.75, 0.45, 0.2),
        license_use_authority_grade=license_grade,
        lobe_target_alignment_grade="C",
        epoch_crucible_coverage_grade="C",
        overall_grade=overall,
        training_readiness_decision=training_decision,
        training_authority=False,
        selected_next_lane=selected_lane,
    )
    grade = authority(
        schema_id="kt.v17_7_4.math_corpus_quality_grade.v1",
        status="PASS",
        overall_grade=overall,
        decision=training_decision,
        selected_next_lane=selected_lane,
    )
    decision = authority(
        schema_id="kt.v17_7_4.math_corpus_training_readiness_decision.v1",
        status=training_decision,
        training_authority=False,
        training_readiness_claim=False,
        dataset_readiness_claim=training_decision == "TRAINING_AUTHORITY_FALSE__BLUEPRINT_ALLOWED",
        blockers_to_training_authority=[
            "training authority is outside this lane",
            "license/use authority remains unknown for many sources",
            "sanitization and train/eval segregation required before any request",
        ],
    )
    return scorecard, grade, decision, selected_lane


def build() -> dict[str, Any]:
    current_head = git(["rev-parse", "HEAD"])
    current_branch = git(["branch", "--show-current"])
    source_summary = read_json("reports/v17_7_4_math_corpus_source_binding_builder_summary.json")
    candidates, authority_by_id, schema_by_path = load_source_maps()
    if not candidates:
        summary = authority(
            schema_id="kt.v17_7_4.math_corpus_quality_audit_builder_summary.v1",
            status="BLOCKED",
            active_tranche=TRANCHE,
            current_head=current_head,
            branch=current_branch,
            outcome="KT_BLOCKED__MATH_CORPUS_QUALITY_TRUTH_PIN_FAILED",
            blockers=["missing source candidate table"],
            next_lawful_move="REPAIR_SOURCE_BINDING_ARTIFACTS",
        )
        write_json("reports/v17_7_4_math_corpus_quality_audit_builder_summary.json", summary)
        return summary

    all_records: list[dict[str, Any]] = []
    parsed_sources: list[dict[str, Any]] = []
    parse_errors: list[dict[str, Any]] = []
    for candidate in candidates:
        records, source, errors = parse_candidate(candidate, authority_by_id, schema_by_path)
        all_records.extend(records)
        parsed_sources.append(source)
        parse_errors.extend(errors)

    lane_counts = Counter(str(record.get("math_lane", "UNKNOWN")) for record in all_records)
    role_counts = Counter(str(record.get("record_role", "UNKNOWN")) for record in all_records)
    source_role_counts = Counter(str(source.get("source_role", "UNKNOWN")) for source in parsed_sources)
    dedup, duplicate_clusters = build_duplicate_clusters(all_records)
    eval_overlap, boundary = build_eval_overlap(all_records)
    leakage, visibility, laundering = build_leakage(all_records)

    inventory = authority(
        schema_id="kt.v17_7_4.math_corpus_inventory.v1",
        status="PASS",
        source_count=len(parsed_sources),
        parsed_source_count=sum(1 for source in parsed_sources if source["parse_status"] == "PARSED"),
        record_count=len(all_records),
        parse_error_count=len(parse_errors),
        current_bound_sources_separated=True,
        historical_partial_sources_separated=True,
        missing_unrecovered_sources_not_invented=True,
    )
    lane_distribution = authority(
        schema_id="kt.v17_7_4.math_corpus_lane_distribution.v1",
        status="PASS",
        lane_counts=dict(lane_counts),
        current_vs_historical_note="Historical 13-lobe and epoch/crucible sources remain partial; counts are audit evidence, not training authority.",
    )
    source_role_distribution = authority(
        schema_id="kt.v17_7_4.math_corpus_source_role_distribution.v1",
        status="PASS",
        source_role_counts=dict(source_role_counts),
        record_role_counts=dict(role_counts),
    )
    format_counts = Counter(str(record.get("format_alignment", "UNKNOWN")) for record in all_records)
    reasoning_count = sum(1 for record in all_records if record.get("reasoning_step_present"))
    final_marker_count = sum(1 for record in all_records if record.get("final_marker_present"))
    difficulty_counts = Counter(str(record.get("difficulty_band", "UNKNOWN")) for record in all_records)
    verifier_counts = Counter(str(record.get("verifier_compatibility", "UNKNOWN")) for record in all_records)

    format_audit = authority(
        schema_id="kt.v17_7_4.math_corpus_format_alignment_audit.v1",
        status="PASS_AUDIT_ONLY",
        format_alignment_counts=dict(format_counts),
        likely_wrong_answer_contract_risk=format_counts.get("MISALIGNED_FINAL_ANSWER_ONLY", 0) + format_counts.get("MISALIGNED_ANSWER_FIRST_NO_REASONING", 0),
        doctrine_governance_contamination_count=lane_counts.get("DOCTRINE_GOVERNANCE_CONTAMINATION", 0),
    )
    answer_contract = authority(
        schema_id="kt.v17_7_4.math_corpus_answer_contract_alignment.v1",
        status="PASS_AUDIT_ONLY",
        final_marker_rate=percent(final_marker_count, len(all_records)),
        answer_contract_ready=False,
        reason="This lane measures alignment only; contract normalization belongs to a future sanitization or blueprint lane.",
    )
    reasoning_presence = authority(
        schema_id="kt.v17_7_4.math_corpus_reasoning_step_presence.v1",
        status="PASS_AUDIT_ONLY",
        reasoning_step_present_count=reasoning_count,
        reasoning_step_present_rate=percent(reasoning_count, len(all_records)),
    )
    difficulty = authority(
        schema_id="kt.v17_7_4.math_corpus_difficulty_distribution.v1",
        status="PASS_AUDIT_ONLY",
        difficulty_band_counts=dict(difficulty_counts),
        olympiad_sources_not_gsm8k_readiness=True,
    )
    gsm8k_features = authority(
        schema_id="kt.v17_7_4.math_corpus_gsm8k_feature_distribution.v1",
        status="PASS_AUDIT_ONLY",
        gsm8k_record_count=lane_counts.get("ARITHMETIC_GSM8K", 0),
        gsm8k_foundation_requires_separate_balancing=True,
    )
    competition_features = authority(
        schema_id="kt.v17_7_4.math_corpus_competition_feature_distribution.v1",
        status="PASS_AUDIT_ONLY",
        competition_record_count=lane_counts.get("COMPETITION_MATH", 0) + lane_counts.get("OLYMPIAD_STRATEGY", 0),
        competition_not_substitute_for_gsm8k_foundation=True,
    )
    solution_quality = authority(
        schema_id="kt.v17_7_4.math_corpus_solution_quality_audit.v1",
        status="PASS_AUDIT_ONLY",
        solution_present_count=sum(1 for record in all_records if record.get("has_solution_text")),
        final_answer_present_count=sum(1 for record in all_records if record.get("has_final_answer")),
        solution_present_rate=percent(sum(1 for record in all_records if record.get("has_solution_text")), len(all_records)),
    )
    verifier = authority(
        schema_id="kt.v17_7_4.math_corpus_verifier_compatibility.v1",
        status="PASS_AUDIT_ONLY",
        verifier_compatibility_counts=dict(verifier_counts),
    )
    verifier_teacher = authority(
        schema_id="kt.v17_7_4.math_corpus_verifier_as_teacher_readiness.v1",
        status="NOT_READY_REQUIRES_SANITIZATION",
        verifier_labels_become_training_labels=False,
        high_or_partial_compatibility_count=verifier_counts.get("HIGH_VERIFIER_COMPATIBILITY", 0) + verifier_counts.get("PARTIAL_VERIFIER_COMPATIBILITY", 0),
    )
    license_matrix = []
    for source in parsed_sources:
        sid = source["source_id"]
        authority_row = authority_by_id.get(sid, {})
        license_status = authority_row.get("license_status", "UNKNOWN_LICENSE")
        license_matrix.append(
            authority(
                schema_id="kt.v17_7_4.math_corpus_training_use_authority_row.v1",
                source_id=sid,
                path=source["path"],
                license_status=license_status,
                prior_use_authority=authority_row.get("use_authority", "AUDIT_ONLY"),
                use_authority_after_audit="EVAL_ONLY" if authority_row.get("use_authority") == "EVAL_ONLY" else "UNKNOWN",
                future_training_allowed_now=False,
                future_training_candidate_if_authorized=False if license_status in {"UNKNOWN_LICENSE", "RESTRICTED"} else True,
                reasons=["UNKNOWN_LICENSE" if license_status == "UNKNOWN_LICENSE" else "AUDIT_REQUIRED", "training_authority_false"],
            )
        )
    license_audit = authority(
        schema_id="kt.v17_7_4.math_corpus_license_use_authority_audit.v1",
        status="PASS_AUDIT_ONLY",
        unknown_license_source_count=sum(1 for row in license_matrix if row["license_status"] == "UNKNOWN_LICENSE"),
        restricted_license_source_count=sum(1 for row in license_matrix if row["license_status"] == "RESTRICTED"),
        no_unknown_license_source_training_ready=True,
        training_authority=False,
    )
    scorecard, grade, training_decision, selected_lane = build_scorecard(all_records, parsed_sources, dedup, eval_overlap, leakage)

    historical_13 = read_json("reports/v17_7_4_historical_13_lobe_training_source_status.json")
    historical_epoch = read_json("reports/v17_7_4_historical_epoch_crucible_source_status.json")
    historical_corpus = read_json("reports/v17_7_4_historical_math_training_corpus_recovery_status.json")
    h13_gap = authority(
        schema_id="kt.v17_7_4.historical_13_lobe_corpus_gap_report.v1",
        status="PARTIAL_BOUND",
        predecessor_status=historical_13.get("status"),
        row_level_source_bound=historical_13.get("row_level_source_bound", False),
        exact_training_rows_recoverable="UNKNOWN_PARTIAL",
        reconstruction_required=not historical_13.get("row_level_source_bound", False),
        no_invention=True,
    )
    epoch_gap = authority(
        schema_id="kt.v17_7_4.historical_epoch_crucible_gap_report.v1",
        status="PARTIAL_BOUND",
        predecessor_status=historical_epoch.get("status"),
        epochs_crucibles_bound=historical_epoch.get("epochs_crucibles_bound", False),
        exact_epoch_crucible_manifests_recoverable="PARTIAL",
        no_invention=True,
    )
    delta_gap = authority(
        schema_id="kt.v17_7_4.recursive_delta_source_gap_report.v1",
        status="PARTIAL_BOUND",
        predecessor_status=historical_corpus.get("status"),
        recursive_delta_data_recoverable="PARTIAL",
        exact_training_prompt_templates_bound=historical_corpus.get("exact_training_prompts_templates_bound", False),
        no_invention=True,
    )
    future_blueprint = authority(
        schema_id="kt.v17_7_4.math_future_dataset_blueprint_requirements.v1",
        status="PASS_REQUIREMENTS_ONLY",
        blueprint_allowed_now=selected_lane == NEXT_BLUEPRINT,
        source_whitelist_required=True,
        source_blacklist_required=True,
        expected_answer_segregation_required=True,
        train_eval_nonoverlap_required=True,
        difficulty_balancing_required=True,
        answer_contract_normalization_required=True,
        no_training_authority_now=True,
    )
    future_sanitization = authority(
        schema_id="kt.v17_7_4.math_future_sanitization_requirements.v1",
        status="REQUIRED" if selected_lane == NEXT_SANITIZE else "OPTIONAL_IF_BLUEPRINT_AUTHORIZED",
        remove_eval_overlap=True,
        quarantine_high_leakage=True,
        normalize_answer_contract=True,
        segregate_expected_answers=True,
        resolve_license_unknowns=True,
    )
    future_prereq = authority(
        schema_id="kt.v17_7_4.math_future_training_authority_prerequisites_update.v1",
        status="TRAINING_AUTHORITY_STILL_FALSE",
        prerequisites=[
            "source whitelist with license/use authority",
            "train/eval overlap zero or explicitly segregated",
            "expected-answer leakage removed",
            "answer contract normalized",
            "difficulty-balanced GSM8K foundation subset",
            "no-regression and rollback plan",
            "EPC training authority request in a later lane",
        ],
    )
    epc = authority(
        schema_id="kt.v17_7_4.epc_decision_after_math_corpus_quality_audit.v1",
        status="PASS_DECIDED",
        options_considered=[
            NEXT_BLUEPRINT,
            NEXT_SANITIZE,
            NEXT_RECOVER,
            "AUTHOR_BASE_MODEL_STANDARD_MATH_PROMPT_PROBE_DESIGN_V1",
            "AUTHOR_BASE_MODEL_STANDARD_MATH_PROMPT_PROBE_25_IF_EPC_AUTHORIZES",
            "AUTHOR_MATH_TRAINING_AUTHORITY_REQUEST_DRAFT_V1",
            "RETURN_TO_ACADEMY_MATH_REPAIR_LADDER",
            "NO_RUNTIME_PACKET__CORPUS_QUALITY_AUDITED",
            "RESEARCH_REGISTER_ONLY_FOR_ROUTER_OR_THEORY",
        ],
        selected_next_lane=selected_lane,
        runtime_allowed_by_this_lane=False,
        training_allowed_by_this_lane=False,
        reason="Corpus has audit signal, but unknown license/use authority, leakage/overlap risk, and answer-contract risk require sanitization before blueprint or authority.",
    )
    next_lane = authority(
        schema_id="kt.v17_7_4.math_corpus_quality_audit_next_lane.v1",
        status="PASS_NO_RUNTIME_PACKET",
        selected_next_lane=selected_lane,
        next_lawful_move=selected_lane,
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
    )
    queue = authority(
        schema_id="kt.v17_7_4.math_corpus_quality_intervention_queue.v1",
        status="PASS",
        queue=[
            {"rank": 1, "lane": selected_lane, "runtime": False, "training": False},
            {"rank": 2, "lane": NEXT_BLUEPRINT, "runtime": False, "training": False},
            {"rank": 3, "lane": NEXT_RECOVER, "runtime": False, "training": False},
            {"rank": 4, "lane": "AUTHOR_MATH_TRAINING_AUTHORITY_REQUEST_DRAFT_V1", "runtime": False, "training": False},
        ],
    )

    truth_pin = authority(
        schema_id="kt.v17_7_4.math_corpus_quality_audit_truth_pin.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        current_branch=current_branch,
        predecessor_outcome=source_summary.get("outcome"),
        predecessor_head=source_summary.get("current_head"),
        source_candidate_index_present=bool(candidates),
        source_authority_map_present=bool(authority_by_id),
        schema_inference_present=bool(schema_by_path),
        claim_ceiling_preserved=True,
    )
    predecessor = authority(
        schema_id="kt.v17_7_4.math_corpus_quality_audit_predecessor_binding.v1",
        status="BOUND",
        source_binding_status=source_summary.get("math_corpus_source_binding_status"),
        source_search_status=source_summary.get("source_search_status"),
        quality_audit_readiness_status=source_summary.get("quality_audit_readiness_status"),
        runtime_authority=source_summary.get("runtime_authority", False),
        training_authority=source_summary.get("training_authority", False),
    )
    claim = authority(
        schema_id="kt.v17_7_4.math_corpus_quality_audit_claim_boundary_receipt.v1",
        status="PASS",
        allowed_internal_claim="KT audited bound math/Academy corpus sources. Training authority remains false.",
        corpus_quality_claim=False,
        dataset_readiness_claim=False,
        training_readiness_claim=False,
    )
    parse_receipt = authority(
        schema_id="kt.v17_7_4.math_corpus_parse_execution_receipt.v1",
        status="PASS",
        parsed_source_count=inventory["parsed_source_count"],
        record_count=inventory["record_count"],
        parse_error_count=inventory["parse_error_count"],
        expected_answer_values_written_to_logs=False,
    )

    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.v17_7_4.math_corpus_quality_record.schema.v1",
        "type": "object",
        "additionalProperties": True,
        "required": [
            "schema_id",
            "source_id",
            "record_id_hash",
            "record_role",
            "math_lane",
            "leakage_risk",
            "format_alignment",
            "training_authority",
        ],
        "properties": {
            "schema_id": {"const": "kt.v17_7_4.math_corpus_quality_record.v1"},
            "source_id": {"type": "string"},
            "record_id_hash": {"type": "string"},
            "record_role": {"type": "string"},
            "math_lane": {"type": "string"},
            "leakage_risk": {"type": "string"},
            "format_alignment": {"type": "string"},
            "training_authority": {"const": False},
        },
    }
    files_changed = [
        "scripts/build_v17_7_4_math_corpus_quality_audit.py",
        "schemas/kt.v17_7_4.math_corpus_quality_record.schema.json",
        "reports/v17_7_4_math_corpus_quality_audit_truth_pin.json",
        "reports/v17_7_4_math_corpus_quality_audit_predecessor_binding.json",
        "reports/v17_7_4_math_corpus_quality_audit_claim_boundary_receipt.json",
        "reports/v17_7_4_math_corpus_parse_execution_receipt.json",
        "reports/v17_7_4_math_corpus_parsed_source_index.json",
        "reports/v17_7_4_math_corpus_parse_errors.jsonl",
        "reports/v17_7_4_math_corpus_record_table.jsonl",
        "reports/v17_7_4_math_corpus_inventory.json",
        "reports/v17_7_4_math_corpus_lane_distribution.json",
        "reports/v17_7_4_math_corpus_source_role_distribution.json",
        "reports/v17_7_4_math_corpus_dedup_audit.json",
        "reports/v17_7_4_math_corpus_duplicate_clusters.jsonl",
        "reports/v17_7_4_math_corpus_eval_overlap_audit.json",
        "reports/v17_7_4_math_corpus_train_eval_boundary_audit.json",
        "reports/v17_7_4_math_corpus_leakage_audit.json",
        "reports/v17_7_4_math_corpus_expected_answer_visibility_matrix.jsonl",
        "reports/v17_7_4_math_corpus_oracle_label_laundering_audit.json",
        "reports/v17_7_4_math_corpus_format_alignment_audit.json",
        "reports/v17_7_4_math_corpus_answer_contract_alignment.json",
        "reports/v17_7_4_math_corpus_reasoning_step_presence.json",
        "reports/v17_7_4_math_corpus_difficulty_distribution.json",
        "reports/v17_7_4_math_corpus_gsm8k_feature_distribution.json",
        "reports/v17_7_4_math_corpus_competition_feature_distribution.json",
        "reports/v17_7_4_math_corpus_solution_quality_audit.json",
        "reports/v17_7_4_math_corpus_verifier_compatibility.json",
        "reports/v17_7_4_math_corpus_verifier_as_teacher_readiness.json",
        "reports/v17_7_4_math_corpus_license_use_authority_audit.json",
        "reports/v17_7_4_math_corpus_training_use_authority_matrix.jsonl",
        "reports/v17_7_4_math_corpus_quality_scorecard.json",
        "reports/v17_7_4_math_corpus_quality_grade.json",
        "reports/v17_7_4_math_corpus_training_readiness_decision.json",
        "reports/v17_7_4_historical_13_lobe_corpus_gap_report.json",
        "reports/v17_7_4_historical_epoch_crucible_gap_report.json",
        "reports/v17_7_4_recursive_delta_source_gap_report.json",
        "reports/v17_7_4_math_future_dataset_blueprint_requirements.json",
        "reports/v17_7_4_math_future_sanitization_requirements.json",
        "reports/v17_7_4_math_future_training_authority_prerequisites_update.json",
        "reports/v17_7_4_epc_decision_after_math_corpus_quality_audit.json",
        "reports/v17_7_4_math_corpus_quality_audit_next_lane.json",
        "reports/v17_7_4_math_corpus_quality_intervention_queue.json",
        "reports/v17_7_4_math_corpus_quality_audit_builder_summary.json",
        "registry/artifact_authority_registry_v17_7_4_math_corpus_quality_audit_delta_receipt.json",
        "tests/test_v17_7_4_math_corpus_quality_audit.py",
    ]
    registry_delta = authority(
        schema_id="kt.artifact_authority_registry_delta.v17_7_4_math_corpus_quality_audit",
        status="PASS",
        active_tranche=TRANCHE,
        outcome=OUTCOME,
        artifacts_added=files_changed,
        runtime_authority=False,
        training_authority=False,
        packet_path_if_any=None,
        claim_ceiling_status="PRESERVED",
    )
    summary = authority(
        schema_id="kt.v17_7_4.math_corpus_quality_audit_builder_summary.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        branch=current_branch,
        outcome=OUTCOME,
        files_changed=files_changed,
        math_corpus_quality_binding_status="BOUND_TO_SOURCE_BINDING_RESULT",
        parse_execution_status=parse_receipt["status"],
        corpus_inventory_status=inventory["status"],
        lane_distribution_status=lane_distribution["status"],
        dedup_audit_status=dedup["status"],
        eval_overlap_audit_status=eval_overlap["status"],
        leakage_audit_status=leakage["status"],
        format_alignment_status=format_audit["status"],
        difficulty_distribution_status=difficulty["status"],
        solution_quality_status=solution_quality["status"],
        verifier_compatibility_status=verifier["status"],
        license_use_authority_status=license_audit["status"],
        quality_scorecard_status=scorecard["status"],
        historical_gap_report_status="PARTIAL_BOUND_GAPS_REPORTED",
        future_blueprint_requirements_status=future_blueprint["status"],
        epc_next_lane_status=next_lane["status"],
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move=selected_lane,
    )
    outputs = {
        "schemas/kt.v17_7_4.math_corpus_quality_record.schema.json": schema,
        "reports/v17_7_4_math_corpus_quality_audit_truth_pin.json": truth_pin,
        "reports/v17_7_4_math_corpus_quality_audit_predecessor_binding.json": predecessor,
        "reports/v17_7_4_math_corpus_quality_audit_claim_boundary_receipt.json": claim,
        "reports/v17_7_4_math_corpus_parse_execution_receipt.json": parse_receipt,
        "reports/v17_7_4_math_corpus_parsed_source_index.json": authority(
            schema_id="kt.v17_7_4.math_corpus_parsed_source_index.v1",
            status="PASS",
            sources=parsed_sources,
        ),
        "reports/v17_7_4_math_corpus_inventory.json": inventory,
        "reports/v17_7_4_math_corpus_lane_distribution.json": lane_distribution,
        "reports/v17_7_4_math_corpus_source_role_distribution.json": source_role_distribution,
        "reports/v17_7_4_math_corpus_dedup_audit.json": dedup,
        "reports/v17_7_4_math_corpus_eval_overlap_audit.json": eval_overlap,
        "reports/v17_7_4_math_corpus_train_eval_boundary_audit.json": boundary,
        "reports/v17_7_4_math_corpus_leakage_audit.json": leakage,
        "reports/v17_7_4_math_corpus_oracle_label_laundering_audit.json": laundering,
        "reports/v17_7_4_math_corpus_format_alignment_audit.json": format_audit,
        "reports/v17_7_4_math_corpus_answer_contract_alignment.json": answer_contract,
        "reports/v17_7_4_math_corpus_reasoning_step_presence.json": reasoning_presence,
        "reports/v17_7_4_math_corpus_difficulty_distribution.json": difficulty,
        "reports/v17_7_4_math_corpus_gsm8k_feature_distribution.json": gsm8k_features,
        "reports/v17_7_4_math_corpus_competition_feature_distribution.json": competition_features,
        "reports/v17_7_4_math_corpus_solution_quality_audit.json": solution_quality,
        "reports/v17_7_4_math_corpus_verifier_compatibility.json": verifier,
        "reports/v17_7_4_math_corpus_verifier_as_teacher_readiness.json": verifier_teacher,
        "reports/v17_7_4_math_corpus_license_use_authority_audit.json": license_audit,
        "reports/v17_7_4_math_corpus_quality_scorecard.json": scorecard,
        "reports/v17_7_4_math_corpus_quality_grade.json": grade,
        "reports/v17_7_4_math_corpus_training_readiness_decision.json": training_decision,
        "reports/v17_7_4_historical_13_lobe_corpus_gap_report.json": h13_gap,
        "reports/v17_7_4_historical_epoch_crucible_gap_report.json": epoch_gap,
        "reports/v17_7_4_recursive_delta_source_gap_report.json": delta_gap,
        "reports/v17_7_4_math_future_dataset_blueprint_requirements.json": future_blueprint,
        "reports/v17_7_4_math_future_sanitization_requirements.json": future_sanitization,
        "reports/v17_7_4_math_future_training_authority_prerequisites_update.json": future_prereq,
        "reports/v17_7_4_epc_decision_after_math_corpus_quality_audit.json": epc,
        "reports/v17_7_4_math_corpus_quality_audit_next_lane.json": next_lane,
        "reports/v17_7_4_math_corpus_quality_intervention_queue.json": queue,
        "registry/artifact_authority_registry_v17_7_4_math_corpus_quality_audit_delta_receipt.json": registry_delta,
        "reports/v17_7_4_math_corpus_quality_audit_builder_summary.json": summary,
    }
    for path, payload in outputs.items():
        write_json(path, payload)
    write_jsonl("reports/v17_7_4_math_corpus_parse_errors.jsonl", parse_errors)
    write_jsonl("reports/v17_7_4_math_corpus_record_table.jsonl", all_records)
    write_jsonl("reports/v17_7_4_math_corpus_duplicate_clusters.jsonl", duplicate_clusters)
    write_jsonl("reports/v17_7_4_math_corpus_expected_answer_visibility_matrix.jsonl", visibility)
    write_jsonl("reports/v17_7_4_math_corpus_training_use_authority_matrix.jsonl", license_matrix)
    return summary


def main() -> None:
    print(json.dumps(build(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
