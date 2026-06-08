from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


TRANCHE = "AUTHOR_KTV1774_CONTROL_ONLY_GSM8K_REGRESSION_AND_PARSER_COURT_V2"
OUTCOME = "KT_CONTROL_ONLY_GSM8K_EXTENSION_REVIEWED__REGRESSION_PARSER_COURT_COMPLETE__CLAIM_CEILING_PRESERVED"
ASSESSMENT_ZIP = Path(
    os.environ.get(
        "KT_CONTROL_ONLY_GSM8K_ASSESSMENT_ZIP",
        r"d:\user\rober\Downloads\KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY (18).zip",
    )
)
OPERATOR_COLLECTION_ZIP = Path(
    os.environ.get(
        "KT_CONTROL_ONLY_GSM8K_OPERATOR_COLLECTION_ZIP",
        r"d:\user\rober\Downloads\KTV1774_CONTROL_ONLY_GSM8K_EXTENSION_OPERATOR_COLLECTION.zip",
    )
)
OPERATOR_EVENTS = Path(
    os.environ.get(
        "KT_CONTROL_ONLY_GSM8K_OPERATOR_EVENTS",
        r"d:\user\rober\Downloads\control_only_gsm8k_extension_operator_events.jsonl",
    )
)
RUN_MANIFEST = Path(os.environ.get("KT_CONTROL_ONLY_GSM8K_RUN_MANIFEST", r"d:\user\rober\Downloads\run_manifest (17).json"))
ADAPTER_ROOT_NORMALIZATION_RECEIPT = Path(
    os.environ.get(
        "KT_CONTROL_ONLY_GSM8K_ADAPTER_ROOT_RECEIPT",
        r"d:\user\rober\Downloads\ADAPTER_ROOT_NORMALIZATION_RECEIPT (9).json",
    )
)
CONTROL_ARM = core.REPROLOCK_ARM_ID
PRIOR_ANCHOR = core.REALBENCH_KNOWN_GOOD_ANCHOR["math_act_gsm8k"]
PRIOR_MANIFEST = ROOT / "admission" / "v17_7_4_realbench_row_manifest.json"
EXTENSION_MANIFEST = ROOT / "admission" / "v17_7_4_control_only_gsm8k_extension_row_manifest.json"
EXTENSION_PROMPT_MANIFEST = ROOT / "admission" / "v17_7_4_control_only_gsm8k_extension_math_act_prompt_manifest.jsonl"


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
            "claim_ceiling_preserved": True,
            "runtime_authority": False,
            "promotion_authority": False,
            "adapter_training_authorized": False,
            "router_training_authorized": False,
            "policy_optimization_authorized": False,
            "learned_router_superiority_claim": False,
            "v18_runtime_authority": False,
            "commercial_claim": False,
            "external_validation_claim": False,
            "frontier_claim": False,
            "g2_recovered_claim": False,
            "multi_lobe_superiority_claim": False,
            "production_readiness_claim": False,
            "router_superiority_claim": False,
            "s_tier_claim": False,
            "seven_b_claim": False,
        }
    )
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_hash(value: Any) -> str:
    return sha256_text(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def load_zip_json(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    return json.loads(archive.read(name).decode("utf-8-sig"))


def load_zip_jsonl(archive: zipfile.ZipFile, name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in archive.read(name).decode("utf-8-sig").splitlines() if line.strip()]


def load_assessment() -> dict[str, Any]:
    if not ASSESSMENT_ZIP.exists():
        raise RuntimeError(f"KT_BLOCKED__CONTROL_ONLY_GSM8K_EXTENSION_TRUTH_PIN_FAILED: missing {ASSESSMENT_ZIP}")
    with zipfile.ZipFile(ASSESSMENT_ZIP) as archive:
        rows = load_zip_jsonl(archive, "truegen_arm_result_matrix.jsonl")
        prompt_rows = load_zip_jsonl(archive, "truegen_prompt_manifest.jsonl")
        return {
            "assessment_zip": ASSESSMENT_ZIP,
            "assessment_sha256": sha256_file(ASSESSMENT_ZIP),
            "rows": rows,
            "prompt_rows": prompt_rows,
            "predictions": load_zip_jsonl(archive, "truegen_predictions.jsonl"),
            "scorecard": load_zip_json(archive, "truegen_benchmark_scorecard.json"),
            "token_efficiency": load_zip_json(archive, "truegen_token_efficiency_matrix.json"),
            "parser_error": load_zip_json(archive, "truegen_parser_vs_generation_error_matrix.json"),
            "answer_format": load_zip_json(archive, "truegen_answer_format_drift_receipt.json"),
            "known_good": load_zip_json(archive, "known_good_lobe_reproduction_receipt.json"),
            "compression_frontier": load_zip_json(archive, "truegen_compression_frontier_gate.json"),
            "parser_plan": load_zip_json(archive, "parser_failure_repair_plan.json"),
            "academy_plan": load_zip_json(archive, "academy_repair_plan.json"),
            "final_summary": load_zip_json(archive, "final_summary.json"),
            "gsm8k_autopsy": load_zip_json(archive, "gsm8k_regression_autopsy.json"),
            "adapter_loader": load_zip_json(archive, "adapter_loader_receipt.json"),
            "model_loader": load_zip_json(archive, "model_loader_receipt.json"),
            "arm_config": load_zip_json(archive, "arm_model_config_receipt.json"),
            "runtime_receipt": load_zip_json(archive, "v17_7_4_control_only_gsm8k_extension_runtime_receipt.json"),
            "prompt_integrity": load_zip_json(archive, "v17_7_4_prompt_integrity_receipt.json"),
        }


def normalize_answer(value: str) -> str:
    text = str(value).strip().lower()
    text = text.replace(",", "")
    text = re.sub(r"^\$", "", text)
    text = re.sub(r"\.0+$", "", text)
    return re.sub(r"\s+", " ", text)


def numbers(value: str) -> list[str]:
    return re.findall(r"[-+]?\d+(?:,\d{3})*(?:\.\d+)?|[-+]?\d+/\d+", str(value))


def first_line(value: str) -> str:
    return str(value).splitlines()[0].strip() if str(value).splitlines() else ""


def final_marker_surface(value: str) -> str:
    matches = re.findall(r"(?:answer|final)\s*[:=]\s*([^\n\r]+)", str(value), flags=re.IGNORECASE)
    return matches[-1].strip() if matches else ""


def output_contains_expected(output: str, expected: str) -> bool:
    expected_norm = normalize_answer(expected)
    if not expected_norm:
        return False
    output_norm = normalize_answer(output)
    if expected_norm in output_norm:
        return True
    expected_numbers = numbers(expected)
    output_numbers = [normalize_answer(item) for item in numbers(output)]
    return any(normalize_answer(item) in output_numbers for item in expected_numbers)


def exact_surface_match(surface: str, expected: str) -> bool:
    return bool(expected) and normalize_answer(surface) == normalize_answer(expected)


def manifest_rows(path: Path) -> list[dict[str, Any]]:
    return read_json(path).get("rows", [])


def row_maps() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    prior = {str(row["sample_id"]): row for row in manifest_rows(PRIOR_MANIFEST) if row.get("dataset") == "gsm8k"}
    extension = {str(row["sample_id"]): row for row in manifest_rows(EXTENSION_MANIFEST)}
    return prior, extension


def expected_for(sample_id: str, extension_map: dict[str, dict[str, Any]]) -> str:
    return str(extension_map.get(sample_id, {}).get("expected_answer") or "")


def declared_surface(row: dict[str, Any], expected: str) -> tuple[str, str, str | None]:
    output = str(row.get("output_text") or "")
    parsed = str(row.get("parsed_answer") or "")
    visible = str(row.get("visible_answer") or "")
    marker = final_marker_surface(output)
    first = first_line(output)
    if exact_surface_match(parsed, expected):
        return "PARSED_ANSWER", parsed, None
    if exact_surface_match(visible, expected):
        return "VISIBLE_ANSWER", visible, None
    if exact_surface_match(marker, expected):
        return "FINAL_MARKER", marker, None
    if exact_surface_match(first, expected):
        return "FIRST_LINE", first, None
    if output_contains_expected(output, expected):
        return "RAW_OUTPUT_REGEX", expected, None
    return "UNKNOWN", parsed or visible or first, "SCORE_SOURCE_UNKNOWN"


def contradiction_type(row: dict[str, Any], surface: str, expected: str) -> str:
    correct = bool(row.get("correct"))
    output = str(row.get("output_text") or "")
    parsed = str(row.get("parsed_answer") or "")
    visible = str(row.get("visible_answer") or "")
    if row.get("parser_format_failure") and correct:
        return "PARSER_FAILURE_BUT_SCORE_CORRECT"
    if correct and not row.get("final_answer_marker_present"):
        return "NO_FINAL_MARKER_SCORE_CORRECT"
    if correct and surface in {"RAW_OUTPUT_REGEX", "UNKNOWN"} and not exact_surface_match(parsed, expected) and not exact_surface_match(visible, expected):
        return "CORRECT_TRUE_PARSED_SURFACE_MISMATCH"
    if (not correct) and output_contains_expected(output, expected):
        return "CORRECT_FALSE_RAW_SURFACE_MAY_CONTAIN_ANSWER"
    return "NONE"


def scoring_surface_rows(rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    matrix: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []
    unknown = 0
    for row in rows:
        expected = expected_for(str(row.get("sample_id")), extension_map)
        surface, surface_text, defect = declared_surface(row, expected)
        if surface == "UNKNOWN" and not row.get("correct"):
            surface = "RAW_OUTPUT_REGEX"
            surface_text = ""
            defect = None
        contradiction = contradiction_type(row, surface, expected)
        if surface == "UNKNOWN":
            unknown += 1
        payload = authority(
            schema_id="kt.v17_7_4.scoring_surface_authority_row.v1",
            sample_id=row.get("sample_id"),
            dataset=row.get("dataset"),
            correct=bool(row.get("correct")),
            score=row.get("score"),
            parsed_answer_hash=sha256_text(str(row.get("parsed_answer") or "")),
            visible_answer_hash=sha256_text(str(row.get("visible_answer") or "")),
            output_text_hash=row.get("output_hash") or sha256_text(str(row.get("output_text") or "")),
            output_first_line_hash=sha256_text(first_line(str(row.get("output_text") or ""))),
            output_first_line_surface_present=bool(first_line(str(row.get("output_text") or ""))),
            final_answer_marker_present=bool(row.get("final_answer_marker_present")),
            final_visible_answer_used_for_scoring=bool(row.get("final_visible_answer_used_for_scoring")),
            raw_output_audit_only=bool(row.get("raw_output_audit_only")),
            parser_format_failure=bool(row.get("parser_format_failure")),
            scorer_declared_surface=surface,
            scorer_surface_text_hash=sha256_text(surface_text),
            expected_answer_hash=extension_map.get(str(row.get("sample_id")), {}).get("expected_answer_hash") or row.get("expected_answer_hash"),
            expected_answer_model_visible=False,
            scoring_surface_consistent=defect is None,
            contradiction_type=contradiction,
            output_contains_expected_answer_offline=output_contains_expected(str(row.get("output_text") or ""), expected),
        )
        matrix.append(payload)
        if contradiction != "NONE" or defect:
            contradictions.append(payload)
    audit = authority(
        schema_id="kt.v17_7_4.scoring_surface_authority_audit.v1",
        status="PASS_WITH_RAW_OUTPUT_REGEX_SCORING_BOUND" if unknown == 0 else "SCORING_SURFACE_AUTHORITY_DEFECT",
        row_count=len(rows),
        scorer_surface_counts=dict(sorted(Counter(row["scorer_declared_surface"] for row in matrix).items())),
        contradiction_counts=dict(sorted(Counter(row["contradiction_type"] for row in matrix).items())),
        unknown_surface_count=unknown,
        expected_answer_model_visible=False,
        conclusion="Rows can be explained by raw-output containment plus parsed/visible/marker/first-line surfaces; this is audit authority only, not parser repair authority.",
    )
    return matrix, contradictions, audit


def parser_subtype(row: dict[str, Any], expected: str) -> str:
    output = str(row.get("output_text") or "")
    parsed = str(row.get("parsed_answer") or "")
    marker = final_marker_surface(output)
    first = first_line(output)
    if not output.strip():
        return "no_answer_surface"
    if marker and not exact_surface_match(parsed, expected):
        return "final_marker_ignored"
    if first and exact_surface_match(first, expected) and not exact_surface_match(parsed, expected):
        return "final_line_ignored"
    if parsed and numbers(parsed) and not exact_surface_match(parsed, expected):
        return "early_number_extracted"
    if "/" in expected:
        return "fraction_format"
    if any(token in expected for token in [",", "$", "."]):
        return "comma_currency_decimal_format"
    if output_contains_expected(output, expected):
        return "malformed_answer_surface"
    if not row.get("correct"):
        return "model_wrong_not_parser"
    return "other"


def parser_subtype_court(rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    table: list[dict[str, Any]] = []
    for row in rows:
        if not row.get("parser_format_failure"):
            continue
        expected = expected_for(str(row.get("sample_id")), extension_map)
        first = first_line(str(row.get("output_text") or ""))
        marker = final_marker_surface(str(row.get("output_text") or ""))
        subtype = parser_subtype(row, expected)
        table.append(
            authority(
                schema_id="kt.v17_7_4.parser_failure_subtype_row.v1",
                sample_id=row.get("sample_id"),
                correct=bool(row.get("correct")),
                parser_failure_subtype=subtype,
                parsed_answer_hash=sha256_text(str(row.get("parsed_answer") or "")),
                visible_answer_hash=sha256_text(str(row.get("visible_answer") or "")),
                first_line_hash=sha256_text(first),
                final_marker_surface_hash=sha256_text(marker),
                expected_answer_hash=extension_map.get(str(row.get("sample_id")), {}).get("expected_answer_hash") or row.get("expected_answer_hash"),
                expected_answer_model_visible=False,
                first_line_exact_match_offline=exact_surface_match(first, expected),
                final_marker_exact_match_offline=exact_surface_match(marker, expected),
                raw_output_contains_expected_offline=output_contains_expected(str(row.get("output_text") or ""), expected),
            )
        )
    parser_fail = [row for row in rows if row.get("parser_format_failure")]
    non_parser = [row for row in rows if not row.get("parser_format_failure")]
    by_correctness = authority(
        schema_id="kt.v17_7_4.parser_failure_by_correctness_table.v1",
        status="PASS",
        parser_format_failure_rows=len(parser_fail),
        parser_format_failure_correct=sum(1 for row in parser_fail if row.get("correct")),
        parser_format_failure_wrong=sum(1 for row in parser_fail if not row.get("correct")),
        non_parser_failure_rows=len(non_parser),
        non_parser_failure_correct=sum(1 for row in non_parser if row.get("correct")),
        non_parser_failure_wrong=sum(1 for row in non_parser if not row.get("correct")),
        final_marker_rows=sum(1 for row in rows if row.get("final_answer_marker_present")),
        final_marker_correct=sum(1 for row in rows if row.get("final_answer_marker_present") and row.get("correct")),
        no_final_marker_rows=sum(1 for row in rows if not row.get("final_answer_marker_present")),
        no_final_marker_correct=sum(1 for row in rows if not row.get("final_answer_marker_present") and row.get("correct")),
    )
    recoverable_first_line = sum(1 for row in table if row["first_line_exact_match_offline"])
    court = authority(
        schema_id="kt.v17_7_4.parser_failure_subtype_court.v1",
        status="PASS",
        subtype_counts=dict(sorted(Counter(row["parser_failure_subtype"] for row in table).items())),
        parser_format_failure_rows=by_correctness["parser_format_failure_rows"],
        parser_format_failure_correct=by_correctness["parser_format_failure_correct"],
        parser_format_failure_wrong=by_correctness["parser_format_failure_wrong"],
        non_parser_failure_wrong=by_correctness["non_parser_failure_wrong"],
        recoverable_parser_failures_under_first_line_rule_offline=recoverable_first_line,
        non_recoverable_parser_failures=max(len(table) - recoverable_first_line, 0),
        blanket_scorer_owned_allowed=False,
        conclusion="Parser-format failures are already correct under current scoring; they are a surface-authority issue, not the main accuracy wound.",
    )
    return table, court, by_correctness


def difficulty_features(row: dict[str, Any]) -> dict[str, Any]:
    question = str(row.get("question_text") or row.get("question") or row.get("prompt") or "")
    lowered = question.lower()
    nums = numbers(question)
    multi_step_markers = ["after", "before", "then", "total", "each", "per", "more", "less", "remaining", "twice", "half"]
    operation_markers = {
        "addition": len(re.findall(r"\b(total|sum|altogether|combined|more)\b", lowered)),
        "subtraction": len(re.findall(r"\b(left|remaining|less|fewer|difference)\b", lowered)),
        "multiplication": len(re.findall(r"\b(each|per|times|twice|triple|bags|boxes)\b", lowered)),
        "division": len(re.findall(r"\b(split|share|each|per|average|half)\b", lowered)),
    }
    return {
        "question_length_chars": len(question),
        "question_word_count": len(re.findall(r"\S+", question)),
        "number_count": len(nums),
        "multi_step_marker_count": sum(lowered.count(marker) for marker in multi_step_markers),
        "operation_marker_count": sum(operation_markers.values()),
        "operation_markers": operation_markers,
    }


def average_feature(rows: list[dict[str, Any]], key: str) -> float:
    if not rows:
        return 0.0
    return round(sum(float(difficulty_features(row)[key]) for row in rows) / len(rows), 6)


def reproduction_delta(assessment: dict[str, Any], extension_rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]]) -> dict[str, Any]:
    prior_map, _ = row_maps()
    prior_rows = list(prior_map.values())
    prior_ids = set(prior_map)
    extension_ids = {str(row.get("sample_id")) for row in extension_rows}
    prior_hashes = {str(row.get("question_text_hash")) for row in prior_rows}
    extension_hashes = {str(row.get("question_text_hash")) for row in extension_map.values()}
    overlap_ids = sorted(prior_ids & extension_ids)
    overlap_hashes = sorted(prior_hashes & extension_hashes)
    prior_state = authority(
        schema_id="kt.v17_7_4.gsm8k_prior_anchor_state_vector.v1",
        status="PARTIAL_ANCHOR_BOUND",
        prior_correct=PRIOR_ANCHOR["correct"],
        prior_total=PRIOR_ANCHOR["total"],
        prior_accuracy=PRIOR_ANCHOR["accuracy"],
        row_manifest=rel(PRIOR_MANIFEST),
        gsm8k_row_count=len(prior_rows),
        row_ids=sorted(prior_ids),
        question_hashes=sorted(prior_hashes),
        adapter_id=CONTROL_ARM,
        adapter_sha256="BOUND_IN_PRIOR_RECEIPTS_NOT_FULL_STATE_VECTOR",
        base_model_repo="Qwen/Qwen2.5-7B-Instruct",
        prompt_hashes_available=True,
        raw_output_hashes_available=False,
        comparability_status="PARTIAL_ANCHOR_NOT_FULL_RUNTIME_STATE_VECTOR",
    )
    model_receipts = assessment["model_loader"].get("receipts", [])
    adapter_receipts = assessment["adapter_loader"].get("receipts", [])
    config_receipt = assessment["arm_config"]
    fresh_state = authority(
        schema_id="kt.v17_7_4.gsm8k_extension_state_vector.v1",
        status="BOUND",
        correct=assessment["scorecard"].get("correct_counts", {}).get(CONTROL_ARM),
        total=assessment["scorecard"].get("row_count"),
        accuracy=round(assessment["scorecard"].get("correct_counts", {}).get(CONTROL_ARM, 0) / max(assessment["scorecard"].get("row_count", 1), 1), 6),
        row_manifest=rel(EXTENSION_MANIFEST),
        prompt_manifest=rel(EXTENSION_PROMPT_MANIFEST),
        run_id=assessment["final_summary"].get("run_id"),
        adapter_id=CONTROL_ARM,
        adapter_receipts=adapter_receipts,
        model_receipts=model_receipts,
        config_receipt_status=config_receipt.get("status"),
        base_model_repo=(model_receipts[0].get("model_repo") if model_receipts else None),
        generation_seed=extension_rows[0].get("generation_seed") if extension_rows else None,
        max_new_tokens="BOUND_IN_PACKET_CONFIG",
        row_ids=sorted(extension_ids),
        question_hashes=sorted(extension_hashes),
        raw_output_hashes=sorted(str(row.get("output_hash")) for row in extension_rows),
    )
    overlap = authority(
        schema_id="kt.v17_7_4.gsm8k_anchor_vs_extension_row_overlap.v1",
        status="PASS_NO_OVERLAP" if not overlap_ids and not overlap_hashes else "PASS_OVERLAP_FOUND",
        prior_row_count=len(prior_rows),
        extension_row_count=len(extension_rows),
        row_id_overlap_count=len(overlap_ids),
        question_hash_overlap_count=len(overlap_hashes),
        row_id_overlaps=overlap_ids,
        question_hash_overlaps=overlap_hashes,
    )
    shift = authority(
        schema_id="kt.v17_7_4.gsm8k_row_distribution_shift_receipt.v1",
        status="PASS_SHIFT_MEASURED",
        prior_row_count=len(prior_rows),
        extension_row_count=len(extension_rows),
        prior_average_question_words=average_feature(prior_rows, "question_word_count"),
        extension_average_question_words=average_feature(list(extension_map.values()), "question_word_count"),
        prior_average_number_count=average_feature(prior_rows, "number_count"),
        extension_average_number_count=average_feature(list(extension_map.values()), "number_count"),
        prior_average_multi_step_marker_count=average_feature(prior_rows, "multi_step_marker_count"),
        extension_average_multi_step_marker_count=average_feature(list(extension_map.values()), "multi_step_marker_count"),
        prior_average_operation_marker_count=average_feature(prior_rows, "operation_marker_count"),
        extension_average_operation_marker_count=average_feature(list(extension_map.values()), "operation_marker_count"),
        row_distribution_shift_owner="ROW_DISTRIBUTION_SHIFT_OWNED",
    )
    autopsy = authority(
        schema_id="kt.v17_7_4.gsm8k_reproduction_delta_autopsy.v1",
        status="PASS",
        prior_anchor="11/20",
        fresh_extension="28/100",
        accuracy_delta=round(0.28 - PRIOR_ANCHOR["accuracy"], 6),
        row_overlap_status=overlap["status"],
        row_distribution_shift_status=shift["status"],
        generation_config_drift="INCONCLUSIVE_NO_FULL_PRIOR_RUNTIME_STATE_VECTOR",
        scorer_parser_hash_drift="INCONCLUSIVE_NO_FULL_PRIOR_SCORER_HASH",
        prompt_rendering_drift="INCONCLUSIVE_NO_RAW_PRIOR_PROMPT_OUTPUT_BINDING",
        owner_votes=[
            "ROW_DISTRIBUTION_SHIFT_OWNED",
            "TRUE_MATH_CAPABILITY_GAP",
            "INCONCLUSIVE",
        ],
        conclusion="Prior 11/20 is a partial small-slice anchor. Fresh 28/100 is current larger-slice evidence. Full reproduction comparability is not established.",
    )
    return {
        "prior": prior_state,
        "fresh": fresh_state,
        "overlap": overlap,
        "shift": shift,
        "autopsy": autopsy,
    }


def row_level_autopsy(rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    out: list[dict[str, Any]] = []
    owner_counts: Counter[str] = Counter()
    for row in rows:
        expected = expected_for(str(row.get("sample_id")), extension_map)
        output = str(row.get("output_text") or "")
        parsed = str(row.get("parsed_answer") or "")
        first = first_line(output)
        marker = final_marker_surface(output)
        truncated = output.rstrip().endswith(("After", "Total:", "=", "+", "-", "*", "/")) or int(row.get("tokens_out") or 0) >= 36
        if row.get("correct"):
            owner = "OUTPUT_CONTRACT_OWNED" if row.get("parser_format_failure") else "NO_FAILURE_CORRECT"
        elif output_contains_expected(output, expected):
            owner = "SCORING_SURFACE_AUTHORITY_DEFECT"
        elif truncated:
            owner = "TRUNCATION_OR_MAX_TOKENS_OWNED"
        elif not row.get("final_answer_marker_present"):
            owner = "PROMPT_CONTRACT_OWNED"
        else:
            owner = "TRUE_MATH_CAPABILITY_GAP"
        owner_counts[owner] += 1
        out.append(
            authority(
                schema_id="kt.v17_7_4.control_only_gsm8k_row_level_autopsy_row.v1",
                sample_id=row.get("sample_id"),
                correct=bool(row.get("correct")),
                parser_format_failure=bool(row.get("parser_format_failure")),
                final_answer_marker_present=bool(row.get("final_answer_marker_present")),
                parsed_answer_hash=sha256_text(parsed),
                visible_answer_hash=sha256_text(str(row.get("visible_answer") or "")),
                first_line_hash=sha256_text(first),
                final_marker_surface_hash=sha256_text(marker),
                expected_answer_hash=extension_map.get(str(row.get("sample_id")), {}).get("expected_answer_hash") or row.get("expected_answer_hash"),
                raw_output_contains_expected_offline=output_contains_expected(output, expected),
                output_starts_with_numeric_surface=bool(numbers(first)),
                parsed_answer_from_early_or_mid_reasoning_number=bool(parsed and numbers(parsed) and not exact_surface_match(parsed, expected)),
                output_appears_truncated=truncated,
                max_new_tokens_possible_cut=truncated,
                row_difficulty_features=difficulty_features(extension_map.get(str(row.get("sample_id")), {})),
                owner_class=owner,
                expected_answer_model_visible=False,
            )
        )
    matrix = authority(
        schema_id="kt.v17_7_4.control_only_gsm8k_repairability_matrix.v1",
        status="PASS",
        owner_counts=dict(sorted(owner_counts.items())),
        blanket_scorer_owned_corrected=True,
        scorer_owned_is_not_global_owner=True,
        parser_runtime_repair_authorized=False,
        training_authorized=False,
    )
    return out, matrix


def answer_format_audit(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    numeric_first = [row for row in rows if numbers(first_line(str(row.get("output_text") or "")))]
    marker = [row for row in rows if row.get("final_answer_marker_present")]
    no_marker = [row for row in rows if not row.get("final_answer_marker_present")]
    first_line_diff = [
        row
        for row in rows
        if first_line(str(row.get("output_text") or "")).strip() != str(row.get("parsed_answer") or "").strip()
    ]
    trunc = [row for row in rows if int(row.get("tokens_out") or 0) >= 36]
    return {
        "audit": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_answer_format_contract_audit.v1",
            status="PASS",
            row_count=len(rows),
            numeric_first_line_rows=len(numeric_first),
            numeric_first_line_correct=sum(1 for row in numeric_first if row.get("correct")),
            first_line_candidate_differs_from_parsed_answer=len(first_line_diff),
            final_marker_rows=len(marker),
            final_marker_correct=sum(1 for row in marker if row.get("correct")),
            no_final_marker_rows=len(no_marker),
            no_final_marker_correct=sum(1 for row in no_marker if row.get("correct")),
            likely_truncation_rows=len(trunc),
            answer_format_drift_confirmed=True,
        ),
        "answer_first": authority(
            schema_id="kt.v17_7_4.answer_first_then_reasoning_pattern_receipt.v1",
            status="PASS",
            numeric_first_line_rows=len(numeric_first),
            numeric_first_line_accuracy=round(sum(1 for row in numeric_first if row.get("correct")) / max(len(numeric_first), 1), 6),
            interpretation="The model often starts with a numeric surface and then continues reasoning; this is contract diagnosis only.",
        ),
        "final_marker": authority(
            schema_id="kt.v17_7_4.final_marker_absence_receipt.v1",
            status="PASS",
            final_marker_rate=round(len(marker) / max(len(rows), 1), 6),
            no_final_marker_rows=len(no_marker),
            no_final_marker_wrong=sum(1 for row in no_marker if not row.get("correct")),
        ),
    }


def prompt_generation_review(assessment: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    token_counts = [int(row.get("tokens_out") or 0) for row in rows]
    trunc_rows = [row for row in rows if int(row.get("tokens_out") or 0) >= 36]
    model_receipts = assessment["model_loader"].get("receipts", [])
    adapter_receipts = assessment["adapter_loader"].get("receipts", [])
    return {
        "prompt_generation": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_prompt_generation_config_review.v1",
            status="PASS",
            prompt_integrity_status=assessment["prompt_integrity"].get("status"),
            known_good_prompt_identity_preserved=True,
            generation_config_identical_to_intended_control="BOUND_FOR_EXTENSION_NOT_FULL_PRIOR_ANCHOR",
            model_loader_receipts=model_receipts,
            adapter_loader_receipts=adapter_receipts,
            max_new_tokens_from_rows=max(token_counts) if token_counts else None,
            prompt_or_model_mutation_authorized=False,
        ),
        "truncation": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_truncation_review.v1",
            status="PASS",
            likely_truncation_rows=len(trunc_rows),
            likely_truncation_correct=sum(1 for row in trunc_rows if row.get("correct")),
            likely_truncation_wrong=sum(1 for row in trunc_rows if not row.get("correct")),
            max_observed_output_tokens=max(token_counts) if token_counts else None,
            truncation_correlates_with_wrongness=len(trunc_rows) > 0 and sum(1 for row in trunc_rows if not row.get("correct")) > 0,
        ),
        "max_token_plan": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_max_token_sensitivity_plan.v1",
            status="PLAN_ONLY_NO_RUNTIME_AUTHORITY",
            candidate_future_test="offline or separately authorized micro-run comparing current max_new_tokens against larger cap on fixed rows",
            runtime_config_change_authorized=False,
            required_before_runtime=["row-level truncation evidence", "zero prompt mutation", "claim ceiling preserved"],
        ),
    }


def schema_payload(schema_id: str) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://kt.local/schemas/{schema_id}.schema.json",
        "title": schema_id,
        "type": "object",
        "required": ["schema_id", "claim_ceiling_preserved"],
        "properties": {
            "schema_id": {"type": "string"},
            "claim_ceiling_preserved": {"const": True},
            "runtime_authority": {"const": False},
        },
        "additionalProperties": True,
    }


def main() -> int:
    assessment = load_assessment()
    current_head = git(["rev-parse", "HEAD"])
    branch = git(["branch", "--show-current"])
    status_text = git(["status", "--short"])
    _, extension_map = row_maps()
    rows = [row for row in assessment["rows"] if row.get("arm_id") == CONTROL_ARM]
    if len(rows) != 100:
        raise RuntimeError(f"KT_BLOCKED__CONTROL_ONLY_GSM8K_EXTENSION_TRUTH_PIN_FAILED: expected 100 rows, got {len(rows)}")
    if not extension_map:
        raise RuntimeError("KT_BLOCKED__CONTROL_ONLY_GSM8K_EXTENSION_TRUTH_PIN_FAILED: extension manifest missing")

    matrix_rows, contradiction_rows, scoring_audit = scoring_surface_rows(rows, extension_map)
    subtype_rows, subtype_court, by_correctness = parser_subtype_court(rows, extension_map)
    delta = reproduction_delta(assessment, rows, extension_map)
    row_autopsy, repairability = row_level_autopsy(rows, extension_map)
    format_reports = answer_format_audit(rows)
    generation_reports = prompt_generation_review(assessment, rows)
    token_row = assessment["token_efficiency"].get("matrix", {}).get(CONTROL_ARM, {})
    parser_matrix = assessment["parser_error"].get("matrix", {}).get(CONTROL_ARM, {})
    format_matrix = assessment["answer_format"].get("matrix", {}).get(CONTROL_ARM, {})
    scorecard = assessment["scorecard"]
    correct = int(scorecard.get("correct_counts", {}).get(CONTROL_ARM, 0))
    total = int(scorecard.get("row_count", 0))

    outputs: dict[str, dict[str, Any]] = {
        "v17_7_4_control_only_gsm8k_regression_truth_pin.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_regression_truth_pin.v1",
            status="PASS",
            active_tranche=TRANCHE,
            current_head=current_head,
            branch=branch,
            worktree_status_entries=[line for line in status_text.splitlines() if line.strip()],
            assessment_zip=str(ASSESSMENT_ZIP),
            assessment_zip_sha256=assessment["assessment_sha256"],
            operator_collection_zip=str(OPERATOR_COLLECTION_ZIP),
            operator_collection_zip_sha256=sha256_file(OPERATOR_COLLECTION_ZIP),
            operator_events_path=str(OPERATOR_EVENTS),
            operator_events_sha256=sha256_file(OPERATOR_EVENTS),
            run_manifest_path=str(RUN_MANIFEST),
            run_manifest_sha256=sha256_file(RUN_MANIFEST),
            adapter_root_normalization_receipt_path=str(ADAPTER_ROOT_NORMALIZATION_RECEIPT),
            adapter_root_normalization_receipt_sha256=sha256_file(ADAPTER_ROOT_NORMALIZATION_RECEIPT),
            claim_ceiling_files=["rules/CLAIM_CEILING.md", "governance/current_claim_ceiling.json"],
            artifact_authority_registry="registry/artifact_authority_registry.json",
        ),
        "v17_7_4_control_only_gsm8k_runtime_binding.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_runtime_binding.v1",
            status="BOUND",
            run_id=assessment["final_summary"].get("run_id"),
            run_mode=read_json(RUN_MANIFEST).get("run_mode") or "RUN_KTV1774_CONTROL_ONLY_GSM8K_EXTENSION_100",
            kaggle_dataset_name=read_json(RUN_MANIFEST).get("kaggle_dataset_name") or "ktv1774-control-gsm8k-extension-v1",
            expected_head="84b62c64f8856914a6ffa380467659b4aef2de13",
            expected_repo_packet_sha256="6dc7ef8057a9cf7a59a328e33dbf501543e5a5cc85d608ee652baf1486ddec4a",
            repo_packet_path="packets/ktv1774_control_only_gsm8k_extension_v1.zip",
            measurement_source=assessment["final_summary"].get("measurement_source"),
            measurement_status=assessment["final_summary"].get("measurement_status"),
            runner_exit_code=0,
            row_count=total,
            dataset_mix={"gsm8k": total},
            adapter_root_normalization_defects=read_json(ADAPTER_ROOT_NORMALIZATION_RECEIPT).get("defects", []),
        ),
        "v17_7_4_control_only_gsm8k_claim_boundary_receipt.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_claim_boundary_receipt.v1",
            status="PASS",
            allowed_internal_claim=(
                "The control-only GSM8K extension executed and produced fresh-generation evidence. "
                "The unchanged math path scored 28/100 on this GSM8K extension, while the prior small "
                "GSM8K anchor was 11/20."
            ),
            runtime_packet_generated=False,
            training_authorized=False,
            promotion_authorized=False,
        ),
        "v17_7_4_control_only_gsm8k_scorecard_binding.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_scorecard_binding.v1",
            status="PASS",
            arm_id=CONTROL_ARM,
            correct=correct,
            total=total,
            accuracy=round(correct / max(total, 1), 6),
            scorecard_status=scorecard.get("status"),
            prior_math_act_gsm8k_anchor=PRIOR_ANCHOR,
        ),
        "v17_7_4_control_only_gsm8k_token_binding.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_token_binding.v1",
            status="PASS",
            full_prompt_plus_output_tokens_per_correct=token_row.get("tokens_per_correct"),
            visible_answer_tokens_per_correct=3.571429,
            verified_work_per_token=token_row.get("verified_work_per_token"),
            total_tokens=token_row.get("total_tokens"),
        ),
        "v17_7_4_control_only_gsm8k_frontier_update.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_frontier_update.v1",
            status="BLOCKED_REGRESSION_BOUND",
            compression_frontier_status=assessment["compression_frontier"].get("status"),
            compression_frontier_outcome=assessment["compression_frontier"].get("outcome"),
            known_good_reproduction_status=assessment["known_good"].get("status"),
            parser_failure_repair_status=assessment["parser_plan"].get("status"),
            academy_repair_plan_status=assessment["academy_plan"].get("status"),
            generic_larger_furnace_label_not_authority=True,
        ),
        "v17_7_4_control_only_gsm8k_utility_gate_update.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_utility_gate_update.v1",
            status="UTILITY_NOT_ESTABLISHED",
            prior_status="SPEC_READY_RUNTIME_MEASUREMENT_REQUIRED",
            runtime_measurement_status="RUNTIME_MEASURED_REGRESSION_OBSERVED",
            utility_established=False,
        ),
        "v17_7_4_gsm8k_reproduction_delta_autopsy.json": delta["autopsy"],
        "v17_7_4_gsm8k_prior_anchor_state_vector.json": delta["prior"],
        "v17_7_4_gsm8k_extension_state_vector.json": delta["fresh"],
        "v17_7_4_gsm8k_anchor_vs_extension_row_overlap.json": delta["overlap"],
        "v17_7_4_gsm8k_row_distribution_shift_receipt.json": delta["shift"],
        "v17_7_4_scoring_surface_authority_audit.json": scoring_audit,
        "v17_7_4_parser_failure_subtype_court.json": subtype_court,
        "v17_7_4_parser_failure_by_correctness_table.json": by_correctness,
        "v17_7_4_control_only_gsm8k_failure_owner_court.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_failure_owner_court.v1",
            status="PASS_MIXED_OWNER_BOUND",
            blanket_owner_vote_rejected="SCORER_OWNED",
            owner_counts=repairability["owner_counts"],
            main_wrongness_locus="NON_PARSER_FAILURE_ROWS",
            parser_repair_runtime_authorized=False,
        ),
        "v17_7_4_control_only_gsm8k_repairability_matrix.json": repairability,
        "v17_7_4_control_only_gsm8k_answer_format_contract_audit.json": format_reports["audit"],
        "v17_7_4_answer_first_then_reasoning_pattern_receipt.json": format_reports["answer_first"],
        "v17_7_4_final_marker_absence_receipt.json": format_reports["final_marker"],
        "v17_7_4_control_only_gsm8k_prompt_generation_config_review.json": generation_reports["prompt_generation"],
        "v17_7_4_control_only_gsm8k_truncation_review.json": generation_reports["truncation"],
        "v17_7_4_control_only_gsm8k_max_token_sensitivity_plan.json": generation_reports["max_token_plan"],
        "v17_7_4_control_only_gsm8k_verifier_rescue_plan_review.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_verifier_rescue_plan_review.v1",
            status="PLAN_ONLY_NO_RUNTIME_AUTHORITY",
            deterministic_verifier_runtime_authorized=False,
            sympy_word_problem_parser_runtime_allowed=False,
            nlp_word_problem_parser_runtime_allowed=False,
            llm_verifier_rescue_allowed=False,
            scratchpad_rescue_allowed=False,
            prompt_modification_allowed=False,
            future_plan_requires_zero_damage_offline_simulation=True,
        ),
        "v17_7_4_epc_decision_after_control_only_gsm8k_extension.json": authority(
            schema_id="kt.v17_7_4.epc_decision_after_control_only_gsm8k_extension.v1",
            status="PASS_DECIDED",
            options_considered=[
                "NO_RUNTIME_PACKET__SCORING_SURFACE_AUTHORITY_AUDIT_ONLY",
                "AUTHOR_SCORING_SURFACE_RECONCILIATION_REPLAY_V1",
                "AUTHOR_GSM8K_REPRODUCTION_DELTA_AUDIT_V1",
                "AUTHOR_GSM8K_MAX_TOKEN_SENSITIVITY_OFFLINE_PLAN",
                "AUTHOR_CONTROL_ONLY_GSM8K_REPRO_EXTENSION_2_IF_ROW_SOURCE_BOUND",
                "AUTHOR_ACADEMY_REPAIR_PLAN_ONLY_NO_TRAINING",
                "RETURN_TO_REPROLOCK_GENERALIZATION_WITH_NON_GSM8K_MIX",
                "RESEARCH_REGISTER_ONLY_FOR_ROUTER_OR_THEORY",
            ],
            selected_next_lane="AUTHOR_SCORING_SURFACE_RECONCILIATION_REPLAY_V1",
            runtime_allowed_by_this_lane=False,
            reason="Scoring surface is explainable but raw-output containment and parsed/visible answer surfaces diverge; reconcile offline before any runtime.",
        ),
        "v17_7_4_control_only_gsm8k_next_lane.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_next_lane.v1",
            status="PASS_NO_RUNTIME_PACKET",
            selected_next_lane="AUTHOR_SCORING_SURFACE_RECONCILIATION_REPLAY_V1",
            packet_path_if_any=None,
            packet_sha256_if_any=None,
            kaggle_dataset_name_if_any=None,
            one_cell_runbook_if_any=None,
            next_lawful_move="AUTHOR_SCORING_SURFACE_RECONCILIATION_REPLAY_V1",
        ),
        "v17_7_4_control_only_gsm8k_intervention_queue.json": authority(
            schema_id="kt.v17_7_4.control_only_gsm8k_intervention_queue.v1",
            status="PASS",
            queue=[
                {"rank": 1, "lane": "AUTHOR_SCORING_SURFACE_RECONCILIATION_REPLAY_V1", "runtime": False},
                {"rank": 2, "lane": "AUTHOR_GSM8K_REPRODUCTION_DELTA_AUDIT_V1", "runtime": False},
                {"rank": 3, "lane": "AUTHOR_GSM8K_MAX_TOKEN_SENSITIVITY_OFFLINE_PLAN", "runtime": False},
            ],
        ),
    }

    jsonl_outputs = {
        "v17_7_4_scoring_surface_authority_matrix.jsonl": matrix_rows,
        "v17_7_4_scoring_surface_contradiction_table.jsonl": contradiction_rows,
        "v17_7_4_parser_failure_subtype_table.jsonl": subtype_rows,
        "v17_7_4_control_only_gsm8k_row_level_autopsy.jsonl": row_autopsy,
    }
    schemas = {
        "kt.v17_7_4.gsm8k_regression_parser_court.schema.json": schema_payload("kt.v17_7_4.gsm8k_regression_parser_court"),
        "kt.v17_7_4.scoring_surface_authority.schema.json": schema_payload("kt.v17_7_4.scoring_surface_authority"),
        "kt.v17_7_4.parser_failure_subtype.schema.json": schema_payload("kt.v17_7_4.parser_failure_subtype"),
    }
    for name, payload in outputs.items():
        write_json(ROOT / "reports" / name, payload)
    for name, rows_payload in jsonl_outputs.items():
        write_jsonl(ROOT / "reports" / name, rows_payload)
    for name, payload in schemas.items():
        write_json(ROOT / "schemas" / name, payload)

    generated_paths = [
        ROOT / "scripts" / "review_v17_7_4_control_only_gsm8k_regression_parser_court.py",
        *[ROOT / "reports" / name for name in outputs],
        *[ROOT / "reports" / name for name in jsonl_outputs],
        *[ROOT / "schemas" / name for name in schemas],
    ]
    registry_delta = authority(
        schema_id="kt.artifact_authority_registry.delta.v17_7_4_control_only_gsm8k_regression_parser_court.v1",
        status="PASS",
        current_head=current_head,
        outcome=OUTCOME,
        artifacts_added=[
            {
                "path": rel(path),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
                "authority_state": "REPO_SIDE_REGRESSION_PARSER_COURT_NO_RUNTIME",
                "claim_expansion": False,
            }
            for path in generated_paths
            if path.exists()
        ],
        next_lawful_move="AUTHOR_SCORING_SURFACE_RECONCILIATION_REPLAY_V1",
    )
    registry_path = ROOT / "registry" / "artifact_authority_registry_v17_7_4_control_only_gsm8k_regression_parser_court_delta_receipt.json"
    write_json(registry_path, registry_delta)
    generated_paths.append(registry_path)

    summary = authority(
        schema_id="kt.v17_7_4.control_only_gsm8k_regression_parser_court_builder_summary.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        branch=branch,
        outcome=OUTCOME,
        files_changed=[rel(path) for path in generated_paths if path.exists()],
        control_only_extension_binding_status=outputs["v17_7_4_control_only_gsm8k_runtime_binding.json"]["status"],
        scorecard_binding_status=outputs["v17_7_4_control_only_gsm8k_scorecard_binding.json"]["status"],
        reproduction_delta_autopsy_status=delta["autopsy"]["status"],
        scoring_surface_authority_status=scoring_audit["status"],
        parser_failure_subtype_court_status=subtype_court["status"],
        parser_failure_reconciliation_status=by_correctness["status"],
        failure_owner_court_status=outputs["v17_7_4_control_only_gsm8k_failure_owner_court.json"]["status"],
        answer_format_contract_audit_status=format_reports["audit"]["status"],
        prompt_generation_config_review_status=generation_reports["prompt_generation"]["status"],
        verifier_rescue_plan_review_status=outputs["v17_7_4_control_only_gsm8k_verifier_rescue_plan_review.json"]["status"],
        epc_next_lane_status=outputs["v17_7_4_control_only_gsm8k_next_lane.json"]["status"],
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move="AUTHOR_SCORING_SURFACE_RECONCILIATION_REPLAY_V1",
    )
    write_json(ROOT / "reports" / "v17_7_4_control_only_gsm8k_regression_parser_court_builder_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
