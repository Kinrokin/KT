from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core
from scripts import replay_v17_7_4_official_scorer_on_gsm8k_extension as scoring_replay
from scripts import review_v17_7_4_control_only_gsm8k_regression_parser_court as parser_court


TRANCHE = "AUTHOR_KTV1774_GSM8K_CAPABILITY_GAP_AUTOPSY_V1"
OUTCOME = "KT_GSM8K_CAPABILITY_GAP_AUTOPSIED__NEXT_REPAIR_OR_DATA_LANE_DECIDED__CLAIM_CEILING_PRESERVED"
CONTROL_ARM = core.REPROLOCK_ARM_ID
NEXT_LAWFUL_MOVE = "AUTHOR_KTV1774_GSM8K_MAXTOKEN_SENSITIVITY_DESIGN_V1"


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
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str | None:
    return parser_court.sha256_file(path)


def read_json(path: Path) -> dict[str, Any]:
    return parser_court.read_json(path)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return parser_court.read_jsonl(path)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    parser_court.write_json(path, payload)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    parser_court.write_jsonl(path, rows)


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def normalize_answer(value: str) -> str:
    return parser_court.normalize_answer(value)


def numbers(value: str) -> list[str]:
    return parser_court.numbers(value)


def output_contains_expected(output: str, expected: str) -> bool:
    return parser_court.output_contains_expected(output, expected)


def first_line(value: str) -> str:
    return parser_court.first_line(value)


def final_marker_surface(value: str) -> str:
    return parser_court.final_marker_surface(value)


def expected_for(sample_id: str, extension_map: dict[str, dict[str, Any]]) -> str:
    return parser_court.expected_for(sample_id, extension_map)


def row_maps() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    return parser_court.row_maps()


def control_rows(assessment: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in assessment["rows"] if row.get("arm_id") == CONTROL_ARM]


def question_text(row: dict[str, Any]) -> str:
    return str(row.get("question_text") or row.get("question") or row.get("prompt") or "")


def operation_cues(text: str) -> dict[str, int]:
    lowered = text.lower()
    return {
        "addition": len(re.findall(r"\b(total|sum|altogether|combined|more|plus|add)\b", lowered)),
        "subtraction": len(re.findall(r"\b(left|remaining|remain|less|fewer|minus|difference|take away)\b", lowered)),
        "multiplication": len(re.findall(r"\b(each|every|per|times|twice|double|triple|product)\b", lowered)),
        "division": len(re.findall(r"\b(split|share|each|per|average|half|divide|quotient)\b", lowered)),
        "ratio_rate": len(re.findall(r"\b(rate|ratio|per|for every|each)\b", lowered)),
        "percent": len(re.findall(r"%|\bpercent\b", lowered)),
        "average": len(re.findall(r"\baverage|mean\b", lowered)),
        "remainder": len(re.findall(r"\bremainder|left over|remaining\b", lowered)),
        "comparison_difference": len(re.findall(r"\bmore than|less than|difference|compare|fewer\b", lowered)),
        "multistep_temporal_update": len(re.findall(r"\bbefore|after|then|next|first|second|finally\b", lowered)),
    }


def difficulty_features(row: dict[str, Any]) -> dict[str, Any]:
    text = question_text(row)
    lowered = text.lower()
    nums = numbers(text)
    magnitudes: list[float] = []
    for item in nums:
        try:
            magnitudes.append(abs(float(item.replace(",", "").split("/")[0])))
        except ValueError:
            pass
    lexical_trap_cues = {
        "each_every_per": len(re.findall(r"\b(each|every|per)\b", lowered)),
        "more_less_left_remain": len(re.findall(r"\b(more|less|left|remain|remaining)\b", lowered)),
        "total_combined": len(re.findall(r"\b(total|combined|altogether)\b", lowered)),
        "twice_half_double": len(re.findall(r"\b(twice|half|double)\b", lowered)),
        "before_after_then": len(re.findall(r"\b(before|after|then)\b", lowered)),
    }
    return {
        "question_char_len": len(text),
        "question_token_proxy_len": len(re.findall(r"\S+", text)),
        "number_count": len(nums),
        "distinct_number_count": len({item.replace(",", "") for item in nums}),
        "largest_number_magnitude": max(magnitudes) if magnitudes else 0,
        "decimal_or_fraction_present": bool(re.search(r"\d+\.\d+|\d+/\d+", text)),
        "money_marker_present": "$" in text or any(word in lowered for word in ["dollar", "cents", "paid", "cost", "price"]),
        "percent_marker_present": "%" in text or "percent" in lowered,
        "unit_marker_count": len(re.findall(r"\b(day|days|hour|hours|minute|minutes|liter|liters|mile|miles|pound|pounds|kg|feet|foot|inch|inches)\b", lowered)),
        "operation_cue_counts": operation_cues(text),
        "entity_count_proxy": len(re.findall(r"\b[A-Z][a-z]+\b", text)),
        "sentence_count": max(len(re.findall(r"[.!?]", text)), 1 if text.strip() else 0),
        "conjunction_count": len(re.findall(r"\b(and|or|but|then|after|before|while)\b", lowered)),
        "conditional_cue_count": len(re.findall(r"\b(if|unless|when|until)\b", lowered)),
        "lexical_trap_cue_count": lexical_trap_cues,
    }


def suspected_truncation(row: dict[str, Any]) -> tuple[bool, list[str]]:
    output = str(row.get("output_text") or "").rstrip()
    lowered = output.lower()
    tokens_out = int(row.get("tokens_out") or 0)
    observed_budget = int(row.get("max_new_tokens") or 50)
    reasons: list[str] = []
    if tokens_out >= observed_budget:
        reasons.append("HIT_OBSERVED_MAX_OUTPUT_TOKENS")
    if lowered.endswith(("after", "before", "then", "total:", "=", "+", "-", "*", "/", "\\times", "(")):
        reasons.append("OUTPUT_ENDS_MID_EXPRESSION_OR_CLAUSE")
    if output.count("(") > output.count(")"):
        reasons.append("UNBALANCED_OPEN_PARENTHESIS")
    if not re.search(r"[.!?)]$", output) and tokens_out >= 32:
        reasons.append("LONG_OUTPUT_NO_SENTENCE_CLOSURE")
    return bool(reasons), reasons


def length_bucket(tokens_out: int) -> str:
    if tokens_out < 24:
        return "lt_24"
    if tokens_out < 32:
        return "24_31"
    if tokens_out < 40:
        return "32_39"
    return "ge_40"


def rate(rows: list[dict[str, Any]], predicate) -> float:
    if not rows:
        return 0.0
    return round(sum(1 for row in rows if predicate(row)) / len(rows), 6)


def summarize_group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "row_count": len(rows),
        "correct_count": sum(1 for row in rows if row.get("correct")),
        "wrong_count": sum(1 for row in rows if not row.get("correct")),
        "correct_rate": rate(rows, lambda row: row.get("correct")),
        "wrong_rate": rate(rows, lambda row: not row.get("correct")),
        "parser_format_failure_count": sum(1 for row in rows if row.get("parser_format_failure")),
        "final_marker_present_count": sum(1 for row in rows if row.get("final_answer_marker_present")),
        "average_tokens_out": round(sum(float(row.get("tokens_out") or 0) for row in rows) / max(len(rows), 1), 6),
        "average_tokens_in": round(sum(float(row.get("tokens_in") or 0) for row in rows) / max(len(rows), 1), 6),
    }


def topology_for_wrong(row: dict[str, Any], manifest_row: dict[str, Any], expected: str) -> tuple[str, str]:
    output = str(row.get("output_text") or "")
    parsed = str(row.get("parsed_answer") or "")
    nums = numbers(output)
    trunc, _ = suspected_truncation(row)
    cues = operation_cues(question_text(manifest_row))
    if output_contains_expected(output, expected):
        return "SCORING_SURFACE_AMBIGUITY", "SCORER_REPORTING_ONLY"
    if trunc:
        return "TRUNCATION_OR_BUDGET_ERROR", "MAX_TOKEN_SENSITIVITY_PLAN_ONLY"
    if len(set(normalize_answer(num) for num in nums)) >= 4:
        return "MULTISTEP_STATE_TRACKING_ERROR", "ACADEMY_REPAIR_CANDIDATE_NO_TRAINING_AUTHORITY"
    if cues["division"] or cues["ratio_rate"] or cues["average"] or cues["percent"]:
        return "UNIT_OR_QUANTITY_TRACKING_ERROR", "ACADEMY_REPAIR_CANDIDATE_NO_TRAINING_AUTHORITY"
    if parsed and numbers(parsed):
        return "ARITHMETIC_COMPUTATION_ERROR", "DETERMINISTIC_CALCULATOR_RESCUE_POSSIBLE_OFFLINE_ONLY"
    return "UNKNOWN", "INCONCLUSIVE"


def build_difficulty_tables(rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]], prior_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    table: list[dict[str, Any]] = []
    for row in rows:
        sample_id = str(row["sample_id"])
        manifest_row = extension_map[sample_id]
        trunc, reasons = suspected_truncation(row)
        feats = difficulty_features(manifest_row)
        table.append(
            authority(
                schema_id="kt.v17_7_4.gsm8k_row_difficulty_row.v1",
                sample_id=sample_id,
                dataset=row.get("dataset"),
                question_hash=manifest_row.get("question_text_hash") or row.get("question_text_hash"),
                expected_answer_hash=manifest_row.get("expected_answer_hash") or row.get("expected_answer_hash"),
                expected_answer_model_visible=False,
                official_correct=bool(row.get("correct")),
                parser_format_failure=bool(row.get("parser_format_failure")),
                scoring_surface_source="RAW_OUTPUT_REGEX",
                output_truncated_proxy=trunc,
                output_truncation_reasons=reasons,
                answer_format_drift=not bool(row.get("final_answer_marker_present")),
                answer_type_class_hash=sha256_text(str(manifest_row.get("answer_type") or "")),
                **feats,
            )
        )
    correct_rows = [row for row in rows if row.get("correct")]
    wrong_rows = [row for row in rows if not row.get("correct")]
    parser_correct = [row for row in rows if row.get("parser_format_failure") and row.get("correct")]
    non_parser_wrong = [row for row in rows if (not row.get("parser_format_failure")) and (not row.get("correct"))]
    prior_rows = list(prior_map.values())
    topology = authority(
        schema_id="kt.v17_7_4.gsm8k_row_difficulty_topology.v1",
        status="PASS",
        deterministic_features_only=True,
        extension_all=summarize_group(rows),
        extension_correct=summarize_group(correct_rows),
        extension_wrong=summarize_group(wrong_rows),
        extension_parser_format_failure_correct=summarize_group(parser_correct),
        extension_non_parser_failure_wrong=summarize_group(non_parser_wrong),
        prior_anchor_proxy={
            "row_count": len(prior_rows),
            "average_question_token_proxy_len": round(sum(difficulty_features(row)["question_token_proxy_len"] for row in prior_rows) / max(len(prior_rows), 1), 6),
            "average_number_count": round(sum(difficulty_features(row)["number_count"] for row in prior_rows) / max(len(prior_rows), 1), 6),
        },
    )
    distribution = authority(
        schema_id="kt.v17_7_4.gsm8k_anchor_vs_extension_distribution_shift.v1",
        status="PASS_SHIFT_MEASURED",
        prior_anchor_row_count=len(prior_rows),
        extension_row_count=len(rows),
        row_distribution_shift_owner="ROW_DISTRIBUTION_SHIFT_OWNED",
        prior_question_hash_count=len({str(row.get("question_text_hash")) for row in prior_rows}),
        extension_question_hash_count=len({str(row.get("question_text_hash")) for row in extension_map.values()}),
        overlap_question_hash_count=len(
            {str(row.get("question_text_hash")) for row in prior_rows}
            & {str(row.get("question_text_hash")) for row in extension_map.values()}
        ),
    )
    return table, topology, distribution


def build_state_vector_delta(assessment: dict[str, Any], rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]], prior_map: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    scoring_summary = read_json(ROOT / "reports" / "v17_7_4_scoring_surface_reconciliation_replay_builder_summary.json")
    score_lock = read_json(ROOT / "reports" / "v17_7_4_control_only_gsm8k_reconciled_scorecard.json")
    prior_ids = set(prior_map)
    extension_ids = {str(row["sample_id"]) for row in rows}
    prior_hashes = {str(row.get("question_text_hash")) for row in prior_map.values()}
    extension_hashes = {str(row.get("question_text_hash")) for row in extension_map.values()}
    adapter_receipts = assessment["adapter_loader"].get("receipts", [])
    model_receipts = assessment["model_loader"].get("receipts", [])
    prior = authority(
        schema_id="kt.v17_7_4.gsm8k_capability_prior_anchor_state_vector.v1",
        status="PARTIAL_ANCHOR_BOUND",
        prior_score="11/20",
        prior_accuracy=0.55,
        row_ids=sorted(prior_ids),
        question_hashes=sorted(prior_hashes),
        raw_output_hashes_available=False,
        prompt_hashes_available=True,
        full_runtime_state_vector_available=False,
        comparability_status="PARTIAL_ANCHOR_NOT_FULL_RUNTIME_STATE_VECTOR",
    )
    extension = authority(
        schema_id="kt.v17_7_4.gsm8k_capability_extension_state_vector.v1",
        status="BOUND",
        official_score=score_lock.get("official_score", "28/100"),
        official_accuracy=0.28,
        row_ids=sorted(extension_ids),
        question_hashes=sorted(extension_hashes),
        prompt_hashes=sorted(str(row.get("prompt_hash")) for row in rows),
        raw_output_hashes=sorted(str(row.get("output_hash")) for row in rows),
        adapter_id=CONTROL_ARM,
        adapter_receipts=adapter_receipts,
        model_receipts=model_receipts,
        base_model_repo=(model_receipts[0].get("model_repo") if model_receipts else "Qwen/Qwen2.5-7B-Instruct"),
        generation_seed=rows[0].get("generation_seed") if rows else None,
        max_new_tokens_observed=max(int(row.get("tokens_out") or 0) for row in rows),
        official_scoring_surface_policy=score_lock.get("official_surface_policy"),
        scoring_reconciliation_head=scoring_summary.get("current_head"),
    )
    overlap = authority(
        schema_id="kt.v17_7_4.gsm8k_capability_overlap_replay_receipt.v1",
        status="PASS_NO_OVERLAP" if not (prior_ids & extension_ids) and not (prior_hashes & extension_hashes) else "PASS_OVERLAP_FOUND",
        row_id_overlap_count=len(prior_ids & extension_ids),
        question_hash_overlap_count=len(prior_hashes & extension_hashes),
        row_id_overlaps=sorted(prior_ids & extension_ids),
        question_hash_overlaps=sorted(prior_hashes & extension_hashes),
    )
    delta = authority(
        schema_id="kt.v17_7_4.gsm8k_capability_anchor_vs_extension_delta.v1",
        status="PASS",
        prior_score="11/20",
        extension_official_score="28/100",
        accuracy_delta=round(0.28 - 0.55, 6),
        owner_votes=["ROW_DISTRIBUTION_SHIFT_OWNED", "TRUE_MATH_CAPABILITY_GAP", "INCONCLUSIVE"],
        conclusion="The prior 11/20 anchor is not directly comparable to the reconciled 100-row extension because full prior runtime state vector and raw outputs are not bound.",
    )
    return {"prior": prior, "extension": extension, "overlap": overlap, "delta": delta}


def build_wrong_topology(rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    table: list[dict[str, Any]] = []
    for row in rows:
        if row.get("correct"):
            continue
        sample_id = str(row["sample_id"])
        manifest_row = extension_map[sample_id]
        expected = expected_for(sample_id, extension_map)
        trunc, reasons = suspected_truncation(row)
        topology, repairability = topology_for_wrong(row, manifest_row, expected)
        output = str(row.get("output_text") or "")
        row_payload = authority(
            schema_id="kt.v17_7_4.gsm8k_wrong_row_autopsy_row.v1",
            sample_id=sample_id,
            question_hash=manifest_row.get("question_text_hash") or row.get("question_text_hash"),
            expected_answer_hash=manifest_row.get("expected_answer_hash") or row.get("expected_answer_hash"),
            expected_answer_model_visible=False,
            raw_output_hash=row.get("output_hash"),
            official_scoring_surface="RAW_OUTPUT_REGEX",
            parsed_answer_hash=sha256_text(str(row.get("parsed_answer") or "")),
            visible_answer_hash=sha256_text(str(row.get("visible_answer") or "")),
            final_marker_present=bool(row.get("final_answer_marker_present")),
            first_line_surface_present=bool(first_line(output)),
            output_starts_with_numeric_surface=bool(numbers(first_line(output))),
            output_contains_multiple_candidate_numbers=len({normalize_answer(num) for num in numbers(output)}) > 1,
            output_truncation_proxy=trunc,
            output_truncation_reasons=reasons,
            max_new_tokens_observed=max(int(r.get("tokens_out") or 0) for r in rows),
            reasoning_length_proxy=int(row.get("reasoning_tokens") or 0),
            answer_format_drift=not bool(row.get("final_answer_marker_present")),
            row_difficulty_features=difficulty_features(manifest_row),
            failure_topology=topology,
            repairability=repairability,
        )
        table.append(row_payload)
    topology_counts = Counter(row["failure_topology"] for row in table)
    repair_counts = Counter(row["repairability"] for row in table)
    summary = authority(
        schema_id="kt.v17_7_4.gsm8k_wrong_row_failure_topology.v1",
        status="PASS",
        wrong_row_count=len(table),
        failure_topology_counts=dict(sorted(topology_counts.items())),
        repairability_counts=dict(sorted(repair_counts.items())),
        expected_answers_hash_only=True,
        runtime_rescue_authorized=False,
    )
    counts = authority(
        schema_id="kt.v17_7_4.gsm8k_failure_topology_counts.v1",
        status="PASS",
        failure_topology_counts=dict(sorted(topology_counts.items())),
        repairability_counts=dict(sorted(repair_counts.items())),
    )
    return table, summary, counts


def build_correct_protection(rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    alt_rows = read_jsonl(ROOT / "reports" / "v17_7_4_alternative_surface_replay_matrix.jsonl")
    alt_by_sample: dict[str, list[dict[str, Any]]] = {}
    for alt in alt_rows:
        alt_by_sample.setdefault(str(alt.get("sample_id")), []).append(alt)
    table: list[dict[str, Any]] = []
    for row in rows:
        if not row.get("correct"):
            continue
        sample_id = str(row["sample_id"])
        expected = expected_for(sample_id, extension_map)
        damages = [
            alt["policy"]
            for alt in alt_by_sample.get(sample_id, [])
            if alt.get("official_correct") and not alt.get("policy_correct")
        ]
        law = "SCORING_SURFACE_STABLE"
        if row.get("parser_format_failure"):
            law = "PARSER_REPORTING_DEFECT_BUT_SCORE_OK"
        if not row.get("final_answer_marker_present"):
            law = "ANSWER_FORMAT_DRIFT_BUT_CORRECT"
        if output_contains_expected(str(row.get("output_text") or ""), expected):
            law = "DO_NOT_TOUCH_RAW_REGEX_SUCCESS"
        if damages:
            law = "FORMAT_REPAIR_RISK_HIGH"
        table.append(
            authority(
                schema_id="kt.v17_7_4.gsm8k_correct_row_autopsy_row.v1",
                sample_id=sample_id,
                expected_answer_hash=extension_map[sample_id].get("expected_answer_hash") or row.get("expected_answer_hash"),
                expected_answer_model_visible=False,
                scoring_surface_succeeded="RAW_OUTPUT_REGEX",
                parser_format_failure=bool(row.get("parser_format_failure")),
                final_marker_absent=not bool(row.get("final_answer_marker_present")),
                raw_regex_scoring_rescued=output_contains_expected(str(row.get("output_text") or ""), expected),
                answer_first_pattern=bool(numbers(first_line(str(row.get("output_text") or "")))),
                damaging_common_fixes=sorted(damages),
                protection_law=law,
            )
        )
    summary = authority(
        schema_id="kt.v17_7_4.gsm8k_correct_row_protection_topology.v1",
        status="PASS",
        correct_row_count=len(table),
        protection_law_counts=dict(sorted(Counter(row["protection_law"] for row in table).items())),
        rows_at_risk_from_common_surface_fixes=sum(1 for row in table if row["damaging_common_fixes"]),
        damage_must_be_zero_for_future_promotion_style_claim=True,
    )
    return table, summary


def build_answer_format(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    table: list[dict[str, Any]] = []
    for row in rows:
        output = str(row.get("output_text") or "")
        table.append(
            authority(
                schema_id="kt.v17_7_4.gsm8k_answer_first_pattern_row.v1",
                sample_id=row.get("sample_id"),
                official_correct=bool(row.get("correct")),
                first_line_hash=sha256_text(first_line(output)),
                first_line_has_numeric_surface=bool(numbers(first_line(output))),
                final_marker_present=bool(row.get("final_answer_marker_present")),
                parser_format_failure=bool(row.get("parser_format_failure")),
                answer_format_drift=not bool(row.get("final_answer_marker_present")),
            )
        )
    marker_rows = [row for row in rows if row.get("final_answer_marker_present")]
    no_marker_rows = [row for row in rows if not row.get("final_answer_marker_present")]
    synthesis = authority(
        schema_id="kt.v17_7_4.gsm8k_answer_format_drift_synthesis.v1",
        status="PASS",
        row_count=len(rows),
        answer_format_drift_rate=round(len(no_marker_rows) / max(len(rows), 1), 6),
        final_marker_rate=round(len(marker_rows) / max(len(rows), 1), 6),
        final_marker_correct=sum(1 for row in marker_rows if row.get("correct")),
        no_final_marker_correct=sum(1 for row in no_marker_rows if row.get("correct")),
        raw_output_regex_scoring_reliance=True,
        interpretation="Format drift is a reporting and protection-risk signal; it is not runtime repair authority because narrower surfaces damage official-correct rows.",
    )
    gap = authority(
        schema_id="kt.v17_7_4.gsm8k_final_marker_contract_gap.v1",
        status="PASS",
        final_marker_rows=len(marker_rows),
        no_final_marker_rows=len(no_marker_rows),
        contract_gap_confirmed=True,
        runtime_format_change_authorized=False,
    )
    return synthesis, table, gap


def build_max_token_plan(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    trunc_rows = []
    non_trunc = []
    for row in rows:
        trunc, _ = suspected_truncation(row)
        (trunc_rows if trunc else non_trunc).append(row)
    trunc_wrong_rate = rate(trunc_rows, lambda row: not row.get("correct"))
    non_trunc_wrong_rate = rate(non_trunc, lambda row: not row.get("correct"))
    delta = round(trunc_wrong_rate - non_trunc_wrong_rate, 6)
    candidate_status = "PLAN_ONLY_CANDIDATE_WEAK"
    if len(trunc_rows) >= 10 and delta >= 0.2:
        candidate_status = "PLAN_ONLY_CANDIDATE_STRONG"
    elif len(trunc_rows) >= 10 and delta > 0:
        candidate_status = "PLAN_ONLY_CANDIDATE_WEAK"
    plan = authority(
        schema_id="kt.v17_7_4.gsm8k_max_token_sensitivity_offline_plan.v1",
        status=candidate_status,
        truncation_proxy_rows=len(trunc_rows),
        truncation_proxy_wrong_rate=trunc_wrong_rate,
        non_truncation_wrong_rate=non_trunc_wrong_rate,
        wrong_rate_delta=delta,
        future_microfurnace_allowed_by_this_lane=False,
        candidate_future_lane="AUTHOR_KTV1774_GSM8K_MAXTOKEN_SENSITIVITY_DESIGN_V1",
        conclusion="Truncation/budget remains plausible enough for design-only analysis, but this autopsy does not authorize runtime.",
    )
    generation = authority(
        schema_id="kt.v17_7_4.gsm8k_generation_config_sensitivity_plan.v1",
        status="PLAN_ONLY",
        prompt_change_allowed=False,
        adapter_change_allowed=False,
        model_change_allowed=False,
        scorer_change_allowed=False,
        parser_change_allowed=False,
        candidate_budgets=["current", "current_plus_32", "current_plus_64", "current_plus_128"],
        all_extra_tokens_must_count=True,
    )
    owner = authority(
        schema_id="kt.v17_7_4.gsm8k_truncation_owner_matrix.v1",
        status="PASS",
        owner="GENERATION_CONFIG_OWNED_CANDIDATE",
        hypothesis_strength="WEAK" if candidate_status.endswith("WEAK") else "STRONG",
        runtime_authorized=False,
        evidence_limits=["deterministic proxy only", "no causal inference", "current row set only"],
    )
    return plan, generation, owner


def build_rescue_plan(rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    table: list[dict[str, Any]] = []
    for row in rows:
        if row.get("correct"):
            continue
        output = str(row.get("output_text") or "")
        has_expression = bool(re.search(r"\d+\s*(?:\+|-|\*|/|x|\\times)\s*\d+", output))
        if not has_expression:
            continue
        sample_id = str(row["sample_id"])
        table.append(
            authority(
                schema_id="kt.v17_7_4.gsm8k_deterministic_rescue_candidate_row.v1",
                sample_id=sample_id,
                expected_answer_hash=extension_map[sample_id].get("expected_answer_hash") or row.get("expected_answer_hash"),
                expected_answer_model_visible=False,
                raw_output_hash=row.get("output_hash"),
                explicit_arithmetic_expression_present=True,
                runtime_rescue_authorized=False,
                owner="OFFLINE_ONLY_CANDIDATE_ROWS_PRESENT",
            )
        )
    receipt = authority(
        schema_id="kt.v17_7_4.gsm8k_verifier_rescue_reassessment.v1",
        status="PASS_OFFLINE_ONLY",
        candidate_row_count=len(table),
        v3_honest_too_weak=True,
        sympy_word_problem_parser_blocked=True,
        deterministic_rescue_ceiling="LOW_TO_MODERATE_BUT_UNPROVEN",
        runtime_verifier_rescue_authorized=False,
        llm_verifier_rescue_allowed=False,
        scratchpad_rescue_allowed=False,
        nlp_word_problem_parser_allowed=False,
    )
    return receipt, table


def build_academy_plan(wrong_table: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    by_topology: dict[str, list[dict[str, Any]]] = {}
    for row in wrong_table:
        by_topology.setdefault(str(row["failure_topology"]), []).append(row)
    manifest: list[dict[str, Any]] = []
    for topology, rows in sorted(by_topology.items()):
        manifest.append(
            authority(
                schema_id="kt.v17_7_4.gsm8k_academy_candidate_scar_delta_row.v1",
                failure_topology=topology,
                evidence_count=len(rows),
                row_ids_hash=sha256_text("|".join(sorted(str(row["sample_id"]) for row in rows))),
                failure_owner=rows[0]["repairability"],
                repair_instruction_candidate=f"Plan-only repair study for {topology.lower()}",
                no_regression_requirement="protect all 28 official-correct rows and preserve official scorer lock",
                target_lobe_candidate="formal_math_candidate_only",
                training_authority=False,
                academy_authority="PLAN_ONLY",
            )
        )
    plan = authority(
        schema_id="kt.v17_7_4.gsm8k_academy_repairability_plan_no_training.v1",
        status="PLAN_ONLY_NO_TRAINING",
        candidate_topology_count=len(manifest),
        total_candidate_rows=sum(row["evidence_count"] for row in manifest),
        training_authority=False,
        academy_run_authorized=False,
        model_visible_expected_answers_allowed=False,
    )
    return plan, manifest


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
    current_head = git(["rev-parse", "HEAD"])
    branch = git(["branch", "--show-current"])
    status_text = git(["status", "--short"])
    assessment = parser_court.load_assessment()
    prior_map, extension_map = row_maps()
    rows = control_rows(assessment)
    if len(rows) != 100:
        raise RuntimeError(f"KT_BLOCKED__GSM8K_CAPABILITY_GAP_TRUTH_PIN_FAILED: expected 100 rows, got {len(rows)}")

    scoring_summary = read_json(ROOT / "reports" / "v17_7_4_scoring_surface_reconciliation_replay_builder_summary.json")
    official_replay = read_json(ROOT / "reports" / "v17_7_4_official_scorer_replay_receipt.json")
    reconciled_scorecard = read_json(ROOT / "reports" / "v17_7_4_control_only_gsm8k_reconciled_scorecard.json")
    contradiction_court = read_json(ROOT / "reports" / "v17_7_4_scoring_surface_contradiction_court.json")
    if official_replay.get("official_scorer_replay_correct") != 28:
        raise RuntimeError("KT_BLOCKED__GSM8K_PREDECESSOR_SCORE_LOCK_DEFECT")

    difficulty_table, difficulty_topology, distribution_shift = build_difficulty_tables(rows, extension_map, prior_map)
    state_delta = build_state_vector_delta(assessment, rows, extension_map, prior_map)
    wrong_table, wrong_summary, failure_counts = build_wrong_topology(rows, extension_map)
    correct_table, correct_summary = build_correct_protection(rows, extension_map)
    answer_synthesis, answer_first_table, final_marker_gap = build_answer_format(rows)
    max_token_plan, generation_plan, trunc_owner = build_max_token_plan(rows)
    rescue_reassessment, rescue_candidates = build_rescue_plan(rows, extension_map)
    academy_plan, academy_manifest = build_academy_plan(wrong_table)

    outputs: dict[str, dict[str, Any]] = {
        "v17_7_4_gsm8k_capability_gap_truth_pin.json": authority(
            schema_id="kt.v17_7_4.gsm8k_capability_gap_truth_pin.v1",
            status="PASS",
            active_tranche=TRANCHE,
            current_head=current_head,
            branch=branch,
            worktree_status_entries=[line for line in status_text.splitlines() if line.strip()],
            assessment_zip=str(parser_court.ASSESSMENT_ZIP),
            assessment_zip_sha256=assessment["assessment_sha256"],
            operator_collection_zip=str(parser_court.OPERATOR_COLLECTION_ZIP),
            operator_collection_zip_sha256=sha256_file(parser_court.OPERATOR_COLLECTION_ZIP),
            claim_ceiling_files=["rules/CLAIM_CEILING.md", "governance/current_claim_ceiling.json"],
            artifact_authority_registry="registry/artifact_authority_registry.json",
        ),
        "v17_7_4_gsm8k_capability_gap_predecessor_binding.json": authority(
            schema_id="kt.v17_7_4.gsm8k_capability_gap_predecessor_binding.v1",
            status="BOUND",
            scoring_reconciliation_outcome=scoring_summary.get("outcome"),
            official_scorer_replay_status=official_replay.get("status"),
            official_score=reconciled_scorecard.get("official_score"),
            parser_subtype_reconciliation_status=read_json(ROOT / "reports" / "v17_7_4_parser_subtype_reconciliation_update.json").get("status"),
            scoring_contradiction_court_status=contradiction_court.get("status"),
        ),
        "v17_7_4_gsm8k_capability_gap_claim_boundary_receipt.json": authority(
            schema_id="kt.v17_7_4.gsm8k_capability_gap_claim_boundary_receipt.v1",
            status="PASS",
            allowed_internal_claim="The reconciled GSM8K extension official score is 28/100; this lane autopsies the offline capability gap without runtime authority.",
            runtime_packet_generated=False,
            gsm8k_recovery_claim=False,
            parser_repair_success_claim=False,
            training_authority=False,
        ),
        "v17_7_4_gsm8k_official_score_lock.json": authority(
            schema_id="kt.v17_7_4.gsm8k_official_score_lock.v1",
            status="PASS",
            official_score="28/100",
            official_correct=28,
            official_total=100,
            official_surface_policy=reconciled_scorecard.get("official_surface_policy"),
            no_score_revision_authorized=True,
            parser_repair_authority=False,
            v3_rescue_authority=False,
            scratchpad_authority=False,
            kt_hat_authority=False,
            training_authority=False,
            promotion_authority=False,
        ),
        "v17_7_4_gsm8k_score_source_lock.json": authority(
            schema_id="kt.v17_7_4.gsm8k_score_source_lock.v1",
            status="PASS",
            official_scoring_surface_policy=reconciled_scorecard.get("official_surface_policy"),
            official_scorer_source=official_replay.get("scorer_source"),
            alternative_surface_replays_audit_only=True,
            score_revision_authorized=False,
        ),
        "v17_7_4_gsm8k_capability_prior_anchor_state_vector.json": state_delta["prior"],
        "v17_7_4_gsm8k_capability_extension_state_vector.json": state_delta["extension"],
        "v17_7_4_gsm8k_capability_anchor_vs_extension_delta.json": state_delta["delta"],
        "v17_7_4_gsm8k_capability_overlap_replay_receipt.json": state_delta["overlap"],
        "v17_7_4_gsm8k_row_difficulty_topology.json": difficulty_topology,
        "v17_7_4_gsm8k_anchor_vs_extension_distribution_shift.json": distribution_shift,
        "v17_7_4_gsm8k_wrong_row_failure_topology.json": wrong_summary,
        "v17_7_4_gsm8k_failure_topology_counts.json": failure_counts,
        "v17_7_4_gsm8k_correct_row_protection_topology.json": correct_summary,
        "v17_7_4_gsm8k_answer_format_drift_synthesis.json": answer_synthesis,
        "v17_7_4_gsm8k_final_marker_contract_gap.json": final_marker_gap,
        "v17_7_4_gsm8k_max_token_sensitivity_offline_plan.json": max_token_plan,
        "v17_7_4_gsm8k_generation_config_sensitivity_plan.json": generation_plan,
        "v17_7_4_gsm8k_truncation_owner_matrix.json": trunc_owner,
        "v17_7_4_gsm8k_verifier_rescue_reassessment.json": rescue_reassessment,
        "v17_7_4_gsm8k_academy_repairability_plan_no_training.json": academy_plan,
        "v17_7_4_epc_decision_after_gsm8k_capability_gap_autopsy.json": authority(
            schema_id="kt.v17_7_4.epc_decision_after_gsm8k_capability_gap_autopsy.v1",
            status="PASS_DECIDED",
            options_considered=[
                "NO_RUNTIME_PACKET__CAPABILITY_GAP_BOUND",
                "AUTHOR_GSM8K_MAX_TOKEN_SENSITIVITY_MICROFURNACE_DESIGN_ONLY",
                "AUTHOR_SCORING_REPORTING_FIX_REPLAY_ONLY_V1",
                "AUTHOR_GSM8K_DETERMINISTIC_RESCUE_OFFLINE_REPLAY_V4",
                "AUTHOR_ACADEMY_REPAIR_PLAN_ONLY_NO_TRAINING",
                "AUTHOR_CONTROL_ONLY_GSM8K_EXTENSION_2_IF_ROW_SOURCE_BOUND",
                "RETURN_TO_MIXED_REALBENCH_NON_MATH_STABILITY",
                "RESEARCH_REGISTER_ONLY_FOR_ROUTER_OR_THEORY",
            ],
            selected_next_lane=NEXT_LAWFUL_MOVE,
            runtime_allowed_by_this_lane=False,
            reason="Capability gap is bound; truncation/budget is a weak candidate requiring design-only sensitivity analysis before any runtime.",
        ),
        "v17_7_4_gsm8k_capability_gap_next_lane.json": authority(
            schema_id="kt.v17_7_4.gsm8k_capability_gap_next_lane.v1",
            status="PASS_NO_RUNTIME_PACKET",
            selected_next_lane=NEXT_LAWFUL_MOVE,
            packet_path_if_any=None,
            packet_sha256_if_any=None,
            kaggle_dataset_name_if_any=None,
            one_cell_runbook_if_any=None,
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
        "v17_7_4_gsm8k_capability_gap_intervention_queue.json": authority(
            schema_id="kt.v17_7_4.gsm8k_capability_gap_intervention_queue.v1",
            status="PASS",
            queue=[
                {"rank": 1, "lane": NEXT_LAWFUL_MOVE, "runtime": False},
                {"rank": 2, "lane": "AUTHOR_GSM8K_DETERMINISTIC_RESCUE_OFFLINE_REPLAY_V4", "runtime": False},
                {"rank": 3, "lane": "AUTHOR_ACADEMY_REPAIR_PLAN_ONLY_NO_TRAINING", "runtime": False},
            ],
        ),
    }
    jsonl_outputs = {
        "v17_7_4_gsm8k_row_difficulty_table.jsonl": difficulty_table,
        "v17_7_4_gsm8k_wrong_row_autopsy.jsonl": wrong_table,
        "v17_7_4_gsm8k_correct_row_autopsy.jsonl": correct_table,
        "v17_7_4_gsm8k_answer_first_pattern_table.jsonl": answer_first_table,
        "v17_7_4_gsm8k_deterministic_rescue_candidate_rows.jsonl": rescue_candidates,
        "v17_7_4_gsm8k_academy_candidate_scar_delta_manifest.jsonl": academy_manifest,
    }
    schemas = {
        "kt.v17_7_4.gsm8k_capability_gap_row.schema.json": schema_payload("kt.v17_7_4.gsm8k_capability_gap_row"),
    }
    for name, payload in outputs.items():
        write_json(ROOT / "reports" / name, payload)
    for name, payload in jsonl_outputs.items():
        write_jsonl(ROOT / "reports" / name, payload)
    for name, payload in schemas.items():
        write_json(ROOT / "schemas" / name, payload)

    generated_paths = [
        ROOT / "scripts" / "autopsy_v17_7_4_gsm8k_capability_gap.py",
        *[ROOT / "reports" / name for name in outputs],
        *[ROOT / "reports" / name for name in jsonl_outputs],
        *[ROOT / "schemas" / name for name in schemas],
    ]
    registry_delta = authority(
        schema_id="kt.artifact_authority_registry.delta.v17_7_4_gsm8k_capability_gap_autopsy.v1",
        status="PASS",
        current_head=current_head,
        outcome=OUTCOME,
        artifacts_added=[
            {
                "path": rel(path),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
                "authority_state": "REPO_SIDE_GSM8K_CAPABILITY_GAP_AUTOPSY_NO_RUNTIME",
                "claim_expansion": False,
            }
            for path in generated_paths
            if path.exists()
        ],
        next_lawful_move=NEXT_LAWFUL_MOVE,
    )
    registry_path = ROOT / "registry" / "artifact_authority_registry_v17_7_4_gsm8k_capability_gap_autopsy_delta_receipt.json"
    write_json(registry_path, registry_delta)
    generated_paths.append(registry_path)

    summary = authority(
        schema_id="kt.v17_7_4.gsm8k_capability_gap_autopsy_builder_summary.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        branch=branch,
        outcome=OUTCOME,
        files_changed=[rel(path) for path in generated_paths if path.exists()],
        gsm8k_capability_gap_binding_status=outputs["v17_7_4_gsm8k_capability_gap_predecessor_binding.json"]["status"],
        official_score_lock_status=outputs["v17_7_4_gsm8k_official_score_lock.json"]["status"],
        prior_anchor_vs_extension_delta_status=state_delta["delta"]["status"],
        row_difficulty_topology_status=difficulty_topology["status"],
        wrong_row_failure_topology_status=wrong_summary["status"],
        correct_row_protection_topology_status=correct_summary["status"],
        answer_format_drift_synthesis_status=answer_synthesis["status"],
        max_token_sensitivity_plan_status=max_token_plan["status"],
        verifier_rescue_reassessment_status=rescue_reassessment["status"],
        academy_repairability_plan_status=academy_plan["status"],
        epc_next_lane_status=outputs["v17_7_4_gsm8k_capability_gap_next_lane.json"]["status"],
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move=NEXT_LAWFUL_MOVE,
    )
    write_json(ROOT / "reports" / "v17_7_4_gsm8k_capability_gap_autopsy_builder_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
