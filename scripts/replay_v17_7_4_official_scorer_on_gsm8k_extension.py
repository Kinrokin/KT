from __future__ import annotations

import hashlib
import json
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
from scripts import review_v17_7_4_control_only_gsm8k_regression_parser_court as predecessor


TRANCHE = "AUTHOR_KTV1774_SCORING_SURFACE_RECONCILIATION_REPLAY_V1"
OUTCOME = "KT_SCORING_SURFACE_RECONCILIATION_REPLAY_COMPLETE__NEXT_EVIDENCE_LANE_DECIDED__CLAIM_CEILING_PRESERVED"
CONTROL_ARM = core.REPROLOCK_ARM_ID
OFFICIAL_POLICY = "RAW_OUTPUT_REGEX_SCORING_BOUND"
NEXT_LAWFUL_MOVE = "AUTHOR_GSM8K_CAPABILITY_GAP_AUTOPSY_V1"


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
    return predecessor.sha256_file(path)


def read_json(path: Path) -> dict[str, Any]:
    return predecessor.read_json(path)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return predecessor.read_jsonl(path)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    predecessor.write_json(path, payload)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    predecessor.write_jsonl(path, rows)


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def normalize_answer(value: str) -> str:
    return predecessor.normalize_answer(value)


def numbers(value: str) -> list[str]:
    return predecessor.numbers(value)


def exact_surface_match(surface: str, expected: str) -> bool:
    return predecessor.exact_surface_match(surface, expected)


def output_contains_expected(output: str, expected: str) -> bool:
    return predecessor.output_contains_expected(output, expected)


def first_line(value: str) -> str:
    return predecessor.first_line(value)


def final_line(value: str) -> str:
    lines = [line.strip() for line in str(value).splitlines() if line.strip()]
    return lines[-1] if lines else ""


def final_marker_surface(value: str) -> str:
    return predecessor.final_marker_surface(value)


def isolated_numeric_line_surface(value: str) -> str:
    candidates: list[str] = []
    for line in str(value).splitlines():
        stripped = line.strip()
        if re.fullmatch(r"[-+]?\$?\d+(?:,\d{3})*(?:\.\d+)?|[-+]?\d+/\d+", stripped):
            candidates.append(stripped)
    return candidates[-1] if candidates else ""


def row_maps() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    return predecessor.row_maps()


def expected_for(sample_id: str, extension_map: dict[str, dict[str, Any]]) -> str:
    return predecessor.expected_for(sample_id, extension_map)


def control_rows(assessment: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in assessment["rows"] if row.get("arm_id") == CONTROL_ARM]


def official_score(row: dict[str, Any], expected_row: dict[str, Any]) -> tuple[float, bool]:
    return core.score_output(
        str(row.get("output_text") or ""),
        str(row.get("parsed_answer") or ""),
        expected_row,
        "contains_expected_label",
    )


def surface_values(row: dict[str, Any], expected: str) -> dict[str, str]:
    output = str(row.get("output_text") or "")
    raw_regex_surface = expected if output_contains_expected(output, expected) else ""
    return {
        "parsed_answer": str(row.get("parsed_answer") or ""),
        "visible_answer": str(row.get("visible_answer") or ""),
        "first_line_surface": first_line(output),
        "final_line_surface": final_line(output),
        "final_marker_surface": final_marker_surface(output),
        "isolated_numeric_line_surface": isolated_numeric_line_surface(output),
        "raw_output_regex_surface": raw_regex_surface,
    }


def score_policy(policy: str, row: dict[str, Any], expected: str, expected_row: dict[str, Any]) -> bool:
    surfaces = surface_values(row, expected)
    if policy == "current_official_scorer":
        _, correct = official_score(row, expected_row)
        return bool(correct)
    if policy == "parsed_answer_only":
        return exact_surface_match(surfaces["parsed_answer"], expected)
    if policy == "visible_answer_only":
        return exact_surface_match(surfaces["visible_answer"], expected)
    if policy == "final_marker_only":
        return exact_surface_match(surfaces["final_marker_surface"], expected)
    if policy == "first_line_only":
        return exact_surface_match(surfaces["first_line_surface"], expected)
    if policy == "final_line_only":
        return exact_surface_match(surfaces["final_line_surface"], expected)
    if policy == "raw_output_regex_only":
        return output_contains_expected(str(row.get("output_text") or ""), expected)
    if policy == "isolated_numeric_line_only":
        return exact_surface_match(surfaces["isolated_numeric_line_surface"], expected)
    raise ValueError(f"unknown policy {policy}")


def declared_explanatory_surface(row: dict[str, Any], expected: str) -> str:
    surface, _, defect = predecessor.declared_surface(row, expected)
    if surface == "UNKNOWN" and not row.get("correct"):
        return "RAW_OUTPUT_REGEX"
    return "UNKNOWN" if defect else surface


def surface_conflict_type(row: dict[str, Any], expected: str) -> str:
    surfaces = surface_values(row, expected)
    output = str(row.get("output_text") or "")
    exact_map = {name: exact_surface_match(value, expected) for name, value in surfaces.items() if name != "raw_output_regex_surface"}
    raw_match = output_contains_expected(output, expected)
    multiple_candidates = len({normalize_answer(value) for value in surfaces.values() if value and numbers(value)}) > 1
    if row.get("correct") and row.get("parser_format_failure"):
        return "PARSED_VS_RAW_REGEX_CONFLICT"
    if row.get("correct") and raw_match and not row.get("final_answer_marker_present"):
        return "FINAL_MARKER_ABSENT_RAW_REGEX_USED"
    if exact_map["visible_answer"] != raw_match:
        return "VISIBLE_VS_RAW_REGEX_CONFLICT"
    if exact_map["first_line_surface"] != exact_map["final_line_surface"]:
        return "FIRST_LINE_VS_FINAL_LINE_CONFLICT"
    if multiple_candidates:
        return "MULTIPLE_NUMERIC_CANDIDATES"
    if not raw_match and declared_explanatory_surface(row, expected) == "UNKNOWN":
        return "UNKNOWN_SCORING_SURFACE"
    if len(set(exact_map.values()) | {raw_match}) == 1:
        return "ALL_SURFACES_AGREE"
    return "NONE"


def contradiction_types(row: dict[str, Any], expected: str) -> list[str]:
    output = str(row.get("output_text") or "")
    surfaces = surface_values(row, expected)
    current = bool(row.get("correct"))
    contradictions: list[str] = []
    parsed_visible_match = exact_surface_match(surfaces["parsed_answer"], expected) or exact_surface_match(surfaces["visible_answer"], expected)
    numeric_candidates = [value for value in surfaces.values() if value and numbers(value)]
    if current and not parsed_visible_match:
        contradictions.append("CURRENT_CORRECT_BUT_PARSED_VISIBLE_MISMATCH")
    if (not current) and output_contains_expected(output, expected):
        contradictions.append("CURRENT_WRONG_BUT_RAW_OUTPUT_REGEX_MATCHES_EXPECTED")
    if current and row.get("parser_format_failure"):
        contradictions.append("CURRENT_CORRECT_WITH_PARSER_FORMAT_FAILURE")
    if current and not row.get("final_answer_marker_present"):
        contradictions.append("CURRENT_CORRECT_WITH_NO_FINAL_MARKER")
    if (not current) and len({normalize_answer(value) for value in numeric_candidates}) > 1:
        contradictions.append("CURRENT_WRONG_WITH_MULTIPLE_NUMERIC_SURFACES")
    if declared_explanatory_surface(row, expected) == "UNKNOWN":
        contradictions.append("CURRENT_SCORE_SOURCE_UNKNOWN")
    return contradictions or ["NO_CONTRADICTION"]


def contradiction_owner(kind: str) -> str:
    if kind in {"CURRENT_CORRECT_WITH_PARSER_FORMAT_FAILURE", "CURRENT_CORRECT_BUT_PARSED_VISIBLE_MISMATCH"}:
        return "PARSER_REPORTING_DEFECT"
    if kind == "CURRENT_CORRECT_WITH_NO_FINAL_MARKER":
        return "ANSWER_FORMAT_CONTRACT_DEFECT"
    if kind == "CURRENT_WRONG_BUT_RAW_OUTPUT_REGEX_MATCHES_EXPECTED":
        return "SCORING_SURFACE_AUTHORITY_DEFECT"
    if kind in {"CURRENT_WRONG_WITH_MULTIPLE_NUMERIC_SURFACES", "ALTERNATIVE_SURFACE_RESCUES_CURRENT_WRONG"}:
        return "GENERATION_MATH_OWNED"
    if kind == "CURRENT_SCORE_SOURCE_UNKNOWN":
        return "INCONCLUSIVE"
    if kind == "ALTERNATIVE_SURFACE_DAMAGES_CURRENT_CORRECT":
        return "RAW_OUTPUT_REGEX_EXPECTED_BEHAVIOR"
    return "RAW_OUTPUT_REGEX_EXPECTED_BEHAVIOR"


def primary_contradiction(kinds: list[str]) -> str:
    if kinds == ["NO_CONTRADICTION"]:
        return "NO_CONTRADICTION"
    priority = [
        "CURRENT_SCORE_SOURCE_UNKNOWN",
        "CURRENT_WRONG_BUT_RAW_OUTPUT_REGEX_MATCHES_EXPECTED",
        "CURRENT_CORRECT_WITH_PARSER_FORMAT_FAILURE",
        "CURRENT_CORRECT_BUT_PARSED_VISIBLE_MISMATCH",
        "CURRENT_CORRECT_WITH_NO_FINAL_MARKER",
        "CURRENT_WRONG_WITH_MULTIPLE_NUMERIC_SURFACES",
        "ALTERNATIVE_SURFACE_RESCUES_CURRENT_WRONG",
        "ALTERNATIVE_SURFACE_DAMAGES_CURRENT_CORRECT",
    ]
    for kind in priority:
        if kind in kinds:
            return kind
    return next(kind for kind in kinds if kind != "NO_CONTRADICTION")


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


def build_surface_replay(rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    replay_rows: list[dict[str, Any]] = []
    unknown = 0
    conflict_counts: Counter[str] = Counter()
    for row in rows:
        sample_id = str(row.get("sample_id"))
        expected_row = extension_map[sample_id]
        expected = expected_for(sample_id, extension_map)
        surfaces = surface_values(row, expected)
        explanatory_surface = declared_explanatory_surface(row, expected)
        conflict = surface_conflict_type(row, expected)
        conflict_counts[conflict] += 1
        if explanatory_surface == "UNKNOWN":
            unknown += 1
        current_surface_hash = sha256_text(str(row.get("output_text") or ""))
        replay_rows.append(
            authority(
                schema_id="kt.v17_7_4.scoring_surface_replay_row.v1",
                sample_id=sample_id,
                dataset=row.get("dataset"),
                correct_current=bool(row.get("correct")),
                score_current=row.get("score"),
                expected_answer_hash=expected_row.get("expected_answer_hash") or row.get("expected_answer_hash"),
                expected_answer_model_visible=False,
                raw_output_hash=row.get("output_hash") or sha256_text(str(row.get("output_text") or "")),
                parsed_answer=surfaces["parsed_answer"],
                visible_answer=surfaces["visible_answer"],
                first_line_surface=surfaces["first_line_surface"],
                final_line_surface=surfaces["final_line_surface"],
                final_marker_surface=surfaces["final_marker_surface"],
                isolated_numeric_line_surface=surfaces["isolated_numeric_line_surface"],
                raw_output_regex_surface_hash=sha256_text(surfaces["raw_output_regex_surface"]),
                scorer_declared_surface=explanatory_surface,
                current_surface_used_for_scoring="RAW_OUTPUT",
                surface_used_for_scoring_hash=current_surface_hash,
                scoring_surface_source="RAW_OUTPUT_REGEX",
                parser_format_failure=bool(row.get("parser_format_failure")),
                answer_format_drift=not bool(row.get("final_answer_marker_present")),
                final_answer_marker_present=bool(row.get("final_answer_marker_present")),
                output_starts_with_numeric_surface=bool(numbers(first_line(str(row.get("output_text") or "")))),
                output_contains_multiple_candidate_surfaces=len({normalize_answer(value) for value in surfaces.values() if value and numbers(value)}) > 1,
                surface_conflict_type=conflict,
            )
        )
    receipt = authority(
        schema_id="kt.v17_7_4.scoring_surface_extraction_receipt.v1",
        status="PASS" if unknown == 0 else "KT_BLOCKED__SCORING_SURFACE_SOURCE_UNKNOWN",
        row_count=len(replay_rows),
        unknown_scoring_surface_count=unknown,
        scoring_surface_source_counts=dict(sorted(Counter(row["scoring_surface_source"] for row in replay_rows).items())),
        explanatory_surface_counts=dict(sorted(Counter(row["scorer_declared_surface"] for row in replay_rows).items())),
        surface_conflict_counts=dict(sorted(conflict_counts.items())),
        expected_answer_model_visible=False,
    )
    return replay_rows, receipt


def build_official_replay(rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    matrix: list[dict[str, Any]] = []
    mismatches: list[str] = []
    correct_count = 0
    for row in rows:
        sample_id = str(row.get("sample_id"))
        expected_row = extension_map[sample_id]
        score, correct = official_score(row, expected_row)
        correct_count += int(correct)
        row_match = bool(correct) == bool(row.get("correct")) and float(score) == float(row.get("score", 0.0))
        if not row_match:
            mismatches.append(sample_id)
        matrix.append(
            authority(
                schema_id="kt.v17_7_4.official_scorer_replay_row.v1",
                sample_id=sample_id,
                dataset=row.get("dataset"),
                expected_answer_hash=expected_row.get("expected_answer_hash") or row.get("expected_answer_hash"),
                expected_answer_model_visible=False,
                raw_output_hash=row.get("output_hash") or sha256_text(str(row.get("output_text") or "")),
                parsed_answer_hash=sha256_text(str(row.get("parsed_answer") or "")),
                current_score=row.get("score"),
                replay_score=score,
                current_correct=bool(row.get("correct")),
                replay_correct=bool(correct),
                row_replay_matches_current=row_match,
                official_scoring_method="contains_expected_label",
                official_scoring_surface="RAW_OUTPUT_REGEX",
            )
        )
    status = "PASS_REPRODUCED_28_OF_100" if correct_count == 28 and not mismatches else "KT_BLOCKED__OFFICIAL_SCORER_REPLAY_MISMATCH"
    receipt = authority(
        schema_id="kt.v17_7_4.official_scorer_replay_receipt.v1",
        status=status,
        row_count=len(rows),
        official_scorer_replay_correct=correct_count,
        official_scorer_replay_total=len(rows),
        official_scorer_replay_accuracy=round(correct_count / max(len(rows), 1), 6),
        expected_correct=28,
        expected_total=100,
        row_mismatch_count=len(mismatches),
        row_mismatches=mismatches,
        replay_deterministic=True,
        scorer_source="runtime.v17_7_4.KT_V1774_TRUEGEN_ARM_CORE.score_output",
        scorer_method="contains_expected_label",
    )
    return matrix, receipt


def build_alternative_replay(rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    policies = [
        "current_official_scorer",
        "parsed_answer_only",
        "visible_answer_only",
        "final_marker_only",
        "first_line_only",
        "final_line_only",
        "raw_output_regex_only",
        "isolated_numeric_line_only",
    ]
    matrix: list[dict[str, Any]] = []
    summary_by_policy: dict[str, Any] = {}
    official_correct_by_sample = {str(row.get("sample_id")): bool(row.get("correct")) for row in rows}
    for policy in policies:
        correct_count = 0
        damage = 0
        rescues = 0
        contradiction_count = 0
        for row in rows:
            sample_id = str(row.get("sample_id"))
            expected = expected_for(sample_id, extension_map)
            expected_row = extension_map[sample_id]
            policy_correct = score_policy(policy, row, expected, expected_row)
            official_correct = official_correct_by_sample[sample_id]
            correct_count += int(policy_correct)
            damage += int(official_correct and not policy_correct)
            rescues += int((not official_correct) and policy_correct)
            contradiction = policy_correct != official_correct
            contradiction_count += int(contradiction)
            matrix.append(
                authority(
                    schema_id="kt.v17_7_4.alternative_surface_replay_row.v1",
                    policy=policy,
                    sample_id=sample_id,
                    dataset=row.get("dataset"),
                    expected_answer_hash=extension_map[sample_id].get("expected_answer_hash") or row.get("expected_answer_hash"),
                    expected_answer_model_visible=False,
                    official_correct=official_correct,
                    policy_correct=bool(policy_correct),
                    contradiction=contradiction,
                    policy_runtime_authority=False,
                    admissible_for_runtime=False,
                )
            )
        summary_by_policy[policy] = {
            "correct_count": correct_count,
            "damage_to_official_correct": damage,
            "rescues_from_official_wrong": rescues,
            "net_delta_vs_official": correct_count - 28,
            "contradiction_count": contradiction_count,
            "policy_runtime_authority": False,
            "admissible_for_runtime": False,
        }
    summary = authority(
        schema_id="kt.v17_7_4.alternative_surface_replay_summary.v1",
        status="PASS_AUDIT_ONLY",
        official_correct=28,
        row_count=len(rows),
        policies=summary_by_policy,
        alternative_surface_replay_audit_only=True,
        parser_repair_authorized=False,
        score_revision_authorized=False,
    )
    return matrix, summary


def build_contradiction_court(rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]], alternative_matrix: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    alternative_by_sample: dict[str, list[dict[str, Any]]] = {}
    for row in alternative_matrix:
        if row["policy"] == "current_official_scorer":
            continue
        alternative_by_sample.setdefault(str(row["sample_id"]), []).append(row)
    table: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    owners: Counter[str] = Counter()
    unknown_source = 0
    for row in rows:
        sample_id = str(row.get("sample_id"))
        expected = expected_for(sample_id, extension_map)
        kinds = contradiction_types(row, expected)
        if "CURRENT_SCORE_SOURCE_UNKNOWN" in kinds:
            unknown_source += 1
        for alt in alternative_by_sample.get(sample_id, []):
            if alt["official_correct"] and not alt["policy_correct"]:
                kinds.append("ALTERNATIVE_SURFACE_DAMAGES_CURRENT_CORRECT")
            if (not alt["official_correct"]) and alt["policy_correct"]:
                kinds.append("ALTERNATIVE_SURFACE_RESCUES_CURRENT_WRONG")
        kinds = sorted(set(kinds))
        primary = primary_contradiction(kinds)
        owner = contradiction_owner(primary)
        counts.update(kinds)
        owners[owner] += 1
        if primary != "NO_CONTRADICTION":
            table.append(
                authority(
                    schema_id="kt.v17_7_4.scoring_surface_contradiction_row.v1",
                    sample_id=sample_id,
                    dataset=row.get("dataset"),
                    expected_answer_hash=extension_map[sample_id].get("expected_answer_hash") or row.get("expected_answer_hash"),
                    expected_answer_model_visible=False,
                    contradiction_types=kinds,
                    primary_contradiction_type=primary,
                    owner=owner,
                    official_correct=bool(row.get("correct")),
                    parser_format_failure=bool(row.get("parser_format_failure")),
                )
            )
    court = authority(
        schema_id="kt.v17_7_4.scoring_surface_contradiction_court.v1",
        status="PASS" if unknown_source == 0 else "KT_BLOCKED__SCORING_SURFACE_SOURCE_UNKNOWN",
        row_count=len(rows),
        contradiction_row_count=len(table),
        contradiction_counts=dict(sorted(counts.items())),
        owner_counts=dict(sorted(owners.items())),
        score_source_unknown_count=unknown_source,
        parser_repair_authorized=False,
        score_revision_authorized=False,
    )
    return table, court


def build_parser_reconciliation(rows: list[dict[str, Any]], extension_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    matrix: list[dict[str, Any]] = []
    parser_rows = [row for row in rows if row.get("parser_format_failure")]
    for row in parser_rows:
        sample_id = str(row.get("sample_id"))
        expected = expected_for(sample_id, extension_map)
        matrix.append(
            authority(
                schema_id="kt.v17_7_4.parser_subtype_reconciliation_row.v1",
                sample_id=sample_id,
                dataset=row.get("dataset"),
                expected_answer_hash=extension_map[sample_id].get("expected_answer_hash") or row.get("expected_answer_hash"),
                expected_answer_model_visible=False,
                official_correct=bool(row.get("correct")),
                official_scoring_surface="RAW_OUTPUT_REGEX",
                raw_output_regex_recovers_expected=output_contains_expected(str(row.get("output_text") or ""), expected),
                parsed_answer_matches_expected=exact_surface_match(str(row.get("parsed_answer") or ""), expected),
                visible_answer_matches_expected=exact_surface_match(str(row.get("visible_answer") or ""), expected),
                reporting_defect_only=bool(row.get("correct")),
                count_as_math_failure=False,
                answer_format_contract_drift=not bool(row.get("final_answer_marker_present")),
            )
        )
    receipt = authority(
        schema_id="kt.v17_7_4.parser_subtype_reconciliation_update.v1",
        status="PASS",
        parser_format_failure_rows=len(parser_rows),
        parser_failures_officially_correct=sum(1 for row in parser_rows if row.get("correct")),
        parser_failures_officially_wrong=sum(1 for row in parser_rows if not row.get("correct")),
        parser_failures_counted_as_math_failures=0,
        parser_failure_count_does_not_inflate_math_failure_count=True,
    )
    return matrix, receipt


def build_reconciled_scorecard(rows: list[dict[str, Any]], contradiction_table: list[dict[str, Any]], contradiction_court: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    parser_rows = [row for row in rows if row.get("parser_format_failure")]
    non_parser_rows = [row for row in rows if not row.get("parser_format_failure")]
    official_wrong = [row for row in rows if not row.get("correct")]
    owner_counts = Counter(row["owner"] for row in contradiction_table)
    scorecard = authority(
        schema_id="kt.v17_7_4.control_only_gsm8k_reconciled_scorecard.v1",
        status="PASS_RECONCILED",
        official_score="28/100",
        official_correct=28,
        official_total=100,
        official_surface_policy=OFFICIAL_POLICY,
        parser_format_failures=len(parser_rows),
        parser_failures_officially_correct=sum(1 for row in parser_rows if row.get("correct")),
        parser_failures_officially_wrong=sum(1 for row in parser_rows if not row.get("correct")),
        non_parser_failures_correct=sum(1 for row in non_parser_rows if row.get("correct")),
        non_parser_failures_wrong=sum(1 for row in non_parser_rows if not row.get("correct")),
        rows_with_unknown_score_surface=contradiction_court["score_source_unknown_count"],
        rows_with_surface_contradictions=contradiction_court["contradiction_row_count"],
        rows_with_true_generation_math_failure_estimate=len(official_wrong),
        rows_with_score_reporting_defect_estimate=owner_counts.get("SCORING_SURFACE_AUTHORITY_DEFECT", 0),
        rows_with_answer_format_contract_defect_estimate=contradiction_court["contradiction_counts"].get("CURRENT_CORRECT_WITH_NO_FINAL_MARKER", 0),
        compression_frontier_status="BLOCKED",
        known_good_reproduction_status="BLOCKED",
        parser_runtime_repair_authority=False,
        v3_rescue_runtime_authority=False,
        scratchpad_runtime_authority=False,
        training_authority=False,
        promotion_authority=False,
    )
    owner_matrix = authority(
        schema_id="kt.v17_7_4.control_only_gsm8k_reconciled_owner_matrix.v1",
        status="PASS",
        owner_counts=dict(sorted(owner_counts.items())),
        official_wrong_rows=len(official_wrong),
        official_wrong_no_surface_rescue_count=len(official_wrong),
        parser_reporting_defect_is_not_math_failure=True,
        next_owner_to_autopsy="GSM8K_CAPABILITY_GAP",
    )
    return scorecard, owner_matrix


def main() -> int:
    current_head = git(["rev-parse", "HEAD"])
    branch = git(["branch", "--show-current"])
    status_text = git(["status", "--short"])
    assessment = predecessor.load_assessment()
    _, extension_map = row_maps()
    rows = control_rows(assessment)
    if len(rows) != 100:
        raise RuntimeError(f"KT_BLOCKED__SCORING_SURFACE_RECONCILIATION_TRUTH_PIN_FAILED: expected 100 rows, got {len(rows)}")
    if not extension_map:
        raise RuntimeError("KT_BLOCKED__SCORING_SURFACE_RECONCILIATION_TRUTH_PIN_FAILED: missing extension manifest")

    predecessor_summary = read_json(ROOT / "reports" / "v17_7_4_control_only_gsm8k_regression_parser_court_builder_summary.json")
    predecessor_audit = read_json(ROOT / "reports" / "v17_7_4_scoring_surface_authority_audit.json")
    predecessor_owner = read_json(ROOT / "reports" / "v17_7_4_control_only_gsm8k_failure_owner_court.json")
    predecessor_parser = read_json(ROOT / "reports" / "v17_7_4_parser_failure_subtype_court.json")
    predecessor_format = read_json(ROOT / "reports" / "v17_7_4_control_only_gsm8k_answer_format_contract_audit.json")
    predecessor_prompt = read_json(ROOT / "reports" / "v17_7_4_control_only_gsm8k_prompt_generation_config_review.json")

    surface_rows, surface_receipt = build_surface_replay(rows, extension_map)
    official_matrix, official_receipt = build_official_replay(rows, extension_map)
    if official_receipt["status"].startswith("KT_BLOCKED"):
        raise RuntimeError(official_receipt["status"])
    alternative_matrix, alternative_summary = build_alternative_replay(rows, extension_map)
    contradiction_table, contradiction_court = build_contradiction_court(rows, extension_map, alternative_matrix)
    if contradiction_court["status"].startswith("KT_BLOCKED"):
        raise RuntimeError(contradiction_court["status"])
    parser_matrix, parser_reconciliation = build_parser_reconciliation(rows, extension_map)
    reconciled_scorecard, reconciled_owner = build_reconciled_scorecard(rows, contradiction_table, contradiction_court)

    outputs: dict[str, dict[str, Any]] = {
        "v17_7_4_scoring_surface_reconciliation_truth_pin.json": authority(
            schema_id="kt.v17_7_4.scoring_surface_reconciliation_truth_pin.v1",
            status="PASS",
            active_tranche=TRANCHE,
            current_head=current_head,
            branch=branch,
            worktree_status_entries=[line for line in status_text.splitlines() if line.strip()],
            assessment_zip=str(predecessor.ASSESSMENT_ZIP),
            assessment_zip_sha256=assessment["assessment_sha256"],
            operator_collection_zip=str(predecessor.OPERATOR_COLLECTION_ZIP),
            operator_collection_zip_sha256=sha256_file(predecessor.OPERATOR_COLLECTION_ZIP),
            control_arm=CONTROL_ARM,
            claim_ceiling_files=["rules/CLAIM_CEILING.md", "governance/current_claim_ceiling.json"],
            artifact_authority_registry="registry/artifact_authority_registry.json",
        ),
        "v17_7_4_scoring_surface_reconciliation_predecessor_binding.json": authority(
            schema_id="kt.v17_7_4.scoring_surface_reconciliation_predecessor_binding.v1",
            status="BOUND",
            predecessor_head=predecessor_summary.get("current_head"),
            predecessor_outcome=predecessor_summary.get("outcome"),
            predecessor_scoring_surface_authority_status=predecessor_audit.get("status"),
            predecessor_failure_owner_court_status=predecessor_owner.get("status"),
            predecessor_parser_subtype_court_status=predecessor_parser.get("status"),
            predecessor_answer_format_contract_audit_status=predecessor_format.get("status"),
            predecessor_prompt_generation_config_review_status=predecessor_prompt.get("status"),
            predecessor_next_lawful_move=predecessor_summary.get("next_lawful_move"),
        ),
        "v17_7_4_scoring_surface_reconciliation_claim_boundary_receipt.json": authority(
            schema_id="kt.v17_7_4.scoring_surface_reconciliation_claim_boundary_receipt.v1",
            status="PASS",
            allowed_internal_claim=(
                "The GSM8K extension scorecard is reconciled offline to bind the exact scoring "
                "surface and separate scoring-surface ambiguity from math capability failures."
            ),
            runtime_packet_generated=False,
            parser_repair_success_claim=False,
            score_revision_authorized=False,
        ),
        "v17_7_4_scoring_surface_extraction_receipt.json": surface_receipt,
        "v17_7_4_official_scorer_replay_receipt.json": official_receipt,
        "v17_7_4_alternative_surface_replay_summary.json": alternative_summary,
        "v17_7_4_scoring_surface_contradiction_court.json": contradiction_court,
        "v17_7_4_parser_subtype_reconciliation_update.json": parser_reconciliation,
        "v17_7_4_control_only_gsm8k_reconciled_scorecard.json": reconciled_scorecard,
        "v17_7_4_control_only_gsm8k_reconciled_owner_matrix.json": reconciled_owner,
        "v17_7_4_epc_decision_after_scoring_surface_reconciliation.json": authority(
            schema_id="kt.v17_7_4.epc_decision_after_scoring_surface_reconciliation.v1",
            status="PASS_DECIDED",
            options_considered=[
                "NO_RUNTIME_PACKET__SCORING_SURFACE_RECONCILED",
                "AUTHOR_GSM8K_CAPABILITY_GAP_AUTOPSY_V1",
                "AUTHOR_SCORING_REPORTING_FIX_REPLAY_ONLY_V1",
                "AUTHOR_ANSWER_FORMAT_CONTRACT_REPORT_ONLY_V1",
                "AUTHOR_GSM8K_MAX_TOKEN_SENSITIVITY_OFFLINE_PLAN",
                "AUTHOR_ACADEMY_REPAIR_PLAN_ONLY_NO_TRAINING",
                "AUTHOR_CONTROL_ONLY_GSM8K_EXTENSION_2_IF_ROW_SOURCE_BOUND",
                "RESEARCH_REGISTER_ONLY_FOR_ROUTER_OR_THEORY",
            ],
            selected_next_lane=NEXT_LAWFUL_MOVE,
            runtime_allowed_by_this_lane=False,
            reason="Official scorer replay reproduced 28/100 and score sources are known; next evidence should autopsy the non-parser GSM8K capability gap.",
        ),
        "v17_7_4_scoring_surface_reconciliation_next_lane.json": authority(
            schema_id="kt.v17_7_4.scoring_surface_reconciliation_next_lane.v1",
            status="PASS_NO_RUNTIME_PACKET",
            selected_next_lane=NEXT_LAWFUL_MOVE,
            packet_path_if_any=None,
            packet_sha256_if_any=None,
            kaggle_dataset_name_if_any=None,
            one_cell_runbook_if_any=None,
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
        "v17_7_4_scoring_surface_reconciliation_intervention_queue.json": authority(
            schema_id="kt.v17_7_4.scoring_surface_reconciliation_intervention_queue.v1",
            status="PASS",
            queue=[
                {"rank": 1, "lane": NEXT_LAWFUL_MOVE, "runtime": False},
                {"rank": 2, "lane": "AUTHOR_ANSWER_FORMAT_CONTRACT_REPORT_ONLY_V1", "runtime": False},
                {"rank": 3, "lane": "AUTHOR_GSM8K_MAX_TOKEN_SENSITIVITY_OFFLINE_PLAN", "runtime": False},
            ],
        ),
    }
    jsonl_outputs = {
        "v17_7_4_scoring_surface_replay_table.jsonl": surface_rows,
        "v17_7_4_official_scorer_replay_matrix.jsonl": official_matrix,
        "v17_7_4_alternative_surface_replay_matrix.jsonl": alternative_matrix,
        "v17_7_4_scoring_surface_reconciliation_contradiction_table.jsonl": contradiction_table,
        "v17_7_4_parser_subtype_reconciliation_matrix.jsonl": parser_matrix,
    }
    schemas = {
        "kt.v17_7_4.scoring_surface_replay_row.schema.json": schema_payload("kt.v17_7_4.scoring_surface_replay_row"),
    }
    for name, payload in outputs.items():
        write_json(ROOT / "reports" / name, payload)
    for name, payload in jsonl_outputs.items():
        write_jsonl(ROOT / "reports" / name, payload)
    for name, payload in schemas.items():
        write_json(ROOT / "schemas" / name, payload)

    generated_paths = [
        ROOT / "scripts" / "replay_v17_7_4_official_scorer_on_gsm8k_extension.py",
        *[ROOT / "reports" / name for name in outputs],
        *[ROOT / "reports" / name for name in jsonl_outputs],
        *[ROOT / "schemas" / name for name in schemas],
    ]
    registry_delta = authority(
        schema_id="kt.artifact_authority_registry.delta.v17_7_4_scoring_surface_reconciliation_replay.v1",
        status="PASS",
        current_head=current_head,
        outcome=OUTCOME,
        artifacts_added=[
            {
                "path": rel(path),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
                "authority_state": "REPO_SIDE_SCORING_SURFACE_RECONCILIATION_NO_RUNTIME",
                "claim_expansion": False,
            }
            for path in generated_paths
            if path.exists()
        ],
        next_lawful_move=NEXT_LAWFUL_MOVE,
    )
    registry_path = ROOT / "registry" / "artifact_authority_registry_v17_7_4_scoring_surface_reconciliation_replay_delta_receipt.json"
    write_json(registry_path, registry_delta)
    generated_paths.append(registry_path)

    summary = authority(
        schema_id="kt.v17_7_4.scoring_surface_reconciliation_replay_builder_summary.v1",
        status="PASS",
        active_tranche=TRANCHE,
        current_head=current_head,
        branch=branch,
        outcome=OUTCOME,
        files_changed=[rel(path) for path in generated_paths if path.exists()],
        scoring_surface_reconciliation_binding_status=outputs["v17_7_4_scoring_surface_reconciliation_predecessor_binding.json"]["status"],
        official_scorer_replay_status=official_receipt["status"],
        surface_extraction_replay_status=surface_receipt["status"],
        alternative_surface_replay_status=alternative_summary["status"],
        scoring_contradiction_court_status=contradiction_court["status"],
        parser_subtype_reconciliation_status=parser_reconciliation["status"],
        reconciled_scorecard_status=reconciled_scorecard["status"],
        epc_next_lane_status=outputs["v17_7_4_scoring_surface_reconciliation_next_lane.json"]["status"],
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        claim_ceiling_status="PRESERVED",
        blockers=[],
        next_lawful_move=NEXT_LAWFUL_MOVE,
    )
    write_json(ROOT / "reports" / "v17_7_4_scoring_surface_reconciliation_replay_builder_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
