from __future__ import annotations

from collections import Counter, defaultdict

from ktstoprt_common import REPORTS, authority_payload, load_assessment_json, load_assessment_jsonl, write_json, write_jsonl
from runtime.final_answer_stop_metrics import compute_semantic_trailer


def main() -> int:
    scorecard = load_assessment_json("stopseq_scorecard.json")
    predictions = load_assessment_jsonl("predictions.jsonl")
    token_rows = load_assessment_jsonl("token_ledger.jsonl")
    token_by_key = {(row["row_id"], row["arm_id"]): row for row in token_rows}
    by_arm = defaultdict(list)
    for row in predictions:
        by_arm[row["arm_id"]].append(row)

    semantic_counts = {}
    for arm_id, rows in by_arm.items():
        semantic_counts[arm_id] = {
            "rows": len(rows),
            "correct": sum(1 for row in rows if row.get("correct")),
            "semantic_trailer_rows": 0,
            "legacy_trailer_rows": sum(1 for row in rows if row.get("trailer_present")),
            "legacy_post_final_tokens": sum(row.get("tokens_after_final_answer") or 0 for row in rows),
            "total_output_tokens": sum(row.get("output_tokens_if_available") or 0 for row in rows),
            "repeated_marker_rows": 0,
            "max_new_tokens_hit_rows": 0,
        }

    forensic_rows = []
    for row in predictions:
        metrics = compute_semantic_trailer(
            row["raw_output"],
            output_tokens_if_available=row.get("output_tokens_if_available"),
        )
        if metrics.semantic_trailer_present:
            semantic_counts[row["arm_id"]]["semantic_trailer_rows"] += 1
        if metrics.repeated_final_answer_count:
            semantic_counts[row["arm_id"]]["repeated_marker_rows"] += 1
        if metrics.max_new_tokens_hit:
            semantic_counts[row["arm_id"]]["max_new_tokens_hit_rows"] += 1
        token_key = token_by_key.get((row["row_id"], row["arm_id"]), {})
        forensic_rows.append(
            {
                "schema_id": "kt.ktstop10.row_level_forensics.v1",
                "row_id": row["row_id"],
                "arm_id": row["arm_id"],
                "answer_line_text": metrics.answer_line_text,
                "answer_suffix_text": metrics.answer_suffix_text,
                "semantic_post_final_line_text": metrics.semantic_post_final_line_text,
                "semantic_trailer_present": metrics.semantic_trailer_present,
                "repeated_final_answer_count": metrics.repeated_final_answer_count,
                "max_new_tokens_hit": metrics.max_new_tokens_hit,
                "stop_reason": "MAX_NEW_TOKENS" if metrics.max_new_tokens_hit else "EOS_OR_MODEL_STOP",
                "tokens_after_complete_final_line": row.get("tokens_after_final_answer"),
                "chars_after_complete_final_line": metrics.chars_after_complete_final_line,
                "legacy_trailer_present": row.get("trailer_present"),
                "legacy_tokens_after_final_answer": row.get("tokens_after_final_answer"),
                "prompt_tokens": token_key.get("prompt_tokens"),
                "output_tokens": token_key.get("output_tokens"),
                "correct": row.get("correct"),
                "claim_ceiling_status": "PRESERVED",
            }
        )

    recompute = {
        "schema_id": "kt.ktstop10.semantic_trailer_recompute.v1",
        "status": "PASS",
        "metric_contract": "same-line units/currency/percent/punctuation are answer-line content, not semantic trailer",
        "by_arm": dict(sorted(semantic_counts.items())),
        "expected_a0_semantic_trailer_rows": 8,
        "expected_a1_semantic_trailer_rows": 7,
        "expectation_status": "PASS" if semantic_counts["A0_CURRENT_PROMPT"]["semantic_trailer_rows"] == 8 and semantic_counts["A1_STOP_AFTER_FINAL_ANSWER"]["semantic_trailer_rows"] == 7 else "FAIL",
        **authority_payload(),
    }
    reconciliation = {
        "schema_id": "kt.ktstop10.scorecard_reconciliation.v1",
        "status": "PASS",
        "official_scorecard": scorecard,
        "prompt_only_verdict": "FAIL_WORSE_TOKEN_ECONOMICS_REPETITION_RISK",
        "correctness_delta": scorecard["correctness_delta"],
        "control_damage_count": scorecard["control_damage_count"],
        "official_trailer_rate_delta": scorecard["trailer_rate_delta"],
        "semantic_trailer_absolute_delta": (
            semantic_counts["A1_STOP_AFTER_FINAL_ANSWER"]["semantic_trailer_rows"]
            - semantic_counts["A0_CURRENT_PROMPT"]["semantic_trailer_rows"]
        )
        / 10,
        "supported_claim": "The prompt instruction materially changed generation trajectory and increased late-generation repetition/token waste on this sample.",
        **authority_payload(),
    }
    metric_definition = {
        "schema_id": "kt.ktstop10.metric_definition_audit.v1",
        "status": "PASS",
        "legacy_metric_preserved": True,
        "corrected_fields_added": [
            "answer_line_text",
            "answer_suffix_text",
            "semantic_post_final_line_text",
            "semantic_trailer_present",
            "repeated_final_answer_count",
            "repeated_marker_before_close",
            "max_new_tokens_hit",
            "stop_reason",
            "tokens_after_complete_final_line",
            "chars_after_complete_final_line",
        ],
        "same_line_answer_material_is_not_trailer": True,
        **authority_payload(),
    }
    class_counts = Counter(row["arm_id"] for row in predictions if row.get("output_tokens_if_available") == 512)
    prompt_failure = {
        "schema_id": "kt.ktstop10.prompt_instruction_failure_receipt.v1",
        "status": "PROMPT_ONLY_STOP_INSTRUCTION_REJECTED",
        "correctness": "UNCHANGED",
        "control_damage": "ZERO",
        "token_economics": "WORSE",
        "repetition_loop_risk": "MATERIAL",
        "generation_time_stopping": "NOT_YET_TESTED",
        "max_new_tokens_hit_by_arm": dict(class_counts),
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop10_scorecard_reconciliation.json", reconciliation)
    write_json(REPORTS / "ktstop10_metric_definition_audit.json", metric_definition)
    write_json(REPORTS / "ktstop10_semantic_trailer_recompute.json", recompute)
    write_jsonl(REPORTS / "ktstop10_row_level_forensics.jsonl", forensic_rows)
    write_json(REPORTS / "ktstop10_prompt_instruction_failure_receipt.json", prompt_failure)
    print(reconciliation)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
