from __future__ import annotations

from ktstoprt_common import REPORTS, authority_payload, load_assessment_jsonl, write_json, write_jsonl
from runtime.final_answer_stop_metrics import compute_semantic_trailer, extract_answer, first_complete_final_line


def main() -> int:
    predictions = load_assessment_jsonl("predictions.jsonl")
    rows = []
    damage = []
    total_chars_removed = 0
    total_tokens_removed = 0
    for row in predictions:
        truncated = first_complete_final_line(row["raw_output"])
        before_answer = row.get("extracted_answer")
        after_answer = extract_answer(truncated)
        before_correct = bool(row.get("correct"))
        after_correct = before_correct if before_answer == after_answer else row["expected_answer_hash"] == __import__("hashlib").sha256(str(after_answer).encode("utf-8")).hexdigest()
        semantic = compute_semantic_trailer(truncated, output_tokens_if_available=None)
        chars_removed = max(0, len(row["raw_output"]) - len(truncated))
        tokens_removed = row.get("tokens_after_final_answer") or 0
        total_chars_removed += chars_removed
        total_tokens_removed += tokens_removed
        replay_row = {
            "schema_id": "kt.ktstop10.truncation_replay_row.v1",
            "row_id": row["row_id"],
            "arm_id": row["arm_id"],
            "before_extracted_answer": before_answer,
            "after_extracted_answer": after_answer,
            "extraction_preserved": before_answer == after_answer,
            "before_correct": before_correct,
            "after_correct": after_correct,
            "correctness_preserved": before_correct == after_correct,
            "semantic_trailer_after_truncation": semantic.semantic_trailer_present,
            "chars_removed": chars_removed,
            "estimated_tokens_removed": tokens_removed,
            "claim_ceiling_status": "PRESERVED",
        }
        rows.append(replay_row)
        if not replay_row["extraction_preserved"] or not replay_row["correctness_preserved"]:
            damage.append(replay_row)
    replay = {
        "schema_id": "kt.ktstop10.first_complete_line_truncation_replay.v1",
        "status": "PASS_20_OF_20_EXTRACTIONS_AND_CORRECTNESS_PRESERVED_ZERO_DAMAGE" if not damage and len(rows) == 20 else "FAIL",
        "trace_count": len(rows),
        "extraction_preserved_count": sum(1 for row in rows if row["extraction_preserved"]),
        "correctness_preserved_count": sum(1 for row in rows if row["correctness_preserved"]),
        "control_damage_count": len(damage),
        "semantic_trailer_after_truncation_count": sum(1 for row in rows if row["semantic_trailer_after_truncation"]),
        "posthoc_truncation_claim_boundary": "delivery_hygiene_only_not_compute_or_latency_savings",
        **authority_payload(),
    }
    savings = {
        "schema_id": "kt.ktstop10.truncation_savings.v1",
        "status": "PASS",
        "trace_count": len(rows),
        "total_chars_removed": total_chars_removed,
        "estimated_generated_tokens_removable_from_stored_boundaries": total_tokens_removed,
        "compute_savings_authority": "NONE_POSTHOC_ONLY",
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop10_first_complete_line_truncation_replay.json", replay)
    write_json(REPORTS / "ktstop10_truncation_savings.json", savings)
    write_jsonl(REPORTS / "ktstop10_truncation_damage_rows.jsonl", damage)
    print(replay)
    if replay["status"] == "FAIL":
        raise SystemExit(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
