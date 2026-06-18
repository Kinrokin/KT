from __future__ import annotations

from collections import Counter

from ktstoprt_common import REPORTS, authority_payload, load_assessment_json, load_assessment_jsonl, load_ktstop10_config, sha256_text, write_json, write_jsonl
from runtime.final_answer_stop_metrics import audit_first_last


def main() -> int:
    predictions = load_assessment_jsonl("predictions.jsonl")
    row_manifest = load_assessment_json("row_manifest.json")
    row_hashes = {row["row_id"]: row["expected_answer_hash"] for row in row_manifest["rows"]}
    config = load_ktstop10_config()
    for row_id, expected in config["scorer_expected_answers"].items():
        row_hashes.setdefault(row_id, sha256_text(str(expected)))
    rows = []
    for row in predictions:
        expected_hash = row_hashes[row["row_id"]]
        audit = audit_first_last(row["raw_output"], expected_hash)
        rows.append(
            {
                "schema_id": "kt.ktstop10.first_last_final_audit_row.v1",
                "row_id": row["row_id"],
                "arm_id": row["arm_id"],
                "row_bucket": row["row_bucket"],
                "expected_answer_hash": expected_hash,
                "current_extracted_answer": row.get("extracted_answer"),
                "current_correct": row.get("correct"),
                **audit,
                "claim_ceiling_status": "PRESERVED",
            }
        )
    counts = Counter(row["classification"] for row in rows)
    first_wrong_later_corrected = counts.get("FIRST_FINAL_WRONG_LATER_CORRECTED", 0)
    summary = {
        "schema_id": "kt.ktstop10.first_last_final_audit.v1",
        "status": "PASS",
        "trace_count": len(rows),
        "classification_counts": dict(sorted(counts.items())),
        "first_final_wrong_later_corrected": first_wrong_later_corrected,
        "first_final_correct_later_damaged": counts.get("FIRST_FINAL_CORRECT_LATER_DAMAGED", 0),
        "compatible_historical_trace_expansion_status": "STOP10_BOUND; KTCFFIX raw outputs have different schema and are not used for first-final gate authority",
        **authority_payload(),
    }
    gate = {
        "schema_id": "kt.ktstop10.first_answer_lock_gate.v1",
        "status": "PASS_ZERO_FIRST_WRONG_LATER_CORRECTED_ON_STOP10" if first_wrong_later_corrected == 0 else "BLOCKED_FIRST_WRONG_LATER_CORRECTED_PRESENT",
        "stop10_trace_count": len(rows),
        "first_final_wrong_later_corrected": first_wrong_later_corrected,
        "first_final_correct_later_damaged": counts.get("FIRST_FINAL_CORRECT_LATER_DAMAGED", 0),
        "packet_authority": "EXACT_10_ROW_SANDBOX_CONFIRMATION_ONLY",
        "shadow_canary_default_authority": False,
        **authority_payload(),
    }
    write_jsonl(REPORTS / "ktstop10_first_last_final_audit.jsonl", rows)
    write_json(REPORTS / "ktstop10_first_last_final_audit.json", summary)
    write_json(REPORTS / "ktstop10_first_answer_lock_gate.json", gate)
    print(gate)
    if gate["status"].startswith("BLOCKED"):
        raise SystemExit(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
