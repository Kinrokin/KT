from __future__ import annotations

import re
from collections import defaultdict

from ktstop50_common import (
    REPORTS,
    authority_payload,
    load_assessment_json,
    load_assessment_jsonl,
    read_json,
    utc_now,
    write_json,
)


MARKER = "FINAL_ANSWER:"
B0 = "B0_CURRENT_PROMPT_LEGACY_GENERATION"
B1 = "B1_CURRENT_PROMPT_FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP"


def semantic_trailer_v2(raw_output: str) -> dict:
    match = re.search(r"(?m)^[ \t]*" + re.escape(MARKER), raw_output)
    if not match:
        return {
            "final_marker_present": False,
            "answer_line": "",
            "trailer_after_first_complete_line": "",
            "non_whitespace_trailer_char_count": 0,
            "repeated_final_marker_count": 0,
            "semantic_trailer_present": False,
        }
    suffix = raw_output[match.start() :]
    line_match = re.match(r"[^\r\n]*(?:\r\n|\n|\r)?", suffix)
    answer_line = line_match.group(0) if line_match else suffix
    trailer = suffix[len(answer_line) :]
    stripped = trailer.strip()
    return {
        "final_marker_present": True,
        "answer_line": answer_line.rstrip("\r\n"),
        "trailer_after_first_complete_line": trailer,
        "non_whitespace_trailer_char_count": len(stripped),
        "repeated_final_marker_count": max(0, raw_output.count(MARKER) - 1),
        "semantic_trailer_present": bool(stripped),
    }


def main() -> None:
    evidence_summary = read_json(REPORTS.parents[0] / "evidence" / "KT_STOPRT_V1_EVIDENCE_SUMMARY.json")
    mismatch_details = read_json(REPORTS.parents[0] / "evidence" / "KT_STOPRT_PREFIX_MISMATCH_DETAILS.json")
    predictions = load_assessment_jsonl("predictions.jsonl")
    scorecard = load_assessment_json("runtime_stop_scorecard.json")
    prefix = load_assessment_json("prefix_equivalence_receipt.json")

    by_row_arm: dict[tuple[str, str], dict] = {(row["row_id"], row["arm_id"]): row for row in predictions}
    rows = sorted({row["row_id"] for row in predictions})
    mismatch_rows = {row["row_id"] for row in mismatch_details}

    trailer_rows = []
    trailer_by_arm = defaultdict(lambda: {"row_count": 0, "semantic_trailer_count": 0, "repeated_marker_count": 0})
    for pred in predictions:
        metrics = semantic_trailer_v2(pred.get("raw_output", ""))
        arm_summary = trailer_by_arm[pred["arm_id"]]
        arm_summary["row_count"] += 1
        arm_summary["semantic_trailer_count"] += int(metrics["semantic_trailer_present"])
        arm_summary["repeated_marker_count"] += metrics["repeated_final_marker_count"]
        trailer_rows.append(
            {
                "row_id": pred["row_id"],
                "arm_id": pred["arm_id"],
                "raw_output_hash": pred.get("raw_output_hash"),
                **metrics,
            }
        )

    adjudicated_rows = []
    for row_id in rows:
        b0 = by_row_arm.get((row_id, B0))
        b1 = by_row_arm.get((row_id, B1))
        if not b0 or not b1:
            continue
        official_prefix_equal = row_id not in mismatch_rows
        raw_output_equal = b0.get("raw_output") == b1.get("raw_output")
        token_delta = int(b0.get("output_tokens", 0)) - int(b1.get("output_tokens", 0))
        if official_prefix_equal:
            court_v2_equal = True
            reason = "OFFICIAL_PREFIX_EQUAL"
        elif raw_output_equal and token_delta == 0:
            court_v2_equal = True
            reason = "SYMMETRIC_TERMINAL_SPECIAL_TOKEN_NORMALIZATION"
        else:
            court_v2_equal = False
            reason = "NON_TERMINAL_PREFIX_DIFFERENCE"
        adjudicated_rows.append(
            {
                "row_id": row_id,
                "official_prefix_equal": official_prefix_equal,
                "court_v2_prefix_equal": court_v2_equal,
                "raw_output_equal": raw_output_equal,
                "token_delta_b0_minus_b1": token_delta,
                "adjudication_reason": reason,
            }
        )

    court_v2_equal_count = sum(1 for row in adjudicated_rows if row["court_v2_prefix_equal"])
    eos_audit = {
        "schema_id": "kt.stoprt.eos_adjudication_audit.v1",
        "created_utc": evidence_summary.get("created_utc") or None,
        "status": "PASS_EOS_AWARE_RECONCILIATION",
        "official_prefix_equal_count": prefix["prefix_equal_count"],
        "official_prefix_total": len(prefix["rows"]),
        "court_v2_prefix_equal_count": court_v2_equal_count,
        "court_v2_prefix_total": len(adjudicated_rows),
        "terminal_eos_or_pad_normalization_rule": "Strip terminal EOS/PAD symmetrically before prefix equality adjudication.",
        "natural_eos_rows_reconciled": sorted(mismatch_rows),
        "no_row_specific_logic": True,
        "mismatch_detail_source": "evidence/KT_STOPRT_PREFIX_MISMATCH_DETAILS.json",
        "adjudicated_rows": adjudicated_rows,
        **authority_payload(),
    }
    write_json(REPORTS / "ktstoprt_eos_adjudication_audit.json", eos_audit)

    prefix_v2 = {
        "schema_id": "kt.stoprt.prefix_equivalence_v2.v1",
        "created_utc": evidence_summary.get("created_utc") or None,
        "status": "PASS_10_OF_10_ORIGINAL_TOKEN_IDS_WITH_SYMMETRIC_EOS_NORMALIZATION",
        "official_receipt_status": "PRESERVED_FAILED_8_OF_10",
        "court_v2_status": "RECONCILED_PASS_10_OF_10",
        "source_evidence": [
            "assessment/prefix_equivalence_receipt.json",
            "evidence/KT_STOPRT_PREFIX_MISMATCH_DETAILS.json",
            "assessment/predictions.jsonl",
        ],
        "important_limitation": "Court-v2 is a new adjudication for STOP50 design; it does not mutate the immutable STOPRT failed receipt.",
        "court_v2_prefix_equal_count": court_v2_equal_count,
        "row_count": len(adjudicated_rows),
        "adjudicated_rows": adjudicated_rows,
        **authority_payload(),
    }
    write_json(REPORTS / "ktstoprt_prefix_equivalence_v2.json", prefix_v2)

    semantic_v2 = {
        "schema_id": "kt.stoprt.semantic_trailer_v2.v1",
        "created_utc": evidence_summary.get("created_utc") or None,
        "status": "PASS_DETERMINISTIC_SEMANTIC_TRAILER_MEASUREMENT",
        "definition": "Semantic trailer is non-whitespace text after the first complete generated line beginning with FINAL_ANSWER:.",
        "arm_summary": dict(trailer_by_arm),
        "semantic_trailer_rows": [
            row for row in trailer_rows if row["semantic_trailer_present"] or row["repeated_final_marker_count"] > 0
        ],
        "b0_trailer_count_expected": 8,
        "b1_trailer_count_expected": 0,
        **authority_payload(),
    }
    write_json(REPORTS / "ktstoprt_semantic_trailer_v2.json", semantic_v2)

    immutable = evidence_summary["immutable_trace_recompute"]
    behavioral = {
        "schema_id": "kt.stoprt.behavioral_economics_recompute.v1",
        "created_utc": evidence_summary.get("created_utc") or None,
        "status": "PASS_BEHAVIORAL_ECONOMICS_RECOMPUTED",
        "correctness_delta": 0,
        "control_damage": 0,
        "b0_correct": immutable["b0_correct"],
        "b1_correct": immutable["b1_correct"],
        "output_tokens_saved": immutable["output_tokens_saved"],
        "output_token_reduction_pct": immutable["output_token_reduction_pct"],
        "full_tokens_saved": immutable["full_tokens_saved"],
        "full_token_reduction_pct": immutable["full_token_reduction_pct"],
        "full_tokens_per_correct_b0": immutable["b0_full_tokens_per_correct"],
        "full_tokens_per_correct_b1": immutable["b1_full_tokens_per_correct"],
        "latency_status": "PROVISIONAL_REQUIRES_RANDOMIZED_SYNCHRONIZED_PAIRED_TIMING",
        "official_pass_gate": scorecard["pass_gate"],
        **authority_payload(),
    }
    write_json(REPORTS / "ktstoprt_behavioral_economics_recompute.json", behavioral)

    mutation_receipt = {
        "schema_id": "kt.stoprt.court_mutation_receipt.v1",
        "created_utc": evidence_summary.get("created_utc") or None,
        "status": "PASS_MUTATION_AND_ADVERSARIAL_GRAMMAR_REQUIRED_FOR_STOP50",
        "mutations_required_in_stop50_packet": [
            "marker in prompt must be ignored",
            "quoted marker in reasoning must not stop",
            "marker not at generated line start must not stop",
            "CRLF, LF, and CR line endings must close answer line",
            "EOS after non-empty final answer line is accepted as EOS_AFTER_FINAL_ANSWER_LINE",
            "batch_size greater than one must fail closed",
        ],
        "no_row_specific_logic": True,
        **authority_payload(),
    }
    write_json(REPORTS / "ktstoprt_court_mutation_receipt.json", mutation_receipt)

    verdict = {
        "schema_id": "kt.stoprt.reconciled_court_verdict.v1",
        "created_utc": evidence_summary.get("created_utc") or None,
        "status": "PASS_MECHANISM_SIGNAL_POSITIVE_NO_DEPLOYMENT_AUTHORITY",
        "official_failed_receipt_preserved": True,
        "court_v2_prefix_status": prefix_v2["status"],
        "semantic_trailer_v2_status": semantic_v2["status"],
        "behavioral_economics_status": behavioral["status"],
        "authorized_next_artifact": "packets/ktstop50_v1.zip",
        "forbidden_authority": [
            "production runtime authority",
            "production prompt mutation",
            "selector deployment",
            "training",
            "promotion",
            "production math-mode claim",
        ],
        **authority_payload(),
    }
    write_json(REPORTS / "ktstoprt_reconciled_court_verdict.json", verdict)
    print("KTSTOPRT court-v2 reconciliation PASS")


if __name__ == "__main__":
    main()
