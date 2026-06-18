from __future__ import annotations

import zipfile

from ktstop50_common import (
    ACTIVE_TRANCHE,
    ASSESSMENT,
    ASSESSMENT_SHA256,
    EVIDENCE_SUMMARY,
    OUTCOME,
    PREFIX_MISMATCH_DETAILS,
    REPORTS,
    SOURCE_PACKET,
    SOURCE_PACKET_SHA256,
    assert_hash,
    authority_payload,
    git_output,
    load_assessment_json,
    read_json,
    rel,
    utc_now,
    write_json,
)


REQUIRED_MEMBERS = {
    "final_summary.json",
    "runtime_stop_scorecard.json",
    "prefix_equivalence_receipt.json",
    "first_last_final_audit.json",
    "metric_definition_receipt.json",
    "predictions.jsonl",
    "token_ledger.jsonl",
    "stop_reason_ledger.jsonl",
    "run_events.jsonl",
}


def main() -> None:
    assessment_sha = assert_hash(ASSESSMENT, ASSESSMENT_SHA256, "KT_STOPRT_V1_ASSESSMENT_ONLY")
    source_sha = assert_hash(SOURCE_PACKET, SOURCE_PACKET_SHA256, "ktstoprt_v1 source packet")

    with zipfile.ZipFile(ASSESSMENT) as zf:
        members = set(zf.namelist())
    missing = sorted(REQUIRED_MEMBERS - members)
    if missing:
        raise SystemExit(f"assessment missing required members: {missing}")

    summary = read_json(EVIDENCE_SUMMARY)
    mismatch_details = read_json(PREFIX_MISMATCH_DETAILS)
    final_summary = load_assessment_json("final_summary.json")
    scorecard = load_assessment_json("runtime_stop_scorecard.json")
    prefix = load_assessment_json("prefix_equivalence_receipt.json")
    metric_definition = load_assessment_json("metric_definition_receipt.json")

    truth_pin = {
        "schema_id": "kt.stoprt.truth_pin.v1",
        "created_utc": utc_now(),
        "active_tranche": ACTIVE_TRANCHE,
        "current_head": git_output("rev-parse", "HEAD"),
        "current_branch": git_output("branch", "--show-current"),
        "worktree_clean": git_output("status", "--porcelain=v1") == "",
        "source_packet": rel(SOURCE_PACKET),
        "source_packet_sha256": source_sha,
        "assessment_path": rel(ASSESSMENT),
        "assessment_sha256": assessment_sha,
        "evidence_summary_path": rel(EVIDENCE_SUMMARY),
        "prefix_mismatch_details_path": rel(PREFIX_MISMATCH_DETAILS),
        "claim_ceiling_status": "PRESERVED",
        "outcome_if_all_gates_pass": OUTCOME,
    }
    write_json(REPORTS / "ktstoprt_truth_pin.json", truth_pin)

    import_receipt = {
        "schema_id": "kt.stoprt.assessment_import_receipt.v1",
        "created_utc": utc_now(),
        "status": "PASS_IMMUTABLE_ASSESSMENT_IMPORTED",
        "assessment_status": summary["assessment_status"],
        "assessment_sha256": assessment_sha,
        "required_members_present": sorted(REQUIRED_MEMBERS),
        "row_count": final_summary["row_count"],
        "arm_count": 2,
        "official_pass_gate": scorecard["pass_gate"],
        "official_prefix_equivalence": prefix["prefix_equal_count"],
        "official_prefix_total": len(prefix["rows"]),
        "semantic_trailer_rate": scorecard["semantic_trailer_rate"],
        "metric_definition_sha256": metric_definition.get("metric_definition_sha256"),
        **authority_payload(),
    }
    write_json(REPORTS / "ktstoprt_assessment_import_receipt.json", import_receipt)

    official_receipt = {
        "schema_id": "kt.stoprt.official_receipt_preservation.v1",
        "created_utc": utc_now(),
        "status": "PRESERVED_NOT_REWRITTEN",
        "official_receipt_must_remain_failed": True,
        "official_pass_gate": scorecard["pass_gate"],
        "official_reason": "Official STOPRT receipt remains false because prefix equivalence was 8/10 and semantic trailer rate was nonzero under the original court.",
        "official_b0_correct": summary["official_receipt"]["b0_correct"],
        "official_b1_correct": summary["official_receipt"]["b1_correct"],
        "official_b0_total_output_tokens": summary["official_receipt"]["b0_total_output_tokens"],
        "official_b1_total_output_tokens": summary["official_receipt"]["b1_total_output_tokens"],
        "official_prefix_equal": summary["official_receipt"]["prefix_equivalence"],
        "official_semantic_trailer_rate": summary["official_receipt"]["semantic_trailer_rate"],
        "court_v2_is_new_adjudication": True,
        "court_v2_does_not_mutate_original_receipt": True,
        "mismatch_rows_preserved_for_adjudication": mismatch_details,
        **authority_payload(),
    }
    write_json(REPORTS / "ktstoprt_official_receipt_preservation.json", official_receipt)

    claim_boundary = {
        "schema_id": "kt.stop50.claim_boundary_receipt.v1",
        "created_utc": utc_now(),
        "status": "PASS_CLAIM_CEILING_PRESERVED",
        "allowed_claim": "STOPRT produced a mechanism signal and STOP50 prepares a sandbox paired timing packet.",
        "forbidden_claims": [
            "production runtime authority",
            "production math mode claim",
            "selector deployment",
            "training authority",
            "promotion authority",
            "commercial readiness",
            "external validation",
            "router superiority",
        ],
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop50_claim_boundary_receipt.json", claim_boundary)

    print("KTSTOPRT assessment import PASS")


if __name__ == "__main__":
    main()
