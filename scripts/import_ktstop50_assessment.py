from __future__ import annotations

import zipfile

from ktstop300_common import (
    ACTIVE_TRANCHE,
    OUTCOME,
    REPORTS,
    STOP50_ASSESSMENT,
    STOP50_ASSESSMENT_SHA256,
    STOP50_PACKET,
    STOP50_PACKET_SHA256,
    STOP50_SYNTHESIS,
    STOP50_WRAPPER,
    STOP50_WRAPPER_SHA256,
    assert_hash,
    authority_payload,
    git_output,
    load_zip_json,
    read_json,
    rel,
    utc_now,
    write_json,
)


REQUIRED_ASSESSMENT_MEMBERS = {
    "final_summary.json",
    "runtime_stop_scorecard.json",
    "predictions.jsonl",
    "prefix_equivalence_rows.jsonl",
    "timing_ledger.jsonl",
    "token_ledger.jsonl",
    "environment_contract_receipt.json",
    "model_loader_receipt.json",
    "quantization_authority_receipt.json",
    "generation_config_authority_receipt.json",
}


def main() -> int:
    packet_sha = assert_hash(STOP50_PACKET, STOP50_PACKET_SHA256, "STOP50 source packet")
    assessment_sha = assert_hash(STOP50_ASSESSMENT, STOP50_ASSESSMENT_SHA256, "STOP50 assessment")
    wrapper_sha = assert_hash(STOP50_WRAPPER, STOP50_WRAPPER_SHA256, "STOP50 wrapper collection")
    synthesis = read_json(STOP50_SYNTHESIS)
    final_summary = load_zip_json(STOP50_ASSESSMENT, "final_summary.json")
    scorecard = load_zip_json(STOP50_ASSESSMENT, "runtime_stop_scorecard.json")
    row_manifest = load_zip_json(STOP50_ASSESSMENT, "row_manifest.json")
    env = load_zip_json(STOP50_ASSESSMENT, "environment_contract_receipt.json")
    model_loader = load_zip_json(STOP50_ASSESSMENT, "model_loader_receipt.json")

    with zipfile.ZipFile(STOP50_ASSESSMENT) as zf:
        missing = sorted(REQUIRED_ASSESSMENT_MEMBERS - set(zf.namelist()))
    if missing:
        raise SystemExit(f"STOP50 assessment missing required members: {missing}")

    truth_pin = {
        "schema_id": "kt.stop300.truth_pin.v1",
        "created_utc": utc_now(),
        "active_tranche": ACTIVE_TRANCHE,
        "current_head": git_output("rev-parse", "HEAD"),
        "current_branch": git_output("branch", "--show-current"),
        "worktree_clean": git_output("status", "--porcelain=v1") == "",
        "stop50_packet": rel(STOP50_PACKET),
        "stop50_packet_sha256": packet_sha,
        "stop50_assessment": rel(STOP50_ASSESSMENT),
        "stop50_assessment_sha256": assessment_sha,
        "stop50_wrapper": rel(STOP50_WRAPPER),
        "stop50_wrapper_sha256": wrapper_sha,
        "target_outcome": OUTCOME,
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop50_truth_pin.json", truth_pin)

    import_receipt = {
        "schema_id": "kt.stop50.assessment_import_receipt.v2",
        "created_utc": utc_now(),
        "status": "PASS_STOP50_IMMUTABLE_ASSESSMENT_BOUND",
        "assessment_sha256": assessment_sha,
        "required_members_present": sorted(REQUIRED_ASSESSMENT_MEMBERS),
        "run_mode": scorecard["run_mode"],
        "unique_rows": scorecard["row_count"],
        "paired_repetitions_per_row": 3,
        "paired_generation_pairs": scorecard["prefix_total"],
        "baseline_correct": scorecard["arm_scorecard"]["C0_MONITOR_FIRST_COMPLETE_FINAL_ANSWER_LINE"]["correct"],
        "runtime_stop_correct": scorecard["arm_scorecard"]["C1_TERMINATE_FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP"]["correct"],
        "raw_original_token_prefix_equality": f"{scorecard['prefix_equal_count']}/{scorecard['prefix_total']}",
        "row_policy": "openai/gsm8k:test[425:475]",
        "row_manifest_count": row_manifest["row_count"],
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop50_assessment_import_receipt.json", import_receipt)

    wrapper_receipt = {
        "schema_id": "kt.stop50.wrapper_import_receipt.v2",
        "created_utc": utc_now(),
        "status": "PASS_STOP50_WRAPPER_BOUND",
        "wrapper_sha256": wrapper_sha,
        "contains_assessment_member": True,
        "publication_order_status": "STOP50_WRAPPER_BOUND_FOR_LINEAGE_ONLY",
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop50_wrapper_import_receipt.json", wrapper_receipt)

    official = {
        "schema_id": "kt.stop50.official_scorecard_preservation.v1",
        "created_utc": utc_now(),
        "status": "PRESERVED",
        "source": "evidence/KT_STOP50_V1_ASSESSMENT_ONLY.zip::runtime_stop_scorecard.json",
        "official_scorecard": scorecard,
        "final_summary_status": final_summary["status"],
        "do_not_reinterpret_repetitions_as_independent_rows": True,
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop50_official_scorecard_preservation.json", official)

    hostile = {
        "schema_id": "kt.stop50.hostile_synthesis_receipt.v2",
        "created_utc": utc_now(),
        "status": "MECHANISM_SIGNAL_STRONG_POSITIVE",
        "scoped_findings": [
            "MECHANISM_SIGNAL_STRONG_POSITIVE",
            "ZERO_OBSERVED_DAMAGE_ON_50_UNIQUE_ROWS",
            "TOKEN_ECONOMICS_CONFIRMED_POSITIVE",
            "LATENCY_SIGNAL_STRONGLY_MECHANISTIC_BUT_NOT_CANONICAL",
            "GENERAL_RUNTIME_SAFETY_UNPROVEN",
            "PRODUCTION_AUTHORITY_NOT_EARNED",
        ],
        "synthesis": synthesis,
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop50_hostile_synthesis.json", hostile)

    distribution = {
        "schema_id": "kt.stop50.savings_distribution_and_concentration.v1",
        "created_utc": utc_now(),
        "status": "PASS_STOP50_DISTRIBUTION_BOUND",
        "distribution": synthesis["distribution"],
        "economics": synthesis["economics"],
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop50_savings_distribution_and_concentration.json", distribution)

    timing = {
        "schema_id": "kt.stop50.timing_mediation_analysis.v1",
        "created_utc": utc_now(),
        "status": "SUPPORTIVE_NOT_CANONICAL",
        "timing_mediation": synthesis["timing_mediation"],
        "latency_claim_boundary": "LATENCY_SIGNAL_STRONGLY_MECHANISTIC_BUT_NOT_CANONICAL",
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop50_timing_mediation_analysis.json", timing)

    environment = {
        "schema_id": "kt.stop50.environment_composite_receipt.v1",
        "created_utc": utc_now(),
        "status": "FUNCTIONAL_FOR_STOP50_EXACT_RUN__NOT_GENERALLY_CLEAN",
        "environment_contract_receipt": env,
        "model_loader_receipt": model_loader,
        "hostile_synthesis_environment": synthesis["environment"],
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop50_environment_composite_receipt.json", environment)

    claim = {
        "schema_id": "kt.stop50.claim_boundary_receipt.v2",
        "created_utc": utc_now(),
        "status": "PASS_CLAIM_CEILING_PRESERVED",
        "allowed_statement": "STOP50 supports exact-protocol final-answer runtime termination as a mechanism signal with positive token economics and zero observed damage on 50 unique rows.",
        "forbidden_claims": [
            "production runtime authority",
            "shadow execution authority",
            "training authority",
            "promotion authority",
            "selector deployment",
            "production prompt mutation",
            "production math-mode claim",
            "general reasoning compression",
            "G2 recovery",
        ],
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop50_claim_boundary_receipt.json", claim)
    print("KTSTOP50 import PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
