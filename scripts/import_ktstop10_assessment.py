from __future__ import annotations

import zipfile

from ktstoprt_common import (
    ACTIVE_TRANCHE,
    ASSESSMENT,
    ASSESSMENT_SHA256,
    REPORTS,
    SOURCE_PACKET,
    SOURCE_PACKET_SHA256,
    assert_hash,
    authority_payload,
    git_output,
    load_assessment_json,
    rel,
    utc_now,
    write_json,
)


def main() -> int:
    assessment_sha = assert_hash(ASSESSMENT, ASSESSMENT_SHA256, "KT_STOP10_V1_ASSESSMENT_ONLY.zip")
    source_sha = assert_hash(SOURCE_PACKET, SOURCE_PACKET_SHA256, "ktstop10_v1.zip")
    with zipfile.ZipFile(ASSESSMENT) as zf:
        members = sorted(zf.namelist())
    final_summary = load_assessment_json("final_summary.json")
    scorecard = load_assessment_json("stopseq_scorecard.json")
    truth = {
        "schema_id": "kt.ktstoprt.truth_pin.v1",
        "created_utc": utc_now(),
        "active_tranche": ACTIVE_TRANCHE,
        "current_head": git_output("rev-parse", "HEAD"),
        "current_branch": git_output("branch", "--show-current"),
        "pre_lane_worktree_clean_observed": True,
        "worktree_porcelain_at_import_runtime": git_output("status", "--porcelain=v1"),
        "live_repo_truth_wins": True,
        **authority_payload(),
    }
    receipt = {
        "schema_id": "kt.ktstoprt.assessment_import_receipt.v1",
        "status": "PASS",
        "assessment_path": rel(ASSESSMENT),
        "assessment_sha256": assessment_sha,
        "source_packet_path": rel(SOURCE_PACKET),
        "source_packet_sha256": source_sha,
        "members": members,
        "final_summary_status": final_summary.get("status"),
        "scorecard_pass_gate": scorecard.get("pass_gate"),
        **authority_payload(),
    }
    source_binding = {
        "schema_id": "kt.ktstoprt.source_binding_receipt.v1",
        "status": "PASS",
        "source_packet": rel(SOURCE_PACKET),
        "source_packet_sha256": source_sha,
        "source_run_mode": "RUN_STOPSEQ_10ROW_PROMPT_PROBE_V1",
        "source_assessment": rel(ASSESSMENT),
        "source_assessment_sha256": assessment_sha,
        "source_hf_result": "https://huggingface.co/datasets/Kinrokin/ktstop10-v1-results",
        **authority_payload(),
    }
    live_delta = {
        "schema_id": "kt.ktstoprt.live_repo_delta_if_any.v1",
        "status": "NO_DELTA_FROM_PACKET_AUTHORED_HEAD" if truth["current_head"] == "669a4d9161fd15f3a0bfcde264014a82ce108348" else "LIVE_MAIN_MOVED_DELTA_BOUND",
        "packet_authored_head": "669a4d9161fd15f3a0bfcde264014a82ce108348",
        "current_head": truth["current_head"],
        **authority_payload(),
    }
    claim = {
        "schema_id": "kt.ktstoprt.claim_boundary_receipt.v1",
        "status": "PASS",
        "allowed_claim": "STOP10 prompt-only stop instruction was imported and rejected as a prompt-only runtime substitute; KTSTOPRT may test code-level sandbox termination only.",
        "blocked_claims": [
            "production runtime readiness",
            "production math-mode claim",
            "prompt superiority",
            "compression frontier gain",
            "training or promotion authority",
        ],
        **authority_payload(),
    }
    write_json(REPORTS / "ktstoprt_truth_pin.json", truth)
    write_json(REPORTS / "ktstoprt_assessment_import_receipt.json", receipt)
    write_json(REPORTS / "ktstoprt_source_binding_receipt.json", source_binding)
    write_json(REPORTS / "ktstoprt_live_repo_delta_if_any.json", live_delta)
    write_json(REPORTS / "ktstoprt_claim_boundary_receipt.json", claim)
    print(receipt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
