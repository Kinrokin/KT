from __future__ import annotations

import hashlib
import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator._gate_f_fixtures import seed_gate_f_base
from tools.operator import cohort0_post_f_track_02_frozen_baseline_and_current_truth_audits_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_track_02_dual_audits_preserve_separate_verdicts(tmp_path: Path, monkeypatch) -> None:
    reports = seed_gate_f_base(tmp_path)
    prompts = tmp_path / "prompts"
    baseline_prompt = prompts / "baseline_scope_normalized_v3_1.md"
    current_prompt = prompts / "current_truth_hardened_post_f_v1.md"
    work_order = tmp_path / "cohort0_post_f_track_02_dual_audit_work_order_v2.json"

    _write_text(baseline_prompt, "baseline prompt\n")
    _write_text(current_prompt, "current prompt\n")
    baseline_sha = hashlib.sha256(baseline_prompt.read_bytes()).hexdigest()
    current_sha = hashlib.sha256(current_prompt.read_bytes()).hexdigest()

    _write_json(
        reports / "cohort0_gate_f_post_close_live_product_truth_packet.json",
        {
            "schema_id": "kt.operator.cohort0_gate_f_post_close_live_product_truth_packet.v1",
            "status": "PASS",
            "canonical_live_product_status": {
                "gate_f_narrow_wedge_confirmed": True,
                "gate_f_open": False,
                "active_profile_id": "local_verifier_mode",
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_broad_canonical_reaudit_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_broad_canonical_reaudit_receipt.v1",
            "status": "PASS",
            "minimum_path_complete_through_gate_f": True,
            "reaudit_outcome": "POST_F_BROAD_CANONICAL_REAUDIT_PASS__MINIMUM_PATH_COMPLETE",
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_01_final_summary_packet.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_final_summary_packet.v1",
            "status": "PASS",
            "summary_outcome": "POST_F_TRACK_01_REPEATED_BOUNDED_ADVANTAGE_FROZEN__CANONICAL_WEDGE_ONLY",
            "final_track_verdict": {
                "statement": "KT canonical wedge has repeated bounded category-fair advantage on the confirmed local_verifier_mode surface, including replay-and-operator-handoff stress."
            },
        },
    )

    _write_json(
        work_order,
        {
            "schema_version": "1.1.0",
            "work_order_id": "cohort0_post_f_track_02_dual_audit_work_order",
            "audit_runs": [
                {
                    "run_id": "frozen_baseline_audit",
                    "evidence_view_mode": "frozen_baseline_view",
                    "expected_axes": [
                        "audit_evidence_set",
                        "timeline_reconstruction",
                        "authoritative_vs_stale_artifacts",
                        "scope_1_repo_only",
                    ],
                    "outputs": {
                        "verdict_path": "${KT_ROOT:-.}/KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_frozen_baseline_audit_packet.json",
                        "receipt_path": "${KT_ROOT:-.}/KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_frozen_baseline_audit_receipt.json",
                        "blocker_ledger_path": "${KT_ROOT:-.}/KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_frozen_baseline_blocker_ledger.json",
                    },
                },
                {
                    "run_id": "hardened_current_truth_audit",
                    "evidence_view_mode": "current_truth_live_view",
                    "authorized_current_truth_classes": [
                        "live_header_packets",
                        "gate_d_gate_e_gate_f_receipts",
                        "post_f_live_product_truth",
                        "post_f_broad_canonical_reaudit_receipt",
                        "track_01_final_summary_packet",
                        "orchestrator_receipt_and_predicate_board",
                        "supersession_notes",
                    ],
                    "expected_axes": [
                        "present_standing_reconstruction",
                        "six_scope_scorecards",
                        "top_50_weaknesses",
                    ],
                    "outputs": {
                        "verdict_path": "${KT_ROOT:-.}/KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_current_truth_audit_packet.json",
                        "receipt_path": "${KT_ROOT:-.}/KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_current_truth_audit_receipt.json",
                        "blocker_ledger_path": "${KT_ROOT:-.}/KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_current_truth_blocker_ledger.json",
                    },
                },
            ],
            "delta_crosswalk": {
                "output_path": "${KT_ROOT:-.}/KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_dual_audit_delta_crosswalk.json",
                "receipt_path": "${KT_ROOT:-.}/KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_dual_audit_delta_crosswalk_receipt.json",
            },
            "meta_summary": {
                "output_path": "${KT_ROOT:-.}/KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_dual_audit_meta_summary.json",
                "rules": [
                    "may summarize but may not collapse separate verdicts",
                    "must preserve the frozen baseline as the static ruler",
                ],
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_dual_audit_scope_packet.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_scope_packet.v1",
            "status": "PASS",
            "scope_outcome": "POST_F_TRACK_02_DUAL_AUDIT_SCOPE_DEFINED__SEPARATE_BASELINE_AND_CURRENT_TRUTH_VERDICTS",
            "track_identity": {"working_branch": "expansion/post-f-track-01"},
            "work_order_binding": {
                "work_order_path": work_order.as_posix(),
            },
            "anchor_binding": {
                "frozen_baseline": {"ref_name": "kt-post-f-reaudit-pass"},
                "current_truth": {"ref_name": "expansion/post-f-track-01"},
            },
            "prompt_artifact_binding": {
                "baseline_frozen": {
                    "source_path": baseline_prompt.as_posix(),
                    "expected_sha256": baseline_sha,
                },
                "current_truth_hardened": {
                    "source_path": current_prompt.as_posix(),
                    "expected_sha256": current_sha,
                },
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_shared_evidence_harvest_and_authority_partition_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_shared_evidence_harvest_and_authority_partition_receipt.v1",
            "status": "PASS",
            "next_lawful_move": "EXECUTE_POST_F_TRACK_02_FROZEN_BASELINE_AND_CURRENT_TRUTH_AUDITS",
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_dual_audit_evidence_manifest.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_evidence_manifest.v1",
            "status": "PASS",
            "source_summaries": [{"source_id": "git_state"}, {"source_id": "cleanroom_reports"}],
            "evidence_entries": [{"artifact_ref": "a"}],
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_dual_audit_authority_partition.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_authority_partition.v1",
            "status": "PASS",
            "authoritative_current_truth_paths": [
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_01_final_summary_packet.json",
                "KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_dual_audit_scope_packet.json",
            ],
            "view_rules": {
                "baseline_view_rejects_post_anchor_authority": True,
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_frozen_baseline_evidence_view.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_frozen_baseline_evidence_view.v1",
            "status": "PASS",
            "anchor_commit": "baseline-sha",
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_current_truth_evidence_view.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_current_truth_evidence_view.v1",
            "status": "PASS",
            "anchor_commit": "current-sha",
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: "expansion/post-f-track-01")
    monkeypatch.setattr(
        tranche,
        "_git_status_porcelain",
        lambda root: "\n".join(
            [
                "?? KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_dual_audit_evidence_manifest.json",
                "?? KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_dual_audit_content_hash_manifest.json",
                "?? KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_dual_audit_authority_partition.json",
                "?? KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_frozen_baseline_evidence_view.json",
                "?? KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_current_truth_evidence_view.json",
                "?? KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_shared_evidence_harvest_and_authority_partition_packet.json",
                "?? KT_PROD_CLEANROOM/reports/cohort0_post_f_track_02_shared_evidence_harvest_and_authority_partition_receipt.json",
                "?? KT_PROD_CLEANROOM/reports/COHORT0_POST_F_TRACK_02_SHARED_EVIDENCE_HARVEST_AND_AUTHORITY_PARTITION_REPORT.md",
            ]
        ),
    )

    result = tranche.run(
        reports_root=reports,
        scope_packet_path=reports / "cohort0_post_f_track_02_dual_audit_scope_packet.json",
        harvest_receipt_path=reports / "cohort0_post_f_track_02_shared_evidence_harvest_and_authority_partition_receipt.json",
    )

    assert result["execution_outcome"] == tranche.EXECUTION_OUTCOME

    baseline_packet = _load(reports / "cohort0_post_f_track_02_frozen_baseline_audit_packet.json")
    current_packet = _load(reports / "cohort0_post_f_track_02_current_truth_audit_packet.json")
    delta = _load(reports / "cohort0_post_f_track_02_dual_audit_delta_crosswalk.json")
    meta = _load(reports / "cohort0_post_f_track_02_dual_audit_meta_summary.json")
    execution_receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert baseline_packet["execution_status"] == tranche.BASELINE_EXECUTION_STATUS
    assert current_packet["execution_status"] == tranche.CURRENT_EXECUTION_STATUS
    assert delta["preserve_separate_verdicts"] is True
    assert meta["current_truth_audit_reference"]["current_truth_audit_is_footing_audit_not_baseline_replacement"] is True
    assert execution_receipt["next_lawful_move"] == tranche.NEXT_MOVE
