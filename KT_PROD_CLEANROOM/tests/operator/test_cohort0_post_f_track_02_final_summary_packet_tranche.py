from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_track_02_final_summary_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_track_02_final_summary_binds_english_closure(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"

    _write_json(
        reports / "cohort0_post_f_track_02_dual_audit_scope_packet.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_scope_packet.v1",
            "status": "PASS",
            "subject_head": "head-123",
            "authority_header": {
                "canonical_authority_branch": "main",
                "working_branch": "expansion/post-f-track-01",
                "working_branch_non_authoritative_until_protected_merge": True,
                "gate_d_cleared_on_successor_line": True,
                "gate_e_open_on_successor_line": True,
                "gate_f_narrow_wedge_confirmed": True,
                "gate_f_open": False,
                "post_f_reaudit_passed": True,
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_dual_audit_execution_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_execution_receipt.v1",
            "status": "PASS",
            "next_lawful_move": "AUTHOR_POST_F_TRACK_02_FINAL_SUMMARY_PACKET",
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_frozen_baseline_audit_packet.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_frozen_baseline_audit_packet.v1",
            "status": "PASS",
            "scope_1_repo_only": {"ruling": "Repo ruling"},
            "scope_2_system_with_receipts": {"ruling": "System ruling"},
            "scope_3_bounded_audited_target": {"ruling": "Target ruling"},
            "scope_4_commercial_product_market_reality": {"ruling": "Commercial ruling"},
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_frozen_baseline_audit_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_frozen_baseline_audit_receipt.v1",
            "status": "PASS",
            "anchor_commit": "baseline-sha",
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_current_truth_audit_packet.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_current_truth_audit_packet.v1",
            "status": "PASS",
            "top_level_verdict": "CURRENT_VERDICT",
            "current_truth_overrides_binding": {
                "gate_d_cleared_on_successor_line": True,
                "gate_e_open_on_successor_line": True,
                "gate_f_narrow_wedge_confirmed_local_verifier_mode_only": True,
                "gate_f_not_broadly_open": True,
                "post_f_broad_canonical_reaudit_passed": True,
                "track_01_closed_as_bounded_comparative_proof_packet": True,
            },
            "section_1_present_standing_reconstruction": {
                "current_head_standing": {"branch": "expansion/post-f-track-01"},
                "unresolved_blockers_preventing_wider_claims": [{"blocker_id": "H1_ACTIVATION_GATE_CLOSED"}],
            },
            "section_2_six_scope_scorecards": {
                "scope_1_current_head_sovereign_control_plane": {"score": "A-"},
                "scope_2_current_head_runtime_capability_plane": {"score": "C+"},
                "scope_3_historical_bounded_frontier_target": {"score": "B+"},
                "scope_4_full_system_civilization_execution_readiness": {"score": "D+"},
                "scope_5_product_commercial_standing": {"score": "D"},
                "scope_6_net_integrated_standing": {"score": "C+"},
            },
            "section_7_final_verdict": {
                "single_sentence_verdict": "Strong governance, bounded proof, weak commercial standing."
            },
            "section_9_benchmark_readiness_map": {
                "ready_now": ["bounded comparator"],
                "not_ready": ["public leaderboard"],
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_current_truth_audit_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_current_truth_audit_receipt.v1",
            "status": "PASS",
            "anchor_commit": "current-sha",
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_dual_audit_delta_crosswalk.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_delta_crosswalk.v1",
            "status": "PASS",
            "preserve_separate_verdicts": True,
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_dual_audit_delta_crosswalk_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_delta_crosswalk_receipt.v1",
            "status": "PASS",
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_dual_audit_meta_summary.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_meta_summary.v1",
            "status": "PASS",
            "baseline_audit_reference": {"top_level_verdict": "BASELINE_VERDICT"},
            "current_truth_audit_reference": {
                "top_level_verdict": "CURRENT_VERDICT",
                "single_sentence_verdict": "Strong governance, bounded proof, weak commercial standing.",
            },
            "delta_crosswalk_reference": {
                "key_delta_finding": "Track 01 is the main improvement.",
                "axes_that_improved": ["historical_bounded_proof"],
                "axes_unchanged": ["commercial_product_truth"],
                "axes_maintained_excellent": ["claim_safety"],
            },
            "forbidden_behaviors_compliance": {
                "baseline_and_current_truth_verdicts_not_blended": True,
            },
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: "expansion/post-f-track-01")
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    result = tranche.run(
        reports_root=reports,
        scope_packet_path=reports / "cohort0_post_f_track_02_dual_audit_scope_packet.json",
        execution_receipt_path=reports / "cohort0_post_f_track_02_dual_audit_execution_receipt.json",
        baseline_packet_path=reports / "cohort0_post_f_track_02_frozen_baseline_audit_packet.json",
        baseline_receipt_path=reports / "cohort0_post_f_track_02_frozen_baseline_audit_receipt.json",
        current_packet_path=reports / "cohort0_post_f_track_02_current_truth_audit_packet.json",
        current_receipt_path=reports / "cohort0_post_f_track_02_current_truth_audit_receipt.json",
        delta_crosswalk_path=reports / "cohort0_post_f_track_02_dual_audit_delta_crosswalk.json",
        delta_receipt_path=reports / "cohort0_post_f_track_02_dual_audit_delta_crosswalk_receipt.json",
        meta_summary_path=reports / "cohort0_post_f_track_02_dual_audit_meta_summary.json",
    )

    assert result["summary_outcome"] == tranche.SUMMARY_OUTCOME

    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert packet["english_executive_brief"]["blunt_system_read"].startswith("KT is a serious governance-first AI system")
    assert packet["explicit_final_answers"]["frontier_grade"]["answer"] is False
    assert packet["next_lawful_move"] == tranche.NEXT_MOVE
    assert receipt["english_executive_brief_bound"] is True
