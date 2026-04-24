from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator._gate_f_fixtures import seed_gate_f_base
from tools.operator import cohort0_post_f_track_01_comparative_scope_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_post_f_track_01_comparative_scope_binds(tmp_path: Path, monkeypatch) -> None:
    reports = seed_gate_f_base(tmp_path)
    _write_json(
        reports / "cohort0_gate_f_post_close_live_product_truth_packet.json",
        {
            "schema_id": "kt.operator.cohort0_gate_f_post_close_live_product_truth_packet.v1",
            "status": "PASS",
            "subject_head": "head-123",
            "canonical_live_product_status": {
                "current_product_posture": "GATE_F_ONE_NARROW_WEDGE_CONFIRMED__LOCAL_VERIFIER_MODE_ONLY",
                "gate_d_cleared_on_successor_line": True,
                "gate_e_open_on_successor_line": True,
                "gate_f_narrow_wedge_confirmed": True,
                "gate_f_open": False,
                "support_tier": "BOUNDED_E1_OPERATOR_GUIDANCE_ONLY",
                "tenant_posture": "SINGLE_TENANT_ONLY_DECLARED",
            },
            "selected_wedge_summary": {
                "wedge_id": "KT_F_NARROW_LOCAL_VERIFIER_EXECUTE_RECEIPT_WEDGE_V1",
                "active_profile_id": "local_verifier_mode",
                "surface_summary": "Single-tenant same-host verifier-backed execution request, receipt retrieval, and replay-kit handoff.",
                "verify_command": "python -m tools.operator.public_verifier",
                "receipt_must_return": [
                    "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
                    "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
                    "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json",
                ],
                "supported_actions": [
                    "submit_bounded_verification_request",
                    "retrieve_pass_fail_receipt",
                    "retrieve_bounded_audit_packet",
                    "retrieve_replay_kit_refs",
                ],
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_broad_canonical_reaudit_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_broad_canonical_reaudit_receipt.v1",
            "status": "PASS",
            "minimum_path_complete_through_gate_f": True,
            "controlled_post_f_expansion_tracks_authorized_now": True,
        },
    )
    _write_json(
        reports / "cohort0_post_merge_closeout_receipt.json",
        {
            "status": "PASS__CANONICAL_CLEAN_CLOSEOUT_MERGED_TO_MAIN",
            "gate_d_cleared_on_successor_line": True,
            "gate_e_open_on_successor_line": True,
            "gate_f_open": False,
            "gate_f_one_narrow_wedge_confirmed_local_verifier_mode_only": True,
            "post_f_broad_canonical_reaudit_pass": True,
        },
    )
    _write_json(
        reports / "cohort0_successor_master_orchestrator_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_successor_master_orchestrator_receipt.v1",
            "status": "PASS",
            "subject_head": "head-123",
            "current_branch_posture": "GATE_E_OPEN__POST_SUCCESSOR_GATE_D_CLEAR",
            "current_product_posture": "GATE_F_ONE_NARROW_WEDGE_CONFIRMED__LOCAL_VERIFIER_MODE_ONLY",
            "gate_e_open": True,
            "gate_f_narrow_wedge_confirmed": True,
            "gate_f_open": False,
            "minimum_path_complete_through_gate_f": True,
            "post_f_broad_canonical_reaudit_passed": True,
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: "expansion/post-f-track-01")

    result = tranche.run(
        reports_root=reports,
        live_product_truth_packet_path=reports / "cohort0_gate_f_post_close_live_product_truth_packet.json",
        post_f_reaudit_receipt_path=reports / "cohort0_post_f_broad_canonical_reaudit_receipt.json",
        post_merge_closeout_receipt_path=reports / "cohort0_post_merge_closeout_receipt.json",
        orchestrator_receipt_path=reports / "cohort0_successor_master_orchestrator_receipt.json",
    )

    assert result["scope_outcome"] == tranche.SCOPE_OUTCOME

    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert packet["track_identity"]["track_id"] == tranche.TRACK_ID
    assert packet["authority_header"]["working_branch_non_authoritative_until_protected_merge"] is True
    assert packet["confirmed_canonical_surface"]["active_profile_id"] == "local_verifier_mode"
    assert packet["comparison_category"]["category_id"] == "GOVERNED_RECEIPT_BACKED_FAIL_CLOSED_EXECUTION_UNDER_LAW"
    assert "best_ai_overall" in packet["forbidden_claims"]
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
