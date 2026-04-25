from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator._gate_f_fixtures import seed_gate_f_base
from tools.operator import cohort0_post_f_track_01_comparator_matrix_packet_tranche as tranche
from tools.operator import cohort0_post_f_track_01_comparative_scope_packet_tranche as scope_tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_post_f_track_01_comparator_matrix_binds(tmp_path: Path, monkeypatch) -> None:
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
        reports / scope_tranche.OUTPUT_PACKET,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_comparative_scope_packet.v1",
            "status": "PASS",
            "scope_outcome": scope_tranche.SCOPE_OUTCOME,
            "subject_head": "head-123",
            "next_lawful_move": "AUTHOR_POST_F_TRACK_01_COMPARATOR_MATRIX_PACKET",
            "authority_header": {
                "canonical_authority_branch": "main",
                "working_branch": "expansion/post-f-track-01",
                "working_branch_non_authoritative_until_protected_merge": True,
                "gate_d_cleared_on_successor_line": True,
                "gate_e_open_on_successor_line": True,
                "gate_f_narrow_wedge_confirmed": True,
                "gate_f_open": False,
            },
            "confirmed_canonical_surface": {
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
                "support_tier": "BOUNDED_E1_OPERATOR_GUIDANCE_ONLY",
                "tenant_posture": "SINGLE_TENANT_ONLY_DECLARED",
            },
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: "expansion/post-f-track-01")

    result = tranche.run(
        reports_root=reports,
        scope_packet_path=reports / scope_tranche.OUTPUT_PACKET,
        live_product_truth_packet_path=reports / "cohort0_gate_f_post_close_live_product_truth_packet.json",
        post_merge_closeout_receipt_path=reports / "cohort0_post_merge_closeout_receipt.json",
    )

    assert result["matrix_outcome"] == tranche.MATRIX_OUTCOME

    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert len(packet["active_comparator_rows"]) == 3
    assert packet["active_comparator_rows"][0]["row_id"] == "KT_CANONICAL_WEDGE"
    assert packet["metric_schema"]["counting_metrics"][0]["metric_id"] == "receipt_completeness"
    assert "No broad reasoning or model superiority claim." in packet["forbidden_score_interpretations"]
    assert receipt["metric_count"] == 5
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
