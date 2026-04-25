from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator._gate_f_fixtures import seed_gate_f_base
from tools.operator import cohort0_post_f_track_01_comparative_scope_packet_tranche as scope_tranche
from tools.operator import cohort0_post_f_track_01_comparator_matrix_packet_tranche as matrix_tranche
from tools.operator import cohort0_post_f_track_01_metric_scorecard_contract_tranche as contract_tranche
from tools.operator import cohort0_post_f_track_01_first_bounded_comparative_execution_tranche as first_wave
from tools.operator import cohort0_post_f_track_01_second_bounded_comparative_execution_tranche as second_wave
from tools.operator import cohort0_post_f_track_01_final_summary_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_post_f_track_01_final_summary_packet_binds(tmp_path: Path, monkeypatch) -> None:
    reports = seed_gate_f_base(tmp_path)

    _write_json(
        reports / scope_tranche.OUTPUT_PACKET,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_comparative_scope_packet.v1",
            "status": "PASS",
            "scope_outcome": scope_tranche.SCOPE_OUTCOME,
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
            "comparison_category": {
                "category_id": "GOVERNED_RECEIPT_BACKED_FAIL_CLOSED_EXECUTION_UNDER_LAW",
            },
            "confirmed_canonical_surface": {
                "wedge_id": "KT_F_NARROW_LOCAL_VERIFIER_EXECUTE_RECEIPT_WEDGE_V1",
                "active_profile_id": "local_verifier_mode",
            },
        },
    )
    _write_json(
        reports / matrix_tranche.OUTPUT_PACKET,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_comparator_matrix_packet.v1",
            "status": "PASS",
            "matrix_outcome": matrix_tranche.MATRIX_OUTCOME,
        },
    )
    _write_json(
        reports / contract_tranche.OUTPUT_PACKET,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_metric_scorecard_contract.v1",
            "status": "PASS",
            "contract_outcome": contract_tranche.CONTRACT_OUTCOME,
            "metric_rules": [{}, {}, {}, {}, {}],
        },
    )
    _write_json(
        reports / first_wave.OUTPUT_PACKET,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_first_bounded_comparative_execution_packet.v1",
            "status": "PASS",
        },
    )
    _write_json(
        reports / first_wave.OUTPUT_RECEIPT,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_first_bounded_comparative_execution_receipt.v1",
            "status": "PASS",
            "subject_head": "head-123",
            "verdict": "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR",
        },
    )
    _write_json(
        reports / first_wave.OUTPUT_SCORECARD,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_first_bounded_comparative_scorecard.v1",
            "status": "PASS",
        },
    )
    _write_json(
        reports / first_wave.OUTPUT_VERDICT,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_comparative_verdict_receipt.v1",
            "status": "PASS",
            "verdict": "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR",
        },
    )
    _write_json(
        reports / first_wave.OUTPUT_KT_ROW,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_row_receipt.v1",
            "status": "PASS",
            "row_id": "KT_CANONICAL_WEDGE",
            "category_fair": True,
            "row_class": "PASS",
            "weighted_score": 26,
            "normalized_score": 1.0,
        },
    )
    _write_json(
        reports / first_wave.OUTPUT_INTERNAL_ROW,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_row_receipt.v1",
            "status": "PASS",
            "row_id": "STRONGEST_APPROVED_STATIC_INTERNAL_BASELINE",
            "category_fair": True,
            "row_class": "PARTIAL",
            "weighted_score": 19,
            "normalized_score": 0.7308,
        },
    )
    _write_json(
        reports / first_wave.OUTPUT_EXTERNAL_ROW,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_row_receipt.v1",
            "status": "PASS",
            "row_id": "ONE_CATEGORY_FAIR_EXTERNAL_MONOLITH_WORKFLOW",
            "category_fair": True,
            "row_class": "PARTIAL",
            "weighted_score": 19,
            "normalized_score": 0.7308,
        },
    )
    _write_json(
        reports / second_wave.OUTPUT_VARIATION,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_second_wave_variation_receipt.v1",
            "status": "PASS",
            "variation_id": second_wave.VARIATION_ID,
            "variation_type": "REPLAY_AND_OPERATOR_HANDOFF_STRESS",
            "same_three_row_matrix": True,
            "same_five_metric_contract": True,
        },
    )
    _write_json(
        reports / second_wave.OUTPUT_PACKET,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_second_bounded_comparative_execution_packet.v1",
            "status": "PASS",
        },
    )
    _write_json(
        reports / second_wave.OUTPUT_RECEIPT,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_second_bounded_comparative_execution_receipt.v1",
            "status": "PASS",
            "subject_head": "head-123",
            "verdict": "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR",
            "next_lawful_move": "AUTHOR_POST_F_TRACK_01_FINAL_SUMMARY_PACKET",
        },
    )
    _write_json(
        reports / second_wave.OUTPUT_SCORECARD,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_second_bounded_comparative_scorecard.v1",
            "status": "PASS",
        },
    )
    _write_json(
        reports / second_wave.OUTPUT_VERDICT,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_second_bounded_comparative_verdict_receipt.v1",
            "status": "PASS",
            "verdict": "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR",
        },
    )
    _write_json(
        reports / second_wave.OUTPUT_KT_ROW,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_second_wave_row_receipt.v1",
            "status": "PASS",
            "row_id": "KT_CANONICAL_WEDGE",
            "category_fair": True,
            "row_class": "PASS",
            "weighted_score": 26,
            "normalized_score": 1.0,
        },
    )
    _write_json(
        reports / second_wave.OUTPUT_INTERNAL_ROW,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_second_wave_row_receipt.v1",
            "status": "PASS",
            "row_id": "STRONGEST_APPROVED_STATIC_INTERNAL_BASELINE",
            "category_fair": True,
            "row_class": "PARTIAL",
            "weighted_score": 16,
            "normalized_score": 0.6154,
        },
    )
    _write_json(
        reports / second_wave.OUTPUT_EXTERNAL_ROW,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_second_wave_row_receipt.v1",
            "status": "PASS",
            "row_id": "ONE_CATEGORY_FAIR_EXTERNAL_MONOLITH_WORKFLOW",
            "category_fair": True,
            "row_class": "PARTIAL",
            "weighted_score": 19,
            "normalized_score": 0.7308,
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: "expansion/post-f-track-01")

    result = tranche.run(
        reports_root=reports,
        scope_packet_path=reports / scope_tranche.OUTPUT_PACKET,
        matrix_packet_path=reports / matrix_tranche.OUTPUT_PACKET,
        contract_packet_path=reports / contract_tranche.OUTPUT_PACKET,
        first_execution_packet_path=reports / first_wave.OUTPUT_PACKET,
        first_execution_receipt_path=reports / first_wave.OUTPUT_RECEIPT,
        first_scorecard_path=reports / first_wave.OUTPUT_SCORECARD,
        first_verdict_path=reports / first_wave.OUTPUT_VERDICT,
        first_kt_row_path=reports / first_wave.OUTPUT_KT_ROW,
        first_internal_row_path=reports / first_wave.OUTPUT_INTERNAL_ROW,
        first_external_row_path=reports / first_wave.OUTPUT_EXTERNAL_ROW,
        second_variation_receipt_path=reports / second_wave.OUTPUT_VARIATION,
        second_execution_packet_path=reports / second_wave.OUTPUT_PACKET,
        second_execution_receipt_path=reports / second_wave.OUTPUT_RECEIPT,
        second_scorecard_path=reports / second_wave.OUTPUT_SCORECARD,
        second_verdict_path=reports / second_wave.OUTPUT_VERDICT,
        second_kt_row_path=reports / second_wave.OUTPUT_KT_ROW,
        second_internal_row_path=reports / second_wave.OUTPUT_INTERNAL_ROW,
        second_external_row_path=reports / second_wave.OUTPUT_EXTERNAL_ROW,
    )

    assert result["summary_outcome"] == tranche.SUMMARY_OUTCOME

    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert packet["final_track_verdict"]["waves_executed"] == 2
    assert packet["final_track_verdict"]["holds_under_replay_and_operator_handoff_stress"] is True
    assert packet["final_track_verdict"]["first_wave_verdict"] == "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR"
    assert packet["final_track_verdict"]["second_wave_verdict"] == "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR"
    assert packet["bound_track_stack"]["first_wave"]["row_summaries"][0]["weighted_score"] == 26
    assert packet["bound_track_stack"]["second_wave"]["row_summaries"][1]["weighted_score"] == 16
    assert "Not Kaggle or math carryover." in packet["forbidden_interpretations"]
    assert receipt["repeated_advantage_confirmed"] is True
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
