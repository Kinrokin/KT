from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator._gate_f_fixtures import seed_gate_f_base
from tools.operator import cohort0_post_f_track_01_first_bounded_comparative_execution_tranche as first_wave
from tools.operator import cohort0_post_f_track_01_metric_scorecard_contract_tranche as contract_tranche
from tools.operator import cohort0_post_f_track_01_second_bounded_comparative_execution_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_post_f_track_01_second_bounded_comparative_execution_binds(tmp_path: Path, monkeypatch) -> None:
    reports = seed_gate_f_base(tmp_path)
    product = tmp_path / "KT_PROD_CLEANROOM" / "product"
    docs_operator = tmp_path / "KT_PROD_CLEANROOM" / "docs" / "operator"

    _write_json(
        reports / "public_verifier_manifest.json",
        {
            "schema_id": "kt.public_verifier_manifest.v4",
            "status": "PASS",
        },
    )
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
            },
            "selected_wedge_summary": {
                "wedge_id": "KT_F_NARROW_LOCAL_VERIFIER_EXECUTE_RECEIPT_WEDGE_V1",
                "active_profile_id": "local_verifier_mode",
            },
        },
    )
    _write_json(
        reports / contract_tranche.matrix_tranche.OUTPUT_PACKET,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_comparator_matrix_packet.v1",
            "status": "PASS",
            "matrix_outcome": contract_tranche.matrix_tranche.MATRIX_OUTCOME,
        },
    )
    _write_json(
        reports / contract_tranche.OUTPUT_PACKET,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_metric_scorecard_contract.v1",
            "status": "PASS",
            "contract_outcome": contract_tranche.CONTRACT_OUTCOME,
            "subject_head": "head-123",
            "score_states": {
                "PASS": {"points": 2},
                "PARTIAL": {"points": 1},
                "FAIL": {"points": 0},
                "DEFERRED": {"points": None},
            },
            "metric_rules": [
                {"metric_id": "receipt_completeness", "weight": 3, "hard_stop": True, "scoring_rule": {}},
                {"metric_id": "replayability", "weight": 3, "hard_stop": True, "scoring_rule": {}},
                {"metric_id": "fail_closed_behavior", "weight": 3, "hard_stop": True, "scoring_rule": {}},
                {"metric_id": "operator_clarity_and_bounded_execution_integrity", "weight": 2, "hard_stop": False, "scoring_rule": {}},
                {"metric_id": "useful_output_success_under_wedge_contract", "weight": 2, "hard_stop": False, "scoring_rule": {}},
            ],
        },
    )
    _write_json(
        reports / first_wave.OUTPUT_PACKET,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_first_bounded_comparative_execution_packet.v1",
            "status": "PASS",
            "row_summary": [
                {"row_id": "KT_CANONICAL_WEDGE", "row_class": "PASS", "weighted_score": 26},
                {"row_id": "STRONGEST_APPROVED_STATIC_INTERNAL_BASELINE", "row_class": "PARTIAL", "weighted_score": 19},
                {"row_id": "ONE_CATEGORY_FAIR_EXTERNAL_MONOLITH_WORKFLOW", "row_class": "PARTIAL", "weighted_score": 19},
            ],
        },
    )
    _write_json(
        reports / first_wave.OUTPUT_RECEIPT,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_first_bounded_comparative_execution_receipt.v1",
            "status": "PASS",
            "subject_head": "head-123",
            "verdict": "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR",
            "next_lawful_move": "DECIDE_POST_F_TRACK_01_SECOND_WAVE_OR_FINAL_SUMMARY_PACKET",
        },
    )
    _write_json(
        reports / first_wave.OUTPUT_INTERNAL_SELECTION,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_internal_baseline_selection_receipt.v1",
            "status": "PASS",
            "selected_profile_id": "regulated_workflow_mode",
        },
    )
    _write_json(
        reports / first_wave.OUTPUT_EXTERNAL_SELECTION,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_external_workflow_selection_receipt.v1",
            "status": "PASS",
            "selected_workflow_id": "KT_PUBLIC_VERIFIER_DETACHED_PACKAGE_WORKFLOW_V1",
        },
    )
    _write_json(
        product / "deployment_profiles.json",
        {
            "schema_id": "kt.product.deployment_profiles_source.v1",
            "status": "ACTIVE",
            "profiles": [
                {
                    "profile_id": "local_verifier_mode",
                    "install_to_pass_fail_minutes": 15,
                    "max_externality_class": "E1_SAME_HOST_DETACHED_REPLAY",
                    "evidence_refs": [
                        "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
                        "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
                    ],
                },
                {
                    "profile_id": "regulated_workflow_mode",
                    "additional_review_minutes": 20,
                    "install_to_pass_fail_minutes": 30,
                    "max_externality_class": "E1_SAME_HOST_DETACHED_REPLAY",
                    "evidence_refs": [
                        "KT_PROD_CLEANROOM/reports/commercial_truth_packet.json",
                        "KT_PROD_CLEANROOM/reports/public_verifier_kit.json",
                        "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json",
                        "KT_PROD_CLEANROOM/product/nist_mapping_matrix.json",
                        "KT_PROD_CLEANROOM/product/iso_42001_mapping_matrix.json",
                        "KT_PROD_CLEANROOM/product/eu_ai_act_alignment_matrix.json",
                    ],
                },
            ],
        },
    )
    _write_text(product / "nist_mapping_matrix.json", "{}\n")
    _write_text(product / "iso_42001_mapping_matrix.json", "{}\n")
    _write_text(product / "eu_ai_act_alignment_matrix.json", "{}\n")
    _write_text(docs_operator / "RUN_KT_IN_30_MINUTES.md", "Run KT in 30 minutes.\n")
    _write_text(reports / "kt_independent_replay_recipe.md", "Replay recipe.\n")

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(first_wave, "_current_branch_name", lambda root: "expansion/post-f-track-01")

    result = tranche.run(
        reports_root=reports,
        contract_packet_path=reports / contract_tranche.OUTPUT_PACKET,
        matrix_packet_path=reports / contract_tranche.matrix_tranche.OUTPUT_PACKET,
        first_execution_packet_path=reports / first_wave.OUTPUT_PACKET,
        first_execution_receipt_path=reports / first_wave.OUTPUT_RECEIPT,
        internal_selection_receipt_path=reports / first_wave.OUTPUT_INTERNAL_SELECTION,
        external_selection_receipt_path=reports / first_wave.OUTPUT_EXTERNAL_SELECTION,
        live_product_truth_packet_path=reports / "cohort0_gate_f_post_close_live_product_truth_packet.json",
    )

    assert result["execution_outcome"] == tranche.EXECUTION_OUTCOME
    assert result["verdict"] == "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR"

    variation = _load(reports / tranche.OUTPUT_VARIATION)
    scorecard = _load(reports / tranche.OUTPUT_SCORECARD)
    internal_row = _load(reports / tranche.OUTPUT_INTERNAL_ROW)
    external_row = _load(reports / tranche.OUTPUT_EXTERNAL_ROW)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert variation["variation_id"] == tranche.VARIATION_ID
    assert variation["row_set_frozen_from_first_wave"] is True
    assert scorecard["row_summaries"][0]["row_id"] == "KT_CANONICAL_WEDGE"
    assert internal_row["row_class"] == "PARTIAL"
    assert internal_row["weighted_score"] == 16
    assert external_row["row_class"] == "PARTIAL"
    assert external_row["weighted_score"] == 19
    assert external_row["metric_results"][1]["metric_id"] == "replayability"
    assert external_row["metric_results"][1]["state"] == "PASS"
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
