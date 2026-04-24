from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator._gate_f_fixtures import seed_gate_f_base
from tools.operator import cohort0_post_f_track_01_comparator_matrix_packet_tranche as matrix_tranche
from tools.operator import cohort0_post_f_track_01_metric_scorecard_contract_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_post_f_track_01_metric_scorecard_contract_binds(tmp_path: Path, monkeypatch) -> None:
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
            },
            "selected_wedge_summary": {
                "wedge_id": "KT_F_NARROW_LOCAL_VERIFIER_EXECUTE_RECEIPT_WEDGE_V1",
                "active_profile_id": "local_verifier_mode",
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
        reports / matrix_tranche.OUTPUT_PACKET,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_comparator_matrix_packet.v1",
            "status": "PASS",
            "matrix_outcome": matrix_tranche.MATRIX_OUTCOME,
            "subject_head": "head-123",
            "next_lawful_move": "AUTHOR_POST_F_TRACK_01_METRIC_SCORECARD_CONTRACT",
            "authority_header": {
                "canonical_authority_branch": "main",
                "working_branch": "expansion/post-f-track-01",
                "working_branch_non_authoritative_until_protected_merge": True,
                "gate_d_cleared_on_successor_line": True,
                "gate_e_open_on_successor_line": True,
                "gate_f_narrow_wedge_confirmed": True,
                "gate_f_open": False,
            },
            "matrix_purpose": {
                "comparison_category": "GOVERNED_RECEIPT_BACKED_FAIL_CLOSED_EXECUTION_UNDER_LAW",
                "confirmed_surface_wedge_id": "KT_F_NARROW_LOCAL_VERIFIER_EXECUTE_RECEIPT_WEDGE_V1",
                "surface_lock": "local_verifier_mode_only",
            },
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: "expansion/post-f-track-01")

    result = tranche.run(
        reports_root=reports,
        matrix_packet_path=reports / matrix_tranche.OUTPUT_PACKET,
        live_product_truth_packet_path=reports / "cohort0_gate_f_post_close_live_product_truth_packet.json",
        post_merge_closeout_receipt_path=reports / "cohort0_post_merge_closeout_receipt.json",
    )

    assert result["contract_outcome"] == tranche.CONTRACT_OUTCOME

    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert len(packet["metric_rules"]) == 5
    assert packet["aggregation_rule"]["max_weighted_score"] == 26
    assert packet["aggregation_rule"]["row_pass_condition"].endswith("weighted_score >= 21.")
    assert packet["comparative_verdict_rulebook"]["allowed_verdicts"][0]["verdict"] == "KT_CANONICAL_WEDGE_ADVANTAGE__CATEGORY_FAIR"
    assert "No Kaggle or math leakage." in packet["anti_drift_guardrails"]
    assert receipt["metric_count"] == 5
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
