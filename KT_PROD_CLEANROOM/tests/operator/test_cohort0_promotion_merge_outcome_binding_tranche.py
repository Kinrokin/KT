from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_promotion_merge_outcome_binding_tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT, _write_json


def test_cohort0_promotion_merge_outcome_binding_tranche_passes_on_current_repo(tmp_path: Path) -> None:
    authoritative_root = tmp_path / "authoritative"
    reports_root = tmp_path / "reports"
    payload = cohort0_promotion_merge_outcome_binding_tranche.run_promotion_merge_outcome_binding_tranche(
        promotion_report_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "cohort0_promotion_candidate_receipt.json",
        followthrough_report_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "cohort0_real_engine_tournament_followthrough_packet.json",
        child_eval_report_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "cohort0_merge_child_evaluation_receipt.json",
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    promotion = payload["promotion_outcome_binding_receipt"]
    merge = payload["merge_outcome_binding_receipt"]
    followthrough = payload["followthrough_packet"]

    assert promotion["status"] == "PASS"
    assert promotion["promotion_posture"] == "PROMOTION_OUTCOME_BOUND__MERGE_PASS_CHILD_READY_FOR_ROUTER_SHADOW_EVALUATION"
    assert promotion["next_lawful_move"] == "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"

    assert merge["status"] == "PASS"
    assert merge["merge_outcome_posture"] == "MERGE_OUTCOME_BOUND__PASS__ROLLBACK_READY"
    assert merge["utility_gate_pass"] is True
    assert merge["safety_regression"] is False

    assert followthrough["followthrough_posture"] == "PROMOTION_AND_MERGE_OUTCOME_BOUND__ROUTER_SHADOW_EVALUATION_REQUIRED"
    assert followthrough["next_lawful_move"] == "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"
    assert followthrough["merge_followthrough"]["execution_ready"] is True
    assert followthrough["promotion_followthrough"]["execution_ready"] is True

    tracked = json.loads((reports_root / "cohort0_promotion_outcome_binding_receipt.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_PROMOTION_OUTCOME_BINDING_RECEIPT"


def test_cohort0_promotion_merge_outcome_binding_tranche_fail_closes_without_merge_pass(tmp_path: Path) -> None:
    authoritative = tmp_path / "authoritative_merge_child_eval.json"
    _write_json(
        authoritative,
        {
            "status": "PASS",
            "evaluation_posture": "MERGE_CHILD_EVALUATED__RECOMMENDED_PARENT_PAIR_NOT_ADMISSIBLE",
        },
    )
    tracked = tmp_path / "tracked_merge_child_eval.json"
    _write_json(
        tracked,
        {
            "authoritative_merge_child_evaluation_receipt_ref": authoritative.as_posix(),
            "status": "PASS",
        },
    )

    with pytest.raises(RuntimeError, match="merge-child pass posture"):
        cohort0_promotion_merge_outcome_binding_tranche.run_promotion_merge_outcome_binding_tranche(
            promotion_report_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "cohort0_promotion_candidate_receipt.json",
            followthrough_report_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "cohort0_real_engine_tournament_followthrough_packet.json",
            child_eval_report_path=tracked,
            authoritative_root=tmp_path / "authoritative",
            reports_root=tmp_path / "reports",
            workspace_root=ROOT,
        )
