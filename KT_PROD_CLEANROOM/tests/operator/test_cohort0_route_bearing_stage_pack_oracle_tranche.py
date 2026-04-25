from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_route_bearing_stage_pack_oracle_tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT


def test_route_bearing_stage_pack_oracle_tranche_binds_local_court_and_kaggle_admissibility(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative"

    payload = cohort0_route_bearing_stage_pack_oracle_tranche.run_route_bearing_stage_pack_oracle_tranche(
        prep_receipt_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "router_superiority_recovery_prep_receipt.json",
        diagnosis_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "router_failure_diagnosis_packet.json",
        policy_registry_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "route_policy_outcome_registry.json",
        alpha_manifest_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "alpha_should_lose_here_manifest.json",
        lobe_survival_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "lobe_survival_verdicts.json",
        prereg_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "route_bearing_battery_preregistration.json",
        oracle_counterfactual_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "oracle_router_counterfactual_matrix.json",
        abstention_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "route_abstention_quality_report.json",
        negative_ledger_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "negative_result_ledger.json",
        current_overlay_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "current_campaign_state_overlay.json",
        next_workstream_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "next_counted_workstream_contract.json",
        resume_blockers_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "resume_blockers_receipt.json",
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    manifest = payload["route_bearing_stage_pack_manifest"]
    index = payload["route_bearing_stage_pack_index"]
    scorecard = payload["oracle_router_local_scorecard"]
    receipt = payload["oracle_router_local_receipt"]

    assert manifest["status"] == "PASS"
    assert manifest["family_count"] == 8
    assert manifest["case_count"] == 39
    assert manifest["held_out_case_count"] == 8
    assert manifest["outcome_counts"]["ROUTE_TO_SPECIALIST"] > 0
    assert manifest["outcome_counts"]["ABSTAIN_FOR_REVIEW"] > 0
    assert manifest["outcome_counts"]["STAY_STATIC_BASELINE"] > 0

    assert index["status"] == "PASS"
    assert index["case_count"] == 39
    assert "case_prompt" not in index["rows"][0]

    assert scorecard["status"] == "PASS"
    assert scorecard["route_divergence_count"] == 34
    assert scorecard["static_control_hold_pass"] is True
    assert scorecard["abstention_family_present"] is True
    assert scorecard["held_out_mutation_present"] is True
    assert scorecard["generic_all_13_heavier_rerun_forbidden"] is True
    assert scorecard["kaggle_admissibility"] == "ADMISSIBLE_FOR_TARGETED_HYPERTRAINING_ONLY"
    assert scorecard["oracle_positive_lobe_ids"] == [
        "lobe.p2.v1",
        "lobe.child.v1",
        "lobe.strategist.v1",
        "lobe.beta.v1",
        "lobe.scout.v1",
        "lobe.auditor.v1",
    ]

    assert receipt["status"] == "PASS"
    assert receipt["oracle_stage_pack_posture"] == "PREREGISTERED_STAGE_PACK_BOUND__LOCAL_ORACLE_PASS__COUNTED_LANE_STILL_CLOSED"
    assert receipt["counted_lane_guardrail"]["overlay_repo_state_executable_now"] is False
    assert receipt["kaggle_admissibility"] == "ADMISSIBLE_FOR_TARGETED_HYPERTRAINING_ONLY"
    assert receipt["next_lawful_move"] == "AUTHOR_TARGETED_HYPERTRAINING_STAGE_INPUTS_FOR_ORACLE_POSITIVE_FAMILIES"

    tracked_manifest = json.loads((reports_root / "route_bearing_stage_pack_manifest.json").read_text(encoding="utf-8"))
    tracked_receipt = json.loads((reports_root / "oracle_router_local_receipt.json").read_text(encoding="utf-8"))
    assert tracked_manifest["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_ROUTE_BEARING_STAGE_PACK_MANIFEST"
    assert tracked_receipt["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_ORACLE_ROUTER_LOCAL_RECEIPT"
