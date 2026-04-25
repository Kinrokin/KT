from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_router_superiority_recovery_prep_tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT


def test_router_superiority_recovery_prep_tranche_emits_lab_only_recovery_surfaces(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative"

    payload = cohort0_router_superiority_recovery_prep_tranche.run_router_superiority_recovery_prep_tranche(
        router_proof_receipt_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "router_vs_best_adapter_proof_ratification_receipt.json",
        scorecard_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "router_superiority_scorecard.json",
        shadow_matrix_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "router_shadow_eval_matrix.json",
        route_health_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "route_distribution_health.json",
        selection_receipt_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "kt_wave2b_router_selection_receipt.json",
        import_receipt_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "cohort0_real_engine_adapter_import_receipt.json",
        tournament_execution_receipt_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "cohort0_tournament_execution_receipt.json",
        followthrough_report_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "cohort0_real_engine_tournament_followthrough_packet.json",
        current_overlay_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "current_campaign_state_overlay.json",
        next_workstream_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "next_counted_workstream_contract.json",
        resume_blockers_path=ROOT / "KT_PROD_CLEANROOM" / "reports" / "resume_blockers_receipt.json",
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    receipt = payload["router_superiority_recovery_prep_receipt"]
    diagnosis = payload["router_failure_diagnosis_packet"]
    lobe_survival = payload["lobe_survival_verdicts"]
    prereg = payload["route_bearing_battery_preregistration"]
    policy_registry = payload["route_policy_outcome_registry"]

    assert receipt["status"] == "PASS"
    assert receipt["prep_posture"] == "ROUTER_SUPERIORITY_RECOVERY_PREP_BOUND__COUNTED_LANE_STILL_CLOSED"
    assert receipt["next_lawful_move"] == "AUTHOR_PREREGISTERED_ROUTE_BEARING_STAGE_PACK_AND_RUN_ORACLE_ROUTING"
    assert receipt["counted_lane_guardrail"]["overlay_repo_state_executable_now"] is False

    assert diagnosis["top_blockers"][0]["blocker_id"] == "BATTERY_TOO_SMALL"
    assert diagnosis["truth_surface_guardrails"]["overlay_next_counted_workstream_id"] == "B04_R6_LEARNED_ROUTER_AUTHORIZATION"

    assert lobe_survival["selected_working_set"] == [
        "lobe.alpha.v1",
        "lobe.p2.v1",
        "lobe.child.v1",
        "lobe.strategist.v1",
        "lobe.beta.v1",
        "lobe.scout.v1",
        "lobe.auditor.v1",
    ]

    outcome_ids = [row["outcome_id"] for row in policy_registry["outcomes"]]
    assert outcome_ids == ["ROUTE_TO_SPECIALIST", "STAY_STATIC_BASELINE", "ABSTAIN_FOR_REVIEW"]
    assert "pre-registered, adversarial, route-bearing battery" in prereg["theorem_statement"]

    tracked_receipt = json.loads((reports_root / "router_superiority_recovery_prep_receipt.json").read_text(encoding="utf-8"))
    assert tracked_receipt["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_ROUTER_SUPERIORITY_RECOVERY_PREP_RECEIPT"
