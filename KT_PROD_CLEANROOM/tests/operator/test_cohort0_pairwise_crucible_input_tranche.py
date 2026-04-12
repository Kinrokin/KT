from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT
from tools.operator import cohort0_pairwise_crucible_input_tranche as tranche


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def test_pairwise_crucible_input_tranche_binds_survivors_controls_and_child_revision(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative_pairwise"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    transfer_report = reports_root / "single_axis_transfer_candidate_report.json"
    residual_refresh = reports_root / "single_axis_residual_alpha_refresh.json"
    pairwise_packet = reports_root / "single_axis_pairwise_escalation_packet.json"
    control_validation = reports_root / "single_axis_control_validation.json"
    transfer_guard = tmp_path / "lab_to_counted_transfer_guard.json"

    _write_json(
        transfer_report,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "controls_preserved": True,
            "survivor_family_ids": [
                "P2_SIGNAL_NOISE_SEPARATION",
                "STRATEGIST_CONSEQUENCE_CHAIN",
                "SCOUT_SPARSE_SEARCH",
                "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
                "BETA_SECOND_ORDER_REFRAME",
            ],
            "blocked_family_ids": ["CHILD_ANOMALY_PRESERVATION"],
            "rows": [],
        },
    )
    _write_json(
        residual_refresh,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "strengthened_family_ids": [
                "P2_SIGNAL_NOISE_SEPARATION",
                "STRATEGIST_CONSEQUENCE_CHAIN",
                "SCOUT_SPARSE_SEARCH",
                "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
                "BETA_SECOND_ORDER_REFRAME",
            ],
            "revise_family_ids": ["CHILD_ANOMALY_PRESERVATION"],
            "control_family_ids": ["BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"],
            "rows": [
                {
                    "family_id": "P2_SIGNAL_NOISE_SEPARATION",
                    "target_lobe_id": "lobe.p2.v1",
                    "control_family": False,
                    "alpha_should_lose_here_because": "p2 because",
                    "acceptance_metric": "p2 metric",
                    "single_axis_primary_pressure_axis": "AMBIGUITY_NOISE_DENSITY",
                    "transfer_candidate_status": "TRANSFER_CANDIDATE_ADMISSIBLE_FOR_COUNTED_LANE",
                    "route_delta_count": 14,
                    "alpha_liability_exposed_count": 15,
                    "wedge_sharpening_count": 9,
                },
                {
                    "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
                    "target_lobe_id": "lobe.strategist.v1",
                    "control_family": False,
                    "alpha_should_lose_here_because": "strategist because",
                    "acceptance_metric": "strategist metric",
                    "single_axis_primary_pressure_axis": "HOP_DEPTH",
                    "transfer_candidate_status": "TRANSFER_CANDIDATE_ADMISSIBLE_FOR_COUNTED_LANE",
                    "route_delta_count": 15,
                    "alpha_liability_exposed_count": 16,
                    "wedge_sharpening_count": 11,
                },
                {
                    "family_id": "SCOUT_SPARSE_SEARCH",
                    "target_lobe_id": "lobe.scout.v1",
                    "control_family": False,
                    "alpha_should_lose_here_because": "scout because",
                    "acceptance_metric": "scout metric",
                    "single_axis_primary_pressure_axis": "SPARSE_BRANCH_BREADTH",
                    "transfer_candidate_status": "TRANSFER_CANDIDATE_ADMISSIBLE_FOR_COUNTED_LANE",
                    "route_delta_count": 13,
                    "alpha_liability_exposed_count": 14,
                    "wedge_sharpening_count": 9,
                },
                {
                    "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
                    "target_lobe_id": "lobe.auditor.v1",
                    "control_family": False,
                    "alpha_should_lose_here_because": "auditor because",
                    "acceptance_metric": "auditor metric",
                    "single_axis_primary_pressure_axis": "PROOF_DISCIPLINE_BURDEN",
                    "transfer_candidate_status": "TRANSFER_CANDIDATE_ADMISSIBLE_FOR_COUNTED_LANE",
                    "route_delta_count": 11,
                    "alpha_liability_exposed_count": 12,
                    "wedge_sharpening_count": 7,
                },
                {
                    "family_id": "BETA_SECOND_ORDER_REFRAME",
                    "target_lobe_id": "lobe.beta.v1",
                    "control_family": False,
                    "alpha_should_lose_here_because": "beta because",
                    "acceptance_metric": "beta metric",
                    "single_axis_primary_pressure_axis": "PARADOX_PRESSURE",
                    "transfer_candidate_status": "TRANSFER_CANDIDATE_ADMISSIBLE_FOR_COUNTED_LANE",
                    "route_delta_count": 10,
                    "alpha_liability_exposed_count": 11,
                    "wedge_sharpening_count": 6,
                },
                {
                    "family_id": "BOUNDARY_ABSTENTION_CONTROL",
                    "target_lobe_id": "",
                    "control_family": True,
                    "alpha_should_lose_here_because": "",
                    "acceptance_metric": "",
                    "single_axis_primary_pressure_axis": "AMBIGUITY_ESCALATION",
                    "transfer_candidate_status": "CONTROL_ONLY_NOT_TRANSFER_CANDIDATE",
                    "route_delta_count": 16,
                    "alpha_liability_exposed_count": 16,
                    "wedge_sharpening_count": 0,
                },
                {
                    "family_id": "STATIC_NO_ROUTE_CONTROL",
                    "target_lobe_id": "lobe.alpha.v1",
                    "control_family": True,
                    "alpha_should_lose_here_because": "",
                    "acceptance_metric": "",
                    "single_axis_primary_pressure_axis": "STATIC_HOLD_STABILITY",
                    "transfer_candidate_status": "CONTROL_ONLY_NOT_TRANSFER_CANDIDATE",
                    "route_delta_count": 0,
                    "alpha_liability_exposed_count": 0,
                    "wedge_sharpening_count": 0,
                },
                {
                    "family_id": "CHILD_ANOMALY_PRESERVATION",
                    "target_lobe_id": "lobe.child.v1",
                    "control_family": False,
                    "alpha_should_lose_here_because": "child because",
                    "acceptance_metric": "child metric",
                    "single_axis_primary_pressure_axis": "ANOMALY_CAMOUFLAGE",
                    "transfer_candidate_status": "ANTI_ALPHA_LIABILITY_EXPOSED_BUT_ROUTE_HYPOTHESIS_STILL_WEAK",
                    "route_delta_count": 7,
                    "alpha_liability_exposed_count": 7,
                    "wedge_sharpening_count": 2,
                },
            ],
        },
    )
    _write_json(
        pairwise_packet,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "controls_preserved": True,
            "survivor_family_ids": [
                "P2_SIGNAL_NOISE_SEPARATION",
                "STRATEGIST_CONSEQUENCE_CHAIN",
                "SCOUT_SPARSE_SEARCH",
                "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
                "BETA_SECOND_ORDER_REFRAME",
            ],
            "blocked_family_ids": ["CHILD_ANOMALY_PRESERVATION"],
            "next_lawful_move": "AUTHOR_PAIRWISE_CRUCIBLE_INPUTS_FOR_SINGLE_AXIS_SURVIVORS__LAB_ONLY",
            "rows": [],
        },
    )
    _write_json(
        control_validation,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "controls_preserved": True,
            "rows": [
                {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "preserved": True},
                {"family_id": "STATIC_NO_ROUTE_CONTROL", "preserved": True},
            ],
        },
    )
    _write_json(
        transfer_guard,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "preserved_controls": {
                "abstention_control_family_ids": ["BOUNDARY_ABSTENTION_CONTROL"],
                "static_hold_family_ids": ["STATIC_NO_ROUTE_CONTROL"],
            },
        },
    )

    payload = tranche.run_pairwise_crucible_input_tranche(
        transfer_report_path=transfer_report,
        residual_refresh_path=residual_refresh,
        pairwise_packet_path=pairwise_packet,
        control_validation_path=control_validation,
        transfer_guard_path=transfer_guard,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    receipt = payload["pairwise_crucible_receipt"]
    manifest = payload["pairwise_crucible_input_manifest"]
    child_packet = payload["child_anomaly_revision_packet"]

    assert receipt["status"] == "PASS"
    assert receipt["pairwise_posture"] == tranche.POSTURE
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
    assert receipt["survivor_family_count"] == 5
    assert manifest["survivor_family_ids"] == [
        "P2_SIGNAL_NOISE_SEPARATION",
        "STRATEGIST_CONSEQUENCE_CHAIN",
        "SCOUT_SPARSE_SEARCH",
        "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
        "BETA_SECOND_ORDER_REFRAME",
    ]
    assert child_packet["family_id"] == "CHILD_ANOMALY_PRESERVATION"
    assert child_packet["revised_single_axis_candidate"]["primary_pressure_axis"] == "TRANSFORMATION_DISTORTION"

    tracked = json.loads((reports_root / "pairwise_crucible_receipt.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_PAIRWISE_CRUCIBLE_RECEIPT"
