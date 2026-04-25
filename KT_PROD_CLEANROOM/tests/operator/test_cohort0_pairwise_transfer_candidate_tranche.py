from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT
from tools.operator import cohort0_pairwise_transfer_candidate_tranche as tranche


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def test_pairwise_transfer_candidate_tranche_binds_ready_set_and_lab_holds(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative_pairwise_transfer"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    exec_matrix = reports_root / "pairwise_crucible_execution_matrix.json"
    control_validation = reports_root / "pairwise_control_validation.json"
    phase_transitions = reports_root / "pairwise_phase_transition_report.json"
    route_economics = reports_root / "pairwise_route_economics_scorecard.json"
    transfer_eligibility = reports_root / "pairwise_transfer_eligibility.json"
    exec_receipt = reports_root / "pairwise_crucible_execution_receipt.json"
    single_axis_refresh = reports_root / "single_axis_residual_alpha_refresh.json"
    alpha_liability = reports_root / "alpha_liability_registry.json"
    residual_packet = reports_root / "cohort0_residual_alpha_dominance_packet.json"
    transfer_guard = tmp_path / "lab_to_counted_transfer_guard.json"

    family_rows = [
        {"family_id": "P2_SIGNAL_NOISE_SEPARATION", "control_family": False, "target_lobe_id": "lobe.p2.v1", "primary_pressure_axis": "AMBIGUITY_NOISE_DENSITY", "secondary_pressure_axis": "CROSS_DOMAIN_OVERLAY", "route_delta_count": 15, "alpha_liability_exposed_count": 15, "wedge_sharpening_count": 10, "contamination_count": 0},
        {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "control_family": False, "target_lobe_id": "lobe.strategist.v1", "primary_pressure_axis": "HOP_DEPTH", "secondary_pressure_axis": "TEMPORAL_DISTORTION", "route_delta_count": 16, "alpha_liability_exposed_count": 16, "wedge_sharpening_count": 12, "contamination_count": 0},
        {"family_id": "SCOUT_SPARSE_SEARCH", "control_family": False, "target_lobe_id": "lobe.scout.v1", "primary_pressure_axis": "SPARSE_BRANCH_BREADTH", "secondary_pressure_axis": "CAUSAL_BRANCHING", "route_delta_count": 13, "alpha_liability_exposed_count": 14, "wedge_sharpening_count": 9, "contamination_count": 0},
        {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "control_family": False, "target_lobe_id": "lobe.auditor.v1", "primary_pressure_axis": "PROOF_DISCIPLINE_BURDEN", "secondary_pressure_axis": "ADVERSARIAL_AMBIGUITY", "route_delta_count": 13, "alpha_liability_exposed_count": 13, "wedge_sharpening_count": 11, "contamination_count": 0},
        {"family_id": "BETA_SECOND_ORDER_REFRAME", "control_family": False, "target_lobe_id": "lobe.beta.v1", "primary_pressure_axis": "PARADOX_PRESSURE", "secondary_pressure_axis": "CROSS_DOMAIN_OVERLAY", "route_delta_count": 12, "alpha_liability_exposed_count": 12, "wedge_sharpening_count": 8, "contamination_count": 0},
        {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "control_family": True, "target_lobe_id": "", "primary_pressure_axis": "AMBIGUITY_ESCALATION", "secondary_pressure_axis": "CONSTITUTIONAL_BOUNDARY_PRESSURE", "route_delta_count": 16, "alpha_liability_exposed_count": 16, "wedge_sharpening_count": 0, "contamination_count": 0},
        {"family_id": "STATIC_NO_ROUTE_CONTROL", "control_family": True, "target_lobe_id": "lobe.alpha.v1", "primary_pressure_axis": "STATIC_HOLD_STABILITY", "secondary_pressure_axis": "NO_REGRESSION_GUARD", "route_delta_count": 0, "alpha_liability_exposed_count": 0, "wedge_sharpening_count": 0, "contamination_count": 0},
    ]

    _write_json(exec_matrix, {"status": "PASS", "subject_head": subject_head, "family_rows": family_rows})
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
        phase_transitions,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"family_id": "P2_SIGNAL_NOISE_SEPARATION", "control_family": False, "transition_detected": True, "transition_level_id": "L3"},
                {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "control_family": False, "transition_detected": True, "transition_level_id": "L2"},
                {"family_id": "SCOUT_SPARSE_SEARCH", "control_family": False, "transition_detected": True, "transition_level_id": "L3"},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "control_family": False, "transition_detected": True, "transition_level_id": "L2"},
                {"family_id": "BETA_SECOND_ORDER_REFRAME", "control_family": False, "transition_detected": True, "transition_level_id": "L3"},
                {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "control_family": True, "transition_detected": False, "transition_level_id": ""},
                {"family_id": "STATIC_NO_ROUTE_CONTROL", "control_family": True, "transition_detected": False, "transition_level_id": ""},
            ],
        },
    )
    _write_json(
        route_economics,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"family_id": "P2_SIGNAL_NOISE_SEPARATION", "control_family": False, "net_route_value_score": 0.275},
                {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "control_family": False, "net_route_value_score": 0.430},
                {"family_id": "SCOUT_SPARSE_SEARCH", "control_family": False, "net_route_value_score": 0.195},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "control_family": False, "net_route_value_score": 0.355},
                {"family_id": "BETA_SECOND_ORDER_REFRAME", "control_family": False, "net_route_value_score": 0.310},
                {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "control_family": True, "net_route_value_score": 0.0},
                {"family_id": "STATIC_NO_ROUTE_CONTROL", "control_family": True, "net_route_value_score": 0.0},
            ],
        },
    )
    _write_json(
        transfer_eligibility,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"family_id": "P2_SIGNAL_NOISE_SEPARATION", "control_family": False, "target_lobe_id": "lobe.p2.v1", "provisional_transfer_candidate_status": "PROVISIONAL_LAB_ONLY"},
                {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "control_family": False, "target_lobe_id": "lobe.strategist.v1", "provisional_transfer_candidate_status": "PROVISIONAL_TRANSFER_READY"},
                {"family_id": "SCOUT_SPARSE_SEARCH", "control_family": False, "target_lobe_id": "lobe.scout.v1", "provisional_transfer_candidate_status": "PROVISIONAL_LAB_ONLY"},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "control_family": False, "target_lobe_id": "lobe.auditor.v1", "provisional_transfer_candidate_status": "PROVISIONAL_TRANSFER_READY"},
                {"family_id": "BETA_SECOND_ORDER_REFRAME", "control_family": False, "target_lobe_id": "lobe.beta.v1", "provisional_transfer_candidate_status": "PROVISIONAL_TRANSFER_READY"},
                {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "control_family": True, "target_lobe_id": "", "provisional_transfer_candidate_status": "CONTROL_ONLY_NOT_TRANSFER_CANDIDATE"},
                {"family_id": "STATIC_NO_ROUTE_CONTROL", "control_family": True, "target_lobe_id": "lobe.alpha.v1", "provisional_transfer_candidate_status": "CONTROL_ONLY_NOT_TRANSFER_CANDIDATE"},
            ],
        },
    )
    _write_json(exec_receipt, {"status": "PASS", "subject_head": subject_head, "next_lawful_move": "DIGEST_PAIRWISE_RESULTS_AND_BIND_TRANSFER_CANDIDATES__LAB_ONLY"})
    _write_json(
        single_axis_refresh,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"family_id": "P2_SIGNAL_NOISE_SEPARATION", "route_delta_count": 14, "wedge_sharpening_count": 9, "alpha_liability_exposed_count": 15},
                {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "route_delta_count": 15, "wedge_sharpening_count": 11, "alpha_liability_exposed_count": 16},
                {"family_id": "SCOUT_SPARSE_SEARCH", "route_delta_count": 13, "wedge_sharpening_count": 9, "alpha_liability_exposed_count": 14},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "route_delta_count": 11, "wedge_sharpening_count": 7, "alpha_liability_exposed_count": 12},
                {"family_id": "BETA_SECOND_ORDER_REFRAME", "route_delta_count": 10, "wedge_sharpening_count": 6, "alpha_liability_exposed_count": 11},
                {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "route_delta_count": 16, "wedge_sharpening_count": 0, "alpha_liability_exposed_count": 16},
                {"family_id": "STATIC_NO_ROUTE_CONTROL", "route_delta_count": 0, "wedge_sharpening_count": 0, "alpha_liability_exposed_count": 0},
            ],
        },
    )
    _write_json(
        alpha_liability,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"family_id": "P2_SIGNAL_NOISE_SEPARATION", "target_lobe_id": "lobe.p2.v1", "alpha_should_lose_here_because": "p2 liability", "new_admissible_eval_family": "P2_SIGNAL_NOISE_SEPARATION__RESIDUAL_ALPHA_DOMINANCE"},
                {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "target_lobe_id": "lobe.strategist.v1", "alpha_should_lose_here_because": "strategist liability", "new_admissible_eval_family": "STRATEGIST_CONSEQUENCE_CHAIN__RESIDUAL_ALPHA_DOMINANCE"},
                {"family_id": "SCOUT_SPARSE_SEARCH", "target_lobe_id": "lobe.scout.v1", "alpha_should_lose_here_because": "scout liability", "new_admissible_eval_family": "SCOUT_SPARSE_SEARCH__RESIDUAL_ALPHA_DOMINANCE"},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "target_lobe_id": "lobe.auditor.v1", "alpha_should_lose_here_because": "auditor liability", "new_admissible_eval_family": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED__RESIDUAL_ALPHA_DOMINANCE"},
                {"family_id": "BETA_SECOND_ORDER_REFRAME", "target_lobe_id": "lobe.beta.v1", "alpha_should_lose_here_because": "beta liability", "new_admissible_eval_family": "BETA_SECOND_ORDER_REFRAME__RESIDUAL_ALPHA_DOMINANCE"},
            ],
        },
    )
    _write_json(residual_packet, {"status": "PASS", "subject_head": subject_head})
    _write_json(transfer_guard, {"status": "PASS", "subject_head": subject_head})

    payload = tranche.run_pairwise_transfer_candidate_tranche(
        exec_matrix_path=exec_matrix,
        control_validation_path=control_validation,
        phase_transitions_path=phase_transitions,
        route_economics_path=route_economics,
        transfer_eligibility_path=transfer_eligibility,
        exec_receipt_path=exec_receipt,
        single_axis_refresh_path=single_axis_refresh,
        alpha_liability_registry_path=alpha_liability,
        residual_packet_path=residual_packet,
        transfer_guard_path=transfer_guard,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    receipt = payload["pairwise_transfer_candidate_receipt"]
    report = payload["pairwise_transfer_candidate_report"]
    augmentation = payload["pairwise_counted_lane_augmentation_packet"]

    assert receipt["status"] == "PASS"
    assert receipt["pairwise_transfer_posture"] == tranche.POSTURE
    assert set(receipt["ready_family_ids"]) == {
        "STRATEGIST_CONSEQUENCE_CHAIN",
        "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
        "BETA_SECOND_ORDER_REFRAME",
    }
    rows = {row["family_id"]: row for row in report["rows"]}
    assert rows["P2_SIGNAL_NOISE_SEPARATION"]["pairwise_verdict"] == "PAIRWISE_SHARPENED_FURTHER__STILL_LAB_ONLY"
    assert rows["SCOUT_SPARSE_SEARCH"]["pairwise_verdict"] == "PAIRWISE_ADDED_NO_VALUE_OVER_SINGLE_AXIS"
    assert rows["STRATEGIST_CONSEQUENCE_CHAIN"]["pairwise_verdict"] == "PAIRWISE_SHARPENED_AND_TRANSFER_ELIGIBLE"
    assert {row["family_id"] for row in augmentation["rows"]} == {
        "STRATEGIST_CONSEQUENCE_CHAIN",
        "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
        "BETA_SECOND_ORDER_REFRAME",
    }

    tracked = json.loads((reports_root / "pairwise_transfer_candidate_receipt.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_PAIRWISE_TRANSFER_CANDIDATE_RECEIPT"
