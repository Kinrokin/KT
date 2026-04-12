from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT
from tools.operator import cohort0_single_axis_crucible_execution_tranche as execution
from tools.operator import cohort0_single_axis_crucible_input_tranche as authoring
from tools.operator import cohort0_single_axis_transfer_candidate_tranche as tranche


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _build_execution_state(tmp_path: Path) -> dict[str, Path]:
    reports_root = tmp_path / "reports"
    authoritative_input_root = tmp_path / "authoritative_inputs"
    authoritative_exec_root = tmp_path / "authoritative_execution"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    residual_packet = tmp_path / "cohort0_residual_alpha_dominance_packet.json"
    residual_wedge_spec = tmp_path / "cohort0_residual_alpha_dominance_wedge_spec.json"
    transfer_guard = tmp_path / "lab_to_counted_transfer_guard.json"
    verdict_grammar = tmp_path / "counted_lane_verdict_grammar.json"
    alpha_liability_registry = tmp_path / "alpha_liability_registry.json"
    policy_registry = tmp_path / "route_policy_outcome_registry.json"

    family_rows = [
        {"family_id": "P2_SIGNAL_NOISE_SEPARATION", "target_lobe_id": "lobe.p2.v1", "residual_status": "SPECIALIST_ROUTE_SIGNAL_PRESENT__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY", "alpha_liability": "alpha p2 liability", "next_focus": "P2_NEXT", "acceptance_metric": "p2 metric", "new_admissible_eval_family": "P2_SIGNAL_NOISE_SEPARATION__RESIDUAL_ALPHA_DOMINANCE", "held_out_preservation_rule": "held-out", "residual_explanation": "p2 failure mode"},
        {"family_id": "CHILD_ANOMALY_PRESERVATION", "target_lobe_id": "lobe.child.v1", "residual_status": "SPECIALIST_ROUTE_SIGNAL_PRESENT__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY", "alpha_liability": "alpha child liability", "next_focus": "CHILD_NEXT", "acceptance_metric": "child metric", "new_admissible_eval_family": "CHILD_ANOMALY_PRESERVATION__RESIDUAL_ALPHA_DOMINANCE", "held_out_preservation_rule": "held-out", "residual_explanation": "child failure mode"},
        {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "target_lobe_id": "lobe.strategist.v1", "residual_status": "SPECIALIST_ROUTE_SIGNAL_PRESENT__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY", "alpha_liability": "alpha strategist liability", "next_focus": "STRATEGIST_NEXT", "acceptance_metric": "strategist metric", "new_admissible_eval_family": "STRATEGIST_CONSEQUENCE_CHAIN__RESIDUAL_ALPHA_DOMINANCE", "held_out_preservation_rule": "held-out", "residual_explanation": "strategist failure mode"},
        {"family_id": "SCOUT_SPARSE_SEARCH", "target_lobe_id": "lobe.scout.v1", "residual_status": "SPECIALIST_ROUTE_SIGNAL_PRESENT__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY", "alpha_liability": "alpha scout liability", "next_focus": "SCOUT_NEXT", "acceptance_metric": "scout metric", "new_admissible_eval_family": "SCOUT_SPARSE_SEARCH__RESIDUAL_ALPHA_DOMINANCE", "held_out_preservation_rule": "held-out", "residual_explanation": "scout failure mode"},
        {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "target_lobe_id": "lobe.auditor.v1", "residual_status": "MIXED_SPECIALIST_AND_FAIL_CLOSED_SIGNAL__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY", "alpha_liability": "alpha auditor liability", "next_focus": "AUDITOR_NEXT", "acceptance_metric": "auditor metric", "new_admissible_eval_family": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED__RESIDUAL_ALPHA_DOMINANCE", "held_out_preservation_rule": "held-out", "residual_explanation": "auditor failure mode"},
        {"family_id": "BETA_SECOND_ORDER_REFRAME", "target_lobe_id": "lobe.beta.v1", "residual_status": "SPECIALIST_ROUTE_SIGNAL_PRESENT__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY", "alpha_liability": "alpha beta liability", "next_focus": "BETA_NEXT", "acceptance_metric": "beta metric", "new_admissible_eval_family": "BETA_SECOND_ORDER_REFRAME__RESIDUAL_ALPHA_DOMINANCE", "held_out_preservation_rule": "held-out", "residual_explanation": "beta failure mode"},
        {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "target_lobe_id": "", "residual_status": "FAIL_CLOSED_DE_RISKING_SIGNAL__NOT_DIRECT_SUPERIORITY", "alpha_liability": "ambiguity liability", "next_focus": "BOUNDARY_NEXT", "acceptance_metric": "boundary metric", "new_admissible_eval_family": "BOUNDARY_ABSTENTION_CONTROL__RESIDUAL_ALPHA_DOMINANCE", "held_out_preservation_rule": "held-out", "residual_explanation": "boundary failure mode"},
        {"family_id": "STATIC_NO_ROUTE_CONTROL", "target_lobe_id": "lobe.alpha.v1", "residual_status": "RIGHTFUL_STATIC_HOLD__CONTROL_FAMILY", "alpha_liability": "static liability", "next_focus": "STATIC_NEXT", "acceptance_metric": "static metric", "new_admissible_eval_family": "STATIC_NO_ROUTE_CONTROL__RESIDUAL_ALPHA_DOMINANCE", "held_out_preservation_rule": "held-out", "residual_explanation": "static failure mode"},
    ]

    _write_json(
        residual_packet,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "next_lawful_move": "AUTHOR_SINGLE_AXIS_CRUCIBLE_INPUTS_AND_EXECUTE_LAB_ONLY_SWEEPS",
            "proof_object_movement": {"route_distribution_delta_count_current": 34},
        },
    )
    _write_json(residual_wedge_spec, {"status": "PASS", "subject_head": subject_head, "rows": family_rows})
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
    _write_json(verdict_grammar, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        alpha_liability_registry,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {
                    "family_id": row["family_id"],
                    "target_lobe_id": row["target_lobe_id"],
                    "alpha_should_lose_here_because": f"{row['family_id']} because",
                    "acceptance_metric": row["acceptance_metric"],
                    "expected_route_outcome": "ROUTE_TO_SPECIALIST",
                    "new_admissible_eval_family": row["new_admissible_eval_family"],
                }
                for row in family_rows
            ],
        },
    )
    _write_json(
        policy_registry,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "outcomes": [
                {"outcome_id": "ROUTE_TO_SPECIALIST"},
                {"outcome_id": "STAY_STATIC_BASELINE"},
                {"outcome_id": "ABSTAIN_FOR_REVIEW"},
            ],
        },
    )

    authoring.run_single_axis_crucible_input_tranche(
        residual_packet_path=residual_packet,
        residual_wedge_spec_path=residual_wedge_spec,
        transfer_guard_path=transfer_guard,
        verdict_grammar_path=verdict_grammar,
        alpha_liability_registry_path=alpha_liability_registry,
        policy_registry_path=policy_registry,
        authoritative_root=authoritative_input_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )
    execution.run_single_axis_crucible_execution_tranche(
        input_manifest_path=reports_root / "single_axis_crucible_input_manifest.json",
        registry_path=reports_root / "single_axis_crucible_registry.json",
        failures_path=reports_root / "single_axis_expected_failure_modes.json",
        transfer_candidates_path=reports_root / "single_axis_transfer_candidates.json",
        input_receipt_path=reports_root / "single_axis_crucible_receipt.json",
        transfer_guard_path=transfer_guard,
        verdict_grammar_path=verdict_grammar,
        authoritative_root=authoritative_exec_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )
    return {
        "reports_root": reports_root,
        "alpha_liability_registry": alpha_liability_registry,
        "residual_packet": residual_packet,
        "transfer_guard": transfer_guard,
    }


def test_single_axis_transfer_candidate_tranche_binds_pairwise_survivors(tmp_path: Path) -> None:
    built = _build_execution_state(tmp_path)
    reports_root = built["reports_root"]
    authoritative_root = tmp_path / "authoritative_transfer"

    payload = tranche.run_single_axis_transfer_candidate_tranche(
        exec_matrix_path=reports_root / "single_axis_crucible_execution_matrix.json",
        control_validation_path=reports_root / "single_axis_control_validation.json",
        transfer_eligibility_path=reports_root / "single_axis_transfer_eligibility.json",
        exec_receipt_path=reports_root / "single_axis_crucible_execution_receipt.json",
        alpha_liability_registry_path=built["alpha_liability_registry"],
        residual_packet_path=built["residual_packet"],
        transfer_guard_path=built["transfer_guard"],
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    receipt = payload["single_axis_transfer_candidate_receipt"]
    report = payload["single_axis_transfer_candidate_report"]
    pairwise = payload["single_axis_pairwise_escalation_packet"]

    assert receipt["status"] == "PASS"
    assert receipt["single_axis_transfer_posture"] == tranche.POSTURE
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
    assert receipt["survivor_family_count"] == 5
    assert "CHILD_ANOMALY_PRESERVATION" in receipt["blocked_family_ids"]
    assert any(row["family_id"] == "P2_SIGNAL_NOISE_SEPARATION" and row["disposition"] == "PROMOTE_TO_PAIRWISE_LAB_ESCALATION" for row in report["rows"])
    assert len(pairwise["rows"]) == 5

    tracked = json.loads((reports_root / "single_axis_transfer_candidate_receipt.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_SINGLE_AXIS_TRANSFER_CANDIDATE_RECEIPT"
