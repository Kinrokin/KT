from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_counted_lane_hardening_tranche as tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def test_counted_lane_hardening_tranche_emits_expected_surfaces(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    residual_packet = tmp_path / "cohort0_residual_alpha_dominance_packet.json"
    residual_wedge_spec = tmp_path / "cohort0_residual_alpha_dominance_wedge_spec.json"
    r5 = tmp_path / "cohort0_recomposed_router_vs_best_adapter_proof_receipt.json"
    ordered = tmp_path / "cohort0_recomposed_router_ordered_proof_receipt.json"
    health = tmp_path / "cohort0_recomposed_route_distribution_health.json"
    crucible = tmp_path / "cohort0_crucible_escalation_packet.json"
    alpha = tmp_path / "alpha_should_lose_here_manifest.json"
    policy = tmp_path / "route_policy_outcome_registry.json"
    oracle = tmp_path / "oracle_router_local_scorecard.json"
    overlay = tmp_path / "current_campaign_state_overlay.json"
    next_workstream = tmp_path / "next_counted_workstream_contract.json"
    resume = tmp_path / "resume_blockers_receipt.json"

    _write_json(
        residual_packet,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "next_lawful_move": tranche.NEXT_MOVE,
            "current_ceiling_summary": {"exact_superiority_outcome": "NOT_EARNED_MATERIAL_ROUTE_VALUE_PRESENT_STATIC_BASELINE_RETAINS_CANONICAL_STATUS"},
            "proof_object_movement": {"unique_route_target_count_current": 7},
            "residual_alpha_dominance_summary": {
                "static_hold_families": ["STATIC_NO_ROUTE_CONTROL"],
                "abstention_control_families": ["BOUNDARY_ABSTENTION_CONTROL"],
                "specialist_signal_families": ["P2_SIGNAL_NOISE_SEPARATION", "STRATEGIST_CONSEQUENCE_CHAIN"],
            },
            "family_rows": [
                {"family_id": "STATIC_NO_ROUTE_CONTROL", "residual_status": "RIGHTFUL_STATIC_HOLD__CONTROL_FAMILY"},
                {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "residual_status": "FAIL_CLOSED_DE_RISKING_SIGNAL__NOT_DIRECT_SUPERIORITY"},
            ],
        },
    )
    _write_json(
        residual_wedge_spec,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {
                    "family_id": "P2_SIGNAL_NOISE_SEPARATION",
                    "target_lobe_id": "lobe.p2.v1",
                    "primary_pressure_axis": "signal_noise_density",
                    "secondary_pressure_axis": "decoy_constraint_pressure",
                    "new_admissible_eval_family": "P2_SIGNAL_NOISE_SEPARATION__RESIDUAL_ALPHA_DOMINANCE",
                }
            ],
        },
    )
    _write_json(r5, {"status": "PASS", "subject_head": subject_head, "router_proof_summary": {"router_superiority_earned": False}})
    _write_json(ordered, {"status": "PASS", "subject_head": subject_head, "material_advance_detected": True})
    _write_json(health, {"status": "PASS", "subject_head": subject_head, "route_distribution_delta_count": 34})
    _write_json(
        crucible,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "transfer_rule": {
                "named_wedge_sharpening_required": True,
                "named_anti_alpha_liability_required": True,
                "measurable_route_delta_hypothesis_required": True,
                "new_admissible_eval_family_required": True,
            },
        },
    )
    _write_json(
        alpha,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {
                    "family_id": "P2_SIGNAL_NOISE_SEPARATION",
                    "target_lobe_id": "lobe.p2.v1",
                    "alpha_should_lose_here_because": "Alpha blurs decisive and decorative constraints.",
                    "acceptance_metric": "Lower failure cost than alpha.",
                    "expected_route_outcome": "ROUTE_TO_SPECIALIST",
                }
            ],
        },
    )
    _write_json(
        policy,
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
    _write_json(oracle, {"status": "PASS", "subject_head": subject_head})
    _write_json(overlay, {"repo_state_executable_now": False, "subject_head": subject_head})
    _write_json(next_workstream, {"repo_state_executable_now": False, "subject_head": subject_head})
    _write_json(resume, {"repo_state_executable_now": False, "subject_head": subject_head})

    payload = tranche.run_counted_lane_hardening_tranche(
        residual_packet_path=residual_packet,
        residual_wedge_spec_path=residual_wedge_spec,
        r5_receipt_path=r5,
        ordered_receipt_path=ordered,
        health_report_path=health,
        crucible_packet_path=crucible,
        alpha_manifest_path=alpha,
        policy_registry_path=policy,
        oracle_scorecard_path=oracle,
        current_overlay_path=overlay,
        next_workstream_path=next_workstream,
        resume_blockers_path=resume,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    assert payload["receipt"]["status"] == "PASS"
    assert payload["receipt"]["verdict_posture"] == tranche.VERDICT_POSTURE
    assert payload["receipt"]["next_lawful_move"] == tranche.NEXT_MOVE
    assert payload["counted_lane_verdict_grammar"]["status"] == "PASS"
    assert payload["lab_to_counted_transfer_guard"]["status"] == "PASS"

    tracked = json.loads((reports_root / "counted_lane_verdict_grammar.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_COUNTED_LANE_VERDICT_GRAMMAR"
