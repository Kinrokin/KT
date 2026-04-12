from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_residual_alpha_dominance_packet_tranche as tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def test_residual_alpha_dominance_packet_emits_family_scoped_next_spec(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    r5 = tmp_path / "cohort0_recomposed_router_vs_best_adapter_proof_receipt.json"
    ordered = tmp_path / "cohort0_recomposed_router_ordered_proof_receipt.json"
    health = tmp_path / "cohort0_recomposed_route_distribution_health.json"
    selection = tmp_path / "cohort0_recomposed_router_selection_receipt.json"
    shadow = tmp_path / "cohort0_recomposed_router_shadow_eval_matrix.json"
    manifest = tmp_path / "route_bearing_stage_pack_manifest.json"
    alpha = tmp_path / "alpha_should_lose_here_manifest.json"
    oracle = tmp_path / "oracle_router_local_scorecard.json"
    followthrough = tmp_path / "cohort0_recomposed_router_shadow_followthrough_packet.json"

    _write_json(r5, {"status": "PASS", "subject_head": subject_head, "next_lawful_move": "AUTHOR_RESIDUAL_ALPHA_DOMINANCE_PACKET", "router_proof_summary": {"material_advance_detected": True, "router_superiority_earned": False}})
    _write_json(
        ordered,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "material_advance_detected": True,
            "ordered_proof_outcome": "PASS_MATERIAL_ADVANCE_STATIC_BASELINE_STILL_CANONICAL",
            "exact_superiority_outcome": "NOT_EARNED_MATERIAL_ROUTE_VALUE_PRESENT_STATIC_BASELINE_RETAINS_CANONICAL_STATUS",
            "learned_router_candidate_status": "LEARNED_ROUTER_CANDIDATE_SIGNAL_PRESENT__AUTHORIZATION_STILL_BLOCKED",
            "proof_object_deltas": {"route_distribution_delta_count_delta": 34, "shadow_match_rate_delta": -0.8718, "exact_path_universality_broken_current": True},
        },
    )
    _write_json(health, {"status": "PASS", "subject_head": subject_head, "route_distribution_delta_count": 34, "exact_path_universality_broken": True, "shadow_match_rate": 0.1282, "unique_route_targets": ["lobe.alpha.v1", "lobe.p2.v1", "lobe.auditor.v1"]})
    _write_json(
        selection,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "case_rows": [
                {"family_id": "P2_SIGNAL_NOISE_SEPARATION", "selected_adapter_ids": ["lobe.p2.v1"]},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "selected_adapter_ids": ["lobe.auditor.v1"]},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "selected_adapter_ids": []},
                {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "selected_adapter_ids": []},
                {"family_id": "STATIC_NO_ROUTE_CONTROL", "selected_adapter_ids": ["lobe.alpha.v1"]},
            ],
        },
    )
    _write_json(
        shadow,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"family_id": "P2_SIGNAL_NOISE_SEPARATION", "family_category": "SPECIALIST_WEDGE", "shadow_policy_outcome": "ROUTE_TO_SPECIALIST", "exact_path_match": False, "divergence_from_static": True},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "family_category": "SPECIALIST_WEDGE", "shadow_policy_outcome": "ROUTE_TO_SPECIALIST", "exact_path_match": False, "divergence_from_static": True},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "family_category": "SPECIALIST_WEDGE", "shadow_policy_outcome": "ABSTAIN_FOR_REVIEW", "exact_path_match": False, "divergence_from_static": True},
                {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "family_category": "ABSTENTION_CONTROL", "shadow_policy_outcome": "ABSTAIN_FOR_REVIEW", "exact_path_match": False, "divergence_from_static": True},
                {"family_id": "STATIC_NO_ROUTE_CONTROL", "family_category": "STATIC_CONTROL", "shadow_policy_outcome": "STAY_STATIC_BASELINE", "exact_path_match": True, "divergence_from_static": False},
            ],
        },
    )
    _write_json(
        manifest,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "family_rows": [
                {"family_id": "P2_SIGNAL_NOISE_SEPARATION", "family_category": "SPECIALIST_WEDGE", "target_lobe_id": "lobe.p2.v1", "case_count": 5, "visible_case_count": 4, "held_out_case_count": 1, "alpha_liability": "Alpha can blur decisive and decorative constraints.", "acceptance_metric": "Lower failure cost than alpha."},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "family_category": "SPECIALIST_WEDGE", "target_lobe_id": "lobe.auditor.v1", "case_count": 5, "visible_case_count": 4, "held_out_case_count": 1, "alpha_liability": "Alpha can underprice receipt gaps.", "acceptance_metric": "Higher fail-closed correctness."},
                {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "family_category": "ABSTENTION_CONTROL", "target_lobe_id": "", "case_count": 4, "visible_case_count": 3, "held_out_case_count": 1, "alpha_liability": "Forced commitment under ambiguity can cost more than abstention.", "acceptance_metric": "Lower failure cost through lawful abstention."},
                {"family_id": "STATIC_NO_ROUTE_CONTROL", "family_category": "STATIC_CONTROL", "target_lobe_id": "lobe.alpha.v1", "case_count": 5, "visible_case_count": 4, "held_out_case_count": 1, "alpha_liability": "No liability should be asserted on true static-control families.", "acceptance_metric": "No-regression hold on the static control path."},
            ],
        },
    )
    _write_json(alpha, {"status": "PASS", "subject_head": subject_head, "rows": [{"family_id": "P2_SIGNAL_NOISE_SEPARATION", "alpha_should_lose_here_because": "Alpha can blur decisive and decorative constraints."}, {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "alpha_should_lose_here_because": "Alpha can sound acceptable while underpricing receipt gaps."}]})
    _write_json(oracle, {"status": "PASS", "subject_head": subject_head, "oracle_positive_family_ids": ["P2_SIGNAL_NOISE_SEPARATION", "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "BOUNDARY_ABSTENTION_CONTROL"]})
    _write_json(followthrough, {"status": "PASS", "subject_head": subject_head, "promotion_followthrough": {"candidate_adapter_id": "lobe.alpha.v1"}})

    payload = tranche.run_residual_alpha_dominance_packet_tranche(
        r5_receipt_path=r5,
        ordered_receipt_path=ordered,
        health_report_path=health,
        selection_receipt_path=selection,
        shadow_matrix_path=shadow,
        stage_pack_manifest_path=manifest,
        alpha_manifest_path=alpha,
        oracle_scorecard_path=oracle,
        followthrough_packet_path=followthrough,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    packet = payload["cohort0_residual_alpha_dominance_packet"]
    wedge_spec = payload["cohort0_residual_alpha_dominance_wedge_spec"]
    assert packet["status"] == "PASS"
    assert packet["verdict_posture"] == tranche.VERDICT_POSTURE
    assert packet["next_lawful_move"] == tranche.NEXT_MOVE
    assert wedge_spec["status"] == "PASS"

    rows = {row["family_id"]: row for row in packet["family_rows"]}
    assert rows["STATIC_NO_ROUTE_CONTROL"]["residual_status"] == tranche.STATUS_STATIC_HOLD
    assert rows["BOUNDARY_ABSTENTION_CONTROL"]["residual_status"] == tranche.STATUS_ABSTAIN
    assert rows["AUDITOR_ADMISSIBILITY_FAIL_CLOSED"]["residual_status"] == tranche.STATUS_MIXED
    assert rows["P2_SIGNAL_NOISE_SEPARATION"]["residual_status"] == tranche.STATUS_SPECIALIST

    tracked_packet = json.loads((reports_root / "cohort0_residual_alpha_dominance_packet.json").read_text(encoding="utf-8"))
    assert tracked_packet["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_DOMINANCE_PACKET"
