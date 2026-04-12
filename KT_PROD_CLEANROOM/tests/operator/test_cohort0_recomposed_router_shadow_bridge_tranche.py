from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_recomposed_router_shadow_bridge_tranche as tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def test_recomposed_router_shadow_bridge_emits_r5_admissible_shadow_surfaces(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    recomposed_substrate = tmp_path / "cohort0_recomposed_13_entrant_substrate_receipt.json"
    followthrough = tmp_path / "cohort0_real_engine_tournament_followthrough_packet.json"
    promotion_outcome = tmp_path / "cohort0_promotion_outcome_binding_receipt.json"
    merge_outcome = tmp_path / "cohort0_merge_outcome_binding_receipt.json"
    oracle_packet = tmp_path / "oracle_router_local_eval_packet.json"
    oracle_scorecard = tmp_path / "oracle_router_local_scorecard.json"
    stage_pack_manifest = tmp_path / "route_bearing_stage_pack_manifest.json"
    policy_registry = tmp_path / "route_policy_outcome_registry.json"

    _write_json(
        recomposed_substrate,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "recomposition_posture": "RECOMPOSED_13_ENTRANT_SUBSTRATE_BOUND__TOURNAMENT_RERUN_ADMISSIBLE",
        },
    )
    _write_json(
        followthrough,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "followthrough_posture": "PROMOTION_AND_MERGE_OUTCOME_BOUND__ROUTER_SHADOW_EVALUATION_REQUIRED",
            "next_lawful_move": "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION",
        },
    )
    _write_json(
        promotion_outcome,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "promotion_posture": "PROMOTION_OUTCOME_BOUND__MERGE_PASS_CHILD_READY_FOR_ROUTER_SHADOW_EVALUATION",
            "candidate": {"adapter_id": "lobe.alpha.v1"},
        },
    )
    _write_json(
        merge_outcome,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "merge_outcome_posture": "MERGE_OUTCOME_BOUND__PASS__ROLLBACK_READY",
        },
    )
    _write_json(
        oracle_packet,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "case_results": [
                {
                    "case_id": "FAMILY__ROUTE",
                    "case_sha256": "a",
                    "case_variant": "ADVERSARIAL",
                    "family_id": "P2_SIGNAL_NOISE_SEPARATION",
                    "family_category": "SPECIALIST_WEDGE",
                    "pack_visibility": "VISIBLE_TO_AUTHORING",
                    "oracle_policy_outcome": "ROUTE_TO_SPECIALIST",
                    "selected_adapter_ids": ["lobe.p2.v1"],
                    "divergence_from_static": True,
                    "preregistered_expectation_satisfied": True,
                    "route_justification": "route",
                    "static_baseline_reason": "",
                    "abstention_reason": "",
                    "review_handoff_rule": "",
                    "safety_effect": "ROUTE_EXPECTED_TO_REDUCE_ALPHA_LIABILITY",
                },
                {
                    "case_id": "FAMILY__ABSTAIN",
                    "case_sha256": "b",
                    "case_variant": "BOUNDARY_TRIAGE",
                    "family_id": "BOUNDARY_ABSTENTION_CONTROL",
                    "family_category": "ABSTENTION_CONTROL",
                    "pack_visibility": "VISIBLE_TO_AUTHORING",
                    "oracle_policy_outcome": "ABSTAIN_FOR_REVIEW",
                    "selected_adapter_ids": [],
                    "divergence_from_static": True,
                    "preregistered_expectation_satisfied": True,
                    "route_justification": "",
                    "static_baseline_reason": "",
                    "abstention_reason": "abstain",
                    "review_handoff_rule": "handoff",
                    "safety_effect": "ABSTENTION_EXPECTED_TO_DE_RISK_FORCED_COMMITMENT",
                },
                {
                    "case_id": "FAMILY__STAY",
                    "case_sha256": "c",
                    "case_variant": "STATIC",
                    "family_id": "STATIC_NO_ROUTE_CONTROL",
                    "family_category": "STATIC_CONTROL",
                    "pack_visibility": "VISIBLE_TO_AUTHORING",
                    "oracle_policy_outcome": "STAY_STATIC_BASELINE",
                    "selected_adapter_ids": [],
                    "divergence_from_static": False,
                    "preregistered_expectation_satisfied": True,
                    "route_justification": "",
                    "static_baseline_reason": "hold static",
                    "abstention_reason": "",
                    "review_handoff_rule": "",
                    "safety_effect": "STATIC_CONTROL_HOLD",
                },
            ],
        },
    )
    _write_json(
        oracle_scorecard,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "nonzero_route_divergence": True,
            "oracle_positive_family_ids": ["P2_SIGNAL_NOISE_SEPARATION", "BOUNDARY_ABSTENTION_CONTROL"],
        },
    )
    _write_json(
        stage_pack_manifest,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "family_rows": [
                {"family_id": "P2_SIGNAL_NOISE_SEPARATION", "target_lobe_id": "lobe.p2.v1", "family_category": "SPECIALIST_WEDGE"},
                {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "target_lobe_id": "", "family_category": "ABSTENTION_CONTROL"},
                {"family_id": "STATIC_NO_ROUTE_CONTROL", "target_lobe_id": "lobe.alpha.v1", "family_category": "STATIC_CONTROL"},
            ],
        },
    )
    _write_json(
        policy_registry,
        {
            "status": "PASS",
            "outcomes": [
                {"outcome_id": "ROUTE_TO_SPECIALIST"},
                {"outcome_id": "STAY_STATIC_BASELINE"},
                {"outcome_id": "ABSTAIN_FOR_REVIEW"},
            ],
        },
    )

    payload = tranche.run_recomposed_router_shadow_bridge_tranche(
        recomposed_substrate_report_path=recomposed_substrate,
        followthrough_report_path=followthrough,
        promotion_outcome_report_path=promotion_outcome,
        merge_outcome_report_path=merge_outcome,
        oracle_packet_path=oracle_packet,
        oracle_scorecard_path=oracle_scorecard,
        stage_pack_manifest_path=stage_pack_manifest,
        policy_registry_path=policy_registry,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    receipt = payload["router_shadow_bridge_receipt"]
    scorecard = payload["router_superiority_scorecard"]
    health = payload["route_distribution_health"]

    assert receipt["status"] == "PASS"
    assert receipt["binding_posture"] == tranche.BRIDGE_POSTURE_READY
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_R5
    assert health["route_distribution_delta_count"] == 2
    assert health["exact_path_universality_broken"] is True
    assert scorecard["r5_admissible"] is True
    assert scorecard["router_superiority_earned"] is False

    tracked = json.loads((reports_root / "cohort0_recomposed_router_shadow_bridge_receipt.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_SHADOW_BRIDGE_RECEIPT"
