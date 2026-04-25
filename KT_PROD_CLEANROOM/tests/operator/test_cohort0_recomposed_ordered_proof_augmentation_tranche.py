from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_recomposed_ordered_proof_augmentation_tranche as tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def test_recomposed_ordered_proof_augmentation_executes_full_shadow_and_r5_chain(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    recomposed_substrate = tmp_path / "cohort0_recomposed_13_entrant_substrate_receipt.json"
    followthrough = tmp_path / "cohort0_recomposed_router_shadow_followthrough_packet.json"
    promotion_outcome = tmp_path / "cohort0_promotion_outcome_binding_receipt.json"
    merge_outcome = tmp_path / "cohort0_merge_outcome_binding_receipt.json"
    augmentation_receipt = tmp_path / "cohort0_recomposed_counted_lane_augmentation_receipt.json"
    augmentation_manifest = tmp_path / "cohort0_recomposed_counted_lane_augmentation_manifest.json"
    null_route = tmp_path / "cohort0_recomposed_null_route_counterfactual_packet.json"
    masked = tmp_path / "cohort0_recomposed_masked_form_variant_packet.json"
    orthogonality = tmp_path / "cohort0_recomposed_orthogonality_appendix.json"
    stress_tax = tmp_path / "cohort0_recomposed_promotion_stress_tax.json"
    pre_health = tmp_path / "route_distribution_health.json"
    pre_scorecard = tmp_path / "router_superiority_scorecard.json"
    case_rows = tmp_path / "cohort0_recomposed_counted_lane_augmentation_cases.json"

    _write_json(recomposed_substrate, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        followthrough,
        {"status": "PASS", "subject_head": subject_head, "followthrough_posture": "RECOMPOSED_PROMOTION_AND_MERGE_BOUND__ROUTER_SHADOW_SURFACES_EMITTED"},
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
        {"status": "PASS", "subject_head": subject_head, "merge_outcome_posture": "MERGE_OUTCOME_BOUND__PASS__ROLLBACK_READY"},
    )
    _write_json(
        case_rows,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {
                    "case_id": "STRATEGIST_CONSEQUENCE_CHAIN__ROUTE",
                    "case_sha256": "a",
                    "case_variant": "ROUTE",
                    "case_role": "ROUTE_CANDIDATE",
                    "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
                    "family_category": "COUNTED_LANE_AUGMENTATION",
                    "expected_policy_outcome": "ROUTE_TO_SPECIALIST",
                    "selected_adapter_ids": ["lobe.strategist.v1"],
                    "target_lobe_id": "lobe.strategist.v1",
                    "alpha_liability": "alpha misses downstream consequence",
                    "objective": "route strategist",
                    "pack_visibility": "VISIBLE_TO_ORDERED_PROOF",
                },
                {
                    "case_id": "STRATEGIST_CONSEQUENCE_CHAIN__ROUTE__MASKED",
                    "case_sha256": "b",
                    "case_variant": "ROUTE__MASKED",
                    "case_role": "MASKED_FORM_VARIANT",
                    "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
                    "family_category": "COUNTED_LANE_AUGMENTATION",
                    "expected_policy_outcome": "ROUTE_TO_SPECIALIST",
                    "selected_adapter_ids": ["lobe.strategist.v1"],
                    "target_lobe_id": "lobe.strategist.v1",
                    "alpha_liability": "alpha misses downstream consequence",
                    "objective": "route strategist masked",
                    "pack_visibility": "VISIBLE_TO_ORDERED_PROOF",
                    "masked_variant_of_case_id": "STRATEGIST_CONSEQUENCE_CHAIN__ROUTE",
                },
                {
                    "case_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED__NULL",
                    "case_sha256": "c",
                    "case_variant": "NULL",
                    "case_role": "NULL_ROUTE_COUNTERFACTUAL",
                    "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
                    "family_category": "COUNTED_LANE_AUGMENTATION",
                    "expected_policy_outcome": "ABSTAIN_FOR_REVIEW",
                    "selected_adapter_ids": [],
                    "target_lobe_id": "lobe.auditor.v1",
                    "alpha_liability": "alpha underprices receipt gaps",
                    "objective": "abstain auditor",
                    "pack_visibility": "VISIBLE_TO_ORDERED_PROOF",
                    "counterfactual_of_case_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED__ROUTE",
                    "abstention_reason": "abstain",
                    "review_handoff_rule": "handoff",
                },
                {
                    "case_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED__ROUTE",
                    "case_sha256": "d",
                    "case_variant": "ROUTE",
                    "case_role": "ROUTE_CANDIDATE",
                    "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
                    "family_category": "COUNTED_LANE_AUGMENTATION",
                    "expected_policy_outcome": "ROUTE_TO_SPECIALIST",
                    "selected_adapter_ids": ["lobe.auditor.v1"],
                    "target_lobe_id": "lobe.auditor.v1",
                    "alpha_liability": "alpha underprices receipt gaps",
                    "objective": "route auditor",
                    "pack_visibility": "VISIBLE_TO_ORDERED_PROOF",
                },
                {
                    "case_id": "BETA_SECOND_ORDER_REFRAME__ROUTE",
                    "case_sha256": "e",
                    "case_variant": "ROUTE",
                    "case_role": "ROUTE_CANDIDATE",
                    "family_id": "BETA_SECOND_ORDER_REFRAME",
                    "family_category": "COUNTED_LANE_AUGMENTATION",
                    "expected_policy_outcome": "ROUTE_TO_SPECIALIST",
                    "selected_adapter_ids": ["lobe.beta.v1"],
                    "target_lobe_id": "lobe.beta.v1",
                    "alpha_liability": "alpha overcommits to first framing",
                    "objective": "route beta",
                    "pack_visibility": "VISIBLE_TO_ORDERED_PROOF",
                },
                {
                    "case_id": "BOUNDARY_ABSTENTION_CONTROL__CONTROL",
                    "case_sha256": "f",
                    "case_variant": "CONTROL",
                    "case_role": "CONTROL",
                    "family_id": "BOUNDARY_ABSTENTION_CONTROL",
                    "family_category": "ABSTENTION_CONTROL",
                    "expected_policy_outcome": "ABSTAIN_FOR_REVIEW",
                    "selected_adapter_ids": [],
                    "target_lobe_id": "",
                    "alpha_liability": "forced commitment costs more here",
                    "objective": "control abstain",
                    "pack_visibility": "VISIBLE_TO_ORDERED_PROOF",
                    "abstention_reason": "abstain",
                    "review_handoff_rule": "handoff",
                },
                {
                    "case_id": "STATIC_NO_ROUTE_CONTROL__CONTROL",
                    "case_sha256": "g",
                    "case_variant": "CONTROL",
                    "case_role": "CONTROL",
                    "family_id": "STATIC_NO_ROUTE_CONTROL",
                    "family_category": "STATIC_CONTROL",
                    "expected_policy_outcome": "STAY_STATIC_BASELINE",
                    "selected_adapter_ids": ["lobe.alpha.v1"],
                    "target_lobe_id": "lobe.alpha.v1",
                    "alpha_liability": "none",
                    "objective": "control static",
                    "pack_visibility": "VISIBLE_TO_ORDERED_PROOF",
                    "static_baseline_reason": "hold static",
                },
            ],
        },
    )
    _write_json(
        augmentation_receipt,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "recomposed_counted_lane_augmentation_posture": "RECOMPOSED_COUNTED_LANE_AUGMENTATION_BOUND__ORDERED_PROOF_READY__COUNTED_LANE_STILL_CLOSED",
        },
    )
    _write_json(augmentation_manifest, {"status": "PASS", "subject_head": subject_head, "case_rows_ref": case_rows.as_posix()})
    _write_json(null_route, {"status": "PASS", "subject_head": subject_head})
    _write_json(masked, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        orthogonality,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"orthogonality_score": 0.9, "orthogonal_enough_for_joint_augmentation": True},
                {"orthogonality_score": 0.85, "orthogonal_enough_for_joint_augmentation": True},
            ],
        },
    )
    _write_json(
        stress_tax,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"promotion_recommended": True, "added_operator_burden_tier": "LOW", "expected_governance_roi_tier": "HIGH"},
                {"promotion_recommended": True, "added_operator_burden_tier": "MEDIUM", "expected_governance_roi_tier": "VERY_HIGH"},
                {"promotion_recommended": True, "added_operator_burden_tier": "LOW", "expected_governance_roi_tier": "MEDIUM"},
            ],
        },
    )
    _write_json(pre_health, {"status": "PASS", "subject_head": subject_head, "route_distribution_delta_count": 0, "shadow_match_rate": 1.0})
    _write_json(pre_scorecard, {"status": "PASS", "subject_head": subject_head})

    payload = tranche.run_recomposed_ordered_proof_augmentation_tranche(
        recomposed_substrate_path=recomposed_substrate,
        followthrough_path=followthrough,
        promotion_outcome_path=promotion_outcome,
        merge_outcome_path=merge_outcome,
        augmentation_receipt_path=augmentation_receipt,
        augmentation_manifest_path=augmentation_manifest,
        null_route_path=null_route,
        masked_path=masked,
        orthogonality_path=orthogonality,
        stress_tax_path=stress_tax,
        pre_kaggle_health_path=pre_health,
        pre_kaggle_scorecard_path=pre_scorecard,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    health = payload["route_distribution_health"]
    ordered = payload["router_ordered_proof_receipt"]
    r5 = payload["router_vs_best_adapter_proof_receipt"]

    assert health["masked_variant_survival_rate"] == 1.0
    assert health["null_route_counterfactual_preservation_rate"] == 1.0
    assert health["control_preservation_rate"] == 1.0
    assert health["fenced_family_route_value_signal"] is True
    assert ordered["status"] == "PASS"
    assert ordered["fenced_family_route_value_earned"] is True
    assert ordered["verdict_posture"] == tranche.VERDICT_FENCED_FAMILY
    assert r5["status"] == "PASS"
    assert r5["router_proof_summary"]["router_superiority_earned"] is False
    assert r5["router_proof_summary"]["fenced_family_route_value_earned"] is True
    assert r5["next_lawful_move"] == tranche.NEXT_MOVE_RESIDUAL

    tracked = json.loads((reports_root / "cohort0_recomposed_router_vs_best_adapter_proof_receipt.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_VS_BEST_ADAPTER_PROOF_RECEIPT"
