from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_residual_alpha_dominance_packet_tranche as tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def test_residual_alpha_dominance_packet_retargets_to_augmented_court_and_emits_new_surfaces(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    r5 = tmp_path / "cohort0_recomposed_router_vs_best_adapter_proof_receipt.json"
    ordered = tmp_path / "cohort0_recomposed_router_ordered_proof_receipt.json"
    health = tmp_path / "cohort0_recomposed_route_distribution_health.json"
    selection = tmp_path / "cohort0_recomposed_router_selection_receipt.json"
    shadow = tmp_path / "cohort0_recomposed_router_shadow_eval_matrix.json"
    augmentation_manifest = tmp_path / "cohort0_recomposed_counted_lane_augmentation_manifest.json"
    null_route = tmp_path / "cohort0_recomposed_null_route_counterfactual_packet.json"
    masked = tmp_path / "cohort0_recomposed_masked_form_variant_packet.json"
    orthogonality = tmp_path / "cohort0_recomposed_orthogonality_appendix.json"
    stress_tax = tmp_path / "cohort0_recomposed_promotion_stress_tax.json"
    pairwise_economics = tmp_path / "pairwise_route_economics_scorecard.json"
    followthrough = tmp_path / "cohort0_recomposed_router_shadow_followthrough_packet.json"

    _write_json(
        r5,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "next_lawful_move": "AUTHOR_RESIDUAL_ALPHA_DOMINANCE_PACKET",
            "verdict_posture": "FENCED_FAMILY_ROUTE_VALUE_EARNED__REMAIN_AT_R5_CEILING",
            "router_proof_summary": {
                "router_superiority_earned": False,
                "fenced_family_route_value_earned": True,
            },
        },
    )
    _write_json(
        ordered,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "verdict_posture": "FENCED_FAMILY_ROUTE_VALUE_EARNED__REMAIN_AT_R5_CEILING",
            "fenced_family_route_value_earned": True,
            "ordered_proof_outcome": "PASS_FENCED_FAMILY_ROUTE_VALUE_EARNED_STATIC_BASELINE_STILL_CANONICAL",
            "exact_superiority_outcome": "NOT_EARNED_FENCED_FAMILY_ROUTE_VALUE_PRESENT_STATIC_BASELINE_RETAINS_CANONICAL_STATUS",
            "learned_router_candidate_status": "FENCED_FAMILY_ROUTE_VALUE_SIGNAL_PRESENT__AUTHORIZATION_STILL_BLOCKED",
            "proof_object_deltas": {
                "route_distribution_delta_count_delta": 17,
                "shadow_match_rate_delta": -0.7727,
                "exact_path_universality_broken_current": True,
            },
        },
    )
    _write_json(
        health,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "route_distribution_delta_count": 17,
            "exact_path_universality_broken": True,
            "shadow_match_rate": 0.2273,
            "masked_variant_survival_rate": 1.0,
            "null_route_counterfactual_preservation_rate": 1.0,
            "control_preservation_rate": 1.0,
            "orthogonality_preserved": True,
            "promotion_stress_tax_acceptable": True,
            "fenced_family_route_value_signal": True,
            "unique_route_targets": ["lobe.alpha.v1", "lobe.auditor.v1", "lobe.beta.v1", "lobe.strategist.v1"],
        },
    )
    selection_rows = [
        {
            "case_id": "STRATEGIST__ROUTE",
            "case_role": "ROUTE_CANDIDATE",
            "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
            "family_category": "COUNTED_LANE_AUGMENTATION",
            "oracle_policy_outcome": "ROUTE_TO_SPECIALIST",
            "selected_adapter_ids": ["lobe.strategist.v1"],
            "divergence_from_static": True,
            "route_justification": "Route to lobe.strategist.v1 because Alpha can stop at a locally good answer without pricing downstream failure cost.",
            "masked_variant_of_case_id": "",
            "counterfactual_of_case_id": "",
            "mask_style": "",
        },
        {
            "case_id": "STRATEGIST__NULL",
            "case_role": "NULL_ROUTE_COUNTERFACTUAL",
            "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
            "family_category": "COUNTED_LANE_AUGMENTATION",
            "oracle_policy_outcome": "STAY_STATIC_BASELINE",
            "selected_adapter_ids": ["lobe.alpha.v1"],
            "divergence_from_static": False,
            "route_justification": "",
            "static_baseline_reason": "Static hold remains rightful on the counterfactual.",
            "masked_variant_of_case_id": "",
            "counterfactual_of_case_id": "STRATEGIST__ROUTE",
            "mask_style": "",
        },
        {
            "case_id": "STRATEGIST__MASKED",
            "case_role": "MASKED_FORM_VARIANT",
            "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
            "family_category": "COUNTED_LANE_AUGMENTATION",
            "oracle_policy_outcome": "ROUTE_TO_SPECIALIST",
            "selected_adapter_ids": ["lobe.strategist.v1"],
            "divergence_from_static": True,
            "route_justification": "Route to lobe.strategist.v1 because Alpha can stop at a locally good answer without pricing downstream failure cost.",
            "masked_variant_of_case_id": "STRATEGIST__ROUTE",
            "counterfactual_of_case_id": "",
            "mask_style": "EVIDENCE_ORDER_INVERSION",
        },
        {
            "case_id": "AUDITOR__ROUTE",
            "case_role": "ROUTE_CANDIDATE",
            "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
            "family_category": "COUNTED_LANE_AUGMENTATION",
            "oracle_policy_outcome": "ROUTE_TO_SPECIALIST",
            "selected_adapter_ids": ["lobe.auditor.v1"],
            "divergence_from_static": True,
            "route_justification": "Route to lobe.auditor.v1 because Alpha can sound acceptable while underpricing receipt gaps, policy breaks, or overclaim risk.",
            "masked_variant_of_case_id": "",
            "counterfactual_of_case_id": "",
            "mask_style": "",
        },
        {
            "case_id": "AUDITOR__NULL",
            "case_role": "NULL_ROUTE_COUNTERFACTUAL",
            "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
            "family_category": "COUNTED_LANE_AUGMENTATION",
            "oracle_policy_outcome": "ABSTAIN_FOR_REVIEW",
            "selected_adapter_ids": [],
            "divergence_from_static": True,
            "abstention_reason": "Counterfactual sibling makes routing unsafe.",
            "masked_variant_of_case_id": "",
            "counterfactual_of_case_id": "AUDITOR__ROUTE",
            "mask_style": "",
        },
        {
            "case_id": "AUDITOR__MASKED",
            "case_role": "MASKED_FORM_VARIANT",
            "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
            "family_category": "COUNTED_LANE_AUGMENTATION",
            "oracle_policy_outcome": "ROUTE_TO_SPECIALIST",
            "selected_adapter_ids": ["lobe.auditor.v1"],
            "divergence_from_static": True,
            "route_justification": "Route to lobe.auditor.v1 because Alpha can sound acceptable while underpricing receipt gaps, policy breaks, or overclaim risk.",
            "masked_variant_of_case_id": "AUDITOR__ROUTE",
            "counterfactual_of_case_id": "",
            "mask_style": "VOICE_AND_FORMAT_SHIFT",
        },
        {
            "case_id": "BETA__ROUTE",
            "case_role": "ROUTE_CANDIDATE",
            "family_id": "BETA_SECOND_ORDER_REFRAME",
            "family_category": "COUNTED_LANE_AUGMENTATION",
            "oracle_policy_outcome": "ROUTE_TO_SPECIALIST",
            "selected_adapter_ids": ["lobe.beta.v1"],
            "divergence_from_static": True,
            "route_justification": "Route to lobe.beta.v1 because Alpha can overcommit to the first clean framing instead of holding a live rival interpretation.",
            "masked_variant_of_case_id": "",
            "counterfactual_of_case_id": "",
            "mask_style": "",
        },
        {
            "case_id": "BETA__NULL",
            "case_role": "NULL_ROUTE_COUNTERFACTUAL",
            "family_id": "BETA_SECOND_ORDER_REFRAME",
            "family_category": "COUNTED_LANE_AUGMENTATION",
            "oracle_policy_outcome": "STAY_STATIC_BASELINE",
            "selected_adapter_ids": ["lobe.alpha.v1"],
            "divergence_from_static": False,
            "route_justification": "",
            "masked_variant_of_case_id": "",
            "counterfactual_of_case_id": "BETA__ROUTE",
            "mask_style": "",
        },
        {
            "case_id": "BETA__MASKED",
            "case_role": "MASKED_FORM_VARIANT",
            "family_id": "BETA_SECOND_ORDER_REFRAME",
            "family_category": "COUNTED_LANE_AUGMENTATION",
            "oracle_policy_outcome": "ROUTE_TO_SPECIALIST",
            "selected_adapter_ids": ["lobe.beta.v1"],
            "divergence_from_static": True,
            "route_justification": "Route to lobe.beta.v1 because Alpha can overcommit to the first clean framing instead of holding a live rival interpretation.",
            "masked_variant_of_case_id": "BETA__ROUTE",
            "counterfactual_of_case_id": "",
            "mask_style": "DOMAIN_SKIN_SHIFT",
        },
        {
            "case_id": "BOUNDARY__CONTROL",
            "case_role": "CONTROL",
            "family_id": "BOUNDARY_ABSTENTION_CONTROL",
            "family_category": "ABSTENTION_CONTROL",
            "oracle_policy_outcome": "ABSTAIN_FOR_REVIEW",
            "selected_adapter_ids": [],
            "divergence_from_static": True,
            "abstention_reason": "Abstention control remains the rightful fail-closed response.",
            "masked_variant_of_case_id": "",
            "counterfactual_of_case_id": "",
            "mask_style": "",
        },
        {
            "case_id": "BOUNDARY__CONTROL_MASKED",
            "case_role": "CONTROL",
            "family_id": "BOUNDARY_ABSTENTION_CONTROL",
            "family_category": "ABSTENTION_CONTROL",
            "oracle_policy_outcome": "ABSTAIN_FOR_REVIEW",
            "selected_adapter_ids": [],
            "divergence_from_static": True,
            "abstention_reason": "Abstention control remains the rightful fail-closed response.",
            "masked_variant_of_case_id": "",
            "counterfactual_of_case_id": "",
            "mask_style": "VOICE_AND_FORMAT_SHIFT",
        },
        {
            "case_id": "STATIC__CONTROL",
            "case_role": "CONTROL",
            "family_id": "STATIC_NO_ROUTE_CONTROL",
            "family_category": "STATIC_CONTROL",
            "oracle_policy_outcome": "STAY_STATIC_BASELINE",
            "selected_adapter_ids": ["lobe.alpha.v1"],
            "divergence_from_static": False,
            "route_justification": "",
            "masked_variant_of_case_id": "",
            "counterfactual_of_case_id": "",
            "mask_style": "",
        },
        {
            "case_id": "STATIC__CONTROL_MASKED",
            "case_role": "CONTROL",
            "family_id": "STATIC_NO_ROUTE_CONTROL",
            "family_category": "STATIC_CONTROL",
            "oracle_policy_outcome": "STAY_STATIC_BASELINE",
            "selected_adapter_ids": ["lobe.alpha.v1"],
            "divergence_from_static": False,
            "route_justification": "",
            "masked_variant_of_case_id": "",
            "counterfactual_of_case_id": "",
            "mask_style": "EVIDENCE_ORDER_INVERSION",
        },
    ]
    _write_json(selection, {"status": "PASS", "subject_head": subject_head, "case_rows": selection_rows})
    _write_json(
        shadow,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {
                    "case_id": row["case_id"],
                    "family_id": row["family_id"],
                    "family_category": row["family_category"],
                    "shadow_policy_outcome": row["oracle_policy_outcome"],
                    "exact_path_match": row["oracle_policy_outcome"] == "STAY_STATIC_BASELINE",
                    "divergence_from_static": row["divergence_from_static"],
                }
                for row in selection_rows
            ],
        },
    )
    _write_json(
        augmentation_manifest,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "ready_family_ids": [
                "STRATEGIST_CONSEQUENCE_CHAIN",
                "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
                "BETA_SECOND_ORDER_REFRAME",
            ],
            "control_family_ids": ["BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"],
            "route_case_family_counts": [
                {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "target_lobe_id": "lobe.strategist.v1"},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "target_lobe_id": "lobe.auditor.v1"},
                {"family_id": "BETA_SECOND_ORDER_REFRAME", "target_lobe_id": "lobe.beta.v1"},
            ],
        },
    )
    _write_json(
        null_route,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"case_id": "STRATEGIST__NULL"},
                {"case_id": "AUDITOR__NULL"},
                {"case_id": "BETA__NULL"},
            ],
        },
    )
    _write_json(
        masked,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"case_id": "STRATEGIST__MASKED", "family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "masked_variant_of_case_id": "STRATEGIST__ROUTE", "mask_style": "EVIDENCE_ORDER_INVERSION", "expected_policy_outcome": "ROUTE_TO_SPECIALIST", "selected_adapter_ids": ["lobe.strategist.v1"]},
                {"case_id": "AUDITOR__MASKED", "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "masked_variant_of_case_id": "AUDITOR__ROUTE", "mask_style": "VOICE_AND_FORMAT_SHIFT", "expected_policy_outcome": "ROUTE_TO_SPECIALIST", "selected_adapter_ids": ["lobe.auditor.v1"]},
                {"case_id": "BETA__MASKED", "family_id": "BETA_SECOND_ORDER_REFRAME", "masked_variant_of_case_id": "BETA__ROUTE", "mask_style": "DOMAIN_SKIN_SHIFT", "expected_policy_outcome": "ROUTE_TO_SPECIALIST", "selected_adapter_ids": ["lobe.beta.v1"]},
                {"case_id": "BOUNDARY__CONTROL_MASKED", "family_id": "BOUNDARY_ABSTENTION_CONTROL", "masked_variant_of_case_id": "", "mask_style": "VOICE_AND_FORMAT_SHIFT", "expected_policy_outcome": "ABSTAIN_FOR_REVIEW", "selected_adapter_ids": []},
                {"case_id": "STATIC__CONTROL_MASKED", "family_id": "STATIC_NO_ROUTE_CONTROL", "masked_variant_of_case_id": "", "mask_style": "EVIDENCE_ORDER_INVERSION", "expected_policy_outcome": "STAY_STATIC_BASELINE", "selected_adapter_ids": ["lobe.alpha.v1"]},
            ],
        },
    )
    _write_json(
        orthogonality,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN__AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "orthogonality_score": 0.9, "orthogonal_enough_for_joint_augmentation": True},
                {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN__BETA_SECOND_ORDER_REFRAME", "orthogonality_score": 0.85, "orthogonal_enough_for_joint_augmentation": True},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED__BETA_SECOND_ORDER_REFRAME", "orthogonality_score": 0.9, "orthogonal_enough_for_joint_augmentation": True},
            ],
        },
    )
    _write_json(
        stress_tax,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "added_proof_burden_tier": "MEDIUM", "expected_governance_roi_tier": "HIGH"},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "added_proof_burden_tier": "HIGH", "expected_governance_roi_tier": "VERY_HIGH"},
                {"family_id": "BETA_SECOND_ORDER_REFRAME", "added_proof_burden_tier": "MEDIUM", "expected_governance_roi_tier": "MEDIUM"},
            ],
        },
    )
    _write_json(
        pairwise_economics,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "mean_static_failure_cost": 1.538, "mean_misroute_cost": 2.378, "mean_abstain_miss_cost": 2.088, "mean_routed_execution_cost": 1.025, "mean_governance_roi": 0.513, "net_route_value_score": 0.48},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "mean_static_failure_cost": 1.518, "mean_misroute_cost": 2.298, "mean_abstain_miss_cost": 2.013, "mean_routed_execution_cost": 1.048, "mean_governance_roi": 0.391, "net_route_value_score": 0.394},
                {"family_id": "BETA_SECOND_ORDER_REFRAME", "mean_static_failure_cost": 1.478, "mean_misroute_cost": 2.298, "mean_abstain_miss_cost": 2.048, "mean_routed_execution_cost": 1.053, "mean_governance_roi": 0.328, "net_route_value_score": 0.34},
            ],
        },
    )
    _write_json(
        followthrough,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "promotion_followthrough": {"candidate_adapter_id": "lobe.alpha.v1"},
        },
    )

    payload = tranche.run_residual_alpha_dominance_packet_tranche(
        r5_receipt_path=r5,
        ordered_receipt_path=ordered,
        health_report_path=health,
        selection_receipt_path=selection,
        shadow_matrix_path=shadow,
        augmentation_manifest_path=augmentation_manifest,
        null_route_path=null_route,
        masked_path=masked,
        orthogonality_path=orthogonality,
        stress_tax_path=stress_tax,
        pairwise_route_economics_path=pairwise_economics,
        followthrough_packet_path=followthrough,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    packet = payload["cohort0_residual_alpha_dominance_packet"]
    wedge_spec = payload["cohort0_residual_alpha_dominance_wedge_spec"]
    route_economics_payload = payload["cohort0_recomposed_case_level_route_economics"]
    shortcut_tags = payload["cohort0_recomposed_shortcut_resistance_tags"]

    assert packet["status"] == "PASS"
    assert packet["verdict_posture"] == tranche.VERDICT_POSTURE
    assert packet["next_lawful_move"] == tranche.NEXT_MOVE
    assert wedge_spec["status"] == "PASS"
    assert route_economics_payload["status"] == "PASS"
    assert shortcut_tags["status"] == "PASS"

    rows = {row["family_id"]: row for row in packet["family_rows"]}
    assert set(rows) == {
        "STRATEGIST_CONSEQUENCE_CHAIN",
        "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
        "BETA_SECOND_ORDER_REFRAME",
        "BOUNDARY_ABSTENTION_CONTROL",
        "STATIC_NO_ROUTE_CONTROL",
    }
    assert rows["STRATEGIST_CONSEQUENCE_CHAIN"]["residual_status"] == tranche.STATUS_FENCED_ROUTE
    assert rows["AUDITOR_ADMISSIBILITY_FAIL_CLOSED"]["residual_status"] == tranche.STATUS_FENCED_MIXED
    assert rows["BOUNDARY_ABSTENTION_CONTROL"]["residual_status"] == tranche.STATUS_CONTROL_ABSTAIN
    assert rows["STATIC_NO_ROUTE_CONTROL"]["residual_status"] == tranche.STATUS_CONTROL_STATIC

    strategist_shortcuts = rows["STRATEGIST_CONSEQUENCE_CHAIN"]["shortcut_resistance"]
    assert strategist_shortcuts["evidence_order"] == "RESISTANT"
    assert strategist_shortcuts["domain_cues"] == "NOT_TESTED"

    economics_rows = {row["case_id"]: row for row in route_economics_payload["rows"]}
    assert economics_rows["STRATEGIST__ROUTE"]["wrong_static_hold_cost"] > 0
    assert economics_rows["STRATEGIST__ROUTE"]["proof_burden_saved_if_correct_policy"] > 0
    assert economics_rows["BOUNDARY__CONTROL"]["missed_abstention_cost"] > 0

    shortcut_rows = {row["case_id"]: row for row in shortcut_tags["rows"]}
    assert shortcut_rows["AUDITOR__MASKED"]["formatting_cues_attacked"] is True
    assert shortcut_rows["BETA__MASKED"]["domain_cues_attacked"] is True
    assert shortcut_rows["BETA__MASKED"]["shortcut_dependency_detected"] is False

    tracked_packet = json.loads((reports_root / "cohort0_residual_alpha_dominance_packet.json").read_text(encoding="utf-8"))
    tracked_route_econ = json.loads((reports_root / "cohort0_recomposed_case_level_route_economics.json").read_text(encoding="utf-8"))
    tracked_shortcuts = json.loads((reports_root / "cohort0_recomposed_shortcut_resistance_tags.json").read_text(encoding="utf-8"))
    assert tracked_packet["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_DOMINANCE_PACKET"
    assert tracked_route_econ["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_RECOMPOSED_CASE_LEVEL_ROUTE_ECONOMICS"
    assert tracked_shortcuts["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_RECOMPOSED_SHORTCUT_RESISTANCE_TAGS"
