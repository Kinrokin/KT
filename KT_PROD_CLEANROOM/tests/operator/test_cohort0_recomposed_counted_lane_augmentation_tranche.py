from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT
from tools.operator import cohort0_recomposed_counted_lane_augmentation_tranche as tranche


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def test_recomposed_counted_lane_augmentation_tranche_binds_ready_set_with_controls_and_appendices(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative_augmentation"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    recomposed_substrate = reports_root / "cohort0_recomposed_13_entrant_substrate_receipt.json"
    recomposed_manifest = reports_root / "cohort0_recomposed_13_entrant_manifest.json"
    pairwise_augmentation = reports_root / "pairwise_counted_lane_augmentation_packet.json"
    pairwise_report = reports_root / "pairwise_transfer_candidate_report.json"
    wedge_spec = reports_root / "cohort0_residual_alpha_dominance_wedge_spec.json"
    stage_pack_manifest = reports_root / "route_bearing_stage_pack_manifest.json"
    route_policy_registry = reports_root / "route_policy_outcome_registry.json"

    _write_json(recomposed_substrate, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        recomposed_manifest,
        {
            "subject_head": subject_head,
            "entries": [
                {"adapter_id": "lobe.strategist.v1", "entry_mode": "REFRESHED_TARGETED"},
                {"adapter_id": "lobe.auditor.v1", "entry_mode": "REFRESHED_TARGETED"},
                {"adapter_id": "lobe.beta.v1", "entry_mode": "REFRESHED_TARGETED"},
            ],
        },
    )
    _write_json(
        pairwise_augmentation,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "next_lawful_move": "AUTHOR_RECOMPOSED_COUNTED_LANE_AUGMENTATION_TRANCHE__ORDERED_PROOF_ONLY",
            "ready_family_ids": [
                "STRATEGIST_CONSEQUENCE_CHAIN",
                "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
                "BETA_SECOND_ORDER_REFRAME",
            ],
            "rows": [
                {
                    "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
                    "target_lobe_id": "lobe.strategist.v1",
                    "named_wedge_sharpening": "PAIRWISE_SHARPENED__HOP_DEPTH__X__TEMPORAL_DISTORTION",
                    "named_anti_alpha_liability": "strategist liability",
                    "measurable_route_delta_hypothesis": "delta strategist",
                    "net_route_value_score": 0.48,
                },
                {
                    "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
                    "target_lobe_id": "lobe.auditor.v1",
                    "named_wedge_sharpening": "PAIRWISE_SHARPENED__PROOF_DISCIPLINE_BURDEN__X__ADVERSARIAL_AMBIGUITY",
                    "named_anti_alpha_liability": "auditor liability",
                    "measurable_route_delta_hypothesis": "delta auditor",
                    "net_route_value_score": 0.394,
                },
                {
                    "family_id": "BETA_SECOND_ORDER_REFRAME",
                    "target_lobe_id": "lobe.beta.v1",
                    "named_wedge_sharpening": "PAIRWISE_SHARPENED__PARADOX_PRESSURE__X__CROSS_DOMAIN_OVERLAY",
                    "named_anti_alpha_liability": "beta liability",
                    "measurable_route_delta_hypothesis": "delta beta",
                    "net_route_value_score": 0.34,
                },
            ],
        },
    )
    _write_json(pairwise_report, {"status": "PASS", "subject_head": subject_head})
    _write_json(
        wedge_spec,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "rows": [
                {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "success_condition": "strategist metric", "new_admissible_eval_family": "STRATEGIST_CONSEQUENCE_CHAIN__RESIDUAL_ALPHA_DOMINANCE"},
                {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "success_condition": "auditor metric", "new_admissible_eval_family": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED__RESIDUAL_ALPHA_DOMINANCE"},
                {"family_id": "BETA_SECOND_ORDER_REFRAME", "success_condition": "beta metric", "new_admissible_eval_family": "BETA_SECOND_ORDER_REFRAME__RESIDUAL_ALPHA_DOMINANCE"},
            ],
        },
    )
    _write_json(
        stage_pack_manifest,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "scoring_channels": ["task_quality", "proof_completeness", "traceability"],
            "family_rows": [
                {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "family_category": "ABSTENTION_CONTROL", "target_lobe_id": "", "alpha_liability": "abstain liability"},
                {"family_id": "STATIC_NO_ROUTE_CONTROL", "family_category": "STATIC_CONTROL", "target_lobe_id": "lobe.alpha.v1", "alpha_liability": "static liability"},
            ],
        },
    )
    _write_json(
        route_policy_registry,
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

    payload = tranche.run_recomposed_counted_lane_augmentation_tranche(
        recomposed_substrate_path=recomposed_substrate,
        recomposed_manifest_path=recomposed_manifest,
        pairwise_augmentation_path=pairwise_augmentation,
        pairwise_report_path=pairwise_report,
        wedge_spec_path=wedge_spec,
        stage_pack_manifest_path=stage_pack_manifest,
        route_policy_registry_path=route_policy_registry,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    receipt = payload["cohort0_recomposed_counted_lane_augmentation_receipt"]
    manifest = payload["cohort0_recomposed_counted_lane_augmentation_manifest"]
    null_packet = payload["cohort0_recomposed_null_route_counterfactual_packet"]
    masked_packet = payload["cohort0_recomposed_masked_form_variant_packet"]
    orthogonality = payload["cohort0_recomposed_orthogonality_appendix"]
    stress_tax = payload["cohort0_recomposed_promotion_stress_tax"]

    assert receipt["status"] == "PASS"
    assert receipt["recomposed_counted_lane_augmentation_posture"] == tranche.POSTURE
    assert receipt["ready_family_ids"] == [
        "STRATEGIST_CONSEQUENCE_CHAIN",
        "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
        "BETA_SECOND_ORDER_REFRAME",
    ]
    assert manifest["case_count"] == 22
    assert manifest["null_route_counterfactual_count"] == 6
    assert manifest["masked_variant_count"] == 8
    assert len(null_packet["rows"]) == 6
    assert len(masked_packet["rows"]) == 8
    assert len(orthogonality["rows"]) == 3
    assert len(stress_tax["rows"]) == 3

    tracked = json.loads((reports_root / "cohort0_recomposed_counted_lane_augmentation_receipt.json").read_text(encoding="utf-8"))
    assert tracked["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_RECOMPOSED_COUNTED_LANE_AUGMENTATION_RECEIPT"
