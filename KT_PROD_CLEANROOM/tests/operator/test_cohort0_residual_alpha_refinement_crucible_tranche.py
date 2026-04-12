from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_residual_alpha_refinement_crucible_tranche as tranche

from KT_PROD_CLEANROOM.tests.operator.test_cohort0_kaggle_import_tranche import ROOT


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def test_residual_alpha_refinement_crucible_tranche_emits_lab_only_packet_for_three_live_families(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    authoritative_root = tmp_path / "authoritative"
    subject_head = "5f1fb07200fe8fcbce57ef1ed92d1189ab571c91"

    residual_packet_authoritative = tmp_path / "authoritative_residual_packet.json"
    residual_packet_tracked = tmp_path / "tracked_residual_packet.json"
    wedge_spec_authoritative = tmp_path / "authoritative_wedge_spec.json"
    wedge_spec_tracked = tmp_path / "tracked_wedge_spec.json"
    route_econ_authoritative = tmp_path / "authoritative_route_economics.json"
    route_econ_tracked = tmp_path / "tracked_route_economics.json"
    shortcut_authoritative = tmp_path / "authoritative_shortcuts.json"
    shortcut_tracked = tmp_path / "tracked_shortcuts.json"
    transfer_guard_authoritative = tmp_path / "authoritative_transfer_guard.json"
    transfer_guard_tracked = tmp_path / "tracked_transfer_guard.json"
    verdict_authoritative = tmp_path / "authoritative_verdict_grammar.json"
    verdict_tracked = tmp_path / "tracked_verdict_grammar.json"

    _write_json(
        residual_packet_authoritative,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "next_lawful_move": "AUTHOR_RESIDUAL_ALPHA_REFINEMENT_CRUCIBLES__LAB_ONLY",
            "residual_alpha_dominance_summary": {
                "route_distribution_delta_count": 17,
                "exact_path_universality_broken": True,
                "specialist_signal_families": [
                    "STRATEGIST_CONSEQUENCE_CHAIN",
                    "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
                    "BETA_SECOND_ORDER_REFRAME",
                ],
            },
            "proof_object_movement": {
                "route_distribution_delta_count_current": 17,
            },
        },
    )
    _write_json(
        residual_packet_tracked,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "authoritative_cohort0_residual_alpha_dominance_packet_ref": residual_packet_authoritative.as_posix(),
        },
    )

    wedge_rows = [
        {
            "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
            "target_lobe_id": "lobe.strategist.v1",
            "family_thesis": "Route strategist where downstream cost actually matters.",
            "alpha_liability": "Alpha underprices downstream failure cost.",
            "residual_status": "FENCED_FAMILY_ROUTE_AND_FAIL_CLOSED_VALUE_PRESENT__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY",
            "next_focus": "STRATEGIST_CONSEQUENCE_CHAIN__SHARPEN_SEQUENCE_COST_AND_NULL_ROUTE_BOUNDARIES",
            "primary_pressure_axis": "hop_depth_and_causal_branching",
            "secondary_pressure_axis": "temporal_distortion",
            "shortcut_resistance_required": True,
            "minimum_mean_net_policy_advantage": 0.9262,
            "new_admissible_eval_family": "STRATEGIST_CONSEQUENCE_CHAIN__RESIDUAL_ALPHA_REFINEMENT",
            "held_out_preservation_rule": "Hold held-out rows out of authoring.",
            "success_condition": "Strengthen superiority-relevant proof without losing controls.",
            "failure_condition": "Loses restraint or shortcut resistance.",
        },
        {
            "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
            "target_lobe_id": "lobe.auditor.v1",
            "family_thesis": "Route auditor where governance cost matters.",
            "alpha_liability": "Alpha can sound acceptable while underpricing receipt gaps.",
            "residual_status": "FENCED_FAMILY_ROUTE_AND_FAIL_CLOSED_VALUE_PRESENT__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY",
            "next_focus": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED__SHARPEN_BREACH_TRIAGE_WITHOUT_LOSING_FAIL_CLOSED_DISCIPLINE",
            "primary_pressure_axis": "adversarial_ambiguity",
            "secondary_pressure_axis": "governed_execution_burden",
            "shortcut_resistance_required": True,
            "minimum_mean_net_policy_advantage": 0.8797,
            "new_admissible_eval_family": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED__RESIDUAL_ALPHA_REFINEMENT",
            "held_out_preservation_rule": "Hold held-out rows out of authoring.",
            "success_condition": "Strengthen superiority-relevant proof without losing controls.",
            "failure_condition": "Loses restraint or shortcut resistance.",
        },
        {
            "family_id": "BETA_SECOND_ORDER_REFRAME",
            "target_lobe_id": "lobe.beta.v1",
            "family_thesis": "Route beta where rival-frame preservation matters.",
            "alpha_liability": "Alpha can overcommit to the first clean framing.",
            "residual_status": "FENCED_FAMILY_ROUTE_AND_FAIL_CLOSED_VALUE_PRESENT__STILL_NEEDS_BRANCH_LEVEL_SUPERIORITY",
            "next_focus": "BETA_SECOND_ORDER_REFRAME__SHARPEN_RIVAL_FRAME_COUNTERREAD_WITHOUT_ALPHA_COLLAPSE",
            "primary_pressure_axis": "paradox_and_second_order_reframing",
            "secondary_pressure_axis": "language_complexity_or_domain_overlay",
            "shortcut_resistance_required": True,
            "minimum_mean_net_policy_advantage": 0.8557,
            "new_admissible_eval_family": "BETA_SECOND_ORDER_REFRAME__RESIDUAL_ALPHA_REFINEMENT",
            "held_out_preservation_rule": "Hold held-out rows out of authoring.",
            "success_condition": "Strengthen superiority-relevant proof without losing controls.",
            "failure_condition": "Loses restraint or shortcut resistance.",
        },
        {
            "family_id": "BOUNDARY_ABSTENTION_CONTROL",
            "target_lobe_id": "",
            "family_thesis": "Keep abstention lawful.",
            "alpha_liability": "Forced commitment can cost more than abstention.",
            "residual_status": "RIGHTFUL_ABSTENTION__CONTROL_FAMILY",
            "next_focus": "BOUNDARY_ABSTENTION_CONTROL__PRESERVE_FAIL_CLOSED_HANDOFF_DISCIPLINE",
            "primary_pressure_axis": "abstention_calibration",
            "secondary_pressure_axis": "overclaim_guard",
            "shortcut_resistance_required": True,
            "minimum_mean_net_policy_advantage": 0.816,
            "new_admissible_eval_family": "BOUNDARY_ABSTENTION_CONTROL__RESIDUAL_ALPHA_REFINEMENT",
            "held_out_preservation_rule": "Hold held-out rows out of authoring.",
            "success_condition": "Abstention remains rightful.",
            "failure_condition": "Forced routing displaces abstention.",
        },
        {
            "family_id": "STATIC_NO_ROUTE_CONTROL",
            "target_lobe_id": "lobe.alpha.v1",
            "family_thesis": "Protect rightful static hold.",
            "alpha_liability": "No liability on true static controls.",
            "residual_status": "RIGHTFUL_STATIC_HOLD__CONTROL_FAMILY",
            "next_focus": "STATIC_NO_ROUTE_CONTROL__PRESERVE_RIGHTFUL_STATIC_HOLD",
            "primary_pressure_axis": "hold_constant",
            "secondary_pressure_axis": "no_regression_guard",
            "shortcut_resistance_required": True,
            "minimum_mean_net_policy_advantage": 0.748,
            "new_admissible_eval_family": "STATIC_NO_ROUTE_CONTROL__RESIDUAL_ALPHA_REFINEMENT",
            "held_out_preservation_rule": "Hold held-out rows out of authoring.",
            "success_condition": "Static hold remains rightful.",
            "failure_condition": "Any new routing appears.",
        },
    ]
    _write_json(wedge_spec_authoritative, {"status": "PASS", "subject_head": subject_head, "rows": wedge_rows})
    _write_json(
        wedge_spec_tracked,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "authoritative_cohort0_residual_alpha_dominance_wedge_spec_ref": wedge_spec_authoritative.as_posix(),
        },
    )

    route_rows = [
        {
            "case_id": "STRATEGIST__ROUTE",
            "case_role": "ROUTE_CANDIDATE",
            "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
            "expected_policy_outcome": "ROUTE_TO_SPECIALIST",
            "net_policy_advantage": 0.513,
            "wrong_static_hold_cost": 1.538,
            "wrong_route_cost": 2.378,
            "missed_abstention_cost": 0.0,
            "proof_burden_saved_if_correct_policy": 0.513,
        },
        {
            "case_id": "STRATEGIST__NULL",
            "case_role": "NULL_ROUTE_COUNTERFACTUAL",
            "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
            "expected_policy_outcome": "STAY_STATIC_BASELINE",
            "net_policy_advantage": 1.648,
            "wrong_static_hold_cost": 1.384,
            "wrong_route_cost": 2.14,
            "missed_abstention_cost": 1.879,
            "proof_burden_saved_if_correct_policy": 0.346,
        },
        {
            "case_id": "STRATEGIST__MASKED",
            "case_role": "MASKED_FORM_VARIANT",
            "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
            "expected_policy_outcome": "ROUTE_TO_SPECIALIST",
            "net_policy_advantage": 0.487,
            "wrong_static_hold_cost": 1.461,
            "wrong_route_cost": 2.259,
            "missed_abstention_cost": 0.0,
            "proof_burden_saved_if_correct_policy": 0.487,
        },
        {
            "case_id": "AUDITOR__ROUTE",
            "case_role": "ROUTE_CANDIDATE",
            "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
            "expected_policy_outcome": "ROUTE_TO_SPECIALIST",
            "net_policy_advantage": 0.47,
            "wrong_static_hold_cost": 1.518,
            "wrong_route_cost": 2.298,
            "missed_abstention_cost": 0.0,
            "proof_burden_saved_if_correct_policy": 0.391,
        },
        {
            "case_id": "AUDITOR__NULL",
            "case_role": "NULL_ROUTE_COUNTERFACTUAL",
            "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
            "expected_policy_outcome": "ABSTAIN_FOR_REVIEW",
            "net_policy_advantage": 1.614,
            "wrong_static_hold_cost": 1.366,
            "wrong_route_cost": 2.068,
            "missed_abstention_cost": 1.812,
            "proof_burden_saved_if_correct_policy": 0.264,
        },
        {
            "case_id": "AUDITOR__MASKED",
            "case_role": "MASKED_FORM_VARIANT",
            "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
            "expected_policy_outcome": "ROUTE_TO_SPECIALIST",
            "net_policy_advantage": 0.446,
            "wrong_static_hold_cost": 1.442,
            "wrong_route_cost": 2.183,
            "missed_abstention_cost": 0.0,
            "proof_burden_saved_if_correct_policy": 0.371,
        },
        {
            "case_id": "BETA__ROUTE",
            "case_role": "ROUTE_CANDIDATE",
            "family_id": "BETA_SECOND_ORDER_REFRAME",
            "expected_policy_outcome": "ROUTE_TO_SPECIALIST",
            "net_policy_advantage": 0.425,
            "wrong_static_hold_cost": 1.478,
            "wrong_route_cost": 2.298,
            "missed_abstention_cost": 0.0,
            "proof_burden_saved_if_correct_policy": 0.328,
        },
        {
            "case_id": "BETA__NULL",
            "case_role": "NULL_ROUTE_COUNTERFACTUAL",
            "family_id": "BETA_SECOND_ORDER_REFRAME",
            "expected_policy_outcome": "ABSTAIN_FOR_REVIEW",
            "net_policy_advantage": 1.645,
            "wrong_static_hold_cost": 1.33,
            "wrong_route_cost": 2.068,
            "missed_abstention_cost": 1.843,
            "proof_burden_saved_if_correct_policy": 0.221,
        },
        {
            "case_id": "BETA__MASKED",
            "case_role": "MASKED_FORM_VARIANT",
            "family_id": "BETA_SECOND_ORDER_REFRAME",
            "expected_policy_outcome": "ROUTE_TO_SPECIALIST",
            "net_policy_advantage": 0.404,
            "wrong_static_hold_cost": 1.404,
            "wrong_route_cost": 2.183,
            "missed_abstention_cost": 0.0,
            "proof_burden_saved_if_correct_policy": 0.312,
        },
        {
            "case_id": "BOUNDARY__CONTROL",
            "case_role": "CONTROL",
            "family_id": "BOUNDARY_ABSTENTION_CONTROL",
            "expected_policy_outcome": "ABSTAIN_FOR_REVIEW",
            "net_policy_advantage": 0.816,
            "wrong_static_hold_cost": 0.918,
            "wrong_route_cost": 0.986,
            "missed_abstention_cost": 1.003,
            "proof_burden_saved_if_correct_policy": 0.115,
        },
        {
            "case_id": "STATIC__CONTROL",
            "case_role": "CONTROL",
            "family_id": "STATIC_NO_ROUTE_CONTROL",
            "expected_policy_outcome": "STAY_STATIC_BASELINE",
            "net_policy_advantage": 0.748,
            "wrong_static_hold_cost": 0.0,
            "wrong_route_cost": 0.799,
            "missed_abstention_cost": 0.0,
            "proof_burden_saved_if_correct_policy": 0.068,
        },
    ]
    _write_json(route_econ_authoritative, {"status": "PASS", "subject_head": subject_head, "rows": route_rows})
    _write_json(
        route_econ_tracked,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "authoritative_cohort0_recomposed_case_level_route_economics_ref": route_econ_authoritative.as_posix(),
        },
    )

    shortcut_rows = [
        {
            "case_id": "STRATEGIST__MASKED",
            "family_id": "STRATEGIST_CONSEQUENCE_CHAIN",
            "shortcut_channels_attacked": ["domain_cues"],
            "shortcut_dependency_detected": False,
            "shortcut_resistance_status": "SHORTCUT_RESISTANT__MASKED_SURVIVAL_CONFIRMED",
        },
        {
            "case_id": "AUDITOR__MASKED",
            "family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
            "shortcut_channels_attacked": ["lexical_cues", "formatting_cues"],
            "shortcut_dependency_detected": False,
            "shortcut_resistance_status": "SHORTCUT_RESISTANT__MASKED_SURVIVAL_CONFIRMED",
        },
        {
            "case_id": "BETA__MASKED",
            "family_id": "BETA_SECOND_ORDER_REFRAME",
            "shortcut_channels_attacked": ["evidence_order"],
            "shortcut_dependency_detected": False,
            "shortcut_resistance_status": "SHORTCUT_RESISTANT__MASKED_SURVIVAL_CONFIRMED",
        },
        {
            "case_id": "BOUNDARY__CONTROL",
            "family_id": "BOUNDARY_ABSTENTION_CONTROL",
            "shortcut_channels_attacked": ["lexical_cues"],
            "shortcut_dependency_detected": False,
            "shortcut_resistance_status": "SHORTCUT_RESISTANT__MASKED_SURVIVAL_CONFIRMED",
        },
        {
            "case_id": "STATIC__CONTROL",
            "family_id": "STATIC_NO_ROUTE_CONTROL",
            "shortcut_channels_attacked": ["evidence_order"],
            "shortcut_dependency_detected": False,
            "shortcut_resistance_status": "SHORTCUT_RESISTANT__MASKED_SURVIVAL_CONFIRMED",
        },
    ]
    shortcut_summaries = [
        {"family_id": "STRATEGIST_CONSEQUENCE_CHAIN", "lexical_cues": "NOT_TESTED", "formatting_cues": "NOT_TESTED", "domain_cues": "RESISTANT", "evidence_order": "RESISTANT", "shortcut_resistant": True},
        {"family_id": "AUDITOR_ADMISSIBILITY_FAIL_CLOSED", "lexical_cues": "RESISTANT", "formatting_cues": "RESISTANT", "domain_cues": "RESISTANT", "evidence_order": "NOT_TESTED", "shortcut_resistant": True},
        {"family_id": "BETA_SECOND_ORDER_REFRAME", "lexical_cues": "NOT_TESTED", "formatting_cues": "NOT_TESTED", "domain_cues": "RESISTANT", "evidence_order": "RESISTANT", "shortcut_resistant": True},
        {"family_id": "BOUNDARY_ABSTENTION_CONTROL", "lexical_cues": "RESISTANT", "formatting_cues": "RESISTANT", "domain_cues": "NOT_TESTED", "evidence_order": "NOT_TESTED", "shortcut_resistant": True},
        {"family_id": "STATIC_NO_ROUTE_CONTROL", "lexical_cues": "NOT_TESTED", "formatting_cues": "NOT_TESTED", "domain_cues": "NOT_TESTED", "evidence_order": "RESISTANT", "shortcut_resistant": True},
    ]
    _write_json(shortcut_authoritative, {"status": "PASS", "subject_head": subject_head, "rows": shortcut_rows, "family_summaries": shortcut_summaries})
    _write_json(
        shortcut_tracked,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "authoritative_cohort0_recomposed_shortcut_resistance_tags_ref": shortcut_authoritative.as_posix(),
        },
    )

    _write_json(
        transfer_guard_authoritative,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "counted_lane_stays_closed_until": [
                "a named wedge sharpening exists",
                "a named anti-alpha liability remains live",
                "a measurable route-delta hypothesis is satisfied",
                "a new admissible eval family is emitted",
                "rerun proof objects move under ordered proof",
            ],
            "preserved_controls": {
                "abstention_control_family_ids": ["BOUNDARY_ABSTENTION_CONTROL"],
                "static_hold_family_ids": ["STATIC_NO_ROUTE_CONTROL"],
            },
        },
    )
    _write_json(
        transfer_guard_tracked,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "authoritative_lab_to_counted_transfer_guard_ref": transfer_guard_authoritative.as_posix(),
        },
    )

    _write_json(
        verdict_authoritative,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "allowed_verdicts": [
                {"verdict_id": "GATE_D_MATERIALLY_ADVANCED__REMAIN_AT_R5_CEILING"},
                {"verdict_id": "FENCED_FAMILY_ROUTE_VALUE_EARNED"},
                {"verdict_id": "LEARNED_ROUTER_CANDIDATE_ADMISSIBLE_NOT_AUTHORIZED"},
                {"verdict_id": "RESIDUAL_ALPHA_DOMINANCE_PRIMARY_BLOCKER"},
                {"verdict_id": "COUNTED_LANE_CONTAMINATION_DETECTED__RESULT_VOID"},
                {"verdict_id": "ROUTER_SUPERIORITY_EARNED"},
            ],
        },
    )
    _write_json(
        verdict_tracked,
        {
            "status": "PASS",
            "subject_head": subject_head,
            "authoritative_counted_lane_verdict_grammar_ref": verdict_authoritative.as_posix(),
        },
    )

    payload = tranche.run_residual_alpha_refinement_crucible_tranche(
        residual_packet_path=residual_packet_tracked,
        residual_wedge_spec_path=wedge_spec_tracked,
        route_economics_path=route_econ_tracked,
        shortcut_tags_path=shortcut_tracked,
        transfer_guard_path=transfer_guard_tracked,
        verdict_grammar_path=verdict_tracked,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=ROOT,
    )

    manifest = payload["cohort0_residual_alpha_refinement_crucible_manifest"]
    registry = payload["cohort0_residual_alpha_refinement_crucible_registry"]
    transfer = payload["cohort0_residual_alpha_refinement_transfer_candidates"]
    receipt = payload["cohort0_residual_alpha_refinement_crucible_receipt"]

    assert manifest["status"] == "PASS"
    assert manifest["specialist_family_ids"] == list(tranche.SPECIALIST_FAMILY_IDS)
    assert manifest["control_family_ids"] == list(tranche.CONTROL_FAMILY_IDS)
    assert receipt["status"] == "PASS"
    assert receipt["residual_alpha_refinement_posture"] == tranche.POSTURE
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE

    manifest_rows = {row["family_id"]: row for row in manifest["family_rows"]}
    assert set(manifest_rows) == set(tranche.FAMILY_ORDER)
    assert manifest_rows["STRATEGIST_CONSEQUENCE_CHAIN"]["route_case_ids"] == ["STRATEGIST__ROUTE"]
    assert manifest_rows["AUDITOR_ADMISSIBILITY_FAIL_CLOSED"]["null_route_case_ids"] == ["AUDITOR__NULL"]
    assert manifest_rows["BETA_SECOND_ORDER_REFRAME"]["masked_case_ids"] == ["BETA__MASKED"]

    registry_rows = {row["family_id"]: row for row in registry["rows"]}
    assert registry_rows["STRATEGIST_CONSEQUENCE_CHAIN"]["shortcut_resistance_summary"]["domain_cues"] == "RESISTANT"
    assert registry_rows["AUDITOR_ADMISSIBILITY_FAIL_CLOSED"]["route_economics_summary"]["maximum_missed_abstention_cost"] == 1.812
    assert registry_rows["STATIC_NO_ROUTE_CONTROL"]["control_family"] is True

    transfer_rows = {row["family_id"]: row for row in transfer["rows"]}
    assert transfer_rows["STRATEGIST_CONSEQUENCE_CHAIN"]["transfer_candidate_status"] == "PENDING_REFINEMENT_EXECUTION"
    assert transfer_rows["BOUNDARY_ABSTENTION_CONTROL"]["transfer_candidate_status"] == "CONTROL_ONLY_NOT_TRANSFER_CANDIDATE"
    assert transfer_rows["BETA_SECOND_ORDER_REFRAME"]["masked_survival_floor"] == 1.0

    strategist_input = authoritative_root / "residual_alpha_refinement_inputs" / "STRATEGIST_CONSEQUENCE_CHAIN" / "residual_refinement_inputs.jsonl"
    assert strategist_input.is_file()
    strategist_lines = strategist_input.read_text(encoding="utf-8").splitlines()
    assert len(strategist_lines) == len(tranche.PRESSURE_LADDER) * len(tranche.PROMPT_FRAMES) * 3
    first_row = json.loads(strategist_lines[0])
    assert first_row["source_case_id"] in {"STRATEGIST__ROUTE", "STRATEGIST__NULL", "STRATEGIST__MASKED"}
    assert first_row["primary_pressure_axis"] == "hop_depth_and_causal_branching"

    tracked_receipt = json.loads((reports_root / tranche.DEFAULT_TRACKED_RECEIPT).read_text(encoding="utf-8"))
    tracked_manifest = json.loads((reports_root / tranche.DEFAULT_TRACKED_MANIFEST).read_text(encoding="utf-8"))
    assert tracked_receipt["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_REFINEMENT_CRUCIBLE_RECEIPT"
    assert tracked_manifest["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_COHORT0_RESIDUAL_ALPHA_REFINEMENT_CRUCIBLE_MANIFEST"
