from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_static_hold_abstention_route_economics_court_validation as validation


COURT_HEAD = "e8a00afa04ce1df380165b85b3620837160244a6"
BRANCH_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MAIN_HEAD = "7873ac6990e5f6c4fff8ccaac31eb31fe4547601"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _base(status: str = "PASS") -> dict:
    return {
        "status": status,
        "current_git_head": COURT_HEAD,
        "current_main_head": COURT_HEAD,
        "architecture_binding_head": "4279eefb58a34089dc0b1930765a36556454e968",
        "selected_architecture_id": validation.SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": validation.SELECTED_ARCHITECTURE_NAME,
        "selected_outcome": validation.EXPECTED_PREVIOUS_OUTCOME,
        "next_lawful_move": validation.EXPECTED_PREVIOUS_NEXT_MOVE,
        "authoritative_lane": validation.PREVIOUS_LANE,
        "previous_authoritative_lane": "B04_R6_NEW_BLIND_INPUT_UNIVERSE_VALIDATION",
        "r6_authorized": False,
        "r6_open": False,
        "router_generation_authorized": False,
        "candidate_generation_authorized": False,
        "candidate_training_authorized": False,
        "afsh_source_packet_authorized": False,
        "afsh_candidate_generation_authorized": False,
        "afsh_candidate_training_authorized": False,
        "shadow_screen_authorized": False,
        "new_shadow_screen_authorized": False,
        "shadow_screen_packet_authorized": False,
        "shadow_screen_execution_authorized": False,
        "learned_router_superiority_earned": False,
        "activation_review_authorized": False,
        "runtime_cutover_authorized": False,
        "learned_router_activated": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion_authorized": False,
        "package_promotion_approved": False,
        "commercial_broadening": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "old_r01_r04_diagnostic_only": True,
        "old_v2_six_row_diagnostic_only": True,
    }


def _binding() -> dict:
    return {
        "case_count": validation.EXPECTED_CASE_COUNT,
        "case_namespace": f"{validation.CASE_PREFIX}*",
        "prior_r01_r04_treatment": "DIAGNOSTIC_ONLY",
        "prior_v2_six_row_treatment": "DIAGNOSTIC_ONLY",
        "status": "BOUND_AND_VALIDATED",
        "validation_outcome": "B04_R6_NEW_BLIND_UNIVERSE_VALIDATED__STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_NEXT",
    }


def _verdict_modes() -> dict:
    return {
        "STATIC_HOLD": {"default": True, "positive_verdict": True},
        "ABSTAIN": {"default": False, "positive_verdict": True},
        "NULL_ROUTE": {"default": False, "positive_verdict": True, "anti_overrouting_control": True},
        "ROUTE_ELIGIBLE": {
            "default": False,
            "positive_verdict": False,
            "non_executing_precondition_only": True,
        },
    }


def _formula() -> dict:
    return {
        "expression": "test",
        "terms": list(validation.ROUTE_VALUE_TERMS),
        "route_eligible_requires": list(validation.ROUTE_ELIGIBILITY_GATES),
    }


def _court_payload() -> dict:
    return {
        **_base(),
        "schema_id": "kt.b04_r6.static_hold_abstention_route_economics_court.v1",
        "validated_blind_universe_binding": _binding(),
        "verdict_modes": _verdict_modes(),
        "route_value_formula": _formula(),
        "route_eligible_law": {
            "non_executing_precondition_only": True,
            "cannot_authorize": list(validation.ROUTE_ELIGIBLE_FORBIDDEN_AUTHORIZATIONS),
            "wins_only_when": list(validation.ROUTE_ELIGIBILITY_GATES),
        },
        "route_eligible_cannot_authorize": list(validation.ROUTE_ELIGIBLE_FORBIDDEN_AUTHORIZATIONS),
        "metric_widening_allowed": False,
        "comparator_weakening_allowed": False,
    }


def _prep_payload() -> dict:
    return {
        **_base("PREP_ONLY"),
        "authority": "PREP_ONLY",
        "draft_status": "PREP_ONLY",
        "cannot_authorize_generation": True,
        "cannot_authorize_training": True,
        "cannot_authorize_screen_packet": True,
        "cannot_authorize_shadow_screen_execution": True,
        "cannot_authorize_activation": True,
        "cannot_authorize_package_promotion": True,
        "next_lawful_move_required_before_authority": validation.EXPECTED_PREVIOUS_NEXT_MOVE,
    }


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    common = _court_payload()
    json_payloads = {
        "court_contract": {**common, "schema_id": "court_contract"},
        "court_receipt": {**common, "schema_id": "court_receipt"},
        "static_hold_control": {**_base(), "schema_id": "static_hold", "default_verdict": True},
        "abstention_registry": {**_base(), "schema_id": "abstention", "positive_success": True},
        "null_route_control": {**_base(), "schema_id": "null_route", "anti_overrouting_control": True},
        "route_economics": {
            **_base(),
            "schema_id": "route_economics",
            "positive_terms": list(validation.ROUTE_VALUE_POSITIVE_TERMS),
            "penalty_terms": list(validation.ROUTE_VALUE_PENALTY_TERMS),
            "route_eligible_is_non_executing": True,
            "routing_requires_positive_permission": True,
        },
        "wrong_route_cost": {**_base(), "schema_id": "wrong_route", "wrong_route_cost_required": True},
        "wrong_static_hold_cost": {
            **_base(),
            "schema_id": "wrong_static",
            "wrong_static_hold_cost_required": True,
            "tracked_but_not_route_authorizing_by_itself": True,
        },
        "proof_burden_delta": {
            **_base(),
            "schema_id": "proof",
            "proof_burden_delta_required": True,
            "routing_must_reduce_or_justify_proof_burden": True,
            "proof_burden_can_block_route": True,
        },
        "threshold_profile": {
            **_base(),
            "schema_id": "threshold",
            "threshold_kind": "FROZEN_BEFORE_CANDIDATE_GENERATION",
            "route_threshold_mutation_requires_later_court": True,
        },
        "reason_codes": {
            **_base(),
            "schema_id": "reason_codes",
            "reason_codes": {
                "STATIC_HOLD": ["RC_STATIC"],
                "ABSTAIN": ["RC_ABSTAIN"],
                "NULL_ROUTE": ["RC_NULL"],
                "ROUTE_ELIGIBLE": ["RC_ROUTE"],
                "TERMINAL_DEFECT": ["RC_TERMINAL"],
            },
        },
        "disqualifier_ledger": {
            **_base(),
            "schema_id": "disqualifier",
            "terminal_disqualifiers": [
                "metric_widening",
                "comparator_weakening",
                "truth_engine_mutation",
                "trust_zone_mutation",
                "candidate_generation_authorization_drift",
                "shadow_screen_authorization_drift",
                "r6_open_drift",
                "activation_authorization_drift",
                "package_promotion_drift",
                "old_universe_reused_as_fresh_proof",
                "label_or_outcome_leakage",
                "route_eligibility_authorizes_execution",
            ],
        },
        "no_authorization_drift": {
            **_base(),
            "schema_id": "no_auth",
            "no_downstream_authority_drift": True,
        },
        "validation_plan": {**_base(), "schema_id": "validation_plan"},
        "validation_reason_codes": {**_base(), "schema_id": "validation_reason_codes"},
        "future_blocker_register": {
            **_base(),
            "schema_id": "future_blockers",
            "blockers": [{"blocker_id": f"FB-{idx:02d}"} for idx in range(1, 11)],
        },
        "previous_next_lawful_move": {**_base(), "schema_id": "next_move"},
    }
    for role, payload in json_payloads.items():
        _write_json(root / validation.INPUTS[role], payload)
    for role in validation.PREP_INPUTS:
        _write_json(root / validation.PREP_INPUTS[role], {**_prep_payload(), "schema_id": role})
    _write_text(root / validation.TEXT_INPUTS["court_report"], "# Court\n\nSTATIC_HOLD\n")
    _write_text(root / validation.TEXT_INPUTS["validation_test_plan"], "# Test Plan\n")
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "registry", "status": "PASS"})
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "scope", "status": "PASS"})
    return reports


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validation.AUTHORITY_BRANCH,
    head: str = BRANCH_HEAD,
    origin_main: str = MAIN_HEAD,
) -> None:
    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


def _receipt(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_receipt"])


def _contract(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_contract"])


def _next(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["next_lawful_move"])


def _rows(outputs: Path) -> list[dict]:
    return _receipt(outputs)["validation_rows"]


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _rows(outputs)}


def test_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == MAIN_HEAD


def test_validation_contract_binds_court_replay_head(outputs: Path) -> None:
    assert _contract(outputs)["court_replay_binding_head"] == COURT_HEAD


def test_validation_contract_binds_selected_afsh_architecture(outputs: Path) -> None:
    assert _contract(outputs)["selected_architecture_id"] == validation.SELECTED_ARCHITECTURE_ID


def test_validation_contract_binds_validated_blind_universe(outputs: Path) -> None:
    assert _contract(outputs)["validated_blind_universe_binding"]["case_count"] == validation.EXPECTED_CASE_COUNT


def test_static_hold_is_default_positive_verdict(outputs: Path) -> None:
    assert "static_hold_is_default_positive_verdict" in _row_ids(outputs)


def test_abstain_is_positive_success_verdict(outputs: Path) -> None:
    assert "abstain_is_positive_success_verdict" in _row_ids(outputs)


def test_null_route_is_anti_overrouting_control(outputs: Path) -> None:
    assert "null_route_is_anti_overrouting_control" in _row_ids(outputs)


def test_route_eligible_is_non_executing_only(outputs: Path) -> None:
    assert "route_eligible_is_non_executing_only" in _row_ids(outputs)


def test_route_eligible_cannot_authorize_source_packet_finality(outputs: Path) -> None:
    assert "route_eligible_cannot_authorize_source_packet_finality" in _row_ids(outputs)


def test_route_eligible_cannot_authorize_candidate_generation(outputs: Path) -> None:
    assert "route_eligible_cannot_authorize_candidate_generation" in _row_ids(outputs)


def test_route_eligible_cannot_authorize_candidate_training(outputs: Path) -> None:
    assert "route_eligible_cannot_authorize_candidate_training" in _row_ids(outputs)


def test_route_eligible_cannot_authorize_shadow_screen_packet(outputs: Path) -> None:
    assert "route_eligible_cannot_authorize_shadow_screen_packet" in _row_ids(outputs)


def test_route_eligible_cannot_authorize_shadow_screen_execution(outputs: Path) -> None:
    assert "route_eligible_cannot_authorize_shadow_screen_execution" in _row_ids(outputs)


def test_route_eligible_cannot_authorize_r6_opening(outputs: Path) -> None:
    assert "route_eligible_cannot_authorize_r6_opening" in _row_ids(outputs)


def test_route_eligible_cannot_authorize_superiority(outputs: Path) -> None:
    assert "route_eligible_cannot_authorize_superiority" in _row_ids(outputs)


def test_route_eligible_cannot_authorize_activation_review(outputs: Path) -> None:
    assert "route_eligible_cannot_authorize_activation_review" in _row_ids(outputs)


def test_route_eligible_cannot_authorize_runtime_cutover(outputs: Path) -> None:
    assert "route_eligible_cannot_authorize_runtime_cutover" in _row_ids(outputs)


def test_route_eligible_cannot_authorize_lobe_escalation(outputs: Path) -> None:
    assert "route_eligible_cannot_authorize_lobe_escalation" in _row_ids(outputs)


def test_route_eligible_cannot_authorize_package_promotion(outputs: Path) -> None:
    assert "route_eligible_cannot_authorize_package_promotion" in _row_ids(outputs)


def test_route_value_formula_has_expected_quality_delta(outputs: Path) -> None:
    assert "route_value_formula_has_expected_quality_delta" in _row_ids(outputs)


def test_route_value_formula_has_expected_governance_benefit(outputs: Path) -> None:
    assert "route_value_formula_has_expected_governance_benefit" in _row_ids(outputs)


def test_route_value_formula_has_expected_proof_burden_reduction(outputs: Path) -> None:
    assert "route_value_formula_has_expected_proof_burden_reduction" in _row_ids(outputs)


def test_route_value_formula_has_expected_error_surface_reduction(outputs: Path) -> None:
    assert "route_value_formula_has_expected_error_surface_reduction" in _row_ids(outputs)


def test_route_value_formula_has_wrong_route_cost(outputs: Path) -> None:
    assert "route_value_formula_has_wrong_route_cost" in _row_ids(outputs)


def test_route_value_formula_has_wrong_static_hold_cost_if_applicable(outputs: Path) -> None:
    assert "route_value_formula_has_wrong_static_hold_cost_if_applicable" in _row_ids(outputs)


def test_route_value_formula_has_overrouting_penalty(outputs: Path) -> None:
    assert "route_value_formula_has_overrouting_penalty" in _row_ids(outputs)


def test_route_value_formula_has_abstention_violation_penalty(outputs: Path) -> None:
    assert "route_value_formula_has_abstention_violation_penalty" in _row_ids(outputs)


def test_route_value_formula_has_null_route_violation_penalty(outputs: Path) -> None:
    assert "route_value_formula_has_null_route_violation_penalty" in _row_ids(outputs)


def test_route_value_formula_has_mirror_masked_instability_penalty(outputs: Path) -> None:
    assert "route_value_formula_has_mirror_masked_instability_penalty" in _row_ids(outputs)


def test_route_value_formula_has_trace_complexity_penalty(outputs: Path) -> None:
    assert "route_value_formula_has_trace_complexity_penalty" in _row_ids(outputs)


def test_route_value_formula_has_trust_zone_risk_penalty(outputs: Path) -> None:
    assert "route_value_formula_has_trust_zone_risk_penalty" in _row_ids(outputs)


def test_threshold_profile_frozen_before_candidate_generation(outputs: Path) -> None:
    assert "threshold_profile_frozen_before_candidate_generation" in _row_ids(outputs)


def test_wrong_route_cost_contract_bound(outputs: Path) -> None:
    assert "wrong_route_cost_contract_bound" in _row_ids(outputs)


def test_wrong_static_hold_cost_contract_bound(outputs: Path) -> None:
    assert "wrong_static_hold_cost_contract_bound" in _row_ids(outputs)


def test_proof_burden_delta_contract_bound(outputs: Path) -> None:
    assert "proof_burden_delta_contract_bound" in _row_ids(outputs)


def test_static_hold_control_contract_bound(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["static_hold_verdict"])["static_hold_default_positive_verdict"] is True


def test_abstention_control_registry_bound(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["abstention_verdict"])["abstain_positive_success_verdict"] is True


def test_null_route_control_contract_bound(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["null_route_verdict"])["null_route_anti_overrouting_control"] is True


def test_reason_code_taxonomy_covers_all_verdict_modes(outputs: Path) -> None:
    ids = _row_ids(outputs)
    assert "reason_code_taxonomy_covers_static_hold" in ids
    assert "reason_code_taxonomy_covers_abstain" in ids
    assert "reason_code_taxonomy_covers_null_route" in ids
    assert "reason_code_taxonomy_covers_route_eligible" in ids


def test_disqualifier_ledger_marks_terminal_authorization_drift(outputs: Path) -> None:
    assert "disqualifier_ledger_marks_terminal_authorization_drift" in _row_ids(outputs)


def test_prep_only_source_packet_draft_cannot_authorize_generation(outputs: Path) -> None:
    assert "prep_only_source_packet_draft_cannot_authorize_generation" in _row_ids(outputs)


def test_prep_only_trace_schema_draft_cannot_authorize_screen(outputs: Path) -> None:
    assert "prep_only_trace_schema_draft_cannot_authorize_screen" in _row_ids(outputs)


def test_prep_only_provenance_matrix_cannot_authorize_candidate(outputs: Path) -> None:
    assert "prep_only_provenance_matrix_cannot_authorize_candidate" in _row_ids(outputs)


def test_future_blocker_register_present(outputs: Path) -> None:
    assert "future_blocker_register_present" in _row_ids(outputs)


def test_metric_widening_forbidden(outputs: Path) -> None:
    assert "metric_widening_forbidden" in _row_ids(outputs)


def test_comparator_weakening_forbidden(outputs: Path) -> None:
    assert "comparator_weakening_forbidden" in _row_ids(outputs)


def test_truth_engine_mutation_forbidden(outputs: Path) -> None:
    assert "truth_engine_mutation_forbidden" in _row_ids(outputs)


def test_trust_zone_mutation_forbidden(outputs: Path) -> None:
    assert "trust_zone_mutation_forbidden" in _row_ids(outputs)


def test_prior_r01_r04_remain_diagnostic_only(outputs: Path) -> None:
    assert "prior_r01_r04_remain_diagnostic_only" in _row_ids(outputs)


def test_prior_v2_six_row_remains_diagnostic_only(outputs: Path) -> None:
    assert "prior_v2_six_row_remains_diagnostic_only" in _row_ids(outputs)


def test_next_lawful_move_is_afsh_implementation_source_packet(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_pass_count_is_at_least_fifty(outputs: Path) -> None:
    assert _receipt(outputs)["pass_count"] >= 50


def test_source_packet_authorship_next_does_not_finalize_source_packet(outputs: Path) -> None:
    receipt = _receipt(outputs)
    assert receipt["source_packet_authorship_next_lawful"] is True
    assert receipt["afsh_source_packet_authorized"] is False
    assert receipt["source_packet_authority_not_finalized"] is True


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: " M something")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)


def test_previous_next_lawful_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    receipt_path = tmp_path / validation.INPUTS["previous_next_lawful_move"]
    receipt = _load(receipt_path)
    receipt["next_lawful_move"] = "WRONG_MOVE"
    _write_json(receipt_path, receipt)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_route_eligible_generation_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    contract_path = tmp_path / validation.INPUTS["court_contract"]
    contract = _load(contract_path)
    contract["route_eligible_law"]["cannot_authorize"].remove("AFSH candidate generation")
    _write_json(contract_path, contract)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="AUTHORIZES_GENERATION"):
        validation.run(reports_root=reports)


def test_metric_widening_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    economics_path = tmp_path / validation.INPUTS["route_economics"]
    economics = _load(economics_path)
    economics["metric_widening_allowed"] = True
    _write_json(economics_path, economics)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="METRIC_WIDENING"):
        validation.run(reports_root=reports)


def test_prep_only_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    draft_path = tmp_path / validation.PREP_INPUTS["afsh_source_packet_prep"]
    draft = _load(draft_path)
    draft["status"] = "PASS"
    _write_json(draft_path, draft)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PREP_ONLY"):
        validation.run(reports_root=reports)
