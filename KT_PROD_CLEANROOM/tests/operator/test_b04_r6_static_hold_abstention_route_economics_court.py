from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_static_hold_abstention_route_economics_court as court


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _base(status: str = "PASS") -> dict:
    return {
        "status": status,
        "current_git_head": "previous-validation-head",
        "current_main_head": "previous-validation-head",
        "architecture_binding_head": "architecture-head",
        "selected_architecture_id": court.SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": court.SELECTED_ARCHITECTURE_NAME,
        "selected_outcome": court.EXPECTED_PREVIOUS_OUTCOME,
        "authoritative_lane": court.PREVIOUS_LANE,
        "bound_universe_validated": True,
        "blind_universe_id": court.UNIVERSE_ID,
        "case_count": court.EXPECTED_CASE_COUNT,
        "failure_count": 0,
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
        "next_lawful_move": court.EXPECTED_PREVIOUS_NEXT_MOVE,
    }


def _cases() -> list[dict]:
    return [
        {"case_id": f"{court.CASE_PREFIX}{idx:04d}", "family_id": "TEST_FAMILY", "variant_type": "CANONICAL"}
        for idx in range(1, court.EXPECTED_CASE_COUNT + 1)
    ]


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    payloads = {
        "validation_contract": {**_base(), "schema_id": "validation_contract", "pass_count": 19},
        "validation_receipt": {**_base(), "schema_id": "validation_receipt", "pass_count": 19},
        "case_manifest": {**_base(), "schema_id": "case_manifest", "cases": _cases()},
        "case_manifest_validation": {**_base(), "schema_id": "case_manifest_validation"},
        "holdout_validation": {**_base(), "schema_id": "holdout_validation"},
        "leakage_validation": {**_base(), "schema_id": "leakage_validation"},
        "control_sibling_validation": {**_base(), "schema_id": "control_sibling_validation"},
        "diagnostic_only_validation": {**_base(), "schema_id": "diagnostic_only_validation"},
        "trust_zone_validation": {**_base(), "schema_id": "trust_zone_validation"},
        "no_authorization_drift": {**_base(), "schema_id": "no_authorization_drift"},
        "replay_validation": {**_base(), "schema_id": "replay_validation"},
        "previous_next_lawful_move": {**_base(), "schema_id": "next_lawful_move"},
    }
    prep_payloads = {
        "static_hold_draft": {**_base("PREP_ONLY"), "schema_id": "static_hold_draft"},
        "abstention_registry_draft": {**_base("PREP_ONLY"), "schema_id": "abstention_registry_draft"},
        "route_economics_draft": {**_base("PREP_ONLY"), "schema_id": "route_economics_draft"},
        "afsh_interface_draft": {**_base("PREP_ONLY"), "schema_id": "afsh_interface_draft"},
        "afsh_trace_schema_draft": {**_base("PREP_ONLY"), "schema_id": "afsh_trace_schema_draft"},
    }
    for role, payload in payloads.items():
        _write_json(root / court.INPUTS[role], payload)
    for role, payload in prep_payloads.items():
        _write_json(root / court.PREP_INPUTS[role], payload)
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "registry", "status": "PASS"})
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "scope", "status": "PASS"})
    return reports


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = court.AUTHORITY_BRANCH,
    head: str = "branch-head",
    origin_main: str = "main-head",
) -> None:
    monkeypatch.setattr(court, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(court.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(court.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(court.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        court,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    court.run(reports_root=reports)
    return reports


def _contract(outputs: Path) -> dict:
    return _load(outputs / court.OUTPUTS["court_contract"])


def _source_prep(outputs: Path) -> dict:
    return _load(outputs / court.OUTPUTS["afsh_source_packet_prep"])


def _features_prep(outputs: Path) -> dict:
    return _load(outputs / court.OUTPUTS["afsh_features_prep"])


def test_court_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == "main-head"


def test_court_contract_binds_selected_afsh_architecture(outputs: Path) -> None:
    assert _contract(outputs)["selected_architecture_id"] == court.SELECTED_ARCHITECTURE_ID


def test_court_contract_binds_validated_18_case_universe(outputs: Path) -> None:
    binding = _contract(outputs)["validated_blind_universe_binding"]
    assert binding["case_count"] == court.EXPECTED_CASE_COUNT
    assert binding["status"] == "BOUND_AND_VALIDATED"


def test_static_hold_is_default_positive_verdict(outputs: Path) -> None:
    verdict = _contract(outputs)["verdict_modes"]["STATIC_HOLD"]
    assert verdict["default"] is True
    assert verdict["positive_verdict"] is True


def test_abstain_is_positive_success_verdict(outputs: Path) -> None:
    assert _contract(outputs)["verdict_modes"]["ABSTAIN"]["positive_verdict"] is True


def test_null_route_is_anti_overrouting_control(outputs: Path) -> None:
    verdict = _contract(outputs)["verdict_modes"]["NULL_ROUTE"]
    assert verdict["anti_overrouting_control"] is True


def test_route_eligible_is_non_executing_precondition_only(outputs: Path) -> None:
    verdict = _contract(outputs)["verdict_modes"]["ROUTE_ELIGIBLE"]
    assert verdict["non_executing_precondition_only"] is True
    assert verdict["positive_verdict"] is False


def test_route_eligible_cannot_authorize_candidate_generation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["candidate_generation_authorized"] is False
    assert "AFSH candidate generation" in contract["route_eligible_cannot_authorize"]


def test_route_eligible_cannot_authorize_shadow_screen(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["shadow_screen_execution_authorized"] is False
    assert "shadow-screen execution" in contract["route_eligible_cannot_authorize"]


def test_route_eligible_cannot_authorize_activation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["activation_review_authorized"] is False
    assert "activation review" in contract["route_eligible_cannot_authorize"]


def test_route_eligible_cannot_authorize_package_promotion(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["package_promotion_remains_deferred"] is True
    assert "package promotion" in contract["route_eligible_cannot_authorize"]


def test_route_value_formula_contains_required_terms(outputs: Path) -> None:
    terms = set(_contract(outputs)["route_value_formula"]["terms"])
    assert set(court.ROUTE_VALUE_TERMS).issubset(terms)


def test_wrong_route_cost_required(outputs: Path) -> None:
    payload = _load(outputs / court.OUTPUTS["wrong_route_cost"])
    assert payload["wrong_route_cost_required"] is True


def test_wrong_static_hold_cost_required(outputs: Path) -> None:
    payload = _load(outputs / court.OUTPUTS["wrong_static_hold_cost"])
    assert payload["wrong_static_hold_cost_required"] is True


def test_proof_burden_delta_required(outputs: Path) -> None:
    payload = _load(outputs / court.OUTPUTS["proof_burden_delta"])
    assert payload["proof_burden_delta_required"] is True


def test_overrouting_penalty_required(outputs: Path) -> None:
    assert "overrouting_penalty" in _contract(outputs)["route_value_formula"]["terms"]


def test_abstention_violation_penalty_required(outputs: Path) -> None:
    assert "abstention_violation_penalty" in _contract(outputs)["route_value_formula"]["terms"]


def test_null_route_violation_penalty_required(outputs: Path) -> None:
    assert "null_route_violation_penalty" in _contract(outputs)["route_value_formula"]["terms"]


def test_mirror_masked_instability_penalty_required(outputs: Path) -> None:
    assert "mirror_masked_instability_penalty" in _contract(outputs)["route_value_formula"]["terms"]


def test_trace_complexity_penalty_required(outputs: Path) -> None:
    assert "trace_complexity_penalty" in _contract(outputs)["route_value_formula"]["terms"]


def test_trust_zone_risk_penalty_required(outputs: Path) -> None:
    assert "trust_zone_risk_penalty" in _contract(outputs)["route_value_formula"]["terms"]


def test_threshold_profile_is_frozen_before_candidate_generation(outputs: Path) -> None:
    payload = _load(outputs / court.OUTPUTS["threshold_profile"])
    assert payload["threshold_kind"] == "FROZEN_BEFORE_CANDIDATE_GENERATION"


def test_metric_widening_forbidden(outputs: Path) -> None:
    assert _contract(outputs)["metric_widening_allowed"] is False


def test_comparator_weakening_forbidden(outputs: Path) -> None:
    assert _contract(outputs)["comparator_weakening_allowed"] is False


def test_truth_engine_mutation_forbidden(outputs: Path) -> None:
    assert _contract(outputs)["truth_engine_derivation_law_unchanged"] is True


def test_trust_zone_mutation_forbidden(outputs: Path) -> None:
    assert _contract(outputs)["trust_zone_law_unchanged"] is True


def test_old_universes_remain_diagnostic_only(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["old_r01_r04_diagnostic_only"] is True
    assert contract["old_v2_six_row_diagnostic_only"] is True


def test_prep_only_source_packet_drafts_cannot_authorize_generation(outputs: Path) -> None:
    payload = _source_prep(outputs)
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_authorize_generation"] is True


def test_future_blocker_register_present(outputs: Path) -> None:
    payload = _load(outputs / court.OUTPUTS["future_blocker_register"])
    assert len(payload["blockers"]) >= 10


def test_next_lawful_move_is_court_validation(outputs: Path) -> None:
    payload = _load(outputs / court.OUTPUTS["next_lawful_move"])
    assert payload["next_lawful_move"] == court.NEXT_LAWFUL_MOVE


def test_allowed_forbidden_feature_draft_bars_blind_labels(outputs: Path) -> None:
    payload = _features_prep(outputs)
    assert "blind_outcome_labels" in payload["forbidden_features"]
    assert "old_r01_r04_counted_labels" in payload["forbidden_features"]


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    monkeypatch.setattr(court.common, "git_status_porcelain", lambda root: " M something")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        court.run(reports_root=reports)


def test_predecessor_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    receipt_path = tmp_path / court.INPUTS["validation_receipt"]
    receipt = _load(receipt_path)
    receipt["next_lawful_move"] = "WRONG_MOVE"
    _write_json(receipt_path, receipt)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="predecessor next lawful move"):
        court.run(reports_root=reports)


def test_prep_draft_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    draft_path = tmp_path / court.PREP_INPUTS["route_economics_draft"]
    draft = _load(draft_path)
    draft["status"] = "PASS"
    _write_json(draft_path, draft)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="route_economics_draft must remain PREP_ONLY"):
        court.run(reports_root=reports)
