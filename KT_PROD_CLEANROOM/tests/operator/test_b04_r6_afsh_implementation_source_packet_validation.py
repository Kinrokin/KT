from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_afsh_implementation_source_packet_validation as validation


SOURCE_PACKET_HEAD = "beef30cec8e63253dcffab574bccbac09ce82de3"
BRANCH_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MAIN_HEAD = "bdddb3f1a9958808f537302114e86866e3f24f3b"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _universe_binding() -> dict:
    return {
        "case_count": validation.EXPECTED_CASE_COUNT,
        "case_namespace": f"{validation.CASE_PREFIX}*",
        "prior_r01_r04_treatment": "DIAGNOSTIC_ONLY",
        "prior_v2_six_row_treatment": "DIAGNOSTIC_ONLY",
        "status": "BOUND_AND_VALIDATED",
    }


def _court_binding() -> dict:
    return {
        "status": "BOUND_AND_VALIDATED",
        "source_packet_input_validation_head": "022a7bfc7f9dbf151506809eaa63682e0cd5a76c",
        "verdict_modes": ["STATIC_HOLD", "ABSTAIN", "NULL_ROUTE", "ROUTE_ELIGIBLE"],
        "route_eligible_non_executing_only": True,
    }


def _base(status: str = "PASS") -> dict:
    return {
        "status": status,
        "current_git_head": SOURCE_PACKET_HEAD,
        "current_main_head": SOURCE_PACKET_HEAD,
        "source_packet_replay_binding_head": SOURCE_PACKET_HEAD,
        "architecture_binding_head": "4279eefb58a34089dc0b1930765a36556454e968",
        "selected_architecture_id": validation.SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": validation.SELECTED_ARCHITECTURE_NAME,
        "selected_outcome": validation.EXPECTED_PREVIOUS_OUTCOME,
        "next_lawful_move": validation.EXPECTED_PREVIOUS_NEXT_MOVE,
        "authoritative_lane": validation.PREVIOUS_LANE,
        "previous_authoritative_lane": "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_VALIDATION",
        "r6_authorized": False,
        "r6_open": False,
        "router_generation_authorized": False,
        "candidate_generation_authorized": False,
        "candidate_training_authorized": False,
        "afsh_candidate_generation_authorized": False,
        "afsh_candidate_generation_executed": False,
        "afsh_candidate_training_authorized": False,
        "afsh_candidate_training_executed": False,
        "afsh_admissibility_authorized": False,
        "afsh_admissibility_executed": False,
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
        "source_packet_authored": True,
        "source_packet_contract_bound": True,
        "source_packet_validation_required_before_generation": True,
        "candidate_generation_remains_forbidden": True,
        "failure_count": 0,
        "validated_blind_universe_binding": _universe_binding(),
        "validated_court_binding": _court_binding(),
        "allowed_feature_families": list(validation.ALLOWED_FEATURE_FAMILIES),
        "forbidden_feature_families": list(validation.FORBIDDEN_FEATURE_FAMILIES),
        "behavioral_defaults_required_for_future_candidate": {
            "unknown_case": "STATIC_HOLD",
            "uncertain_case": "ABSTAIN_OR_STATIC_HOLD",
            "boundary_unclear": "ABSTAIN",
            "trust_zone_unclear": "ABSTAIN",
            "route_value_below_threshold": "STATIC_HOLD",
            "null_route_sibling": "NULL_ROUTE",
            "mirror_masked_instability": "STATIC_HOLD",
            "proof_burden_not_justified": "STATIC_HOLD",
        },
        "route_value_court_compatibility": {
            "route_value_law_validated": True,
            "static_hold_default_required": True,
            "abstention_preservation_required": True,
            "null_route_preservation_required": True,
            "route_eligible_non_executing_only": True,
        },
    }


def _prep_payload() -> dict:
    return {
        **_base("PREP_ONLY"),
        "authority": "PREP_ONLY",
        "draft_status": "PREP_ONLY",
        "cannot_authorize_generation": True,
        "cannot_authorize_training": True,
        "cannot_authorize_admissibility": True,
        "cannot_authorize_screen_packet": True,
        "cannot_authorize_shadow_screen_execution": True,
        "cannot_authorize_activation": True,
        "cannot_authorize_package_promotion": True,
        "next_lawful_move_required_before_authority": validation.EXPECTED_PREVIOUS_NEXT_MOVE,
    }


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    for role, raw in validation.INPUTS.items():
        payload = {**_base(), "schema_id": role}
        if role == "allowed_features":
            payload.update({"allowed_features": list(validation.ALLOWED_FEATURE_FAMILIES)})
        if role == "forbidden_features":
            payload.update(
                {
                    "forbidden_features": list(validation.FORBIDDEN_FEATURE_FAMILIES),
                    "blind_label_access_forbidden": True,
                    "blind_outcome_access_forbidden": True,
                    "route_success_label_access_forbidden": True,
                }
            )
        if role == "trace_schema":
            payload.update(
                {
                    "trace_schema": {
                        **{flag: True for flag in validation.TRACE_REQUIREMENT_FLAGS},
                        "required_trace_groups": list(validation.TRACE_GROUPS),
                    }
                }
            )
        if role == "provenance_matrix":
            payload.update(
                {
                    "required_provenance": [
                        {"artifact": f"{binding}.json", "required_binding": binding}
                        for binding in validation.PROVENANCE_BINDINGS
                    ]
                }
            )
        if role == "determinism":
            payload.update(
                {
                    "determinism_requirements": {
                        "deterministic": True,
                        "seed_bound": True,
                        "hash_bound": True,
                        "no_network": True,
                        "no_runtime_mutation": True,
                    }
                }
            )
        if role == "no_contamination":
            payload.update(
                {
                    "no_contamination_rules": {
                        "blind_labels_inaccessible": True,
                        "blind_outcomes_inaccessible": True,
                        "route_success_labels_inaccessible": True,
                        "old_r01_r04_diagnostic_only": True,
                        "old_v2_six_row_diagnostic_only": True,
                        "candidate_generation_still_forbidden": True,
                    }
                }
            )
        if role == "no_authorization_drift":
            payload["no_downstream_authorization_drift"] = True
        if role == "trust_zone_binding":
            payload["fresh_trust_zone_validation"] = {"status": "PASS", "failures": [], "checks": []}
        if role in {"candidate_generation_protocol_prep", "candidate_manifest_schema_prep", "admissibility_court_prep"}:
            payload = {**_prep_payload(), "schema_id": role}
        if role == "future_blocker_register":
            payload["blockers"] = [
                {"blocker_id": "B04R6-FB-012", "future_blocker": "Source packet validates but candidate generation protocol is not ready."},
                {"blocker_id": "B04R6-FB-013", "future_blocker": "Candidate exists but admissibility law is not ready."},
                {"blocker_id": "B04R6-FB-014", "future_blocker": "Candidate generation accidentally uses blind outcomes."},
            ]
        if role == "previous_next_lawful_move":
            payload["schema_id"] = "next_move"
        _write_json(root / raw, payload)
    _write_text(root / validation.TEXT_INPUTS["source_packet_report"], "# AFSH Source Packet\n\nThis source packet is bound.\n")
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


def _contract(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["next_lawful_move"])


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _receipt(outputs)["validation_rows"]}


def test_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == MAIN_HEAD


def test_validation_contract_binds_selected_afsh_architecture(outputs: Path) -> None:
    assert _contract(outputs)["selected_architecture_id"] == validation.SELECTED_ARCHITECTURE_ID


def test_validation_contract_binds_validated_blind_universe(outputs: Path) -> None:
    assert _contract(outputs)["validated_blind_universe_binding"]["case_count"] == validation.EXPECTED_CASE_COUNT


def test_validation_contract_binds_validated_route_economics_court(outputs: Path) -> None:
    assert _contract(outputs)["validated_court_binding"]["status"] == "BOUND_AND_VALIDATED"


def test_immutable_source_inputs_share_replay_head(outputs: Path) -> None:
    assert "immutable_source_inputs_share_replay_head" in _row_ids(outputs)


def test_source_packet_contract_exists_and_parses(outputs: Path) -> None:
    assert "source_packet_contract_exists_and_parses" in _row_ids(outputs)


def test_source_packet_receipt_exists_and_parses(outputs: Path) -> None:
    assert "source_packet_receipt_exists_and_parses" in _row_ids(outputs)


def test_allowed_features_contract_bound(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["allowed_features_validation"])["allowed_features_validated"] is True


def test_forbidden_features_contract_bound(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["forbidden_features_validation"])["forbidden_features_validated"] is True


def test_blind_outcome_labels_forbidden(outputs: Path) -> None:
    assert "blind_outcome_labels_forbidden" in _row_ids(outputs)


def test_blind_route_success_labels_forbidden(outputs: Path) -> None:
    assert "blind_route_success_labels_forbidden" in _row_ids(outputs)


def test_post_screen_labels_forbidden(outputs: Path) -> None:
    assert "post_screen_labels_forbidden" in _row_ids(outputs)


def test_hidden_adjudication_labels_forbidden(outputs: Path) -> None:
    assert "hidden_adjudication_labels_forbidden" in _row_ids(outputs)


def test_old_r01_r04_counted_labels_forbidden(outputs: Path) -> None:
    assert "old_r01_r04_counted_labels_forbidden" in _row_ids(outputs)


def test_old_v2_six_row_counted_labels_forbidden(outputs: Path) -> None:
    assert "old_v2_six_row_counted_labels_forbidden" in _row_ids(outputs)


def test_prior_r01_r04_remain_diagnostic_only(outputs: Path) -> None:
    assert "prior_r01_r04_remain_diagnostic_only" in _row_ids(outputs)


def test_prior_v2_six_row_remain_diagnostic_only(outputs: Path) -> None:
    assert "prior_v2_six_row_remain_diagnostic_only" in _row_ids(outputs)


def test_trace_schema_contract_bound(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["trace_schema_validation"])["trace_schema_validated"] is True


def test_trace_schema_requires_verdict_mode(outputs: Path) -> None:
    assert "trace_schema_requires_verdict_mode" in _row_ids(outputs)


def test_trace_schema_requires_route_value_terms(outputs: Path) -> None:
    assert "trace_schema_requires_route_value_terms" in _row_ids(outputs)


def test_trace_schema_requires_static_hold_reason_code(outputs: Path) -> None:
    assert "trace_schema_requires_static_hold_reason_code" in _row_ids(outputs)


def test_trace_schema_requires_abstention_reason_code(outputs: Path) -> None:
    assert "trace_schema_requires_abstention_reason_code" in _row_ids(outputs)


def test_trace_schema_requires_null_route_reason_code(outputs: Path) -> None:
    assert "trace_schema_requires_null_route_reason_code" in _row_ids(outputs)


def test_trace_schema_requires_route_eligible_reason_code(outputs: Path) -> None:
    assert "trace_schema_requires_route_eligible_reason_code" in _row_ids(outputs)


def test_trace_schema_requires_trust_zone_status(outputs: Path) -> None:
    assert "trace_schema_requires_trust_zone_status" in _row_ids(outputs)


def test_trace_schema_requires_comparator_preservation_status(outputs: Path) -> None:
    assert "trace_schema_requires_comparator_preservation_status" in _row_ids(outputs)


def test_trace_schema_requires_metric_preservation_status(outputs: Path) -> None:
    assert "trace_schema_requires_metric_preservation_status" in _row_ids(outputs)


def test_provenance_matrix_bound(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["provenance_matrix_validation"])["provenance_matrix_validated"] is True


def test_source_determinism_contract_bound(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["determinism_validation"])["source_determinism_validated"] is True


def test_source_is_hash_bound(outputs: Path) -> None:
    assert "source_is_hash_bound" in _row_ids(outputs)


def test_source_is_no_network(outputs: Path) -> None:
    assert "source_is_no_network" in _row_ids(outputs)


def test_source_forbids_runtime_mutation(outputs: Path) -> None:
    assert "source_forbids_runtime_mutation" in _row_ids(outputs)


def test_source_forbids_truth_engine_mutation(outputs: Path) -> None:
    assert "source_forbids_truth_engine_mutation" in _row_ids(outputs)


def test_source_forbids_trust_zone_mutation(outputs: Path) -> None:
    assert "source_forbids_trust_zone_mutation" in _row_ids(outputs)


def test_source_forbids_package_promotion_behavior(outputs: Path) -> None:
    assert "source_forbids_package_promotion_behavior" in _row_ids(outputs)


def test_source_forbids_activation_cutover_behavior(outputs: Path) -> None:
    assert "source_forbids_activation_cutover_behavior" in _row_ids(outputs)


def test_static_hold_default_preserved(outputs: Path) -> None:
    assert "static_hold_default_preserved" in _row_ids(outputs)


def test_abstention_preservation_required(outputs: Path) -> None:
    assert "abstention_preservation_required" in _row_ids(outputs)


def test_null_route_preservation_required(outputs: Path) -> None:
    assert "null_route_preservation_required" in _row_ids(outputs)


def test_mirror_masked_stability_required(outputs: Path) -> None:
    assert "mirror_masked_stability_required" in _row_ids(outputs)


def test_route_value_court_compatibility_preserved(outputs: Path) -> None:
    assert "route_value_court_compatibility_preserved" in _row_ids(outputs)


def test_candidate_generation_protocol_is_prep_only(outputs: Path) -> None:
    assert "candidate_generation_protocol_is_prep_only" in _row_ids(outputs)


def test_candidate_manifest_schema_is_prep_only(outputs: Path) -> None:
    assert "candidate_manifest_schema_is_prep_only" in _row_ids(outputs)


def test_admissibility_court_draft_is_prep_only(outputs: Path) -> None:
    assert "admissibility_court_draft_is_prep_only" in _row_ids(outputs)


def test_prep_only_drafts_cannot_authorize_generation(outputs: Path) -> None:
    assert "prep_only_drafts_cannot_authorize_generation" in _row_ids(outputs)


def test_prep_only_drafts_cannot_authorize_training(outputs: Path) -> None:
    assert "prep_only_drafts_cannot_authorize_training" in _row_ids(outputs)


def test_prep_only_drafts_cannot_authorize_admissibility(outputs: Path) -> None:
    assert "prep_only_drafts_cannot_authorize_admissibility" in _row_ids(outputs)


def test_prep_only_drafts_cannot_authorize_shadow_screen_packet(outputs: Path) -> None:
    assert "prep_only_drafts_cannot_authorize_shadow_screen_packet" in _row_ids(outputs)


def test_prep_only_drafts_cannot_authorize_shadow_screen_execution(outputs: Path) -> None:
    assert "prep_only_drafts_cannot_authorize_shadow_screen_execution" in _row_ids(outputs)


def test_prep_only_drafts_cannot_authorize_activation(outputs: Path) -> None:
    assert "prep_only_drafts_cannot_authorize_activation" in _row_ids(outputs)


def test_prep_only_drafts_cannot_authorize_lobe_escalation(outputs: Path) -> None:
    assert "prep_only_drafts_cannot_authorize_lobe_escalation" in _row_ids(outputs)


def test_prep_only_drafts_cannot_authorize_package_promotion(outputs: Path) -> None:
    assert "prep_only_drafts_cannot_authorize_package_promotion" in _row_ids(outputs)


def test_metric_widening_forbidden(outputs: Path) -> None:
    assert "metric_widening_forbidden" in _row_ids(outputs)


def test_comparator_weakening_forbidden(outputs: Path) -> None:
    assert "comparator_weakening_forbidden" in _row_ids(outputs)


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    assert "no_authorization_drift_receipt_passes" in _row_ids(outputs)


def test_trust_zone_binding_receipt_passes(outputs: Path) -> None:
    assert "trust_zone_binding_receipt_passes" in _row_ids(outputs)


def test_future_blocker_register_present(outputs: Path) -> None:
    assert "future_blocker_register_present" in _row_ids(outputs)


def test_next_lawful_move_is_candidate_generation(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_candidate_generation_is_next_lawful_but_not_executed(outputs: Path) -> None:
    receipt = _receipt(outputs)
    assert receipt["candidate_generation_next_lawful"] is True
    assert receipt["candidate_generation_not_executed_by_validation"] is True
    assert receipt["afsh_candidate_generation_executed"] is False


def test_validation_pass_count_is_at_least_fifty_five(outputs: Path) -> None:
    assert _receipt(outputs)["pass_count"] >= 55


def test_self_replay_handoff_reruns_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, head=BRANCH_HEAD)
    validation.run(reports_root=reports)
    _patch_env(monkeypatch, tmp_path, head="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    result = validation.run(reports_root=reports)
    assert result["verdict"] == validation.SELECTED_OUTCOME
    assert _load(reports / validation.OUTPUTS["next_lawful_move"])["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


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


def test_mixed_source_input_replay_head_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    allowed_path = tmp_path / validation.INPUTS["allowed_features"]
    allowed = _load(allowed_path)
    allowed["current_git_head"] = "cccccccccccccccccccccccccccccccccccccccc"
    _write_json(allowed_path, allowed)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="replay head"):
        validation.run(reports_root=reports)


def test_generation_authorization_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    receipt_path = tmp_path / validation.INPUTS["source_packet_receipt"]
    receipt = _load(receipt_path)
    receipt["afsh_candidate_generation_authorized"] = True
    _write_json(receipt_path, receipt)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="GENERATION_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_forbidden_feature_missing_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    features_path = tmp_path / validation.INPUTS["forbidden_features"]
    features = _load(features_path)
    features["forbidden_features"].remove("blind_outcome_labels")
    _write_json(features_path, features)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FORBIDDEN_FEATURES_MISSING"):
        validation.run(reports_root=reports)


def test_trace_schema_missing_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    trace_path = tmp_path / validation.INPUTS["trace_schema"]
    trace = _load(trace_path)
    trace["trace_schema"]["must_emit_verdict_mode"] = False
    _write_json(trace_path, trace)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="TRACE_SCHEMA_INCOMPLETE"):
        validation.run(reports_root=reports)


def test_no_network_missing_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    determinism_path = tmp_path / validation.INPUTS["determinism"]
    determinism = _load(determinism_path)
    determinism["determinism_requirements"]["no_network"] = False
    _write_json(determinism_path, determinism)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NETWORK_ALLOWED"):
        validation.run(reports_root=reports)


def test_prep_only_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    draft_path = tmp_path / validation.INPUTS["candidate_generation_protocol_prep"]
    draft = _load(draft_path)
    draft["status"] = "PASS"
    _write_json(draft_path, draft)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PREP_ONLY"):
        validation.run(reports_root=reports)
