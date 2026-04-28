from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_afsh_implementation_source_packet as source_packet


PREVIOUS_VALIDATION_HEAD = "022a7bfc7f9dbf151506809eaa63682e0cd5a76c"
COURT_REPLAY_HEAD = "e8a00afa04ce1df380165b85b3620837160244a6"
BRANCH_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MAIN_HEAD = "3bc4ab79299487f3aaa76496886c22825d84774e"


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
        "case_count": source_packet.EXPECTED_CASE_COUNT,
        "case_namespace": f"{source_packet.CASE_PREFIX}*",
        "prior_r01_r04_treatment": "DIAGNOSTIC_ONLY",
        "prior_v2_six_row_treatment": "DIAGNOSTIC_ONLY",
        "status": "BOUND_AND_VALIDATED",
        "validation_outcome": "B04_R6_NEW_BLIND_UNIVERSE_VALIDATED__STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_NEXT",
    }


def _court_binding() -> dict:
    return {
        "court_replay_binding_head": COURT_REPLAY_HEAD,
        "next_lawful_move": source_packet.EXPECTED_PREVIOUS_NEXT_MOVE,
        "previous_next_lawful_move": "VALIDATE_B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT",
        "previous_outcome": "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_BOUND__COURT_VALIDATION_NEXT",
        "selected_validation_outcome": source_packet.EXPECTED_PREVIOUS_OUTCOME,
        "status": "BOUND_AND_VALIDATED",
    }


def _base(status: str = "PASS") -> dict:
    return {
        "status": status,
        "current_git_head": PREVIOUS_VALIDATION_HEAD,
        "current_main_head": PREVIOUS_VALIDATION_HEAD,
        "court_replay_binding_head": COURT_REPLAY_HEAD,
        "architecture_binding_head": "4279eefb58a34089dc0b1930765a36556454e968",
        "selected_architecture_id": source_packet.SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": source_packet.SELECTED_ARCHITECTURE_NAME,
        "selected_outcome": source_packet.EXPECTED_PREVIOUS_OUTCOME,
        "next_lawful_move": source_packet.EXPECTED_PREVIOUS_NEXT_MOVE,
        "authoritative_lane": source_packet.PREVIOUS_LANE,
        "previous_authoritative_lane": "B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT",
        "r6_authorized": False,
        "r6_open": False,
        "router_generation_authorized": False,
        "candidate_generation_authorized": False,
        "candidate_training_authorized": False,
        "afsh_candidate_generation_authorized": False,
        "afsh_candidate_training_authorized": False,
        "afsh_admissibility_authorized": False,
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
        "court_validated": True,
        "failure_count": 0,
        "validated_blind_universe_binding": _universe_binding(),
        "validated_court_binding": _court_binding(),
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
        "next_lawful_move_required_before_authority": "VALIDATE_B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT",
    }


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"

    for role, raw in source_packet.INPUTS.items():
        payload = {**_base(), "schema_id": role}
        if role == "previous_next_lawful_move":
            payload["schema_id"] = "next_move"
        _write_json(root / raw, payload)

    _write_json(
        root / source_packet.PREP_INPUTS["afsh_source_packet_prep"],
        {
            **_prep_payload(),
            "schema_id": "source_packet_prep",
            "allowed_future_sections": [
                "allowed_features",
                "forbidden_features",
                "trace_schema",
                "provenance_matrix",
                "determinism_requirements",
            ],
        },
    )
    _write_json(
        root / source_packet.PREP_INPUTS["afsh_features_prep"],
        {
            **_prep_payload(),
            "schema_id": "features_prep",
            "allowed_features": [
                "input_family_descriptors",
                "source_metadata_hashes",
                "static_comparator_features",
                "confidence_estimates",
                "calibration_bucket",
                "risk_bucket",
                "route_cost_estimate",
                "proof_burden_estimate",
                "trust_zone_eligibility_bit",
                "mirror_masked_stability_features",
            ],
            "forbidden_features": list(source_packet.FORBIDDEN_FEATURE_FAMILIES),
        },
    )
    _write_json(
        root / source_packet.PREP_INPUTS["afsh_trace_prep"],
        {
            **_prep_payload(),
            "schema_id": "trace_prep",
            "required_trace_groups": list(source_packet.TRACE_GROUPS),
        },
    )
    _write_json(
        root / source_packet.PREP_INPUTS["afsh_provenance_prep"],
        {
            **_prep_payload(),
            "schema_id": "provenance_prep",
            "required_future_provenance": [
                "source_packet_hash",
                "allowed_feature_contract_hash",
                "forbidden_feature_contract_hash",
                "route_economics_contract_hash",
                "trace_schema_hash",
                "blind_universe_manifest_hash",
                "no_contamination_receipt",
            ],
        },
    )
    _write_text(root / source_packet.TEXT_INPUTS["court_validation_report"], "# Court Validation\n\nSTATIC_HOLD\n")
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "registry", "status": "PASS"})
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "scope", "status": "PASS"})
    return reports


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = source_packet.AUTHORITY_BRANCH,
    head: str = BRANCH_HEAD,
    origin_main: str = MAIN_HEAD,
) -> None:
    monkeypatch.setattr(source_packet, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(source_packet.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(source_packet.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(source_packet.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        source_packet,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    source_packet.run(reports_root=reports)
    return reports


def _contract(outputs: Path) -> dict:
    return _load(outputs / source_packet.OUTPUTS["source_packet_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / source_packet.OUTPUTS["source_packet_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / source_packet.OUTPUTS["next_lawful_move"])


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _receipt(outputs)["validation_rows"]}


def test_source_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == MAIN_HEAD


def test_source_packet_binds_selected_afsh_architecture(outputs: Path) -> None:
    assert _contract(outputs)["selected_architecture_id"] == source_packet.SELECTED_ARCHITECTURE_ID


def test_source_packet_binds_validated_blind_universe(outputs: Path) -> None:
    assert _contract(outputs)["validated_blind_universe_binding"]["case_count"] == source_packet.EXPECTED_CASE_COUNT


def test_source_packet_binds_validated_route_economics_court(outputs: Path) -> None:
    assert _contract(outputs)["validated_court_binding"]["status"] == "BOUND_AND_VALIDATED"


def test_previous_next_lawful_move_binding_is_git_object(outputs: Path) -> None:
    bindings = {row["role"]: row for row in _contract(outputs)["input_bindings"]}
    binding = bindings["previous_next_lawful_move"]
    assert binding["binding_kind"] == "git_object_before_overwrite"
    assert binding["git_commit"] == BRANCH_HEAD
    assert binding["mutable_canonical_path_overwritten_by_this_lane"] is True


def test_source_packet_does_not_authorize_candidate_generation(outputs: Path) -> None:
    assert "source_packet_does_not_authorize_candidate_generation" in _row_ids(outputs)
    assert _contract(outputs)["candidate_generation_authorized"] is False


def test_source_packet_does_not_authorize_candidate_training(outputs: Path) -> None:
    assert "source_packet_does_not_authorize_candidate_training" in _row_ids(outputs)


def test_source_packet_does_not_authorize_admissibility(outputs: Path) -> None:
    assert "source_packet_does_not_authorize_admissibility" in _row_ids(outputs)


def test_source_packet_does_not_authorize_shadow_screen_packet(outputs: Path) -> None:
    assert "source_packet_does_not_authorize_shadow_screen_packet" in _row_ids(outputs)


def test_source_packet_does_not_authorize_shadow_screen_execution(outputs: Path) -> None:
    assert "source_packet_does_not_authorize_shadow_screen_execution" in _row_ids(outputs)


def test_source_packet_does_not_authorize_r6_open(outputs: Path) -> None:
    assert "source_packet_does_not_authorize_r6_open" in _row_ids(outputs)


def test_source_packet_does_not_authorize_superiority(outputs: Path) -> None:
    assert "source_packet_does_not_authorize_superiority" in _row_ids(outputs)


def test_source_packet_does_not_authorize_activation_review(outputs: Path) -> None:
    assert "source_packet_does_not_authorize_activation_review" in _row_ids(outputs)


def test_source_packet_does_not_authorize_runtime_cutover(outputs: Path) -> None:
    assert "source_packet_does_not_authorize_runtime_cutover" in _row_ids(outputs)


def test_source_packet_does_not_authorize_lobe_escalation(outputs: Path) -> None:
    assert "source_packet_does_not_authorize_lobe_escalation" in _row_ids(outputs)


def test_source_packet_does_not_authorize_package_promotion(outputs: Path) -> None:
    assert "source_packet_does_not_authorize_package_promotion" in _row_ids(outputs)


def test_allowed_features_are_defined(outputs: Path) -> None:
    payload = _load(outputs / source_packet.OUTPUTS["allowed_features"])
    assert set(source_packet.ALLOWED_FEATURE_FAMILIES).issubset(set(payload["allowed_features"]))


def test_forbidden_features_are_defined(outputs: Path) -> None:
    payload = _load(outputs / source_packet.OUTPUTS["forbidden_features"])
    assert set(source_packet.FORBIDDEN_FEATURE_FAMILIES).issubset(set(payload["forbidden_features"]))


def test_blind_outcome_labels_forbidden(outputs: Path) -> None:
    assert "blind_outcome_labels_forbidden" in _row_ids(outputs)


def test_blind_route_success_labels_forbidden(outputs: Path) -> None:
    assert "blind_route_success_labels_forbidden" in _row_ids(outputs)


def test_old_r01_r04_counted_labels_forbidden(outputs: Path) -> None:
    assert "old_r01_r04_counted_labels_forbidden" in _row_ids(outputs)


def test_old_v2_six_row_counted_labels_forbidden(outputs: Path) -> None:
    assert "old_v2_six_row_counted_labels_forbidden" in _row_ids(outputs)


def test_metric_widening_forbidden(outputs: Path) -> None:
    assert "metric_widening_forbidden" in _row_ids(outputs)


def test_comparator_weakening_forbidden(outputs: Path) -> None:
    assert "comparator_weakening_forbidden" in _row_ids(outputs)


def test_truth_engine_mutation_forbidden(outputs: Path) -> None:
    assert "truth_engine_mutation_forbidden" in _row_ids(outputs)


def test_trust_zone_mutation_forbidden(outputs: Path) -> None:
    assert "trust_zone_mutation_forbidden" in _row_ids(outputs)


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


def test_derivation_constraints_are_deterministic(outputs: Path) -> None:
    assert _contract(outputs)["derivation_constraints"]["deterministic"] is True


def test_derivation_constraints_are_hash_bound(outputs: Path) -> None:
    assert _contract(outputs)["derivation_constraints"]["hash_bound"] is True


def test_derivation_constraints_are_no_network(outputs: Path) -> None:
    assert _contract(outputs)["derivation_constraints"]["no_network"] is True


def test_candidate_generation_protocol_is_prep_only(outputs: Path) -> None:
    payload = _load(outputs / source_packet.OUTPUTS["candidate_generation_protocol_prep"])
    assert payload["authority"] == "PREP_ONLY"


def test_candidate_manifest_schema_is_prep_only(outputs: Path) -> None:
    payload = _load(outputs / source_packet.OUTPUTS["candidate_manifest_schema_prep"])
    assert payload["authority"] == "PREP_ONLY"


def test_admissibility_court_draft_is_prep_only(outputs: Path) -> None:
    payload = _load(outputs / source_packet.OUTPUTS["admissibility_court_prep"])
    assert payload["authority"] == "PREP_ONLY"


def test_prep_only_drafts_cannot_authorize_generation(outputs: Path) -> None:
    assert "prep_only_drafts_cannot_authorize_generation" in _row_ids(outputs)


def test_prep_only_drafts_cannot_authorize_screen(outputs: Path) -> None:
    assert "prep_only_drafts_cannot_authorize_screen" in _row_ids(outputs)


def test_prep_only_drafts_cannot_authorize_activation(outputs: Path) -> None:
    assert "prep_only_drafts_cannot_authorize_activation" in _row_ids(outputs)


def test_prep_only_drafts_cannot_authorize_package_promotion(outputs: Path) -> None:
    assert "prep_only_drafts_cannot_authorize_package_promotion" in _row_ids(outputs)


def test_next_lawful_move_is_source_packet_validation(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == source_packet.NEXT_LAWFUL_MOVE


def test_source_packet_pass_count_is_at_least_fifty(outputs: Path) -> None:
    assert _receipt(outputs)["pass_count"] >= 50


def test_self_replay_handoff_reruns_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, head=BRANCH_HEAD)
    source_packet.run(reports_root=reports)
    _patch_env(monkeypatch, tmp_path, head="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    result = source_packet.run(reports_root=reports)
    assert result["verdict"] == source_packet.SELECTED_OUTCOME
    assert _load(reports / source_packet.OUTPUTS["next_lawful_move"])["next_lawful_move"] == source_packet.NEXT_LAWFUL_MOVE


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    monkeypatch.setattr(source_packet.common, "git_status_porcelain", lambda root: " M something")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        source_packet.run(reports_root=reports)


def test_previous_next_lawful_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    receipt_path = tmp_path / source_packet.INPUTS["previous_next_lawful_move"]
    receipt = _load(receipt_path)
    receipt["next_lawful_move"] = "WRONG_MOVE"
    _write_json(receipt_path, receipt)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        source_packet.run(reports_root=reports)


def test_candidate_generation_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    receipt_path = tmp_path / source_packet.INPUTS["court_validation_receipt"]
    receipt = _load(receipt_path)
    receipt["candidate_generation_authorized"] = True
    _write_json(receipt_path, receipt)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="GENERATION_AUTHORIZATION_DRIFT"):
        source_packet.run(reports_root=reports)


def test_forbidden_feature_missing_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    draft_path = tmp_path / source_packet.PREP_INPUTS["afsh_features_prep"]
    draft = _load(draft_path)
    draft["forbidden_features"].remove("blind_outcome_labels")
    _write_json(draft_path, draft)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FORBIDDEN_FEATURES_INCOMPLETE"):
        source_packet.run(reports_root=reports)


def test_prep_only_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    draft_path = tmp_path / source_packet.PREP_INPUTS["afsh_source_packet_prep"]
    draft = _load(draft_path)
    draft["status"] = "PASS"
    _write_json(draft_path, draft)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PREP_ONLY"):
        source_packet.run(reports_root=reports)
