from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_afsh_admissibility_court as admissibility
from tools.operator import cohort0_b04_r6_afsh_candidate_generation as generation


SOURCE_VALIDATION_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CANDIDATE_REPLAY_HEAD = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ADMISSIBILITY_BRANCH_HEAD = "cccccccccccccccccccccccccccccccccccccccc"
CURRENT_MAIN_HEAD = "dddddddddddddddddddddddddddddddddddddddd"


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
        "case_count": generation.EXPECTED_CASE_COUNT,
        "case_namespace": f"{generation.CASE_PREFIX}*",
        "prior_r01_r04_treatment": "DIAGNOSTIC_ONLY",
        "prior_v2_six_row_treatment": "DIAGNOSTIC_ONLY",
        "status": "BOUND_AND_VALIDATED",
    }


def _court_binding() -> dict:
    return {
        "status": "BOUND_AND_VALIDATED",
        "verdict_modes": list(generation.TOP_LEVEL_VERDICTS),
        "route_eligible_non_executing_only": True,
    }


def _source_validation_payload(*, role: str, status: str = "PASS") -> dict:
    return {
        "schema_id": role,
        "artifact_id": role.upper(),
        "status": status,
        "current_git_head": SOURCE_VALIDATION_HEAD,
        "current_main_head": SOURCE_VALIDATION_HEAD,
        "selected_architecture_id": generation.SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": generation.SELECTED_ARCHITECTURE_NAME,
        "authoritative_lane": generation.PREVIOUS_LANE,
        "previous_authoritative_lane": "B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET",
        "selected_outcome": generation.EXPECTED_PREVIOUS_OUTCOME,
        "next_lawful_move": generation.EXPECTED_PREVIOUS_NEXT_MOVE,
        "source_packet_validated": True,
        "validated_blind_universe_binding": _universe_binding(),
        "validated_court_binding": _court_binding(),
        "architecture_binding_head": "4279eefb58a34089dc0b1930765a36556454e968",
        "pass_count": 71,
        "failure_count": 0,
        "r6_authorized": False,
        "r6_open": False,
        "router_generation_authorized": False,
        "candidate_training_authorized": False,
        "candidate_training_executed": False,
        "afsh_candidate_training_authorized": False,
        "afsh_candidate_training_executed": False,
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
    }


def _write_source_validation_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    _write_json(root / generation.REFERENCE_INPUTS["source_packet_contract"], {"schema_id": "source", "status": "PASS"})
    for role, raw in generation.INPUTS.items():
        payload = _source_validation_payload(role=role)
        if role == "source_validation_contract":
            payload["input_bindings"] = [
                {
                    "binding_kind": "file_sha256_at_validation",
                    "path": generation.REFERENCE_INPUTS["source_packet_contract"],
                    "role": "source_packet_contract",
                    "sha256": generation.file_sha256(root / generation.REFERENCE_INPUTS["source_packet_contract"]),
                }
            ]
        _write_json(root / raw, payload)
    _write_text(root / generation.TEXT_INPUTS["source_validation_report"], "# AFSH Source Packet Validation\n\nPASS\n")
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "trust", "status": "PASS"})
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "scope", "status": "PASS"})
    return reports


def _patch_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state: dict) -> None:
    monkeypatch.setattr(generation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(admissibility, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(generation.common, "git_current_branch_name", lambda root: state["branch"])
    monkeypatch.setattr(generation.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(
        generation.common,
        "git_rev_parse",
        lambda root, ref: state["origin_main"] if ref == "origin/main" else state["head"],
    )
    monkeypatch.setattr(
        generation,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )
    monkeypatch.setattr(
        admissibility,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _write_candidate_generation_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict]:
    reports = _write_source_validation_inputs(tmp_path)
    state = {"branch": "main", "head": CANDIDATE_REPLAY_HEAD, "origin_main": CANDIDATE_REPLAY_HEAD}
    _patch_env(monkeypatch, tmp_path, state)
    generation.run(reports_root=reports)
    return reports, state


def _run_admissibility(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports, state = _write_candidate_generation_state(tmp_path, monkeypatch)
    state.update({"branch": admissibility.AUTHORITY_BRANCH, "head": ADMISSIBILITY_BRANCH_HEAD, "origin_main": CURRENT_MAIN_HEAD})
    admissibility.run(reports_root=reports)
    return reports


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return _run_admissibility(tmp_path, monkeypatch)


def _contract(outputs: Path) -> dict:
    return _load(outputs / admissibility.OUTPUTS["admissibility_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / admissibility.OUTPUTS["admissibility_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / admissibility.OUTPUTS["next_lawful_move"])


def _candidate(outputs: Path) -> dict:
    return _load(outputs / generation.OUTPUTS["candidate_v1"])


def _manifest(outputs: Path) -> dict:
    return _load(outputs / generation.OUTPUTS["candidate_manifest"])


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _contract(outputs)["validation_rows"]}


@pytest.mark.parametrize("filename", sorted(admissibility.OUTPUTS.values()))
def test_required_json_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    if filename.endswith(".md"):
        assert (outputs / filename).read_text(encoding="utf-8").strip()
    else:
        assert _load(outputs / filename)


def test_admissibility_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == CURRENT_MAIN_HEAD


def test_admissibility_binds_candidate_replay_head(outputs: Path) -> None:
    assert _contract(outputs)["candidate_replay_binding_head"] == CANDIDATE_REPLAY_HEAD


def test_admissibility_binds_selected_afsh_architecture(outputs: Path) -> None:
    assert _contract(outputs)["selected_architecture_id"] == admissibility.SELECTED_ARCHITECTURE_ID


def test_admissibility_binds_validated_blind_universe(outputs: Path) -> None:
    assert _contract(outputs)["universe_binding"]["case_count"] == generation.EXPECTED_CASE_COUNT


def test_admissibility_binds_validated_route_value_court(outputs: Path) -> None:
    assert _contract(outputs)["court_binding"]["verdict_modes"] == list(admissibility.TOP_LEVEL_VERDICTS)


def test_admissibility_binds_validated_source_packet(outputs: Path) -> None:
    assert _contract(outputs)["source_packet_binding"]["status"] == "BOUND_AND_VALIDATED"


def test_candidate_manifest_exists_and_parses(outputs: Path) -> None:
    assert _manifest(outputs)["artifact_id"] == "B04_R6_AFSH_CANDIDATE_MANIFEST"


def test_candidate_artifact_exists_and_parses(outputs: Path) -> None:
    assert _candidate(outputs)["artifact_id"] == admissibility.CANDIDATE_ID


def test_candidate_hash_receipt_bound(outputs: Path) -> None:
    assert _load(outputs / admissibility.OUTPUTS["candidate_hash_admissibility_receipt"])["candidate_semantic_hash"]


def test_candidate_semantic_hash_excludes_generated_utc(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["stable_semantic_hash_basis"])["excluded_volatile_fields"] == ["generated_utc"]


def test_candidate_receipt_hash_includes_envelope(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["candidate_hash_receipt"])["candidate_receipt_hash_includes_envelope"] is True


def test_candidate_immutable_inputs_share_replay_head(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["immutable_input_manifest"])["immutable_source_inputs_share_replay_head"] is True


def test_candidate_mixed_head_inputs_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports, state = _write_candidate_generation_state(tmp_path, monkeypatch)
    path = tmp_path / admissibility.INPUTS["candidate_hash_receipt"]
    payload = _load(path)
    payload["current_git_head"] = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    _write_json(path, payload)
    state.update({"branch": admissibility.AUTHORITY_BRANCH, "head": ADMISSIBILITY_BRANCH_HEAD, "origin_main": CURRENT_MAIN_HEAD})
    with pytest.raises(RuntimeError, match="IMMUTABLE_INPUT_MIXED_HEAD|CANDIDATE_REPLAY_HEAD_MISMATCH"):
        admissibility.run(reports_root=reports)


def test_candidate_mutable_handoff_bound_before_overwrite(outputs: Path) -> None:
    rows = _load(outputs / admissibility.OUTPUTS["candidate_mutable_handoff_admissibility_receipt"])["input_bindings"]
    assert any(row["role"] == "previous_next_lawful_move" and row["binding_kind"] == "git_object_before_overwrite" for row in rows)


def test_candidate_kind_is_deterministic_rule_materialization(outputs: Path) -> None:
    assert _manifest(outputs)["candidate_kind"] == "DETERMINISTIC_RULE_MATERIALIZATION"


def test_candidate_training_executed_false(outputs: Path) -> None:
    assert _manifest(outputs)["training_executed"] is False


def test_candidate_training_remains_unauthorized(outputs: Path) -> None:
    assert _manifest(outputs)["candidate_training_authorized"] is False


def test_candidate_generation_executed_in_prior_lane_only(outputs: Path) -> None:
    assert _contract(outputs)["candidate_generation_executed"] is True
    assert _contract(outputs)["candidate_admissibility_executed"] is True


def test_admissibility_does_not_execute_training(outputs: Path) -> None:
    assert _contract(outputs)["candidate_training_executed"] is False


def test_static_hold_default_preserved(outputs: Path) -> None:
    assert _candidate(outputs)["candidate_defaults"]["unknown_case"] == "STATIC_HOLD"


def test_abstention_preservation_required(outputs: Path) -> None:
    assert _candidate(outputs)["candidate_defaults"]["boundary_unclear"] == "ABSTAIN"


def test_null_route_preservation_required(outputs: Path) -> None:
    assert _candidate(outputs)["candidate_defaults"]["null_route_sibling"] == "NULL_ROUTE"


def test_mirror_masked_stability_required(outputs: Path) -> None:
    assert _candidate(outputs)["guard_ensemble"]["mirror_masked_stability_required"] is True


def test_route_value_court_compatibility_preserved(outputs: Path) -> None:
    assert _contract(outputs)["court_binding"]["route_eligible_non_executing_only"] is True


def test_candidate_includes_numeric_triage_emit_core(outputs: Path) -> None:
    assert _candidate(outputs)["modules"]["numeric_triage_emit_core"] == "B04_R6_AFSH_NUMERIC_TRIAGE_EMIT_CORE"


def test_triage_top_level_verdict_modes_match_validated_court_modes(outputs: Path) -> None:
    assert _candidate(outputs)["top_level_verdict_modes"] == list(admissibility.TOP_LEVEL_VERDICTS)


def test_triage_subtypes_do_not_create_new_verdict_modes(outputs: Path) -> None:
    core = _load(outputs / generation.OUTPUTS["numeric_triage_emit_core"])
    assert core["new_top_level_verdicts_allowed"] is False
    assert not set(core["triage_subtypes_allowed"]) & set(core["top_level_verdict_modes"])


def test_only_route_eligible_enters_selector(outputs: Path) -> None:
    assert _candidate(outputs)["selector_entry_rule"]["only_top_level_verdict_allowed_to_enter_selector"] == "ROUTE_ELIGIBLE"


@pytest.mark.parametrize(
    ("test_name", "key"),
    [
        ("static_hold_cases_do_not_enter_selector", "static_hold_enters_selector"),
        ("abstain_cases_do_not_enter_selector", "abstain_enters_selector"),
        ("null_route_cases_do_not_enter_selector", "null_route_enters_selector"),
    ],
)
def test_non_route_verdicts_do_not_enter_selector(outputs: Path, test_name: str, key: str) -> None:
    assert test_name in _row_ids(outputs)
    assert _candidate(outputs)["selector_entry_rule"][key] is False


def test_triage_selector_entry_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports, state = _write_candidate_generation_state(tmp_path, monkeypatch)
    path = tmp_path / admissibility.INPUTS["candidate_artifact"]
    payload = _load(path)
    payload["selector_entry_rule"]["static_hold_enters_selector"] = True
    _write_json(path, payload)
    state.update({"branch": admissibility.AUTHORITY_BRANCH, "head": ADMISSIBILITY_BRANCH_HEAD, "origin_main": CURRENT_MAIN_HEAD})
    with pytest.raises(RuntimeError, match="TRIAGE_STATIC_HOLD_ENTERS_SELECTOR|CANDIDATE_SEMANTIC_HASH_UNSTABLE"):
        admissibility.run(reports_root=reports)


def test_triage_scores_are_deterministic(outputs: Path) -> None:
    score_schema = _load(outputs / generation.OUTPUTS["triage_score_schema"])
    assert score_schema["deterministic"] is True
    assert score_schema["score_bounds"] == {"min": 0.0, "max": 1.0}


def test_triage_emit_logic_is_fail_closed(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["triage_emit_decision_matrix"])["fail_closed_default"] == "STATIC_HOLD"


def test_triage_tags_are_receipt_derived(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["triage_tag_schema"])["tags_must_be_receipt_derived"] is True


def test_triage_tags_are_source_packet_allowed(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["triage_tag_schema"])["tags_must_be_source_packet_allowed"] is True


@pytest.mark.parametrize(
    ("row_id", "dependency"),
    [
        ("triage_tags_do_not_use_blind_outcomes", "blind_outcome_labels"),
        ("triage_tags_do_not_use_route_success_labels", "blind_route_success_labels"),
        ("triage_tags_do_not_use_post_screen_labels", "post_screen_labels"),
        ("triage_tags_do_not_use_old_r01_r04_counted_labels", "old_r01_r04_counted_labels"),
        ("triage_tags_do_not_use_old_v2_six_row_counted_labels", "old_v2_six_row_counted_labels"),
    ],
)
def test_triage_tags_forbid_leakage_dependencies(outputs: Path, row_id: str, dependency: str) -> None:
    assert row_id in _row_ids(outputs)
    assert dependency in _load(outputs / generation.OUTPUTS["triage_tag_schema"])["forbidden_tag_dependencies"]


@pytest.mark.parametrize("field", admissibility.NUMERIC_SCORE_FIELDS)
def test_triage_receipt_schema_emits_numeric_scores(outputs: Path, field: str) -> None:
    assert field in _load(outputs / generation.OUTPUTS["triage_receipt_schema"])["numeric_scores_required"]


def test_triage_receipt_schema_emits_why_not_route(outputs: Path) -> None:
    assert "why_not_route" in _load(outputs / generation.OUTPUTS["triage_receipt_schema"])["required_fields"]


def test_triage_receipt_schema_emits_selector_entry_authorization_status(outputs: Path) -> None:
    assert "selector_entry_authorized" in _load(outputs / generation.OUTPUTS["triage_receipt_schema"])["required_fields"]


@pytest.mark.parametrize("field", admissibility.TRACE_FIELDS)
def test_trace_schema_emits_required_field(outputs: Path, field: str) -> None:
    assert _candidate(outputs)["trace_requirements"][field] is True
    assert f"trace_schema_emits_{field}" in _row_ids(outputs)


def test_no_contamination_receipt_passes(outputs: Path) -> None:
    receipt = _load(outputs / admissibility.OUTPUTS["candidate_no_contamination_admissibility_receipt"])
    assert receipt["failure_count"] == 0
    assert all(value is False for value in receipt["forbidden_access_status"].values())


def test_old_universe_diagnostic_only_receipt_passes(outputs: Path) -> None:
    receipt = _load(outputs / admissibility.OUTPUTS["candidate_old_universe_diagnostic_only_admissibility_receipt"])
    assert receipt["prior_r01_r04_treatment"] == "DIAGNOSTIC_ONLY"
    assert receipt["prior_v2_six_row_treatment"] == "DIAGNOSTIC_ONLY"


def test_prior_r01_r04_remain_diagnostic_only(outputs: Path) -> None:
    assert _contract(outputs)["universe_binding"]["prior_r01_r04_treatment"] == "DIAGNOSTIC_ONLY"


def test_prior_v2_six_row_remains_diagnostic_only(outputs: Path) -> None:
    assert _contract(outputs)["universe_binding"]["prior_v2_six_row_treatment"] == "DIAGNOSTIC_ONLY"


@pytest.mark.parametrize(
    "output_key",
    [
        "shadow_screen_packet_prep",
        "shadow_screen_metric_contract_prep",
        "shadow_screen_disqualifier_ledger_prep",
        "shadow_screen_replay_manifest_prep",
        "shadow_screen_external_verifier_requirements_prep",
    ],
)
def test_shadow_screen_prep_outputs_are_prep_only(outputs: Path, output_key: str) -> None:
    payload = _load(outputs / admissibility.OUTPUTS[output_key])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_shadow_screen_execution"] is True


def test_prep_only_shadow_metric_contract_cannot_change_current_metrics(outputs: Path) -> None:
    assert _load(outputs / admissibility.OUTPUTS["shadow_screen_metric_contract_prep"])["cannot_widen_metric"] is True


def test_prep_only_disqualifier_ledger_cannot_authorize_screen(outputs: Path) -> None:
    assert _load(outputs / admissibility.OUTPUTS["shadow_screen_disqualifier_ledger_prep"])["cannot_authorize_shadow_screen_execution"] is True


def test_prep_only_external_verifier_requirements_cannot_authorize_public_claims(outputs: Path) -> None:
    assert _load(outputs / admissibility.OUTPUTS["shadow_screen_external_verifier_requirements_prep"])["cannot_claim_superiority"] is True


def test_turboquant_research_packet_remains_prep_only(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["turboquant_translation"])["authority"] == "PREP_ONLY"


def test_compressed_index_cannot_be_source_of_truth(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["compressed_receipt_index"])["compressed_index_is_source_of_truth"] is False


def test_raw_hash_bound_artifact_required_after_compressed_retrieval(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["compressed_receipt_index"])["raw_hash_bound_artifact_required_after_retrieval"] is True


def test_turboquant_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports, state = _write_candidate_generation_state(tmp_path, monkeypatch)
    path = tmp_path / admissibility.INPUTS["turboquant_translation"]
    payload = _load(path)
    payload["authority"] = "AUTHORITATIVE"
    _write_json(path, payload)
    state.update({"branch": admissibility.AUTHORITY_BRANCH, "head": ADMISSIBILITY_BRANCH_HEAD, "origin_main": CURRENT_MAIN_HEAD})
    with pytest.raises(RuntimeError, match="SHADOW_PACKET_AUTHORIZED_TOO_EARLY"):
        admissibility.run(reports_root=reports)


def test_admissibility_does_not_authorize_shadow_screen_execution(outputs: Path) -> None:
    assert _contract(outputs)["shadow_screen_execution_authorized"] is False


def test_admissibility_does_not_open_r6(outputs: Path) -> None:
    assert _contract(outputs)["r6_open"] is False


def test_admissibility_does_not_claim_superiority(outputs: Path) -> None:
    assert _contract(outputs)["learned_router_superiority_earned"] is False


def test_admissibility_does_not_authorize_activation_review(outputs: Path) -> None:
    assert _contract(outputs)["activation_review_authorized"] is False


def test_admissibility_does_not_authorize_package_promotion(outputs: Path) -> None:
    assert _contract(outputs)["package_promotion_authorized"] is False


def test_shadow_screen_authorization_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports, state = _write_candidate_generation_state(tmp_path, monkeypatch)
    path = tmp_path / admissibility.INPUTS["no_authorization_drift_receipt"]
    payload = _load(path)
    payload["shadow_screen_execution_authorized"] = True
    _write_json(path, payload)
    state.update({"branch": admissibility.AUTHORITY_BRANCH, "head": ADMISSIBILITY_BRANCH_HEAD, "origin_main": CURRENT_MAIN_HEAD})
    with pytest.raises(RuntimeError, match="R6_OPEN_DRIFT|SHADOW_SCREEN_EXECUTED"):
        admissibility.run(reports_root=reports)


def test_metric_widening_forbidden(outputs: Path) -> None:
    assert "metric_widening_forbidden" in _row_ids(outputs)


def test_comparator_weakening_forbidden(outputs: Path) -> None:
    assert "comparator_weakening_forbidden" in _row_ids(outputs)


def test_truth_engine_mutation_forbidden(outputs: Path) -> None:
    assert _contract(outputs)["truth_engine_derivation_law_unchanged"] is True


def test_trust_zone_mutation_forbidden(outputs: Path) -> None:
    assert _contract(outputs)["trust_zone_law_unchanged"] is True


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    assert _load(outputs / admissibility.OUTPUTS["no_authorization_drift_receipt"])["no_downstream_authorization_drift"] is True


def test_next_lawful_move_is_shadow_screen_packet(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == admissibility.NEXT_LAWFUL_MOVE
    assert _next(outputs)["selected_outcome"] == admissibility.SELECTED_OUTCOME


def test_required_validation_row_present(outputs: Path) -> None:
    required = {
        "admissibility_contract_preserves_current_main_head",
        "candidate_mixed_head_inputs_fail_closed",
        "only_route_eligible_enters_selector",
        "triage_tags_do_not_use_blind_outcomes",
        "admissibility_does_not_authorize_shadow_screen_execution",
        "next_lawful_move_is_shadow_screen_packet",
    }
    assert required <= _row_ids(outputs)
