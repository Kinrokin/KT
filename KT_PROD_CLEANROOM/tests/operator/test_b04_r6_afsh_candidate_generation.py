from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_afsh_candidate_generation as generation


SOURCE_VALIDATION_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
BRANCH_HEAD = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
MAIN_HEAD = "f8b21fb763f999626c92867c9365c2976d2cf3fc"


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


def _previous_payload(*, role: str, status: str = "PASS") -> dict:
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


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    for role, raw in generation.INPUTS.items():
        _write_json(root / raw, _previous_payload(role=role))
    _write_text(root / generation.TEXT_INPUTS["source_validation_report"], "# AFSH Source Packet Validation\n\nPASS\n")
    _write_json(root / generation.REFERENCE_INPUTS["source_packet_contract"], {"schema_id": "source", "status": "PASS"})
    _write_json(root / generation.REFERENCE_INPUTS["court_validation_receipt"], {"schema_id": "court", "status": "PASS"})
    _write_json(
        root / generation.REFERENCE_INPUTS["blind_universe_manifest"],
        {"schema_id": "universe", "status": "PASS", "case_count": generation.EXPECTED_CASE_COUNT},
    )
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "trust", "status": "PASS"})
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "scope", "status": "PASS"})
    return reports


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = generation.AUTHORITY_BRANCH,
    head: str = BRANCH_HEAD,
    origin_main: str = MAIN_HEAD,
) -> None:
    monkeypatch.setattr(generation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(generation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(generation.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(generation.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        generation,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    generation.run(reports_root=reports)
    return reports


def _contract(outputs: Path) -> dict:
    return _load(outputs / generation.OUTPUTS["generation_contract"])


def _manifest(outputs: Path) -> dict:
    return _load(outputs / generation.OUTPUTS["candidate_manifest"])


def _candidate(outputs: Path) -> dict:
    return _load(outputs / generation.OUTPUTS["candidate_v1"])


def _hash_receipt(outputs: Path) -> dict:
    return _load(outputs / generation.OUTPUTS["candidate_hash_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / generation.OUTPUTS["next_lawful_move"])


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _contract(outputs)["validation_rows"]}


@pytest.mark.parametrize("filename", sorted(generation.OUTPUTS.values()))
def test_required_json_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    assert _load(outputs / filename)


def test_candidate_generation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == MAIN_HEAD


def test_candidate_generation_binds_selected_afsh_architecture(outputs: Path) -> None:
    assert _manifest(outputs)["selected_architecture_id"] == generation.SELECTED_ARCHITECTURE_ID


def test_candidate_generation_binds_validated_blind_universe(outputs: Path) -> None:
    assert _manifest(outputs)["validated_inputs"]["blind_universe"]["case_count"] == generation.EXPECTED_CASE_COUNT


def test_candidate_generation_binds_validated_route_value_court(outputs: Path) -> None:
    assert _manifest(outputs)["validated_inputs"]["route_value_court"]["verdict_modes"] == list(generation.TOP_LEVEL_VERDICTS)


def test_candidate_generation_binds_validated_source_packet(outputs: Path) -> None:
    assert _manifest(outputs)["validated_inputs"]["implementation_source_packet"]["outcome"] == generation.EXPECTED_PREVIOUS_OUTCOME


def test_candidate_manifest_exists_and_parses(outputs: Path) -> None:
    assert _manifest(outputs)["artifact_id"] == "B04_R6_AFSH_CANDIDATE_MANIFEST"


def test_candidate_artifact_exists_and_parses(outputs: Path) -> None:
    assert _candidate(outputs)["artifact_id"] == "B04_R6_AFSH_CANDIDATE_V1"


def test_candidate_id_is_b04_r6_afsh_candidate_v1(outputs: Path) -> None:
    assert _candidate(outputs)["candidate_id"] == generation.CANDIDATE_ID


def test_candidate_kind_is_deterministic_rule_materialization(outputs: Path) -> None:
    assert _manifest(outputs)["candidate_kind"] == "DETERMINISTIC_RULE_MATERIALIZATION"


def test_candidate_generation_executed_true(outputs: Path) -> None:
    assert _manifest(outputs)["candidate_generation_executed"] is True


def test_candidate_training_executed_false(outputs: Path) -> None:
    assert _manifest(outputs)["training_executed"] is False


def test_candidate_training_remains_unauthorized(outputs: Path) -> None:
    assert _manifest(outputs)["authorization_state"]["candidate_training_authorized"] is False


def test_candidate_semantic_hash_excludes_generated_utc(outputs: Path) -> None:
    candidate = _candidate(outputs)
    mutated = {**candidate, "generated_utc": "2099-01-01T00:00:00Z"}
    assert generation.candidate_semantic_hash(candidate) == generation.candidate_semantic_hash(mutated)
    assert _hash_receipt(outputs)["candidate_semantic_hash"] == generation.candidate_semantic_hash(mutated)


def test_candidate_receipt_hash_includes_envelope(outputs: Path) -> None:
    receipt = _hash_receipt(outputs)
    assert receipt["candidate_envelope_hash"] != receipt["candidate_semantic_hash"]
    assert receipt["candidate_receipt_hash_includes_envelope"] is True


def test_candidate_immutable_inputs_share_replay_head(outputs: Path) -> None:
    manifest = _load(outputs / generation.OUTPUTS["immutable_input_manifest"])
    assert manifest["source_validation_replay_head"] == SOURCE_VALIDATION_HEAD
    assert manifest["immutable_source_inputs_share_replay_head"] is True


def test_candidate_mixed_head_inputs_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    path = tmp_path / generation.INPUTS["allowed_features_validation"]
    payload = _load(path)
    payload["current_git_head"] = "cccccccccccccccccccccccccccccccccccccccc"
    _write_json(path, payload)
    with pytest.raises(RuntimeError, match="replay head"):
        generation.run(reports_root=reports)


def test_candidate_mutable_handoff_bound_before_overwrite(outputs: Path) -> None:
    receipt = _load(outputs / generation.OUTPUTS["mutable_handoff_binding_receipt"])
    rows = [row for row in receipt["input_bindings"] if row["role"] == "previous_next_lawful_move"]
    assert rows and rows[0]["binding_kind"] == "git_object_before_overwrite"


def test_candidate_generation_does_not_train(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["no_training_receipt"])["candidate_training_executed"] is False


def test_candidate_generation_does_not_execute_admissibility(outputs: Path) -> None:
    assert _manifest(outputs)["authorization_state"]["afsh_admissibility_executed"] is False


def test_candidate_generation_does_not_access_blind_labels(outputs: Path) -> None:
    status = _load(outputs / generation.OUTPUTS["no_contamination_receipt"])["forbidden_access_status"]
    assert status["blind_outcome_labels_accessed"] is False


def test_candidate_generation_does_not_access_route_success_labels(outputs: Path) -> None:
    status = _load(outputs / generation.OUTPUTS["no_contamination_receipt"])["forbidden_access_status"]
    assert status["blind_route_success_labels_accessed"] is False


def test_candidate_prep_only_admissibility_draft_non_authoritative(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["admissibility_court_prep"])["authority"] == "PREP_ONLY"


def test_candidate_post_merge_replay_required(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["replay_binding_receipt"])["post_merge_replay_required"] is True


def test_candidate_includes_numeric_triage_emit_core(outputs: Path) -> None:
    assert _candidate(outputs)["modules"]["numeric_triage_emit_core"] == "B04_R6_AFSH_NUMERIC_TRIAGE_EMIT_CORE"


def test_candidate_includes_triage_intake_gate(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["triage_intake_gate"])["runs_before_selector"] is True


def test_triage_gate_is_stage_0_or_stage_1_not_stage_2_selector(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["triage_intake_gate"])["stage"].startswith("STAGE_0")


def test_triage_top_level_verdict_modes_match_validated_court_modes(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["numeric_triage_emit_core"])["top_level_verdict_modes"] == list(generation.TOP_LEVEL_VERDICTS)


def test_human_review_maps_to_abstain_subtype(outputs: Path) -> None:
    matrix = _load(outputs / generation.OUTPUTS["numeric_triage_emit_core"])["emit_logic_order"]
    assert {"if": "boundary_unclear", "emit": "ABSTAIN", "triage_subtype": "HUMAN_OR_COURT_REVIEW"} in matrix


def test_quarantine_maps_to_abstain_subtype(outputs: Path) -> None:
    matrix = _load(outputs / generation.OUTPUTS["numeric_triage_emit_core"])["emit_logic_order"]
    assert {"if": "trust_zone_unclear", "emit": "ABSTAIN", "triage_subtype": "QUARANTINE_OR_NONCANONICAL"} in matrix


def test_null_route_surface_temptation_maps_to_null_route(outputs: Path) -> None:
    matrix = _load(outputs / generation.OUTPUTS["numeric_triage_emit_core"])["emit_logic_order"]
    assert {"if": "null_route_control_active", "emit": "NULL_ROUTE", "triage_subtype": "DEFER"} in matrix


def test_only_route_eligible_enters_selector(outputs: Path) -> None:
    assert _candidate(outputs)["selector_entry_rule"]["only_top_level_verdict_allowed_to_enter_selector"] == "ROUTE_ELIGIBLE"


@pytest.mark.parametrize("verdict", ["static_hold", "abstain", "null_route"])
def test_non_route_eligible_cases_do_not_enter_selector(outputs: Path, verdict: str) -> None:
    assert _candidate(outputs)["selector_entry_rule"][f"{verdict}_enters_selector"] is False


def test_triage_scores_are_deterministic(outputs: Path) -> None:
    score_schema = _load(outputs / generation.OUTPUTS["triage_score_schema"])
    assert score_schema["deterministic"] is True
    assert score_schema["numeric_score_fields"] == list(generation.NUMERIC_SCORE_FIELDS)


def test_triage_emit_logic_is_fail_closed(outputs: Path) -> None:
    matrix = _load(outputs / generation.OUTPUTS["triage_emit_decision_matrix"])
    assert matrix["fail_closed_default"] == "STATIC_HOLD"


def test_triage_tags_are_receipt_derived(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["triage_tag_schema"])["tags_must_be_receipt_derived"] is True


@pytest.mark.parametrize(
    "forbidden",
    [
        "blind_outcome_labels",
        "blind_route_success_labels",
        "post_screen_labels",
        "old_r01_r04_counted_labels",
        "old_v2_six_row_counted_labels",
    ],
)
def test_triage_tags_do_not_use_forbidden_label_sources(outputs: Path, forbidden: str) -> None:
    assert forbidden in _load(outputs / generation.OUTPUTS["triage_tag_schema"])["forbidden_tag_dependencies"]


@pytest.mark.parametrize(
    "field",
    [
        "numeric_scores",
        "trust_zone_tags",
        "evidence_tags",
        "risk_tags",
        "route_economics_tags",
        "why_not_route",
        "selector_entry_authorized",
    ],
)
def test_triage_receipt_schema_requires_core_fields(outputs: Path, field: str) -> None:
    assert field in _load(outputs / generation.OUTPUTS["triage_receipt_schema"])["required_fields"]


def test_triage_receipt_emits_specialist_candidate_tags_only_for_route_eligible(outputs: Path) -> None:
    invariants = _load(outputs / generation.OUTPUTS["triage_receipt_schema"])["invariants"]
    assert "specialist_candidate_tags must be empty unless top_level_verdict == ROUTE_ELIGIBLE" in invariants


def test_triage_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["triage_no_authorization_drift_receipt"])["admissibility_executed"] is False


@pytest.mark.parametrize(
    "filename",
    [
        generation.OUTPUTS["admissibility_court_prep"],
        generation.OUTPUTS["admissibility_reason_codes_prep"],
        generation.OUTPUTS["replay_validation_plan_prep"],
        generation.OUTPUTS["trace_compatibility_validation_plan_prep"],
    ],
)
def test_admissibility_prep_outputs_are_prep_only(outputs: Path, filename: str) -> None:
    assert _load(outputs / filename)["authority"] == "PREP_ONLY"


@pytest.mark.parametrize(
    "flag",
    [
        "cannot_authorize_admissibility_execution",
        "cannot_authorize_shadow_screen_packet",
        "cannot_authorize_shadow_screen_execution",
        "cannot_authorize_activation",
        "cannot_authorize_package_promotion",
    ],
)
def test_prep_only_drafts_cannot_authorize_downstream_execution(outputs: Path, flag: str) -> None:
    assert _load(outputs / generation.OUTPUTS["admissibility_court_prep"])[flag] is True


def test_memory_compression_research_packet_is_prep_only(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["turboquant_translation"])["authority"] == "PREP_ONLY"


@pytest.mark.parametrize(
    "forbidden",
    [
        "B04_R6_AFSH_CANDIDATE_GENERATION_EXECUTION",
        "AFSH_ADMISSIBILITY",
        "SHADOW_SCREEN_EXECUTION",
        "R6_OPEN",
        "LEARNED_ROUTER_SUPERIORITY",
        "ACTIVATION",
        "PACKAGE_PROMOTION",
        "CURRENT_ROUTE_VALUE_FORMULA_MUTATION",
    ],
)
def test_memory_compression_cannot_authorize_downstream_or_mutate_law(outputs: Path, forbidden: str) -> None:
    assert forbidden in _load(outputs / generation.OUTPUTS["turboquant_translation"])["cannot_authorize"]


def test_compressed_index_cannot_be_source_of_truth(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["compressed_receipt_index"])["compressed_index_is_source_of_truth"] is False


def test_raw_hash_bound_artifact_required_after_compressed_retrieval(outputs: Path) -> None:
    assert _load(outputs / generation.OUTPUTS["compressed_receipt_index"])["raw_hash_bound_artifact_required_after_retrieval"] is True


def test_next_lawful_move_is_admissibility_court(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == generation.NEXT_LAWFUL_MOVE


REQUIRED_ROW_IDS = [
    "candidate_generation_contract_preserves_current_main_head",
    "candidate_generation_binds_selected_afsh_architecture",
    "candidate_generation_binds_validated_blind_universe",
    "candidate_generation_binds_validated_route_value_court",
    "candidate_generation_binds_validated_source_packet",
    "candidate_id_is_b04_r6_afsh_candidate_v1",
    "candidate_kind_is_deterministic_rule_materialization",
    "candidate_generation_executed_true",
    "candidate_training_executed_false",
    "candidate_training_remains_unauthorized",
    "candidate_hash_receipt_bound",
    "candidate_derivation_receipt_bound",
    "rule_materialization_receipt_bound",
    "no_training_receipt_bound",
    "no_contamination_receipt_bound",
    "static_hold_default_receipt_bound",
    "abstention_preservation_receipt_bound",
    "null_route_preservation_receipt_bound",
    "mirror_masked_stability_receipt_bound",
    "source_hash_receipt_bound",
    "no_authorization_drift_receipt_passes",
    "candidate_includes_numeric_triage_emit_core",
    "candidate_includes_triage_intake_gate",
    "triage_gate_is_stage_0_or_stage_1_not_stage_2_selector",
    "triage_top_level_verdict_modes_match_validated_court_modes",
    "human_review_maps_to_abstain_subtype",
    "quarantine_maps_to_abstain_subtype",
    "null_route_surface_temptation_maps_to_null_route",
    "only_route_eligible_enters_selector",
    "static_hold_cases_do_not_enter_selector",
    "abstain_cases_do_not_enter_selector",
    "null_route_cases_do_not_enter_selector",
    "triage_scores_are_deterministic",
    "triage_emit_logic_is_fail_closed",
    "triage_tags_are_receipt_derived",
    "triage_tags_do_not_use_blind_outcomes",
    "triage_tags_do_not_use_route_success_labels",
    "triage_tags_do_not_use_post_screen_labels",
    "triage_tags_do_not_use_old_r01_r04_counted_labels",
    "triage_tags_do_not_use_old_v2_six_row_counted_labels",
    "triage_receipt_emits_numeric_scores",
    "triage_receipt_emits_trust_zone_tags",
    "triage_receipt_emits_evidence_tags",
    "triage_receipt_emits_risk_tags",
    "triage_receipt_emits_route_economics_tags",
    "triage_receipt_emits_why_not_route",
    "triage_receipt_emits_selector_entry_authorization_status",
    "triage_receipt_emits_specialist_candidate_tags_only_for_route_eligible",
    "triage_no_authorization_drift_receipt_passes",
    "candidate_semantic_hash_excludes_generated_utc",
    "candidate_receipt_hash_includes_envelope",
    "candidate_immutable_inputs_share_replay_head",
    "candidate_mixed_head_inputs_fail_closed",
    "candidate_mutable_handoff_bound_before_overwrite",
    "candidate_generation_does_not_train",
    "candidate_generation_does_not_execute_admissibility",
    "candidate_generation_does_not_access_blind_labels",
    "candidate_generation_does_not_access_route_success_labels",
    "candidate_prep_only_admissibility_draft_non_authoritative",
    "candidate_post_merge_replay_required",
    "admissibility_court_draft_is_prep_only",
    "admissibility_reason_codes_are_prep_only",
    "replay_validation_plan_is_prep_only",
    "trace_compatibility_plan_is_prep_only",
    "prep_only_drafts_cannot_authorize_admissibility_execution",
    "prep_only_drafts_cannot_authorize_shadow_screen_packet",
    "prep_only_drafts_cannot_authorize_shadow_screen_execution",
    "prep_only_drafts_cannot_authorize_activation",
    "prep_only_drafts_cannot_authorize_package_promotion",
    "memory_compression_research_packet_is_prep_only",
    "memory_compression_cannot_authorize_candidate_generation",
    "memory_compression_cannot_authorize_admissibility",
    "memory_compression_cannot_authorize_shadow_screen",
    "memory_compression_cannot_authorize_r6_open",
    "memory_compression_cannot_claim_superiority",
    "memory_compression_cannot_authorize_activation",
    "memory_compression_cannot_authorize_package_promotion",
    "memory_compression_cannot_change_route_value_formula_in_current_lane",
    "compressed_index_cannot_be_source_of_truth",
    "raw_hash_bound_artifact_required_after_compressed_retrieval",
    "metric_widening_forbidden",
    "comparator_weakening_forbidden",
    "truth_engine_law_unchanged",
    "trust_zone_law_unchanged",
    "next_lawful_move_is_admissibility_court",
]


@pytest.mark.parametrize("row_id", REQUIRED_ROW_IDS)
def test_required_validation_row_present(outputs: Path, row_id: str) -> None:
    assert row_id in _row_ids(outputs)
