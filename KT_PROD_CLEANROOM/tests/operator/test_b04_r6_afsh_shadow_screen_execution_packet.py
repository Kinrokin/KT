from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_afsh_admissibility_court as admissibility
from tools.operator import cohort0_b04_r6_afsh_candidate_generation as generation
from tools.operator import cohort0_b04_r6_afsh_shadow_screen_execution_packet as packet


ADMISSIBILITY_REPLAY_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CANDIDATE_REPLAY_HEAD = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
PACKET_BRANCH_HEAD = "cccccccccccccccccccccccccccccccccccccccc"
CURRENT_MAIN_HEAD = "dddddddddddddddddddddddddddddddddddddddd"
CANDIDATE_SEMANTIC_HASH = "07c6f5f98b25349d3c1ced9de80410fc9800e944430099433cb1fedd2ce87025"
CANDIDATE_ENVELOPE_HASH = "aba6765e3a95c19f1e4d2b669e86285be99a6d848046cb908dd731228a11e39f"


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
        "court_replay_binding_head": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "route_eligible_non_executing_only": True,
        "status": "BOUND_AND_VALIDATED",
        "verdict_modes": list(generation.TOP_LEVEL_VERDICTS),
    }


def _source_packet_binding() -> dict:
    return {
        "source_packet_validation_replay_binding_head": "ffffffffffffffffffffffffffffffffffffffff",
        "status": "BOUND_AND_VALIDATED",
    }


def _authorization_state() -> dict:
    return {
        "activation_cutover_authorized": False,
        "activation_review_authorized": False,
        "afsh_admissibility_executed": True,
        "candidate_generation_executed_in_prior_lane": True,
        "candidate_training_authorized": False,
        "candidate_training_executed": False,
        "learned_router_superiority": "UNEARNED",
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "r6_open": False,
        "runtime_cutover_authorized": False,
        "shadow_screen_execution_authorized": False,
        "shadow_screen_packet_authorized_as_authority": False,
        "shadow_screen_packet_next_lawful_lane": True,
        "trust_zone_law_changed": False,
        "truth_engine_law_changed": False,
    }


def _admissibility_payload(*, artifact_id: str, schema_id: str = "test.schema", rows: list[dict] | None = None) -> dict:
    return {
        "schema_id": schema_id,
        "artifact_id": artifact_id,
        "status": "PASS",
        "current_git_head": ADMISSIBILITY_REPLAY_HEAD,
        "current_main_head": ADMISSIBILITY_REPLAY_HEAD,
        "authoritative_lane": admissibility.AUTHORITATIVE_LANE,
        "selected_outcome": admissibility.SELECTED_OUTCOME,
        "next_lawful_move": admissibility.NEXT_LAWFUL_MOVE,
        "selected_architecture_id": packet.SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": packet.SELECTED_ARCHITECTURE_NAME,
        "candidate_id": packet.CANDIDATE_ID,
        "candidate_version": packet.CANDIDATE_VERSION,
        "candidate_replay_binding_head": CANDIDATE_REPLAY_HEAD,
        "candidate_semantic_hash": CANDIDATE_SEMANTIC_HASH,
        "candidate_envelope_hash": CANDIDATE_ENVELOPE_HASH,
        "candidate_training_authorized": False,
        "candidate_training_executed": False,
        "shadow_screen_packet_authorized_as_authority": False,
        "shadow_screen_execution_authorized": False,
        "shadow_screen_executed": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "activation_review_authorized": False,
        "runtime_cutover_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "authorization_state": _authorization_state(),
        "universe_binding": _universe_binding(),
        "court_binding": _court_binding(),
        "source_packet_binding": _source_packet_binding(),
        "validation_rows": rows or [{"check_id": "pass", "status": "PASS"}],
    }


def _candidate_manifest() -> dict:
    return {
        "schema_id": "kt.b04_r6.afsh_candidate_manifest.v1",
        "artifact_id": "B04_R6_AFSH_CANDIDATE_MANIFEST",
        "candidate_id": packet.CANDIDATE_ID,
        "candidate_version": packet.CANDIDATE_VERSION,
        "candidate_kind": "DETERMINISTIC_RULE_MATERIALIZATION",
        "candidate_semantic_hash": CANDIDATE_SEMANTIC_HASH,
        "candidate_envelope_hash": CANDIDATE_ENVELOPE_HASH,
        "candidate_training_executed": False,
        "current_git_head": CANDIDATE_REPLAY_HEAD,
        "current_main_head": CANDIDATE_REPLAY_HEAD,
        "selected_architecture_id": packet.SELECTED_ARCHITECTURE_ID,
        "top_level_verdict_modes": list(generation.TOP_LEVEL_VERDICTS),
        "trace_requirements": {field: True for field in generation.TRACE_FIELDS},
        "authorization_state": {
            "r6_open": False,
            "learned_router_superiority": "UNEARNED",
            "candidate_training_authorized": False,
            "candidate_training_executed": False,
            "shadow_screen_execution_authorized": False,
            "shadow_screen_packet_authorized": False,
            "activation_review_authorized": False,
            "activation_cutover_authorized": False,
            "runtime_cutover_authorized": False,
            "lobe_escalation_authorized": False,
            "package_promotion": "DEFERRED",
            "truth_engine_law_changed": False,
            "trust_zone_law_changed": False,
        },
    }


def _candidate_artifact() -> dict:
    return {
        "schema_id": "kt.b04_r6.afsh_candidate_v1.v1",
        "artifact_id": packet.CANDIDATE_ID,
        "candidate_id": packet.CANDIDATE_ID,
        "candidate_version": packet.CANDIDATE_VERSION,
        "top_level_verdict_modes": list(generation.TOP_LEVEL_VERDICTS),
        "selector_entry_rule": {
            "only_top_level_verdict_allowed_to_enter_selector": "ROUTE_ELIGIBLE",
            "static_hold_enters_selector": False,
            "abstain_enters_selector": False,
            "null_route_enters_selector": False,
        },
    }


def _candidate_hash_receipt() -> dict:
    return {
        "schema_id": "kt.b04_r6.afsh_candidate_hash_receipt.v1",
        "artifact_id": "B04_R6_AFSH_CANDIDATE_HASH_RECEIPT",
        "status": "PASS",
        "candidate_id": packet.CANDIDATE_ID,
        "candidate_semantic_hash": CANDIDATE_SEMANTIC_HASH,
        "candidate_envelope_hash": CANDIDATE_ENVELOPE_HASH,
        "candidate_receipt_hash_includes_envelope": True,
        "candidate_training_executed": False,
        "shadow_screen_execution_authorized": False,
    }


def _numeric_triage_core() -> dict:
    return {
        "schema_id": "kt.b04_r6.afsh_numeric_triage_emit_core.v1",
        "artifact_id": "B04_R6_AFSH_NUMERIC_TRIAGE_EMIT_CORE",
        "status": "PASS",
        "top_level_verdict_modes": list(generation.TOP_LEVEL_VERDICTS),
        "new_top_level_verdicts_allowed": False,
        "selector_entry_rule": {
            "selector_entry_authorized_only_if": "top_level_verdict == ROUTE_ELIGIBLE",
            "static_hold_selector_entry": False,
            "abstain_selector_entry": False,
            "null_route_selector_entry": False,
        },
    }


def _trace_schema_admissibility() -> dict:
    payload = _admissibility_payload(artifact_id="B04_R6_AFSH_TRACE_SCHEMA_ADMISSIBILITY_RECEIPT")
    payload["required_trace_fields"] = list(generation.TRACE_FIELDS)
    payload["trace_schema_complete"] = True
    return payload


def _turboquant_payload() -> dict:
    return {
        "schema_id": "kt.memory_efficient_replay.turboquant_translation_matrix.v1",
        "artifact_id": "KT_TURBOQUANT_RESEARCH_TRANSLATION_MATRIX_PREP_ONLY",
        "status": "PREP_ONLY",
        "authority": "PREP_ONLY",
        "raw_hash_bound_artifact_required": True,
        "compressed_index_truth_status": "retrieval_aid_not_source_of_truth",
    }


def _compressed_index_payload() -> dict:
    return {
        "schema_id": "kt.memory_efficient_replay.compressed_receipt_vector_index_contract.v1",
        "artifact_id": "KT_COMPRESSED_RECEIPT_VECTOR_INDEX_CONTRACT_PREP_ONLY",
        "status": "PREP_ONLY",
        "authority": "PREP_ONLY",
        "compressed_index_is_source_of_truth": False,
        "raw_hash_bound_artifact_required": True,
        "raw_hash_bound_artifact_required_after_retrieval": True,
    }


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    _write_json(root / packet.INPUTS["admissibility_contract"], _admissibility_payload(artifact_id="B04_R6_AFSH_ADMISSIBILITY_COURT_CONTRACT"))
    _write_json(root / packet.INPUTS["admissibility_receipt"], _admissibility_payload(artifact_id="B04_R6_AFSH_ADMISSIBILITY_COURT_RECEIPT"))
    for role in (
        "candidate_manifest_admissibility",
        "candidate_hash_admissibility",
        "candidate_semantic_hash_admissibility",
        "candidate_replay_binding_admissibility",
        "triage_core_admissibility",
        "no_authorization_drift_admissibility",
    ):
        _write_json(root / packet.INPUTS[role], _admissibility_payload(artifact_id=role.upper()))
    _write_json(root / packet.INPUTS["trace_schema_admissibility"], _trace_schema_admissibility())
    _write_json(root / packet.INPUTS["candidate_manifest"], _candidate_manifest())
    _write_json(root / packet.INPUTS["candidate_artifact"], _candidate_artifact())
    _write_json(root / packet.INPUTS["candidate_hash_receipt"], _candidate_hash_receipt())
    _write_json(root / packet.INPUTS["numeric_triage_emit_core"], _numeric_triage_core())
    _write_json(root / packet.INPUTS["triage_tag_schema"], {"schema_id": "tag", "artifact_id": "TAG_SCHEMA", "status": "PASS"})
    _write_json(root / packet.INPUTS["triage_score_schema"], {"schema_id": "score", "artifact_id": "SCORE_SCHEMA", "status": "PASS"})
    _write_json(root / packet.INPUTS["triage_receipt_schema"], {"schema_id": "receipt", "artifact_id": "RECEIPT_SCHEMA", "status": "PASS"})
    _write_json(root / packet.INPUTS["turboquant_translation"], _turboquant_payload())
    _write_json(root / packet.INPUTS["compressed_receipt_index"], _compressed_index_payload())
    _write_json(root / packet.INPUTS["previous_next_lawful_move"], _admissibility_payload(artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT"))
    _write_text(root / packet.TEXT_INPUTS["admissibility_report"], "# B04 R6 AFSH Admissibility Court\n\nPASS\n")
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "trust", "status": "PASS"})
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "scope", "status": "PASS"})
    return reports


def _patch_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state: dict) -> None:
    monkeypatch.setattr(packet, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(packet.common, "git_current_branch_name", lambda root: state["branch"])
    monkeypatch.setattr(packet.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(
        packet.common,
        "git_rev_parse",
        lambda root, ref: state["origin_main"] if ref == "origin/main" else state["head"],
    )
    monkeypatch.setattr(
        packet,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _write_inputs(tmp_path)
    state = {"branch": packet.AUTHORITY_BRANCH, "head": PACKET_BRANCH_HEAD, "origin_main": CURRENT_MAIN_HEAD}
    _patch_env(monkeypatch, tmp_path, state)
    packet.run(reports_root=reports)
    return reports


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return _run_packet(tmp_path, monkeypatch)


def _contract(outputs: Path) -> dict:
    return _load(outputs / packet.OUTPUTS["packet_contract"])


def _next(outputs: Path) -> dict:
    return _load(outputs / packet.OUTPUTS["next_lawful_move"])


def _metric_contract(outputs: Path) -> dict:
    return _load(outputs / packet.OUTPUTS["metric_contract"])


def _disqualifier_ledger(outputs: Path) -> dict:
    return _load(outputs / packet.OUTPUTS["disqualifier_ledger"])


def _result_contract(outputs: Path) -> dict:
    return _load(outputs / packet.OUTPUTS["result_interpretation_contract"])


@pytest.mark.parametrize("filename", sorted(packet.OUTPUTS.values()))
def test_required_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    if filename.endswith(".md"):
        assert (outputs / filename).read_text(encoding="utf-8").strip()
    else:
        assert _load(outputs / filename)


def test_packet_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == CURRENT_MAIN_HEAD


def test_packet_binds_selected_afsh_architecture(outputs: Path) -> None:
    assert _contract(outputs)["selected_architecture_id"] == packet.SELECTED_ARCHITECTURE_ID


def test_packet_binds_admissible_candidate(outputs: Path) -> None:
    assert _contract(outputs)["candidate_id"] == packet.CANDIDATE_ID
    assert _contract(outputs)["predecessor_outcome"] == packet.EXPECTED_PREVIOUS_OUTCOME


def test_packet_binds_candidate_manifest_hash(outputs: Path) -> None:
    hashes = _contract(outputs)["binding_hashes"]
    assert len(hashes["candidate_manifest_hash"]) == 64


def test_packet_binds_candidate_semantic_hash(outputs: Path) -> None:
    assert _contract(outputs)["binding_hashes"]["candidate_semantic_hash"] == CANDIDATE_SEMANTIC_HASH


def test_packet_binds_validated_blind_universe_hash(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["validated_blind_universe_hash"]) == 64


def test_packet_binds_validated_route_value_court_hash(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["validated_court_hash"]) == 64


def test_packet_binds_validated_source_packet_hash(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["validated_source_packet_hash"]) == 64


def test_packet_binds_admissibility_receipt_hash(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["admissibility_receipt_hash"]) == 64


def test_packet_binds_numeric_triage_core_hash(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["numeric_triage_emit_core_hash"]) == 64


def test_packet_binds_trace_schema_hash(outputs: Path) -> None:
    assert len(_contract(outputs)["binding_hashes"]["trace_schema_hash"]) == 64


def test_packet_does_not_execute_shadow_screen(outputs: Path) -> None:
    assert _contract(outputs)["shadow_screen_executed"] is False


def test_packet_does_not_authorize_shadow_screen_execution(outputs: Path) -> None:
    assert _contract(outputs)["shadow_screen_execution_authorized"] is False


def test_packet_does_not_claim_superiority(outputs: Path) -> None:
    assert _contract(outputs)["learned_router_superiority_earned"] is False


def test_packet_does_not_open_r6(outputs: Path) -> None:
    assert _contract(outputs)["r6_open"] is False


def test_packet_does_not_authorize_activation_review(outputs: Path) -> None:
    assert _contract(outputs)["activation_review_authorized"] is False


def test_packet_does_not_authorize_runtime_cutover(outputs: Path) -> None:
    assert _contract(outputs)["runtime_cutover_authorized"] is False


def test_packet_does_not_authorize_lobe_escalation(outputs: Path) -> None:
    assert _contract(outputs)["lobe_escalation_authorized"] is False


def test_packet_does_not_authorize_package_promotion(outputs: Path) -> None:
    assert _contract(outputs)["package_promotion_authorized"] is False


def test_static_comparator_contract_exists(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["static_comparator_contract"])["artifact_id"] == "B04_R6_AFSH_SHADOW_SCREEN_STATIC_COMPARATOR_CONTRACT"


def test_static_comparator_is_frozen(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["static_comparator_contract"])["comparator_must_be_frozen"] is True


def test_comparator_weakening_forbidden(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["static_comparator_contract"])["comparator_weakening_forbidden"] is True


def test_metric_contract_exists(outputs: Path) -> None:
    assert _metric_contract(outputs)["artifact_id"] == "B04_R6_AFSH_SHADOW_SCREEN_METRIC_CONTRACT"


def test_metric_widening_forbidden(outputs: Path) -> None:
    assert _metric_contract(outputs)["metric_widening_forbidden"] is True


def test_metrics_frozen_before_execution(outputs: Path) -> None:
    assert _metric_contract(outputs)["metrics_frozen_before_execution"] is True


@pytest.mark.parametrize("metric", packet.PRIMARY_METRICS)
def test_metric_contract_includes_primary_metrics(outputs: Path, metric: str) -> None:
    assert metric in _metric_contract(outputs)["primary_metrics"]


def test_disqualifier_ledger_exists(outputs: Path) -> None:
    assert _disqualifier_ledger(outputs)["artifact_id"] == "B04_R6_AFSH_SHADOW_SCREEN_DISQUALIFIER_LEDGER"


@pytest.mark.parametrize("name", packet.TERMINAL_DISQUALIFIERS)
def test_disqualifier_ledger_marks_terminal_conditions(outputs: Path, name: str) -> None:
    assert name in _disqualifier_ledger(outputs)["terminal_disqualifiers"]


def test_result_interpretation_contract_exists(outputs: Path) -> None:
    assert _result_contract(outputs)["artifact_id"] == "B04_R6_AFSH_SHADOW_SCREEN_RESULT_INTERPRETATION_CONTRACT"


def test_result_interpretation_requires_all_success_conditions(outputs: Path) -> None:
    assert _result_contract(outputs)["superiority_cannot_be_earned_unless_all_required_conditions_pass"] is True


def test_result_interpretation_prevents_partial_win_from_superiority(outputs: Path) -> None:
    assert _result_contract(outputs)["partial_win_cannot_claim_superiority"] is True


def test_result_interpretation_preserves_failure_and_invalidated_outcomes(outputs: Path) -> None:
    outcomes = set(_result_contract(outputs)["future_screen_allowed_outcomes"])
    assert "B04_R6_AFSH_SHADOW_SUPERIORITY_FAILED__SUPERIORITY_NOT_EARNED_CLOSEOUT_OR_REDESIGN_NEXT" in outcomes
    assert "B04_R6_AFSH_SHADOW_SCREEN_INVALIDATED__FORENSIC_INVALIDATION_COURT_NEXT" in outcomes


@pytest.mark.parametrize("condition", packet.SUCCESS_CONDITIONS)
def test_result_interpretation_requires_success_conditions(outputs: Path, condition: str) -> None:
    assert condition in _result_contract(outputs)["required_success_conditions"]


def test_replay_manifest_exists(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["replay_manifest"])["artifact_id"] == "B04_R6_AFSH_SHADOW_SCREEN_REPLAY_MANIFEST"


def test_replay_manifest_binds_expected_artifacts(outputs: Path) -> None:
    assert "candidate_manifest" in _load(outputs / packet.OUTPUTS["replay_manifest"])["expected_artifact_roles"]


def test_replay_manifest_includes_required_text_artifacts(outputs: Path) -> None:
    manifest = _load(outputs / packet.OUTPUTS["replay_manifest"])
    assert "admissibility_report" in manifest["expected_artifact_roles"]
    assert "admissibility_report" in manifest["expected_text_artifact_roles"]


def test_replay_manifest_requires_raw_hash_bound_artifacts(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["replay_manifest"])["raw_hash_bound_artifacts_required"] is True


def test_external_verifier_requirements_exist(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["external_verifier_requirements"])["artifact_id"] == "B04_R6_AFSH_SHADOW_SCREEN_EXTERNAL_VERIFIER_REQUIREMENTS"


def test_external_verifier_requirements_are_non_executing(outputs: Path) -> None:
    reqs = _load(outputs / packet.OUTPUTS["external_verifier_requirements"])
    assert reqs["cannot_execute_shadow_screen"] is True
    assert reqs["cannot_claim_superiority"] is True


@pytest.mark.parametrize(
    "role",
    [
        "execution_prep_only_draft",
        "result_schema_prep_only_draft",
        "activation_review_packet_prep_only_draft",
        "superiority_not_earned_closeout_prep_only_draft",
        "forensic_invalidation_court_prep_only_draft",
    ],
)
def test_future_drafts_are_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / packet.OUTPUTS[role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_execute_shadow_screen"] is True


def test_turboquant_memory_replay_artifacts_remain_prep_only(outputs: Path) -> None:
    assert _contract(outputs)["validation_rows"]
    assert _load(outputs / packet.OUTPUTS["external_verifier_requirements"])["compressed_index_cannot_be_source_of_truth"] is True


def test_compressed_index_cannot_be_source_of_truth(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["replay_manifest"])["compressed_indexes_are_retrieval_aids_only"] is True


def test_raw_hash_bound_artifact_required_after_compressed_retrieval(outputs: Path) -> None:
    assert _load(outputs / packet.OUTPUTS["replay_manifest"])["raw_hash_bound_artifacts_required"] is True


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _load(outputs / packet.OUTPUTS["no_authorization_drift_receipt"])
    assert receipt["status"] == "PASS"
    assert receipt["no_downstream_authorization_drift"] is True


def test_truth_engine_law_unchanged(outputs: Path) -> None:
    assert _contract(outputs)["truth_engine_derivation_law_unchanged"] is True


def test_trust_zone_law_unchanged(outputs: Path) -> None:
    assert _contract(outputs)["trust_zone_law_unchanged"] is True


def test_next_lawful_move_is_packet_validation(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == packet.NEXT_LAWFUL_MOVE
    assert _next(outputs)["selected_outcome"] == packet.SELECTED_OUTCOME


def test_packet_validation_scaffold_points_to_shadow_screen_later(outputs: Path) -> None:
    plan = _load(outputs / packet.OUTPUTS["packet_validation_plan"])
    assert plan["expected_success_outcome"] == "B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET_VALIDATED__SHADOW_SCREEN_NEXT"
    assert plan["next_lawful_move_after_validation_success"] == "RUN_B04_R6_AFSH_SHADOW_SCREEN"
    assert plan["execution_authorized_by_this_plan"] is False


def test_future_blocker_register_updated(outputs: Path) -> None:
    register = _load(outputs / packet.OUTPUTS["future_blocker_register"])
    assert register["current_authoritative_lane"] == "AUTHOR_B04_R6_AFSH_SHADOW_SCREEN_EXECUTION_PACKET"


def test_shadow_execution_authorization_in_input_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    payload = _load(tmp_path / packet.INPUTS["admissibility_contract"])
    payload["shadow_screen_execution_authorized"] = True
    _write_json(tmp_path / packet.INPUTS["admissibility_contract"], payload)
    state = {"branch": packet.AUTHORITY_BRANCH, "head": PACKET_BRANCH_HEAD, "origin_main": CURRENT_MAIN_HEAD}
    _patch_env(monkeypatch, tmp_path, state)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        packet.run(reports_root=reports)


def test_superiority_claim_in_input_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    payload = _load(tmp_path / packet.INPUTS["admissibility_receipt"])
    payload["learned_router_superiority_earned"] = True
    _write_json(tmp_path / packet.INPUTS["admissibility_receipt"], payload)
    state = {"branch": packet.AUTHORITY_BRANCH, "head": PACKET_BRANCH_HEAD, "origin_main": CURRENT_MAIN_HEAD}
    _patch_env(monkeypatch, tmp_path, state)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        packet.run(reports_root=reports)


def test_compressed_index_as_truth_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    payload = _load(tmp_path / packet.INPUTS["compressed_receipt_index"])
    payload["compressed_index_is_source_of_truth"] = True
    _write_json(tmp_path / packet.INPUTS["compressed_receipt_index"], payload)
    state = {"branch": packet.AUTHORITY_BRANCH, "head": PACKET_BRANCH_HEAD, "origin_main": CURRENT_MAIN_HEAD}
    _patch_env(monkeypatch, tmp_path, state)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        packet.run(reports_root=reports)


def test_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    payload = _load(tmp_path / packet.INPUTS["previous_next_lawful_move"])
    payload["next_lawful_move"] = "RUN_B04_R6_AFSH_SHADOW_SCREEN"
    _write_json(tmp_path / packet.INPUTS["previous_next_lawful_move"], payload)
    state = {"branch": packet.AUTHORITY_BRANCH, "head": PACKET_BRANCH_HEAD, "origin_main": CURRENT_MAIN_HEAD}
    _patch_env(monkeypatch, tmp_path, state)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        packet.run(reports_root=reports)
