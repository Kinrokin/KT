from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_limited_runtime_execution_packet as execution
from tools.operator import cohort0_b04_r6_limited_runtime_execution_packet_validation as validation


VALIDATION_HEAD = "7777777777777777777777777777777777777777"
VALIDATION_MAIN_HEAD = "41bc4b4c256a5ea76d900d5c2c8b1ab7035d618d"


def _load_execution_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_limited_runtime_execution_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_limited_runtime_execution_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load limited-runtime execution helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


execution_helpers = _load_execution_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_validation_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validation.AUTHORITY_BRANCH,
    head: str = VALIDATION_HEAD,
    origin_main: str = VALIDATION_MAIN_HEAD,
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


def _run_execution_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return execution_helpers._run_execution(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_execution_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("limited_runtime_execution_packet_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_validation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _contract(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["next_lawful_move"])


def _scaffold(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["lane_compiler_scaffold_receipt"])


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _contract(outputs)["validation_rows"]}


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_authoritative_lane(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == execution.AUTHORITATIVE_LANE


def test_validation_binds_limited_runtime_execution_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["predecessor_outcome"] == execution.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == execution.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["execution_packet_contract_hash"]
    assert contract["binding_hashes"]["execution_packet_receipt_hash"]


def test_validation_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME


def test_next_lawful_move_is_limited_runtime_run(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_report_states_non_execution(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "does not execute limited runtime" in text
    assert "runtime cutover" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize(
    "flag",
    [
        "r6_open",
        "limited_runtime_authorized",
        "limited_runtime_execution_authorized",
        "limited_runtime_executed",
        "runtime_execution_authorized",
        "runtime_cutover_authorized",
        "activation_cutover_executed",
        "lobe_escalation_authorized",
        "package_promotion_authorized",
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
        "metric_contract_mutated",
        "static_comparator_weakened",
    ],
)
def test_validation_does_not_authorize_forbidden_boundaries(outputs: Path, flag: str) -> None:
    assert _contract(outputs)[flag] is False


def test_validation_marks_execution_packet_validated_but_not_executed(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["limited_runtime_execution_packet_authored"] is True
    assert contract["limited_runtime_execution_packet_validated"] is True
    assert contract["limited_runtime_execution_authorized"] is False
    assert contract["limited_runtime_executed"] is False


@pytest.mark.parametrize("role", validation.CONTROL_VALIDATION_ROLES)
def test_control_validation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _load(outputs / validation.OUTPUTS[role])
    assert payload["validation_status"] == "PASS"
    assert payload["validated_hashes"]


@pytest.mark.parametrize(
    "role,source_role",
    [
        ("execution_packet_binding_validation", "execution_packet_contract"),
        ("mode_validation", "mode_contract"),
        ("scope_validation", "scope_manifest"),
        ("static_authority_validation", "static_authority_contract"),
        ("afsh_shadow_observation_validation", "afsh_shadow_observation_contract"),
        ("operator_override_validation", "operator_override_contract"),
        ("kill_switch_validation", "kill_switch_execution_contract"),
        ("rollback_execution_validation", "rollback_execution_contract"),
        ("route_distribution_health_validation", "route_distribution_health_contract"),
        ("drift_monitoring_validation", "drift_monitoring_contract"),
        ("incident_freeze_validation", "incident_freeze_contract"),
        ("runtime_receipt_schema_validation", "runtime_receipt_schema"),
        ("external_verifier_validation", "external_verifier_requirements"),
        ("commercial_claim_boundary_validation", "commercial_claim_boundary"),
        ("package_promotion_boundary_validation", "commercial_claim_boundary"),
    ],
)
def test_validation_receipts_bind_source_hashes(outputs: Path, role: str, source_role: str) -> None:
    payload = _load(outputs / validation.OUTPUTS[role])
    assert payload["validated_hashes"][f"{source_role}_hash"] == _contract(outputs)["binding_hashes"][f"{source_role}_hash"]


@pytest.mark.parametrize("role", sorted(validation.EXECUTION_JSON_INPUTS))
def test_validation_binds_all_execution_json_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]
    assert f"validation_binds_{role}" in _row_ids(outputs)


@pytest.mark.parametrize("role", sorted(validation.EXECUTION_TEXT_INPUTS))
def test_validation_binds_all_execution_text_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize(
    "carried_hash",
    [
        "validated_packet_contract_hash",
        "validated_packet_receipt_hash",
        "validated_activation_review_validation_contract_hash",
        "validated_activation_review_validation_receipt_hash",
        "validated_shadow_screen_result_hash",
        "validated_candidate_hash",
        "validated_candidate_manifest_hash",
        "validated_candidate_semantic_hash",
        "validated_static_comparator_contract_hash",
        "validated_metric_contract_hash",
        "validated_trace_completeness_receipt_hash",
        "validated_trust_zone_validation_receipt_hash",
    ],
)
def test_validation_carries_packet_binding_hashes(outputs: Path, carried_hash: str) -> None:
    value = _contract(outputs)["binding_hashes"][carried_hash]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_limited_runtime_mode_is_shadow_only(outputs: Path) -> None:
    mode = _load(outputs / execution.OUTPUTS["mode_contract"])
    receipt = _load(outputs / validation.OUTPUTS["mode_validation"])
    assert mode["selected_mode"] == execution.RUNTIME_MODE
    assert mode["allowed_modes"] == ["SHADOW_RUNTIME_ONLY"]
    assert receipt["selected_mode"] == execution.RUNTIME_MODE


def test_limited_runtime_scope_is_limited(outputs: Path) -> None:
    scope = _load(outputs / execution.OUTPUTS["scope_manifest"])
    receipt = _load(outputs / validation.OUTPUTS["scope_validation"])
    assert scope["limited_scope_required"] is True
    assert scope["global_r6_scope"] is False
    assert scope["max_live_traffic_percent_authorized_by_this_packet"] == 0
    assert scope["user_facing_decision_changes_allowed"] is False
    assert receipt["live_traffic_percent"] == 0


def test_static_remains_authoritative(outputs: Path) -> None:
    static = _load(outputs / validation.OUTPUTS["static_authority_validation"])
    assert static["static_decision_authoritative"] is True
    assert static["afsh_can_change_user_facing_decision"] is False


def test_afsh_observation_does_not_cut_over_runtime(outputs: Path) -> None:
    afsh = _load(outputs / validation.OUTPUTS["afsh_shadow_observation_validation"])
    assert afsh["afsh_observation_only"] is True
    assert afsh["selector_may_cutover"] is False


@pytest.mark.parametrize(
    "role,requirements",
    [
        ("scope_manifest", ["limited_scope_required", "shadow_runtime_only", "no_live_traffic_authorized", "not_global_r6"]),
        ("mode_contract", ["shadow_runtime_only", "static_authoritative", "afsh_observation_only", "no_autonomous_cutover"]),
        ("case_class_contract", ["packet_bound_cases_only", "no_global_r6_cases", "no_old_universe_fresh_proof"]),
        ("static_authority_contract", ["static_decision_authoritative", "afsh_cannot_change_user_facing_decision", "static_fallback_always_available"]),
        ("afsh_shadow_observation_contract", ["afsh_observation_only", "receipt_emission_required", "selector_receipts_required"]),
        ("operator_override_contract", ["operator_override_required", "override_may_force_static_only", "override_receipt_required"]),
        ("kill_switch_execution_contract", ["kill_switch_required", "kill_switch_halts_afsh_observation", "kill_switch_receipt_required"]),
        ("rollback_execution_contract", ["rollback_to_static_required", "rollback_receipt_required", "rollback_replay_required"]),
        ("route_distribution_health_contract", ["route_distribution_monitoring_required", "selector_entry_rate_monitored", "overrouting_alarm_required"]),
        ("drift_monitoring_contract", ["metric_drift_freezes_runtime", "trust_zone_drift_freezes_runtime", "truth_engine_drift_freezes_runtime"]),
        ("incident_freeze_contract", ["incident_freeze_required", "freeze_receipt_required", "forensic_path_required"]),
        ("runtime_receipt_schema", ["runtime_receipt_required", "raw_hash_bound_artifacts_required", "external_replay_refs_required"]),
        ("external_verifier_requirements", ["external_verifier_non_executing", "raw_hash_bound_artifacts_required", "public_claims_forbidden"]),
        ("commercial_claim_boundary", ["commercial_activation_claims_unauthorized", "package_promotion_prohibited", "customer_safe_status_language_required"]),
    ],
)
def test_required_execution_control_requirements_exist(outputs: Path, role: str, requirements: list[str]) -> None:
    payload = _load(outputs / execution.OUTPUTS[role])
    assert set(requirements).issubset(set(payload["requirements"]))


@pytest.mark.parametrize("role", execution.CONTROL_OUTPUT_ROLES)
def test_execution_controls_remain_non_authorizing(outputs: Path, role: str) -> None:
    payload = _load(outputs / execution.OUTPUTS[role])
    assert payload["can_execute_runtime"] is False
    assert payload["can_authorize_runtime_cutover"] is False
    assert payload["can_open_r6"] is False
    assert payload["can_promote_package"] is False


@pytest.mark.parametrize("field", execution.RUNTIME_RECEIPT_FIELDS)
def test_runtime_receipt_schema_contains_required_fields(outputs: Path, field: str) -> None:
    receipt = _load(outputs / validation.OUTPUTS["runtime_receipt_schema_validation"])
    assert field in receipt["required_fields"]
    assert f"runtime_receipt_schema_requires_{field}" in _row_ids(outputs)


@pytest.mark.parametrize("condition", execution.INCIDENT_FREEZE_CONDITIONS)
def test_incident_freeze_conditions_exist(outputs: Path, condition: str) -> None:
    receipt = _load(outputs / validation.OUTPUTS["incident_freeze_validation"])
    assert condition in receipt["freeze_conditions"]
    assert f"incident_freeze_on_{condition}" in _row_ids(outputs)


@pytest.mark.parametrize("signal", execution.ROUTE_HEALTH_SIGNALS)
def test_route_health_signals_exist(outputs: Path, signal: str) -> None:
    receipt = _load(outputs / validation.OUTPUTS["route_distribution_health_validation"])
    assert signal in receipt["monitored_signals"]
    assert f"route_health_monitors_{signal}" in _row_ids(outputs)


def test_external_verifier_requirements_are_non_executing(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["external_verifier_validation"])
    assert receipt["external_verifier_non_executing"] is True
    assert receipt["raw_hash_bound_artifacts_required"] is True


def test_commercial_activation_claims_remain_unauthorized(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["commercial_claim_boundary_validation"])
    assert receipt["commercial_activation_claims_authorized"] is False


def test_package_promotion_not_authorized(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["package_promotion_boundary_validation"])
    assert receipt["package_promotion_automatic"] is False
    assert receipt["package_promotion_authorized"] is False


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["no_authorization_drift_validation"])
    assert receipt["no_downstream_authorization_drift"] is True
    assert receipt["limited_runtime_execution_authorized"] is False
    assert receipt["limited_runtime_executed"] is False


def test_lane_compiler_scaffold_is_prep_only(outputs: Path) -> None:
    scaffold = _scaffold(outputs)
    assert scaffold["scaffold_authority"] == "PREP_ONLY_TOOLING"
    assert scaffold["scaffold"]["authority"] == "PREP_ONLY_TOOLING"
    assert scaffold["scaffold_can_authorize"] is False


def test_lane_compiler_scaffold_records_lane_law(outputs: Path) -> None:
    metadata = _scaffold(outputs)["scaffold"]["lane_law_metadata"]
    assert metadata["lane_kind"] == "VALIDATION"
    assert metadata["selected_outcome"] == validation.SELECTED_OUTCOME
    assert metadata["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert "LIMITED_RUNTIME_EXECUTED" in metadata["must_not_authorize"]


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / validation.OUTPUTS[role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["limited_runtime_execution_authorized"] is False
    assert payload["limited_runtime_executed"] is False
    assert payload["r6_open"] is False


def test_pipeline_board_marks_validation_and_run_next(outputs: Path) -> None:
    payload = _load(outputs / validation.OUTPUTS["pipeline_board"])
    board = {row["lane"]: row for row in payload["board"]}
    assert board["VALIDATE_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET"]["status"] == "CURRENT_VALIDATED"
    assert board["RUN_B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME"]["status"] == "NEXT"


def test_runtime_corridor_status_marks_run_next_not_executed(outputs: Path) -> None:
    payload = _load(outputs / validation.OUTPUTS["runtime_corridor_status"])
    corridor = {row["lane"]: row["status"] for row in payload["corridor"]}
    assert corridor["limited_runtime_execution_packet"] == "BOUND_AND_VALIDATED"
    assert corridor["limited_runtime_shadow_runtime"] == "NEXT_NOT_EXECUTED"


def test_future_blocker_register_updated(outputs: Path) -> None:
    payload = _load(outputs / validation.OUTPUTS["future_blocker_register"])
    assert payload["current_authoritative_lane"] == "VALIDATE_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET"
    assert len(payload["blockers"]) >= 3


@pytest.mark.parametrize("check_id", sorted(row["check_id"] for row in validation._validation_rows()))
def test_validation_rows_include_required_checks(outputs: Path, check_id: str) -> None:
    assert check_id in _row_ids(outputs)


@pytest.mark.parametrize("code", validation.REASON_CODES)
def test_reason_codes_are_recorded(outputs: Path, code: str) -> None:
    assert code in _contract(outputs)["reason_codes"]


@pytest.mark.parametrize("action", validation.FORBIDDEN_ACTIONS)
def test_forbidden_actions_are_recorded(outputs: Path, action: str) -> None:
    assert action in _contract(outputs)["forbidden_actions"]


def test_validation_self_replay_handoff_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation(tmp_path, monkeypatch)

    validation.run(reports_root=reports)

    nxt = _load(reports / validation.OUTPUTS["next_lawful_move"])
    assert nxt["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert nxt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_mutated_execution_mode_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["mode_contract"]
    payload = _load(path)
    payload["allowed_modes"] = ["SHADOW_RUNTIME_ONLY", "PRODUCTION_ROUTING"]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="MODE_NOT_SHADOW_OR_CANARY"):
        validation.run(reports_root=reports)


def test_mutated_scope_global_r6_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["scope_manifest"]
    payload = _load(path)
    payload["global_r6_scope"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="GLOBAL_R6_SCOPE|R6_OPEN_DRIFT"):
        validation.run(reports_root=reports)


def test_mutated_scope_live_traffic_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["scope_manifest"]
    payload = _load(path)
    payload["max_live_traffic_percent_authorized_by_this_packet"] = 1
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_EXECUTION_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_mutated_static_authority_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["static_authority_contract"]
    payload = _load(path)
    payload["afsh_can_change_user_facing_decision"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="STATIC_AUTHORITY_MISSING"):
        validation.run(reports_root=reports)


def test_mutated_afsh_cutover_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["afsh_shadow_observation_contract"]
    payload = _load(path)
    payload["selector_may_cutover"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_EXECUTION_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_missing_kill_switch_requirement_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["kill_switch_execution_contract"]
    payload = _load(path)
    payload["requirements"] = ["kill_switch_required"]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="KILL_SWITCH_MISSING"):
        validation.run(reports_root=reports)


def test_runtime_receipt_schema_missing_field_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["runtime_receipt_schema"]
    payload = _load(path)
    payload["required_fields"] = payload["required_fields"][:-1]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="RUNTIME_RECEIPT_SCHEMA_MISSING"):
        validation.run(reports_root=reports)


def test_runtime_executed_flag_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["execution_packet_contract"]
    payload = _load(path)
    payload["limited_runtime_executed"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_EXECUTION_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_nested_authorization_state_cutover_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["execution_packet_contract"]
    payload = _load(path)
    payload.setdefault("authorization_state", {})["runtime_cutover_authorized"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="RUNTIME_CUTOVER_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_prep_only_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["runtime_evidence_review_packet_prep_only_draft"]
    payload = _load(path)
    payload["authority"] = "AUTHORITATIVE"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="PREP_ONLY_AUTHORITY_DRIFT"):
        validation.run(reports_root=reports)


def test_invalid_execution_packet_outcome_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["execution_packet_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_BOUND__R6_OPEN"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="PACKET_BINDING_MISSING"):
        validation.run(reports_root=reports)


def test_invalid_self_replay_handoff_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "R6_OPEN"
    _write(path, payload)

    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)
