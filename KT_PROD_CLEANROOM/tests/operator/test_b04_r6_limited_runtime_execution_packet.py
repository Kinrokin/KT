from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_limited_runtime_authorization_packet as limited_auth
from tools.operator import cohort0_b04_r6_limited_runtime_authorization_packet_validation as auth_validation
from tools.operator import cohort0_b04_r6_limited_runtime_execution_packet as execution


EXECUTION_HEAD = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
EXECUTION_MAIN_HEAD = "6f562f19f5028d2f962ea9ccb33245ee49a33fbd"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_limited_runtime_authorization_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_limited_runtime_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_execution_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = execution.AUTHORITY_BRANCH,
    head: str = EXECUTION_HEAD,
    origin_main: str = EXECUTION_MAIN_HEAD,
) -> None:
    monkeypatch.setattr(execution, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(execution.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(execution.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(execution.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        execution,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_previous_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_previous_validation(tmp_path, monkeypatch)
    _patch_execution_env(monkeypatch, tmp_path)
    execution.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("limited_runtime_execution_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_execution(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _contract(outputs: Path) -> dict:
    return _load(outputs / execution.OUTPUTS["execution_packet_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / execution.OUTPUTS["execution_packet_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / execution.OUTPUTS["next_lawful_move"])


def _scaffold(outputs: Path) -> dict:
    return _load(outputs / execution.OUTPUTS["lane_compiler_scaffold_receipt"])


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _contract(outputs)["validation_rows"]}


@pytest.mark.parametrize("filename", sorted(execution.OUTPUTS.values()))
def test_required_execution_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_execution_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == EXECUTION_MAIN_HEAD


def test_execution_packet_binds_predecessor_outcome(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["predecessor_outcome"] == auth_validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == auth_validation.NEXT_LAWFUL_MOVE


def test_execution_packet_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == execution.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == execution.SELECTED_OUTCOME


def test_next_lawful_move_is_execution_packet_validation(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == execution.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == execution.NEXT_LAWFUL_MOVE


def test_execution_packet_report_states_non_execution(outputs: Path) -> None:
    text = (outputs / execution.OUTPUTS["execution_packet_report"]).read_text(encoding="utf-8").lower()
    assert "does not execute limited runtime" in text
    assert "static remains authoritative" in text
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
def test_execution_packet_does_not_authorize_forbidden_boundaries(outputs: Path, flag: str) -> None:
    assert _contract(outputs)[flag] is False


def test_execution_packet_marks_packet_authored_but_not_validated(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["limited_runtime_execution_packet_authored"] is True
    assert contract["limited_runtime_execution_packet_validated"] is False
    assert contract["runtime_execution_authorized"] is False


def test_runtime_mode_is_shadow_runtime_only(outputs: Path) -> None:
    mode = _load(outputs / execution.OUTPUTS["mode_contract"])
    assert mode["selected_mode"] == execution.RUNTIME_MODE
    assert mode["allowed_modes"] == ["SHADOW_RUNTIME_ONLY"]
    assert mode["afsh_observation_only"] is True


def test_scope_is_limited_and_non_global(outputs: Path) -> None:
    scope = _load(outputs / execution.OUTPUTS["scope_manifest"])
    assert scope["limited_scope_required"] is True
    assert scope["global_r6_scope"] is False
    assert scope["max_live_traffic_percent_authorized_by_this_packet"] == 0
    assert scope["user_facing_decision_changes_allowed"] is False


def test_static_authority_contract_preserves_static(outputs: Path) -> None:
    static = _load(outputs / execution.OUTPUTS["static_authority_contract"])
    assert static["static_decision_authoritative"] is True
    assert static["afsh_can_change_user_facing_decision"] is False


def test_afsh_shadow_observation_is_observation_only(outputs: Path) -> None:
    payload = _load(outputs / execution.OUTPUTS["afsh_shadow_observation_contract"])
    assert payload["afsh_observation_only"] is True
    assert payload["selector_may_cutover"] is False


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
def test_control_outputs_remain_non_authorizing(outputs: Path, role: str) -> None:
    payload = _load(outputs / execution.OUTPUTS[role])
    assert payload["can_execute_runtime"] is False
    assert payload["can_authorize_runtime_cutover"] is False
    assert payload["can_open_r6"] is False
    assert payload["can_promote_package"] is False


@pytest.mark.parametrize("field", execution.RUNTIME_RECEIPT_FIELDS)
def test_runtime_receipt_schema_contains_required_fields(outputs: Path, field: str) -> None:
    payload = _load(outputs / execution.OUTPUTS["runtime_receipt_schema"])
    assert field in payload["required_fields"]
    assert f"runtime_receipt_requires_{field}" in _row_ids(outputs)


@pytest.mark.parametrize("condition", execution.INCIDENT_FREEZE_CONDITIONS)
def test_incident_freeze_conditions_exist(outputs: Path, condition: str) -> None:
    payload = _load(outputs / execution.OUTPUTS["incident_freeze_contract"])
    assert condition in payload["freeze_conditions"]
    assert f"incident_freeze_on_{condition}" in _row_ids(outputs)


@pytest.mark.parametrize("signal", execution.ROUTE_HEALTH_SIGNALS)
def test_route_health_signals_exist(outputs: Path, signal: str) -> None:
    payload = _load(outputs / execution.OUTPUTS["route_distribution_health_contract"])
    assert signal in payload["monitored_signals"]
    assert f"route_health_monitors_{signal}" in _row_ids(outputs)


@pytest.mark.parametrize("key", sorted(["binding_hashes", "input_bindings", "validation_rows", "lane_compiler_scaffold"]))
def test_contract_carries_core_receipt_sections(outputs: Path, key: str) -> None:
    assert _contract(outputs)[key]


@pytest.mark.parametrize("role", sorted(execution.INPUTS))
def test_execution_packet_binds_all_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]
    assert f"execution_packet_binds_{role}" in _row_ids(outputs)


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
def test_execution_packet_carries_prior_validation_hashes(outputs: Path, carried_hash: str) -> None:
    value = _contract(outputs)["binding_hashes"][carried_hash]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_authorization_validation_binding_receipt_passes(outputs: Path) -> None:
    payload = _load(outputs / execution.OUTPUTS["authorization_validation_binding_receipt"])
    assert payload["binding_status"] == "PASS"
    assert payload["bound_hashes"]


def test_shadow_result_binding_receipt_passes(outputs: Path) -> None:
    payload = _load(outputs / execution.OUTPUTS["shadow_result_binding_receipt"])
    assert payload["binding_status"] == "PASS"
    assert payload["bound_hashes"]["validated_shadow_screen_result_hash"]


def test_candidate_binding_receipt_passes(outputs: Path) -> None:
    payload = _load(outputs / execution.OUTPUTS["candidate_binding_receipt"])
    assert payload["binding_status"] == "PASS"
    assert payload["bound_hashes"]["validated_candidate_hash"]


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    payload = _load(outputs / execution.OUTPUTS["no_authorization_drift_receipt"])
    assert payload["no_downstream_authorization_drift"] is True
    assert payload["limited_runtime_execution_authorized"] is False


def test_execution_validation_plan_points_to_validation_lane(outputs: Path) -> None:
    payload = _load(outputs / execution.OUTPUTS["execution_validation_plan"])
    assert payload["future_lane"] == execution.NEXT_LAWFUL_MOVE
    assert "execution packet is hash-bound" in payload["required_checks"]


def test_execution_validation_reason_codes_exist(outputs: Path) -> None:
    payload = _load(outputs / execution.OUTPUTS["execution_validation_reason_codes"])
    codes = {row["code"] for row in payload["reason_codes"]}
    assert set(execution.REASON_CODES).issubset(codes)


def test_lane_compiler_scaffold_is_prep_only(outputs: Path) -> None:
    scaffold = _scaffold(outputs)
    assert scaffold["scaffold_authority"] == "PREP_ONLY_TOOLING"
    assert scaffold["scaffold"]["authority"] == "PREP_ONLY_TOOLING"
    assert scaffold["scaffold_can_authorize"] is False


def test_lane_compiler_scaffold_records_lane_law(outputs: Path) -> None:
    metadata = _scaffold(outputs)["scaffold"]["lane_law_metadata"]
    assert metadata["lane_kind"] == "AUTHORING"
    assert metadata["selected_outcome"] == execution.SELECTED_OUTCOME
    assert metadata["next_lawful_move"] == execution.NEXT_LAWFUL_MOVE
    assert "LIMITED_RUNTIME_EXECUTED" in metadata["must_not_authorize"]


@pytest.mark.parametrize("role", execution.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / execution.OUTPUTS[role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["limited_runtime_execution_authorized"] is False
    assert payload["r6_open"] is False


def test_operator_runbook_delta_is_prep_only(outputs: Path) -> None:
    text = (outputs / execution.OUTPUTS["operator_runbook_delta_prep_only"]).read_text(encoding="utf-8")
    assert "Authority: PREP_ONLY" in text
    assert "may not grant AFSH runtime authority" in text


def test_customer_status_language_is_prep_only(outputs: Path) -> None:
    text = (outputs / execution.OUTPUTS["customer_safe_status_language_prep_only"]).read_text(encoding="utf-8")
    assert "Authority: PREP_ONLY" in text
    assert "AFSH is live" in text


def test_pipeline_board_marks_current_and_next_lanes(outputs: Path) -> None:
    payload = _load(outputs / execution.OUTPUTS["pipeline_board"])
    board = {row["lane"]: row for row in payload["board"]}
    assert board["AUTHOR_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET"]["status"] == "CURRENT_AUTHORED"
    assert board["VALIDATE_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET"]["status"] == "NEXT"


def test_runtime_corridor_status_blocks_runtime_execution(outputs: Path) -> None:
    payload = _load(outputs / execution.OUTPUTS["runtime_corridor_status"])
    corridor = {row["lane"]: row["status"] for row in payload["corridor"]}
    assert corridor["limited_runtime_execution_packet"] == "BOUND_NOT_VALIDATED"
    assert corridor["limited_runtime_shadow_runtime"] == "NOT_EXECUTED"


def test_future_blocker_register_updated(outputs: Path) -> None:
    payload = _load(outputs / execution.OUTPUTS["future_blocker_register"])
    assert payload["current_authoritative_lane"] == "AUTHOR_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET"
    assert len(payload["blockers"]) >= 4


@pytest.mark.parametrize("check_id", sorted(row["check_id"] for row in execution._validation_rows()))
def test_validation_rows_include_required_checks(outputs: Path, check_id: str) -> None:
    assert check_id in _row_ids(outputs)


def test_execution_self_replay_handoff_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution(tmp_path, monkeypatch)

    execution.run(reports_root=reports)

    nxt = _load(reports / execution.OUTPUTS["next_lawful_move"])
    assert nxt["authoritative_lane"] == execution.AUTHORITATIVE_LANE
    assert nxt["next_lawful_move"] == execution.NEXT_LAWFUL_MOVE


def test_mutated_authorization_scope_live_traffic_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_previous_validation(tmp_path, monkeypatch)
    path = reports / limited_auth.OUTPUTS["scope_manifest"]
    payload = _load(path)
    payload["max_live_traffic_percent_authorized_by_this_packet"] = 1
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_EXECUTION_AUTHORIZED"):
        execution.run(reports_root=reports)


def test_missing_authorized_kill_switch_requirement_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_previous_validation(tmp_path, monkeypatch)
    path = reports / limited_auth.OUTPUTS["kill_switch_contract"]
    payload = _load(path)
    payload["requirements"] = ["kill_switch_required"]
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="AUTHORIZATION_VALIDATION_MISSING"):
        execution.run(reports_root=reports)


def test_mutated_validation_outcome_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_previous_validation(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_VALIDATED__R6_OPEN"
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="AUTHORIZATION_VALIDATION_MISSING"):
        execution.run(reports_root=reports)


def test_runtime_authorization_flag_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_previous_validation(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["runtime_execution_authorized"] = True
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_EXECUTION_AUTHORIZED"):
        execution.run(reports_root=reports)


def test_limited_runtime_executed_flag_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_previous_validation(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["limited_runtime_executed"] = True
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_EXECUTION_AUTHORIZED"):
        execution.run(reports_root=reports)


def test_nested_authorization_state_runtime_cutover_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _run_previous_validation(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload.setdefault("authorization_state", {})["runtime_cutover_authorized"] = True
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="RUNTIME_CUTOVER_AUTHORIZED"):
        execution.run(reports_root=reports)


def test_invalid_self_replay_handoff_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "RUN_B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME"
    _write(path, payload)

    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        execution.run(reports_root=reports)
