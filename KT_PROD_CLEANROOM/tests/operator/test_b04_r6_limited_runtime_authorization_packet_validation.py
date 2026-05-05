from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_limited_runtime_authorization_packet as limited
from tools.operator import cohort0_b04_r6_limited_runtime_authorization_packet_validation as validation


VALIDATION_HEAD = "9999999999999999999999999999999999999999"
VALIDATION_MAIN_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _load_limited_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_limited_runtime_authorization_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_limited_runtime_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load limited-runtime helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


limited_helpers = _load_limited_helpers()


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


def _run_packet_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return limited_helpers._run_limited(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_packet_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("limited_runtime_validation")
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
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["artifact_id"]
        assert payload["schema_id"]


def test_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_authoritative_lane(outputs: Path) -> None:
    assert _contract(outputs)["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert _contract(outputs)["previous_authoritative_lane"] == limited.AUTHORITATIVE_LANE


def test_validation_binds_limited_runtime_authorization_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["predecessor_outcome"] == limited.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == limited.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["packet_contract_hash"]


def test_validation_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME


def test_next_lawful_move_is_limited_runtime_execution_packet(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_self_replay_handoff_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation(tmp_path, monkeypatch)

    validation.run(reports_root=reports)

    nxt = _load(reports / validation.OUTPUTS["next_lawful_move"])
    assert nxt["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert nxt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_report_states_non_execution(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "does not authorize limited-runtime execution" in text
    assert "r6 opening" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize(
    "flag",
    [
        "r6_open",
        "limited_runtime_authorized",
        "limited_runtime_execution_authorized",
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


def test_validation_marks_packet_validated_but_not_runtime_authorized(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["limited_runtime_authorization_packet_validated"] is True
    assert contract["limited_runtime_authorized"] is False
    assert contract["runtime_execution_authorized"] is False


@pytest.mark.parametrize(
    "key",
    [
        "packet_contract_hash",
        "packet_receipt_hash",
        "packet_report_hash",
        "activation_review_validation_binding_receipt_hash",
        "shadow_result_binding_receipt_hash",
        "candidate_binding_receipt_hash",
        "scope_manifest_hash",
        "static_fallback_contract_hash",
        "abstention_fallback_contract_hash",
        "null_route_preservation_contract_hash",
        "operator_override_contract_hash",
        "kill_switch_contract_hash",
        "rollback_plan_hash",
        "route_distribution_health_contract_hash",
        "drift_monitoring_contract_hash",
        "runtime_receipt_schema_hash",
        "incident_freeze_contract_hash",
        "external_verifier_requirements_hash",
        "commercial_claim_boundary_hash",
        "no_authorization_drift_receipt_hash",
        "activation_review_validation_contract_hash",
        "activation_review_validation_receipt_hash",
        "activation_review_validation_report_hash",
        "shadow_screen_result_hash",
        "shadow_screen_execution_receipt_hash",
        "candidate_hash",
        "candidate_manifest_hash",
        "candidate_semantic_hash",
        "static_comparator_contract_hash",
        "metric_contract_hash",
        "trace_completeness_receipt_hash",
        "trust_zone_validation_receipt_hash",
    ],
)
def test_validation_binds_required_hashes(outputs: Path, key: str) -> None:
    value = _contract(outputs)["binding_hashes"][key]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", validation.CONTROL_VALIDATION_ROLES)
def test_control_validation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _load(outputs / validation.OUTPUTS[role])
    assert payload["validation_status"] == "PASS"
    assert payload["validated_hashes"]


@pytest.mark.parametrize(
    "role,source_role",
    [
        ("scope_validation", "scope_manifest"),
        ("static_fallback_validation", "static_fallback_contract"),
        ("abstention_fallback_validation", "abstention_fallback_contract"),
        ("null_route_preservation_validation", "null_route_preservation_contract"),
        ("operator_override_validation", "operator_override_contract"),
        ("kill_switch_validation", "kill_switch_contract"),
        ("rollback_plan_validation", "rollback_plan"),
        ("route_distribution_health_validation", "route_distribution_health_contract"),
        ("drift_monitoring_validation", "drift_monitoring_contract"),
        ("runtime_receipt_schema_validation", "runtime_receipt_schema"),
        ("incident_freeze_validation", "incident_freeze_contract"),
        ("external_verifier_validation", "external_verifier_requirements"),
        ("commercial_claim_boundary_validation", "commercial_claim_boundary"),
        ("package_promotion_boundary_validation", "commercial_claim_boundary"),
    ],
)
def test_validation_receipts_bind_source_hashes(outputs: Path, role: str, source_role: str) -> None:
    payload = _load(outputs / validation.OUTPUTS[role])
    assert payload["validated_hashes"][f"{source_role}_hash"] == _contract(outputs)["binding_hashes"][f"{source_role}_hash"]


def test_limited_runtime_scope_is_defined(outputs: Path) -> None:
    scope = _load(outputs / limited.OUTPUTS["scope_manifest"])
    assert scope["limited_scope_required"] is True


def test_limited_runtime_scope_is_not_global_r6(outputs: Path) -> None:
    scope_text = json.dumps(_load(outputs / limited.OUTPUTS["scope_manifest"]), sort_keys=True).lower()
    assert "global_r6" not in scope_text
    assert _contract(outputs)["r6_open"] is False


def test_limited_runtime_scope_is_canary_or_shadow_runtime_only(outputs: Path) -> None:
    scope = _load(outputs / limited.OUTPUTS["scope_manifest"])
    assert scope["allowed_future_modes_after_validation"] == ["CANARY_ONLY", "SHADOW_RUNTIME_ONLY"]
    assert scope["max_live_traffic_percent_authorized_by_this_packet"] == 0


@pytest.mark.parametrize(
    "role,requirements",
    [
        ("static_fallback_contract", ["static_comparator_remains_available", "static_hold_default_preserved"]),
        ("abstention_fallback_contract", ["boundary_uncertainty_abstains", "trust_zone_uncertainty_abstains"]),
        ("null_route_preservation_contract", ["null_route_controls_do_not_enter_selector", "surface_temptations_remain_blocked"]),
        ("operator_override_contract", ["operator_override_required", "override_may_force_static_fallback"]),
        ("kill_switch_contract", ["kill_switch_required", "kill_switch_returns_to_static_comparator"]),
        ("rollback_plan", ["rollback_to_static_comparator_required", "rollback_execution_receipt_required"]),
        ("route_distribution_health_contract", ["selector_entry_rate_monitored", "overrouting_alarm_required"]),
        ("drift_monitoring_contract", ["metric_drift_freezes_runtime", "trust_zone_drift_freezes_runtime"]),
        ("external_verifier_requirements", ["external_verifier_non_executing", "raw_hash_bound_artifacts_required"]),
        ("commercial_claim_boundary", ["commercial_activation_claims_unauthorized", "package_promotion_prohibited"]),
    ],
)
def test_required_control_requirements_exist(outputs: Path, role: str, requirements: list[str]) -> None:
    payload = _load(outputs / limited.OUTPUTS[role])
    assert set(requirements).issubset(set(payload["requirements"]))


@pytest.mark.parametrize("role", limited.CONTROL_OUTPUT_ROLES)
def test_packet_controls_remain_non_authorizing(outputs: Path, role: str) -> None:
    payload = _load(outputs / limited.OUTPUTS[role])
    assert payload["can_authorize_limited_runtime"] is False
    assert payload["can_execute_runtime"] is False
    assert payload["can_open_r6"] is False
    assert payload["can_promote_package"] is False


@pytest.mark.parametrize("field", limited.RUNTIME_RECEIPT_FIELDS)
def test_runtime_receipt_schema_contains_required_fields(outputs: Path, field: str) -> None:
    receipt = _load(outputs / validation.OUTPUTS["runtime_receipt_schema_validation"])
    assert field in receipt["required_fields"]
    assert f"runtime_receipt_schema_requires_{field}" in _row_ids(outputs)


@pytest.mark.parametrize("condition", limited.INCIDENT_FREEZE_CONDITIONS)
def test_incident_freeze_conditions_exist(outputs: Path, condition: str) -> None:
    receipt = _load(outputs / validation.OUTPUTS["incident_freeze_validation"])
    assert condition in receipt["freeze_conditions"]
    assert f"incident_freeze_on_{condition}" in _row_ids(outputs)


def test_external_verifier_requirements_are_non_executing(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["external_verifier_validation"])
    assert receipt["external_verifier_non_executing"] is True


def test_commercial_activation_claims_remain_unauthorized(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["commercial_claim_boundary_validation"])
    assert receipt["commercial_activation_claims_authorized"] is False


def test_package_promotion_not_automatic(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["package_promotion_boundary_validation"])
    assert receipt["package_promotion_automatic"] is False
    assert receipt["package_promotion_authorized"] is False


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["no_authorization_drift_validation"])
    assert receipt["no_downstream_authorization_drift"] is True
    assert receipt["limited_runtime_execution_authorized"] is False


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
    assert "LIMITED_RUNTIME_EXECUTION_AUTHORIZED" in metadata["must_not_authorize"]


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_drafts_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / validation.OUTPUTS[role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["limited_runtime_execution_authorized"] is False
    assert payload["r6_open"] is False


def test_future_blocker_register_updated(outputs: Path) -> None:
    payload = _load(outputs / validation.OUTPUTS["future_blocker_register"])
    assert payload["current_authoritative_lane"] == "VALIDATE_B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET"
    assert len(payload["blockers"]) >= 3


@pytest.mark.parametrize("check_id", sorted(row["check_id"] for row in validation._validation_rows()))
def test_validation_rows_include_required_checks(outputs: Path, check_id: str) -> None:
    assert check_id in _row_ids(outputs)


def test_mutated_scope_live_traffic_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    scope_path = reports / limited.OUTPUTS["scope_manifest"]
    scope = _load(scope_path)
    scope["max_live_traffic_percent_authorized_by_this_packet"] = 1
    _write(scope_path, scope)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_missing_kill_switch_requirement_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / limited.OUTPUTS["kill_switch_contract"]
    payload = _load(path)
    payload["requirements"] = ["kill_switch_required"]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_VAL_KILL_SWITCH_MISSING"):
        validation.run(reports_root=reports)


def test_runtime_authorization_flag_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / limited.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["runtime_execution_authorized"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_prep_only_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / limited.OUTPUTS["runtime_evidence_packet_prep_only"]
    payload = _load(path)
    payload["authority"] = "AUTHORITATIVE"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_VAL_PREP_ONLY_AUTHORITY_DRIFT"):
        validation.run(reports_root=reports)


def test_invalid_self_replay_handoff_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_VALIDATED__R6_OPEN"
    _write(path, payload)

    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)
