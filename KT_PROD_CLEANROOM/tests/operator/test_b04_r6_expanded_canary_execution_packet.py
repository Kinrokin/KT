from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_expanded_canary_execution_packet as execution
from tools.operator.titanium_common import file_sha256


EXECUTION_HEAD = "cccccccccccccccccccccccccccccccccccccccc"
EXECUTION_MAIN_HEAD = "fff1ba5975ab7d96be7c3eaf2be04442edd48b5a"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_expanded_canary_authorization_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_expanded_canary_authorization_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load expanded canary authorization validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed_missing_campaign_inputs(reports: Path) -> None:
    for role, filename in execution.INPUTS.items():
        path = reports / filename
        if path.exists():
            continue
        _write(
            path,
            {
                "schema_id": f"test.seed.{role}.v1",
                "artifact_id": role.upper(),
                "selected_outcome": "SEE_PREVIOUS_BOUND_INPUT",
                "next_lawful_move": "SEE_PREVIOUS_BOUND_INPUT",
                "expanded_canary_runtime_authorized": False,
                "expanded_canary_runtime_executed": False,
                "runtime_cutover_authorized": False,
                "activation_cutover_executed": False,
                "r6_open": False,
                "global_runtime_surface_authorized": False,
                "lobe_escalation_authorized": False,
                "package_promotion": "DEFERRED",
                "package_promotion_authorized": False,
                "commercial_activation_claim_authorized": False,
                "commercial_claim_status": "BOUNDARY_ONLY",
                "truth_engine_law_changed": False,
                "trust_zone_law_changed": False,
                "metric_contract_mutated": False,
                "static_comparator_weakened": False,
            },
        )


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
    monkeypatch.setattr(execution.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)


def _run_previous_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = validation_helpers._run_validation(tmp_path, monkeypatch)
    _seed_missing_campaign_inputs(reports)
    return reports


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_previous_authority(tmp_path, monkeypatch)
    _patch_execution_env(monkeypatch, tmp_path)
    execution.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("expanded_canary_execution_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / execution.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "packet_contract")


def _receipt(outputs: Path) -> dict:
    return _payload(outputs, "packet_receipt")


@pytest.mark.parametrize("filename", sorted(execution.OUTPUTS.values()))
def test_required_expanded_canary_execution_packet_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_execution_packet_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == execution.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == execution.SELECTED_OUTCOME


def test_execution_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == EXECUTION_MAIN_HEAD


def test_execution_packet_binds_authorization_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == execution.PREVIOUS_LANE
    assert contract["predecessor_outcome"] == execution.EXPECTED_PREVIOUS_OUTCOME
    assert contract["previous_next_lawful_move"] == execution.EXPECTED_PREVIOUS_NEXT_MOVE
    assert contract["binding_hashes"]["expanded_canary_authorization_validation_receipt_hash"]
    assert contract["binding_hashes"]["expanded_canary_authorization_packet_hash"]


def test_execution_packet_routes_to_validation(outputs: Path) -> None:
    nxt = _payload(outputs, "next_lawful_move")
    assert nxt["selected_outcome"] == execution.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == execution.NEXT_LAWFUL_MOVE
    assert nxt["validation_success_next_lawful_move"] == execution.VALIDATION_SUCCESS_NEXT_MOVE


def test_execution_packet_report_states_non_execution(outputs: Path) -> None:
    text = (outputs / execution.OUTPUTS["packet_report"]).read_text(encoding="utf-8").lower()
    assert "does not execute expanded canary" in text
    assert "does not authorize expanded canary runtime" in text
    assert "does not authorize runtime cutover" in text
    assert "does not open r6" in text


@pytest.mark.parametrize("role, filename", sorted(execution.INPUTS.items()))
def test_execution_packet_binds_each_input_hash(outputs: Path, role: str, filename: str) -> None:
    expected = file_sha256(outputs / filename)
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"] == expected


@pytest.mark.parametrize("role", execution.CONTRACT_ROLES)
def test_execution_contract_roles_are_bound_non_executing(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["contract_status"] == "BOUND_NON_EXECUTING"
    assert payload["expanded_canary_execution_packet_authored"] is True
    assert payload["expanded_canary_execution_packet_validated"] is False
    assert payload["expanded_canary_runtime_authorized"] is False
    assert payload["expanded_canary_runtime_executed"] is False


@pytest.mark.parametrize(
    "role, detail_key, expected",
    [
        ("execution_mode_contract", "execution_mode_defined", True),
        ("execution_mode_contract", "runtime_may_run_before_validation", False),
        ("execution_mode_contract", "runtime_may_run_after_validation_only", True),
        ("execution_scope_manifest", "scope_status", "EXPANDED_CANARY_EXECUTION_SCOPE_DEFINED_NOT_VALIDATED"),
        ("execution_scope_manifest", "global_r6_scope_allowed", False),
        ("execution_scope_manifest", "runtime_cutover_allowed", False),
        ("execution_scope_manifest", "commercial_surface_allowed", False),
        ("execution_scope_manifest", "max_case_count_per_window", 36),
        ("sample_limit_contract", "sample_limit_defined", True),
        ("sample_limit_contract", "sample_limit_drift_fails_closed", True),
        ("sample_limit_contract", "max_cases", 36),
        ("sample_limit_contract", "max_route_observations", 24),
        ("expansion_delta_contract", "expansion_delta_defined", True),
        ("expansion_delta_contract", "prior_canary_max_cases", 12),
        ("expansion_delta_contract", "expanded_canary_max_cases", 36),
        ("static_fallback_contract", "static_fallback_required", True),
        ("abstention_fallback_contract", "abstention_fallback_required", True),
        ("null_route_preservation_contract", "null_route_preservation_required", True),
        ("operator_override_contract", "operator_override_required", True),
        ("kill_switch_contract", "kill_switch_required", True),
        ("rollback_contract", "rollback_required", True),
        ("route_distribution_thresholds", "route_distribution_thresholds_defined", True),
        ("drift_thresholds", "drift_thresholds_defined", True),
        ("incident_freeze_contract", "incident_freeze_conditions_defined", True),
        ("runtime_receipt_schema", "runtime_receipt_schema_defined", True),
        ("replay_manifest", "runtime_replay_manifest_defined", True),
        ("expected_artifact_manifest", "expected_artifact_manifest_defined", True),
        ("external_verifier_requirements", "external_verifier_required", True),
        ("result_interpretation_contract", "result_interpretation_contract_defined", True),
        ("result_interpretation_contract", "canary_pass_does_not_authorize_cutover", True),
        ("result_interpretation_contract", "canary_pass_does_not_open_r6", True),
        ("result_interpretation_contract", "canary_pass_does_not_promote_package", True),
    ],
)
def test_execution_packet_required_details(outputs: Path, role: str, detail_key: str, expected: object) -> None:
    assert _payload(outputs, role)["details"][detail_key] == expected


def test_allowed_case_classes_match_expected_bounded_set(outputs: Path) -> None:
    allowed = _payload(outputs, "allowed_case_class_contract")["details"]["allowed_case_classes"]
    assert tuple(allowed) == execution.EXPECTED_ALLOWED_CASE_CLASSES


def test_excluded_case_classes_reject_global_cutover_and_commercial_surfaces(outputs: Path) -> None:
    excluded = set(_payload(outputs, "excluded_case_class_contract")["details"]["excluded_case_classes"])
    assert set(execution.EXPECTED_EXCLUDED_CASE_CLASSES).issubset(excluded)
    assert "GLOBAL_R6_TRAFFIC" in excluded
    assert "RUNTIME_CUTOVER_SURFACE" in excluded
    assert "COMMERCIAL_ACTIVATION_SURFACE" in excluded
    assert "PACKAGE_PROMOTION_SURFACE" in excluded


@pytest.mark.parametrize(
    "role",
    ["packet_contract", "packet_receipt", "no_authorization_drift_receipt", "next_lawful_move"],
)
@pytest.mark.parametrize(
    "flag",
    [
        "expanded_canary_execution_packet_validated",
        "expanded_canary_runtime_authorized",
        "expanded_canary_runtime_executed",
        "runtime_cutover_authorized",
        "activation_cutover_executed",
        "r6_open",
        "global_runtime_surface_authorized",
        "lobe_escalation_authorized",
        "package_promotion_authorized",
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
        "metric_contract_mutated",
        "static_comparator_weakened",
    ],
)
def test_execution_packet_does_not_authorize_forbidden_boundaries(outputs: Path, role: str, flag: str) -> None:
    assert _payload(outputs, role)[flag] is False


@pytest.mark.parametrize("role", execution.PREP_ONLY_ROLES)
def test_downstream_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_execute_expanded_canary"] is True
    assert payload["cannot_authorize_runtime_cutover"] is True
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["expanded_canary_runtime_authorized"] is False


@pytest.mark.parametrize("code", execution.REASON_CODES)
def test_validation_reason_codes_are_scaffolded(outputs: Path, code: str) -> None:
    assert code in _payload(outputs, "validation_reason_codes")["reason_codes"]
    assert code in _payload(outputs, "validation_plan")["checks"]


def test_all_authority_drift_reason_codes_are_published(outputs: Path) -> None:
    published = set(_payload(outputs, "validation_reason_codes")["reason_codes"])
    assert set(execution.AUTHORITY_DRIFT_KEYS.values()).issubset(published)


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _payload(outputs, "no_authorization_drift_receipt")
    assert receipt["no_authorization_drift"] is True
    assert receipt["expanded_canary_runtime_authorized"] is False
    assert receipt["runtime_cutover_authorized"] is False


def test_result_interpretation_routes_success_to_evidence_review(outputs: Path) -> None:
    details = _payload(outputs, "result_interpretation_contract")["details"]
    assert details["success_routes_to"] == "AUTHOR_B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET"
    assert "B04_R6_EXPANDED_CANARY_RUNTIME_PASSED__EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET_NEXT" in details["allowed_runtime_outcomes"]


def test_invalid_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_previous_authority(tmp_path, monkeypatch)
    _patch_execution_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(RuntimeError, match="must run on one of"):
        execution.run(reports_root=reports)


def test_authorization_validation_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_previous_authority(tmp_path, monkeypatch)
    path = reports / execution.INPUTS["expanded_canary_authorization_validation_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "DRIFTED"
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="AUTHORIZATION_OUTCOME_DRIFT"):
        execution.run(reports_root=reports)


def test_authorization_validation_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_previous_authority(tmp_path, monkeypatch)
    path = reports / execution.INPUTS["expanded_canary_authorization_next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "RUN_B04_R6_EXPANDED_CANARY_RUNTIME"
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        execution.run(reports_root=reports)


def test_sample_limit_scope_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_previous_authority(tmp_path, monkeypatch)
    path = reports / execution.INPUTS["expanded_canary_authorization_scope_manifest"]
    payload = _load(path)
    payload["details"]["max_case_count_per_window"] = 3600
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="SAMPLE_LIMIT_DRIFT"):
        execution.run(reports_root=reports)


def test_sample_limit_contract_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_previous_authority(tmp_path, monkeypatch)
    path = reports / execution.INPUTS["expanded_canary_authorization_sample_limit"]
    payload = _load(path)
    payload["details"]["max_cases"] = 3600
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="SAMPLE_LIMIT_DRIFT"):
        execution.run(reports_root=reports)


@pytest.mark.parametrize(
    "allowed_case_classes",
    [
        ["GLOBAL_R6_TRAFFIC"],
        ["ROUTE_ELIGIBLE_LOW_RISK_CANARY_CONFIRMED"],
        [
            "ROUTE_ELIGIBLE_LOW_RISK_CANARY_CONFIRMED",
            "STATIC_FALLBACK_AVAILABLE_EXPANDED_ROUTE_CHECK",
            "NON_COMMERCIAL_OPERATOR_OBSERVED_EXPANDED_SAMPLE",
            "PRIOR_CANARY_COVERED_CASE_CLASS_EXTENSION",
            "RUNTIME_CUTOVER_SURFACE",
        ],
    ],
)
def test_allowed_case_class_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, allowed_case_classes: list[str]
) -> None:
    reports = _run_previous_authority(tmp_path, monkeypatch)
    path = reports / execution.INPUTS["expanded_canary_authorization_allowed_case_classes"]
    payload = _load(path)
    payload["details"]["allowed_case_classes"] = allowed_case_classes
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="ALLOWED_CASE_CLASSES_DRIFT"):
        execution.run(reports_root=reports)


@pytest.mark.parametrize(
    "missing_case, expected_reason",
    [
        ("GLOBAL_R6_TRAFFIC", "EXCLUDED_CASE_CLASSES_DRIFT"),
        ("RUNTIME_CUTOVER_SURFACE", "EXCLUDED_CASE_CLASSES_DRIFT"),
        ("COMMERCIAL_ACTIVATION_SURFACE", "EXCLUDED_CASE_CLASSES_DRIFT"),
    ],
)
def test_required_excluded_case_class_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing_case: str, expected_reason: str
) -> None:
    reports = _run_previous_authority(tmp_path, monkeypatch)
    path = reports / execution.INPUTS["expanded_canary_authorization_excluded_case_classes"]
    payload = _load(path)
    payload["details"]["excluded_case_classes"] = [
        item for item in payload["details"]["excluded_case_classes"] if item != missing_case
    ]
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match=expected_reason):
        execution.run(reports_root=reports)


@pytest.mark.parametrize(
    "role, detail_key, expected_reason",
    [
        ("expanded_canary_authorization_static_fallback", "static_fallback_required", "FALLBACK_MISSING"),
        ("expanded_canary_authorization_abstention_fallback", "abstention_fallback_required", "FALLBACK_MISSING"),
        ("expanded_canary_authorization_null_route", "null_route_preservation_required", "FALLBACK_MISSING"),
        ("expanded_canary_authorization_operator_override", "operator_override_required", "OPERATOR_CONTROL_MISSING"),
        ("expanded_canary_authorization_kill_switch", "kill_switch_required", "KILL_SWITCH_MISSING"),
        ("expanded_canary_authorization_rollback", "rollback_required", "ROLLBACK_MISSING"),
    ],
)
def test_required_safety_control_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str, detail_key: str, expected_reason: str
) -> None:
    reports = _run_previous_authority(tmp_path, monkeypatch)
    path = reports / execution.INPUTS[role]
    payload = _load(path)
    payload["details"][detail_key] = False
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match=expected_reason):
        execution.run(reports_root=reports)


@pytest.mark.parametrize("field", sorted(execution.AUTHORITY_DRIFT_KEYS))
@pytest.mark.parametrize("drift_value", [True, "AUTHORIZED", 1])
def test_any_non_false_authority_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, drift_value: object
) -> None:
    reports = _run_previous_authority(tmp_path, monkeypatch)
    path = reports / execution.INPUTS["expanded_canary_authorization_validation_receipt"]
    payload = _load(path)
    payload[field] = drift_value
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        execution.run(reports_root=reports)


@pytest.mark.parametrize(
    "field, value, expected_reason",
    [
        ("package_promotion", "AUTHORIZED", "PACKAGE_PROMOTION_DRIFT"),
        ("commercial_claim_status", "AUTHORIZED", "COMMERCIAL_CLAIM_DRIFT"),
    ],
)
def test_claim_text_authority_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: str, expected_reason: str
) -> None:
    reports = _run_previous_authority(tmp_path, monkeypatch)
    path = reports / execution.INPUTS["expanded_canary_authorization_validation_receipt"]
    payload = _load(path)
    payload[field] = value
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match=expected_reason):
        execution.run(reports_root=reports)
