from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_expanded_canary_execution_packet as execution
from tools.operator import cohort0_b04_r6_expanded_canary_execution_packet_validation as validation


VALIDATION_HEAD = "dddddddddddddddddddddddddddddddddddddddd"
VALIDATION_MAIN_HEAD = "d6d05dcb414938145ca6050c9d37f9cc275368d5"


def _load_execution_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_expanded_canary_execution_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_expanded_canary_execution_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load expanded canary execution helpers")
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
    dirty: str = "",
) -> None:
    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_execution_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return execution_helpers._run(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_execution_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("expanded_canary_execution_packet_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_validation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / validation.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "validation_contract")


def _receipt(outputs: Path) -> dict:
    return _payload(outputs, "validation_receipt")


def _next(outputs: Path) -> dict:
    return _payload(outputs, "next_lawful_move")


def _json_roles() -> list[str]:
    return sorted(role for role, filename in validation.OUTPUTS.items() if filename.endswith(".json"))


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


def test_validation_binds_expanded_canary_execution_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == execution.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == execution.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == execution.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["packet_contract_hash"]
    assert contract["binding_hashes"]["packet_receipt_hash"]


def test_validation_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME


def test_next_lawful_move_is_expanded_canary_runtime(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert nxt["expanded_canary_runtime_next_lawful_lane"] is True


def test_validation_report_states_runtime_next_but_not_run(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "next lawful lane" in text
    assert "does not execute expanded canary" in text
    assert "does not authorize runtime cutover" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize("role", sorted(validation.EXECUTION_JSON_INPUTS))
def test_validation_binding_hashes_include_each_execution_json_input(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(validation.EXECUTION_TEXT_INPUTS))
def test_validation_binding_hashes_include_each_execution_text_input(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_input_binding_rows_anchor_to_binding_hashes(outputs: Path) -> None:
    contract = _contract(outputs)
    for row in contract["input_bindings"]:
        assert contract["binding_hashes"][f"{row['role']}_hash"] == row["sha256"]


@pytest.mark.parametrize("row_index", range(0, 90))
def test_input_binding_rows_have_hash_shape(outputs: Path, row_index: int) -> None:
    rows = _contract(outputs)["input_bindings"]
    if row_index >= len(rows):
        pytest.skip("fewer input rows than parameterized guard")
    assert len(rows[row_index]["sha256"]) == 64
    assert all(ch in "0123456789abcdef" for ch in rows[row_index]["sha256"])


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["validation_status"] == "PASS"
    assert payload["validated_hashes"]


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_bind_hashes(outputs: Path, role: str) -> None:
    receipt = _payload(outputs, role)
    for value in receipt["validated_hashes"].values():
        assert len(value) == 64
        assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_preserve_lane_identity(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert payload["selected_outcome"] == validation.SELECTED_OUTCOME
    assert payload["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("expanded_canary_execution_packet_validated", True),
        ("expanded_canary_runtime_next_lawful_lane", True),
        ("expanded_canary_runtime_authorized", False),
        ("expanded_canary_runtime_executed", False),
        ("runtime_cutover_authorized", False),
        ("activation_cutover_executed", False),
        ("r6_open", False),
        ("global_runtime_surface_authorized", False),
        ("lobe_escalation_authorized", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("trust_zone_law_changed", False),
        ("metric_contract_mutated", False),
        ("static_comparator_weakened", False),
    ],
)
def test_all_json_outputs_preserve_authority_state(outputs: Path, role: str, field: str, expected: object) -> None:
    assert _payload(outputs, role)[field] == expected


@pytest.mark.parametrize("role", execution.CONTRACT_ROLES)
def test_authoring_contracts_stay_bound_non_executing(outputs: Path, role: str) -> None:
    payload = _load(outputs / execution.OUTPUTS[role])
    assert payload["contract_status"] == "BOUND_NON_EXECUTING"
    assert payload["expanded_canary_execution_packet_validated"] is False
    assert payload["expanded_canary_runtime_authorized"] is False
    assert payload["expanded_canary_runtime_executed"] is False
    assert payload["runtime_cutover_authorized"] is False


@pytest.mark.parametrize(
    "role,detail_key,expected",
    [
        ("execution_mode_contract", "execution_mode_defined", True),
        ("execution_mode_contract", "runtime_may_run_before_validation", False),
        ("execution_mode_contract", "runtime_may_run_after_validation_only", True),
        ("execution_scope_manifest", "global_r6_scope_allowed", False),
        ("execution_scope_manifest", "runtime_cutover_allowed", False),
        ("execution_scope_manifest", "commercial_surface_allowed", False),
        ("execution_scope_manifest", "max_case_count_per_window", 36),
        ("sample_limit_contract", "sample_limit_drift_fails_closed", True),
        ("sample_limit_contract", "max_cases", 36),
        ("sample_limit_contract", "max_route_observations", 24),
        ("expansion_delta_contract", "expansion_delta_defined", True),
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
def test_authoring_required_details_validate(outputs: Path, role: str, detail_key: str, expected: object) -> None:
    assert _load(outputs / execution.OUTPUTS[role])["details"][detail_key] == expected


def test_allowed_case_classes_match_expected_bounded_set(outputs: Path) -> None:
    allowed = _load(outputs / execution.OUTPUTS["allowed_case_class_contract"])["details"]["allowed_case_classes"]
    assert tuple(allowed) == execution.EXPECTED_ALLOWED_CASE_CLASSES


def test_excluded_case_classes_block_global_cutover_and_commercial(outputs: Path) -> None:
    excluded = set(_load(outputs / execution.OUTPUTS["excluded_case_class_contract"])["details"]["excluded_case_classes"])
    assert set(execution.EXPECTED_EXCLUDED_CASE_CLASSES).issubset(excluded)
    assert {"GLOBAL_R6_TRAFFIC", "RUNTIME_CUTOVER_SURFACE", "COMMERCIAL_ACTIVATION_SURFACE"}.issubset(excluded)


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _payload(outputs, "no_authorization_drift_validation")
    assert receipt["no_authorization_drift"] is True
    assert receipt["expanded_canary_runtime_authorized"] is False
    assert receipt["expanded_canary_runtime_executed"] is False
    assert receipt["runtime_cutover_authorized"] is False
    assert receipt["r6_open"] is False


@pytest.mark.parametrize("role", execution.PREP_ONLY_ROLES)
def test_execution_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / execution.OUTPUTS[role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_execute_expanded_canary"] is True
    assert payload["cannot_authorize_runtime_cutover"] is True
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


@pytest.mark.parametrize("code", validation.AUTHORITY_DRIFT_KEYS.values())
def test_all_authority_drift_reason_codes_are_published(code: str) -> None:
    assert code in validation.REASON_CODES


def test_forbidden_actions_include_runtime_authorized_boundary() -> None:
    assert "EXPANDED_CANARY_RUNTIME_AUTHORIZED" in validation.FORBIDDEN_ACTIONS


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, dirty=" M changed.json")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(RuntimeError, match="must run on one of"):
        validation.run(reports_root=reports)


def test_packet_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "DRIFT"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PACKET_OUTCOME_DRIFT"):
        validation.run(reports_root=reports)


def test_packet_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "DRIFT"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_input_hash_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.INPUTS["expanded_canary_readiness_matrix"]
    payload = _load(path)
    payload["test_mutation"] = "drift"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="INPUT_HASH_DRIFT"):
        validation.run(reports_root=reports)


def test_runtime_authorized_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["expanded_canary_runtime_authorized"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="RUNTIME_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_sample_limit_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["sample_limit_contract"]
    payload = _load(path)
    payload["details"]["max_cases"] = 37
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="SAMPLE_LIMIT_MISSING"):
        validation.run(reports_root=reports)


def test_allowed_case_class_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["allowed_case_class_contract"]
    payload = _load(path)
    payload["details"]["allowed_case_classes"] = ["GLOBAL_R6_TRAFFIC"]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="ALLOWED_CASE_CLASSES_DRIFT"):
        validation.run(reports_root=reports)


def test_prep_only_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["expanded_canary_run_result_schema_prep_only"]
    payload = _load(path)
    payload["authority"] = "AUTHORITATIVE"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PREP_ONLY_DRIFT"):
        validation.run(reports_root=reports)


def test_missing_safety_reason_code_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["kill_switch_contract"]
    payload = _load(path)
    payload["details"]["reason_code"] = ""
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PREP_ONLY_DRIFT"):
        validation.run(reports_root=reports)
