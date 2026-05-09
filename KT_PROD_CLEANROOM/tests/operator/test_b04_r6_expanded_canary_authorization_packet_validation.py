from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_expanded_canary_authorization_packet as expanded
from tools.operator import cohort0_b04_r6_expanded_canary_authorization_packet_validation as validation
from tools.operator.titanium_common import file_sha256


VALIDATION_HEAD = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
VALIDATION_MAIN_HEAD = "663db20fd0bd5fd803e1d36356911f9e50778dcb"


def _load_expanded_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_expanded_canary_authorization_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_expanded_canary_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load expanded canary authorization helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


expanded_helpers = _load_expanded_helpers()


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


def _run_authoring_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return expanded_helpers._run(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("expanded_canary_authorization_validation")
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


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_expanded_canary_authorization_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME


def test_validation_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_expanded_canary_authorization_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == expanded.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == expanded.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == expanded.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["packet_contract_hash"]
    assert contract["binding_hashes"]["packet_receipt_hash"]


def test_next_lawful_move_is_expanded_canary_execution_packet_authoring(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_report_states_non_execution(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "does not execute expanded canary" in text
    assert "does not authorize expanded canary runtime" in text
    assert "does not authorize runtime cutover" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize("role", sorted(validation.EXPANDED_JSON_INPUTS))
def test_validation_binding_hashes_include_each_expanded_canary_json_input(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(validation.EXPANDED_TEXT_INPUTS))
def test_validation_binding_hashes_include_each_expanded_canary_text_input(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role, raw", sorted(validation.EXPANDED_JSON_INPUTS.items()))
def test_validation_binding_hashes_match_on_disk_expanded_canary_json_inputs(outputs: Path, role: str, raw: str) -> None:
    expected = file_sha256(outputs.parent.parent / raw)
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"] == expected


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["validation_status"] == "PASS"
    assert len(payload["validated_hash"]) == 64


@pytest.mark.parametrize(
    "payload_role",
    [
        "validation_contract",
        "validation_receipt",
        "no_authorization_drift_validation",
        "next_lawful_move",
    ],
)
@pytest.mark.parametrize(
    "flag",
    [
        "expanded_canary_runtime_authorized",
        "expanded_canary_runtime_executed",
        "runtime_cutover_authorized",
        "activation_cutover_executed",
        "r6_open",
        "lobe_escalation_authorized",
        "package_promotion_authorized",
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
        "metric_contract_mutated",
        "static_comparator_weakened",
    ],
)
def test_validation_does_not_authorize_forbidden_boundaries(outputs: Path, payload_role: str, flag: str) -> None:
    assert _payload(outputs, payload_role)[flag] is False


def test_validation_marks_packet_validated_but_execution_not_authored(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["expanded_canary_authorization_packet_authored"] is True
    assert contract["expanded_canary_authorization_packet_validated"] is True
    assert contract["expanded_canary_execution_packet_authored"] is False
    assert contract["expanded_canary_execution_packet_validated"] is False
    assert contract["expanded_canary_runtime_authorized"] is False
    assert contract["expanded_canary_runtime_executed"] is False


@pytest.mark.parametrize("role", expanded.CONTRACT_ROLES)
def test_authoring_operational_contracts_stay_bound_non_executing(outputs: Path, role: str) -> None:
    payload = _load(outputs / expanded.OUTPUTS[role])
    assert payload["contract_status"] == "BOUND_NON_EXECUTING"
    assert payload["expanded_canary_runtime_authorized"] is False
    assert payload["expanded_canary_runtime_executed"] is False
    assert payload["runtime_cutover_authorized"] is False


@pytest.mark.parametrize(
    "role, detail_key, expected",
    [
        ("scope_manifest", "scope_status", "EXPANDED_CANARY_SCOPE_DEFINED_NOT_EXECUTING"),
        ("scope_manifest", "global_r6_scope_allowed", False),
        ("scope_manifest", "runtime_cutover_allowed", False),
        ("scope_manifest", "max_case_count_per_window", 36),
        ("sample_limit_contract", "max_cases", 36),
        ("static_fallback_contract", "static_fallback_required", True),
        ("abstention_fallback_contract", "abstention_fallback_required", True),
        ("null_route_preservation_contract", "null_route_preservation_required", True),
        ("operator_override_contract", "operator_override_required", True),
        ("kill_switch_contract", "kill_switch_required", True),
        ("rollback_contract", "rollback_required", True),
        ("route_distribution_health_thresholds", "route_distribution_thresholds_defined", True),
        ("drift_thresholds", "drift_thresholds_defined", True),
        ("incident_freeze_contract", "incident_freeze_conditions_defined", True),
        ("runtime_receipt_schema", "runtime_receipt_schema_defined", True),
        ("external_verifier_requirements", "external_verifier_required", True),
        ("commercial_claim_boundary", "commercial_claim_status", "BOUNDARY_ONLY"),
        ("package_promotion_prohibition_receipt", "package_promotion_authorized", False),
    ],
)
def test_expanded_canary_authorization_required_details_validate(
    outputs: Path, role: str, detail_key: str, expected: object
) -> None:
    assert _load(outputs / expanded.OUTPUTS[role])["details"][detail_key] == expected


def test_allowed_and_excluded_case_classes_remain_bounded(outputs: Path) -> None:
    allowed = _load(outputs / expanded.OUTPUTS["allowed_case_class_contract"])["details"]["allowed_case_classes"]
    excluded = _load(outputs / expanded.OUTPUTS["excluded_case_class_contract"])["details"]["excluded_case_classes"]
    assert "PRIOR_CANARY_COVERED_CASE_CLASS_EXTENSION" in allowed
    assert "GLOBAL_R6_TRAFFIC" in excluded
    assert "RUNTIME_CUTOVER_SURFACE" in excluded
    assert "COMMERCIAL_ACTIVATION_SURFACE" in excluded


@pytest.mark.parametrize("role", expanded.PREP_ONLY_ROLES)
def test_authoring_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / expanded.OUTPUTS[role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_expanded_canary_execution"] is True
    assert payload["expanded_canary_runtime_authorized"] is False


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["can_authorize"] is False
    assert payload["cannot_authorize_expanded_canary_execution"] is True
    assert payload["expanded_canary_runtime_authorized"] is False


@pytest.mark.parametrize("code", validation.REASON_CODES)
def test_validation_reason_codes_are_recorded(outputs: Path, code: str) -> None:
    assert code in _contract(outputs)["reason_codes"]


@pytest.mark.parametrize("defect", validation.TERMINAL_DEFECTS)
def test_validation_terminal_defects_are_recorded(outputs: Path, defect: str) -> None:
    assert defect in _contract(outputs)["terminal_defects"]


@pytest.mark.parametrize("row", range(1, 34))
def test_validation_rows_are_pass(outputs: Path, row: int) -> None:
    rows = {index: item for index, item in enumerate(_contract(outputs)["validation_rows"], start=1)}
    assert rows[row]["status"] == "PASS"


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _payload(outputs, "no_authorization_drift_validation")
    assert receipt["no_authorization_drift"] is True
    assert receipt["expanded_canary_runtime_authorized"] is False
    assert receipt["runtime_cutover_authorized"] is False


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, dirty=" M something")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)


def test_invalid_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(RuntimeError, match="must run on one of"):
        validation.run(reports_root=reports)


def test_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / expanded.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "RUN_B04_R6_EXPANDED_CANARY"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_binding_hash_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / expanded.INPUTS["canary_evidence_scorecard"]
    payload = _load(path)
    payload["overall_grade"] = "DRIFTED"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="INPUT_HASH_DRIFT"):
        validation.run(reports_root=reports)


def test_scope_widening_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / expanded.OUTPUTS["scope_manifest"]
    payload = _load(path)
    payload["details"]["global_r6_scope_allowed"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="SCOPE_MISSING"):
        validation.run(reports_root=reports)


def test_sample_limit_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / expanded.OUTPUTS["scope_manifest"]
    payload = _load(path)
    payload["details"]["max_case_count_per_window"] = 3600
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="SAMPLE_LIMIT_MISSING"):
        validation.run(reports_root=reports)


def test_sample_limit_contract_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / expanded.OUTPUTS["sample_limit_contract"]
    payload = _load(path)
    payload["details"]["max_cases"] = 3600
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="SAMPLE_LIMIT_MISSING"):
        validation.run(reports_root=reports)


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
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / expanded.OUTPUTS["allowed_case_class_contract"]
    payload = _load(path)
    payload["details"]["allowed_case_classes"] = allowed_case_classes
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="ALLOWED_CASE_CLASSES_MISSING"):
        validation.run(reports_root=reports)


@pytest.mark.parametrize(
    "role, detail_key, expected_reason",
    [
        ("static_fallback_contract", "static_fallback_required", "STATIC_FALLBACK_MISSING"),
        ("operator_override_contract", "operator_override_required", "OPERATOR_OVERRIDE_MISSING"),
        ("kill_switch_contract", "kill_switch_required", "KILL_SWITCH_MISSING"),
        ("rollback_contract", "rollback_required", "ROLLBACK_MISSING"),
    ],
)
def test_required_true_safety_control_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str, detail_key: str, expected_reason: str
) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / expanded.OUTPUTS[role]
    payload = _load(path)
    payload["details"][detail_key] = False
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match=expected_reason):
        validation.run(reports_root=reports)


@pytest.mark.parametrize("field", sorted(validation.AUTHORITY_DRIFT_KEYS))
@pytest.mark.parametrize("drift_value", [True, "AUTHORIZED", 1])
def test_any_non_false_authority_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, drift_value: object
) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / expanded.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload[field] = drift_value
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        validation.run(reports_root=reports)


def test_malformed_text_boundary_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / expanded.OUTPUTS["packet_report"]
    path.write_text("Expanded canary authorization packet\n", encoding="utf-8")
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="RUNTIME_EXECUTED"):
        validation.run(reports_root=reports)


def test_hashes_use_current_file_content(outputs: Path) -> None:
    contract = _contract(outputs)
    digest = hashlib.sha256((outputs / expanded.OUTPUTS["packet_contract"]).read_bytes()).hexdigest()
    assert contract["binding_hashes"]["packet_contract_hash"] == digest
