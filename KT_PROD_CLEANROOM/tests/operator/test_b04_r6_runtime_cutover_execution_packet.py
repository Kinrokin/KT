from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_runtime_cutover_authorization_packet_validation as auth_validation
from tools.operator import cohort0_b04_r6_runtime_cutover_execution_packet as exec_packet
from tools.operator.titanium_common import file_sha256


EXEC_HEAD = "cccccccccccccccccccccccccccccccccccccccc"
EXEC_MAIN_HEAD = "1e74e888f8f47f783b00e879f05cac4fd5b6d1f5"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_runtime_cutover_authorization_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_runtime_cutover_authorization_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load runtime cutover authorization validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_exec_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = exec_packet.AUTHORITY_BRANCH,
    head: str = EXEC_HEAD,
    origin_main: str = EXEC_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(exec_packet, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(exec_packet.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(exec_packet.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(exec_packet.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        exec_packet,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_predecessor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_exec_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_exec_env(monkeypatch, tmp_path)
    exec_packet.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("runtime_cutover_execution_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_exec_packet(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / exec_packet.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "packet_contract")


def _receipt(outputs: Path) -> dict:
    return _payload(outputs, "packet_receipt")


def _next(outputs: Path) -> dict:
    return _payload(outputs, "next_lawful_move")


def _json_output_roles() -> list[str]:
    return sorted(role for role, filename in exec_packet.OUTPUTS.items() if filename.endswith(".json"))


GUARD_FALSE_FIELDS = [
    "runtime_cutover_execution_packet_validated",
    "runtime_cutover_authorized",
    "runtime_cutover_executed",
    "activation_cutover_executed",
    "r6_open",
    "lobe_escalation_authorized",
    "package_promotion_authorized",
    "commercial_activation_claim_authorized",
    "truth_engine_law_changed",
    "trust_zone_law_changed",
    "metric_contract_mutated",
    "static_comparator_weakened",
]

PREP_ONLY_GUARDS = [
    "cannot_authorize_runtime_cutover",
    "cannot_execute_runtime_cutover",
    "cannot_open_r6",
    "cannot_authorize_lobe_escalation",
    "cannot_authorize_package_promotion",
    "cannot_authorize_commercial_activation_claims",
    "cannot_mutate_truth_engine_law",
    "cannot_mutate_trust_zone_law",
]


def test_reason_codes_are_unique() -> None:
    assert len(exec_packet.REASON_CODES) == len(set(exec_packet.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(exec_packet.OUTPUTS.values()))
def test_required_runtime_cutover_execution_packet_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "does not execute runtime cutover" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == EXEC_MAIN_HEAD


def test_branch_packet_binds_canonical_source_head(outputs: Path) -> None:
    assert _contract(outputs)["current_git_head"] == EXEC_MAIN_HEAD


def test_packet_binds_runtime_cutover_authorization_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == exec_packet.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == exec_packet.PREVIOUS_LANE
    assert contract["predecessor_outcome"] == exec_packet.EXPECTED_PREVIOUS_OUTCOME
    assert contract["previous_next_lawful_move"] == exec_packet.EXPECTED_PREVIOUS_NEXT_MOVE
    assert contract["binding_hashes"]["validation_contract_hash"]
    assert contract["binding_hashes"]["validation_receipt_hash"]


def test_packet_selects_execution_packet_validation_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == exec_packet.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == exec_packet.SELECTED_OUTCOME
    assert _receipt(outputs)["verdict"] == "BOUND_FOR_RUNTIME_CUTOVER_EXECUTION_VALIDATION_ONLY"
    assert _next(outputs)["next_lawful_move"] == exec_packet.NEXT_LAWFUL_MOVE


def test_report_states_no_execution_or_open_boundaries(outputs: Path) -> None:
    text = (outputs / exec_packet.OUTPUTS["packet_report"]).read_text(encoding="utf-8").lower()
    assert "does not execute runtime cutover" in text
    assert "does not open r6" in text
    assert "does not promote package" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("runtime_cutover_review_validated", True),
        ("runtime_cutover_authorization_packet_authored", True),
        ("runtime_cutover_authorization_validated", True),
        ("runtime_cutover_execution_packet_authored", True),
        ("runtime_cutover_execution_packet_validated", False),
        ("runtime_cutover_authorized", False),
        ("runtime_cutover_executed", False),
        ("activation_cutover_executed", False),
        ("r6_open", False),
        ("lobe_escalation_authorized", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
        ("metric_contract_mutated", False),
        ("static_comparator_weakened", False),
    ],
)
def test_packet_contract_preserves_authority_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", sorted(exec_packet.VALIDATION_JSON_INPUTS))
def test_packet_binds_all_authorization_validation_json_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(exec_packet.VALIDATION_TEXT_INPUTS))
def test_packet_binds_all_authorization_validation_text_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role, raw", sorted(exec_packet.VALIDATION_JSON_INPUTS.items()))
def test_packet_binding_hashes_match_on_disk_validation_json_inputs(outputs: Path, role: str, raw: str) -> None:
    expected = file_sha256(outputs.parent.parent / raw)
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"] == expected


def test_input_binding_rows_anchor_to_binding_hashes(outputs: Path) -> None:
    contract = _contract(outputs)
    for row in contract["input_bindings"]:
        assert contract["binding_hashes"][f"{row['role']}_hash"] == row["sha256"]


def test_input_binding_rows_are_sorted_by_role(outputs: Path) -> None:
    roles = [row["role"] for row in _contract(outputs)["input_bindings"]]
    assert roles == sorted(roles)


@pytest.mark.parametrize("row_index", range(0, 220))
def test_input_binding_rows_have_hash_shape(outputs: Path, row_index: int) -> None:
    rows = _contract(outputs)["input_bindings"]
    if row_index >= len(rows):
        pytest.skip("fewer input rows than parameterized guard")
    row = rows[row_index]
    assert len(row["sha256"]) == 64
    assert all(ch in "0123456789abcdef" for ch in row["sha256"])


@pytest.mark.parametrize("role", exec_packet.CONTROL_CONTRACT_ROLES)
def test_control_contracts_are_defined_for_validation_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["control_status"] == "DEFINED_FOR_VALIDATION"
    assert payload["does_not_execute_runtime_cutover"] is True
    assert payload["does_not_open_r6"] is True
    assert payload["requires_future_validation"] == exec_packet.NEXT_LAWFUL_MOVE


def test_scope_rejects_global_runtime_surface(outputs: Path) -> None:
    scope = _payload(outputs, "scope_manifest")
    assert scope["scope_status"] == "LIMITED_SCOPE_DEFINED"
    assert scope["global_runtime_surface"] is False


def test_allowed_and_excluded_case_classes_are_bounded(outputs: Path) -> None:
    allowed = _payload(outputs, "allowed_case_class_contract")["allowed_case_classes"]
    excluded = _payload(outputs, "excluded_case_class_contract")["excluded_case_classes"]
    assert "validated_r6_routing_cases" in allowed
    assert "commercial_activation" in excluded
    assert "package_promotion" in excluded
    assert "unbounded_runtime" in excluded


def test_traffic_limit_fails_closed_on_drift(outputs: Path) -> None:
    payload = _payload(outputs, "traffic_limit_contract")
    assert payload["traffic_limit"] == "bounded_r6_cutover_surface_only"
    assert payload["sample_limit_drift_fails_closed"] is True


def test_control_contracts_require_safety_controls(outputs: Path) -> None:
    assert _payload(outputs, "static_fallback_contract")["static_fallback_required"] is True
    assert _payload(outputs, "abstention_fallback_contract")["abstention_fallback_required"] is True
    assert _payload(outputs, "null_route_preservation_contract")["null_route_preservation_required"] is True
    assert _payload(outputs, "operator_override_contract")["operator_override_required"] is True
    assert _payload(outputs, "kill_switch_contract")["kill_switch_required"] is True
    assert _payload(outputs, "rollback_contract")["rollback_required"] is True


def test_result_interpretation_does_not_open_r6(outputs: Path) -> None:
    payload = _payload(outputs, "result_interpretation_contract")
    assert payload["cutover_pass_does_not_open_r6"] is True
    assert payload["r6_open"] is False


def test_commercial_boundary_blocks_activation_claims(outputs: Path) -> None:
    payload = _payload(outputs, "commercial_claim_boundary")
    assert payload["allowed_claim_ceiling"] == "CUTOVER_EXECUTION_PACKET_AUTHORED_ONLY"
    assert "AFSH is live" in payload["forbidden_claims"]
    assert "R6 is open" in payload["forbidden_claims"]
    assert "commercial activation is authorized" in payload["forbidden_claims"]


@pytest.mark.parametrize("role", exec_packet.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_outputs_are_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"


@pytest.mark.parametrize("role", exec_packet.PREP_ONLY_OUTPUT_ROLES)
@pytest.mark.parametrize("guard", PREP_ONLY_GUARDS)
def test_prep_only_outputs_keep_guards(outputs: Path, role: str, guard: str) -> None:
    assert _payload(outputs, role)[guard] is True


@pytest.mark.parametrize("role", _json_output_roles())
@pytest.mark.parametrize("flag", GUARD_FALSE_FIELDS)
def test_all_json_outputs_keep_hard_negative_flags(outputs: Path, role: str, flag: str) -> None:
    assert _payload(outputs, role)[flag] is False


@pytest.mark.parametrize("role", _json_output_roles())
def test_all_json_outputs_keep_truth_and_trust_law_unchanged(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["truth_engine_law_unchanged"] is True
    assert payload["trust_zone_law_unchanged"] is True


@pytest.mark.parametrize("role", _json_output_roles())
def test_all_json_outputs_include_forbidden_actions(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert "RUNTIME_CUTOVER_EXECUTED" in payload["forbidden_actions"]
    assert "R6_OPEN" in payload["forbidden_actions"]
    assert "PACKAGE_PROMOTION_AUTHORIZED" in payload["forbidden_actions"]
    assert "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED" in payload["forbidden_actions"]


def test_pipeline_board_marks_execution_packet_bound_not_executed(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")["board_state"]
    assert board["runtime_cutover_authorization"] == "VALIDATED"
    assert board["runtime_cutover_execution_packet"] == "BOUND_FOR_VALIDATION"
    assert board["runtime_cutover"] == "UNEXECUTED"
    assert board["r6"] == "CLOSED"


def test_next_lawful_move_is_execution_packet_validation(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == "VALIDATE_B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET"
    assert _next(outputs)["runtime_cutover_executed"] is False
    assert _next(outputs)["r6_open"] is False


def test_main_branch_replay_requires_head_to_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_exec_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(exec_packet.LaneFailure, match="main replay requires HEAD to equal origin/main"):
        exec_packet.run(reports_root=reports)


def test_disallowed_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_exec_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(exec_packet.LaneFailure, match="branch"):
        exec_packet.run(reports_root=reports)


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_exec_env(monkeypatch, tmp_path, dirty=" M something")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        exec_packet.run(reports_root=reports)


def test_missing_authorization_validation_contract_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    (reports / auth_validation.OUTPUTS["validation_contract"]).unlink()
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="validation_contract"):
        exec_packet.run(reports_root=reports)


def test_previous_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="PREVIOUS_OUTCOME_DRIFT"):
        exec_packet.run(reports_root=reports)


def test_previous_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "RUN_B04_R6_RUNTIME_CUTOVER"
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="NEXT_MOVE_DRIFT"):
        exec_packet.run(reports_root=reports)


def test_empty_input_bindings_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["input_bindings"] = []
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="INPUT_BINDINGS_EMPTY"):
        exec_packet.run(reports_root=reports)


def test_previous_validation_not_true_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["runtime_cutover_authorization_validated"] = False
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="PREVIOUS_VALIDATION_MISSING"):
        exec_packet.run(reports_root=reports)


def test_already_authored_execution_packet_claim_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["runtime_cutover_execution_packet_authored"] = True
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="PREVIOUS_VALIDATION_MISSING"):
        exec_packet.run(reports_root=reports)


@pytest.mark.parametrize(
    "field, value, reason",
    [
        ("runtime_cutover_authorized", True, "RUNTIME_CUTOVER_AUTHORIZED"),
        ("runtime_cutover_executed", True, "RUNTIME_CUTOVER_EXECUTED"),
        ("activation_cutover_executed", True, "ACTIVATION_CUTOVER_EXECUTED"),
        ("r6_open", True, "R6_OPEN_DRIFT"),
        ("package_promotion_authorized", True, "PACKAGE_PROMOTION_DRIFT"),
        ("commercial_activation_claim_authorized", True, "COMMERCIAL_CLAIM_DRIFT"),
        ("truth_engine_law_changed", True, "TRUTH_ENGINE_MUTATION"),
        ("trust_zone_law_changed", True, "TRUST_ZONE_MUTATION"),
    ],
)
def test_authority_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object, reason: str
) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload[field] = value
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match=reason):
        exec_packet.run(reports_root=reports)


def test_plain_r6_open_claim_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["runtime_cutover_execution_packet_prep_only_draft"]
    payload = _load(path)
    payload["r6"] = "OPEN"
    payload["r6_open"] = False
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="R6_OPEN_DRIFT"):
        exec_packet.run(reports_root=reports)


def test_claim_bearing_authorized_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["commercial_claim_state"] = "AUTHORIZED"
    payload["commercial_activation_claim_authorized"] = False
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        exec_packet.run(reports_root=reports)


def test_text_artifact_forbidden_claim_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_report"]
    text = path.read_text(encoding="utf-8")
    path.write_text(text + "\nRUNTIME CUTOVER EXECUTED\n", encoding="utf-8")
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        exec_packet.run(reports_root=reports)


def test_prep_only_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["runtime_cutover_execution_packet_prep_only_draft"]
    payload = _load(path)
    payload["authority"] = "AUTHORITY"
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="PREP_ONLY_DRIFT"):
        exec_packet.run(reports_root=reports)


def test_trust_zone_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_exec_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        exec_packet,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "FAIL", "failures": ["boom"], "checks": []},
    )
    with pytest.raises(exec_packet.LaneFailure, match="TRUST_ZONE_FAILED"):
        exec_packet.run(reports_root=reports)
