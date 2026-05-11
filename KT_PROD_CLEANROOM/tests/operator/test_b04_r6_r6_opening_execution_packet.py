from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_r6_opening_authorization_packet_validation as auth_validation
from tools.operator import cohort0_b04_r6_r6_opening_execution_packet as exec_packet
from tools.operator.titanium_common import file_sha256


EXEC_HEAD = "6868686868686868686868686868686868686868"
EXEC_MAIN_HEAD = "40785593737bfd9f47973fc02a767faa9da72ca9"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_r6_opening_authorization_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_r6_opening_authorization_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load R6 opening authorization validation helpers")
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
        "_git_blob_sha256",
        lambda root, commit, raw: file_sha256(exec_packet.common.resolve_path(root, raw)),
    )
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
    tmp_path = tmp_path_factory.mktemp("r6_opening_execution_packet")
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
    "r6_opening_execution_packet_validated",
    "r6_opening_authorized",
    "r6_opening_executed",
    "r6_open",
    "global_runtime_surface_authorized",
    "lobe_escalation_authorized",
    "package_promotion_authorized",
    "commercial_activation_claim_authorized",
    "truth_engine_law_changed",
    "trust_zone_law_changed",
    "metric_contract_mutated",
    "static_comparator_weakened",
]


PREP_ONLY_GUARDS = [
    "cannot_execute_r6_opening",
    "cannot_open_r6",
    "cannot_authorize_lobe_escalation",
    "cannot_authorize_package_promotion",
    "cannot_authorize_commercial_activation_claims",
    "cannot_mutate_truth_engine_law",
    "cannot_mutate_trust_zone_law",
    "cannot_authorize_global_runtime_surface",
]


def test_reason_codes_are_unique() -> None:
    assert len(exec_packet.REASON_CODES) == len(set(exec_packet.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(exec_packet.OUTPUTS.values()))
def test_required_r6_opening_execution_packet_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "does not execute r6 opening" in text
        assert "does not open r6" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == EXEC_MAIN_HEAD
    assert _contract(outputs)["current_git_head"] == EXEC_MAIN_HEAD


def test_packet_binds_r6_opening_authorization_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == exec_packet.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == exec_packet.PREVIOUS_LANE
    assert contract["predecessor_outcome"] == exec_packet.EXPECTED_PREVIOUS_OUTCOME
    assert contract["previous_next_lawful_move"] == exec_packet.EXPECTED_PREVIOUS_NEXT_MOVE
    assert contract["binding_hashes"]["validation_contract_hash"]
    assert contract["binding_hashes"]["validation_receipt_hash"]


def test_packet_selects_execution_validation_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == exec_packet.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == exec_packet.SELECTED_OUTCOME
    assert _receipt(outputs)["verdict"] == "BOUND_FOR_R6_OPENING_EXECUTION_VALIDATION_ONLY"
    assert _next(outputs)["next_lawful_move"] == exec_packet.NEXT_LAWFUL_MOVE


@pytest.mark.parametrize(
    "flag, expected",
    [
        ("runtime_cutover_executed", True),
        ("post_cutover_evidence_review_validated", True),
        ("r6_opening_review_validated", True),
        ("r6_opening_authorization_packet_authored", True),
        ("r6_opening_authorization_validated", True),
        ("r6_opening_execution_packet_authored", True),
        ("r6_opening_execution_packet_validated", False),
        ("r6_opening_authorized", False),
        ("r6_opening_executed", False),
        ("r6_open", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("trust_zone_law_changed", False),
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


def test_shared_canonical_outputs_bind_pre_overwrite_git_objects(outputs: Path) -> None:
    rows = {row["role"]: row for row in _contract(outputs)["input_bindings"]}
    for role in exec_packet.SHARED_CANONICAL_INPUTS:
        assert rows[role]["binding_kind"] == "git_object_before_overwrite"
        assert rows[role]["git_commit"] == EXEC_MAIN_HEAD
        assert rows[role]["mutable_canonical_path_overwritten_by_this_lane"] is True


@pytest.mark.parametrize("role", exec_packet.CONTROL_CONTRACT_ROLES)
def test_control_contracts_are_defined_for_validation_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["control_status"] == "DEFINED_FOR_VALIDATION"
    assert payload["does_not_execute_r6_opening"] is True
    assert payload["does_not_open_r6"] is True
    assert payload["requires_future_validation"] == exec_packet.NEXT_LAWFUL_MOVE


def test_execution_scope_rejects_global_runtime_surface(outputs: Path) -> None:
    scope = _payload(outputs, "scope_manifest")
    assert scope["scope_status"] == "LIMITED_SCOPE_DEFINED"
    assert scope["global_runtime_surface"] is False


def test_allowed_and_excluded_surfaces_are_bounded(outputs: Path) -> None:
    allowed = _payload(outputs, "allowed_surface_contract")["allowed_surfaces"]
    excluded = _payload(outputs, "excluded_surface_contract")["excluded_surfaces"]
    assert "B04_R6_BOUNDED_RUNTIME_SURFACE" in allowed
    assert "STATIC_FALLBACK_PROTECTED_SURFACE" in allowed
    assert "GLOBAL_RUNTIME_SURFACE" in excluded
    assert "COMMERCIAL_ACTIVATION_SURFACE" in excluded
    assert "PACKAGE_PROMOTION_SURFACE" in excluded


def test_opening_preconditions_require_separate_validation(outputs: Path) -> None:
    preconditions = _payload(outputs, "opening_preconditions_contract")["required_preconditions"]
    assert "r6_opening_authorization_validation" in preconditions
    assert "r6_opening_execution_packet_validation" in preconditions
    assert _payload(outputs, "opening_preconditions_contract")["r6_opening_executed"] is False


def test_safety_controls_have_reason_code_mapping(outputs: Path) -> None:
    payload = _payload(outputs, "kill_switch_contract")
    mapping = payload["safety_control_reason_codes"]
    assert mapping["kill_switch_required"].startswith("RC_B04R6_R6_OPENING_EXEC_PACKET")
    assert _payload(outputs, "static_fallback_contract")["static_fallback_required"] is True
    assert _payload(outputs, "operator_override_contract")["operator_override_required"] is True
    assert _payload(outputs, "rollback_contract")["rollback_required"] is True


def test_receipts_replay_and_interpretation_are_defined(outputs: Path) -> None:
    assert _payload(outputs, "runtime_receipt_schema")["receipt_schema_required"] is True
    assert _payload(outputs, "replay_manifest")["replay_manifest_required"] is True
    assert _payload(outputs, "external_verifier_requirements")["external_verifier_required"] is True
    assert _payload(outputs, "result_interpretation_contract")["opening_result_does_not_promote_package"] is True


def test_expected_artifact_manifest_includes_future_execution_contract(outputs: Path) -> None:
    artifacts = _payload(outputs, "expected_artifact_manifest")["expected_artifacts"]
    assert "b04_r6_r6_opening_execution_contract.json" in artifacts
    assert "b04_r6_r6_opening_execution_receipt.json" in artifacts
    assert "b04_r6_r6_opening_result.json" in artifacts
    assert "b04_r6_r6_opening_report.md" in artifacts


def test_commercial_claim_boundary_blocks_activation_claims(outputs: Path) -> None:
    payload = _payload(outputs, "commercial_claim_boundary")
    assert "R6 opening execution packet is authored for validation." in payload["allowed_claims"]
    assert "R6 is open." in payload["forbidden_claims"]
    assert "R6 opening executed." in payload["forbidden_claims"]
    assert "Commercial activation authorized." in payload["forbidden_claims"]


@pytest.mark.parametrize("role", exec_packet.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_outputs_are_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    if role in {"pipeline_board", "future_blocker_register"}:
        assert payload["artifact_id"] in {"B04_R6_PIPELINE_BOARD", "KT_FUTURE_BLOCKER_REGISTER"}
    else:
        assert payload["authority"] == "PREP_ONLY"
        assert payload["status"] == "PREP_ONLY"


@pytest.mark.parametrize("role", exec_packet.PREP_ONLY_OUTPUT_ROLES)
@pytest.mark.parametrize("guard", PREP_ONLY_GUARDS)
def test_prep_only_outputs_keep_guards(outputs: Path, role: str, guard: str) -> None:
    if role in {"pipeline_board", "future_blocker_register"}:
        pytest.skip("shared boards keep canonical shape instead of prep-only guards")
    assert _payload(outputs, role)[guard] is True


@pytest.mark.parametrize("role", _json_output_roles())
@pytest.mark.parametrize("flag", GUARD_FALSE_FIELDS)
def test_all_json_outputs_keep_hard_negative_flags(outputs: Path, role: str, flag: str) -> None:
    assert _payload(outputs, role)[flag] is False


def test_pipeline_board_marks_execution_packet_validation_next(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")
    assert board["artifact_id"] == "B04_R6_PIPELINE_BOARD"
    lanes = {row["lane"]: row["status"] for row in board["lanes"]}
    assert lanes["VALIDATE_B04_R6_R6_OPENING_AUTHORIZATION_PACKET"] == "VALIDATED"
    assert lanes[exec_packet.AUTHORITATIVE_LANE] == "CURRENT_BOUND"
    assert lanes[exec_packet.NEXT_LAWFUL_MOVE] == "NEXT"


def test_next_lawful_move_is_execution_validation(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == exec_packet.NEXT_LAWFUL_MOVE
    assert _next(outputs)["r6_opening_executed"] is False
    assert _next(outputs)["r6_open"] is False


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_exec_env(monkeypatch, tmp_path, branch="feature/nope")
    with pytest.raises(exec_packet.LaneFailure, match="NEXT_MOVE_DRIFT"):
        exec_packet.run(reports_root=reports)


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_exec_env(monkeypatch, tmp_path, dirty=" M thing")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        exec_packet.run(reports_root=reports)


def test_previous_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_R6_OPENING_AUTHORIZATION_REJECTED__R6_OPENING_NOT_JUSTIFIED"
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="PREVIOUS_OUTCOME_DRIFT"):
        exec_packet.run(reports_root=reports)


def test_previous_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "RUN_B04_R6_R6_OPENING"
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="NEXT_MOVE_DRIFT"):
        exec_packet.run(reports_root=reports)


@pytest.mark.parametrize(
    "field, value, reason",
    [
        ("r6_opening_authorized", True, "AUTHORIZATION_DRIFT"),
        ("r6_opening_executed", True, "EXECUTION_DRIFT"),
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


def test_claim_bearing_execution_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["allowed_claims"] = ["R6 opening executed"]
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="EXECUTION_DRIFT"):
        exec_packet.run(reports_root=reports)


def test_text_input_r6_open_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_report"]
    text = path.read_text(encoding="utf-8")
    path.write_text(text + "\nR6_OPEN\n", encoding="utf-8")
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="R6_OPEN_DRIFT"):
        exec_packet.run(reports_root=reports)


def test_text_input_package_promotion_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_report"]
    text = path.read_text(encoding="utf-8")
    path.write_text(text + "\nPACKAGE_PROMOTION_AUTHORIZED\n", encoding="utf-8")
    _patch_exec_env(monkeypatch, tmp_path)
    with pytest.raises(exec_packet.LaneFailure, match="PACKAGE_PROMOTION_DRIFT"):
        exec_packet.run(reports_root=reports)


def test_forbidden_claim_list_may_describe_blocked_claims(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["forbidden_claims"] = ["R6 is open", "R6 opening executed", "Commercial activation authorized"]
    _write(path, payload)
    _patch_exec_env(monkeypatch, tmp_path)
    exec_packet.run(reports_root=reports)


def test_prep_only_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["r6_opening_execution_packet_prep_only_draft"]
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
