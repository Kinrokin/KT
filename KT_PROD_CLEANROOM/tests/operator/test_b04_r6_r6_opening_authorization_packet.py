from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_r6_opening_authorization_packet as auth


AUTH_HEAD = "5656565656565656565656565656565656565656"
AUTH_MAIN_HEAD = "b553fe0a865c3476333f35df7112667d38175330"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_r6_opening_review_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_r6_opening_review_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load R6 opening review validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_auth_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = auth.AUTHORITY_BRANCH,
    head: str = AUTH_HEAD,
    origin_main: str = AUTH_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(auth, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(auth.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(auth.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(auth.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        auth,
        "_git_blob_sha256",
        lambda root, commit, raw: auth.file_sha256(auth.common.resolve_path(root, raw)),
    )
    monkeypatch.setattr(
        auth,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_predecessor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_auth_env(monkeypatch, tmp_path)
    auth.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("r6_opening_authorization_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_auth(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / auth.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "packet_contract")


def _receipt(outputs: Path) -> dict:
    return _payload(outputs, "packet_receipt")


def _next(outputs: Path) -> dict:
    return _payload(outputs, "next_lawful_move")


def _json_output_roles() -> list[str]:
    return sorted(role for role, filename in auth.OUTPUTS.items() if filename.endswith(".json"))


GUARD_FALSE_FIELDS = [
    "r6_opening_authorization_validated",
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
    "r6_opening_authorization_treated_as_r6_open",
    "r6_opening_authorization_treated_as_package_promotion",
]


PREP_ONLY_GUARDS = [
    "cannot_execute_r6_opening",
    "cannot_open_r6",
    "cannot_authorize_lobe_escalation",
    "cannot_authorize_package_promotion",
    "cannot_authorize_commercial_activation_claims",
    "cannot_mutate_truth_engine_law",
    "cannot_mutate_trust_zone_law",
]


def test_reason_codes_are_unique() -> None:
    assert len(auth.REASON_CODES) == len(set(auth.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(auth.OUTPUTS.values()))
def test_required_authorization_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "r6 opening authorization packet" in text
        assert "does not execute r6 opening" in text
        assert "does not open r6" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == AUTH_MAIN_HEAD


def test_branch_packet_binds_canonical_source_head(outputs: Path) -> None:
    assert _contract(outputs)["current_git_head"] == AUTH_MAIN_HEAD


def test_packet_binds_r6_opening_review_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == auth.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == auth.PREVIOUS_LANE
    assert contract["predecessor_outcome"] == auth.EXPECTED_PREVIOUS_OUTCOME
    assert contract["previous_next_lawful_move"] == auth.EXPECTED_PREVIOUS_NEXT_MOVE
    assert contract["binding_hashes"]["validation_contract_hash"]
    assert contract["binding_hashes"]["validation_receipt_hash"]


def test_packet_selects_authorization_validation_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == auth.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == auth.SELECTED_OUTCOME
    assert _receipt(outputs)["verdict"] == "BOUND_FOR_R6_OPENING_AUTHORIZATION_VALIDATION_ONLY"
    assert _next(outputs)["next_lawful_move"] == auth.NEXT_LAWFUL_MOVE


def test_report_states_no_execution_or_open_boundaries(outputs: Path) -> None:
    text = (outputs / auth.OUTPUTS["packet_report"]).read_text(encoding="utf-8").lower()
    assert "does not execute r6 opening" in text
    assert "does not open r6" in text
    assert "does not promote package" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("runtime_cutover_executed", True),
        ("post_cutover_evidence_review_validated", True),
        ("r6_opening_review_validated", True),
        ("r6_opening_authorization_packet_authored", True),
        ("r6_opening_authorization_validated", False),
        ("r6_opening_authorized", False),
        ("r6_opening_executed", False),
        ("r6_open", False),
        ("global_runtime_surface_authorized", False),
        ("lobe_escalation_authorized", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
        ("metric_contract_mutated", False),
        ("static_comparator_weakened", False),
        ("r6_opening_authorization_treated_as_r6_open", False),
        ("r6_opening_authorization_treated_as_package_promotion", False),
    ],
)
def test_packet_contract_preserves_authority_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", sorted(auth.VALIDATION_JSON_INPUTS))
def test_packet_binds_all_validation_json_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(auth.VALIDATION_TEXT_INPUTS))
def test_packet_binds_all_validation_text_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_input_binding_rows_anchor_to_binding_hashes(outputs: Path) -> None:
    contract = _contract(outputs)
    for row in contract["input_bindings"]:
        assert contract["binding_hashes"][f"{row['role']}_hash"] == row["sha256"]


def test_input_binding_rows_are_sorted_by_role(outputs: Path) -> None:
    roles = [row["role"] for row in _contract(outputs)["input_bindings"]]
    assert roles == sorted(roles)


def test_shared_canonical_outputs_bind_pre_overwrite_git_objects(outputs: Path) -> None:
    rows = {row["role"]: row for row in _contract(outputs)["input_bindings"]}
    for role in auth.SHARED_CANONICAL_INPUTS:
        assert rows[role]["binding_kind"] == "git_object_before_overwrite"
        assert rows[role]["git_commit"] == AUTH_MAIN_HEAD
        assert rows[role]["mutable_canonical_path_overwritten_by_this_lane"] is True


@pytest.mark.parametrize("row_index", range(0, 220))
def test_input_binding_rows_have_hash_shape(outputs: Path, row_index: int) -> None:
    rows = _contract(outputs)["input_bindings"]
    if row_index >= len(rows):
        pytest.skip("fewer input rows than parameterized guard")
    row = rows[row_index]
    assert len(row["sha256"]) == 64
    assert all(ch in "0123456789abcdef" for ch in row["sha256"])


@pytest.mark.parametrize("role", auth.CONTROL_CONTRACT_ROLES)
def test_control_contracts_are_defined_for_validation_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["control_status"] == "DEFINED_FOR_VALIDATION"
    assert payload["does_not_execute_r6_opening"] is True
    assert payload["does_not_open_r6"] is True
    assert payload["requires_future_validation"] == auth.NEXT_LAWFUL_MOVE


def test_allowed_and_excluded_surfaces_are_bounded(outputs: Path) -> None:
    allowed = _payload(outputs, "allowed_surface_contract")["allowed_surfaces"]
    excluded = _payload(outputs, "excluded_surface_contract")["excluded_surfaces"]
    assert "B04_R6_BOUNDED_RUNTIME_SURFACE" in allowed
    assert "STATIC_FALLBACK_PROTECTED_SURFACE" in allowed
    assert "GLOBAL_RUNTIME_SURFACE" in excluded
    assert "COMMERCIAL_ACTIVATION_SURFACE" in excluded
    assert "PACKAGE_PROMOTION_SURFACE" in excluded
    assert "LOBE_ESCALATION_SURFACE" in excluded


def test_opening_preconditions_require_separate_execution_packet(outputs: Path) -> None:
    preconditions = _payload(outputs, "opening_preconditions_contract")["required_preconditions"]
    assert "r6_opening_authorization_validation" in preconditions
    assert "r6_opening_execution_packet_authoring" in preconditions
    assert "r6_opening_execution_packet_validation" in preconditions
    assert _payload(outputs, "opening_preconditions_contract")["r6_opening_executed"] is False


def test_control_contracts_require_safety_controls(outputs: Path) -> None:
    assert _payload(outputs, "static_fallback_contract")["static_fallback_required"] is True
    assert _payload(outputs, "operator_override_contract")["operator_override_required"] is True
    assert _payload(outputs, "kill_switch_contract")["kill_switch_required"] is True
    assert _payload(outputs, "rollback_contract")["rollback_required"] is True
    assert _payload(outputs, "monitoring_window_contract")["monitoring_window_required"] is True


def test_thresholds_and_receipts_are_defined(outputs: Path) -> None:
    assert _payload(outputs, "route_distribution_thresholds")["thresholds_defined"] is True
    assert _payload(outputs, "drift_thresholds")["thresholds_defined"] is True
    assert _payload(outputs, "incident_freeze_contract")["incident_freeze_required"] is True
    assert _payload(outputs, "runtime_receipt_schema")["receipt_schema_required"] is True
    assert _payload(outputs, "external_verifier_requirements")["external_verifier_required"] is True


def test_commercial_claim_ceiling_blocks_activation_claims(outputs: Path) -> None:
    payload = _payload(outputs, "commercial_claim_ceiling")
    assert "R6 remains closed." in payload["allowed_claims"]
    assert "R6 is open." in payload["forbidden_claims"]
    assert "R6 opening executed." in payload["forbidden_claims"]
    assert "Commercial activation authorized." in payload["forbidden_claims"]


def test_package_promotion_is_prohibited(outputs: Path) -> None:
    payload = _payload(outputs, "package_promotion_prohibition_receipt")
    assert payload["package_promotion_prohibited"] is True
    assert payload["package_promotion_authorized"] is False


def test_validation_plan_prepares_execution_packet_next_not_opening(outputs: Path) -> None:
    plan = _payload(outputs, "validation_plan")
    assert auth.VALIDATION_SUCCESS_OUTCOME in plan["validation_outcomes_prepared"]
    assert plan["r6_opening_authorized"] is False
    assert plan["r6_opening_executed"] is False
    assert plan["r6_open"] is False


@pytest.mark.parametrize("role", auth.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_outputs_are_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"


@pytest.mark.parametrize("role", auth.PREP_ONLY_OUTPUT_ROLES)
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
    assert "R6_OPEN" in payload["forbidden_actions"]
    assert "R6_OPENING_AUTHORIZED" in payload["forbidden_actions"]
    assert "R6_OPENING_EXECUTED" in payload["forbidden_actions"]
    assert "PACKAGE_PROMOTION_AUTHORIZED" in payload["forbidden_actions"]
    assert "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED" in payload["forbidden_actions"]


def test_pipeline_board_marks_authorization_validation_next(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")
    assert board["schema_id"].startswith("kt.b04_r6.pipeline_board.")
    assert board["artifact_id"] == "B04_R6_PIPELINE_BOARD"
    lanes = {row["lane"]: row["status"] for row in board["lanes"]}
    assert lanes["VALIDATE_B04_R6_R6_OPENING_REVIEW_PACKET"] == "VALIDATED"
    assert lanes[auth.AUTHORITATIVE_LANE] == "CURRENT_BOUND"
    assert lanes[auth.NEXT_LAWFUL_MOVE] == "NEXT"
    assert lanes["AUTHOR_B04_R6_R6_OPENING_EXECUTION_PACKET"] == "BLOCKED_PENDING_AUTHORIZATION_VALIDATION"


def test_campaign_board_keeps_canonical_shape(outputs: Path) -> None:
    board = _payload(outputs, "campaign_board")
    assert board["schema_id"].startswith("kt.e2e_closure.campaign_board.")
    assert board["artifact_id"] == "KT_E2E_CLOSURE_CAMPAIGN_BOARD"
    corridors = {row["corridor"]: row["status"] for row in board["corridors"]}
    assert corridors["R6_OPENING"] == "AUTHORIZATION_PACKET_BOUND_VALIDATION_NEXT"
    assert corridors["PACKAGE_PROMOTION"] == "BLOCKED"


def test_future_blocker_register_keeps_canonical_shape(outputs: Path) -> None:
    register = _payload(outputs, "future_blocker_register")
    assert register["schema_id"].startswith("kt.future_blocker_register.")
    assert register["artifact_id"] == "KT_FUTURE_BLOCKER_REGISTER"
    assert all(isinstance(row, dict) for row in register["blockers"])
    assert {row["category"] for row in register["blockers"]} >= {
        "r6_opening_authorization",
        "r6_opening_execution",
        "package_promotion",
        "commercial_claims",
    }


def test_next_lawful_move_is_authorization_validation(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == auth.NEXT_LAWFUL_MOVE
    assert _next(outputs)["r6_opening_authorized"] is False
    assert _next(outputs)["r6_opening_executed"] is False
    assert _next(outputs)["r6_open"] is False


def test_main_branch_replay_requires_head_to_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_auth_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(auth.LaneFailure, match="main replay requires HEAD to equal origin/main"):
        auth.run(reports_root=reports)


def test_disallowed_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_auth_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(auth.LaneFailure, match="branch"):
        auth.run(reports_root=reports)


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_auth_env(monkeypatch, tmp_path, dirty=" M something")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        auth.run(reports_root=reports)


def test_missing_validation_contract_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    (reports / auth.review_validation.OUTPUTS["validation_contract"]).unlink()
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="PREVIOUS_VALIDATION_MISSING"):
        auth.run(reports_root=reports)


def test_previous_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_R6_OPENING_REVIEW_DEFERRED__NAMED_REVIEW_DEFECT_REMAINS"
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="PREVIOUS_OUTCOME_DRIFT"):
        auth.run(reports_root=reports)


def test_previous_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_R6_OPENING_EXECUTION_PACKET"
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="NEXT_MOVE_DRIFT"):
        auth.run(reports_root=reports)


def test_validation_receipt_lane_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["validation_receipt"]
    payload = _load(path)
    payload["authoritative_lane"] = "B04_R6_WRONG_LANE"
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="PREVIOUS_VALIDATION_MISSING"):
        auth.run(reports_root=reports)


def test_next_lawful_move_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_R6_OPENING_REVIEW_DEFERRED__NAMED_REVIEW_DEFECT_REMAINS"
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="PREVIOUS_OUTCOME_DRIFT"):
        auth.run(reports_root=reports)


def test_missing_authorization_next_flag_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["r6_opening_authorization_packet_next"] = False
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="REVIEW_VALIDATION_INCOMPLETE"):
        auth.run(reports_root=reports)


def test_empty_input_bindings_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["input_bindings"] = []
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="INPUT_HASH_MISSING"):
        auth.run(reports_root=reports)


def test_malformed_input_hash_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["input_bindings"][0]["sha256"] = "not-a-sha"
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="INPUT_HASH_MALFORMED"):
        auth.run(reports_root=reports)


def test_r6_open_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["r6_open"] = True
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="R6_OPEN"):
        auth.run(reports_root=reports)


def test_r6_open_non_false_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["r6_open"] = ""
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="R6_OPEN"):
        auth.run(reports_root=reports)


def test_r6_opening_authorized_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["r6_opening_authorized"] = True
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="AUTHORIZATION_DRIFT"):
        auth.run(reports_root=reports)


def test_plain_r6_open_claim_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["pipeline_board"]
    payload = _load(path)
    payload["board"]["r6"] = "OPEN"
    payload["r6_open"] = False
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        auth.run(reports_root=reports)


def test_array_claim_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["allowed_claims"] = ["R6 is open"]
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        auth.run(reports_root=reports)


def test_forbidden_claim_array_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["forbidden_claims"] = ["R6 is open"]
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        auth.run(reports_root=reports)


def test_package_promotion_claim_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["package_promotion"] = "AUTHORIZED"
    payload["package_promotion_authorized"] = False
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        auth.run(reports_root=reports)


def test_commercial_claim_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / auth.review_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["commercial_claim"] = "COMMERCIAL_ACTIVATION"
    payload["commercial_activation_claim_authorized"] = False
    _write(path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(auth.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        auth.run(reports_root=reports)


def test_trust_zone_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_auth_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        auth,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "FAIL", "failures": ["boom"], "checks": []},
    )
    with pytest.raises(auth.LaneFailure, match="TRUST_ZONE_FAILED"):
        auth.run(reports_root=reports)
