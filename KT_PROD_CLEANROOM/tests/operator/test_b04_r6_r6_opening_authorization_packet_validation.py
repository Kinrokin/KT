from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_r6_opening_authorization_packet as auth
from tools.operator import cohort0_b04_r6_r6_opening_authorization_packet_validation as validation
from tools.operator.titanium_common import file_sha256


VALIDATION_HEAD = "6767676767676767676767676767676767676767"
VALIDATION_MAIN_HEAD = "62578eb6391b5eaf54de4190409d48383504c202"


def _load_auth_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_r6_opening_authorization_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_r6_opening_authorization_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load R6 opening authorization helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


auth_helpers = _load_auth_helpers()


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
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_authoring_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return auth_helpers._run_auth(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("r6_opening_authorization_validation")
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
def test_required_r6_opening_authorization_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
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


def test_validation_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["verdict"] == "VALIDATED_FOR_R6_OPENING_EXECUTION_PACKET_AUTHORING_ONLY"


def test_validation_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD
    assert _contract(outputs)["current_git_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_r6_opening_authorization_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == auth.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == auth.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == auth.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["packet_contract_hash"]
    assert contract["binding_hashes"]["packet_receipt_hash"]


def test_next_lawful_move_is_r6_opening_execution_packet_authoring(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_report_states_non_execution_boundaries(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "does not execute r6 opening" in text
    assert "does not open r6" in text
    assert "does not promote package" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize("role", sorted(validation.AUTH_JSON_INPUTS))
def test_validation_binding_hashes_include_each_authorization_json_input(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(validation.AUTH_TEXT_INPUTS))
def test_validation_binding_hashes_include_each_authorization_text_input(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role, raw", sorted(validation.AUTH_JSON_INPUTS.items()))
def test_validation_binding_hashes_match_on_disk_authorization_json_inputs(outputs: Path, role: str, raw: str) -> None:
    expected = file_sha256(outputs.parent.parent / raw)
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"] == expected


def test_input_binding_rows_anchor_to_binding_hashes(outputs: Path) -> None:
    contract = _contract(outputs)
    for row in contract["input_bindings"]:
        assert contract["binding_hashes"][f"{row['role']}_hash"] == row["sha256"]


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["validation_status"] == "PASS"
    assert len(payload["validated_hash"]) == 64


@pytest.mark.parametrize(
    "payload_role",
    ["validation_contract", "validation_receipt", "no_authorization_drift_validation", "next_lawful_move"],
)
@pytest.mark.parametrize(
    "flag",
    [
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
    ],
)
def test_validation_does_not_authorize_forbidden_boundaries(outputs: Path, payload_role: str, flag: str) -> None:
    assert _payload(outputs, payload_role)[flag] is False


def test_validation_marks_authorization_validated_but_no_execution(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["r6_opening_authorization_packet_authored"] is True
    assert contract["r6_opening_authorization_validated"] is True
    assert contract["r6_opening_execution_packet_authored"] is False
    assert contract["r6_opening_execution_packet_validated"] is False
    assert contract["r6_opening_authorized"] is False
    assert contract["r6_opening_executed"] is False
    assert contract["r6_open"] is False


@pytest.mark.parametrize("role", auth.CONTROL_CONTRACT_ROLES)
def test_authorization_operational_contracts_stay_bound_non_executing(outputs: Path, role: str) -> None:
    payload = _load(outputs / auth.OUTPUTS[role])
    assert payload["control_status"] == "DEFINED_FOR_VALIDATION"
    assert payload["does_not_execute_r6_opening"] is True
    assert payload["does_not_open_r6"] is True


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_execute_r6_opening"] is True
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


@pytest.mark.parametrize("role", auth.PREP_ONLY_OUTPUT_ROLES)
def test_authorization_prep_only_inputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / auth.OUTPUTS[role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_execute_r6_opening"] is True
    assert payload["cannot_open_r6"] is True


def test_shared_canonical_inputs_keep_expected_shape(outputs: Path) -> None:
    assert _load(outputs / auth.OUTPUTS["pipeline_board"])["artifact_id"] == "B04_R6_PIPELINE_BOARD"
    assert _load(outputs / auth.OUTPUTS["campaign_board"])["artifact_id"] == "KT_E2E_CLOSURE_CAMPAIGN_BOARD"
    assert _load(outputs / auth.OUTPUTS["future_blocker_register"])["artifact_id"] == "KT_FUTURE_BLOCKER_REGISTER"


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    payload = _payload(outputs, "no_authorization_drift_validation")
    assert payload["validation_status"] == "PASS"
    assert payload["drift_detected"] is False


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, dirty=" M reports/x.json")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="feature/nope")
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_main_branch_replay_requires_head_to_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(validation.LaneFailure, match="main replay requires HEAD to equal origin/main"):
        validation.run(reports_root=reports)


def test_missing_authorization_packet_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    (reports / auth.OUTPUTS["packet_contract"]).unlink()
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="packet_contract"):
        validation.run(reports_root=reports)


def test_empty_input_bindings_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["input_bindings"] = []
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_INPUT_BINDINGS_EMPTY"):
        validation.run(reports_root=reports)


def test_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "R6_OPEN"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_OUTCOME_DRIFT"):
        validation.run(reports_root=reports)


def test_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "RUN_B04_R6_R6_OPENING"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_next_move_lane_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["authoritative_lane"] = "B04_R6_WRONG_LANE"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_next_move_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_R6_OPENING_AUTHORIZATION_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_OUTCOME_DRIFT"):
        validation.run(reports_root=reports)


@pytest.mark.parametrize(
    "field, value, reason",
    [
        ("r6_opening_authorization_validated", True, "RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_OUTCOME_DRIFT"),
        ("r6_opening_authorized", True, "RC_B04R6_R6_OPENING_AUTH_VAL_AUTHORIZATION_DRIFT"),
        ("r6_opening_executed", True, "RC_B04R6_R6_OPENING_AUTH_VAL_EXECUTION_DRIFT"),
        ("r6_open", True, "RC_B04R6_R6_OPENING_AUTH_VAL_R6_OPEN_DRIFT"),
        ("global_runtime_surface_authorized", True, "RC_B04R6_R6_OPENING_AUTH_VAL_GLOBAL_SURFACE_DRIFT"),
        ("package_promotion_authorized", True, "RC_B04R6_R6_OPENING_AUTH_VAL_PACKAGE_PROMOTION_DRIFT"),
        ("commercial_activation_claim_authorized", True, "RC_B04R6_R6_OPENING_AUTH_VAL_COMMERCIAL_CLAIM_DRIFT"),
        ("truth_engine_law_changed", True, "RC_B04R6_R6_OPENING_AUTH_VAL_TRUTH_ENGINE_MUTATION"),
        ("trust_zone_law_changed", True, "RC_B04R6_R6_OPENING_AUTH_VAL_TRUST_ZONE_MUTATION"),
    ],
)
def test_authority_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object, reason: str
) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload[field] = value
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match=reason):
        validation.run(reports_root=reports)


def test_plain_r6_open_claim_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["pipeline_board"]
    payload = _load(path)
    payload["r6"] = "OPEN"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_R6_OPEN_DRIFT"):
        validation.run(reports_root=reports)


def test_claim_bearing_positive_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["commercial_claim_ceiling"]
    payload = _load(path)
    payload["allowed_claims"] = ["R6 is open"]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_R6_OPEN_DRIFT"):
        validation.run(reports_root=reports)


def test_json_execution_claim_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["commercial_claim_ceiling"]
    payload = _load(path)
    payload["allowed_claims"] = ["R6 opening executed"]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_EXECUTION_DRIFT"):
        validation.run(reports_root=reports)


def test_forbidden_claim_list_may_describe_blocked_positive_tokens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["commercial_claim_ceiling"]
    payload = _load(path)
    payload["forbidden_claims"] = ["R6 is open", "R6 opening executed", "Commercial activation authorized"]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)


def test_text_artifact_forbidden_claim_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["packet_report"]
    text = path.read_text(encoding="utf-8")
    path.write_text(text + "\nR6 IS OPEN\n", encoding="utf-8")
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_R6_OPEN_DRIFT"):
        validation.run(reports_root=reports)


def test_prep_only_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["r6_opening_execution_packet_prep_only_draft"]
    payload = _load(path)
    payload["authority"] = "AUTHORITY"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_PREP_ONLY_DRIFT"):
        validation.run(reports_root=reports)


def test_shared_board_shape_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    path = reports / auth.OUTPUTS["campaign_board"]
    payload = _load(path)
    payload["corridors"] = "not-a-list"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_SHARED_BOARD_SHAPE_DRIFT"):
        validation.run(reports_root=reports)


def test_trust_zone_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authoring_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "FAIL", "failures": ["boom"], "checks": []},
    )
    with pytest.raises(validation.LaneFailure, match="RC_B04R6_R6_OPENING_AUTH_VAL_TRUST_ZONE_FAILED"):
        validation.run(reports_root=reports)
