from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_commercial_activation_authorization_packet_validation as auth_validation
from tools.operator import cohort0_b04_r6_commercial_activation_execution_packet as execution


EXEC_HEAD = "edededededededededededededededededededed"
EXEC_MAIN_HEAD = "9839cbbf8182cd241797f57c946d05294bd67795"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_commercial_activation_authorization_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_commercial_activation_auth_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load commercial activation authorization validation helpers")
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
    head: str = EXEC_HEAD,
    origin_main: str = EXEC_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(execution, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(execution.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(execution.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(execution.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        execution,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_authorization_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_authorization_validation(tmp_path, monkeypatch)
    _patch_execution_env(monkeypatch, tmp_path)
    execution.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("commercial_activation_execution_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_execution(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / execution.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "execution_contract")


def _json_roles() -> list[str]:
    return sorted(role for role, filename in execution.OUTPUTS.items() if filename.endswith(".json"))


def test_reason_codes_are_unique() -> None:
    assert len(execution.REASON_CODES) == len(set(execution.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(execution.OUTPUTS.values()))
def test_required_execution_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "commercial activation execution packet" in text
        assert "does not run commercial activation" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_execution_packet_binds_authorization_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == execution.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == auth_validation.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == auth_validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == auth_validation.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["validation_contract_hash"]
    assert contract["binding_hashes"]["validation_receipt_hash"]


def test_execution_packet_selects_execution_validation_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == execution.SELECTED_OUTCOME
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == execution.NEXT_LAWFUL_MOVE


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("r6_open", True),
        ("package_promotion_passed", True),
        ("commercial_activation_authorization_validated", True),
        ("commercial_activation_execution_packet_authored", True),
        ("commercial_activation_execution_packet_validated", False),
        ("commercial_activation_executed", False),
        ("commercial_activation_claim_authorized", False),
        ("benchmark_prep_authorizes_commercial_activation", False),
        ("seven_b_amplification_claimed_proven", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
    ],
)
def test_execution_packet_preserves_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", execution.EXECUTION_CONTRACT_ROLES)
def test_execution_contracts_are_bound(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["contract_status"] == "BOUND"
    assert payload["requirements"]


@pytest.mark.parametrize("role", execution.PREP_ONLY_ROLES)
def test_execution_prep_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_execute_commercial_activation"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_claim_7b_amplification_proven"] is True


def test_authorization_validation_execution_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authorization_validation(tmp_path, monkeypatch)
    contract_path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(contract_path)
    payload["commercial_activation_executed"] = True
    _write(contract_path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(execution.LaneFailure) as excinfo:
        execution.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_EXECUTION_DRIFT"


def test_authorization_validation_claim_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authorization_validation(tmp_path, monkeypatch)
    contract_path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(contract_path)
    payload["commercial_activation_claim_authorized"] = True
    _write(contract_path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(execution.LaneFailure) as excinfo:
        execution.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_CLAIM_DRIFT"


def test_claim_token_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authorization_validation(tmp_path, monkeypatch)
    path = reports / auth_validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["commercial_claim"] = "commercial activation authorized"
    _write(path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(execution.LaneFailure) as excinfo:
        execution.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_CLAIM_TOKEN_DRIFT"


def test_benchmark_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authorization_validation(tmp_path, monkeypatch)
    contract_path = reports / auth_validation.OUTPUTS["validation_contract"]
    payload = _load(contract_path)
    payload["benchmark_prep_authorizes_commercial_activation"] = True
    _write(contract_path, payload)
    _patch_execution_env(monkeypatch, tmp_path)
    with pytest.raises(execution.LaneFailure) as excinfo:
        execution.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_BENCHMARK_AUTHORITY_DRIFT"


def test_main_replay_requires_head_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_authorization_validation(tmp_path, monkeypatch)
    _patch_execution_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(execution.LaneFailure) as excinfo:
        execution.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_NEXT_MOVE_DRIFT"


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_have_current_main_head(outputs: Path, role: str) -> None:
    assert _payload(outputs, role)["current_main_head"] == EXEC_MAIN_HEAD


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_record_branch_head_as_current_git_head(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["current_git_head"] == EXEC_HEAD
    assert payload["current_branch_head"] == EXEC_HEAD
