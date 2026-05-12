from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_package_promotion_execution_packet as execution
from tools.operator import cohort0_b04_r6_package_promotion_execution_packet_validation as validation


VALIDATION_HEAD = "ffffffffffffffffffffffffffffffffffffffff"
VALIDATION_MAIN_HEAD = "f7c1b58d5b8136e7f7ba0807e1d4c750e10a7b64"


def _load_execution_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_package_promotion_execution_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_package_execution_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load package promotion execution helpers")
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


def _run_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return execution_helpers._run_execution(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_execution(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("package_promotion_execution_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_validation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / validation.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "validation_contract")


def _json_roles() -> list[str]:
    return sorted(role for role, filename in validation.OUTPUTS.items() if filename.endswith(".json"))


def test_reason_codes_are_unique() -> None:
    assert len(validation.REASON_CODES) == len(set(validation.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "package promotion execution packet validation" in text
        assert "does not execute package promotion" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_binds_execution_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == execution.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == execution.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == execution.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["execution_contract_hash"]
    assert contract["binding_hashes"]["execution_receipt_hash"]


def test_validation_selects_package_promotion_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _payload(outputs, "validation_receipt")["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("r6_open", True),
        ("package_promotion_authorization_validated", True),
        ("package_promotion_execution_packet_authored", True),
        ("package_promotion_execution_packet_validated", True),
        ("package_promotion_next", True),
        ("package_promotion_authorized", False),
        ("package_promotion_executed", False),
        ("commercial_activation_claim_authorized", False),
        ("benchmark_prep_authorizes_package_promotion", False),
        ("seven_b_amplification_claimed_proven", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
    ],
)
def test_validation_preserves_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["validation_status"] == "PASS"
    assert payload["validated_hash"]


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_prep_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_execute_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_claim_7b_amplification_proven"] is True


def test_execution_claiming_already_executed_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution(tmp_path, monkeypatch)
    contract_path = reports / execution.OUTPUTS["execution_contract"]
    payload = _load(contract_path)
    payload["package_promotion_executed"] = True
    _write(contract_path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_EXEC_VAL_PACKAGE_EXECUTION_DRIFT"


def test_execution_claiming_commercial_activation_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["claim_ceiling_contract"]
    payload = _load(path)
    payload["commercial_claim"] = "commercial activation authorized"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_EXEC_VAL_CLAIM_TOKEN_DRIFT"


def test_execution_prep_only_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["package_promotion_run_result_schema_prep_only"]
    payload = _load(path)
    payload["authority"] = "AUTHORITATIVE"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_EXEC_VAL_PREP_ONLY_DRIFT"


def test_main_replay_requires_head_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_EXEC_VAL_NEXT_MOVE_DRIFT"


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_have_current_main_head(outputs: Path, role: str) -> None:
    assert _payload(outputs, role)["current_main_head"] == VALIDATION_MAIN_HEAD
