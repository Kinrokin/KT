from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_commercial_activation as activation
from tools.operator import cohort0_b04_r6_commercial_activation_execution_packet_validation as validation


ACTIVATION_HEAD = "abababababababababababababababababababab"
ACTIVATION_MAIN_HEAD = "506e42d23a6a311d1ab850a77ad8ab67580e96cd"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_commercial_activation_execution_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_commercial_activation_exec_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load commercial activation execution validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_activation_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = activation.AUTHORITY_BRANCH,
    head: str = ACTIVATION_HEAD,
    origin_main: str = ACTIVATION_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(activation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(activation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(activation.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(activation.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(activation, "_git_is_ancestor", lambda root, ancestor, descendant: True)
    monkeypatch.setattr(activation, "_git_blob_sha256", lambda root, commit, raw: "b" * 64)
    monkeypatch.setattr(
        activation,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_execution_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_activation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    _patch_activation_env(monkeypatch, tmp_path)
    activation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("commercial_activation_run")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_activation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / activation.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "activation_contract")


def _json_roles() -> list[str]:
    return sorted(role for role, filename in activation.OUTPUTS.items() if filename.endswith(".json"))


def test_reason_codes_are_unique() -> None:
    assert len(activation.REASON_CODES) == len(set(activation.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(activation.OUTPUTS.values()))
def test_required_activation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "commercial activation passed" in text
        assert "claims remain unauthorized" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_activation_binds_execution_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == activation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["validation_contract_hash"]
    assert contract["binding_hashes"]["validation_receipt_hash"]


def test_activation_selects_evidence_review_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == activation.SELECTED_OUTCOME
    assert _payload(outputs, "activation_receipt")["selected_outcome"] == activation.SELECTED_OUTCOME
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == activation.NEXT_LAWFUL_MOVE


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("r6_open", True),
        ("package_promotion_passed", True),
        ("commercial_activation_execution_packet_validated", True),
        ("commercial_activation_authorized", True),
        ("commercial_activation_executed", True),
        ("commercial_activation_passed", True),
        ("commercial_activation_evidence_review_packet_next", True),
        ("commercial_activation_claim_authorized", False),
        ("benchmark_prep_authorizes_commercial_activation", False),
        ("seven_b_amplification_claimed_proven", False),
        ("follow_up_audit_readiness_validated", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
    ],
)
def test_activation_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", activation.ACTIVATION_RECEIPT_ROLES)
def test_activation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["receipt_status"] == "PASS"
    assert payload["checks"]


@pytest.mark.parametrize("role", activation.PREP_ONLY_ROLES)
def test_downstream_prep_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_claim_7b_amplification_proven"] is True
    assert payload["cannot_validate_follow_up_audit_readiness"] is True


def test_claim_authorization_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    contract_path = reports / validation.OUTPUTS["validation_contract"]
    payload = _load(contract_path)
    payload["commercial_activation_claim_authorized"] = True
    _write(contract_path, payload)
    _patch_activation_env(monkeypatch, tmp_path)
    with pytest.raises(activation.LaneFailure) as excinfo:
        activation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_CLAIM_DRIFT"


def test_claim_text_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["commercial_claim"] = "commercial activation claims authorized"
    _write(path, payload)
    _patch_activation_env(monkeypatch, tmp_path)
    with pytest.raises(activation.LaneFailure) as excinfo:
        activation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_CLAIM_TOKEN_DRIFT"


def test_authorization_wording_cannot_mask_positive_claim_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["commercial_claim"] = "commercial activation claim authorization active"
    _write(path, payload)
    _patch_activation_env(monkeypatch, tmp_path)
    with pytest.raises(activation.LaneFailure) as excinfo:
        activation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_CLAIM_TOKEN_DRIFT"


def test_validation_prep_only_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["commercial_activation_run_prep_only_draft"]
    payload = _load(path)
    payload["authority"] = "AUTHORITATIVE"
    _write(path, payload)
    _patch_activation_env(monkeypatch, tmp_path)
    with pytest.raises(activation.LaneFailure) as excinfo:
        activation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_PREP_ONLY_DRIFT"


def test_validation_source_hash_mismatch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    contract_path = reports / validation.OUTPUTS["validation_contract"]
    contract = _load(contract_path)
    first_binding = contract["input_bindings"][0]
    target = tmp_path / first_binding["path"]
    target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    _patch_activation_env(monkeypatch, tmp_path)
    with pytest.raises(activation.LaneFailure) as excinfo:
        activation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_INPUT_HASH_MISMATCH"


def test_main_replay_uses_validation_main_for_overwritten_activation_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    contract_path = reports / validation.OUTPUTS["validation_contract"]
    contract = _load(contract_path)
    contract["current_git_head"] = contract["current_main_head"]
    contract["current_branch_head"] = contract["current_main_head"]
    _write(contract_path, contract)
    claim_binding = next(row for row in contract["input_bindings"] if row["role"] == "claim_ceiling_current_state")
    target = tmp_path / claim_binding["path"]
    target.write_text('{"post_activation": "overwrite"}\n', encoding="utf-8")
    replay_head = "9" * 40
    _patch_activation_env(monkeypatch, tmp_path, branch="main", head=replay_head, origin_main=replay_head)
    calls: list[tuple[str, str]] = []

    def fake_git_blob_sha256(root: Path, commit: str, raw: str) -> str:
        calls.append((commit, raw))
        if commit == contract["current_main_head"] and raw == claim_binding["path"]:
            return claim_binding["sha256"]
        return "0" * 64

    monkeypatch.setattr(activation, "_git_blob_sha256", fake_git_blob_sha256)
    activation.run(reports_root=reports)
    assert (contract["current_main_head"], claim_binding["path"]) in calls


def test_main_replay_fallback_head_must_be_replay_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    contract_path = reports / validation.OUTPUTS["validation_contract"]
    contract = _load(contract_path)
    claim_binding = next(row for row in contract["input_bindings"] if row["role"] == "claim_ceiling_current_state")
    target = tmp_path / claim_binding["path"]
    target.write_text('{"post_activation": "overwrite"}\n', encoding="utf-8")
    replay_head = "9" * 40
    _patch_activation_env(monkeypatch, tmp_path, branch="main", head=replay_head, origin_main=replay_head)

    def fake_git_blob_sha256(root: Path, commit: str, raw: str) -> str:
        if commit == contract["current_main_head"] and raw == claim_binding["path"]:
            return claim_binding["sha256"]
        return "0" * 64

    monkeypatch.setattr(activation, "_git_blob_sha256", fake_git_blob_sha256)
    with pytest.raises(activation.LaneFailure) as excinfo:
        activation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_PREDECESSOR_MAIN_DRIFT"


def test_predecessor_not_in_current_main_lineage_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    _patch_activation_env(monkeypatch, tmp_path)
    monkeypatch.setattr(activation, "_git_is_ancestor", lambda root, ancestor, descendant: False)
    with pytest.raises(activation.LaneFailure) as excinfo:
        activation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_PREDECESSOR_MAIN_DRIFT"


def test_main_replay_requires_head_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    _patch_activation_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(activation.LaneFailure) as excinfo:
        activation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_NEXT_MOVE_DRIFT"


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_have_current_main_head(outputs: Path, role: str) -> None:
    assert _payload(outputs, role)["current_main_head"] == ACTIVATION_MAIN_HEAD


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_record_branch_head_as_current_git_head(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["current_git_head"] == ACTIVATION_HEAD
    assert payload["current_branch_head"] == ACTIVATION_HEAD
