from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_commercial_activation_authorization_packet as authorization
from tools.operator import cohort0_b04_r6_commercial_activation_review_packet_validation as review_validation
from tools.operator import kt_provider_benchmark_harness


AUTH_HEAD = "abababababababababababababababababababab"
AUTH_MAIN_HEAD = "a0c90bd196152a51ff3dd5e36265314b8602453a"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_commercial_activation_review_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_commercial_review_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load commercial review validation helpers")
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
    branch: str = authorization.AUTHORITY_BRANCH,
    head: str = AUTH_HEAD,
    origin_main: str = AUTH_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(authorization, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(authorization.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(authorization.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(authorization.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        authorization,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_review_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_authorization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_review_validation(tmp_path, monkeypatch)
    _patch_auth_env(monkeypatch, tmp_path)
    authorization.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("commercial_activation_authorization_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_authorization(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / authorization.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "authorization_contract")


def _json_roles() -> list[str]:
    return sorted(role for role, filename in authorization.OUTPUTS.items() if filename.endswith(".json"))


def test_reason_codes_are_unique() -> None:
    assert len(authorization.REASON_CODES) == len(set(authorization.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(authorization.OUTPUTS.values()))
def test_required_authorization_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "commercial activation authorization packet" in text
        assert "does not execute commercial activation" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_authorization_packet_binds_validated_commercial_activation_review(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == authorization.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == review_validation.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == review_validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == review_validation.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["validation_contract_hash"]
    assert contract["binding_hashes"]["validation_receipt_hash"]


def test_authorization_packet_selects_validation_next(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["selected_outcome"] == authorization.SELECTED_OUTCOME
    assert contract["next_lawful_move"] == authorization.NEXT_LAWFUL_MOVE
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == authorization.NEXT_LAWFUL_MOVE


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("r6_open", True),
        ("package_promotion_executed", True),
        ("package_promotion_passed", True),
        ("package_promotion_evidence_review_validated", True),
        ("commercial_activation_review_packet_validated", True),
        ("commercial_activation_authorization_packet_authored", True),
        ("commercial_activation_authorization_validated", False),
        ("commercial_activation_execution_packet_authored", False),
        ("commercial_activation_claim_authorized", False),
        ("commercial_activation_executed", False),
        ("benchmark_prep_authorizes_commercial_activation", False),
        ("seven_b_amplification_claimed_proven", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
    ],
)
def test_authorization_preserves_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", authorization.AUTHORIZATION_CONTRACT_ROLES)
def test_authorization_contracts_are_bound(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["contract_status"] == "BOUND"
    assert payload["requirements"]


@pytest.mark.parametrize("role", authorization.PREP_ONLY_ROLES)
def test_downstream_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_execute_commercial_activation"] is True
    assert payload["cannot_mutate_truth_engine_law"] is True
    assert payload["cannot_mutate_trust_zone_law"] is True


@pytest.mark.parametrize("role", authorization.BENCHMARK_PREP_ROLES)
def test_benchmark_outputs_remain_prep_only_and_non_claiming(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["benchmark_authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_claim_7b_amplification_proven"] is True
    assert payload["governing_statement"] == authorization.BENCHMARK_GOVERNING_STATEMENT
    assert payload["metric"] == "lawful_replayable_progress_per_dollar"


def test_claim_ceiling_allows_only_current_truth(outputs: Path) -> None:
    ceiling = _payload(outputs, "claim_ceiling_current_state")
    assert "Commercial activation review is validated." in ceiling["allowed_claims"]
    assert "Commercial activation is not executed." in ceiling["allowed_claims"]
    assert "KT is commercially activated." in ceiling["forbidden_claims"]
    assert "7B amplification is proven." in ceiling["forbidden_claims"]


def test_provider_benchmark_harness_remains_prep_only() -> None:
    payload = kt_provider_benchmark_harness.build_scorecard()
    assert payload["authority"] == "PREP_ONLY"
    assert payload["metric"] == "lawful_replayable_progress_per_dollar"
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_claim_7b_amplification_proven"] is True
    assert payload["governing_statement"] == authorization.BENCHMARK_GOVERNING_STATEMENT


def test_prior_commercial_claim_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_validation(tmp_path, monkeypatch)
    contract_path = reports / review_validation.OUTPUTS["validation_contract"]
    payload = _load(contract_path)
    payload["commercial_activation_claim_authorized"] = True
    _write(contract_path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(authorization.LaneFailure) as excinfo:
        authorization.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_COMMERCIAL_CLAIM_DRIFT"


def test_prior_commercial_execution_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_validation(tmp_path, monkeypatch)
    contract_path = reports / review_validation.OUTPUTS["validation_contract"]
    payload = _load(contract_path)
    payload["commercial_activation_executed"] = True
    _write(contract_path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(authorization.LaneFailure) as excinfo:
        authorization.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_EXECUTION_DRIFT"


def test_claim_token_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_validation(tmp_path, monkeypatch)
    next_path = reports / review_validation.OUTPUTS["next_lawful_move"]
    payload = _load(next_path)
    payload["commercial_claim"] = "commercial activation executed"
    _write(next_path, payload)
    _patch_auth_env(monkeypatch, tmp_path)
    with pytest.raises(authorization.LaneFailure) as excinfo:
        authorization.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_CLAIM_TOKEN_DRIFT"


def test_main_replay_requires_head_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_validation(tmp_path, monkeypatch)
    _patch_auth_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(authorization.LaneFailure) as excinfo:
        authorization.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_NEXT_MOVE_DRIFT"


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_have_current_main_head(outputs: Path, role: str) -> None:
    assert _payload(outputs, role)["current_main_head"] == AUTH_MAIN_HEAD
