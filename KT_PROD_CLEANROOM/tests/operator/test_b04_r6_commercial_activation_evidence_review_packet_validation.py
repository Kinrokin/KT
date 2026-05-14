from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_commercial_activation_evidence_review_packet as review
from tools.operator import cohort0_b04_r6_commercial_activation_evidence_review_packet_validation as validation


VALIDATION_HEAD = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
REPLAY_BOUND_MAIN = "aa80cb56fff06de35feade4337a7e839c58a8abd"


def _load_review_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_commercial_activation_evidence_review_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_commercial_activation_evidence_review_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load commercial activation evidence review helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


review_helpers = _load_review_helpers()


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
    origin_main: str = REPLAY_BOUND_MAIN,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    contract_path = tmp_path / "KT_PROD_CLEANROOM/reports" / review.OUTPUTS["review_contract"]
    fallback_hashes = {}
    if contract_path.exists():
        contract = _load(contract_path)
        fallback_hashes = {row["path"]: row["sha256"] for row in contract.get("input_bindings", [])}
    monkeypatch.setattr(validation, "_git_blob_hash", lambda root, commit, raw_path: fallback_hashes.get(raw_path))
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_replay_bound_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = review_helpers._run_activation(tmp_path, monkeypatch)
    review_helpers._patch_review_env(
        monkeypatch,
        tmp_path,
        branch="main",
        head=REPLAY_BOUND_MAIN,
        origin_main=REPLAY_BOUND_MAIN,
    )
    review.run(reports_root=reports)
    return reports


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_replay_bound_review(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("commercial_activation_evidence_review_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_validation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / validation.OUTPUTS[role])


def _review_payload(outputs: Path, role: str) -> dict:
    return _load(outputs / review.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "validation_contract")


def _json_output_roles() -> list[str]:
    return sorted(role for role, filename in validation.OUTPUTS.items() if filename.endswith(".json"))


def test_reason_codes_are_unique() -> None:
    assert len(validation.REASON_CODES) == len(set(validation.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "commercial activation evidence review validates" in text
        assert "does not authorize commercial activation claims" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_contract_binds_replayed_evidence_review(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == review.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == review.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == review.NEXT_LAWFUL_MOVE
    assert contract["current_main_head"] == REPLAY_BOUND_MAIN
    assert contract["current_git_head"] == REPLAY_BOUND_MAIN
    assert contract["current_branch_head"] == VALIDATION_HEAD


def test_validation_routes_to_follow_up_audit_readiness_packet(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _payload(outputs, "validation_receipt")["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert _payload(outputs, "next_lawful_move")["commercial_activation_claim_authorized"] is False


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("r6_open", True),
        ("package_promotion_passed", True),
        ("commercial_activation_executed", True),
        ("commercial_activation_passed", True),
        ("commercial_activation_evidence_review_packet_authored", True),
        ("commercial_activation_evidence_review_validated", True),
        ("follow_up_audit_readiness_packet_next", True),
        ("follow_up_audit_readiness_validated", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
        ("benchmark_prep_authorizes_commercial_activation", False),
        ("seven_b_amplification_claimed_proven", False),
    ],
)
def test_validation_preserves_authority_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", sorted(validation.REVIEW_JSON_INPUTS))
def test_validation_binds_all_review_json_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(validation.REVIEW_TEXT_INPUTS))
def test_validation_binds_all_review_text_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_review_packet_source_bindings_are_recomputed(outputs: Path) -> None:
    review_contract = _review_payload(outputs, "review_contract")
    for row in review_contract["input_bindings"]:
        assert review_contract["binding_hashes"][f"{row['role']}_hash"] == row["sha256"]


def test_scorecard_and_readiness_matrices_are_validated(outputs: Path) -> None:
    scorecard = _review_payload(outputs, "evidence_scorecard")
    claim_matrix = _review_payload(outputs, "claim_authorization_readiness_matrix")
    assert scorecard["overall_grade"] == "A_REVIEWABLE"
    assert scorecard["recommended_next_path"] == review.RECOMMENDED_NEXT_PATH
    assert claim_matrix["claim_authorization_ready"] is False
    assert claim_matrix["readiness_status"] == "FOLLOW_UP_AUDIT_REVIEW_FIRST"
    assert _payload(outputs, "evidence_scorecard_validation")["validation_status"] == "PASS"
    assert _payload(outputs, "claim_authorization_readiness_validation")["validation_status"] == "PASS"


@pytest.mark.parametrize("role", review.REVIEW_CONTRACT_ROLES)
def test_review_contracts_are_validated(outputs: Path, role: str) -> None:
    validation_role = {
        "claim_ceiling_review": "claim_ceiling_review_validation",
        "allowed_forbidden_claims_review": "allowed_forbidden_claims_validation",
        "package_promotion_evidence_review": "package_promotion_evidence_validation",
        "r6_opening_evidence_review": "r6_opening_evidence_validation",
        "runtime_cutover_evidence_review": "runtime_cutover_evidence_validation",
        "external_verifier_readiness_review": "external_verifier_readiness_validation",
        "operator_runbook_readiness_review": "operator_runbook_readiness_validation",
        "deployment_profile_readiness_review": "deployment_profile_readiness_validation",
        "incident_freeze_review": "incident_freeze_validation",
        "rollback_review": "rollback_validation",
        "provider_benchmark_prep_review": "provider_benchmark_prep_validation",
    }[role]
    assert _review_payload(outputs, role)["review_status"] == "BOUND"
    assert _payload(outputs, validation_role)["validation_status"] == "PASS"


@pytest.mark.parametrize("role", review.PREP_ONLY_ROLES)
def test_prep_only_inputs_are_validated(outputs: Path, role: str) -> None:
    payload = _review_payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_validate_follow_up_audit_readiness"] is True
    assert _payload(outputs, "prep_only_boundary_validation")["validation_status"] == "PASS"


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_prep_outputs_are_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_validate_follow_up_audit_readiness"] is True
    assert payload["cannot_claim_7b_amplification_proven"] is True


def test_claim_text_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_replay_bound_review(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["commercial_claim_ceiling_update"]
    payload = _load(path)
    payload["allowed_claims"].append("Commercial activation claims authorized.")
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_EVID_VAL_CLAIM_TOKEN_DRIFT"


def test_input_binding_hash_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_replay_bound_review(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["review_contract"]
    payload = _load(path)
    payload["input_bindings"][0]["sha256"] = "0" * 64
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code in {
        "RC_B04R6_COMMERCIAL_ACTIVATION_EVID_VAL_INPUT_HASH_MISSING",
        "RC_B04R6_COMMERCIAL_ACTIVATION_EVID_VAL_INPUT_HASH_MISMATCH",
    }


def test_preoverwrite_fallback_requires_replay_bound_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_replay_bound_review(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["review_contract"]
    payload = _load(path)
    payload["current_branch_head"] = "f" * 40
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_EVID_VAL_INPUT_HASH_MISMATCH"


def test_validation_fails_if_claim_authorization_readiness_drifts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_replay_bound_review(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["claim_authorization_readiness_matrix"]
    payload = _load(path)
    payload["claim_authorization_ready"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_EVID_VAL_DECISION_MATRIX_UNJUSTIFIED"


def test_main_replay_requires_head_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_replay_bound_review(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_EVID_VAL_NEXT_MOVE_DRIFT"


@pytest.mark.parametrize("role", _json_output_roles())
def test_all_json_outputs_record_expected_heads(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["current_main_head"] == REPLAY_BOUND_MAIN
    assert payload["current_git_head"] == REPLAY_BOUND_MAIN
    assert payload["current_branch_head"] == VALIDATION_HEAD
