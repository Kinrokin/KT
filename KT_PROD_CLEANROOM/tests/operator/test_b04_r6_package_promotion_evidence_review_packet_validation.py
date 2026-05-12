from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_package_promotion_evidence_review_packet as review
from tools.operator import cohort0_b04_r6_package_promotion_evidence_review_packet_validation as validation


VALIDATION_HEAD = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
VALIDATION_MAIN_HEAD = "1b838e507a7bba167ebc3cc3cf9baeb7e3dbf1cd"


def _load_review_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_package_promotion_evidence_review_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_package_promotion_evidence_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load package promotion evidence review helpers")
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


def _run_review_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return review_helpers._run_review(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("package_promotion_evidence_review_validation")
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
        assert "commercial-activation review packet authorship" in text
        assert "does not authorize commercial activation claims" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_contract_preserves_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD
    assert _contract(outputs)["current_git_head"] == VALIDATION_MAIN_HEAD
    assert _contract(outputs)["current_branch_head"] == VALIDATION_HEAD


def test_validation_binds_package_promotion_evidence_review(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == review.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == review.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == review.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["review_contract_hash"]
    assert contract["binding_hashes"]["review_receipt_hash"]


def test_validation_selects_commercial_activation_review_authorship(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _payload(outputs, "validation_receipt")["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert _payload(outputs, "next_lawful_move")["commercial_activation_claim_authorized"] is False


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("r6_open", True),
        ("package_promotion_executed", True),
        ("package_promotion_passed", True),
        ("package_promotion_evidence_review_packet_authored", True),
        ("package_promotion_evidence_review_validated", True),
        ("commercial_activation_review_packet_next", True),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
        ("benchmark_prep_authorizes_package_promotion", False),
        ("seven_b_amplification_claimed_proven", False),
    ],
)
def test_validation_contract_preserves_authority_boundaries(outputs: Path, flag: str, expected: object) -> None:
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


def test_input_binding_rows_anchor_to_binding_hashes(outputs: Path) -> None:
    contract = _contract(outputs)
    for row in contract["input_bindings"]:
        assert contract["binding_hashes"][f"{row['role']}_hash"] == row["sha256"]


def test_scorecard_is_validated(outputs: Path) -> None:
    scorecard = _review_payload(outputs, "evidence_scorecard")
    assert scorecard["overall_grade"] == "A_REVIEWABLE"
    assert scorecard["package_promotion_passed"] is True
    assert scorecard["recommended_next_path"] == review.RECOMMENDED_NEXT_PATH
    assert scorecard["commercial_activation_claim_authorized"] is False
    assert _payload(outputs, "evidence_scorecard_validation")["validation_status"] == "PASS"


def test_decision_matrix_is_validated_as_review_packet_next_only(outputs: Path) -> None:
    matrix = _review_payload(outputs, "post_promotion_decision_matrix")
    assert matrix["recommended_next_path"] == review.RECOMMENDED_NEXT_PATH
    assert matrix["commercial_activation_review_ready"] is True
    assert matrix["commercial_activation_claim_status"] == "UNAUTHORIZED_REVIEW_ONLY"
    assert matrix["commercial_activation_claim_authorized"] is False
    assert _payload(outputs, "decision_matrix_validation")["validation_status"] == "PASS"


@pytest.mark.parametrize("role", review.REVIEW_CONTRACT_ROLES)
def test_review_contracts_are_validated(outputs: Path, role: str) -> None:
    validation_roles = {
        "release_truth_review": "release_truth_review_validation",
        "external_verifier_readiness_review": "external_verifier_readiness_validation",
        "commercial_claim_ceiling_review": "commercial_claim_ceiling_validation",
        "operator_runbook_review": "operator_runbook_validation",
        "deployment_profile_review": "deployment_profile_validation",
        "rollback_review": "rollback_validation",
        "incident_freeze_review": "incident_freeze_validation",
        "data_governance_review": "data_governance_validation",
        "public_verifier_bundle_review": "public_verifier_bundle_validation",
        "clean_distributable_review": "clean_distributable_validation",
    }
    assert _review_payload(outputs, role)["review_status"] == "BOUND"
    assert _payload(outputs, validation_roles[role])["validation_status"] == "PASS"


@pytest.mark.parametrize("role", review.PREP_ONLY_ROLES)
def test_prep_only_inputs_are_validated(outputs: Path, role: str) -> None:
    payload = _review_payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_prep_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True


@pytest.mark.parametrize("role", _json_output_roles())
def test_all_json_outputs_preserve_boundaries(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["package_promotion_passed"] is True
    assert payload["commercial_activation_claim_authorized"] is False
    assert payload["truth_engine_law_changed"] is False
    assert payload["trust_zone_law_changed"] is False


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, dirty=" M drift")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(validation.LaneFailure, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_packet_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["review_contract"]
    payload = _load(path)
    payload["selected_outcome"] = review.OUTCOME_INVALID
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="PACKET_OUTCOME_DRIFT"):
        validation.run(reports_root=reports)


def test_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PACKET"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_scorecard_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["evidence_scorecard"]
    payload = _load(path)
    payload["overall_grade"] = "D_DISQUALIFIER"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="SCORECARD_INCOMPLETE"):
        validation.run(reports_root=reports)


def test_decision_matrix_recommendation_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["post_promotion_decision_matrix"]
    payload = _load(path)
    payload["recommended_next_path"] = "EXTERNAL_AUDIT_DELTA_PACKET_NEXT"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="DECISION_MATRIX_UNJUSTIFIED"):
        validation.run(reports_root=reports)


def test_commercial_claim_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["post_promotion_decision_matrix"]
    payload = _load(path)
    payload["commercial_activation_claim_authorized"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="COMMERCIAL_CLAIM_DRIFT"):
        validation.run(reports_root=reports)


def test_claim_token_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["post_promotion_decision_matrix"]
    payload = _load(path)
    payload["commercial_claim"] = "AUTHORIZED"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        validation.run(reports_root=reports)


def test_lawful_self_replay_next_move_receipt_is_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation(tmp_path, monkeypatch)
    self_replay_payload = _load(reports / validation.OUTPUTS["next_lawful_move"])
    _write(reports / review.OUTPUTS["next_lawful_move"], self_replay_payload)
    _patch_validation_env(monkeypatch, tmp_path, branch=f"{validation.REPLAY_BRANCH_PREFIX}-test")
    validation.run(reports_root=reports)
    assert _load(reports / validation.OUTPUTS["validation_contract"])["selected_outcome"] == validation.SELECTED_OUTCOME


def test_malformed_self_replay_next_move_receipt_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation(tmp_path, monkeypatch)
    payload = _load(reports / validation.OUTPUTS["next_lawful_move"])
    payload["previous_next_lawful_move"] = "AUTHOR_B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PACKET"
    _write(reports / review.OUTPUTS["next_lawful_move"], payload)
    _patch_validation_env(monkeypatch, tmp_path, branch=f"{validation.REPLAY_BRANCH_PREFIX}-test")
    with pytest.raises(validation.LaneFailure, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_trust_zone_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "FAIL", "failures": ["boom"], "checks": []},
    )
    with pytest.raises(validation.LaneFailure, match="TRUST_ZONE_FAILED"):
        validation.run(reports_root=reports)
