from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_package_promotion_review_packet as package_review
from tools.operator import cohort0_b04_r6_r6_opening_evidence_review_packet_validation as opening_validation


PACKAGE_REVIEW_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
PACKAGE_REVIEW_MAIN_HEAD = "88006dfffe006761bf144e6961ea43d50bd74571"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_r6_opening_evidence_review_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_opening_evidence_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load R6 opening evidence validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_package_review_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = package_review.AUTHORITY_BRANCH,
    head: str = PACKAGE_REVIEW_HEAD,
    origin_main: str = PACKAGE_REVIEW_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(package_review, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(package_review.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(package_review.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(package_review.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        package_review,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_opening_evidence_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_package_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_opening_evidence_validation(tmp_path, monkeypatch)
    _patch_package_review_env(monkeypatch, tmp_path)
    package_review.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("package_promotion_review_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_package_review(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / package_review.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "packet_contract")


def _scorecard(outputs: Path) -> dict:
    return _payload(outputs, "evidence_scorecard")["scorecard"]


def _decision(outputs: Path) -> dict:
    return _payload(outputs, "decision_matrix")["decision_matrix"]


def _json_roles() -> list[str]:
    return sorted(role for role, filename in package_review.OUTPUTS.items() if filename.endswith(".json"))


def test_reason_codes_are_unique() -> None:
    assert len(package_review.REASON_CODES) == len(set(package_review.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(package_review.OUTPUTS.values()))
def test_required_package_promotion_review_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "package-promotion review packet" in text
        assert "does not authorize package promotion" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == PACKAGE_REVIEW_MAIN_HEAD


def test_packet_binds_r6_opening_evidence_review_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == package_review.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == opening_validation.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == opening_validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == opening_validation.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["validation_contract_hash"]
    assert contract["binding_hashes"]["validation_receipt_hash"]


def test_packet_selects_package_promotion_review_validation_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == package_review.SELECTED_OUTCOME
    assert _contract(outputs)["next_lawful_move"] == package_review.NEXT_LAWFUL_MOVE
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == package_review.NEXT_LAWFUL_MOVE


def test_decision_matrix_recommends_authorization_packet_without_authority(outputs: Path) -> None:
    decision = _decision(outputs)
    assert decision["recommended_next_path"] == package_review.RECOMMENDED_VALIDATED_PATH
    assert decision["recommendation_is_authority"] is False
    assert decision["package_promotion_authorization_packet_ready"] is True
    assert decision["package_promotion_ready"] is False
    assert decision["package_promotion_authorized"] is False


def test_decision_matrix_derives_from_readiness() -> None:
    scorecard = {
        "r6_open": True,
        "r6_opening_evidence_review_validated": True,
        "package_promotion_review_packet_next": True,
        "external_audit_delta_ready": False,
        "public_verifier_ready": True,
        "commercial_claim_boundary_preserved": True,
        "no_authorization_drift": True,
        "blocking_reasons": [],
    }
    decision = package_review._decision_matrix(scorecard)
    assert decision["recommended_next_path"] == "EXTERNAL_AUDIT_DELTA_PACKET_NEXT"
    assert decision["package_promotion_authorization_packet_ready"] is False


@pytest.mark.parametrize(
    "field,expected",
    [
        ("r6_open", True),
        ("r6_opening_evidence_review_validated", True),
        ("package_promotion_review_packet_next", True),
        ("package_promotion_review_ready", True),
        ("package_promotion_authorization_ready", True),
        ("package_promotion_ready", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("external_audit_delta_ready", True),
        ("public_verifier_ready", True),
        ("release_truth_derivation_ready", True),
        ("commercial_claim_boundary_preserved", True),
        ("no_authorization_drift", True),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_unchanged", True),
    ],
)
def test_scorecard_grades_required_categories(outputs: Path, field: str, expected: object) -> None:
    assert _scorecard(outputs)[field] == expected


@pytest.mark.parametrize(
    "role",
    [
        "release_truth_derivation_review",
        "external_audit_delta_readiness_review",
        "public_verifier_readiness_review",
        "commercial_claim_boundary_review",
    ],
)
def test_review_contracts_pass(outputs: Path, role: str) -> None:
    assert _payload(outputs, role)["review_status"] == "PASS"


@pytest.mark.parametrize("role", package_review.PREP_ONLY_ROLES)
def test_downstream_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_execute_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


def test_package_promotion_review_validation_artifact_ids_are_not_duplicated(outputs: Path) -> None:
    assert (
        _payload(outputs, "package_promotion_review_validation_plan")["artifact_id"]
        == "B04_R6_PACKAGE_PROMOTION_REVIEW_VALIDATION_PLAN"
    )
    assert (
        _payload(outputs, "package_promotion_review_validation_reason_codes")["artifact_id"]
        == "B04_R6_PACKAGE_PROMOTION_REVIEW_VALIDATION_REASON_CODES"
    )


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("r6_open", True),
        ("package_promotion_review_packet_authored", True),
        ("package_promotion_review_validated", False),
        ("package_promotion_authorization_packet_authored", False),
        ("package_promotion_authorized", False),
        ("package_promotion_executed", False),
        ("commercial_activation_claim_authorized", False),
        ("lobe_escalation_authorized", False),
        ("truth_engine_law_changed", False),
        ("trust_zone_law_changed", False),
        ("r6_open_treated_as_package_promotion", False),
        ("package_promotion_treated_as_commercial_activation", False),
    ],
)
def test_all_json_outputs_preserve_authority_boundaries(
    outputs: Path, role: str, field: str, expected: object
) -> None:
    assert _payload(outputs, role)[field] == expected


def test_pipeline_board_routes_to_validation(outputs: Path) -> None:
    lanes = {row["lane"]: row["status"] for row in _payload(outputs, "pipeline_board")["lanes"]}
    assert lanes["AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET"] == "CURRENT_BOUND"
    assert lanes["VALIDATE_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET"] == "NEXT"
    assert lanes["PACKAGE_PROMOTION_AUTHORIZATION"] == "RECOMMENDED_NOT_AUTHORIZED"


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _payload(outputs, "no_authorization_drift_receipt")
    assert receipt["validation_status"] == "PASS"
    assert receipt["no_downstream_authorization_drift"] is True


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_evidence_validation(tmp_path, monkeypatch)
    _patch_package_review_env(monkeypatch, tmp_path, dirty=" M drift")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        package_review.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_evidence_validation(tmp_path, monkeypatch)
    _patch_package_review_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(package_review.LaneFailure, match="NEXT_MOVE_DRIFT"):
        package_review.run(reports_root=reports)


def test_previous_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_evidence_validation(tmp_path, monkeypatch)
    path = reports / opening_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["selected_outcome"] = opening_validation.OUTCOME_INVALID
    _write(path, payload)
    _patch_package_review_env(monkeypatch, tmp_path)
    with pytest.raises(package_review.LaneFailure, match="VALIDATION_OUTCOME_DRIFT"):
        package_review.run(reports_root=reports)


def test_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_evidence_validation(tmp_path, monkeypatch)
    path = reports / opening_validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_PACKET"
    _write(path, payload)
    _patch_package_review_env(monkeypatch, tmp_path)
    with pytest.raises(package_review.LaneFailure, match="NEXT_MOVE_DRIFT"):
        package_review.run(reports_root=reports)


def test_r6_opening_evidence_review_validation_truth_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _run_opening_evidence_validation(tmp_path, monkeypatch)
    path = reports / opening_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["r6_opening_evidence_review_validated"] = False
    _write(path, payload)
    _patch_package_review_env(monkeypatch, tmp_path)
    with pytest.raises(package_review.LaneFailure, match="VALIDATION_OUTCOME_DRIFT"):
        package_review.run(reports_root=reports)


def test_claim_token_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_evidence_validation(tmp_path, monkeypatch)
    path = reports / opening_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["package_promotion"] = "AUTHORIZED"
    _write(path, payload)
    _patch_package_review_env(monkeypatch, tmp_path)
    with pytest.raises(package_review.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        package_review.run(reports_root=reports)


def test_package_promotion_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_evidence_validation(tmp_path, monkeypatch)
    path = reports / opening_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["package_promotion_authorized"] = True
    _write(path, payload)
    _patch_package_review_env(monkeypatch, tmp_path)
    with pytest.raises(package_review.LaneFailure, match="PACKAGE_PROMOTION_DRIFT"):
        package_review.run(reports_root=reports)


def test_no_authorization_drift_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_evidence_validation(tmp_path, monkeypatch)
    path = reports / opening_validation.OUTPUTS["no_authorization_drift_validation"]
    payload = _load(path)
    payload["no_authorization_drift"] = False
    _write(path, payload)
    _patch_package_review_env(monkeypatch, tmp_path)
    with pytest.raises(package_review.LaneFailure, match="READINESS_INCOMPLETE"):
        package_review.run(reports_root=reports)


def test_trust_zone_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_evidence_validation(tmp_path, monkeypatch)
    _patch_package_review_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        package_review,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "FAIL", "failures": ["boom"], "checks": []},
    )
    with pytest.raises(package_review.LaneFailure, match="TRUST_ZONE_FAILED"):
        package_review.run(reports_root=reports)
