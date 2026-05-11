from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_post_cutover_evidence_review_packet as review
from tools.operator import cohort0_b04_r6_post_cutover_evidence_review_packet_validation as validation


VALIDATION_HEAD = "abababababababababababababababababababab"
VALIDATION_MAIN_HEAD = "e9f9a51bbbf1c62e69d79b6edb6a420fa4a3efb6"


def _load_review_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_post_cutover_evidence_review_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_post_cutover_review_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load post-cutover review helpers")
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
    tmp_path = tmp_path_factory.mktemp("post_cutover_review_validation")
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


def _receipt(outputs: Path) -> dict:
    return _payload(outputs, "validation_receipt")


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
        assert "does not open r6" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_post_cutover_evidence_review_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == review.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == review.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == review.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["packet_contract_hash"]
    assert contract["binding_hashes"]["packet_receipt_hash"]


def test_validation_selects_r6_opening_review_packet_authorship(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["verdict"] == "POST_CUTOVER_EVIDENCE_REVIEW_VALIDATED_R6_OPENING_REVIEW_PACKET_NEXT"
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_report_states_non_authorization_boundaries(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "permits only r6 opening review packet authorship" in text
    assert "does not open r6" in text
    assert "does not promote package" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("runtime_cutover_executed", True),
        ("post_cutover_evidence_review_packet_authored", True),
        ("post_cutover_evidence_review_validated", True),
        ("r6_opening_review_packet_next", True),
        ("r6_opening_review_packet_authored", False),
        ("r6_opening_review_authorized", False),
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
        ("post_cutover_evidence_treated_as_r6_opening", False),
        ("post_cutover_evidence_treated_as_package_promotion", False),
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
    scorecard = _review_payload(outputs, "evidence_scorecard")["scorecard"]
    assert scorecard["overall_grade"] == "A_READY_FOR_R6_OPENING_REVIEW"
    assert scorecard["route_distribution_health"] == "PASS"
    assert scorecard["fallback_behavior"] == "PASS"
    assert scorecard["incident_freeze_clean"] is True
    assert scorecard["trace_completeness"] == "PASS"
    assert _payload(outputs, "evidence_scorecard_validation")["validation_status"] == "PASS"


def test_decision_matrix_is_validated_as_review_packet_next_only(outputs: Path) -> None:
    matrix = _review_payload(outputs, "decision_matrix")["decision_matrix"]
    assert matrix["recommended_next_path"] == review.RECOMMENDED_VALIDATED_PATH
    assert matrix["r6_opening_review_ready"] is True
    assert matrix["recommendation_is_authority"] is False
    assert matrix["package_promotion_ready"] is False
    assert matrix["commercial_claim_status"] == "BOUNDARY_ONLY"
    assert _payload(outputs, "decision_matrix_validation")["validation_status"] == "PASS"


@pytest.mark.parametrize(
    "role",
    [
        "r6_opening_readiness_matrix",
        "rollback_continuation_matrix",
        "package_promotion_blocker_matrix",
        "external_audit_delta_readiness",
        "public_verifier_readiness",
    ],
)
def test_readiness_artifacts_are_bound(outputs: Path, role: str) -> None:
    assert _review_payload(outputs, role)["selected_outcome"] == review.SELECTED_OUTCOME


@pytest.mark.parametrize("role", validation.REVIEW_ROLES)
def test_review_contracts_are_validated(outputs: Path, role: str) -> None:
    validation_roles = {
        "external_verifier_review": "external_verifier_readiness_validation",
        "commercial_claim_boundary_review": "commercial_claim_boundary_validation",
    }
    assert _review_payload(outputs, role)["review_status"] == "PASS"
    assert _payload(outputs, validation_roles.get(role, f"{role}_validation"))["validation_status"] == "PASS"


@pytest.mark.parametrize("role", review.PREP_ONLY_ROLES)
def test_prep_only_boundaries_are_validated(outputs: Path, role: str) -> None:
    payload = _review_payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_prep_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_package_promotion"] is True


@pytest.mark.parametrize("role", _json_output_roles())
def test_all_json_outputs_preserve_boundaries(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["r6_open"] is False
    assert payload["package_promotion_authorized"] is False
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
    path = reports / review.OUTPUTS["packet_contract"]
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
    payload["next_lawful_move"] = "AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_scorecard_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["evidence_scorecard"]
    payload = _load(path)
    payload["scorecard"]["trace_completeness"] = "FAIL"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="SCORECARD_MISSING"):
        validation.run(reports_root=reports)


def test_decision_matrix_recommendation_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["decision_matrix"]
    payload = _load(path)
    payload["decision_matrix"]["recommended_next_path"] = "PACKAGE_PROMOTION_REVIEW_PACKET_NEXT"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="DECISION_MATRIX_UNJUSTIFIED"):
        validation.run(reports_root=reports)


def test_review_contract_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["fallback_behavior_review"]
    payload = _load(path)
    payload["review_status"] = "FAIL"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="REVIEW_CONTRACT_MISSING"):
        validation.run(reports_root=reports)


def test_claim_token_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["decision_matrix"]
    payload = _load(path)
    payload["r6_status"] = "OPEN"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        validation.run(reports_root=reports)
