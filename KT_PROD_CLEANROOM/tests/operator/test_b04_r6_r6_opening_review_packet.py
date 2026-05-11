from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_post_cutover_evidence_review_packet_validation as prior
from tools.operator import cohort0_b04_r6_r6_opening_review_packet as review


REVIEW_HEAD = "1212121212121212121212121212121212121212"
REVIEW_MAIN_HEAD = "ea3018d74cff36c5df9291ce4c9519685a706ac1"


def _load_prior_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_post_cutover_evidence_review_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_post_cutover_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load post-cutover validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prior_helpers = _load_prior_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_review_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = review.AUTHORITY_BRANCH,
    head: str = REVIEW_HEAD,
    origin_main: str = REVIEW_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(review, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(review.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(review.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(review.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        review,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_prior_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return prior_helpers._run_validation(tmp_path, monkeypatch)


def _run_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path)
    review.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("r6_opening_review")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_review(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / review.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "packet_contract")


def _scorecard(outputs: Path) -> dict:
    return _payload(outputs, "opening_review_scorecard")["scorecard"]


def _decision(outputs: Path) -> dict:
    return _payload(outputs, "opening_decision_matrix")["decision_matrix"]


def _json_roles() -> list[str]:
    return sorted(role for role, filename in review.OUTPUTS.items() if filename.endswith(".json"))


@pytest.mark.parametrize("filename", sorted(review.OUTPUTS.values()))
def test_required_r6_opening_review_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        text = path.read_text(encoding="utf-8").lower()
        assert "r6 opening review packet" in text
        assert "does not open r6" in text


def test_r6_opening_review_preserves_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == REVIEW_MAIN_HEAD


def test_r6_opening_review_binds_post_cutover_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == prior.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == prior.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == prior.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["validation_contract_hash"]
    assert contract["binding_hashes"]["source_evidence_scorecard_hash"]


def test_overwritten_inputs_are_marked_as_pre_overwrite_bindings(outputs: Path) -> None:
    rows = {row["role"]: row for row in _contract(outputs)["input_bindings"]}
    for role in ("source_pipeline_board", "source_campaign_board", "source_future_blocker_register", "source_next_lawful_move"):
        assert rows[role]["overwritten_by_r6_opening_review_output"] is True
        assert rows[role]["binding_kind"] == "pre_overwrite_file_sha256_at_r6_opening_review_authoring"
        assert rows[role]["git_object_before_overwrite"]


def test_r6_opening_review_selects_validation_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == review.SELECTED_OUTCOME
    assert _contract(outputs)["next_lawful_move"] == review.NEXT_LAWFUL_MOVE
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == review.NEXT_LAWFUL_MOVE


def test_decision_matrix_recommends_authorization_packet_only(outputs: Path) -> None:
    decision = _decision(outputs)
    assert decision["recommended_next_path"] == review.RECOMMENDED_VALIDATED_PATH
    assert decision["recommendation_is_authority"] is False
    assert decision["r6_opening_authorization_review_ready"] is True
    assert decision["package_promotion_ready"] is False


@pytest.mark.parametrize(
    "field,expected",
    [
        ("post_cutover_evidence_review_validated", True),
        ("runtime_cutover_passed", True),
        ("fallbacks_preserved", True),
        ("operator_controls_preserved", True),
        ("kill_switch_ready", True),
        ("rollback_ready", True),
        ("drift_bounded", True),
        ("incident_freeze_clean", True),
        ("trace_replay_complete", True),
        ("external_verifier_ready", True),
        ("commercial_claim_boundary_preserved", True),
        ("package_promotion_ready", False),
        ("r6_open_ready", False),
    ],
)
def test_scorecard_grades_required_opening_categories(outputs: Path, field: str, expected: object) -> None:
    assert _scorecard(outputs)[field] == expected


@pytest.mark.parametrize("role", review.REVIEW_CONTRACT_ROLES)
def test_review_contracts_pass(outputs: Path, role: str) -> None:
    assert _payload(outputs, role)["review_status"] == "PASS"


@pytest.mark.parametrize("role", review.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("runtime_cutover_executed", True),
        ("post_cutover_evidence_review_validated", True),
        ("r6_opening_review_packet_authored", True),
        ("r6_opening_review_validated", False),
        ("r6_opening_authorized", False),
        ("r6_open", False),
        ("global_runtime_surface_authorized", False),
        ("lobe_escalation_authorized", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("trust_zone_law_changed", False),
        ("metric_contract_mutated", False),
        ("static_comparator_weakened", False),
        ("opening_review_treated_as_r6_opening", False),
        ("opening_review_treated_as_package_promotion", False),
    ],
)
def test_all_json_outputs_preserve_authority_boundaries(
    outputs: Path, role: str, field: str, expected: object
) -> None:
    assert _payload(outputs, role)[field] == expected


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, dirty=" M file")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        review.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, branch="feature/not-lawful")
    with pytest.raises(review.LaneFailure, match="branch"):
        review.run(reports_root=reports)


def test_previous_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    contract_path = reports / prior.OUTPUTS["validation_contract"]
    payload = _load(contract_path)
    payload["selected_outcome"] = "WRONG"
    _write(contract_path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="PREVIOUS_OUTCOME_DRIFT"):
        review.run(reports_root=reports)


def test_r6_open_claim_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    contract_path = reports / prior.OUTPUTS["validation_contract"]
    payload = _load(contract_path)
    payload["r6_status"] = "OPEN"
    _write(contract_path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        review.run(reports_root=reports)


def test_scorecard_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    scorecard_path = reports / prior.review.OUTPUTS["evidence_scorecard"]
    payload = _load(scorecard_path)
    payload["scorecard"]["kill_switch_ready"] = False
    _write(scorecard_path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="SCORECARD_INCOMPLETE"):
        review.run(reports_root=reports)
