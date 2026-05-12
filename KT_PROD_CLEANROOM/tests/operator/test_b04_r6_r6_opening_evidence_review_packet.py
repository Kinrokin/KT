from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_r6_opening as opening
from tools.operator import cohort0_b04_r6_r6_opening_evidence_review_packet as review
from tools.operator.titanium_common import file_sha256


REVIEW_HEAD = "9999999999999999999999999999999999999999"
REVIEW_MAIN_HEAD = "7f81474828c09f57251dd9f58df4d33e0e25e4aa"


def _load_opening_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_r6_opening.py")
    spec = importlib.util.spec_from_file_location("b04_r6_r6_opening_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load R6 opening helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


opening_helpers = _load_opening_helpers()


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


def _run_opening_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return opening_helpers._run_opening(tmp_path, monkeypatch)


def _run_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_opening_only(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path)
    review.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("r6_opening_evidence_review")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_review(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / review.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "packet_contract")


def _decision(outputs: Path) -> dict:
    return _payload(outputs, "decision_matrix")["decision_matrix"]


def _scorecard(outputs: Path) -> dict:
    return _payload(outputs, "evidence_scorecard")["scorecard"]


def _json_roles() -> list[str]:
    return sorted(role for role, filename in review.OUTPUTS.items() if filename.endswith(".json"))


@pytest.mark.parametrize("filename", sorted(review.OUTPUTS.values()))
def test_required_r6_opening_evidence_review_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "r6 opening evidence review" in text
        assert "does not authorize package promotion" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_review_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == REVIEW_MAIN_HEAD


def test_review_packet_binds_r6_opening_run(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == opening.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == opening.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == opening.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["opening_execution_contract_hash"]
    assert contract["binding_hashes"]["opening_result_hash"]


def test_review_packet_selects_validation_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == review.SELECTED_OUTCOME
    assert _contract(outputs)["next_lawful_move"] == review.NEXT_LAWFUL_MOVE
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == review.NEXT_LAWFUL_MOVE


def test_decision_matrix_recommends_package_promotion_review_without_authority(outputs: Path) -> None:
    decision = _decision(outputs)
    assert decision["recommended_next_path"] == review.RECOMMENDED_VALIDATED_PATH
    assert decision["recommendation_is_authority"] is False
    assert decision["package_promotion_review_ready"] is True
    assert decision["package_promotion_ready"] is False


def test_decision_matrix_derives_readiness_from_scorecard(outputs: Path) -> None:
    scorecard = dict(_scorecard(outputs))
    scorecard["fallback_behavior"] = "FAIL"
    decision = review._decision_matrix(scorecard)
    assert decision["package_promotion_review_ready"] is False
    assert decision["recommended_next_path"] == "LIMITED_CONTINUATION_PACKET_NEXT"


@pytest.mark.parametrize(
    "field,expected",
    [
        ("opening_result", "PASSED"),
        ("r6_opening_executed", True),
        ("r6_open", True),
        ("sample_limit_respected", True),
        ("route_distribution_health", "PASS"),
        ("fallback_behavior", "PASS"),
        ("static_fallback_preserved", True),
        ("abstention_fallback_preserved", True),
        ("null_route_preserved", True),
        ("operator_override_ready", True),
        ("kill_switch_ready", True),
        ("rollback_ready", True),
        ("drift_status", "PASS"),
        ("incident_freeze_clean", True),
        ("trace_completeness", "PASS"),
        ("replay_status", "PASS"),
        ("external_verifier_ready", True),
        ("commercial_claim_boundary_preserved", True),
        ("package_promotion_review_ready", True),
        ("package_promotion_ready", False),
        ("commercial_activation_claim_ready", False),
    ],
)
def test_scorecard_grades_required_categories(outputs: Path, field: str, expected: object) -> None:
    assert _scorecard(outputs)[field] == expected


@pytest.mark.parametrize(
    "role",
    [
        "route_distribution_review",
        "fallback_behavior_review",
        "static_fallback_review",
        "abstention_fallback_review",
        "null_route_review",
        "operator_override_review",
        "kill_switch_review",
        "rollback_review",
        "drift_monitoring_review",
        "incident_freeze_review",
        "trace_completeness_review",
        "replay_readiness_review",
        "external_verifier_review",
        "commercial_claim_boundary_review",
        "package_promotion_blocker_review",
    ],
)
def test_review_statuses_are_derived_passes(outputs: Path, role: str) -> None:
    assert _payload(outputs, role)["review_status"] == "PASS"


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("r6_opening_executed", True),
        ("r6_open", True),
        ("r6_opening_evidence_review_packet_authored", True),
        ("r6_opening_evidence_review_validated", False),
        ("global_runtime_surface_authorized", False),
        ("lobe_escalation_authorized", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("trust_zone_law_changed", False),
        ("metric_contract_mutated", False),
        ("static_comparator_weakened", False),
        ("r6_open_treated_as_package_promotion", False),
        ("r6_open_treated_as_commercial_activation", False),
    ],
)
def test_all_json_outputs_preserve_authority_boundaries(outputs: Path, role: str, field: str, expected: object) -> None:
    assert _payload(outputs, role)[field] == expected


@pytest.mark.parametrize("role", sorted(review.ALL_JSON_INPUTS))
def test_review_packet_binds_all_json_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize("role, raw", sorted(review.ALL_JSON_INPUTS.items()))
def test_review_packet_binding_hashes_match_json_inputs(outputs: Path, role: str, raw: str) -> None:
    if role in _contract(outputs)["overwritten_input_roles"]:
        pytest.skip("input was intentionally overwritten by R6 opening evidence review output after pre-run binding")
    expected = file_sha256(outputs.parent.parent / raw)
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"] == expected


@pytest.mark.parametrize("role", review.PREP_ONLY_ROLES)
def test_downstream_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


def test_pipeline_board_routes_to_validation(outputs: Path) -> None:
    lanes = {row["lane"]: row["status"] for row in _payload(outputs, "pipeline_board")["lanes"]}
    assert lanes["AUTHOR_B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET"] == "CURRENT_BOUND"
    assert lanes["VALIDATE_B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET"] == "NEXT"
    assert lanes["PACKAGE_PROMOTION_REVIEW"] == "RECOMMENDED_NOT_AUTHORIZED"


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _payload(outputs, "no_authorization_drift_receipt")
    assert receipt["validation_status"] == "PASS"
    assert receipt["no_downstream_authorization_drift"] is True
    assert receipt["package_promotion_authorized"] is False
    assert receipt["commercial_activation_claim_authorized"] is False


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_only(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, dirty=" M reports/x.json")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        review.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_only(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, branch="feature/nope")
    with pytest.raises(review.LaneFailure, match="NEXT_MOVE_DRIFT"):
        review.run(reports_root=reports)


def test_opening_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_only(tmp_path, monkeypatch)
    path = reports / opening.OUTPUTS["execution_contract"]
    payload = _load(path)
    payload["selected_outcome"] = opening.OUTCOME_FAILED
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="RUNTIME_OUTCOME_DRIFT"):
        review.run(reports_root=reports)


def test_missing_opening_truth_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_only(tmp_path, monkeypatch)
    path = reports / opening.OUTPUTS["execution_contract"]
    payload = _load(path)
    payload["r6_open"] = False
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="RUNTIME_EVIDENCE_MISSING"):
        review.run(reports_root=reports)


def test_package_promotion_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_only(tmp_path, monkeypatch)
    path = reports / opening.OUTPUTS["execution_contract"]
    payload = _load(path)
    payload["package_promotion_authorized"] = True
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="PACKAGE_PROMOTION_DRIFT"):
        review.run(reports_root=reports)


def test_scorecard_incomplete_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_only(tmp_path, monkeypatch)
    path = reports / opening.OUTPUTS["execution_contract"]
    payload = _load(path)
    payload["scorecard"]["rollback_ready"] = False
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="SCORECARD_INCOMPLETE"):
        review.run(reports_root=reports)


def test_trust_zone_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_opening_only(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        review,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "FAIL", "failures": ["boom"], "checks": []},
    )
    with pytest.raises(review.LaneFailure, match="TRUST_ZONE_FAILED"):
        review.run(reports_root=reports)
