from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_post_cutover_evidence_review_packet as review
from tools.operator import cohort0_b04_r6_runtime_cutover as runtime
from tools.operator.titanium_common import file_sha256


REVIEW_HEAD = "ffffffffffffffffffffffffffffffffffffffff"
REVIEW_MAIN_HEAD = "c85b9668f46bbb398a52b847b1e0416f4c7bccc1"


def _load_runtime_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_runtime_cutover.py")
    spec = importlib.util.spec_from_file_location("b04_r6_runtime_cutover_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load runtime cutover helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime_helpers = _load_runtime_helpers()


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


def _run_runtime_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return runtime_helpers._run_runtime(tmp_path, monkeypatch)


def _run_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_runtime_only(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path)
    review.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("post_cutover_review")
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
def test_required_post_cutover_review_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "post-cutover evidence review" in text
        assert "does not open r6" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_review_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == REVIEW_MAIN_HEAD


def test_review_packet_binds_runtime_cutover(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == runtime.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == runtime.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == runtime.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["runtime_execution_contract_hash"]
    assert contract["binding_hashes"]["runtime_result_hash"]


def test_review_packet_selects_validation_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == review.SELECTED_OUTCOME
    assert _contract(outputs)["next_lawful_move"] == review.NEXT_LAWFUL_MOVE
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == review.NEXT_LAWFUL_MOVE


def test_decision_matrix_recommends_r6_opening_review_without_authority(outputs: Path) -> None:
    decision = _decision(outputs)
    assert decision["recommended_next_path"] == review.RECOMMENDED_VALIDATED_PATH
    assert decision["recommendation_is_authority"] is False
    assert decision["r6_opening_review_ready"] is True
    assert decision["package_promotion_ready"] is False


@pytest.mark.parametrize(
    "field,expected",
    [
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
        ("r6_opening_review_ready", True),
        ("package_promotion_ready", False),
    ],
)
def test_scorecard_grades_required_categories(outputs: Path, field: str, expected: object) -> None:
    assert _scorecard(outputs)[field] == expected


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("runtime_cutover_executed", True),
        ("post_cutover_evidence_review_packet_authored", True),
        ("post_cutover_evidence_review_validated", False),
        ("r6_opening_review_authorized", False),
        ("r6_open", False),
        ("global_runtime_surface_authorized", False),
        ("lobe_escalation_authorized", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("trust_zone_law_changed", False),
        ("metric_contract_mutated", False),
        ("static_comparator_weakened", False),
        ("cutover_result_treated_as_r6_opening", False),
        ("cutover_result_treated_as_package_promotion", False),
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
        pytest.skip("input was intentionally overwritten by post-cutover review output after pre-run binding")
    expected = file_sha256(outputs.parent.parent / raw)
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"] == expected


@pytest.mark.parametrize("role", review.PREP_ONLY_ROLES)
def test_downstream_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


def test_pipeline_board_routes_to_validation(outputs: Path) -> None:
    lanes = {row["lane"]: row["status"] for row in _payload(outputs, "pipeline_board")["lanes"]}
    assert lanes["AUTHOR_B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET"] == "CURRENT_BOUND"
    assert lanes["VALIDATE_B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET"] == "NEXT"
    assert lanes["R6_OPENING_REVIEW"] == "RECOMMENDED_NOT_AUTHORIZED"


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _payload(outputs, "no_authorization_drift_receipt")
    assert receipt["validation_status"] == "PASS"
    assert receipt["no_downstream_authorization_drift"] is True
    assert receipt["r6_open"] is False


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_runtime_only(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, dirty=" M drift")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        review.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_runtime_only(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(review.LaneFailure, match="branch"):
        review.run(reports_root=reports)


def test_runtime_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_runtime_only(tmp_path, monkeypatch)
    path = reports / runtime.OUTPUTS["execution_contract"]
    payload = _load(path)
    payload["selected_outcome"] = runtime.OUTCOME_FAILED
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="RUNTIME_OUTCOME_DRIFT"):
        review.run(reports_root=reports)


def test_runtime_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_runtime_only(tmp_path, monkeypatch)
    path = reports / runtime.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_R6_OPENING_REVIEW_PACKET"
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="NEXT_MOVE_DRIFT"):
        review.run(reports_root=reports)


def test_r6_open_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_runtime_only(tmp_path, monkeypatch)
    path = reports / runtime.OUTPUTS["result"]
    payload = _load(path)
    payload["r6_open"] = True
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="R6_OPEN_DRIFT"):
        review.run(reports_root=reports)


def test_incomplete_scorecard_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_runtime_only(tmp_path, monkeypatch)
    path = reports / runtime.OUTPUTS["result"]
    payload = _load(path)
    payload["result"]["rollback_ready"] = False
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="SCORECARD_INCOMPLETE"):
        review.run(reports_root=reports)


def test_replay_allows_runtime_paths_overwritten_by_prior_review_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_runtime_only(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, branch=review.AUTHORITY_BRANCH)
    review.run(reports_root=reports)
    _patch_review_env(
        monkeypatch,
        tmp_path,
        branch=f"{review.REPLAY_BRANCH_PREFIX}-main-replay",
        head=REVIEW_HEAD,
        origin_main=REVIEW_MAIN_HEAD,
    )
    contract = review.run(reports_root=reports)
    assert contract["selected_outcome"] == review.SELECTED_OUTCOME
    assert "runtime_next_lawful_move_hash" not in contract["binding_hashes"]
    assert "runtime_campaign_board_hash" not in contract["binding_hashes"]
    assert "next_lawful_move" in contract["replay_overwritten_runtime_input_roles"]
    assert "campaign_board" in contract["replay_overwritten_runtime_input_roles"]
