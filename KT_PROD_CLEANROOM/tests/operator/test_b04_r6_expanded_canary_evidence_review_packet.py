from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_expanded_canary_evidence_review_packet as review
from tools.operator import cohort0_b04_r6_expanded_canary_runtime as runtime


REVIEW_HEAD = "f" * 40
REVIEW_MAIN_HEAD = "5dd206e075f4f0c9a9e0c20db81276d58c4efed0"


def _load_runtime_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_expanded_canary_runtime.py")
    spec = importlib.util.spec_from_file_location("b04_r6_expanded_canary_runtime_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load runtime helpers")
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


def _run_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = runtime_helpers._run_runtime(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path)
    review.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("expanded_canary_evidence_review")
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
    return _payload(outputs, "post_run_decision_matrix")["decision_matrix"]


def _json_roles() -> list[str]:
    return sorted(role for role, filename in review.OUTPUTS.items() if filename.endswith(".json"))


@pytest.mark.parametrize("filename", sorted(review.OUTPUTS.values()))
def test_required_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8")
        assert "Runtime cutover remains unauthorized" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_packet_binds_expanded_canary_runtime_result(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == runtime.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == runtime.SELECTED_OUTCOME
    assert contract["binding_hashes"]["expanded_canary_runtime_result_hash"]


def test_packet_binds_runtime_receipt_case_manifest_and_drift_receipt(outputs: Path) -> None:
    hashes = _contract(outputs)["binding_hashes"]
    assert hashes["expanded_canary_runtime_execution_receipt_hash"]
    assert hashes["expanded_canary_case_manifest_hash"]
    assert hashes["expanded_canary_no_authorization_drift_receipt_hash"]


def test_success_outcome_routes_to_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["selected_outcome"] == review.SELECTED_OUTCOME
    assert contract["next_lawful_move"] == review.NEXT_LAWFUL_MOVE


def test_decision_matrix_recommends_runtime_cutover_review_only(outputs: Path) -> None:
    decision = _decision(outputs)
    assert decision["recommended_next_path"] == review.RECOMMENDED_NEXT_PATH
    assert decision["recommended_next_path"] in review.ALLOWED_RECOMMENDED_NEXT_PATHS
    assert decision["runtime_cutover_review_ready"] is True
    assert decision["runtime_cutover_authorized"] is False
    assert decision["package_promotion_ready"] is False
    assert decision["commercial_claim_status"] == "BOUNDARY_ONLY"


@pytest.mark.parametrize("category", review.REVIEW_CATEGORIES)
def test_scorecard_has_required_categories(outputs: Path, category: str) -> None:
    rows = {row["category"]: row for row in _payload(outputs, "evidence_scorecard")["scorecard"]["categories"]}
    assert category in rows
    assert rows[category]["status"] == "PASS"


@pytest.mark.parametrize(
    "role",
    [
        "evidence_inventory",
        "evidence_scorecard",
        "post_run_decision_matrix",
        "post_expanded_canary_blocker_ledger",
        "runtime_cutover_readiness_matrix",
        "additional_expanded_canary_readiness_matrix",
        "external_audit_readiness_matrix",
        "package_promotion_blocker_review_contract",
        "external_verifier_readiness_review_contract",
        "commercial_claim_boundary_review_contract",
    ],
)
def test_decision_grade_artifacts_exist(outputs: Path, role: str) -> None:
    assert _payload(outputs, role)["selected_outcome"] == review.SELECTED_OUTCOME


@pytest.mark.parametrize("role", sorted(review.ALL_JSON_INPUTS))
def test_all_json_inputs_are_hash_bound(outputs: Path, role: str) -> None:
    contract = _contract(outputs)
    assert f"{role}_hash" in contract["input_bindings"]
    assert f"{role}_hash" in contract["binding_hashes"]


@pytest.mark.parametrize("role", sorted(review.ALL_TEXT_INPUTS))
def test_all_text_inputs_are_hash_bound(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["input_bindings"]


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("expanded_canary_runtime_executed", True),
        ("expanded_canary_evidence_review_packet_authored", True),
        ("expanded_canary_evidence_review_validated", False),
        ("runtime_cutover_authorized", False),
        ("activation_cutover_executed", False),
        ("r6_open", False),
        ("lobe_escalation_authorized", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("trust_zone_law_changed", False),
        ("metric_contract_mutated", False),
        ("static_comparator_weakened", False),
        ("expanded_canary_evidence_treated_as_package_promotion", False),
    ],
)
def test_all_json_outputs_preserve_authority_boundaries(outputs: Path, role: str, field: str, expected: object) -> None:
    assert _payload(outputs, role)[field] == expected


@pytest.mark.parametrize("role", review.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_artifacts_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_runtime_cutover"] is True
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


def test_blocker_ledger_covers_key_future_authorities(outputs: Path) -> None:
    categories = {row["category"] for row in _payload(outputs, "post_expanded_canary_blocker_ledger")["blockers"]}
    assert {"runtime_cutover", "package_promotion", "commercial_claims", "external_audit"}.issubset(categories)


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _payload(outputs, "no_authorization_drift_receipt")
    assert receipt["status"] == "PASS"
    assert "runtime_cutover_authorized" in receipt["checked_fields"]


def test_pipeline_board_keeps_cutover_blocked(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")["board"]
    assert board["expanded_canary_runtime"] == "PASSED_REPLAYED"
    assert board["runtime_cutover"] == "UNAUTHORIZED"
    assert board["r6"] == "CLOSED"


def test_claim_boundary_blocks_live_language(outputs: Path) -> None:
    claim = _payload(outputs, "commercial_claim_boundary_update_prep_only")
    assert "AFSH is live." in claim["forbidden_claims"]
    assert "Runtime cutover remains unauthorized." in claim["allowed_claims"]


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = runtime_helpers._run_runtime(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, dirty=" M drift.json")
    with pytest.raises(review.LaneFailure, match="worktree dirty"):
        review.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = runtime_helpers._run_runtime(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(review.LaneFailure):
        review.run(reports_root=reports)


def test_runtime_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = runtime_helpers._run_runtime(tmp_path, monkeypatch)
    result_path = reports / runtime.OUTPUTS["result"]
    result = _load(result_path)
    result["selected_outcome"] = runtime.OUTCOME_FAILED
    _write(result_path, result)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="did not pass"):
        review.run(reports_root=reports)


def test_runtime_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = runtime_helpers._run_runtime(tmp_path, monkeypatch)
    result_path = reports / runtime.OUTPUTS["result"]
    result = _load(result_path)
    result["next_lawful_move"] = "AUTHOR_RUNTIME_CUTOVER_PACKET"
    _write(result_path, result)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="next move drifted"):
        review.run(reports_root=reports)


@pytest.mark.parametrize("field", sorted(review.AUTHORITY_DRIFT_KEYS))
def test_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    reports = runtime_helpers._run_runtime(tmp_path, monkeypatch)
    result_path = reports / runtime.OUTPUTS["result"]
    result = _load(result_path)
    result[field] = True
    _write(result_path, result)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure):
        review.run(reports_root=reports)
