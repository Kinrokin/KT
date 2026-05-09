from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_canary_evidence_review_packet as review
from tools.operator import cohort0_b04_r6_limited_runtime_canary as canary
from tools.operator import kt_claim_compiler


SUPERLANE_HEAD = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
SUPERLANE_MAIN_HEAD = "8457dd0365953736eb393c63b90ad8f3407a7a46"


def _load_canary_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_limited_runtime_canary.py")
    spec = importlib.util.spec_from_file_location("b04_r6_limited_runtime_canary_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load canary helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


canary_helpers = _load_canary_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_review_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = review.AUTHORITY_BRANCH,
    head: str = SUPERLANE_HEAD,
    origin_main: str = SUPERLANE_MAIN_HEAD,
    dirty: str = "",
    git_refs: dict[str, str] | None = None,
    git_blob_store: dict[tuple[str, str], bytes] | None = None,
) -> None:
    raw_inputs = list(review.ALL_JSON_INPUTS.values()) + list(review.ALL_TEXT_INPUTS.values())
    blob_store = {(origin_main, raw): (tmp_path / raw).read_bytes() for raw in raw_inputs if (tmp_path / raw).exists()}
    if git_blob_store:
        blob_store.update(git_blob_store)
    refs = {"HEAD": head, "origin/main": origin_main, **(git_refs or {})}

    def fake_git_blob_bytes(root: Path, commit: str, raw: str) -> bytes:
        return blob_store.get((commit, raw), (root / raw).read_bytes())

    def fake_git_blob_sha256(root: Path, commit: str, raw: str) -> str:
        return hashlib.sha256(fake_git_blob_bytes(root, commit, raw)).hexdigest()

    monkeypatch.setattr(review, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(review.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(review.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(review.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(review, "_git_blob_bytes", fake_git_blob_bytes)
    monkeypatch.setattr(review, "_git_blob_sha256", fake_git_blob_sha256)
    monkeypatch.setattr(
        review,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = canary_helpers._run_canary(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path)
    review.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("canary_evidence_review")
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
def test_required_superlane_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md") or filename.endswith(".py"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_canary_evidence_packet_binds_canary_result(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == canary.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == canary.SELECTED_OUTCOME
    assert contract["binding_hashes"]["canary_result_hash"]


def test_canary_evidence_packet_binds_canary_execution_receipt(outputs: Path) -> None:
    assert _contract(outputs)["binding_hashes"]["canary_execution_receipt_hash"]


def test_canary_evidence_packet_binds_canary_report(outputs: Path) -> None:
    assert _contract(outputs)["binding_hashes"]["canary_report_hash"]


def test_canary_evidence_packet_binds_case_manifest(outputs: Path) -> None:
    assert _contract(outputs)["binding_hashes"]["canary_case_manifest_hash"]


@pytest.mark.parametrize(
    "role",
    [
        "evidence_inventory",
        "evidence_scorecard",
        "post_run_decision_matrix",
        "post_canary_blocker_ledger",
        "runtime_cutover_readiness_matrix",
        "expanded_canary_readiness_matrix",
        "second_canary_readiness_matrix",
        "package_promotion_blocker_review_contract",
        "external_verifier_readiness_review_contract",
        "commercial_claim_boundary_review_contract",
    ],
)
def test_decision_grade_artifacts_exist(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["selected_outcome"] == review.SELECTED_OUTCOME


def test_decision_matrix_selects_one_allowed_recommended_next_path(outputs: Path) -> None:
    decision = _decision(outputs)
    assert decision["recommended_next_path"] in review.ALLOWED_RECOMMENDED_NEXT_PATHS
    assert decision["recommended_next_path"] == review.RECOMMENDED_NEXT_PATH


def test_decision_matrix_does_not_authorize_runtime_cutover(outputs: Path) -> None:
    decision = _decision(outputs)
    assert decision["runtime_cutover_review_ready"] is False
    assert _payload(outputs, "runtime_cutover_readiness_matrix")["readiness"]["ready"] is False


def test_decision_matrix_recommends_expanded_canary_before_cutover(outputs: Path) -> None:
    decision = _decision(outputs)
    assert decision["expanded_canary_ready"] is True
    assert decision["package_promotion_ready"] is False
    assert decision["commercial_claim_status"] == "BOUNDARY_ONLY"


@pytest.mark.parametrize("category", review.REVIEW_CATEGORIES)
def test_evidence_scorecard_has_required_categories(outputs: Path, category: str) -> None:
    categories = {row["category"]: row for row in _payload(outputs, "evidence_scorecard")["scorecard"]["categories"]}
    assert category in categories
    assert categories[category]["status"]


@pytest.mark.parametrize("role", sorted(review.ALL_JSON_INPUTS))
def test_all_json_inputs_are_hash_bound(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["input_bindings"]
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize("role", sorted(review.ALL_TEXT_INPUTS))
def test_all_text_inputs_are_hash_bound(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["input_bindings"]


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("canary_runtime_executed", True),
        ("canary_evidence_review_packet_authored", True),
        ("canary_evidence_review_validated", False),
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
        ("canary_evidence_treated_as_package_promotion", False),
    ],
)
def test_all_json_outputs_preserve_authority_boundaries(outputs: Path, role: str, field: str, expected: object) -> None:
    assert _payload(outputs, role)[field] == expected


@pytest.mark.parametrize("role", review.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    filename = review.OUTPUTS[role]
    if filename.endswith(".json"):
        payload = _payload(outputs, role)
        for key, value in review.PREP_ONLY_INVARIANTS.items():
            assert payload[key] == value
    else:
        text = (outputs / filename).read_text(encoding="utf-8")
        assert "PREP_ONLY" in text


@pytest.mark.parametrize("role", review.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_artifacts_cannot_satisfy_authoritative_inputs(outputs: Path, role: str) -> None:
    assert role not in review.AUTHORITATIVE_OUTPUT_ROLES
    filename = review.OUTPUTS[role]
    if filename.endswith(".json"):
        assert _payload(outputs, role)["authority"] == "PREP_ONLY"


@pytest.mark.parametrize("action", review.FORBIDDEN_ACTIONS)
def test_forbidden_actions_are_recorded(outputs: Path, action: str) -> None:
    assert action in _contract(outputs)["forbidden_actions"]


@pytest.mark.parametrize("code", review.REASON_CODES)
def test_reason_codes_are_recorded(outputs: Path, code: str) -> None:
    assert code in _contract(outputs)["reason_codes"]


def test_post_canary_blocker_ledger_covers_required_categories(outputs: Path) -> None:
    categories = {row["category"] for row in _payload(outputs, "post_canary_blocker_ledger")["blockers"]}
    assert {
        "runtime_cutover",
        "expanded_canary",
        "second_canary",
        "package_promotion",
        "external_audit",
        "public_verifier",
        "commercial_claims",
        "operator_readiness",
        "deployment_profile",
        "rollback_proof",
        "data_governance",
        "secret_distributable_hygiene",
        "benchmark_reaudit_readiness",
    } <= categories


def test_campaign_board_tracks_required_corridors(outputs: Path) -> None:
    board = _payload(outputs, "e2e_closure_campaign_board")
    corridors = {row["corridor"] for row in board["corridors"]}
    assert "R6 proof corridor" in corridors
    assert "canary corridor" in corridors
    assert "runtime cutover corridor" in corridors
    assert "package promotion corridor" in corridors
    assert "commercial truth plane corridor" in corridors


def test_claim_compiler_outputs_current_claim_ceiling(outputs: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    compiled = kt_claim_compiler.compile_claims(outputs)
    assert "AFSH passed limited-runtime canary under bounded packet law." in compiled["allowed_claims"]
    assert "AFSH is live." in compiled["forbidden_claims"]
    assert compiled["runtime_cutover_authorized"] is False


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _payload(outputs, "no_authorization_drift_receipt")
    assert receipt["no_authorization_drift"] is True
    assert receipt["runtime_cutover_authorized"] is False
    assert receipt["r6_open"] is False


def test_next_lawful_move_is_canary_evidence_review_validation(outputs: Path) -> None:
    nxt = _payload(outputs, "next_lawful_move")
    assert nxt["selected_outcome"] == review.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == review.NEXT_LAWFUL_MOVE


def test_report_states_campaign_boundary(outputs: Path) -> None:
    text = (outputs / review.OUTPUTS["packet_report"]).read_text(encoding="utf-8").lower()
    assert "expanded-canary" in text
    assert "does not authorize runtime cutover" in text
    assert "package promotion" in text


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    canary_helpers._run_canary(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, dirty=" M file")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        review.run(reports_root=tmp_path / "KT_PROD_CLEANROOM" / "reports")


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    canary_helpers._run_canary(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(RuntimeError, match="must run on one of"):
        review.run(reports_root=tmp_path / "KT_PROD_CLEANROOM" / "reports")


def test_main_replay_binds_overwritten_prior_handoff_to_first_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reports = canary_helpers._run_canary(tmp_path, monkeypatch)
    raw_inputs = list(review.ALL_JSON_INPUTS.values()) + list(review.ALL_TEXT_INPUTS.values())
    pre_merge_main = SUPERLANE_MAIN_HEAD
    post_merge_main = "ffffffffffffffffffffffffffffffffffffffff"
    pre_merge_blobs = {
        (pre_merge_main, raw): (tmp_path / raw).read_bytes()
        for raw in raw_inputs
        if (tmp_path / raw).exists()
    }

    _patch_review_env(monkeypatch, tmp_path)
    review.run(reports_root=reports)
    assert _payload(reports, "next_lawful_move")["next_lawful_move"] == review.NEXT_LAWFUL_MOVE

    _patch_review_env(
        monkeypatch,
        tmp_path,
        branch="main",
        head=post_merge_main,
        origin_main=post_merge_main,
        git_refs={"HEAD^1": pre_merge_main},
        git_blob_store=pre_merge_blobs,
    )
    review.run(reports_root=reports)

    contract = _contract(reports)
    assert contract["current_main_head"] == post_merge_main
    assert contract["input_bindings"]["canary_next_lawful_move_hash"] == hashlib.sha256(
        pre_merge_blobs[
            (
                pre_merge_main,
                f"KT_PROD_CLEANROOM/reports/{canary.OUTPUTS['next_lawful_move']}",
            )
        ]
    ).hexdigest()


def test_unpassed_canary_result_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = canary_helpers._run_canary(tmp_path, monkeypatch)
    result_path = reports / canary.OUTPUTS["result"]
    result = _load(result_path)
    result["selected_outcome"] = "B04_R6_LIMITED_RUNTIME_CANARY_FAILED__CANARY_REPAIR_OR_CLOSEOUT_NEXT"
    _write(result_path, result)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="CANARY_RESULT_NOT_PASSED"):
        review.run(reports_root=reports)


def test_cutover_authority_in_input_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = canary_helpers._run_canary(tmp_path, monkeypatch)
    result_path = reports / canary.OUTPUTS["result"]
    result = _load(result_path)
    result["runtime_cutover_authorized"] = True
    _write(result_path, result)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="RUNTIME_CUTOVER_AUTHORIZED"):
        review.run(reports_root=reports)


def test_package_promotion_in_input_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = canary_helpers._run_canary(tmp_path, monkeypatch)
    result_path = reports / canary.OUTPUTS["result"]
    result = _load(result_path)
    result["package_promotion_authorized"] = True
    _write(result_path, result)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PACKAGE_PROMOTION_DRIFT"):
        review.run(reports_root=reports)


def test_non_deferred_package_promotion_state_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = canary_helpers._run_canary(tmp_path, monkeypatch)
    result_path = reports / canary.OUTPUTS["result"]
    result = _load(result_path)
    result["authorization_state"]["package_promotion"] = "AUTHORIZED"
    result["package_promotion_authorized"] = False
    _write(result_path, result)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PACKAGE_PROMOTION_DRIFT"):
        review.run(reports_root=reports)
