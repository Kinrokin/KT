from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_limited_runtime_shadow_runtime as shadow
from tools.operator import cohort0_b04_r6_runtime_evidence_review_packet as review


REVIEW_HEAD = "9999999999999999999999999999999999999999"
REVIEW_MAIN_HEAD = "a377786ca79931085a1bd0be221f97cbc6dfda3c"


def _load_shadow_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_limited_runtime_shadow_runtime.py")
    spec = importlib.util.spec_from_file_location("b04_r6_shadow_runtime_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load shadow runtime helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shadow_helpers = _load_shadow_helpers()


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
    monkeypatch.setattr(review, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(review.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(review.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(review.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        review,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_shadow_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return shadow_helpers._run_shadow(tmp_path, monkeypatch)


def _run_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_shadow_only(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path)
    review.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("runtime_evidence_review_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_review(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _contract(outputs: Path) -> dict:
    return _load(outputs / review.OUTPUTS["review_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / review.OUTPUTS["review_receipt"])


def _score(outputs: Path) -> dict:
    return _load(outputs / review.OUTPUTS["evidence_scorecard"])["scorecard"]


def _inventory(outputs: Path) -> dict:
    return _load(outputs / review.OUTPUTS["evidence_inventory"])


def _next(outputs: Path) -> dict:
    return _load(outputs / review.OUTPUTS["next_lawful_move"])


def _canary_matrix(outputs: Path) -> dict:
    return _load(outputs / review.OUTPUTS["canary_readiness_matrix"])


def _review_contract(outputs: Path, role: str) -> dict:
    return _load(outputs / review.OUTPUTS[role])


def _case_rows(outputs: Path) -> list[dict]:
    return _load(outputs / shadow.OUTPUTS["case_manifest"])["cases"]


@pytest.mark.parametrize("filename", sorted(review.OUTPUTS.values()))
def test_required_runtime_evidence_review_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_review_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == REVIEW_MAIN_HEAD


def test_review_contract_binds_previous_shadow_runtime_lane(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == shadow.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == shadow.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == shadow.NEXT_LAWFUL_MOVE


def test_review_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == review.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == review.SELECTED_OUTCOME


def test_next_lawful_move_is_runtime_evidence_validation(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == review.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == review.NEXT_LAWFUL_MOVE


def test_review_report_is_evidence_sweep_not_activation(outputs: Path) -> None:
    text = (outputs / review.OUTPUTS["review_report"]).read_text(encoding="utf-8").lower()
    assert "freezes and summarizes" in text
    assert "shadow_runtime_only" in text
    assert "does not validate itself" in text
    assert "does not authorize canary runtime" in text


@pytest.mark.parametrize(
    "flag",
    [
        "runtime_evidence_review_validated",
        "canary_runtime_authorized",
        "canary_runtime_executed",
        "afsh_runtime_authority_granted",
        "user_facing_decision_changed",
        "runtime_cutover_authorized",
        "activation_cutover_executed",
        "r6_open",
        "lobe_escalation_authorized",
        "package_promotion_authorized",
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
        "metric_contract_mutated",
        "static_comparator_weakened",
    ],
)
def test_review_contract_does_not_authorize_forbidden_boundaries(outputs: Path, flag: str) -> None:
    assert _contract(outputs)[flag] is False


@pytest.mark.parametrize(
    "flag",
    [
        "canary_runtime_authorized",
        "canary_runtime_executed",
        "afsh_runtime_authority_granted",
        "runtime_cutover_authorized",
        "r6_open",
        "package_promotion_authorized",
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
    ],
)
def test_no_authorization_drift_receipt_keeps_downstream_authority_closed(outputs: Path, flag: str) -> None:
    receipt = _load(outputs / review.OUTPUTS["no_authorization_drift_receipt"])
    assert receipt[flag] is False
    assert receipt["no_authorization_drift"] is True


def test_runtime_evidence_inventory_binds_raw_artifacts(outputs: Path) -> None:
    inventory = _inventory(outputs)
    assert inventory["raw_hash_bound_artifacts_required"] is True
    assert inventory["compressed_index_source_of_truth"] is False
    assert inventory["artifact_count"] == len(review.ALL_JSON_INPUTS) + len(review.ALL_TEXT_INPUTS)


@pytest.mark.parametrize("role", sorted(review.ALL_JSON_INPUTS))
def test_inventory_contains_each_json_input(outputs: Path, role: str) -> None:
    inventory = _inventory(outputs)
    matches = [row for row in inventory["artifacts"] if row["role"] == role]
    assert len(matches) == 1
    row = matches[0]
    assert row["evidence_kind"] == "json_receipt"
    assert row["sha256"]
    assert row["source_lane"] == shadow.AUTHORITATIVE_LANE


@pytest.mark.parametrize("role", sorted(review.ALL_TEXT_INPUTS))
def test_inventory_contains_each_text_input(outputs: Path, role: str) -> None:
    inventory = _inventory(outputs)
    matches = [row for row in inventory["artifacts"] if row["role"] == role]
    assert len(matches) == 1
    assert matches[0]["evidence_kind"] == "text_report"
    assert matches[0]["non_empty"] is True


@pytest.mark.parametrize("role", sorted(review.ALL_JSON_INPUTS))
def test_binding_hashes_include_each_json_input(outputs: Path, role: str) -> None:
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"]


@pytest.mark.parametrize("role", sorted(review.ALL_TEXT_INPUTS))
def test_binding_hashes_include_each_text_input(outputs: Path, role: str) -> None:
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"]


def test_mutable_prior_handoff_is_git_object_bound_before_overwrite(outputs: Path) -> None:
    contract = _contract(outputs)
    overwritten = {
        row["role"]: row
        for row in contract["input_bindings"]
        if row.get("mutable_canonical_path_overwritten_by_this_lane") is True
    }
    assert "shadow_next_lawful_move" in overwritten
    assert "shadow_canary_authorization_packet_prep_only_draft" in overwritten
    assert overwritten["shadow_next_lawful_move"]["binding_kind"] == "git_object_before_overwrite"
    assert overwritten["shadow_next_lawful_move"]["git_commit"] == REVIEW_HEAD


def test_scorecard_freezes_shadow_runtime_evidence(outputs: Path) -> None:
    score = _score(outputs)
    assert score["runtime_mode"] == review.RUNTIME_MODE
    assert score["shadow_runtime_passed"] is True
    assert score["total_cases"] == len(shadow.SHADOW_CASES)
    assert score["evidence_review_status"] == "PASS"


@pytest.mark.parametrize(
    "key, expected",
    [
        ("static_authoritative_cases", len(shadow.SHADOW_CASES)),
        ("afsh_observation_only_cases", len(shadow.SHADOW_CASES)),
        ("user_facing_decision_changes", 0),
        ("canary_runtime_cases", 0),
        ("runtime_cutover_authorized_cases", 0),
        ("fallback_failures", 0),
        ("trace_complete_cases", len(shadow.SHADOW_CASES)),
        ("fired_disqualifiers", []),
        ("drift_signals", []),
        ("incident_freeze_triggers", []),
    ],
)
def test_scorecard_required_values(outputs: Path, key: str, expected: object) -> None:
    assert _score(outputs)[key] == expected


@pytest.mark.parametrize("case_index", range(len(shadow.SHADOW_CASES)))
@pytest.mark.parametrize(
    "field, expected",
    [
        ("runtime_mode", review.RUNTIME_MODE),
        ("static_authoritative", True),
        ("afsh_observation_only", True),
        ("user_facing_decision_changed", False),
        ("canary_runtime_executed", False),
        ("runtime_cutover_authorized", False),
        ("trace_complete", True),
        ("raw_hash_bound_artifact_refs_required", True),
    ],
)
def test_shadow_runtime_cases_remain_bounded(outputs: Path, case_index: int, field: str, expected: object) -> None:
    assert _case_rows(outputs)[case_index][field] == expected


@pytest.mark.parametrize("role", review.REVIEW_CONTRACT_ROLES)
def test_review_contracts_pass(outputs: Path, role: str) -> None:
    payload = _review_contract(outputs, role)
    assert payload["review_status"] == "PASS"
    assert payload["findings"]["status"] == "PASS"
    assert payload["canary_runtime_authorized"] is False
    assert payload["runtime_cutover_authorized"] is False
    assert payload["package_promotion_authorized"] is False


@pytest.mark.parametrize("role", review.REVIEW_CONTRACT_ROLES)
def test_review_contracts_bind_evidence_roles(outputs: Path, role: str) -> None:
    payload = _review_contract(outputs, role)
    assert payload["evidence_roles"]
    assert all(evidence_role.startswith("shadow_") for evidence_role in payload["evidence_roles"])


@pytest.mark.parametrize("role", review.REVIEW_CONTRACT_ROLES)
def test_review_contracts_have_questions(outputs: Path, role: str) -> None:
    assert _review_contract(outputs, role)["review_question"].endswith("?")


@pytest.mark.parametrize("role", review.PREP_ONLY_OUTPUT_ROLES)
def test_downstream_drafts_are_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / review.OUTPUTS[role])
    assert payload["status"] == "PREP_ONLY"
    assert payload["authority"] == "PREP_ONLY_NON_AUTHORITY"
    assert payload["canary_runtime_authorized"] is False
    assert payload["runtime_cutover_authorized"] is False


def test_canary_readiness_matrix_is_prep_ready_not_authorized(outputs: Path) -> None:
    matrix = _canary_matrix(outputs)
    assert matrix["readiness_status"] == "PREP_READY_NOT_AUTHORIZED"
    assert matrix["canary_runtime_authorized"] is False
    statuses = {row["readiness_item"]: row["status"] for row in matrix["rows"]}
    assert statuses["shadow_runtime_passed"] == "PASS"
    assert statuses["evidence_review_validation_required"] == "BLOCKING_NEXT"
    assert statuses["canary_authorization_packet_required"] == "BLOCKED"


def test_package_promotion_blocker_review_keeps_promotion_blocked(outputs: Path) -> None:
    payload = _review_contract(outputs, "package_promotion_blocker_review")
    assert payload["findings"]["blockers_remain"] is True
    assert payload["package_promotion_authorized"] is False


def test_pipeline_board_shows_runtime_evidence_review_next(outputs: Path) -> None:
    board = _load(outputs / review.OUTPUTS["pipeline_board"])
    lanes = {row["lane"]: row for row in board["lanes"]}
    assert lanes["AUTHOR_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET"]["status"] == "CURRENT_BOUND"
    assert lanes["VALIDATE_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET"]["status"] == "NEXT"
    assert lanes["RUN_B04_R6_CANARY_RUNTIME"]["status"] == "BLOCKED"
    assert lanes["AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET"]["status"] == "BLOCKED"


def test_lane_compiler_used_as_prep_only_scaffold(outputs: Path) -> None:
    scaffold = _contract(outputs)["lane_compiler_scaffold"]
    assert scaffold["compiler_id"] == "KT_LANE_COMPILER_V0"
    assert scaffold["authority"] == "PREP_ONLY_TOOLING"
    assert scaffold["status"] == "PREP_ONLY_TOOLING_USED_AS_SCAFFOLD"
    assert scaffold["non_authorization_guards"]["runtime_authorized"] is False


def test_validation_rows_all_pass(outputs: Path) -> None:
    assert all(row["status"] == "PASS" for row in _contract(outputs)["validation_rows"])


@pytest.mark.parametrize("code", review.REASON_CODES)
def test_reason_codes_are_declared(outputs: Path, code: str) -> None:
    assert code in _contract(outputs)["reason_codes"]


@pytest.mark.parametrize("defect", review.TERMINAL_DEFECTS)
def test_terminal_defects_are_declared(outputs: Path, defect: str) -> None:
    assert defect in _contract(outputs)["terminal_defects"]


@pytest.mark.parametrize("action", review.FORBIDDEN_ACTIONS)
def test_forbidden_actions_are_declared(outputs: Path, action: str) -> None:
    assert action in _contract(outputs)["forbidden_actions"]


def test_shadow_result_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_shadow_only(tmp_path, monkeypatch)
    path = reports / shadow.OUTPUTS["result"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME_FAILED__RUNTIME_REPAIR_OR_CLOSEOUT_NEXT"
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="SHADOW_RESULT_BINDING_MISSING"):
        review.run(reports_root=reports)


def test_shadow_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_shadow_only(tmp_path, monkeypatch)
    path = reports / shadow.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_CANARY_AUTHORIZATION_PACKET"
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        review.run(reports_root=reports)


def test_user_facing_decision_change_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_shadow_only(tmp_path, monkeypatch)
    path = reports / shadow.OUTPUTS["case_manifest"]
    payload = _load(path)
    payload["cases"][0]["user_facing_decision_changed"] = True
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="USER_FACING_CHANGE"):
        review.run(reports_root=reports)


def test_canary_authorization_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_shadow_only(tmp_path, monkeypatch)
    path = reports / shadow.OUTPUTS["execution_contract"]
    payload = _load(path)
    payload["canary_runtime_authorized"] = True
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="CANARY_AUTHORIZED"):
        review.run(reports_root=reports)


def test_no_authorization_drift_false_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_shadow_only(tmp_path, monkeypatch)
    path = reports / shadow.OUTPUTS["no_authorization_drift_receipt"]
    payload = _load(path)
    payload["no_downstream_authorization_drift"] = False
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="PREP_ONLY_AUTHORITY_DRIFT"):
        review.run(reports_root=reports)


def test_trace_incomplete_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_shadow_only(tmp_path, monkeypatch)
    path = reports / shadow.OUTPUTS["result"]
    payload = _load(path)
    payload["result"]["trace_complete_cases"] = 0
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="TRACE_INCOMPLETE"):
        review.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_shadow_only(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, branch="feature/not-authoritative")

    with pytest.raises(RuntimeError, match="must run on one of"):
        review.run(reports_root=reports)


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_shadow_only(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, dirty=" M file")

    with pytest.raises(RuntimeError, match="dirty worktree"):
        review.run(reports_root=reports)
