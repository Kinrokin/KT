from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_runtime_cutover_review_packet as cutover


CUTOVER_HEAD = "cccccccccccccccccccccccccccccccccccccccc"
CUTOVER_MAIN_HEAD = "271635976229d469b0456c8254cdce1ceabf4dea"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_expanded_canary_evidence_review_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_expanded_canary_evidence_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load expanded canary evidence validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_cutover_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = cutover.AUTHORITY_BRANCH,
    head: str = CUTOVER_HEAD,
    origin_main: str = CUTOVER_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(cutover, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(cutover.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(cutover.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(cutover.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        cutover,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_predecessor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_cutover(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_cutover_env(monkeypatch, tmp_path)
    cutover.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("runtime_cutover_review_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_cutover(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / cutover.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "packet_contract")


def _receipt(outputs: Path) -> dict:
    return _payload(outputs, "packet_receipt")


def _next(outputs: Path) -> dict:
    return _payload(outputs, "next_lawful_move")


def _json_output_roles() -> list[str]:
    return sorted(role for role, filename in cutover.OUTPUTS.items() if filename.endswith(".json"))


GUARD_FIELDS = [
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
    "runtime_cutover_review_treated_as_cutover_authorization",
]


PREP_ONLY_GUARDS = [
    "cannot_authorize_runtime_cutover",
    "cannot_execute_runtime_cutover",
    "cannot_open_r6",
    "cannot_authorize_lobe_escalation",
    "cannot_authorize_package_promotion",
    "cannot_authorize_commercial_activation_claims",
    "cannot_mutate_truth_engine_law",
    "cannot_mutate_trust_zone_law",
]


def test_reason_codes_are_unique() -> None:
    assert len(cutover.REASON_CODES) == len(set(cutover.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(cutover.OUTPUTS.values()))
def test_required_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "does not authorize runtime cutover" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_packet_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == CUTOVER_MAIN_HEAD


def test_packet_binds_expanded_canary_evidence_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == cutover.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == cutover.PREVIOUS_LANE
    assert contract["predecessor_outcome"] == cutover.EXPECTED_PREVIOUS_OUTCOME
    assert contract["previous_next_lawful_move"] == cutover.EXPECTED_PREVIOUS_NEXT_MOVE
    assert contract["binding_hashes"]["validation_contract_hash"]
    assert contract["binding_hashes"]["validation_receipt_hash"]


def test_packet_selects_review_validation_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == cutover.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == cutover.SELECTED_OUTCOME
    assert _receipt(outputs)["verdict"] == "BOUND_FOR_RUNTIME_CUTOVER_REVIEW_VALIDATION_ONLY"
    assert _next(outputs)["next_lawful_move"] == cutover.NEXT_LAWFUL_MOVE


def test_report_states_non_authorization_boundaries(outputs: Path) -> None:
    text = (outputs / cutover.OUTPUTS["packet_report"]).read_text(encoding="utf-8").lower()
    assert "does not authorize runtime cutover" in text
    assert "does not execute cutover" in text
    assert "does not open r6" in text
    assert "does not promote package" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("expanded_canary_evidence_review_validated", True),
        ("runtime_cutover_review_packet_authored", True),
        ("runtime_cutover_review_treated_as_cutover_authorization", False),
        ("runtime_cutover_authorization_packet_authored", False),
        ("runtime_cutover_authorized", False),
        ("activation_cutover_executed", False),
        ("r6_open", False),
        ("lobe_escalation_authorized", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
        ("metric_contract_mutated", False),
        ("static_comparator_weakened", False),
    ],
)
def test_packet_contract_preserves_authority_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", sorted(cutover.VALIDATION_JSON_INPUTS))
def test_packet_binds_all_validation_json_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(cutover.VALIDATION_TEXT_INPUTS))
def test_packet_binds_all_validation_text_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_input_binding_rows_anchor_to_binding_hashes(outputs: Path) -> None:
    contract = _contract(outputs)
    for row in contract["input_bindings"]:
        assert contract["binding_hashes"][f"{row['role']}_hash"] == row["sha256"]


@pytest.mark.parametrize("row_index", range(0, 160))
def test_input_binding_rows_have_hash_shape(outputs: Path, row_index: int) -> None:
    rows = _contract(outputs)["input_bindings"]
    if row_index >= len(rows):
        pytest.skip("fewer input rows than parameterized guard")
    row = rows[row_index]
    assert len(row["sha256"]) == 64
    assert all(ch in "0123456789abcdef" for ch in row["sha256"])


def test_evidence_inventory_contains_every_bound_input(outputs: Path) -> None:
    inventory = _payload(outputs, "evidence_inventory")
    roles = {row["role"] for row in inventory["evidence_inventory"]}
    assert roles == set(cutover.VALIDATION_JSON_INPUTS) | set(cutover.VALIDATION_TEXT_INPUTS)


@pytest.mark.parametrize("category", cutover.REVIEW_CATEGORIES)
def test_scorecard_categories_are_present(outputs: Path, category: str) -> None:
    scorecard = _payload(outputs, "review_scorecard")["scorecard"]
    rows = {row["category"]: row for row in scorecard["categories"]}
    assert category in rows
    assert rows[category]["status"] in {"PASS", "BLOCKED_BY_AUTHORITY"}


def test_scorecard_routes_to_authorization_packet_authorship_review_only(outputs: Path) -> None:
    scorecard = _payload(outputs, "review_scorecard")["scorecard"]
    assert scorecard["overall_grade"] == "A_READY_FOR_RUNTIME_CUTOVER_AUTHORIZATION_PACKET_AUTHORSHIP_REVIEW"
    assert scorecard["runtime_cutover_review_ready"] is True
    assert scorecard["runtime_cutover_execution_ready"] is False
    assert scorecard["commercial_claim_status"] == "BOUNDARY_ONLY"
    assert scorecard["package_promotion_ready"] is False


def test_decision_matrix_selects_one_allowed_recommended_next_path(outputs: Path) -> None:
    matrix = _payload(outputs, "decision_matrix")["decision_matrix"]
    assert matrix["recommended_next_path"] == cutover.RECOMMENDED_NEXT_PATH
    assert matrix["recommended_next_path"] in matrix["allowed_recommended_next_paths"]
    assert matrix["allowed_recommended_next_paths"] == list(cutover.ALLOWED_RECOMMENDED_NEXT_PATHS)


def test_decision_matrix_does_not_authorize_cutover(outputs: Path) -> None:
    matrix = _payload(outputs, "decision_matrix")["decision_matrix"]
    assert matrix["runtime_cutover_review_ready"] is True
    assert matrix["runtime_cutover_authorization_packet_authoring_ready"] is True
    assert matrix["runtime_cutover_execution_ready"] is False
    assert matrix["runtime_cutover_authorized"] is False
    assert matrix["activation_cutover_executed"] is False
    assert matrix["r6_open"] is False
    assert matrix["package_promotion_ready"] is False
    assert matrix["commercial_claim_status"] == "BOUNDARY_ONLY"


@pytest.mark.parametrize("role", cutover.REVIEW_CONTRACT_ROLES)
def test_review_contracts_exist_and_do_not_authorize_cutover(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["review_status"] == "PASS"
    assert payload["does_not_authorize_runtime_cutover"] is True
    assert payload["required_future_validation"] == cutover.NEXT_LAWFUL_MOVE


def test_blocker_ledger_tracks_runtime_and_promotion_blockers(outputs: Path) -> None:
    blockers = _payload(outputs, "blocker_ledger")["blockers"]
    categories = {row["category"] for row in blockers}
    assert "runtime_cutover" in categories
    assert "runtime_cutover_authorization" in categories
    assert "runtime_cutover_execution" in categories
    assert "package_promotion" in categories
    assert "commercial_claims" in categories
    assert all(row["severity"] == "BLOCKING" for row in blockers)


@pytest.mark.parametrize("role", cutover.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_outputs_are_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"


@pytest.mark.parametrize("role", cutover.PREP_ONLY_OUTPUT_ROLES)
@pytest.mark.parametrize("guard", PREP_ONLY_GUARDS)
def test_prep_only_outputs_cannot_authorize_future_authorities(outputs: Path, role: str, guard: str) -> None:
    assert _payload(outputs, role)[guard] is True


@pytest.mark.parametrize("role", _json_output_roles())
@pytest.mark.parametrize("flag", GUARD_FIELDS)
def test_all_json_outputs_keep_hard_negative_flags(outputs: Path, role: str, flag: str) -> None:
    assert _payload(outputs, role)[flag] is False


@pytest.mark.parametrize("role", _json_output_roles())
def test_all_json_outputs_keep_truth_and_trust_law_unchanged(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["truth_engine_law_unchanged"] is True
    assert payload["trust_zone_law_unchanged"] is True


@pytest.mark.parametrize("role", _json_output_roles())
def test_all_json_outputs_include_forbidden_actions(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert "RUNTIME_CUTOVER_AUTHORIZED" in payload["forbidden_actions"]
    assert "R6_OPEN" in payload["forbidden_actions"]
    assert "PACKAGE_PROMOTION_AUTHORIZED" in payload["forbidden_actions"]
    assert "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED" in payload["forbidden_actions"]


@pytest.mark.parametrize("outcome", cutover.VALIDATION_OUTCOMES_PREPARED)
def test_validation_outcomes_are_prepared_without_execution(outputs: Path, outcome: str) -> None:
    contract = _contract(outputs)
    assert outcome in contract["validation_outcomes_prepared"]
    assert contract["runtime_cutover_authorized"] is False
    assert contract["activation_cutover_executed"] is False


def test_validation_plan_prepares_validation_not_cutover(outputs: Path) -> None:
    plan = _payload(outputs, "validation_plan")
    assert plan["authority"] == "PREP_ONLY"
    assert cutover.VALIDATION_OUTCOMES_PREPARED[0] in plan["validation_outcomes_prepared"]
    assert plan["cannot_authorize_runtime_cutover"] is True


def test_commercial_claim_boundary_update_blocks_live_claims(outputs: Path) -> None:
    payload = _payload(outputs, "commercial_claim_boundary_update_prep_only")
    forbidden = set(payload["forbidden_claims"])
    assert "Runtime cutover is authorized." in forbidden
    assert "R6 is open." in forbidden
    assert "Commercial activation is authorized." in forbidden


def test_pipeline_board_marks_validation_next_and_cutover_unauthorized(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")["board"]
    assert board["runtime_cutover_review_packet"] == "BOUND"
    assert board["runtime_cutover_review_validation"] == "NEXT"
    assert board["runtime_cutover"] == "UNAUTHORIZED"
    assert board["r6"] == "CLOSED"


def test_next_lawful_move_is_runtime_cutover_review_validation(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == "VALIDATE_B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET"
    assert _next(outputs)["runtime_cutover_authorized"] is False


def test_main_branch_replay_requires_head_to_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_cutover_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(cutover.LaneFailure, match="main replay requires HEAD to equal origin/main"):
        cutover.run(reports_root=reports)


def test_disallowed_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_cutover_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(cutover.LaneFailure, match="branch"):
        cutover.run(reports_root=reports)


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_cutover_env(monkeypatch, tmp_path, dirty=" M something")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        cutover.run(reports_root=reports)


def test_missing_predecessor_validation_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    (reports / cutover.evidence_validation.OUTPUTS["validation_contract"]).unlink()
    _patch_cutover_env(monkeypatch, tmp_path)
    with pytest.raises(cutover.LaneFailure, match="PREVIOUS_VALIDATION_MISSING"):
        cutover.run(reports_root=reports)


def test_previous_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / cutover.evidence_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATED__EXTERNAL_AUDIT_DELTA_PACKET_NEXT"
    _write(path, payload)
    _patch_cutover_env(monkeypatch, tmp_path)
    with pytest.raises(cutover.LaneFailure, match="PREVIOUS_OUTCOME_DRIFT"):
        cutover.run(reports_root=reports)


def test_previous_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / cutover.evidence_validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_PACKET"
    _write(path, payload)
    _patch_cutover_env(monkeypatch, tmp_path)
    with pytest.raises(cutover.LaneFailure, match="NEXT_MOVE_DRIFT"):
        cutover.run(reports_root=reports)


def test_authority_boolean_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / cutover.evidence_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["runtime_cutover_authorized"] = True
    _write(path, payload)
    _patch_cutover_env(monkeypatch, tmp_path)
    with pytest.raises(cutover.LaneFailure, match="RUNTIME_CUTOVER_AUTHORIZED"):
        cutover.run(reports_root=reports)


def test_claim_bearing_authority_token_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / cutover.evidence_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["package_promotion"] = "AUTHORIZED"
    payload["package_promotion_authorized"] = False
    _write(path, payload)
    _patch_cutover_env(monkeypatch, tmp_path)
    with pytest.raises(cutover.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        cutover.run(reports_root=reports)


def test_plain_r6_state_open_claim_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / cutover.evidence_validation.OUTPUTS["pipeline_board"]
    payload = _load(path)
    payload["board"]["r6"] = "OPEN"
    payload["r6_open"] = False
    _write(path, payload)
    _patch_cutover_env(monkeypatch, tmp_path)
    with pytest.raises(cutover.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        cutover.run(reports_root=reports)


def test_validation_report_cutover_authorized_claim_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / cutover.evidence_validation.OUTPUTS["validation_report"]
    path.write_text(path.read_text(encoding="utf-8") + "\nRuntime cutover authorized.\n", encoding="utf-8")
    _patch_cutover_env(monkeypatch, tmp_path)
    with pytest.raises(cutover.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        cutover.run(reports_root=reports)


def test_predecessor_binding_row_malformed_hash_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / cutover.evidence_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["input_bindings"][0]["sha256"] = "not-a-sha"
    _write(path, payload)
    _patch_cutover_env(monkeypatch, tmp_path)
    with pytest.raises(cutover.LaneFailure, match="INPUT_HASH_MALFORMED"):
        cutover.run(reports_root=reports)


def test_predecessor_binding_map_mismatch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    path = reports / cutover.evidence_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    first = payload["input_bindings"][0]["role"]
    payload["binding_hashes"][f"{first}_hash"] = "0" * 64
    _write(path, payload)
    _patch_cutover_env(monkeypatch, tmp_path)
    with pytest.raises(cutover.LaneFailure, match="INPUT_HASH_MISSING"):
        cutover.run(reports_root=reports)


def test_trust_zone_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_predecessor(tmp_path, monkeypatch)
    _patch_cutover_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        cutover,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "FAIL", "failures": ["boom"], "checks": []},
    )
    with pytest.raises(cutover.LaneFailure, match="TRUST_ZONE_FAILED"):
        cutover.run(reports_root=reports)
