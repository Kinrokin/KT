from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_runtime_cutover_review_packet as review
from tools.operator import cohort0_b04_r6_runtime_cutover_review_packet_validation as validation


VALIDATION_HEAD = "dddddddddddddddddddddddddddddddddddddddd"
VALIDATION_MAIN_HEAD = "48b39c17498668290ff49ed95a714f2ed1e87de7"


def _load_review_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_runtime_cutover_review_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_runtime_cutover_review_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load runtime cutover review helpers")
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
    return review_helpers._run_cutover(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("runtime_cutover_review_packet_validation")
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


def _next(outputs: Path) -> dict:
    return _payload(outputs, "next_lawful_move")


def _json_output_roles() -> list[str]:
    return sorted(role for role, filename in validation.OUTPUTS.items() if filename.endswith(".json"))


GUARD_FALSE_FIELDS = [
    "runtime_cutover_authorization_packet_authored",
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
    assert len(validation.REASON_CODES) == len(set(validation.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "does not authorize runtime cutover" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_runtime_cutover_review_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == review.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == review.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == review.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["packet_contract_hash"]
    assert contract["binding_hashes"]["packet_receipt_hash"]


def test_validation_routes_to_runtime_cutover_authorization_packet_authorship(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["verdict"] == "RUNTIME_CUTOVER_REVIEW_VALIDATED_AUTHORIZATION_PACKET_NEXT"
    assert _next(outputs)["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert _next(outputs)["runtime_cutover_authorized"] is False


def test_validation_report_states_non_authorization_boundaries(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "permits only runtime cutover authorization packet authorship" in text
    assert "does not authorize runtime cutover" in text
    assert "does not execute cutover" in text
    assert "does not open r6" in text
    assert "does not promote package" in text


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("runtime_cutover_review_packet_authored", True),
        ("runtime_cutover_review_packet_validated", True),
        ("runtime_cutover_authorization_packet_next", True),
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
def test_validation_contract_preserves_authority_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", sorted(validation.CUTOVER_JSON_INPUTS))
def test_validation_binds_all_review_json_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(validation.CUTOVER_TEXT_INPUTS))
def test_validation_binds_all_review_text_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_input_binding_rows_anchor_to_binding_hashes(outputs: Path) -> None:
    contract = _contract(outputs)
    for row in contract["input_bindings"]:
        assert contract["binding_hashes"][f"{row['role']}_hash"] == row["sha256"]


def test_input_binding_rows_are_sorted_by_role(outputs: Path) -> None:
    roles = [row["role"] for row in _contract(outputs)["input_bindings"]]
    assert roles == sorted(roles)


@pytest.mark.parametrize("row_index", range(0, 160))
def test_input_binding_rows_have_hash_shape(outputs: Path, row_index: int) -> None:
    rows = _contract(outputs)["input_bindings"]
    if row_index >= len(rows):
        pytest.skip("fewer input rows than parameterized guard")
    row = rows[row_index]
    assert len(row["sha256"]) == 64
    assert all(ch in "0123456789abcdef" for ch in row["sha256"])


def test_review_scorecard_is_validated(outputs: Path) -> None:
    scorecard = _review_payload(outputs, "review_scorecard")["scorecard"]
    assert scorecard["runtime_cutover_review_ready"] is True
    assert scorecard["runtime_cutover_execution_ready"] is False
    assert scorecard["package_promotion_ready"] is False


@pytest.mark.parametrize("category", review.REVIEW_CATEGORIES)
def test_review_scorecard_categories_are_validated(outputs: Path, category: str) -> None:
    scorecard = _review_payload(outputs, "review_scorecard")["scorecard"]
    rows = {row["category"]: row for row in scorecard["categories"]}
    assert category in rows
    assert rows[category]["status"] in {"PASS", "BLOCKED_BY_AUTHORITY"}


def test_decision_matrix_is_validated_as_authorization_packet_next_only(outputs: Path) -> None:
    matrix = _review_payload(outputs, "decision_matrix")["decision_matrix"]
    assert matrix["recommended_next_path"] == review.RECOMMENDED_NEXT_PATH
    assert matrix["runtime_cutover_authorization_packet_authoring_ready"] is True
    assert matrix["runtime_cutover_authorized"] is False
    assert matrix["activation_cutover_executed"] is False
    assert matrix["r6_open"] is False
    assert matrix["package_promotion_ready"] is False


@pytest.mark.parametrize("role", review.REVIEW_CONTRACT_ROLES)
def test_review_contracts_are_validated(outputs: Path, role: str) -> None:
    receipt_role = {
        "commercial_claim_boundary_review_contract": "commercial_claim_boundary_validation",
        "package_promotion_blocker_review_contract": "package_promotion_blocker_validation",
    }.get(role, role.replace("_contract", "_validation"))
    receipt = _payload(outputs, receipt_role)
    assert receipt["validation_status"] == "PASS"
    assert role in receipt["source_roles"]


def test_blocker_ledger_is_validated(outputs: Path) -> None:
    receipt = _payload(outputs, "blocker_ledger_validation")
    assert receipt["validation_status"] == "PASS"
    categories = {row["category"] for row in _review_payload(outputs, "blocker_ledger")["blockers"]}
    assert "runtime_cutover_authorization" in categories
    assert "runtime_cutover_execution" in categories
    assert "package_promotion" in categories


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_prep_only_outputs_are_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
@pytest.mark.parametrize("guard", PREP_ONLY_GUARDS)
def test_validation_prep_only_outputs_cannot_authorize_future_authorities(outputs: Path, role: str, guard: str) -> None:
    assert _payload(outputs, role)[guard] is True


@pytest.mark.parametrize("role", _json_output_roles())
@pytest.mark.parametrize("flag", GUARD_FALSE_FIELDS)
def test_all_validation_json_outputs_keep_hard_negative_flags(outputs: Path, role: str, flag: str) -> None:
    assert _payload(outputs, role)[flag] is False


@pytest.mark.parametrize("role", _json_output_roles())
def test_all_validation_json_outputs_keep_truth_and_trust_law_unchanged(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["truth_engine_law_unchanged"] is True
    assert payload["trust_zone_law_unchanged"] is True


@pytest.mark.parametrize("role", _json_output_roles())
def test_all_validation_json_outputs_include_forbidden_actions(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert "RUNTIME_CUTOVER_AUTHORIZED" in payload["forbidden_actions"]
    assert "ACTIVATION_CUTOVER_EXECUTED" in payload["forbidden_actions"]
    assert "R6_OPEN" in payload["forbidden_actions"]
    assert "PACKAGE_PROMOTION_AUTHORIZED" in payload["forbidden_actions"]


def test_no_authorization_drift_validation_passes(outputs: Path) -> None:
    assert _payload(outputs, "no_authorization_drift_validation")["no_authorization_drift"] is True
    assert _payload(outputs, "claim_token_boundary_validation")["claim_bearing_authority_tokens_absent"] is True


def test_pipeline_board_marks_authorization_packet_next_only(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")["board"]
    assert board["runtime_cutover_review_packet"] == "VALIDATED"
    assert board["runtime_cutover_authorization_packet"] == "NEXT_AUTHORING_LANE"
    assert board["runtime_cutover"] == "UNAUTHORIZED"
    assert board["r6"] == "CLOSED"


def test_main_branch_replay_requires_head_to_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(validation.LaneFailure, match="main replay requires HEAD to equal origin/main"):
        validation.run(reports_root=reports)


def test_disallowed_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(validation.LaneFailure, match="branch"):
        validation.run(reports_root=reports)


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, dirty=" M something")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)


def test_missing_packet_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    (reports / review.OUTPUTS["packet_contract"]).unlink()
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="PACKET_MISSING"):
        validation.run(reports_root=reports)


def test_packet_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET_INVALID__FORENSIC_RUNTIME_CUTOVER_REVIEW_NEXT"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="PACKET_OUTCOME_DRIFT"):
        validation.run(reports_root=reports)


def test_packet_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_PACKET"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_runtime_cutover_authorized_bool_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["runtime_cutover_authorized"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RUNTIME_CUTOVER_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_runtime_cutover_authorized_non_false_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["runtime_cutover_authorized"] = None
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="RUNTIME_CUTOVER_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_plain_r6_open_claim_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["pipeline_board"]
    payload = _load(path)
    payload["board"]["r6"] = "OPEN"
    payload["r6_open"] = False
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        validation.run(reports_root=reports)


def test_claim_bearing_authority_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["commercial_claim"] = "COMMERCIAL_ACTIVATION_AUTHORIZED"
    payload["commercial_activation_claim_authorized"] = False
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        validation.run(reports_root=reports)


def test_decision_matrix_authorizes_cutover_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["decision_matrix"]
    payload = _load(path)
    payload["decision_matrix"]["runtime_cutover_authorized"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="DECISION_MATRIX_UNLAWFUL|RUNTIME_CUTOVER_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_prep_only_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["runtime_cutover_execution_packet_prep_only_draft"]
    payload = _load(path)
    payload["authority"] = "AUTHORITATIVE"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="PREP_ONLY_DRIFT"):
        validation.run(reports_root=reports)


def test_malformed_input_hash_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["input_bindings"][0]["sha256"] = "not-a-sha"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="INPUT_HASH_MALFORMED"):
        validation.run(reports_root=reports)


def test_binding_map_mismatch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["packet_contract"]
    payload = _load(path)
    first = payload["input_bindings"][0]["role"]
    payload["binding_hashes"][f"{first}_hash"] = "0" * 64
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="INPUT_HASH_MISSING"):
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
