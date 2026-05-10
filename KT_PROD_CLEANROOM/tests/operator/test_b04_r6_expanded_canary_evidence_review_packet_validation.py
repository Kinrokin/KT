from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_expanded_canary_evidence_review_packet as review
from tools.operator import cohort0_b04_r6_expanded_canary_evidence_review_packet_validation as validation


VALIDATION_HEAD = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
VALIDATION_MAIN_HEAD = "46fee5dd0dbe89bd207ee378ea910c0e03bda843"


def _load_review_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_expanded_canary_evidence_review_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_expanded_canary_evidence_review_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load expanded canary evidence review helpers")
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
    tmp_path = tmp_path_factory.mktemp("expanded_canary_evidence_review_packet_validation")
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


def test_reason_codes_are_unique() -> None:
    assert len(validation.REASON_CODES) == len(set(validation.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8")
        assert "does not authorize runtime cutover" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_expanded_canary_evidence_review_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == review.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == review.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == review.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["packet_contract_hash"]
    assert contract["binding_hashes"]["packet_receipt_hash"]


def test_validation_selects_runtime_cutover_review_packet_authorship(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["verdict"] == "EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATED_RUNTIME_CUTOVER_REVIEW_PACKET_NEXT"
    assert _next(outputs)["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert _next(outputs)["recommended_next_path_validated"] == review.RECOMMENDED_NEXT_PATH


def test_validation_report_states_non_authorization_boundaries(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "permits only runtime cutover review packet authorship" in text
    assert "does not authorize runtime cutover" in text
    assert "does not open r6" in text
    assert "does not promote package" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("expanded_canary_runtime_executed", True),
        ("expanded_canary_evidence_review_packet_authored", True),
        ("expanded_canary_evidence_review_validated", True),
        ("runtime_cutover_review_packet_next", True),
        ("runtime_cutover_review_packet_authored", False),
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
        ("expanded_canary_evidence_treated_as_package_promotion", False),
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


@pytest.mark.parametrize("row_index", range(0, 80))
def test_input_binding_rows_have_hash_shape(outputs: Path, row_index: int) -> None:
    rows = _contract(outputs)["input_bindings"]
    if row_index >= len(rows):
        pytest.skip("fewer input rows than parameterized guard")
    row = rows[row_index]
    assert len(row["sha256"]) == 64
    assert all(ch in "0123456789abcdef" for ch in row["sha256"])


def test_evidence_inventory_is_validated(outputs: Path) -> None:
    receipt = _payload(outputs, "evidence_inventory_validation")
    assert receipt["validation_status"] == "PASS"
    inventory = _review_payload(outputs, "evidence_inventory")
    roles = {row["role"] for row in inventory["evidence_inventory"]}
    assert roles == set(review.ALL_JSON_INPUTS) | set(review.ALL_TEXT_INPUTS)


@pytest.mark.parametrize("category", review.REVIEW_CATEGORIES)
def test_scorecard_categories_are_validated(outputs: Path, category: str) -> None:
    scorecard = _review_payload(outputs, "evidence_scorecard")["scorecard"]
    rows = {row["category"]: row for row in scorecard["categories"]}
    assert rows[category]["status"] == "PASS"


def test_scorecard_runtime_cutover_review_grade_is_validated(outputs: Path) -> None:
    scorecard = _review_payload(outputs, "evidence_scorecard")["scorecard"]
    assert scorecard["overall_grade"] == "A_READY_FOR_RUNTIME_CUTOVER_REVIEW_PACKET"
    assert scorecard["route_distribution_health"] == "PASS"
    assert scorecard["drift_status"] == "PASS"
    assert scorecard["trace_completeness"] == "PASS"
    assert scorecard["replay_status"] == "PASS"
    assert scorecard["trace_complete_cases"] == review.runtime.MAX_CASES


def test_decision_matrix_is_validated_as_review_packet_next_only(outputs: Path) -> None:
    matrix = _review_payload(outputs, "post_run_decision_matrix")["decision_matrix"]
    assert matrix["recommended_next_path"] == "RUNTIME_CUTOVER_REVIEW_PACKET_NEXT"
    assert matrix["runtime_cutover_review_ready"] is True
    assert matrix["runtime_cutover_authorized"] is False
    assert matrix["package_promotion_ready"] is False
    assert matrix["commercial_claim_status"] == "BOUNDARY_ONLY"
    assert _payload(outputs, "post_run_decision_matrix_validation")["validation_status"] == "PASS"


@pytest.mark.parametrize(
    "role",
    [
        "post_expanded_canary_blocker_ledger",
        "runtime_cutover_readiness_matrix",
        "additional_expanded_canary_readiness_matrix",
        "external_audit_readiness_matrix",
        "package_promotion_blocker_review_contract",
        "external_verifier_readiness_review_contract",
        "commercial_claim_boundary_review_contract",
    ],
)
def test_decision_grade_artifacts_are_bound(outputs: Path, role: str) -> None:
    assert _review_payload(outputs, role)["selected_outcome"] == review.SELECTED_OUTCOME


@pytest.mark.parametrize("role", validation.REVIEW_CONTRACT_ROLES)
def test_direct_review_contracts_are_validated(outputs: Path, role: str) -> None:
    payload = _review_payload(outputs, role)
    assert payload["status"] == "PASS"
    assert payload["cannot_authorize_runtime_cutover"] is True
    assert payload["cannot_authorize_package_promotion"] is True


@pytest.mark.parametrize("role", review.PREP_ONLY_OUTPUT_ROLES)
def test_source_prep_only_artifacts_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _review_payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_runtime_cutover"] is True
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_prep_only_artifacts_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_authorize_runtime_cutover"] is True
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["validation_status"] == "PASS"
    assert payload["source_roles"]


@pytest.mark.parametrize("role", _json_output_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("expanded_canary_runtime_executed", True),
        ("expanded_canary_evidence_review_packet_authored", True),
        ("expanded_canary_evidence_review_validated", True),
        ("runtime_cutover_review_packet_next", True),
        ("runtime_cutover_review_packet_authored", False),
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
def test_all_json_validation_outputs_preserve_authority_boundaries(
    outputs: Path, role: str, field: str, expected: object
) -> None:
    assert _payload(outputs, role)[field] == expected


@pytest.mark.parametrize("role", _json_output_roles())
def test_json_output_reason_codes_are_unique(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    if "reason_codes" not in payload:
        pytest.skip("artifact does not carry reason code registry")
    assert len(payload["reason_codes"]) == len(set(payload["reason_codes"]))


def test_pipeline_board_routes_to_runtime_cutover_review_without_cutover(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")["board"]
    assert board["runtime_cutover_review_packet"] == "NEXT_AUTHORING_LANE"
    assert board["runtime_cutover"] == "UNAUTHORIZED"
    assert board["r6"] == "CLOSED"


def test_no_authorization_drift_and_claim_token_receipts_pass(outputs: Path) -> None:
    assert _payload(outputs, "no_authorization_drift_validation")["no_authorization_drift"] is True
    assert _payload(outputs, "claim_token_boundary_validation")["claim_bearing_authority_tokens_absent"] is True


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(RuntimeError, match="must run on one of"):
        validation.run(reports_root=reports)


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, dirty=" M drift.json")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)


def test_main_replay_head_mismatch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(RuntimeError, match="main replay requires local main"):
        validation.run(reports_root=reports)


def test_review_packet_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET_INVALID"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="outcome drifted"):
        validation.run(reports_root=reports)


def test_review_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_RUNTIME_CUTOVER"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="next move drifted"):
        validation.run(reports_root=reports)


def test_decision_matrix_cutover_authorization_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["post_run_decision_matrix"]
    payload = _load(path)
    payload["decision_matrix"]["runtime_cutover_authorized"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="runtime_cutover_authorized"):
        validation.run(reports_root=reports)


def test_decision_matrix_unjustified_path_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["post_run_decision_matrix"]
    payload = _load(path)
    payload["decision_matrix"]["recommended_next_path"] = "RUNTIME_CUTOVER_AUTHORIZED"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="authority token|recommended next path"):
        validation.run(reports_root=reports)


def test_scorecard_missing_category_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["evidence_scorecard"]
    payload = _load(path)
    payload["scorecard"]["categories"] = payload["scorecard"]["categories"][1:]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="missing or failed"):
        validation.run(reports_root=reports)


def test_prep_only_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["runtime_cutover_review_packet_prep_only_draft"]
    payload = _load(path)
    payload["authority"] = "AUTHORITATIVE"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="authority drifted"):
        validation.run(reports_root=reports)


def test_claim_bearing_authority_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["commercial_claim_boundary_update_prep_only"]
    payload = _load(path)
    payload["commercial_claim_boundary"] = "PACKAGE_PROMOTION AUTHORIZED"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="authority token"):
        validation.run(reports_root=reports)


def test_package_promotion_string_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["package_promotion"] = "AUTHORIZED"
    payload["package_promotion_authorized"] = False
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="package_promotion"):
        validation.run(reports_root=reports)


def test_malformed_source_hash_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["input_bindings"]["runtime_result_hash"] = "not-a-sha"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="malformed"):
        validation.run(reports_root=reports)


def test_missing_source_hash_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["packet_contract"]
    payload = _load(path)
    del payload["input_bindings"]["runtime_result_hash"]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="missing"):
        validation.run(reports_root=reports)
