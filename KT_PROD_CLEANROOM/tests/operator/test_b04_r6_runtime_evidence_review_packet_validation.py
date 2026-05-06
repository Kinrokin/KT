from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_runtime_evidence_review_packet as review
from tools.operator import cohort0_b04_r6_runtime_evidence_review_packet_validation as validation


VALIDATION_HEAD = "8888888888888888888888888888888888888888"
VALIDATION_MAIN_HEAD = "b7fd9699ee909546a0260486426970e523e2a32e"


def _load_review_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_runtime_evidence_review_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_runtime_evidence_review_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load runtime evidence review helpers")
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
    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(validation, "_git_blob_bytes", lambda root, commit, raw: (root / raw).read_bytes())
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
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
    tmp_path = tmp_path_factory.mktemp("runtime_evidence_review_packet_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_validation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _contract(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["next_lawful_move"])


def _review_contract(outputs: Path) -> dict:
    return _load(outputs / review.OUTPUTS["review_contract"])


def _scorecard(outputs: Path) -> dict:
    return _load(outputs / review.OUTPUTS["evidence_scorecard"])["scorecard"]


def _row_ids(outputs: Path) -> set[str]:
    return {row["name"] for row in _contract(outputs)["validation_rows"]}


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_runtime_evidence_review_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == review.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == review.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == review.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["review_contract_hash"]
    assert contract["binding_hashes"]["review_receipt_hash"]


def test_validation_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME


def test_next_lawful_move_is_canary_authorization_packet(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_report_states_non_authorization(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "does not authorize canary runtime" in text
    assert "does not execute canary" in text
    assert "does not authorize runtime cutover" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize(
    "flag",
    [
        "canary_runtime_authorized",
        "canary_runtime_executed",
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
def test_validation_does_not_authorize_forbidden_boundaries(outputs: Path, flag: str) -> None:
    assert _contract(outputs)[flag] is False


def test_validation_marks_packet_validated_but_canary_not_authorized(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["runtime_evidence_review_packet_authored"] is True
    assert contract["runtime_evidence_review_validated"] is True
    assert contract["canary_authorization_packet_next"] is True
    assert contract["canary_runtime_authorized"] is False
    assert contract["canary_runtime_executed"] is False


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _load(outputs / validation.OUTPUTS[role])
    assert payload["validation_status"] == "PASS"
    assert payload["validated_hashes"]


@pytest.mark.parametrize(
    "role,source_role",
    [
        ("evidence_inventory_validation", "evidence_inventory"),
        ("evidence_scorecard_validation", "evidence_scorecard"),
        ("static_authority_validation", "static_authority_review"),
        ("afsh_observation_validation", "afsh_observation_review"),
        ("route_distribution_health_validation", "route_distribution_health_review"),
        ("fallback_behavior_validation", "fallback_behavior_review"),
        ("abstention_preservation_validation", "abstention_preservation_review"),
        ("null_route_preservation_validation", "null_route_preservation_review"),
        ("operator_control_validation", "operator_control_review"),
        ("kill_switch_validation", "kill_switch_readiness_review"),
        ("rollback_validation", "rollback_readiness_review"),
        ("drift_monitoring_validation", "drift_monitoring_review"),
        ("incident_freeze_validation", "incident_freeze_review"),
        ("trace_completeness_validation", "trace_completeness_review"),
        ("replay_readiness_validation", "replay_readiness_review"),
        ("external_verifier_validation", "external_verifier_readiness_review"),
        ("commercial_claim_boundary_validation", "commercial_claim_boundary_review"),
        ("package_promotion_blocker_validation", "package_promotion_blocker_review"),
        ("canary_readiness_matrix_validation", "canary_readiness_matrix"),
        ("pipeline_board_validation", "pipeline_board"),
    ],
)
def test_validation_receipts_bind_source_hashes(outputs: Path, role: str, source_role: str) -> None:
    payload = _load(outputs / validation.OUTPUTS[role])
    assert payload["validated_hashes"][f"{source_role}_hash"] == _contract(outputs)["binding_hashes"][f"{source_role}_hash"]


@pytest.mark.parametrize("role", sorted(validation.REVIEW_JSON_INPUTS))
def test_validation_binds_all_review_json_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize("role", sorted(validation.REVIEW_TEXT_INPUTS))
def test_validation_binds_all_review_text_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize("role", sorted(validation.REVIEW_JSON_INPUTS))
def test_validation_input_bindings_include_each_json_input(outputs: Path, role: str) -> None:
    rows = {row["role"]: row for row in _contract(outputs)["input_bindings"]}
    assert role in rows
    assert rows[role]["sha256"]


@pytest.mark.parametrize("role", sorted(validation.REVIEW_TEXT_INPUTS))
def test_validation_input_bindings_include_each_text_input(outputs: Path, role: str) -> None:
    rows = {row["role"]: row for row in _contract(outputs)["input_bindings"]}
    assert role in rows
    assert rows[role]["sha256"]


def test_overwritten_review_outputs_bind_to_canonical_base_git_objects(outputs: Path) -> None:
    rows = {
        row["role"]: row
        for row in _contract(outputs)["input_bindings"]
        if row.get("mutable_canonical_path_overwritten_by_this_lane") is True
    }
    assert rows["next_lawful_move"]["binding_kind"] == "git_object_before_overwrite"
    assert rows["next_lawful_move"]["git_commit"] == VALIDATION_MAIN_HEAD
    assert rows["future_blocker_register"]["git_commit"] == VALIDATION_MAIN_HEAD
    assert rows["pipeline_board"]["git_commit"] == VALIDATION_MAIN_HEAD


def test_review_packet_prior_handoff_binds_shadow_inputs_to_prior_replay_head(outputs: Path) -> None:
    prior = _review_contract(outputs)
    overwritten = {
        row["role"]: row
        for row in prior["input_bindings"]
        if row.get("mutable_canonical_path_overwritten_by_this_lane") is True
    }
    assert overwritten["shadow_next_lawful_move"]["git_commit"] == prior["current_main_head"]


@pytest.mark.parametrize("category", sorted(validation.REQUIRED_SCORECARD_CATEGORIES))
def test_runtime_evidence_scorecard_has_required_categories(outputs: Path, category: str) -> None:
    assert category in _scorecard(outputs)


@pytest.mark.parametrize(
    "key,expected",
    [
        ("runtime_mode", review.RUNTIME_MODE),
        ("shadow_runtime_passed", True),
        ("evidence_review_status", "PASS"),
        ("canary_readiness_status", "PREP_READY_NOT_AUTHORIZED"),
        ("user_facing_decision_changes", 0),
        ("canary_runtime_cases", 0),
        ("runtime_cutover_authorized_cases", 0),
        ("fallback_failures", 0),
        ("fired_disqualifiers", []),
        ("drift_signals", []),
        ("incident_freeze_triggers", []),
        ("package_promotion_status", "BLOCKED_PENDING_RUNTIME_EVIDENCE_REVIEW_AND_FUTURE_AUTHORITY"),
    ],
)
def test_runtime_evidence_scorecard_required_values(outputs: Path, key: str, expected: object) -> None:
    assert _scorecard(outputs)[key] == expected


def test_runtime_evidence_inventory_is_raw_hash_bound(outputs: Path) -> None:
    inventory = _load(outputs / review.OUTPUTS["evidence_inventory"])
    assert inventory["raw_hash_bound_artifacts_required"] is True
    assert inventory["compressed_index_source_of_truth"] is False
    assert inventory["artifact_count"] == len(inventory["artifacts"])
    assert inventory["artifact_count"] > 0


@pytest.mark.parametrize("artifact_index", range(27))
def test_runtime_evidence_inventory_artifacts_have_validation_signed_hashes(outputs: Path, artifact_index: int) -> None:
    artifact = _load(outputs / review.OUTPUTS["evidence_inventory"])["artifacts"][artifact_index]
    assert artifact["role"]
    assert artifact["path"]
    assert len(artifact["sha256"]) == 64


@pytest.mark.parametrize("role", review.REVIEW_CONTRACT_ROLES)
def test_review_contracts_are_bound_and_pass(outputs: Path, role: str) -> None:
    payload = _load(outputs / review.OUTPUTS[role])
    assert payload["review_status"] == "PASS"
    assert payload["findings"]["status"] == "PASS"
    assert payload["canary_runtime_authorized"] is False
    assert payload["package_promotion_authorized"] is False


@pytest.mark.parametrize("role", review.PREP_ONLY_OUTPUT_ROLES)
def test_authoring_downstream_drafts_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / review.OUTPUTS[role])
    assert payload["status"] == "PREP_ONLY"
    assert payload["authority"] == "PREP_ONLY_NON_AUTHORITY"
    assert payload["canary_runtime_authorized"] is False
    assert payload["runtime_cutover_authorized"] is False


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_downstream_drafts_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / validation.OUTPUTS[role])
    assert payload["status"] == "PREP_ONLY"
    assert payload["authority"] == "PREP_ONLY_NON_AUTHORITY"
    assert payload["canary_runtime_authorized"] is False
    assert payload["runtime_cutover_authorized"] is False


def test_canary_readiness_matrix_has_required_blockers(outputs: Path) -> None:
    matrix = _load(outputs / review.OUTPUTS["canary_readiness_matrix"])
    statuses = {row["readiness_item"]: row["status"] for row in matrix["rows"]}
    assert statuses["shadow_runtime_passed"] == "PASS"
    assert statuses["evidence_review_validation_required"] == "BLOCKING_NEXT"
    assert statuses["canary_authorization_packet_required"] == "BLOCKED"
    assert statuses["canary_validation_required"] == "BLOCKED"
    assert matrix["canary_runtime_authorized"] is False


def test_package_promotion_blocker_review_has_required_blockers(outputs: Path) -> None:
    payload = _load(outputs / review.OUTPUTS["package_promotion_blocker_review"])
    assert payload["findings"]["blockers_remain"] is True
    assert payload["package_promotion_authorized"] is False


def test_external_verifier_readiness_is_non_executing(outputs: Path) -> None:
    payload = _load(outputs / review.OUTPUTS["external_verifier_readiness_review"])
    assert payload["findings"]["external_verifier_ready"] is True
    assert payload["canary_runtime_authorized"] is False


def test_commercial_claim_boundary_blocks_activation_claims(outputs: Path) -> None:
    payload = _load(outputs / review.OUTPUTS["commercial_claim_boundary_review"])
    assert payload["findings"]["commercial_activation_claim_authorized"] is False
    assert payload["commercial_activation_claim_authorized"] is False


def test_pipeline_board_marks_canary_authorization_next(outputs: Path) -> None:
    board = _load(outputs / validation.OUTPUTS["pipeline_board"])
    lanes = {row["lane"]: row for row in board["lanes"]}
    assert lanes["VALIDATE_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET"]["status"] == "CURRENT_VALIDATED"
    assert lanes["AUTHOR_B04_R6_CANARY_AUTHORIZATION_PACKET"]["status"] == "NEXT"
    assert lanes["RUN_B04_R6_LIMITED_RUNTIME_CANARY"]["status"] == "BLOCKED"


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["no_authorization_drift_validation"])
    assert receipt["no_downstream_authorization_drift"] is True
    assert receipt["canary_runtime_authorized"] is False
    assert receipt["canary_runtime_executed"] is False
    assert receipt["runtime_cutover_authorized"] is False
    assert receipt["r6_open"] is False


def test_lane_compiler_scaffold_is_prep_only(outputs: Path) -> None:
    scaffold = _load(outputs / validation.OUTPUTS["lane_compiler_scaffold_receipt"])
    assert scaffold["scaffold_authority"] == "PREP_ONLY_TOOLING"
    assert scaffold["scaffold"]["authority"] == "PREP_ONLY_TOOLING"
    assert scaffold["scaffold_can_authorize"] is False


def test_lane_compiler_scaffold_records_validation_lane_law(outputs: Path) -> None:
    metadata = _load(outputs / validation.OUTPUTS["lane_compiler_scaffold_receipt"])["scaffold"]["lane_law_metadata"]
    assert metadata["lane_kind"] == "VALIDATION"
    assert metadata["selected_outcome"] == validation.SELECTED_OUTCOME
    assert metadata["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert "CANARY_RUNTIME_AUTHORIZED" in metadata["must_not_authorize"]


@pytest.mark.parametrize("row_name", [row["name"] for row in validation._validation_rows()])
def test_validation_rows_include_required_checks(outputs: Path, row_name: str) -> None:
    assert row_name in _row_ids(outputs)


@pytest.mark.parametrize("code", validation.REASON_CODES)
def test_reason_codes_are_recorded(outputs: Path, code: str) -> None:
    assert code in _contract(outputs)["reason_codes"]


@pytest.mark.parametrize("defect", validation.TERMINAL_DEFECTS)
def test_terminal_defects_are_recorded(outputs: Path, defect: str) -> None:
    assert defect in _contract(outputs)["terminal_defects"]


@pytest.mark.parametrize("action", validation.FORBIDDEN_ACTIONS)
def test_forbidden_actions_are_recorded(outputs: Path, action: str) -> None:
    assert action in _contract(outputs)["forbidden_actions"]


def test_missing_validation_signed_input_hash_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["review_contract"]
    payload = _load(path)
    payload["binding_hashes"].pop("shadow_result_hash")
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="INPUT_HASH_MISSING"):
        validation.run(reports_root=reports)


def test_malformed_validation_signed_input_hash_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["review_contract"]
    payload = _load(path)
    payload["input_bindings"][0]["sha256"] = "not-a-sha"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="INPUT_HASH_MALFORMED"):
        validation.run(reports_root=reports)


def test_prior_git_binding_commit_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["review_contract"]
    payload = _load(path)
    for row in payload["input_bindings"]:
        if row.get("binding_kind") == "git_object_before_overwrite":
            row["git_commit"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            break
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="PRIOR_GIT_BINDING_DRIFT"):
        validation.run(reports_root=reports)


def test_scorecard_canary_case_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["evidence_scorecard"]
    payload = _load(path)
    payload["scorecard"]["canary_runtime_cases"] = 1
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="SCORECARD_MISSING"):
        validation.run(reports_root=reports)


def test_canary_readiness_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["canary_readiness_matrix"]
    payload = _load(path)
    payload["canary_runtime_authorized"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="CANARY_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_pipeline_board_canary_unblocked_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["pipeline_board"]
    payload = _load(path)
    for row in payload["lanes"]:
        if row["lane"] == "RUN_B04_R6_CANARY_RUNTIME":
            row["status"] = "NEXT"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="CANARY_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_prep_only_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["canary_authorization_packet_prep_only_draft"]
    payload = _load(path)
    payload["status"] = "AUTHORITATIVE"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="PREP_ONLY_AUTHORITY_DRIFT"):
        validation.run(reports_root=reports)


def test_invalid_review_packet_outcome_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["review_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_RUNTIME_EVIDENCE_REVIEW_VALIDATED__CANARY_AUTHORIZATION_PACKET_NEXT"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="PACKET_BINDING_MISSING"):
        validation.run(reports_root=reports)


def test_validation_self_replay_handoff_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation(tmp_path, monkeypatch)

    validation.run(reports_root=reports)

    nxt = _load(reports / validation.OUTPUTS["next_lawful_move"])
    assert nxt["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert nxt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_invalid_self_replay_handoff_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "RUN_B04_R6_LIMITED_RUNTIME_CANARY"
    _write(path, payload)

    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="feature/not-authoritative")

    with pytest.raises(RuntimeError, match="must run on one of"):
        validation.run(reports_root=reports)


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, dirty=" M file")

    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)
