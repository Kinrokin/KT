from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_canary_execution_packet as packet
from tools.operator import cohort0_b04_r6_canary_execution_packet_validation as packet_validation
from tools.operator import cohort0_b04_r6_limited_runtime_canary as canary


CANARY_HEAD = "dddddddddddddddddddddddddddddddddddddddd"
CANARY_MAIN_HEAD = "1de7d82548802b8b4bf81be2a48478796642d485"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_canary_execution_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_canary_execution_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load canary execution validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_canary_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = canary.AUTHORITY_BRANCH,
    head: str = CANARY_HEAD,
    origin_main: str = CANARY_MAIN_HEAD,
    dirty: str = "",
) -> None:
    raw_inputs = list(canary.ALL_JSON_INPUTS.values()) + list(canary.ALL_TEXT_INPUTS.values())
    git_blob_store = {(origin_main, raw): (tmp_path / raw).read_bytes() for raw in raw_inputs if (tmp_path / raw).exists()}

    def fake_git_blob_bytes(root: Path, commit: str, raw: str) -> bytes:
        return git_blob_store.get((commit, raw), (root / raw).read_bytes())

    def fake_git_blob_sha256(root: Path, commit: str, raw: str) -> str:
        return hashlib.sha256(fake_git_blob_bytes(root, commit, raw)).hexdigest()

    monkeypatch.setattr(canary, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(canary.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(canary.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(canary.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(canary, "_git_blob_bytes", fake_git_blob_bytes)
    monkeypatch.setattr(canary, "_git_blob_sha256", fake_git_blob_sha256)
    monkeypatch.setattr(
        canary,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_validation_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_canary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_canary_env(monkeypatch, tmp_path)
    canary.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("limited_runtime_canary")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_canary(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _contract(outputs: Path) -> dict:
    return _load(outputs / canary.OUTPUTS["execution_contract"])


def _result(outputs: Path) -> dict:
    return _load(outputs / canary.OUTPUTS["result"])


def _next(outputs: Path) -> dict:
    return _load(outputs / canary.OUTPUTS["next_lawful_move"])


def _case_manifest(outputs: Path) -> dict:
    return _load(outputs / canary.OUTPUTS["case_manifest"])


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / canary.OUTPUTS[role])


def _json_roles() -> list[str]:
    return sorted(role for role, filename in canary.OUTPUTS.items() if filename.endswith(".json"))


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _contract(outputs)["validation_rows"]}


def _cases(outputs: Path) -> list[dict]:
    return _case_manifest(outputs)["cases"]


@pytest.mark.parametrize("filename", sorted(canary.OUTPUTS.values()))
def test_required_canary_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_canary_run_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == CANARY_MAIN_HEAD


def test_canary_run_binds_validated_execution_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == packet_validation.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == packet_validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == packet_validation.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["validation_validation_contract_hash"]
    assert contract["binding_hashes"]["packet_packet_contract_hash"]


def test_canary_run_binds_candidate(outputs: Path) -> None:
    hashes = _contract(outputs)["binding_hashes"]
    candidate = _load(outputs / "b04_r6_activation_review_candidate_binding_validation_receipt.json")
    assert hashes["afsh_candidate_hash"] == candidate["candidate_hash"]
    assert hashes["afsh_candidate_manifest_hash"] == candidate["candidate_manifest_hash"]
    assert hashes["afsh_candidate_semantic_hash"] == candidate["candidate_semantic_hash"]


def test_canary_selects_success_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == canary.SELECTED_OUTCOME
    assert _result(outputs)["selected_outcome"] == canary.SELECTED_OUTCOME


def test_success_outcome_routes_to_canary_evidence_review_packet(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == canary.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == canary.NEXT_LAWFUL_MOVE
    assert _contract(outputs)["outcome_routing"][canary.OUTCOME_PASSED] == canary.NEXT_LAWFUL_MOVE


def test_failure_outcome_routes_to_canary_repair_or_closeout(outputs: Path) -> None:
    assert _contract(outputs)["outcome_routing"][canary.OUTCOME_FAILED] == "AUTHOR_B04_R6_CANARY_REPAIR_OR_CLOSEOUT_PACKET"


def test_invalidated_outcome_routes_to_forensic_canary_review(outputs: Path) -> None:
    assert _contract(outputs)["outcome_routing"][canary.OUTCOME_INVALIDATED] == "AUTHOR_B04_R6_FORENSIC_CANARY_RUNTIME_REVIEW_PACKET"


def test_deferred_outcome_routes_to_named_canary_defect(outputs: Path) -> None:
    assert _contract(outputs)["outcome_routing"][canary.OUTCOME_DEFERRED] == "REPAIR_B04_R6_LIMITED_RUNTIME_CANARY_DEFECTS"


def test_canary_report_states_boundaries(outputs: Path) -> None:
    text = (outputs / canary.OUTPUTS["report"]).read_text(encoding="utf-8").lower()
    assert "limited-runtime canary ran" in text
    assert "does not authorize runtime cutover" in text
    assert "package promotion" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("canary_runtime_executed", True),
        ("limited_runtime_canary_executed", True),
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
        ("canary_result_treated_as_package_promotion", False),
    ],
)
def test_all_json_outputs_preserve_authority_state(outputs: Path, role: str, field: str, expected: object) -> None:
    assert _payload(outputs, role)[field] == expected


@pytest.mark.parametrize("role", sorted(canary.ALL_JSON_INPUTS))
def test_canary_run_binds_all_json_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]
    assert f"canary_run_binds_{role}" in _row_ids(outputs)


@pytest.mark.parametrize("role", sorted(canary.ALL_TEXT_INPUTS))
def test_canary_run_binds_all_text_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize(
    "carried_hash",
    [
        "validated_canary_execution_packet_hash",
        "validated_canary_execution_packet_receipt_hash",
        "validated_canary_authorization_hash",
        "runtime_evidence_review_validation_hash",
        "runtime_evidence_scorecard_hash",
        "afsh_candidate_hash",
        "afsh_candidate_manifest_hash",
        "afsh_candidate_semantic_hash",
    ],
)
def test_canary_run_carries_required_binding_hashes(outputs: Path, carried_hash: str) -> None:
    value = _contract(outputs)["binding_hashes"][carried_hash]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_canary_case_manifest_respects_sample_limit(outputs: Path) -> None:
    assert len(_cases(outputs)) == len(canary.CANARY_CASES) == 12
    assert _contract(outputs)["scorecard"]["sample_limit_respected"] is True


@pytest.mark.parametrize("case", list(canary.CANARY_CASES))
def test_canary_cases_use_allowed_case_classes(outputs: Path, case: dict) -> None:
    observed = {row["case_id"]: row for row in _cases(outputs)}
    row = observed[case["case_id"]]
    assert row["case_class"] == case["case_class"]
    assert row["excluded_case_class"] is False


@pytest.mark.parametrize("case_class", canary.EXCLUDED_CASE_CLASS_BLOCKS)
def test_excluded_case_classes_are_blocked(outputs: Path, case_class: str) -> None:
    manifest = _case_manifest(outputs)
    assert case_class in manifest["excluded_case_class_blocks"]
    assert all(row["case_class"] != case_class for row in manifest["cases"])


@pytest.mark.parametrize("row", list(canary.CANARY_CASES))
@pytest.mark.parametrize(
    "field,expected",
    [
        ("operator_observed", True),
        ("static_fallback_available", True),
        ("abstention_fallback_available", True),
        ("null_route_control", False),
        ("runtime_cutover_authorized", False),
        ("r6_open", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("trace_complete", True),
    ],
)
def test_each_canary_case_preserves_runtime_boundaries(outputs: Path, row: dict, field: str, expected: object) -> None:
    observed = {case["case_id"]: case for case in _cases(outputs)}
    assert observed[row["case_id"]][field] == expected


def test_route_distribution_receipt_exists(outputs: Path) -> None:
    receipt = _payload(outputs, "route_distribution_receipt")
    assert receipt["route_distribution_health"] == "PASS"
    assert receipt["route_observations"] == _contract(outputs)["scorecard"]["route_observations"]


def test_fallback_behavior_receipt_exists(outputs: Path) -> None:
    receipt = _payload(outputs, "fallback_behavior_receipt")
    assert receipt["fallback_failures"] == 0
    assert receipt["fallback_invocations"] == _contract(outputs)["scorecard"]["fallback_invocations"]


def test_static_fallback_receipt_exists(outputs: Path) -> None:
    assert _payload(outputs, "static_fallback_receipt")["static_fallback_preserved"] is True


def test_abstention_fallback_receipt_exists(outputs: Path) -> None:
    assert _payload(outputs, "abstention_fallback_receipt")["abstention_fallback_preserved"] is True


def test_null_route_preservation_receipt_exists(outputs: Path) -> None:
    receipt = _payload(outputs, "null_route_preservation_receipt")
    assert receipt["null_route_preserved"] is True
    assert receipt["null_route_controls_entered_canary"] == 0


def test_operator_override_receipt_exists(outputs: Path) -> None:
    assert _payload(outputs, "operator_override_receipt")["operator_override_ready"] is True


def test_kill_switch_receipt_exists(outputs: Path) -> None:
    receipt = _payload(outputs, "kill_switch_receipt")
    assert receipt["kill_switch_ready"] is True
    assert receipt["kill_switch_invocations"] == 0


def test_rollback_receipt_exists(outputs: Path) -> None:
    receipt = _payload(outputs, "rollback_receipt")
    assert receipt["rollback_ready"] is True
    assert receipt["rollback_invocations"] == 0


def test_drift_monitoring_receipt_exists(outputs: Path) -> None:
    receipt = _payload(outputs, "drift_monitoring_receipt")
    assert receipt["drift_status"] == "PASS"
    assert receipt["drift_signals"] == []


def test_incident_freeze_receipt_exists(outputs: Path) -> None:
    assert _payload(outputs, "incident_freeze_receipt")["incident_freeze_triggers"] == []


def test_trace_completeness_receipt_exists(outputs: Path) -> None:
    receipt = _payload(outputs, "trace_completeness_receipt")
    assert receipt["trace_complete_cases"] == receipt["total_cases"] == 12


def test_replay_receipt_exists(outputs: Path) -> None:
    receipt = _payload(outputs, "replay_receipt")
    assert receipt["replay_status"] == "PASS"
    assert receipt["raw_hash_bound_artifacts_required"] is True


def test_external_verifier_readiness_receipt_exists(outputs: Path) -> None:
    assert _payload(outputs, "external_verifier_readiness_receipt")["external_verifier_ready"] is True


def test_commercial_claim_boundary_receipt_exists(outputs: Path) -> None:
    receipt = _payload(outputs, "commercial_claim_boundary_receipt")
    assert receipt["commercial_activation_claim_authorized"] is False
    assert "AFSH is live" in receipt["forbidden_claims"]


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _payload(outputs, "no_authorization_drift_receipt")
    assert receipt["no_downstream_authorization_drift"] is True
    assert receipt["runtime_cutover_authorized"] is False
    assert receipt["r6_open"] is False
    assert receipt["package_promotion_authorized"] is False


@pytest.mark.parametrize(
    "role,canonical_role",
    [
        ("expected_runtime_execution_receipt", "execution_receipt"),
        ("expected_runtime_result", "result"),
        ("expected_runtime_case_manifest", "case_manifest"),
        ("expected_runtime_route_distribution_health_receipt", "route_distribution_receipt"),
        ("expected_runtime_no_authorization_drift_receipt", "no_authorization_drift_receipt"),
    ],
)
def test_packet_expected_artifact_aliases_are_emitted(outputs: Path, role: str, canonical_role: str) -> None:
    assert _payload(outputs, role)["artifact_id"] == _payload(outputs, canonical_role)["artifact_id"]


@pytest.mark.parametrize("role", canary.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["runtime_cutover_authorized"] is False
    assert payload["r6_open"] is False


def test_future_blocker_register_updated(outputs: Path) -> None:
    payload = _payload(outputs, "future_blocker_register")
    assert payload["current_authoritative_lane"] == canary.AUTHORITATIVE_LANE
    assert len(payload["blockers"]) >= 3


def test_pipeline_board_routes_to_canary_evidence_review(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")
    lanes = {row["lane"]: row for row in board["lanes"]}
    assert lanes["RUN_B04_R6_LIMITED_RUNTIME_CANARY"]["status"] == "CURRENT_EXECUTED"
    assert lanes["AUTHOR_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET"]["status"] == "NEXT"
    assert lanes["RUNTIME_CUTOVER"]["status"] == "BLOCKED"


@pytest.mark.parametrize("check_id", sorted(row["check_id"] for row in canary._validation_rows(canary._case_rows())))
def test_validation_rows_include_required_checks(outputs: Path, check_id: str) -> None:
    assert check_id in _row_ids(outputs)


@pytest.mark.parametrize("code", canary.REASON_CODES)
def test_reason_codes_are_recorded(outputs: Path, code: str) -> None:
    assert code in _contract(outputs)["reason_codes"]


@pytest.mark.parametrize("action", canary.FORBIDDEN_ACTIONS)
def test_forbidden_actions_are_recorded(outputs: Path, action: str) -> None:
    assert action in _contract(outputs)["forbidden_actions"]


def test_canary_run_self_replay_handoff_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_canary(tmp_path, monkeypatch)
    canary.run(reports_root=reports)
    assert _load(reports / canary.OUTPUTS["next_lawful_move"])["next_lawful_move"] == canary.NEXT_LAWFUL_MOVE


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_canary_env(monkeypatch, tmp_path, dirty=" M changed.json")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        canary.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_canary_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(RuntimeError, match="must run on one of"):
        canary.run(reports_root=reports)


def test_mutated_validated_packet_scope_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["scope_manifest"]
    payload = _load(path)
    payload["details"]["max_case_count_per_window"] = 999
    _write(path, payload)
    _patch_canary_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="SAMPLE_LIMIT|hash differs from validation binding"):
        canary.run(reports_root=reports)


def test_mutated_validation_next_move_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / packet_validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET"
    _write(path, payload)
    _patch_canary_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        canary.run(reports_root=reports)


def test_cutover_authorization_in_input_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / packet_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["runtime_cutover_authorized"] = True
    _write(path, payload)
    _patch_canary_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="RUNTIME_CUTOVER_AUTHORIZED"):
        canary.run(reports_root=reports)


def test_package_promotion_in_input_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / packet_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["package_promotion_authorized"] = True
    _write(path, payload)
    _patch_canary_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PACKAGE_PROMOTION_DRIFT"):
        canary.run(reports_root=reports)


def test_missing_candidate_hash_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / "b04_r6_activation_review_candidate_binding_validation_receipt.json"
    payload = _load(path)
    payload["candidate_hash"] = ""
    _write(path, payload)
    _patch_canary_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="CANDIDATE_BINDING_MISSING"):
        canary.run(reports_root=reports)
