from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_limited_runtime_execution_packet as execution
from tools.operator import cohort0_b04_r6_limited_runtime_execution_packet_validation as packet_validation
from tools.operator import cohort0_b04_r6_limited_runtime_shadow_runtime as shadow


SHADOW_HEAD = "8888888888888888888888888888888888888888"
SHADOW_MAIN_HEAD = "3e621fd4296380f5c643a59d0d986cbf00569e94"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_limited_runtime_execution_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_limited_runtime_execution_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load limited-runtime execution validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_shadow_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = shadow.AUTHORITY_BRANCH,
    head: str = SHADOW_HEAD,
    origin_main: str = SHADOW_MAIN_HEAD,
) -> None:
    monkeypatch.setattr(shadow, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(shadow.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(shadow.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(shadow.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        shadow,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_validation_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_shadow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_shadow_env(monkeypatch, tmp_path)
    shadow.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("limited_runtime_shadow_runtime")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_shadow(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _contract(outputs: Path) -> dict:
    return _load(outputs / shadow.OUTPUTS["execution_contract"])


def _result(outputs: Path) -> dict:
    return _load(outputs / shadow.OUTPUTS["result"])


def _next(outputs: Path) -> dict:
    return _load(outputs / shadow.OUTPUTS["next_lawful_move"])


def _case_manifest(outputs: Path) -> dict:
    return _load(outputs / shadow.OUTPUTS["case_manifest"])


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _contract(outputs)["validation_rows"]}


def _cases(outputs: Path) -> list[dict]:
    return _case_manifest(outputs)["cases"]


@pytest.mark.parametrize("filename", sorted(shadow.OUTPUTS.values()))
def test_required_shadow_runtime_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_shadow_runtime_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == SHADOW_MAIN_HEAD


def test_shadow_runtime_binds_validated_execution_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == packet_validation.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == packet_validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == packet_validation.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["validation_validation_contract_hash"]
    assert contract["binding_hashes"]["execution_execution_packet_contract_hash"]


def test_shadow_runtime_selects_success_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == shadow.SELECTED_OUTCOME
    assert _result(outputs)["selected_outcome"] == shadow.SELECTED_OUTCOME


def test_success_outcome_routes_to_runtime_evidence_review_packet(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == shadow.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == shadow.NEXT_LAWFUL_MOVE
    assert _contract(outputs)["outcome_routing"][shadow.OUTCOME_PASSED] == shadow.NEXT_LAWFUL_MOVE


def test_failure_outcome_routes_to_runtime_repair_or_closeout(outputs: Path) -> None:
    assert _contract(outputs)["outcome_routing"][shadow.OUTCOME_FAILED] == "AUTHOR_B04_R6_RUNTIME_REPAIR_OR_CLOSEOUT"


def test_invalidated_outcome_routes_to_forensic_runtime_invalidation(outputs: Path) -> None:
    assert _contract(outputs)["outcome_routing"][shadow.OUTCOME_INVALIDATED] == "AUTHOR_B04_R6_FORENSIC_RUNTIME_INVALIDATION_COURT"


def test_deferred_outcome_routes_to_named_runtime_defect(outputs: Path) -> None:
    assert _contract(outputs)["outcome_routing"][shadow.OUTCOME_DEFERRED] == "REPAIR_B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME_DEFECTS"


def test_shadow_runtime_report_states_boundaries(outputs: Path) -> None:
    text = (outputs / shadow.OUTPUTS["report"]).read_text(encoding="utf-8").lower()
    assert "shadow_runtime_only" in text
    assert "static remained authoritative" in text
    assert "does not authorize canary runtime" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize(
    "flag",
    [
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
def test_shadow_runtime_does_not_authorize_forbidden_boundaries(outputs: Path, flag: str) -> None:
    assert _contract(outputs)[flag] is False


def test_shadow_runtime_executes_shadow_only(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["shadow_runtime_executed"] is True
    assert contract["limited_runtime_shadow_runtime_executed"] is True
    assert contract["runtime_mode"] == shadow.RUNTIME_MODE
    assert contract["static_authoritative"] is True
    assert contract["afsh_observation_only"] is True


def test_runtime_mode_is_shadow_runtime_only(outputs: Path) -> None:
    assert _result(outputs)["result"]["shadow_runtime_mode"] == shadow.RUNTIME_MODE
    assert _contract(outputs)["runtime_mode"] == "SHADOW_RUNTIME_ONLY"


def test_canary_runtime_is_not_authorized(outputs: Path) -> None:
    assert _result(outputs)["result"]["canary_runtime_cases"] == 0
    assert _contract(outputs)["canary_runtime_executed"] is False


def test_static_remains_authoritative(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["static_authority_preservation_receipt"])
    assert receipt["static_authoritative_cases"] == len(shadow.SHADOW_CASES)
    assert receipt["user_facing_decision_changes"] == 0


def test_afsh_is_observational_only(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["afsh_observation_receipt"])
    assert receipt["observation_only_cases"] == len(shadow.SHADOW_CASES)


def test_afsh_cannot_change_user_facing_decision(outputs: Path) -> None:
    assert all(case["user_facing_decision_changed"] is False for case in _cases(outputs))


def test_runtime_cutover_is_not_authorized(outputs: Path) -> None:
    assert all(case["runtime_cutover_authorized"] is False for case in _cases(outputs))
    assert _contract(outputs)["runtime_cutover_authorized"] is False


def test_r6_remains_closed(outputs: Path) -> None:
    assert _contract(outputs)["r6_open"] is False


@pytest.mark.parametrize(
    "role",
    [
        "case_manifest",
        "afsh_observation_receipt",
        "static_authority_preservation_receipt",
        "route_distribution_health_receipt",
        "fallback_behavior_receipt",
        "abstention_preservation_receipt",
        "null_route_preservation_receipt",
        "operator_override_readiness_receipt",
        "kill_switch_readiness_receipt",
        "rollback_readiness_receipt",
        "drift_monitoring_receipt",
        "incident_freeze_receipt",
        "trace_completeness_receipt",
        "runtime_replay_receipt",
        "external_verifier_readiness_receipt",
        "commercial_claim_boundary_receipt",
        "no_authorization_drift_receipt",
    ],
)
def test_runtime_evidence_receipts_pass(outputs: Path, role: str) -> None:
    payload = _load(outputs / shadow.OUTPUTS[role])
    assert payload["receipt_status"] == "PASS"


def test_shadow_case_manifest_exists(outputs: Path) -> None:
    assert len(_cases(outputs)) == len(shadow.SHADOW_CASES)


@pytest.mark.parametrize("case_id", [case["case_id"] for case in shadow.SHADOW_CASES])
def test_shadow_cases_are_in_manifest(outputs: Path, case_id: str) -> None:
    assert case_id in {case["case_id"] for case in _cases(outputs)}


@pytest.mark.parametrize("case_id", [case["case_id"] for case in shadow.SHADOW_CASES])
def test_shadow_cases_static_authoritative(outputs: Path, case_id: str) -> None:
    case = next(row for row in _cases(outputs) if row["case_id"] == case_id)
    assert case["static_authoritative"] is True
    assert f"shadow_case_{case_id}_static_authoritative" in _row_ids(outputs)


@pytest.mark.parametrize("case_id", [case["case_id"] for case in shadow.SHADOW_CASES])
def test_shadow_cases_afsh_observation_only(outputs: Path, case_id: str) -> None:
    case = next(row for row in _cases(outputs) if row["case_id"] == case_id)
    assert case["afsh_observation_only"] is True
    assert f"shadow_case_{case_id}_afsh_observation_only" in _row_ids(outputs)


@pytest.mark.parametrize("case_id", [case["case_id"] for case in shadow.SHADOW_CASES])
def test_shadow_cases_trace_complete(outputs: Path, case_id: str) -> None:
    case = next(row for row in _cases(outputs) if row["case_id"] == case_id)
    assert case["trace_complete"] is True
    assert f"shadow_case_{case_id}_trace_complete" in _row_ids(outputs)


@pytest.mark.parametrize("case_id", [case["case_id"] for case in shadow.SHADOW_CASES])
def test_shadow_cases_no_user_facing_change(outputs: Path, case_id: str) -> None:
    case = next(row for row in _cases(outputs) if row["case_id"] == case_id)
    assert case["user_facing_decision_changed"] is False
    assert f"shadow_case_{case_id}_no_user_facing_change" in _row_ids(outputs)


@pytest.mark.parametrize("case_id", [case["case_id"] for case in shadow.SHADOW_CASES])
def test_shadow_cases_no_canary_runtime(outputs: Path, case_id: str) -> None:
    case = next(row for row in _cases(outputs) if row["case_id"] == case_id)
    assert case["canary_runtime_executed"] is False


@pytest.mark.parametrize("case_id", [case["case_id"] for case in shadow.SHADOW_CASES])
def test_shadow_cases_have_runtime_receipt_ids(outputs: Path, case_id: str) -> None:
    case = next(row for row in _cases(outputs) if row["case_id"] == case_id)
    assert case["runtime_receipt_id"].startswith("B04R6-SHADOW-RR-")


@pytest.mark.parametrize("field", execution.RUNTIME_RECEIPT_FIELDS)
def test_runtime_receipt_fields_are_emitted(outputs: Path, field: str) -> None:
    assert f"runtime_receipt_field_{field}_emitted" in _row_ids(outputs)


@pytest.mark.parametrize("signal", execution.ROUTE_HEALTH_SIGNALS)
def test_route_distribution_health_signals_are_measured(outputs: Path, signal: str) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["route_distribution_health_receipt"])
    assert signal in receipt["monitored_signals"]
    assert f"route_health_signal_{signal}_measured" in _row_ids(outputs)


def test_fallback_behavior_receipt_exists(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["fallback_behavior_receipt"])
    assert receipt["fallback_failures"] == 0
    assert receipt["static_fallback_available"] is True


def test_abstention_preservation_receipt_exists(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["abstention_preservation_receipt"])
    assert receipt["abstention_preserved"] is True
    assert receipt["abstention_observations"] >= 1


def test_null_route_preservation_receipt_exists(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["null_route_preservation_receipt"])
    assert receipt["null_route_preserved"] is True
    assert receipt["null_route_observations"] >= 1


def test_operator_override_readiness_receipt_exists(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["operator_override_readiness_receipt"])
    assert receipt["operator_override_ready"] is True
    assert receipt["override_may_force_afsh_authority"] is False


def test_kill_switch_readiness_receipt_exists(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["kill_switch_readiness_receipt"])
    assert receipt["kill_switch_ready"] is True
    assert receipt["kill_switch_halts_afsh_observation"] is True


def test_rollback_readiness_receipt_exists(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["rollback_readiness_receipt"])
    assert receipt["rollback_ready"] is True
    assert receipt["rollback_to_static_required"] is True


def test_drift_monitoring_receipt_exists(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["drift_monitoring_receipt"])
    assert receipt["drift_status"] == "PASS"
    assert receipt["drift_signals"] == []


def test_incident_freeze_receipt_exists(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["incident_freeze_receipt"])
    assert receipt["incident_freeze_triggers"] == []
    assert set(execution.INCIDENT_FREEZE_CONDITIONS).issubset(set(receipt["freeze_conditions"]))


def test_trace_completeness_receipt_exists(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["trace_completeness_receipt"])
    assert receipt["trace_complete_cases"] == receipt["total_cases"] == len(shadow.SHADOW_CASES)


def test_runtime_replay_receipt_exists(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["runtime_replay_receipt"])
    assert receipt["replay_status"] == "PASS"
    assert receipt["raw_hash_bound_artifacts_required"] is True


def test_external_verifier_readiness_receipt_exists(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["external_verifier_readiness_receipt"])
    assert receipt["external_verifier_ready"] is True
    assert receipt["external_verifier_non_executing"] is True


def test_commercial_claim_boundary_receipt_exists(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["commercial_claim_boundary_receipt"])
    assert receipt["commercial_activation_claim_authorized"] is False
    assert "AFSH is live" in receipt["forbidden_claims"]


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _load(outputs / shadow.OUTPUTS["no_authorization_drift_receipt"])
    assert receipt["no_downstream_authorization_drift"] is True
    assert receipt["canary_runtime_executed"] is False
    assert receipt["afsh_runtime_authority_granted"] is False
    assert receipt["runtime_cutover_authorized"] is False


@pytest.mark.parametrize("role", sorted(shadow.ALL_JSON_INPUTS))
def test_shadow_runtime_binds_all_json_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]
    assert f"shadow_runtime_binds_{role}" in _row_ids(outputs)


@pytest.mark.parametrize("role", sorted(shadow.ALL_TEXT_INPUTS))
def test_shadow_runtime_binds_all_text_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize(
    "carried_hash",
    [
        "validated_packet_contract_hash",
        "validated_packet_receipt_hash",
        "validated_shadow_screen_result_hash",
        "validated_candidate_hash",
        "validated_candidate_manifest_hash",
        "validated_candidate_semantic_hash",
        "validated_static_comparator_contract_hash",
        "validated_metric_contract_hash",
        "validated_trace_completeness_receipt_hash",
        "validated_trust_zone_validation_receipt_hash",
    ],
)
def test_shadow_runtime_carries_validated_hashes(outputs: Path, carried_hash: str) -> None:
    value = _contract(outputs)["binding_hashes"][carried_hash]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", shadow.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / shadow.OUTPUTS[role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["canary_runtime_executed"] is False
    assert payload["runtime_cutover_authorized"] is False
    assert payload["r6_open"] is False


def test_runtime_evidence_review_packet_draft_is_prep_only(outputs: Path) -> None:
    assert _load(outputs / shadow.OUTPUTS["runtime_evidence_review_packet_prep_only_draft"])["authority"] == "PREP_ONLY"


def test_canary_authorization_packet_draft_is_prep_only(outputs: Path) -> None:
    assert _load(outputs / shadow.OUTPUTS["canary_authorization_packet_prep_only_draft"])["authority"] == "PREP_ONLY"


def test_package_promotion_review_draft_is_prep_only(outputs: Path) -> None:
    assert _load(outputs / shadow.OUTPUTS["package_promotion_review_preconditions_prep_only_draft"])["authority"] == "PREP_ONLY"


def test_external_audit_delta_manifest_draft_is_prep_only(outputs: Path) -> None:
    assert _load(outputs / shadow.OUTPUTS["external_audit_delta_manifest_prep_only_draft"])["authority"] == "PREP_ONLY"


def test_future_blocker_register_updated(outputs: Path) -> None:
    payload = _load(outputs / shadow.OUTPUTS["future_blocker_register"])
    assert payload["current_authoritative_lane"] == "RUN_B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME"
    assert len(payload["blockers"]) >= 3


@pytest.mark.parametrize("check_id", sorted(row["check_id"] for row in shadow._validation_rows(shadow._case_rows())))
def test_validation_rows_include_required_checks(outputs: Path, check_id: str) -> None:
    assert check_id in _row_ids(outputs)


@pytest.mark.parametrize("code", shadow.REASON_CODES)
def test_reason_codes_are_recorded(outputs: Path, code: str) -> None:
    assert code in _contract(outputs)["reason_codes"]


@pytest.mark.parametrize("action", shadow.FORBIDDEN_ACTIONS)
def test_forbidden_actions_are_recorded(outputs: Path, action: str) -> None:
    assert action in _contract(outputs)["forbidden_actions"]


def test_shadow_runtime_self_replay_handoff_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_shadow(tmp_path, monkeypatch)

    shadow.run(reports_root=reports)

    nxt = _load(reports / shadow.OUTPUTS["next_lawful_move"])
    assert nxt["authoritative_lane"] == shadow.AUTHORITATIVE_LANE
    assert nxt["next_lawful_move"] == shadow.NEXT_LAWFUL_MOVE


def test_mutated_packet_mode_to_canary_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["mode_contract"]
    payload = _load(path)
    payload["allowed_modes"] = ["SHADOW_RUNTIME_ONLY", "CANARY_ONLY"]
    _write(path, payload)
    _patch_shadow_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="MODE_DRIFT|EXECUTION_PACKET_BINDING_MISSING"):
        shadow.run(reports_root=reports)


def test_mutated_static_authority_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["static_authority_contract"]
    payload = _load(path)
    payload["afsh_can_change_user_facing_decision"] = True
    _write(path, payload)
    _patch_shadow_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="STATIC_AUTHORITY|EXECUTION_PACKET_BINDING_MISSING"):
        shadow.run(reports_root=reports)


def test_mutated_afsh_observation_cutover_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["afsh_shadow_observation_contract"]
    payload = _load(path)
    payload["selector_may_cutover"] = True
    _write(path, payload)
    _patch_shadow_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="AFSH_AUTHORITY|EXECUTION_PACKET_BINDING_MISSING"):
        shadow.run(reports_root=reports)


def test_canary_executed_flag_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / packet_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["canary_runtime_executed"] = True
    _write(path, payload)
    _patch_shadow_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="CANARY_EXECUTED"):
        shadow.run(reports_root=reports)


def test_invalid_previous_next_move_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / packet_validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "RUN_B04_R6_LIMITED_RUNTIME_CANARY_OR_SHADOW_RUNTIME"
    _write(path, payload)
    _patch_shadow_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        shadow.run(reports_root=reports)


def test_packet_validation_hash_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["scope_manifest"]
    payload = _load(path)
    payload["post_validation_mutation"] = "hash drift"
    _write(path, payload)
    _patch_shadow_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="hash differs from validation binding"):
        shadow.run(reports_root=reports)


def test_missing_packet_validation_hash_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / packet_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["binding_hashes"].pop("route_distribution_health_contract_hash")
    _write(path, payload)
    _patch_shadow_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="missing validation binding hash route_distribution_health_contract_hash"):
        shadow.run(reports_root=reports)
