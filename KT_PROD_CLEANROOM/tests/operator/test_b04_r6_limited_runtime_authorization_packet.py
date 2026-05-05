from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_limited_runtime_authorization_packet as limited


LIMITED_HEAD = "7777777777777777777777777777777777777777"
LIMITED_MAIN_HEAD = "8888888888888888888888888888888888888888"


def _load_activation_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_learned_router_activation_review_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_activation_review_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load activation-review validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


activation_validation_helpers = _load_activation_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_limited_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = limited.AUTHORITY_BRANCH,
    head: str = LIMITED_HEAD,
    origin_main: str = LIMITED_MAIN_HEAD,
) -> None:
    monkeypatch.setattr(limited, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(limited.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(limited.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(limited.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        limited,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_limited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = activation_validation_helpers._run_validation(tmp_path, monkeypatch)
    _patch_limited_env(monkeypatch, tmp_path)
    limited.run(reports_root=reports)
    return reports


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return _run_limited(tmp_path, monkeypatch)


def _contract(outputs: Path) -> dict:
    return _load(outputs / limited.OUTPUTS["packet_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / limited.OUTPUTS["packet_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / limited.OUTPUTS["next_lawful_move"])


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _contract(outputs)["validation_rows"]}


@pytest.mark.parametrize("filename", sorted(limited.OUTPUTS.values()))
def test_required_limited_runtime_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["artifact_id"]
        assert payload["schema_id"]


def test_limited_runtime_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == LIMITED_MAIN_HEAD


def test_limited_runtime_packet_binds_authoritative_lane(outputs: Path) -> None:
    assert _contract(outputs)["authoritative_lane"] == limited.AUTHORITATIVE_LANE


def test_limited_runtime_packet_binds_activation_review_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["predecessor_outcome"] == limited.EXPECTED_PREVIOUS_OUTCOME
    assert contract["previous_next_lawful_move"] == limited.EXPECTED_PREVIOUS_NEXT_MOVE


def test_limited_runtime_packet_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == limited.SELECTED_OUTCOME


def test_next_lawful_move_is_limited_runtime_validation(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == limited.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == limited.NEXT_LAWFUL_MOVE


def test_packet_report_states_non_execution(outputs: Path) -> None:
    text = (outputs / limited.OUTPUTS["packet_report"]).read_text(encoding="utf-8").lower()
    assert "does not authorize limited runtime" in text
    assert "does not authorize commercial activation claims" in text


@pytest.mark.parametrize(
    "flag",
    [
        "r6_open",
        "limited_runtime_authorized",
        "runtime_execution_authorized",
        "runtime_cutover_authorized",
        "activation_cutover_authorized",
        "activation_cutover_executed",
        "lobe_escalation_authorized",
        "package_promotion_authorized",
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
    ],
)
def test_packet_does_not_authorize_forbidden_boundaries(outputs: Path, flag: str) -> None:
    assert _contract(outputs)[flag] is False


def test_packet_authors_only_authorization_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["limited_runtime_authorization_packet_authored"] is True
    assert contract["limited_runtime_authorization_packet_validated"] is False
    assert contract["limited_runtime_authorized"] is False


@pytest.mark.parametrize(
    "key",
    [
        "activation_review_validation_contract_hash",
        "activation_review_validation_receipt_hash",
        "activation_review_validation_report_hash",
        "shadow_screen_result_hash",
        "shadow_screen_execution_receipt_hash",
        "candidate_hash",
        "candidate_manifest_hash",
        "candidate_semantic_hash",
        "static_comparator_contract_hash",
        "metric_contract_hash",
        "trace_completeness_receipt_hash",
        "trust_zone_validation_receipt_hash",
        "no_authorization_drift_receipt_hash",
    ],
)
def test_required_hashes_are_bound(outputs: Path, key: str) -> None:
    value = _contract(outputs)["binding_hashes"][key]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize(
    "role,key",
    [
        ("activation_review_validation_binding_receipt", "activation_review_validation_contract_hash"),
        ("shadow_result_binding_receipt", "shadow_screen_result_hash"),
        ("candidate_binding_receipt", "candidate_hash"),
    ],
)
def test_binding_receipts_bind_expected_hashes(outputs: Path, role: str, key: str) -> None:
    payload = _load(outputs / limited.OUTPUTS[role])
    assert payload["binding_status"] == "BOUND"
    assert payload["bound_hashes"][key] == _contract(outputs)["binding_hashes"][key]


def test_scope_manifest_is_limited_and_non_authorizing(outputs: Path) -> None:
    scope = _load(outputs / limited.OUTPUTS["scope_manifest"])
    assert scope["limited_scope_required"] is True
    assert scope["max_live_traffic_percent_authorized_by_this_packet"] == 0
    assert scope["can_authorize_limited_runtime"] is False
    assert scope["can_execute_runtime"] is False
    assert scope["allowed_future_modes_after_validation"] == ["CANARY_ONLY", "SHADOW_RUNTIME_ONLY"]


@pytest.mark.parametrize("role", limited.CONTROL_OUTPUT_ROLES)
def test_control_outputs_are_required_and_non_authorizing(outputs: Path, role: str) -> None:
    payload = _load(outputs / limited.OUTPUTS[role])
    assert payload["required_before_limited_runtime_validation"] is True
    assert payload["can_authorize_limited_runtime"] is False
    assert payload["can_execute_runtime"] is False
    assert payload["can_open_r6"] is False
    assert payload["can_promote_package"] is False


def test_static_fallback_contract_exists(outputs: Path) -> None:
    requirements = set(_load(outputs / limited.OUTPUTS["static_fallback_contract"])["requirements"])
    assert "static_comparator_remains_available" in requirements
    assert "static_hold_default_preserved" in requirements


def test_abstention_fallback_contract_exists(outputs: Path) -> None:
    requirements = set(_load(outputs / limited.OUTPUTS["abstention_fallback_contract"])["requirements"])
    assert "boundary_uncertainty_abstains" in requirements
    assert "trust_zone_uncertainty_abstains" in requirements


def test_null_route_preservation_contract_exists(outputs: Path) -> None:
    requirements = set(_load(outputs / limited.OUTPUTS["null_route_preservation_contract"])["requirements"])
    assert "null_route_controls_do_not_enter_selector" in requirements


def test_operator_override_contract_exists(outputs: Path) -> None:
    assert "operator_override_required" in _load(outputs / limited.OUTPUTS["operator_override_contract"])["requirements"]


def test_kill_switch_contract_exists(outputs: Path) -> None:
    requirements = set(_load(outputs / limited.OUTPUTS["kill_switch_contract"])["requirements"])
    assert "kill_switch_required" in requirements
    assert "kill_switch_returns_to_static_comparator" in requirements


def test_rollback_plan_exists(outputs: Path) -> None:
    assert "rollback_to_static_comparator_required" in _load(outputs / limited.OUTPUTS["rollback_plan"])["requirements"]


def test_route_distribution_health_contract_exists(outputs: Path) -> None:
    assert "overrouting_alarm_required" in _load(outputs / limited.OUTPUTS["route_distribution_health_contract"])["requirements"]


def test_drift_monitoring_contract_exists(outputs: Path) -> None:
    assert "metric_drift_freezes_runtime" in _load(outputs / limited.OUTPUTS["drift_monitoring_contract"])["requirements"]


@pytest.mark.parametrize("field", limited.RUNTIME_RECEIPT_FIELDS)
def test_runtime_receipt_schema_requires_fields(outputs: Path, field: str) -> None:
    payload = _load(outputs / limited.OUTPUTS["runtime_receipt_schema"])
    assert field in payload["required_fields"]
    assert f"limited_runtime_runtime_receipt_requires_{field}" in _row_ids(outputs)


@pytest.mark.parametrize("condition", limited.INCIDENT_FREEZE_CONDITIONS)
def test_incident_freeze_contract_requires_conditions(outputs: Path, condition: str) -> None:
    payload = _load(outputs / limited.OUTPUTS["incident_freeze_contract"])
    assert payload["any_condition_freezes_runtime_consideration"] is True
    assert condition in payload["freeze_conditions"]
    assert f"limited_runtime_incident_freeze_on_{condition}" in _row_ids(outputs)


def test_external_verifier_requirements_exist(outputs: Path) -> None:
    requirements = set(_load(outputs / limited.OUTPUTS["external_verifier_requirements"])["requirements"])
    assert "external_verifier_non_executing" in requirements
    assert "raw_hash_bound_artifacts_required" in requirements


def test_commercial_claim_boundary_exists(outputs: Path) -> None:
    requirements = set(_load(outputs / limited.OUTPUTS["commercial_claim_boundary"])["requirements"])
    assert "commercial_activation_claims_unauthorized" in requirements
    assert "package_promotion_prohibited" in requirements


def test_validation_plan_scaffolds_next_lane(outputs: Path) -> None:
    payload = _load(outputs / limited.OUTPUTS["validation_plan"])
    assert payload["expected_successful_validation_outcome"] == "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_VALIDATED__LIMITED_RUNTIME_EXECUTION_PACKET_NEXT"
    assert payload["expected_next_lawful_move_after_validation"] == "AUTHOR_B04_R6_LIMITED_RUNTIME_EXECUTION_OR_CANARY_PACKET"


def test_reason_code_taxonomy_is_bound(outputs: Path) -> None:
    payload = _load(outputs / limited.OUTPUTS["validation_reason_codes"])
    assert "RC_B04R6_LIMITED_RUNTIME_PACKET_SCOPE_NOT_LIMITED" in payload["reason_codes"]
    assert "SCOPE_NOT_LIMITED" in payload["terminal_defects"]


@pytest.mark.parametrize("role", limited.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    filename = limited.OUTPUTS[role]
    if filename.endswith(".md"):
        text = (outputs / filename).read_text(encoding="utf-8")
        assert "Authority: PREP_ONLY" in text
        assert "cannot authorize limited runtime" in text
    else:
        payload = _load(outputs / filename)
        assert payload["authority"] == "PREP_ONLY"
        assert payload["limited_runtime_authorized"] is False
        assert payload["runtime_execution_authorized"] is False
        assert payload["package_promotion_authorized"] is False


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    payload = _load(outputs / limited.OUTPUTS["no_authorization_drift_receipt"])
    assert payload["no_downstream_authorization_drift"] is True
    assert payload["limited_runtime_authorized"] is False
    assert payload["runtime_execution_authorized"] is False


def test_future_blocker_register_names_runtime_and_claim_blockers(outputs: Path) -> None:
    payload = _load(outputs / limited.OUTPUTS["future_blocker_register"])
    blockers = {row["blocker_id"]: row for row in payload["blockers"]}
    assert "B04R6-FB-041" in blockers
    assert "B04R6-FB-043" in blockers


def test_row_count_exceeds_minimum_bar(outputs: Path) -> None:
    assert len(_contract(outputs)["validation_rows"]) >= 70


def test_limited_runtime_accepts_self_replay_handoff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_limited(tmp_path, monkeypatch)
    _patch_limited_env(monkeypatch, tmp_path)
    limited.run(reports_root=reports)
    assert _contract(reports)["handoff_validation"]["self_replay_handoff_accepted"] is True


def test_limited_runtime_rejects_copied_move_without_lane_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = activation_validation_helpers._run_validation(tmp_path, monkeypatch)
    path = reports / limited.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["authoritative_lane"] = "COPIED_LIMITED_RUNTIME_MOVE"
    payload["selected_outcome"] = limited.EXPECTED_PREVIOUS_OUTCOME
    payload["next_lawful_move"] = limited.EXPECTED_PREVIOUS_NEXT_MOVE
    _write(path, payload)
    _patch_limited_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        limited.run(reports_root=reports)


def test_limited_runtime_rejects_unvalidated_activation_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = activation_validation_helpers._run_validation(tmp_path, monkeypatch)
    path = reports / "b04_r6_activation_review_validation_contract.json"
    payload = _load(path)
    payload["activation_review_validated"] = False
    _write(path, payload)
    _patch_limited_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="ACTIVATION_REVIEW_VALIDATION_MISSING"):
        limited.run(reports_root=reports)


def test_limited_runtime_rejects_runtime_authorization_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = activation_validation_helpers._run_validation(tmp_path, monkeypatch)
    path = reports / "b04_r6_activation_review_validation_contract.json"
    payload = _load(path)
    payload["limited_runtime_authorized"] = True
    _write(path, payload)
    _patch_limited_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_AUTHORIZED"):
        limited.run(reports_root=reports)


def test_limited_runtime_rejects_truth_engine_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = activation_validation_helpers._run_validation(tmp_path, monkeypatch)
    path = reports / "b04_r6_activation_review_validation_receipt.json"
    payload = _load(path)
    payload["truth_engine_law_changed"] = True
    _write(path, payload)
    _patch_limited_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="TRUTH_ENGINE_MUTATION"):
        limited.run(reports_root=reports)


def test_limited_runtime_rejects_package_promotion_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = activation_validation_helpers._run_validation(tmp_path, monkeypatch)
    path = reports / "b04_r6_activation_review_commercial_claim_boundary.json"
    payload = _load(path)
    payload["package_promotion_authorized"] = True
    _write(path, payload)
    _patch_limited_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PACKAGE_PROMOTION_DRIFT"):
        limited.run(reports_root=reports)
