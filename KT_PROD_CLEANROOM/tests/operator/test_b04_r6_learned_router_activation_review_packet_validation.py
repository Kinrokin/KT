from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_learned_router_activation_review_packet as activation
from tools.operator import cohort0_b04_r6_learned_router_activation_review_packet_validation as validation


VAL_HEAD = "5555555555555555555555555555555555555555"
VAL_MAIN_HEAD = "6666666666666666666666666666666666666666"


def _load_activation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_learned_router_activation_review_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_activation_review_packet_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load activation-review packet test helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


activation_helpers = _load_activation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_validation_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validation.AUTHORITY_BRANCH,
    head: str = VAL_HEAD,
    origin_main: str = VAL_MAIN_HEAD,
) -> None:
    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _write_activation_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return activation_helpers._run_activation(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _write_activation_outputs(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return _run_validation(tmp_path, monkeypatch)


def _contract(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["next_lawful_move"])


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _receipt(outputs)["validation_rows"]}


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["artifact_id"]
        assert payload["schema_id"]


def test_activation_review_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VAL_MAIN_HEAD


def test_activation_review_validation_binds_authority_lane(outputs: Path) -> None:
    assert _contract(outputs)["authoritative_lane"] == validation.AUTHORITATIVE_LANE


def test_activation_review_validation_binds_previous_lane(outputs: Path) -> None:
    assert _contract(outputs)["previous_authoritative_lane"] == activation.AUTHORITATIVE_LANE


def test_activation_review_validation_binds_selected_architecture(outputs: Path) -> None:
    assert _contract(outputs)["selected_architecture_id"] == validation.SELECTED_ARCHITECTURE_ID


def test_activation_review_validation_binds_packet_replay_head(outputs: Path) -> None:
    assert _contract(outputs)["packet_replay_binding_head"] == activation_helpers.ACT_HEAD


def test_activation_review_validation_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME


def test_activation_review_validation_next_lawful_move_is_limited_runtime_packet(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert _next(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME


def test_activation_review_validation_marks_packet_validated_only(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["activation_review_packet_authored"] is True
    assert contract["activation_review_validated"] is True
    assert contract["limited_runtime_authorization_packet_next"] is True
    assert contract["limited_runtime_authorized"] is False


@pytest.mark.parametrize(
    "flag",
    [
        "r6_open",
        "limited_runtime_authorized",
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
def test_validation_does_not_authorize_runtime_boundaries(outputs: Path, flag: str) -> None:
    assert _contract(outputs)[flag] is False


@pytest.mark.parametrize("key", validation.REQUIRED_BINDING_HASH_KEYS)
def test_required_binding_hashes_are_bound(outputs: Path, key: str) -> None:
    value = _contract(outputs)["binding_hashes"][key]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize(
    "role,key",
    [
        ("shadow_result_binding_validation", "shadow_screen_result_hash"),
        ("candidate_binding_validation", "candidate_hash"),
        ("screen_packet_binding_validation", "validated_shadow_screen_packet_hash"),
        ("universe_binding_validation", "validated_blind_universe_hash"),
        ("court_binding_validation", "validated_route_economics_court_hash"),
        ("source_packet_binding_validation", "validated_source_packet_hash"),
        ("admissibility_binding_validation", "admissibility_receipt_hash"),
        ("triage_core_binding_validation", "numeric_triage_emit_core_hash"),
        ("static_comparator_binding_validation", "static_comparator_contract_hash"),
        ("metric_contract_binding_validation", "metric_contract_hash"),
        ("disqualifier_binding_validation", "disqualifier_ledger_hash"),
        ("trace_completeness_binding_validation", "trace_completeness_receipt_hash"),
    ],
)
def test_binding_validation_receipts_bind_expected_hashes(outputs: Path, role: str, key: str) -> None:
    payload = _load(outputs / validation.OUTPUTS[role])
    assert payload["status"] == "PASS"
    assert payload[key] == _contract(outputs)["binding_hashes"][key]


def test_shadow_superiority_result_is_bound(outputs: Path) -> None:
    payload = _load(outputs / validation.OUTPUTS["shadow_result_binding_validation"])
    assert payload["fired_disqualifiers"] == []
    assert payload["shadow_screen_result_hash"] == _contract(outputs)["binding_hashes"]["shadow_screen_result_hash"]


def test_zero_fired_disqualifiers_are_bound(outputs: Path) -> None:
    assert "zero_fired_disqualifiers_bound" in _row_ids(outputs)


def test_packet_contract_validation_receipt_passes(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["packet_contract_validation"])["status"] == "PASS"


def test_packet_receipt_validation_receipt_passes(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["packet_receipt_validation"])["status"] == "PASS"


@pytest.mark.parametrize("role", validation.CONTROL_ROLES)
def test_control_validation_receipts_pass(outputs: Path, role: str) -> None:
    receipt_role = {
        "scope_contract": "scope_validation",
        "runtime_preconditions_contract": "runtime_preconditions_validation",
        "static_fallback_contract": "static_fallback_validation",
        "operator_override_contract": "operator_override_validation",
        "kill_switch_contract": "kill_switch_validation",
        "rollback_plan_contract": "rollback_plan_validation",
        "route_distribution_health_contract": "route_distribution_health_validation",
        "drift_monitoring_contract": "drift_monitoring_validation",
        "runtime_receipt_schema_contract": "runtime_receipt_schema_validation",
        "external_verifier_requirements": "external_verifier_validation",
        "commercial_claim_boundary": "commercial_claim_boundary_validation",
    }[role]
    assert _load(outputs / validation.OUTPUTS[receipt_role])["status"] == "PASS"


@pytest.mark.parametrize("key", activation.RUNTIME_PRECONDITION_KEYS)
def test_runtime_preconditions_are_required(outputs: Path, key: str) -> None:
    packet_contract = _load(outputs / activation.OUTPUTS["packet_contract"])
    assert packet_contract["runtime_preconditions"][key] is True
    assert f"runtime_precondition_requires_{key}" in _row_ids(outputs)


@pytest.mark.parametrize("requirement", activation.ACTIVATION_SUCCESS_REQUIREMENTS)
def test_activation_review_success_requirements_are_required(outputs: Path, requirement: str) -> None:
    packet_contract = _load(outputs / activation.OUTPUTS["packet_contract"])
    assert requirement in packet_contract["activation_review_success_requirements"]
    assert f"activation_review_success_requires_{requirement}" in _row_ids(outputs)


def test_static_fallback_contract_preserves_static_abstain_null_route(outputs: Path) -> None:
    requirements = set(_load(outputs / activation.OUTPUTS["static_fallback_contract"])["requirements"])
    assert "static_fallback_required" in requirements
    assert "abstention_fallback_required" in requirements
    assert "null_route_preservation_required" in requirements


def test_operator_override_contract_exists(outputs: Path) -> None:
    assert "human_operator_override_required" in _load(outputs / activation.OUTPUTS["operator_override_contract"])["requirements"]


def test_kill_switch_contract_exists(outputs: Path) -> None:
    assert "kill_switch_required" in _load(outputs / activation.OUTPUTS["kill_switch_contract"])["requirements"]


def test_rollback_plan_contract_exists(outputs: Path) -> None:
    assert "rollback_plan_required" in _load(outputs / activation.OUTPUTS["rollback_plan_contract"])["requirements"]


def test_route_distribution_health_contract_exists(outputs: Path) -> None:
    assert "selector_entry_rate_monitored" in _load(outputs / activation.OUTPUTS["route_distribution_health_contract"])["requirements"]


def test_drift_monitoring_contract_exists(outputs: Path) -> None:
    assert "metric_drift_freezes_runtime_consideration" in _load(outputs / activation.OUTPUTS["drift_monitoring_contract"])["requirements"]


def test_runtime_receipt_schema_contract_exists(outputs: Path) -> None:
    assert "verdict_mode_required" in _load(outputs / activation.OUTPUTS["runtime_receipt_schema_contract"])["requirements"]


def test_external_verifier_requirements_are_non_executing(outputs: Path) -> None:
    payload = _load(outputs / activation.OUTPUTS["external_verifier_requirements"])
    assert payload["can_execute_runtime"] is False
    assert "external_verifier_non_executing" in payload["requirements"]


def test_commercial_claim_boundary_exists(outputs: Path) -> None:
    requirements = set(_load(outputs / activation.OUTPUTS["commercial_claim_boundary"])["requirements"])
    assert "commercial_activation_claims_unauthorized" in requirements
    assert "package_promotion_prohibited" in requirements


@pytest.mark.parametrize("role", validation.PREP_ONLY_ROLES)
def test_prep_only_drafts_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / activation.OUTPUTS[role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["limited_runtime_authorized"] is False
    assert payload["runtime_cutover_authorized"] is False
    assert payload["package_promotion_authorized"] is False


def test_no_authorization_drift_validation_receipt_passes(outputs: Path) -> None:
    payload = _load(outputs / validation.OUTPUTS["no_authorization_drift_validation"])
    assert payload["status"] == "PASS"
    assert payload["no_downstream_authorization_drift"] is True
    assert payload["limited_runtime_authorized"] is False


def test_trust_zone_validation_receipt_passes(outputs: Path) -> None:
    assert _load(outputs / validation.OUTPUTS["trust_zone_validation"])["fresh_trust_zone_validation"]["status"] == "PASS"


def test_replay_binding_validation_records_mutable_handoff(outputs: Path) -> None:
    payload = _load(outputs / validation.OUTPUTS["replay_binding_validation"])
    assert payload["mutable_handoff_bound_before_overwrite"] is True
    rows = [row for row in payload["input_bindings"] if row["role"] == "next_lawful_move"]
    assert len(rows) == 1
    assert rows[0]["binding_kind"] == "git_object_before_overwrite"


def test_handoff_accepts_predecessor_packet(outputs: Path) -> None:
    assert _contract(outputs)["handoff_state"]["predecessor_handoff_accepted"] is True


def test_activation_review_validation_accepts_self_replay_handoff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    result = validation.run(reports_root=reports)
    assert result["verdict"] == validation.SELECTED_OUTCOME
    assert _next(reports)["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert _contract(reports)["handoff_state"]["self_replay_handoff_accepted"] is True


def test_validation_plan_expected_outcome_matches_validator(outputs: Path) -> None:
    payload = _load(outputs / activation.OUTPUTS["validation_plan"])
    assert payload["expected_successful_validation_outcome"] == validation.SELECTED_OUTCOME
    assert payload["expected_next_lawful_move_after_validation"] == validation.NEXT_LAWFUL_MOVE


def test_validation_report_states_non_activation(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "does not authorize limited runtime" in text
    assert validation.NEXT_LAWFUL_MOVE.lower() in text.lower()


def test_row_count_exceeds_minimum_bar(outputs: Path) -> None:
    assert _receipt(outputs)["pass_count"] >= 70


def test_validation_rejects_packet_self_validation_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_activation_outputs(tmp_path, monkeypatch)
    path = reports / activation.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["activation_review_validated"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="SELF_VALIDATION_DRIFT"):
        validation.run(reports_root=reports)


def test_validation_rejects_limited_runtime_authorization_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_activation_outputs(tmp_path, monkeypatch)
    path = reports / activation.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["limited_runtime_authorized"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_validation_rejects_copied_next_move_without_lane_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_activation_outputs(tmp_path, monkeypatch)
    path = reports / activation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["authoritative_lane"] = "COPIED_ACTIVATION_MOVE"
    payload["selected_outcome"] = activation.SELECTED_OUTCOME
    payload["next_lawful_move"] = activation.NEXT_LAWFUL_MOVE
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_validation_rejects_mutated_candidate_after_packet_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_activation_outputs(tmp_path, monkeypatch)
    path = tmp_path / activation.INPUTS["candidate_artifact"]
    payload = _load(path)
    payload["candidate_id"] = "MUTATED_AFTER_PACKET_BINDING"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="MULTIPLE_HASH_BINDING_SOURCES"):
        validation.run(reports_root=reports)


def test_validation_rejects_divergent_packet_receipt_binding_hashes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_activation_outputs(tmp_path, monkeypatch)
    path = reports / activation.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["binding_hashes"]["candidate_hash"] = "0" * 64
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="MULTIPLE_HASH_BINDING_SOURCES"):
        validation.run(reports_root=reports)


def test_validation_rejects_missing_kill_switch_requirement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_activation_outputs(tmp_path, monkeypatch)
    path = reports / activation.OUTPUTS["kill_switch_contract"]
    payload = _load(path)
    payload["requirements"] = [item for item in payload["requirements"] if item != "kill_switch_required"]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="KILL_SWITCH_MISSING"):
        validation.run(reports_root=reports)


def test_validation_rejects_missing_abstention_fallback_requirement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_activation_outputs(tmp_path, monkeypatch)
    path = reports / activation.OUTPUTS["static_fallback_contract"]
    payload = _load(path)
    payload["requirements"] = [item for item in payload["requirements"] if item != "abstention_fallback_required"]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="ABSTENTION_FALLBACK_MISSING"):
        validation.run(reports_root=reports)


def test_validation_rejects_commercial_claim_boundary_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_activation_outputs(tmp_path, monkeypatch)
    path = reports / activation.OUTPUTS["commercial_claim_boundary"]
    payload = _load(path)
    payload["requirements"] = [item for item in payload["requirements"] if item != "package_promotion_prohibited"]
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PACKAGE_PROMOTION_AUTOMATIC"):
        validation.run(reports_root=reports)


def test_validation_rejects_prep_only_authority_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_activation_outputs(tmp_path, monkeypatch)
    path = reports / activation.OUTPUTS["limited_runtime_authorization_prep_only_draft"]
    payload = _load(path)
    payload["authority"] = "AUTHORITATIVE"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PREP_ONLY_AUTHORITY_DRIFT"):
        validation.run(reports_root=reports)


def test_validation_rejects_validation_plan_next_move_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_activation_outputs(tmp_path, monkeypatch)
    path = reports / activation.OUTPUTS["validation_plan"]
    payload = _load(path)
    payload["expected_next_lawful_move_after_validation"] = "RUNTIME_CUTOVER"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)
