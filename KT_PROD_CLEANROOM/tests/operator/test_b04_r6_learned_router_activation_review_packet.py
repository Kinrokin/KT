from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_learned_router_activation_review_packet as activation


ACT_HEAD = "3333333333333333333333333333333333333333"
ACT_MAIN_HEAD = "4444444444444444444444444444444444444444"


def _load_screen_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_afsh_shadow_screen.py")
    spec = importlib.util.spec_from_file_location("b04_r6_shadow_screen_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load shadow-screen test helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


screen_helpers = _load_screen_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_activation_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = activation.AUTHORITY_BRANCH,
    head: str = ACT_HEAD,
    origin_main: str = ACT_MAIN_HEAD,
) -> None:
    monkeypatch.setattr(activation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(activation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(activation.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(activation.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        activation,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_activation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = screen_helpers._run_screen(tmp_path, monkeypatch)
    _patch_activation_env(monkeypatch, tmp_path)
    activation.run(reports_root=reports)
    return reports


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return _run_activation(tmp_path, monkeypatch)


def _contract(outputs: Path) -> dict:
    return _load(outputs / activation.OUTPUTS["packet_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / activation.OUTPUTS["packet_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / activation.OUTPUTS["next_lawful_move"])


JSON_OUTPUT_ROLES = [role for role, name in activation.OUTPUTS.items() if not name.endswith(".md")]


@pytest.mark.parametrize("role", JSON_OUTPUT_ROLES)
def test_required_activation_review_outputs_exist_and_parse(outputs: Path, role: str) -> None:
    payload = _load(outputs / activation.OUTPUTS[role])
    assert payload["artifact_id"]
    assert payload["schema_id"]


def test_activation_review_packet_report_exists(outputs: Path) -> None:
    report = (outputs / activation.OUTPUTS["packet_report"]).read_text(encoding="utf-8")
    assert "activation-review" in report.lower()
    assert activation.SELECTED_OUTCOME in report


def test_activation_review_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == ACT_MAIN_HEAD


def test_activation_review_packet_binds_shadow_superiority_result(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["predecessor_outcome"] == activation.EXPECTED_PREVIOUS_OUTCOME
    assert contract["shadow_screen_result"]["status"] == "SHADOW_SUPERIORITY_PASSED"


def test_activation_review_packet_binds_zero_fired_disqualifiers(outputs: Path) -> None:
    assert _contract(outputs)["shadow_screen_result"]["fired_disqualifiers"] == []


@pytest.mark.parametrize(
    "key",
    [
        "shadow_screen_result_hash",
        "shadow_screen_execution_receipt_hash",
        "shadow_screen_result_report_hash",
        "fired_disqualifier_receipt_hash",
        "candidate_hash",
        "candidate_manifest_hash",
        "candidate_semantic_hash",
        "candidate_hash_receipt_hash",
        "validated_shadow_screen_packet_hash",
        "validated_shadow_packet_validation_receipt_hash",
        "validated_blind_universe_hash",
        "validated_blind_universe_receipt_hash",
        "validated_route_economics_court_hash",
        "validated_route_economics_court_receipt_hash",
        "validated_source_packet_hash",
        "validated_source_packet_receipt_hash",
        "admissibility_receipt_hash",
        "numeric_triage_emit_core_hash",
        "static_comparator_contract_hash",
        "metric_contract_hash",
        "disqualifier_ledger_hash",
        "trace_completeness_receipt_hash",
        "trust_zone_validation_receipt_hash",
        "no_authorization_drift_receipt_hash",
    ],
)
def test_activation_review_packet_binds_required_hashes(outputs: Path, key: str) -> None:
    value = _contract(outputs)["binding_hashes"][key]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize(
    "role,key",
    [
        ("shadow_result_binding_receipt", "shadow_screen_result_hash"),
        ("candidate_binding_receipt", "candidate_hash"),
        ("screen_packet_binding_receipt", "validated_shadow_screen_packet_hash"),
        ("universe_binding_receipt", "validated_blind_universe_hash"),
        ("court_binding_receipt", "validated_route_economics_court_hash"),
        ("source_packet_binding_receipt", "validated_source_packet_hash"),
        ("admissibility_binding_receipt", "admissibility_receipt_hash"),
        ("triage_core_binding_receipt", "numeric_triage_emit_core_hash"),
        ("static_comparator_binding_receipt", "static_comparator_contract_hash"),
        ("metric_contract_binding_receipt", "metric_contract_hash"),
        ("disqualifier_binding_receipt", "disqualifier_ledger_hash"),
        ("trace_completeness_binding_receipt", "trace_completeness_receipt_hash"),
    ],
)
def test_binding_receipts_bind_expected_subjects(outputs: Path, role: str, key: str) -> None:
    payload = _load(outputs / activation.OUTPUTS[role])
    assert payload["binding_status"] == "BOUND"
    assert payload["bound_hashes"][key] == _contract(outputs)["binding_hashes"][key]


@pytest.mark.parametrize(
    "flag",
    [
        "r6_open",
        "activation_review_validated",
        "limited_runtime_authorized",
        "runtime_cutover_authorized",
        "activation_cutover_executed",
        "activation_cutover_authorized",
        "lobe_escalation_authorized",
        "package_promotion_authorized",
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
    ],
)
def test_shadow_superiority_does_not_authorize_runtime_boundaries(outputs: Path, flag: str) -> None:
    assert _contract(outputs)[flag] is False


def test_shadow_superiority_records_packet_authorship_only(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["shadow_superiority_passed"] is True
    assert contract["activation_review_packet_authored"] is True
    assert contract["activation_review_validated"] is False


@pytest.mark.parametrize(
    "role",
    [
        "scope_contract",
        "runtime_preconditions_contract",
        "static_fallback_contract",
        "operator_override_contract",
        "kill_switch_contract",
        "rollback_plan_contract",
        "route_distribution_health_contract",
        "drift_monitoring_contract",
        "runtime_receipt_schema_contract",
        "external_verifier_requirements",
        "commercial_claim_boundary",
    ],
)
def test_activation_review_control_contracts_exist_and_are_non_authorizing(outputs: Path, role: str) -> None:
    payload = _load(outputs / activation.OUTPUTS[role])
    assert payload["required_before_limited_runtime_authorization"] is True
    assert payload["can_authorize_limited_runtime"] is False
    assert payload["can_execute_runtime"] is False
    assert payload["can_open_r6"] is False


@pytest.mark.parametrize("key", activation.RUNTIME_PRECONDITION_KEYS)
def test_runtime_preconditions_are_required(outputs: Path, key: str) -> None:
    assert _contract(outputs)["runtime_preconditions"][key] is True


@pytest.mark.parametrize("requirement", activation.ACTIVATION_SUCCESS_REQUIREMENTS)
def test_activation_review_success_requirements_are_defined(outputs: Path, requirement: str) -> None:
    assert requirement in _contract(outputs)["activation_review_success_requirements"]


@pytest.mark.parametrize(
    "role",
    [
        "limited_runtime_authorization_prep_only_draft",
        "limited_runtime_scope_manifest_prep_only_draft",
        "limited_runtime_monitoring_prep_only_draft",
        "limited_runtime_rollback_receipt_schema_prep_only_draft",
        "package_promotion_review_preconditions_prep_only_draft",
        "external_audit_delta_manifest_prep_only_draft",
    ],
)
def test_future_runtime_and_package_outputs_are_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / activation.OUTPUTS[role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["limited_runtime_authorized"] is False
    assert payload["runtime_cutover_authorized"] is False
    assert payload["package_promotion_authorized"] is False


def test_activation_review_packet_does_not_validate_itself(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["activation_review_packet_authored"] is True
    assert contract["activation_review_validated"] is False
    assert contract["next_lawful_move"] == activation.NEXT_LAWFUL_MOVE


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    payload = _load(outputs / activation.OUTPUTS["no_authorization_drift_receipt"])
    assert payload["no_downstream_authorization_drift"] is True
    assert payload["limited_runtime_authorized"] is False
    assert payload["r6_open"] is False


def test_validation_plan_scaffolds_next_lane(outputs: Path) -> None:
    payload = _load(outputs / activation.OUTPUTS["validation_plan"])
    assert payload["validator_role"].startswith("hostile verifier")
    assert payload["expected_successful_validation_outcome"] == "B04_R6_ACTIVATION_REVIEW_VALIDATED__LIMITED_RUNTIME_AUTHORIZATION_PACKET_NEXT"
    assert payload["expected_next_lawful_move_after_validation"] == "AUTHOR_B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET"


@pytest.mark.parametrize("reason_code", activation.REASON_CODES[:20])
def test_validation_reason_code_taxonomy_includes_core_codes(outputs: Path, reason_code: str) -> None:
    payload = _load(outputs / activation.OUTPUTS["validation_reason_codes"])
    assert reason_code in payload["reason_codes"]


@pytest.mark.parametrize("defect", activation.TERMINAL_DEFECTS)
def test_terminal_defect_taxonomy_is_bound(outputs: Path, defect: str) -> None:
    payload = _load(outputs / activation.OUTPUTS["validation_reason_codes"])
    assert defect in payload["terminal_defects"]


def test_next_lawful_move_is_activation_review_validation(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == activation.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == activation.NEXT_LAWFUL_MOVE
    assert nxt["authoritative_lane"] == activation.AUTHORITATIVE_LANE


def test_input_handoff_validates_previous_authoritative_lane(outputs: Path) -> None:
    assert _contract(outputs)["handoff_validation"]["predecessor_handoff_accepted"] is True


def test_future_blocker_register_names_runtime_and_claim_blockers(outputs: Path) -> None:
    payload = _load(outputs / activation.OUTPUTS["future_blocker_register"])
    blockers = {row["blocker_id"]: row for row in payload["blockers"]}
    assert "B04R6-FB-031" in blockers
    assert "B04R6-FB-033" in blockers


def test_activation_review_rejects_fired_disqualifiers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = screen_helpers._run_screen(tmp_path, monkeypatch)
    result_path = reports / "b04_r6_afsh_shadow_screen_result.json"
    payload = _load(result_path)
    payload["disqualifier_result"]["fired_disqualifiers"] = ["metric_contract_mutated"]
    _write(result_path, payload)
    _patch_activation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FIRED_DISQUALIFIERS_NOT_ZERO"):
        activation.run(reports_root=reports)


def test_activation_review_rejects_copied_move_without_lane_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = screen_helpers._run_screen(tmp_path, monkeypatch)
    next_path = reports / activation.OUTPUTS["next_lawful_move"]
    payload = _load(next_path)
    payload["authoritative_lane"] = "COPIED_BUT_NOT_AUTHORITATIVE"
    payload["selected_outcome"] = activation.EXPECTED_PREVIOUS_OUTCOME
    payload["next_lawful_move"] = activation.EXPECTED_PREVIOUS_NEXT_MOVE
    _write(next_path, payload)
    _patch_activation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        activation.run(reports_root=reports)


def test_activation_review_rejects_runtime_authorization_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = screen_helpers._run_screen(tmp_path, monkeypatch)
    result_path = reports / "b04_r6_afsh_shadow_screen_result.json"
    payload = _load(result_path)
    payload["limited_runtime_authorized"] = True
    _write(result_path, payload)
    _patch_activation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="LIMITED_RUNTIME_AUTHORIZED"):
        activation.run(reports_root=reports)


def test_activation_review_rejects_mutated_candidate_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = screen_helpers._run_screen(tmp_path, monkeypatch)
    candidate_path = tmp_path / activation.INPUTS["candidate_artifact"]
    payload = _load(candidate_path)
    payload["candidate_id"] = "MUTATED"
    _write(candidate_path, payload)
    _patch_activation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="CANDIDATE_BINDING_MISSING"):
        activation.run(reports_root=reports)


@pytest.mark.parametrize(
    "role",
    [
        "validated_blind_universe_receipt",
        "validated_route_economics_court_receipt",
        "validated_source_packet_receipt",
    ],
)
def test_activation_review_rejects_mutated_upstream_validation_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    reports = screen_helpers._run_screen(tmp_path, monkeypatch)
    path = tmp_path / activation.INPUTS[role]
    payload = _load(path)
    payload["status"] = "PASS"
    payload["post_screen_mutation"] = True
    _write(path, payload)
    _patch_activation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="CANDIDATE_BINDING_MISSING"):
        activation.run(reports_root=reports)


def test_activation_review_rejects_divergent_shadow_execution_binding_hashes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = screen_helpers._run_screen(tmp_path, monkeypatch)
    receipt_path = reports / "b04_r6_afsh_shadow_screen_execution_receipt.json"
    payload = _load(receipt_path)
    payload["binding_hashes"]["validated_blind_universe_hash"] = "a" * 64
    _write(receipt_path, payload)
    _patch_activation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="binding hashes diverged"):
        activation.run(reports_root=reports)


def test_activation_review_accepts_self_replay_handoff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_activation(tmp_path, monkeypatch)
    _patch_activation_env(monkeypatch, tmp_path)
    activation.run(reports_root=reports)
    payload = _load(reports / activation.OUTPUTS["packet_contract"])
    assert payload["handoff_validation"]["self_replay_handoff_accepted"] is True
