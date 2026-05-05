from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_b04_r6_limited_runtime_authorization_packet as limited_auth
from tools.operator import cohort0_b04_r6_limited_runtime_authorization_packet_validation as auth_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_lane_compiler
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-limited-runtime-execution-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET"
PREVIOUS_LANE = auth_validation.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = auth_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = auth_validation.NEXT_LAWFUL_MOVE
OUTCOME_BOUND = "B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_BOUND__LIMITED_RUNTIME_EXECUTION_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET"

MAY_AUTHORIZE = ("LIMITED_RUNTIME_EXECUTION_PACKET_AUTHORED",)
FORBIDDEN_ACTIONS = (
    "LIMITED_RUNTIME_EXECUTED",
    "LIMITED_RUNTIME_EXECUTION_AUTHORIZED",
    "LIMITED_RUNTIME_AUTHORIZED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "ACTIVATION_CUTOVER_EXECUTED",
    "R6_OPEN",
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "METRIC_CONTRACT_MUTATED",
    "STATIC_COMPARATOR_WEAKENED",
)
TERMINAL_DEFECTS = (
    "LIMITED_RUNTIME_EXECUTED",
    "LIMITED_RUNTIME_EXECUTION_AUTHORIZED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "R6_OPEN_DRIFT",
    "LOBE_ESCALATION_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL_CLAIM_DRIFT",
    "METRIC_MUTATION",
    "COMPARATOR_WEAKENING",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "NEXT_MOVE_DRIFT",
)
REASON_CODES = (
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_CONTRACT_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_MAIN_HEAD_MISMATCH",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_SCOPE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_MODE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_STATIC_AUTHORITY_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AFSH_OBSERVATION_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_OPERATOR_OVERRIDE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_KILL_SWITCH_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_ROLLBACK_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_ROUTE_HEALTH_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_DRIFT_MONITORING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_RUNTIME_RECEIPT_SCHEMA_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_INCIDENT_FREEZE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_LIMITED_RUNTIME_EXECUTION_AUTHORIZED",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_R6_OPEN_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_METRIC_MUTATION",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_COMPARATOR_WEAKENING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_TRUST_ZONE_MUTATION",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_NEXT_MOVE_DRIFT",
)

RUNTIME_MODE = "SHADOW_RUNTIME_ONLY"
ALLOWED_FUTURE_EXECUTION_MODES = ("SHADOW_RUNTIME_ONLY",)
FORBIDDEN_RUNTIME_MODES = (
    "AUTONOMOUS_CUTOVER",
    "GLOBAL_R6",
    "PRODUCTION_ROUTING",
    "PACKAGE_PROMOTION_RUNTIME",
)
RUNTIME_RECEIPT_FIELDS = (
    "runtime_receipt_id",
    "case_id",
    "execution_mode",
    "static_authoritative_decision",
    "afsh_shadow_decision",
    "afsh_observation_only",
    "selector_entry_authorized",
    "static_fallback_status",
    "abstention_fallback_status",
    "null_route_preservation_status",
    "operator_override_status",
    "kill_switch_status",
    "rollback_status",
    "route_distribution_health_status",
    "drift_status",
    "incident_freeze_status",
    "trace_receipt_hash",
    "raw_hash_bound_artifact_refs",
    "external_verifier_refs",
    "commercial_claim_boundary_status",
)
INCIDENT_FREEZE_CONDITIONS = (
    "static_authority_drift",
    "afsh_user_facing_decision_change",
    "selector_entry_rate_out_of_bounds",
    "abstention_collapse",
    "null_route_collapse",
    "kill_switch_failure",
    "rollback_failure",
    "trace_receipt_missing",
    "trust_zone_drift",
    "truth_engine_drift",
)
ROUTE_HEALTH_SIGNALS = (
    "selector_entry_rate",
    "static_hold_rate",
    "abstention_rate",
    "null_route_rate",
    "operator_override_rate",
    "kill_switch_readiness",
    "rollback_readiness",
)

VALIDATION_JSON_INPUTS = {
    f"validation_{role}": f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in auth_validation.OUTPUTS.items()
    if filename.endswith(".json")
}
AUTHORIZATION_PACKET_JSON_INPUTS = {
    f"authorized_{role}": raw for role, raw in auth_validation.PACKET_JSON_INPUTS.items()
}
INPUTS = {**AUTHORIZATION_PACKET_JSON_INPUTS, **VALIDATION_JSON_INPUTS}
TEXT_INPUTS = {
    "authorization_packet_report": f"KT_PROD_CLEANROOM/reports/{limited_auth.OUTPUTS['packet_report']}",
    "authorization_validation_report": f"KT_PROD_CLEANROOM/reports/{auth_validation.OUTPUTS['validation_report']}",
}

CONTROL_OUTPUT_ROLES = (
    "scope_manifest",
    "mode_contract",
    "case_class_contract",
    "static_authority_contract",
    "afsh_shadow_observation_contract",
    "operator_override_contract",
    "kill_switch_execution_contract",
    "rollback_execution_contract",
    "route_distribution_health_contract",
    "drift_monitoring_contract",
    "incident_freeze_contract",
    "runtime_receipt_schema",
    "external_verifier_requirements",
    "commercial_claim_boundary",
)
PREP_ONLY_OUTPUT_ROLES = (
    "runtime_evidence_review_packet_prep_only_draft",
    "runtime_evidence_scorecard_prep_only_draft",
    "runtime_route_distribution_health_review_prep_only",
    "runtime_operator_intervention_review_prep_only",
    "runtime_trace_completeness_review_prep_only",
    "runtime_incident_and_freeze_review_prep_only",
    "runtime_rollback_readiness_review_prep_only",
    "limited_runtime_failure_closeout_prep_only",
    "runtime_rollback_execution_receipt_schema_prep_only",
    "runtime_incident_forensic_court_prep_only",
    "runtime_freeze_condition_contract_prep_only",
    "runtime_redesign_authorization_court_prep_only",
    "external_verifier_delta_requirements_prep_only",
    "external_audit_delta_manifest_prep_only",
    "replay_bundle_manifest_prep_only",
    "public_verifier_receipt_schema_prep_only",
    "external_hash_manifest_prep_only",
    "commercial_claim_boundary_update_prep_only",
    "forbidden_runtime_claims_receipt_prep_only",
    "deployment_profile_delta_prep_only",
)
VALIDATION_SIGNED_AUTHORIZATION_INPUT_ROLES = (
    "packet_contract",
    "packet_receipt",
    "scope_manifest",
    "static_fallback_contract",
    "abstention_fallback_contract",
    "null_route_preservation_contract",
    "operator_override_contract",
    "kill_switch_contract",
    "rollback_plan",
    "route_distribution_health_contract",
    "drift_monitoring_contract",
    "runtime_receipt_schema",
    "incident_freeze_contract",
    "external_verifier_requirements",
    "commercial_claim_boundary",
    "activation_review_validation_binding_receipt",
    "candidate_binding_receipt",
    "shadow_result_binding_receipt",
)

OUTPUTS = {
    "execution_packet_contract": "b04_r6_limited_runtime_execution_packet_contract.json",
    "execution_packet_receipt": "b04_r6_limited_runtime_execution_packet_receipt.json",
    "execution_packet_report": "b04_r6_limited_runtime_execution_packet_report.md",
    "authorization_validation_binding_receipt": "b04_r6_limited_runtime_execution_authorization_validation_binding_receipt.json",
    "shadow_result_binding_receipt": "b04_r6_limited_runtime_execution_shadow_result_binding_receipt.json",
    "candidate_binding_receipt": "b04_r6_limited_runtime_execution_candidate_binding_receipt.json",
    "scope_manifest": "b04_r6_limited_runtime_scope_manifest.json",
    "mode_contract": "b04_r6_limited_runtime_mode_contract.json",
    "case_class_contract": "b04_r6_limited_runtime_case_class_contract.json",
    "static_authority_contract": "b04_r6_limited_runtime_static_authority_contract.json",
    "afsh_shadow_observation_contract": "b04_r6_limited_runtime_afsh_shadow_observation_contract.json",
    "operator_override_contract": "b04_r6_limited_runtime_operator_override_contract.json",
    "kill_switch_execution_contract": "b04_r6_limited_runtime_kill_switch_execution_contract.json",
    "rollback_execution_contract": "b04_r6_limited_runtime_rollback_execution_contract.json",
    "route_distribution_health_contract": "b04_r6_limited_runtime_route_distribution_health_contract.json",
    "drift_monitoring_contract": "b04_r6_limited_runtime_drift_monitoring_contract.json",
    "incident_freeze_contract": "b04_r6_limited_runtime_incident_freeze_contract.json",
    "runtime_receipt_schema": "b04_r6_limited_runtime_receipt_schema.json",
    "external_verifier_requirements": "b04_r6_limited_runtime_external_verifier_requirements.json",
    "commercial_claim_boundary": "b04_r6_limited_runtime_commercial_claim_boundary.json",
    "no_authorization_drift_receipt": "b04_r6_limited_runtime_no_authorization_drift_receipt.json",
    "execution_validation_plan": "b04_r6_limited_runtime_execution_validation_plan.json",
    "execution_validation_reason_codes": "b04_r6_limited_runtime_execution_validation_reason_codes.json",
    "lane_compiler_scaffold_receipt": "b04_r6_limited_runtime_execution_packet_lane_compiler_scaffold_receipt.json",
    "runtime_evidence_review_packet_prep_only_draft": "b04_r6_runtime_evidence_review_packet_prep_only_draft.json",
    "runtime_evidence_scorecard_prep_only_draft": "b04_r6_runtime_evidence_scorecard_prep_only_draft.json",
    "runtime_route_distribution_health_review_prep_only": "b04_r6_runtime_route_distribution_health_review_prep_only.json",
    "runtime_operator_intervention_review_prep_only": "b04_r6_runtime_operator_intervention_review_prep_only.json",
    "runtime_trace_completeness_review_prep_only": "b04_r6_runtime_trace_completeness_review_prep_only.json",
    "runtime_incident_and_freeze_review_prep_only": "b04_r6_runtime_incident_and_freeze_review_prep_only.json",
    "runtime_rollback_readiness_review_prep_only": "b04_r6_runtime_rollback_readiness_review_prep_only.json",
    "limited_runtime_failure_closeout_prep_only": "b04_r6_limited_runtime_failure_closeout_prep_only.json",
    "runtime_rollback_execution_receipt_schema_prep_only": "b04_r6_runtime_rollback_execution_receipt_schema_prep_only.json",
    "runtime_incident_forensic_court_prep_only": "b04_r6_runtime_incident_forensic_court_prep_only.json",
    "runtime_freeze_condition_contract_prep_only": "b04_r6_runtime_freeze_condition_contract_prep_only.json",
    "runtime_redesign_authorization_court_prep_only": "b04_r6_runtime_redesign_authorization_court_prep_only.json",
    "external_verifier_delta_requirements_prep_only": "b04_r6_external_verifier_delta_requirements_prep_only.json",
    "external_audit_delta_manifest_prep_only": "b04_r6_external_audit_delta_manifest_prep_only.json",
    "replay_bundle_manifest_prep_only": "b04_r6_replay_bundle_manifest_prep_only.json",
    "public_verifier_receipt_schema_prep_only": "b04_r6_public_verifier_receipt_schema_prep_only.json",
    "external_hash_manifest_prep_only": "b04_r6_external_hash_manifest_prep_only.json",
    "commercial_claim_boundary_update_prep_only": "b04_r6_commercial_claim_boundary_update_prep_only.json",
    "forbidden_runtime_claims_receipt_prep_only": "b04_r6_forbidden_runtime_claims_receipt_prep_only.json",
    "operator_runbook_delta_prep_only": "b04_r6_operator_runbook_delta_prep_only.md",
    "deployment_profile_delta_prep_only": "b04_r6_deployment_profile_delta_prep_only.json",
    "customer_safe_status_language_prep_only": "b04_r6_customer_safe_status_language_prep_only.md",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "runtime_corridor_status": "b04_r6_runtime_corridor_status.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}


def _fail(code: str, detail: str) -> None:
    raise RuntimeError(f"FAIL_CLOSED: {code}: {detail}")


def _ensure_branch_context(root: Path) -> str:
    current_branch = common.git_current_branch_name(root)
    if current_branch not in ALLOWED_BRANCHES:
        allowed = ", ".join(sorted(ALLOWED_BRANCHES))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}; got: {current_branch}")
    if current_branch == "main":
        head = common.git_rev_parse(root, "HEAD")
        origin_main = common.git_rev_parse(root, "origin/main")
        if head != origin_main:
            raise RuntimeError(
                "FAIL_CLOSED: main replay requires local main converged with origin/main; "
                f"HEAD={head}; origin/main={origin_main}"
            )
    return current_branch


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


def _is_sha256(value: Any) -> bool:
    text = str(value)
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _ensure_runtime_closed(payload: Dict[str, Any], *, label: str) -> None:
    true_forbidden = (
        ("r6_open", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_R6_OPEN_DRIFT"),
        ("limited_runtime_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_LIMITED_RUNTIME_EXECUTION_AUTHORIZED"),
        ("limited_runtime_execution_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_LIMITED_RUNTIME_EXECUTION_AUTHORIZED"),
        ("limited_runtime_executed", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_LIMITED_RUNTIME_EXECUTION_AUTHORIZED"),
        ("runtime_execution_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_LIMITED_RUNTIME_EXECUTION_AUTHORIZED"),
        ("runtime_cutover_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED"),
        ("activation_cutover_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED"),
        ("activation_cutover_executed", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED"),
        ("lobe_escalation_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_LOBE_ESCALATION_DRIFT"),
        ("package_promotion_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT"),
        ("commercial_activation_claim_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT"),
        ("truth_engine_law_changed", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_TRUTH_ENGINE_MUTATION"),
        ("trust_zone_law_changed", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_TRUST_ZONE_MUTATION"),
        ("metric_contract_mutated", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_METRIC_MUTATION"),
        ("static_comparator_weakened", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_COMPARATOR_WEAKENING"),
    )
    for key, code in true_forbidden:
        if payload.get(key) is True:
            _fail(code, f"{label} sets {key}")
    state = payload.get("authorization_state")
    if isinstance(state, dict):
        _ensure_runtime_closed(state, label=f"{label}.authorization_state")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT", f"{label} package promotion drift")
    if payload.get("truth_engine_derivation_law_unchanged") is False:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_TRUTH_ENGINE_MUTATION", f"{label} truth derivation drift")
    if payload.get("trust_zone_law_unchanged") is False:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_TRUST_ZONE_MUTATION", f"{label} trust-zone drift")


def _validate_handoff(payload: Dict[str, Any]) -> Dict[str, bool]:
    predecessor = (
        payload.get("authoritative_lane") == PREVIOUS_LANE
        and payload.get("selected_outcome") == EXPECTED_PREVIOUS_OUTCOME
        and payload.get("next_lawful_move") == EXPECTED_PREVIOUS_NEXT_MOVE
    )
    self_replay = (
        payload.get("authoritative_lane") == AUTHORITATIVE_LANE
        and payload.get("selected_outcome") == SELECTED_OUTCOME
        and payload.get("next_lawful_move") == NEXT_LAWFUL_MOVE
    )
    if not (predecessor or self_replay):
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_NEXT_MOVE_DRIFT", "handoff lacks valid predecessor or self-replay lane identity")
    return {"predecessor_handoff_accepted": predecessor, "self_replay_handoff_accepted": self_replay}


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> Dict[str, bool]:
    validation_contract = payloads["validation_validation_contract"]
    validation_receipt = payloads["validation_validation_receipt"]
    next_move = payloads["validation_next_lawful_move"]
    for label, payload in payloads.items():
        _ensure_runtime_closed(payload, label=label)
        if label == "validation_next_lawful_move":
            continue
        if payload.get("status") not in (None, "PASS", "PREP_ONLY"):
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"{label} must be PASS/PREP_ONLY/structural")
    for label, payload in (("validation_contract", validation_contract), ("validation_receipt", validation_receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"{label} lane identity drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"{label} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_NEXT_MOVE_DRIFT", f"{label} next move drift")
        if payload.get("limited_runtime_authorization_packet_validated") is not True:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"{label} missing packet validation")
    accepted = _validate_handoff(next_move)
    if "does not authorize limited-runtime execution" not in texts["authorization_validation_report"].lower():
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", "validation report lacks non-execution boundary")
    return accepted


def _validate_current_authorization_inputs_match_validation(
    root: Path, payloads: Dict[str, Dict[str, Any]], handoff_acceptance: Dict[str, bool]
) -> None:
    validation_hashes = payloads["validation_validation_contract"].get("binding_hashes")
    if not isinstance(validation_hashes, dict):
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", "validation binding hashes missing")
    output_names = set(OUTPUTS.values())
    self_replay = handoff_acceptance.get("self_replay_handoff_accepted") is True
    for signed_role in VALIDATION_SIGNED_AUTHORIZATION_INPUT_ROLES:
        input_role = f"authorized_{signed_role}"
        raw = AUTHORIZATION_PACKET_JSON_INPUTS[input_role]
        expected = validation_hashes.get(f"{signed_role}_hash")
        if not _is_sha256(expected):
            _fail(
                "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING",
                f"validation did not bind {input_role}",
            )
        actual = file_sha256(common.resolve_path(root, raw))
        if actual == expected:
            continue
        payload = payloads[input_role]
        if self_replay and Path(raw).name in output_names and _is_execution_self_replay_payload(payload):
            continue
        _fail(
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING",
            f"{input_role} current hash differs from validation binding",
        )


def _requirements(payload: Dict[str, Any]) -> set[str]:
    values = payload.get("requirements")
    if not isinstance(values, list):
        return set()
    return {str(value) for value in values}


def _is_execution_self_replay_payload(payload: Dict[str, Any]) -> bool:
    return (
        payload.get("authoritative_lane") == AUTHORITATIVE_LANE
        and payload.get("selected_outcome") == SELECTED_OUTCOME
        and payload.get("next_lawful_move") == NEXT_LAWFUL_MOVE
    )


def _requirements_match(payload: Dict[str, Any], acceptable_sets: Sequence[Sequence[str]]) -> bool:
    requirements = _requirements(payload)
    return any(set(values).issubset(requirements) for values in acceptable_sets)


def _validate_authorized_controls(payloads: Dict[str, Dict[str, Any]]) -> None:
    scope = payloads["authorized_scope_manifest"]
    if _is_execution_self_replay_payload(scope):
        if scope.get("limited_scope_required") is not True:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_SCOPE_MISSING", "self-replay execution scope is not limited")
        if scope.get("max_live_traffic_percent_authorized_by_this_packet") != 0:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "self-replay execution scope allowed live traffic")
        if scope.get("selected_runtime_mode") != RUNTIME_MODE:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_MODE_MISSING", "self-replay execution scope lacks shadow-runtime mode")
        if scope.get("global_r6_scope") is not False:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_R6_OPEN_DRIFT", "self-replay execution scope drifted to global R6")
        if scope.get("user_facing_decision_changes_allowed") is not False:
            _fail(
                "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_LIMITED_RUNTIME_EXECUTION_AUTHORIZED",
                "self-replay execution scope allowed user-facing decision changes",
            )
        if not {"not_global_r6", "no_live_traffic_authorized"}.issubset(_requirements(scope)):
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_SCOPE_MISSING", "self-replay execution scope lost bounded requirements")
    else:
        if scope.get("limited_scope_required") is not True:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_SCOPE_MISSING", "validated authorization scope is not limited")
        if scope.get("max_live_traffic_percent_authorized_by_this_packet") != 0:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "validated authorization allowed live traffic")
        if scope.get("allowed_future_modes_after_validation") != ["CANARY_ONLY", "SHADOW_RUNTIME_ONLY"]:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_SCOPE_MISSING", "validated authorization lacks canary/shadow boundary")

    required = {
        "authorized_static_fallback_contract": (("static_comparator_remains_available", "static_hold_default_preserved"),),
        "authorized_abstention_fallback_contract": (("boundary_uncertainty_abstains", "trust_zone_uncertainty_abstains"),),
        "authorized_null_route_preservation_contract": (("null_route_controls_do_not_enter_selector", "surface_temptations_remain_blocked"),),
        "authorized_operator_override_contract": (
            ("operator_override_required", "override_may_force_static_fallback"),
            ("operator_override_required", "override_may_force_static_only", "override_receipt_required"),
        ),
        "authorized_kill_switch_contract": (("kill_switch_required", "kill_switch_returns_to_static_comparator"),),
        "authorized_rollback_plan": (("rollback_to_static_comparator_required", "rollback_execution_receipt_required"),),
        "authorized_route_distribution_health_contract": (("selector_entry_rate_monitored", "overrouting_alarm_required"),),
        "authorized_drift_monitoring_contract": (("metric_drift_freezes_runtime", "trust_zone_drift_freezes_runtime"),),
        "authorized_external_verifier_requirements": (("external_verifier_non_executing", "raw_hash_bound_artifacts_required"),),
        "authorized_commercial_claim_boundary": (("commercial_activation_claims_unauthorized", "package_promotion_prohibited"),),
    }
    for role, acceptable_sets in required.items():
        if not _requirements_match(payloads[role], acceptable_sets):
            _fail(
                "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING",
                f"{role} missing one acceptable requirement set",
            )


def _input_bindings(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    output_names = set(OUTPUTS.values())
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(INPUTS.items()):
        path = common.resolve_path(root, raw)
        row: Dict[str, Any] = {
            "role": role,
            "path": raw,
            "sha256": file_sha256(path),
            "binding_kind": "file_sha256_at_limited_runtime_execution_packet_authoring",
        }
        if Path(raw).name in output_names:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(TEXT_INPUTS.items()):
        path = common.resolve_path(root, raw)
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(path),
                "binding_kind": "file_sha256_at_limited_runtime_execution_packet_authoring",
            }
        )
    return rows


def _binding_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    hashes = {f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(INPUTS.items())}
    hashes.update({f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(TEXT_INPUTS.items())})
    validation_hashes = payloads["validation_validation_contract"].get("binding_hashes")
    if not isinstance(validation_hashes, dict):
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", "validated packet hashes missing")
    for key in (
        "packet_contract_hash",
        "packet_receipt_hash",
        "activation_review_validation_contract_hash",
        "activation_review_validation_receipt_hash",
        "shadow_screen_result_hash",
        "candidate_hash",
        "candidate_manifest_hash",
        "candidate_semantic_hash",
        "static_comparator_contract_hash",
        "metric_contract_hash",
        "trace_completeness_receipt_hash",
        "trust_zone_validation_receipt_hash",
    ):
        value = validation_hashes.get(key)
        if not _is_sha256(value):
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"missing carried validation hash {key}")
        hashes[f"validated_{key}"] = str(value)
    return hashes


def _pass_row(check_id: str, reason_code: str, detail: str, *, group: str) -> Dict[str, str]:
    return {"check_id": check_id, "group": group, "status": "PASS", "reason_code": reason_code, "detail": detail}


def _validation_rows() -> list[Dict[str, str]]:
    rows = [
        _pass_row("execution_packet_contract_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_CONTRACT_MISSING", "execution packet contract exists", group="packet"),
        _pass_row("execution_packet_binds_authorization_validation", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", "authorization validation is bound", group="binding"),
        _pass_row(
            "execution_packet_current_inputs_match_authorization_validation",
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING",
            "current authorization inputs match validation bindings",
            group="binding",
        ),
        _pass_row("execution_packet_mode_is_shadow_runtime_only", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_MODE_MISSING", "mode is shadow runtime only", group="mode"),
        _pass_row("execution_packet_scope_is_limited", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_SCOPE_MISSING", "scope is limited", group="scope"),
        _pass_row("execution_packet_scope_is_not_global_r6", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_R6_OPEN_DRIFT", "scope is not global R6", group="scope"),
        _pass_row("execution_packet_static_remains_authoritative", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_STATIC_AUTHORITY_MISSING", "static remains authoritative", group="static"),
        _pass_row("execution_packet_afsh_observation_only", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AFSH_OBSERVATION_MISSING", "AFSH is observation only", group="mode"),
        _pass_row("execution_packet_operator_override_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_OPERATOR_OVERRIDE_MISSING", "operator override exists", group="controls"),
        _pass_row("execution_packet_kill_switch_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_KILL_SWITCH_MISSING", "kill switch exists", group="controls"),
        _pass_row("execution_packet_rollback_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_ROLLBACK_MISSING", "rollback exists", group="controls"),
        _pass_row("execution_packet_route_health_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_ROUTE_HEALTH_MISSING", "route health exists", group="monitoring"),
        _pass_row("execution_packet_drift_monitoring_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_DRIFT_MONITORING_MISSING", "drift monitoring exists", group="monitoring"),
        _pass_row("execution_packet_incident_freeze_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_INCIDENT_FREEZE_MISSING", "incident freeze exists", group="monitoring"),
        _pass_row("execution_packet_external_verifier_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_EXTERNAL_VERIFIER_MISSING", "external verifier exists", group="external"),
        _pass_row("execution_packet_commercial_claims_blocked", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT", "commercial claims blocked", group="claims"),
        _pass_row("execution_packet_package_promotion_blocked", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT", "package promotion blocked", group="claims"),
        _pass_row("execution_packet_validation_plan_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_CONTRACT_MISSING", "validation plan exists", group="scaffold"),
        _pass_row("execution_packet_reason_codes_exist", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_CONTRACT_MISSING", "reason codes exist", group="scaffold"),
        _pass_row("execution_packet_lane_compiler_scaffold_is_prep_only", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_PREP_ONLY_AUTHORITY_DRIFT", "compiler scaffold is prep-only", group="scaffold"),
        _pass_row("execution_packet_does_not_execute_limited_runtime", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "limited runtime not executed", group="authorization"),
        _pass_row("execution_packet_does_not_authorize_runtime_cutover", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED", "runtime cutover unauthorized", group="authorization"),
        _pass_row("execution_packet_does_not_open_r6", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_R6_OPEN_DRIFT", "R6 closed", group="authorization"),
        _pass_row("execution_packet_does_not_authorize_lobe_escalation", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_LOBE_ESCALATION_DRIFT", "lobe escalation unauthorized", group="authorization"),
        _pass_row("execution_packet_truth_engine_law_unchanged", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_TRUTH_ENGINE_MUTATION", "truth law unchanged", group="authorization"),
        _pass_row("execution_packet_trust_zone_law_unchanged", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_TRUST_ZONE_MUTATION", "trust law unchanged", group="authorization"),
        _pass_row("execution_packet_next_lawful_move_is_validation", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_NEXT_MOVE_DRIFT", "next move is validation", group="next_move"),
        _pass_row("pipeline_board_updated", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_CONTRACT_MISSING", "pipeline board updated", group="board"),
        _pass_row("runtime_corridor_status_updated", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_CONTRACT_MISSING", "runtime corridor status updated", group="board"),
    ]
    rows.extend(
        _pass_row(f"execution_packet_binds_{role}", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"{role} input is hash-bound", group="binding")
        for role in sorted(INPUTS)
    )
    rows.extend(
        _pass_row(f"execution_packet_writes_{role}", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_CONTRACT_MISSING", f"{role} output is emitted", group="outputs")
        for role in sorted(OUTPUTS)
    )
    rows.extend(
        _pass_row(f"runtime_receipt_requires_{field}", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_RUNTIME_RECEIPT_SCHEMA_MISSING", f"runtime receipt requires {field}", group="receipts")
        for field in RUNTIME_RECEIPT_FIELDS
    )
    rows.extend(
        _pass_row(f"incident_freeze_on_{condition}", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_INCIDENT_FREEZE_MISSING", f"incident freezes on {condition}", group="incident")
        for condition in INCIDENT_FREEZE_CONDITIONS
    )
    rows.extend(
        _pass_row(f"route_health_monitors_{signal}", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_ROUTE_HEALTH_MISSING", f"route health monitors {signal}", group="monitoring")
        for signal in ROUTE_HEALTH_SIGNALS
    )
    rows.extend(
        _pass_row(f"prep_only_output_{role}_cannot_authorize", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_PREP_ONLY_AUTHORITY_DRIFT", f"{role} remains prep-only", group="prep_only")
        for role in PREP_ONLY_OUTPUT_ROLES
    )
    return list(rows)


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "shadow_superiority_passed": True,
        "activation_review_validated": True,
        "limited_runtime_authorization_packet_authored": True,
        "limited_runtime_authorization_packet_validated": True,
        "limited_runtime_execution_packet_authored": True,
        "limited_runtime_execution_packet_validated": False,
        "limited_runtime_authorized": False,
        "limited_runtime_execution_authorized": False,
        "limited_runtime_executed": False,
        "runtime_execution_authorized": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
    }


def _compiler_scaffold(current_main_head: str) -> Dict[str, Any]:
    spec = {
        "lane_id": "AUTHOR_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET",
        "lane_name": "Author B04 R6 Limited Runtime Execution Packet",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM/tools/operator",
        "summary": "Prep-only scaffold for limited-runtime execution packet authoring.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/cohort0_b04_r6_limited_runtime_execution_packet.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_b04_r6_limited_runtime_execution_packet.py",
        "artifacts": [f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values()],
        "lane_kind": "AUTHORING",
        "current_main_head": current_main_head,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "may_authorize": list(MAY_AUTHORIZE),
        "must_not_authorize": list(FORBIDDEN_ACTIONS),
        "authoritative_inputs": sorted(INPUTS),
        "prep_only_outputs": list(PREP_ONLY_OUTPUT_ROLES),
        "json_parse_inputs": [f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values() if filename.endswith(".json")],
        "no_authorization_drift_checks": [
            "Limited runtime is not executed.",
            "Runtime cutover remains unauthorized.",
            "R6 remains closed.",
            "Package and commercial claim boundaries remain closed.",
        ],
        "future_blockers": [
            "LIMITED_RUNTIME_EXECUTION_PACKET_VALIDATION_NOT_YET_RUN",
            "LIMITED_RUNTIME_RUN_NOT_YET_LAWFUL",
            "RUNTIME_EVIDENCE_REVIEW_NOT_YET_AUTHORED",
            "EXTERNAL_AUDIT_DELTA_NOT_YET_AUTHORED",
        ],
        "reason_codes": list(REASON_CODES),
    }
    compiled = kt_lane_compiler.build_lane_contract(spec)
    rendered = json.dumps(compiled, sort_keys=True, ensure_ascii=True)
    return {
        "schema_id": "kt.b04_r6.limited_runtime.execution_packet_lane_compiler_scaffold_receipt.v1",
        "artifact_id": "B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_LANE_COMPILER_SCAFFOLD_RECEIPT",
        "compiler_id": compiled["compiler_id"],
        "authority": compiled["authority"],
        "status": "PREP_ONLY_SCAFFOLD",
        "lane_id": spec["lane_id"],
        "lane_law_metadata": compiled["lane_law_metadata"],
        "generated_artifacts": compiled["generated_artifacts"],
        "generated_file_count": len(compiled["files"]),
        "compiled_contract_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "files_omitted_from_receipt": True,
        "scaffold_can_authorize": False,
        "can_execute_runtime": False,
        "can_open_r6": False,
        "can_promote_package": False,
    }


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    current_branch: str,
    input_bindings: list[Dict[str, Any]],
    binding_hashes: Dict[str, str],
    validation_rows: list[Dict[str, str]],
    compiler_scaffold: Dict[str, Any],
    trust_zone_validation: Dict[str, Any],
    handoff_acceptance: Dict[str, bool],
) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_utc": generated_utc,
        "current_branch": current_branch,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "status": "PASS",
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "may_authorize": list(MAY_AUTHORIZE),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "terminal_defects": list(TERMINAL_DEFECTS),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "validation_rows": validation_rows,
        "lane_compiler_scaffold": compiler_scaffold,
        "handoff_acceptance": handoff_acceptance,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": trust_zone_validation.get("failures", []),
        "authorization_state": _authorization_state(),
        "runtime_mode": RUNTIME_MODE,
        "allowed_future_execution_modes": list(ALLOWED_FUTURE_EXECUTION_MODES),
        "r6_open": False,
        "limited_runtime_authorization_packet_validated": True,
        "limited_runtime_execution_packet_authored": True,
        "limited_runtime_execution_packet_validated": False,
        "limited_runtime_authorized": False,
        "limited_runtime_execution_authorized": False,
        "limited_runtime_executed": False,
        "runtime_execution_authorized": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "metric_contract_mutated": False,
        "static_comparator_weakened": False,
    }


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    payload = dict(base)
    payload.update({"schema_id": schema_id, "artifact_id": artifact_id})
    payload.update(extra)
    return payload


def _control_payload(base: Dict[str, Any], *, schema_slug: str, artifact_id: str, requirements: Sequence[str], **extra: Any) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.limited_runtime.execution.{schema_slug}.v1",
        artifact_id=artifact_id,
        requirements=list(requirements),
        can_execute_runtime=False,
        can_authorize_runtime_cutover=False,
        can_open_r6=False,
        can_promote_package=False,
        can_authorize_commercial_claims=False,
        static_authority_preserved=True,
        validation_required_before_execution=True,
        **extra,
    )


def _prep_only(base: Dict[str, Any], *, artifact_id: str, schema_slug: str, purpose: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.{schema_slug}.v1",
        artifact_id=artifact_id,
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_authorize=list(FORBIDDEN_ACTIONS),
        limited_runtime_authorized=False,
        limited_runtime_execution_authorized=False,
        limited_runtime_executed=False,
        runtime_execution_authorized=False,
        runtime_cutover_authorized=False,
        r6_open=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
    )


def _markdown_prep(base: Dict[str, Any], *, title: str, body: str) -> str:
    return (
        f"# {title}\n\n"
        "Authority: PREP_ONLY\n\n"
        f"Outcome context: {base['selected_outcome']}\n\n"
        f"{body}\n\n"
        "This draft does not execute limited runtime, authorize runtime cutover, open R6, promote package, or authorize commercial activation claims.\n"
    )


def _contract(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.limited_runtime_execution_packet.v1",
        artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET",
        packet_scope={
            "purpose": "Author the exact non-executing packet for a future bounded limited-runtime shadow run.",
            "non_purpose": [
                "Does not execute limited runtime.",
                "Does not authorize runtime cutover.",
                "Does not open R6.",
                "Does not authorize lobe escalation.",
                "Does not authorize package promotion.",
                "Does not authorize commercial activation claims.",
            ],
        },
        execution_packet_result={
            "packet_authored": True,
            "selected_runtime_mode": RUNTIME_MODE,
            "static_remains_authoritative": True,
            "afsh_observation_only": True,
            "validation_required_before_execution": True,
        },
    )


def _binding_receipt(base: Dict[str, Any], *, role: str, artifact_id: str, source_roles: Sequence[str]) -> Dict[str, Any]:
    bound_hashes = {}
    for source_role in source_roles:
        key = source_role if source_role.endswith("_hash") else f"{source_role}_hash"
        bound_hashes[key] = base["binding_hashes"][key]
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.limited_runtime.execution.binding.{role}.v1",
        artifact_id=artifact_id,
        binding_role=role,
        bound_hashes=bound_hashes,
        binding_status="PASS",
    )


def _validation_plan(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.limited_runtime_execution_validation_plan.v1",
        artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_VALIDATION_PLAN",
        authority="VALIDATION_AHEAD_SCAFFOLD",
        future_lane="VALIDATE_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET",
        required_checks=[
            "execution packet is hash-bound",
            "mode is shadow runtime only",
            "scope is limited and not global R6",
            "static remains authoritative",
            "AFSH cannot change user-facing decisions",
            "operator override exists",
            "kill switch execution contract exists",
            "rollback execution contract exists",
            "runtime receipts are complete",
            "incident freeze conditions are complete",
            "external verifier requirements are non-executing",
            "commercial and package promotion claims remain blocked",
            "next lawful move is bounded runtime run only after validation",
        ],
        cannot_authorize=list(FORBIDDEN_ACTIONS),
    )


def _reason_code_payload(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.limited_runtime_execution_validation_reason_codes.v1",
        artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_VALIDATION_REASON_CODES",
        authority="VALIDATION_AHEAD_SCAFFOLD",
        reason_codes=[
            {"code": code, "terminal": code.replace("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_", "") in TERMINAL_DEFECTS}
            for code in REASON_CODES
        ],
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v8",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        current_authoritative_lane="AUTHOR_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET",
        blockers=[
            {
                "blocker_id": "B04R6-FB-061",
                "future_blocker": "Execution packet exists but has not been validated.",
                "neutralization_now": [OUTPUTS["execution_validation_plan"], OUTPUTS["execution_validation_reason_codes"]],
            },
            {
                "blocker_id": "B04R6-FB-062",
                "future_blocker": "Runtime evidence review law missing after future shadow runtime.",
                "neutralization_now": [
                    OUTPUTS["runtime_evidence_review_packet_prep_only_draft"],
                    OUTPUTS["runtime_evidence_scorecard_prep_only_draft"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-063",
                "future_blocker": "Failure, incident, or rollback path missing for runtime corridor.",
                "neutralization_now": [
                    OUTPUTS["limited_runtime_failure_closeout_prep_only"],
                    OUTPUTS["runtime_incident_forensic_court_prep_only"],
                    OUTPUTS["runtime_rollback_execution_receipt_schema_prep_only"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-064",
                "future_blocker": "External verifier and commercial boundary not ready for runtime evidence.",
                "neutralization_now": [
                    OUTPUTS["external_verifier_delta_requirements_prep_only"],
                    OUTPUTS["external_audit_delta_manifest_prep_only"],
                    OUTPUTS["commercial_claim_boundary_update_prep_only"],
                ],
            },
        ],
    )


def _pipeline_board(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.pipeline_board.v1",
        artifact_id="B04_R6_PIPELINE_BOARD",
        board=[
            {
                "lane": "AUTHOR_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET",
                "status": "CURRENT_AUTHORED",
                "authoritative": True,
                "expected_outcome": SELECTED_OUTCOME,
                "next_lane": NEXT_LAWFUL_MOVE,
                "blocked_by": [],
                "forbidden": list(FORBIDDEN_ACTIONS),
            },
            {
                "lane": "VALIDATE_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET",
                "status": "NEXT",
                "authoritative": False,
                "expected_outcome": "B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_VALIDATED__LIMITED_RUNTIME_RUN_NEXT",
                "next_lane": "RUN_B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME",
                "blocked_by": ["execution packet validation"],
            },
            {
                "lane": "AUTHOR_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET",
                "status": "PREP_ONLY_HORIZON",
                "authoritative": False,
                "blocked_by": ["bounded runtime execution evidence"],
            },
        ],
    )


def _runtime_corridor_status(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.runtime_corridor_status.v1",
        artifact_id="B04_R6_RUNTIME_CORRIDOR_STATUS",
        corridor=[
            {"lane": "limited_runtime_authorization_packet", "status": "BOUND_AND_VALIDATED"},
            {"lane": "limited_runtime_execution_packet", "status": "BOUND_NOT_VALIDATED"},
            {"lane": "limited_runtime_shadow_runtime", "status": "NOT_EXECUTED"},
            {"lane": "runtime_evidence_review", "status": "PREP_ONLY_DRAFTED"},
            {"lane": "package_promotion_review", "status": "BLOCKED_BY_RUNTIME_EVIDENCE"},
        ],
    )


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Limited-Runtime Execution Packet\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "This packet authors a bounded SHADOW_RUNTIME_ONLY execution plan. Static remains authoritative, "
        "AFSH is observation-only, runtime receipts are required, operator override, kill switch, rollback, "
        "route-health monitoring, drift monitoring, incident freeze, and external verifier requirements are bound.\n\n"
        "This packet does not execute limited runtime, authorize runtime cutover, open R6, authorize lobe escalation, "
        "promote package, authorize commercial activation claims, or mutate truth/trust law.\n"
    )


def _outputs(base: Dict[str, Any], compiler_scaffold: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "execution_packet_contract": _contract(base),
        "execution_packet_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.limited_runtime_execution_packet_receipt.v1",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_RECEIPT",
            verdict="EXECUTION_PACKET_BOUND_NON_EXECUTING",
        ),
        "authorization_validation_binding_receipt": _binding_receipt(
            base,
            role="authorization_validation",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_AUTHORIZATION_VALIDATION_BINDING_RECEIPT",
            source_roles=("validation_validation_contract", "validation_validation_receipt"),
        ),
        "shadow_result_binding_receipt": _binding_receipt(
            base,
            role="shadow_result",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_SHADOW_RESULT_BINDING_RECEIPT",
            source_roles=("validated_shadow_screen_result_hash",),
        ),
        "candidate_binding_receipt": _binding_receipt(
            base,
            role="candidate",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_CANDIDATE_BINDING_RECEIPT",
            source_roles=("validated_candidate_hash", "validated_candidate_manifest_hash", "validated_candidate_semantic_hash"),
        ),
        "scope_manifest": _control_payload(
            base,
            schema_slug="scope_manifest",
            artifact_id="B04_R6_LIMITED_RUNTIME_SCOPE_MANIFEST",
            requirements=("limited_scope_required", "shadow_runtime_only", "no_live_traffic_authorized", "not_global_r6"),
            limited_scope_required=True,
            selected_runtime_mode=RUNTIME_MODE,
            global_r6_scope=False,
            max_live_traffic_percent_authorized_by_this_packet=0,
            user_facing_decision_changes_allowed=False,
            allowed_case_classes=["B04_R6_AFSH_SHADOW_RUNTIME_PACKET_BOUND_CASES_ONLY"],
            excluded_case_classes=["GLOBAL_R6", "PRODUCTION_USER_FACING", "PACKAGE_PROMOTION"],
        ),
        "mode_contract": _control_payload(
            base,
            schema_slug="mode_contract",
            artifact_id="B04_R6_LIMITED_RUNTIME_MODE_CONTRACT",
            requirements=("shadow_runtime_only", "static_authoritative", "afsh_observation_only", "no_autonomous_cutover"),
            selected_mode=RUNTIME_MODE,
            allowed_modes=list(ALLOWED_FUTURE_EXECUTION_MODES),
            forbidden_modes=list(FORBIDDEN_RUNTIME_MODES),
            static_authoritative=True,
            afsh_observation_only=True,
        ),
        "case_class_contract": _control_payload(
            base,
            schema_slug="case_class_contract",
            artifact_id="B04_R6_LIMITED_RUNTIME_CASE_CLASS_CONTRACT",
            requirements=("packet_bound_cases_only", "no_global_r6_cases", "no_old_universe_fresh_proof"),
            allowed_case_classes=["packet_bound_shadow_runtime_cases_only"],
            old_r01_r04_treatment="DIAGNOSTIC_ONLY",
            prior_v2_six_row_treatment="DIAGNOSTIC_ONLY",
        ),
        "static_authority_contract": _control_payload(
            base,
            schema_slug="static_authority_contract",
            artifact_id="B04_R6_LIMITED_RUNTIME_STATIC_AUTHORITY_CONTRACT",
            requirements=("static_decision_authoritative", "afsh_cannot_change_user_facing_decision", "static_fallback_always_available"),
            static_decision_authoritative=True,
            afsh_can_change_user_facing_decision=False,
        ),
        "afsh_shadow_observation_contract": _control_payload(
            base,
            schema_slug="afsh_shadow_observation_contract",
            artifact_id="B04_R6_LIMITED_RUNTIME_AFSH_SHADOW_OBSERVATION_CONTRACT",
            requirements=("afsh_observation_only", "receipt_emission_required", "selector_receipts_required"),
            afsh_observation_only=True,
            selector_may_observe_route_eligible=True,
            selector_may_cutover=False,
        ),
        "operator_override_contract": _control_payload(
            base,
            schema_slug="operator_override_contract",
            artifact_id="B04_R6_LIMITED_RUNTIME_OPERATOR_OVERRIDE_CONTRACT",
            requirements=("operator_override_required", "override_may_force_static_only", "override_receipt_required"),
            operator_override_required=True,
            override_may_force_static_only=True,
            override_may_force_afsh_authority=False,
        ),
        "kill_switch_execution_contract": _control_payload(
            base,
            schema_slug="kill_switch_execution_contract",
            artifact_id="B04_R6_LIMITED_RUNTIME_KILL_SWITCH_EXECUTION_CONTRACT",
            requirements=("kill_switch_required", "kill_switch_halts_afsh_observation", "kill_switch_receipt_required"),
            kill_switch_required=True,
            kill_switch_halts_afsh_observation=True,
        ),
        "rollback_execution_contract": _control_payload(
            base,
            schema_slug="rollback_execution_contract",
            artifact_id="B04_R6_LIMITED_RUNTIME_ROLLBACK_EXECUTION_CONTRACT",
            requirements=("rollback_to_static_required", "rollback_receipt_required", "rollback_replay_required"),
            rollback_to_static_required=True,
        ),
        "route_distribution_health_contract": _control_payload(
            base,
            schema_slug="route_distribution_health_contract",
            artifact_id="B04_R6_LIMITED_RUNTIME_ROUTE_DISTRIBUTION_HEALTH_CONTRACT",
            requirements=("route_distribution_monitoring_required", "selector_entry_rate_monitored", "overrouting_alarm_required"),
            monitored_signals=list(ROUTE_HEALTH_SIGNALS),
        ),
        "drift_monitoring_contract": _control_payload(
            base,
            schema_slug="drift_monitoring_contract",
            artifact_id="B04_R6_LIMITED_RUNTIME_DRIFT_MONITORING_CONTRACT",
            requirements=("metric_drift_freezes_runtime", "trust_zone_drift_freezes_runtime", "truth_engine_drift_freezes_runtime"),
            freeze_on_metric_drift=True,
            freeze_on_trust_zone_drift=True,
            freeze_on_truth_engine_drift=True,
        ),
        "incident_freeze_contract": _control_payload(
            base,
            schema_slug="incident_freeze_contract",
            artifact_id="B04_R6_LIMITED_RUNTIME_INCIDENT_FREEZE_CONTRACT",
            requirements=("incident_freeze_required", "freeze_receipt_required", "forensic_path_required"),
            freeze_conditions=list(INCIDENT_FREEZE_CONDITIONS),
        ),
        "runtime_receipt_schema": _control_payload(
            base,
            schema_slug="runtime_receipt_schema",
            artifact_id="B04_R6_LIMITED_RUNTIME_RECEIPT_SCHEMA",
            requirements=("runtime_receipt_required", "raw_hash_bound_artifacts_required", "external_replay_refs_required"),
            required_fields=list(RUNTIME_RECEIPT_FIELDS),
        ),
        "external_verifier_requirements": _control_payload(
            base,
            schema_slug="external_verifier_requirements",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXTERNAL_VERIFIER_REQUIREMENTS",
            requirements=("external_verifier_non_executing", "raw_hash_bound_artifacts_required", "public_claims_forbidden"),
            external_verifier_non_executing=True,
            compressed_index_source_of_truth=False,
            raw_hash_bound_artifacts_required=True,
        ),
        "commercial_claim_boundary": _control_payload(
            base,
            schema_slug="commercial_claim_boundary",
            artifact_id="B04_R6_LIMITED_RUNTIME_COMMERCIAL_CLAIM_BOUNDARY",
            requirements=("commercial_activation_claims_unauthorized", "package_promotion_prohibited", "customer_safe_status_language_required"),
            allowed_status_language="Execution packet authored; runtime not active.",
            forbidden_claims=["AFSH is live", "R6 is open", "package promotion is ready"],
        ),
        "no_authorization_drift_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.limited_runtime_execution.no_authorization_drift_receipt.v1",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_NO_AUTHORIZATION_DRIFT_RECEIPT",
            no_downstream_authorization_drift=True,
            limited_runtime_execution_authorized=False,
            limited_runtime_executed=False,
            runtime_cutover_authorized=False,
            r6_open=False,
            package_promotion_authorized=False,
            commercial_activation_claim_authorized=False,
        ),
        "execution_validation_plan": _validation_plan(base),
        "execution_validation_reason_codes": _reason_code_payload(base),
        "lane_compiler_scaffold_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.limited_runtime.execution_packet_lane_compiler_scaffold_binding_receipt.v1",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_LANE_COMPILER_SCAFFOLD_BINDING_RECEIPT",
            scaffold=compiler_scaffold,
            scaffold_authority="PREP_ONLY_TOOLING",
            scaffold_can_authorize=False,
        ),
        "pipeline_board": _pipeline_board(base),
        "runtime_corridor_status": _runtime_corridor_status(base),
        "future_blocker_register": _future_blocker_register(base),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v19",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            verdict="NEXT_LAWFUL_MOVE_SET",
        ),
    }


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 limited-runtime execution packet authoring")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in TEXT_INPUTS.items()}
    handoff_acceptance = _validate_inputs(payloads, texts)
    _validate_authorized_controls(payloads)
    _validate_current_authorization_inputs_match_validation(root, payloads, handoff_acceptance)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if current_branch != "main" else "HEAD")
    generated_utc = utc_now_iso_z()
    input_bindings = _input_bindings(root, handoff_git_commit=head)
    binding_hashes = _binding_hashes(root, payloads)
    validation_rows = _validation_rows()
    compiler_scaffold = _compiler_scaffold(current_main_head)
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=input_bindings,
        binding_hashes=binding_hashes,
        validation_rows=validation_rows,
        compiler_scaffold=compiler_scaffold,
        trust_zone_validation=fresh_trust_validation,
        handoff_acceptance=handoff_acceptance,
    )
    output_payloads = _outputs(base, compiler_scaffold)
    output_payloads.update(
        {
            role: _prep_only(
                base,
                artifact_id=f"B04_R6_{role.upper()}",
                schema_slug=role,
                purpose=f"Prep-only scaffold for future {role.replace('_', ' ')}.",
            )
            for role in PREP_ONLY_OUTPUT_ROLES
        }
    )

    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "execution_packet_report":
            path.write_text(_report_text(output_payloads["execution_packet_contract"]), encoding="utf-8", newline="\n")
        elif role == "operator_runbook_delta_prep_only":
            path.write_text(
                _markdown_prep(
                    base,
                    title="B04 R6 Operator Runbook Delta Prep Only",
                    body="Operators may observe, freeze, force static-only fallback, invoke kill switch, and request rollback receipts. Operators may not grant AFSH runtime authority.",
                ),
                encoding="utf-8",
                newline="\n",
            )
        elif role == "customer_safe_status_language_prep_only":
            path.write_text(
                _markdown_prep(
                    base,
                    title="B04 R6 Customer-Safe Status Language Prep Only",
                    body="Allowed: A limited-runtime execution packet is authored for future validation. Forbidden: AFSH is live, R6 is open, package promotion is ready.",
                ),
                encoding="utf-8",
                newline="\n",
            )
        else:
            write_json_stable(path, output_payloads[role])
    return output_payloads["execution_packet_contract"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author B04 R6 limited-runtime execution packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
