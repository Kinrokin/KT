from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_expanded_canary_authorization_packet_validation as authorization_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable


AUTHORITY_BRANCH = "authoritative/b04-r6-expanded-canary-execution-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-expanded-canary-execution-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_EXPANDED_CANARY_EXECUTION_PACKET"
PREVIOUS_LANE = authorization_validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = authorization_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = authorization_validation.NEXT_LAWFUL_MOVE

SELECTED_OUTCOME = (
    "B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_BOUND__"
    "EXPANDED_CANARY_EXECUTION_VALIDATION_NEXT"
)
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_EXPANDED_CANARY_EXECUTION_PACKET"
VALIDATION_SUCCESS_OUTCOME = (
    "B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_VALIDATED__"
    "EXPANDED_CANARY_RUNTIME_NEXT"
)
VALIDATION_SUCCESS_NEXT_MOVE = "RUN_B04_R6_EXPANDED_CANARY_RUNTIME"

OUTCOME_DEFERRED = "B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_REJECTED = "B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_REJECTED__EXPANDED_CANARY_EXECUTION_NOT_JUSTIFIED"
OUTCOME_INVALID = "B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_INVALID__FORENSIC_EXPANDED_CANARY_EXECUTION_REVIEW_NEXT"

FORBIDDEN_ACTIONS = (
    "EXPANDED_CANARY_RUNTIME_EXECUTED",
    "EXPANDED_CANARY_RUNTIME_AUTHORIZED",
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
    "GLOBAL_RUNTIME_SURFACE_AUTHORIZED",
)

AUTHORITY_DRIFT_KEYS = {
    "expanded_canary_runtime_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RUNTIME_AUTHORIZED",
    "expanded_canary_runtime_executed": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RUNTIME_EXECUTED",
    "expanded_canary_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RUNTIME_AUTHORIZED",
    "expanded_canary_executed": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RUNTIME_EXECUTED",
    "runtime_cutover_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
    "activation_cutover_executed": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
    "r6_open": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_R6_OPEN_DRIFT",
    "global_runtime_surface_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_GLOBAL_RUNTIME_SURFACE",
    "lobe_escalation_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_COMPARATOR_WEAKENED",
}

REASON_CODES = (
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_AUTHORIZATION_OUTCOME_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_NEXT_MOVE_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_INPUT_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_SCOPE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_SAMPLE_LIMIT_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_SAMPLE_LIMIT_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_ALLOWED_CASE_CLASSES_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_EXCLUDED_CASE_CLASSES_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_GLOBAL_SURFACE_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_CUTOVER_SURFACE_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_COMMERCIAL_SURFACE_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_FALLBACK_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_OPERATOR_CONTROL_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_KILL_SWITCH_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_ROLLBACK_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_REASON_CODE_MAPPING_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_ROUTE_THRESHOLDS_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_DRIFT_THRESHOLDS_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_INCIDENT_FREEZE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RECEIPT_SCHEMA_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_REPLAY_MANIFEST_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_EXPECTED_ARTIFACT_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RESULT_INTERPRETATION_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_PREP_ONLY_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RUNTIME_AUTHORIZED",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RUNTIME_EXECUTED",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_R6_OPEN_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_TRUST_ZONE_MUTATION",
)

EXPECTED_ALLOWED_CASE_CLASSES = (
    "ROUTE_ELIGIBLE_LOW_RISK_CANARY_CONFIRMED",
    "STATIC_FALLBACK_AVAILABLE_EXPANDED_ROUTE_CHECK",
    "NON_COMMERCIAL_OPERATOR_OBSERVED_EXPANDED_SAMPLE",
    "PRIOR_CANARY_COVERED_CASE_CLASS_EXTENSION",
)
EXPECTED_EXCLUDED_CASE_CLASSES = (
    "GLOBAL_R6_TRAFFIC",
    "RUNTIME_CUTOVER_SURFACE",
    "NULL_ROUTE_CONTROL",
    "COMMERCIAL_ACTIVATION_SURFACE",
    "PACKAGE_PROMOTION_SURFACE",
)

INPUTS = {
    "expanded_canary_authorization_validation_receipt": "b04_r6_expanded_canary_authorization_packet_validation_receipt.json",
    "expanded_canary_authorization_next_lawful_move": "b04_r6_expanded_canary_authorization_validation_next_lawful_move_receipt.json",
    "expanded_canary_authorization_packet": "b04_r6_expanded_canary_authorization_packet_contract.json",
    "expanded_canary_authorization_scope_manifest": "b04_r6_expanded_canary_scope_manifest.json",
    "expanded_canary_authorization_allowed_case_classes": "b04_r6_expanded_canary_allowed_case_class_contract.json",
    "expanded_canary_authorization_excluded_case_classes": "b04_r6_expanded_canary_excluded_case_class_contract.json",
    "expanded_canary_authorization_sample_limit": "b04_r6_expanded_canary_sample_limit_contract.json",
    "expanded_canary_authorization_static_fallback": "b04_r6_expanded_canary_static_fallback_contract.json",
    "expanded_canary_authorization_abstention_fallback": "b04_r6_expanded_canary_abstention_fallback_contract.json",
    "expanded_canary_authorization_null_route": "b04_r6_expanded_canary_null_route_preservation_contract.json",
    "expanded_canary_authorization_operator_override": "b04_r6_expanded_canary_operator_override_contract.json",
    "expanded_canary_authorization_kill_switch": "b04_r6_expanded_canary_kill_switch_contract.json",
    "expanded_canary_authorization_rollback": "b04_r6_expanded_canary_rollback_contract.json",
    "expanded_canary_authorization_route_thresholds": "b04_r6_expanded_canary_route_distribution_health_thresholds.json",
    "expanded_canary_authorization_drift_thresholds": "b04_r6_expanded_canary_drift_thresholds.json",
    "expanded_canary_authorization_incident_freeze": "b04_r6_expanded_canary_incident_freeze_contract.json",
    "expanded_canary_authorization_runtime_receipt_schema": "b04_r6_expanded_canary_runtime_receipt_schema.json",
    "expanded_canary_authorization_external_verifier": "b04_r6_expanded_canary_external_verifier_requirements.json",
    "expanded_canary_authorization_commercial_boundary": "b04_r6_expanded_canary_commercial_claim_boundary.json",
    "canary_evidence_review_validation_receipt": "b04_r6_canary_evidence_review_validation_receipt.json",
    "canary_evidence_scorecard": "b04_r6_canary_evidence_scorecard.json",
    "post_canary_decision_matrix": "b04_r6_canary_post_run_decision_matrix.json",
    "expanded_canary_readiness_matrix": "b04_r6_expanded_canary_readiness_matrix.json",
    "runtime_cutover_readiness_matrix": "b04_r6_runtime_cutover_readiness_matrix.json",
    "package_promotion_blocker_review": "b04_r6_canary_package_promotion_blocker_review_contract.json",
    "external_verifier_readiness_review": "b04_r6_canary_external_verifier_readiness_review_contract.json",
    "commercial_claim_boundary_review": "b04_r6_canary_commercial_claim_boundary_review_contract.json",
    "afsh_candidate_hash_receipt": "b04_r6_afsh_candidate_hash_receipt.json",
    "route_distribution_evidence": "b04_r6_canary_route_distribution_receipt.json",
    "fallback_behavior_evidence": "b04_r6_canary_fallback_behavior_receipt.json",
    "operator_override_evidence": "b04_r6_canary_operator_override_receipt.json",
    "kill_switch_evidence": "b04_r6_canary_kill_switch_receipt.json",
    "rollback_evidence": "b04_r6_canary_rollback_receipt.json",
    "drift_evidence": "b04_r6_canary_drift_monitoring_receipt.json",
    "incident_freeze_evidence": "b04_r6_canary_incident_freeze_receipt.json",
    "trace_completeness_evidence": "b04_r6_canary_trace_completeness_receipt.json",
    "runtime_replay_evidence": "b04_r6_canary_replay_receipt.json",
}

OUTPUTS = {
    "packet_contract": "b04_r6_expanded_canary_execution_packet_contract.json",
    "packet_receipt": "b04_r6_expanded_canary_execution_packet_receipt.json",
    "packet_report": "b04_r6_expanded_canary_execution_packet_report.md",
    "execution_mode_contract": "b04_r6_expanded_canary_execution_mode_contract.json",
    "execution_scope_manifest": "b04_r6_expanded_canary_execution_scope_manifest.json",
    "allowed_case_class_contract": "b04_r6_expanded_canary_execution_allowed_case_class_contract.json",
    "excluded_case_class_contract": "b04_r6_expanded_canary_execution_excluded_case_class_contract.json",
    "sample_limit_contract": "b04_r6_expanded_canary_execution_sample_limit_contract.json",
    "expansion_delta_contract": "b04_r6_expanded_canary_execution_expansion_delta_contract.json",
    "static_fallback_contract": "b04_r6_expanded_canary_execution_static_fallback_contract.json",
    "abstention_fallback_contract": "b04_r6_expanded_canary_execution_abstention_fallback_contract.json",
    "null_route_preservation_contract": "b04_r6_expanded_canary_execution_null_route_preservation_contract.json",
    "operator_override_contract": "b04_r6_expanded_canary_execution_operator_override_contract.json",
    "kill_switch_contract": "b04_r6_expanded_canary_execution_kill_switch_contract.json",
    "rollback_contract": "b04_r6_expanded_canary_execution_rollback_contract.json",
    "route_distribution_thresholds": "b04_r6_expanded_canary_execution_route_distribution_thresholds.json",
    "drift_thresholds": "b04_r6_expanded_canary_execution_drift_thresholds.json",
    "incident_freeze_contract": "b04_r6_expanded_canary_execution_incident_freeze_contract.json",
    "runtime_receipt_schema": "b04_r6_expanded_canary_execution_runtime_receipt_schema.json",
    "replay_manifest": "b04_r6_expanded_canary_execution_replay_manifest.json",
    "expected_artifact_manifest": "b04_r6_expanded_canary_execution_expected_artifact_manifest.json",
    "external_verifier_requirements": "b04_r6_expanded_canary_execution_external_verifier_requirements.json",
    "result_interpretation_contract": "b04_r6_expanded_canary_execution_result_interpretation_contract.json",
    "no_authorization_drift_receipt": "b04_r6_expanded_canary_execution_no_authorization_drift_receipt.json",
    "validation_plan": "b04_r6_expanded_canary_execution_validation_plan.json",
    "validation_reason_codes": "b04_r6_expanded_canary_execution_validation_reason_codes.json",
    "expanded_canary_run_result_schema_prep_only": "b04_r6_expanded_canary_run_result_schema_prep_only.json",
    "expanded_canary_failure_closeout_prep_only_draft": "b04_r6_expanded_canary_failure_closeout_prep_only_draft.json",
    "expanded_canary_forensic_invalidation_court_prep_only_draft": "b04_r6_expanded_canary_forensic_invalidation_court_prep_only_draft.json",
    "next_lawful_move": "b04_r6_expanded_canary_execution_next_lawful_move_receipt.json",
}

CONTRACT_ROLES = (
    "execution_mode_contract",
    "execution_scope_manifest",
    "allowed_case_class_contract",
    "excluded_case_class_contract",
    "sample_limit_contract",
    "expansion_delta_contract",
    "static_fallback_contract",
    "abstention_fallback_contract",
    "null_route_preservation_contract",
    "operator_override_contract",
    "kill_switch_contract",
    "rollback_contract",
    "route_distribution_thresholds",
    "drift_thresholds",
    "incident_freeze_contract",
    "runtime_receipt_schema",
    "replay_manifest",
    "expected_artifact_manifest",
    "external_verifier_requirements",
    "result_interpretation_contract",
)

PREP_ONLY_ROLES = (
    "expanded_canary_run_result_schema_prep_only",
    "expanded_canary_failure_closeout_prep_only_draft",
    "expanded_canary_forensic_invalidation_court_prep_only_draft",
)


def _fail(code: str, detail: str) -> None:
    raise RuntimeError(f"FAIL_CLOSED: {code}: {detail}")


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch not in ALLOWED_BRANCHES and not branch.startswith(REPLAY_BRANCH_PREFIX):
        allowed = ", ".join(sorted([*ALLOWED_BRANCHES, f"{REPLAY_BRANCH_PREFIX}*"]))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}; got: {branch}")
    if branch == "main":
        head = common.git_rev_parse(root, "HEAD")
        origin_main = common.git_rev_parse(root, "origin/main")
        if head != origin_main:
            raise RuntimeError("FAIL_CLOSED: main replay requires local main to equal origin/main")
    return branch


def _walk_dicts(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


def _load_inputs(root: Path, reports_root: Path) -> Dict[str, Dict[str, Any]]:
    payloads: Dict[str, Dict[str, Any]] = {}
    for role, filename in INPUTS.items():
        path = reports_root / filename
        if not path.exists():
            _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_INPUT_MISSING", f"missing {filename}")
        payload = common.load_json_required(root, f"KT_PROD_CLEANROOM/reports/{filename}", label=role)
        if not isinstance(payload, dict):
            _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_INPUT_MISSING", f"{filename} must be object")
        payloads[role] = payload
    return payloads


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role, payload in payloads.items():
        for nested in _walk_dicts(payload):
            for key, code in AUTHORITY_DRIFT_KEYS.items():
                if key in nested and nested.get(key) is not False:
                    _fail(code, f"{role}.{key} drifted to {nested.get(key)!r}")
            if nested.get("package_promotion") not in (None, "DEFERRED"):
                _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT", f"{role}.package_promotion drifted")
            if nested.get("commercial_claim_status") not in (None, "BOUNDARY_ONLY"):
                _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT", f"{role}.commercial_claim_status drifted")


def _details(payloads: Dict[str, Dict[str, Any]], role: str) -> Dict[str, Any]:
    value = payloads[role].get("details", {})
    if not isinstance(value, dict):
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_INPUT_MISSING", f"{role}.details missing")
    return value


def _validate_previous_authority(payloads: Dict[str, Dict[str, Any]]) -> None:
    receipt = payloads["expanded_canary_authorization_validation_receipt"]
    next_receipt = payloads["expanded_canary_authorization_next_lawful_move"]
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_AUTHORIZATION_OUTCOME_DRIFT", "authorization validation receipt outcome drifted")
    if receipt.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_NEXT_MOVE_DRIFT", "authorization validation receipt next move drifted")
    if next_receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_AUTHORIZATION_OUTCOME_DRIFT", "authorization next receipt outcome drifted")
    if next_receipt.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_NEXT_MOVE_DRIFT", "authorization next receipt next move drifted")


def _validate_authorized_scope(payloads: Dict[str, Dict[str, Any]]) -> None:
    scope = _details(payloads, "expanded_canary_authorization_scope_manifest")
    if scope.get("scope_status") != "EXPANDED_CANARY_SCOPE_DEFINED_NOT_EXECUTING":
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_SCOPE_MISSING", "authorization scope is not bounded")
    if scope.get("global_r6_scope_allowed") is not False:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_GLOBAL_SURFACE_DRIFT", "global R6 scope drifted")
    if scope.get("runtime_cutover_allowed") is not False:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_CUTOVER_SURFACE_DRIFT", "runtime cutover scope drifted")
    if scope.get("max_case_count_per_window") != 36 or scope.get("max_window_minutes") != 120:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_SAMPLE_LIMIT_DRIFT", "authorization sample/window limits drifted")

    sample = _details(payloads, "expanded_canary_authorization_sample_limit")
    if sample.get("max_cases") != 36 or sample.get("max_route_observations") != 24:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_SAMPLE_LIMIT_DRIFT", "sample limit contract drifted")
    if sample.get("requires_operator_observation") is not True or sample.get("may_not_expand_without_validation") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_SAMPLE_LIMIT_MISSING", "sample limit guards missing")

    allowed = tuple(_details(payloads, "expanded_canary_authorization_allowed_case_classes").get("allowed_case_classes", []))
    if allowed != EXPECTED_ALLOWED_CASE_CLASSES:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_ALLOWED_CASE_CLASSES_DRIFT", "allowed case classes do not match bounded expected set")

    excluded = set(_details(payloads, "expanded_canary_authorization_excluded_case_classes").get("excluded_case_classes", []))
    required_excluded = set(EXPECTED_EXCLUDED_CASE_CLASSES)
    if not required_excluded.issubset(excluded):
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_EXCLUDED_CASE_CLASSES_DRIFT", "required excluded case classes missing")
    if "GLOBAL_R6_TRAFFIC" not in excluded:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_GLOBAL_SURFACE_DRIFT", "global surface not excluded")
    if "RUNTIME_CUTOVER_SURFACE" not in excluded:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_CUTOVER_SURFACE_DRIFT", "cutover surface not excluded")
    if "COMMERCIAL_ACTIVATION_SURFACE" not in excluded:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_COMMERCIAL_SURFACE_DRIFT", "commercial surface not excluded")


def _validate_safety_controls(payloads: Dict[str, Dict[str, Any]]) -> None:
    required_controls = {
        "expanded_canary_authorization_static_fallback": ("static_fallback_required", "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_FALLBACK_MISSING"),
        "expanded_canary_authorization_abstention_fallback": ("abstention_fallback_required", "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_FALLBACK_MISSING"),
        "expanded_canary_authorization_null_route": ("null_route_preservation_required", "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_FALLBACK_MISSING"),
        "expanded_canary_authorization_operator_override": ("operator_override_required", "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_OPERATOR_CONTROL_MISSING"),
        "expanded_canary_authorization_kill_switch": ("kill_switch_required", "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_KILL_SWITCH_MISSING"),
        "expanded_canary_authorization_rollback": ("rollback_required", "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_ROLLBACK_MISSING"),
    }
    for role, (key, code) in required_controls.items():
        if _details(payloads, role).get(key) is not True:
            _fail(code, f"{role}.{key} missing")

    if _details(payloads, "expanded_canary_authorization_route_thresholds").get("route_distribution_thresholds_defined") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_ROUTE_THRESHOLDS_MISSING", "route thresholds missing")
    if _details(payloads, "expanded_canary_authorization_drift_thresholds").get("drift_thresholds_defined") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_DRIFT_THRESHOLDS_MISSING", "drift thresholds missing")
    if _details(payloads, "expanded_canary_authorization_incident_freeze").get("incident_freeze_conditions_defined") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_INCIDENT_FREEZE_MISSING", "incident freeze missing")
    if _details(payloads, "expanded_canary_authorization_runtime_receipt_schema").get("runtime_receipt_schema_defined") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RECEIPT_SCHEMA_MISSING", "runtime receipt schema missing")
    if _details(payloads, "expanded_canary_authorization_external_verifier").get("external_verifier_required") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_EXTERNAL_VERIFIER_MISSING", "external verifier requirement missing")


def _validate_campaign_evidence(payloads: Dict[str, Dict[str, Any]]) -> None:
    decision_payload = payloads["post_canary_decision_matrix"]
    decision = decision_payload.get("decision_matrix", decision_payload)
    if decision.get("recommended_next_path") != "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT":
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_INPUT_MISSING", "post-canary decision did not recommend expanded canary authorization")
    if decision.get("runtime_cutover_review_ready") is not False or decision.get("package_promotion_ready") is not False:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED", "post-canary decision widened authority")
    readiness = payloads["expanded_canary_readiness_matrix"].get("decision_matrix", payloads["expanded_canary_readiness_matrix"])
    if readiness.get("expanded_canary_ready") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_INPUT_MISSING", "expanded canary readiness not true")


def _validate_inputs(payloads: Dict[str, Dict[str, Any]]) -> None:
    _validate_previous_authority(payloads)
    _ensure_authority_closed(payloads)
    _validate_authorized_scope(payloads)
    _validate_safety_controls(payloads)
    _validate_campaign_evidence(payloads)


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    return [
        {
            "role": role,
            "path": f"KT_PROD_CLEANROOM/reports/{filename}",
            "sha256": file_sha256(common.resolve_path(root, f"KT_PROD_CLEANROOM/reports/{filename}")),
            "binding_kind": "file_sha256_at_expanded_canary_execution_packet_authoring",
        }
        for role, filename in sorted(INPUTS.items())
    ]


def _binding_hashes(reports_root: Path) -> Dict[str, str]:
    return {f"{role}_hash": file_sha256(reports_root / filename) for role, filename in sorted(INPUTS.items())}


def _guard() -> Dict[str, Any]:
    return {
        "expanded_canary_authorization_packet_validated": True,
        "expanded_canary_execution_packet_authored": True,
        "expanded_canary_execution_packet_validated": False,
        "expanded_canary_runtime_authorized": False,
        "expanded_canary_runtime_executed": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "r6_open": False,
        "global_runtime_surface_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_changed": False,
        "trust_zone_law_unchanged": True,
        "metric_contract_mutated": False,
        "static_comparator_weakened": False,
    }


def _prep_guard() -> Dict[str, Any]:
    return {
        "authority": "PREP_ONLY",
        "cannot_execute_expanded_canary": True,
        "cannot_authorize_runtime_cutover": True,
        "cannot_open_r6": True,
        "cannot_authorize_lobe_escalation": True,
        "cannot_authorize_package_promotion": True,
        "cannot_authorize_commercial_activation_claims": True,
        "cannot_mutate_truth_engine_law": True,
        "cannot_mutate_trust_zone_law": True,
    }


def _base(
    *,
    branch: str,
    head: str,
    current_main_head: str,
    generated_utc: str,
    input_bindings: list[Dict[str, str]],
    binding_hashes: Dict[str, str],
) -> Dict[str, Any]:
    return {
        "schema_version": "v1",
        "generated_utc": generated_utc,
        "current_branch": branch,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "validation_success_outcome": VALIDATION_SUCCESS_OUTCOME,
        "validation_success_next_lawful_move": VALIDATION_SUCCESS_NEXT_MOVE,
        "may_authorize": ["EXPANDED_CANARY_EXECUTION_PACKET_AUTHORED"],
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "allowed_outcomes": [SELECTED_OUTCOME, OUTCOME_DEFERRED, OUTCOME_REJECTED, OUTCOME_INVALID],
        "outcome_routing": {
            SELECTED_OUTCOME: NEXT_LAWFUL_MOVE,
            OUTCOME_DEFERRED: "REPAIR_B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_DEFECTS",
            OUTCOME_REJECTED: "AUTHOR_B04_R6_EXPANDED_CANARY_EXECUTION_REJECTION_CLOSEOUT_PACKET",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_EXPANDED_CANARY_EXECUTION_REVIEW_PACKET",
        },
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        **_guard(),
    }


def _contract_detail(role: str) -> Dict[str, Any]:
    details: Dict[str, Dict[str, Any]] = {
        "execution_mode_contract": {
            "execution_mode_defined": True,
            "execution_mode": "EXPANDED_CANARY_EXECUTION_PACKET_ONLY",
            "runtime_may_run_before_validation": False,
            "runtime_may_run_after_validation_only": True,
            "operator_observed": True,
        },
        "execution_scope_manifest": {
            "scope_status": "EXPANDED_CANARY_EXECUTION_SCOPE_DEFINED_NOT_VALIDATED",
            "global_r6_scope_allowed": False,
            "runtime_cutover_allowed": False,
            "commercial_surface_allowed": False,
            "max_case_count_per_window": 36,
            "max_window_minutes": 120,
        },
        "allowed_case_class_contract": {"allowed_case_classes": list(EXPECTED_ALLOWED_CASE_CLASSES)},
        "excluded_case_class_contract": {"excluded_case_classes": list(EXPECTED_EXCLUDED_CASE_CLASSES)},
        "sample_limit_contract": {
            "sample_limit_defined": True,
            "max_cases": 36,
            "max_route_observations": 24,
            "sample_limit_drift_fails_closed": True,
            "requires_operator_observation": True,
        },
        "expansion_delta_contract": {
            "expansion_delta_defined": True,
            "prior_canary_max_cases": 12,
            "expanded_canary_max_cases": 36,
            "delta_requires_validation_before_runtime": True,
            "expansion_description": "Adds bounded prior-canary-covered extensions while preserving non-commercial operator-observed execution law.",
        },
        "static_fallback_contract": {
            "static_fallback_required": True,
            "static_fallback_authoritative": True,
            "reason_code": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_FALLBACK_MISSING",
        },
        "abstention_fallback_contract": {
            "abstention_fallback_required": True,
            "reason_code": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_FALLBACK_MISSING",
        },
        "null_route_preservation_contract": {
            "null_route_preservation_required": True,
            "null_route_controls_excluded": True,
            "reason_code": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_FALLBACK_MISSING",
        },
        "operator_override_contract": {
            "operator_override_required": True,
            "operator_override_freezes_run": True,
            "reason_code": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_OPERATOR_CONTROL_MISSING",
        },
        "kill_switch_contract": {
            "kill_switch_required": True,
            "kill_switch_invocation_freezes_expanded_canary": True,
            "reason_code": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_KILL_SWITCH_MISSING",
        },
        "rollback_contract": {
            "rollback_required": True,
            "rollback_to_prior_static_authority": True,
            "reason_code": "RC_B04R6_EXPANDED_CANARY_EXEC_PACKET_ROLLBACK_MISSING",
        },
        "route_distribution_thresholds": {
            "route_distribution_thresholds_defined": True,
            "max_unknown_route_rate": 0.0,
            "max_static_fallback_rate": 0.6,
        },
        "drift_thresholds": {"drift_thresholds_defined": True, "max_drift_signal_count": 0},
        "incident_freeze_contract": {
            "incident_freeze_conditions_defined": True,
            "freeze_on_any_user_facing_authority_drift": True,
            "freeze_on_any_commercial_claim_drift": True,
            "freeze_on_any_scope_or_sample_limit_drift": True,
        },
        "runtime_receipt_schema": {
            "runtime_receipt_schema_defined": True,
            "required_receipts": [
                "b04_r6_expanded_canary_runtime_execution_receipt.json",
                "b04_r6_expanded_canary_runtime_result.json",
                "b04_r6_expanded_canary_case_manifest.json",
                "b04_r6_expanded_canary_route_distribution_receipt.json",
                "b04_r6_expanded_canary_fallback_behavior_receipt.json",
                "b04_r6_expanded_canary_operator_override_receipt.json",
                "b04_r6_expanded_canary_kill_switch_receipt.json",
                "b04_r6_expanded_canary_rollback_receipt.json",
                "b04_r6_expanded_canary_drift_monitoring_receipt.json",
                "b04_r6_expanded_canary_incident_freeze_receipt.json",
                "b04_r6_expanded_canary_trace_completeness_receipt.json",
                "b04_r6_expanded_canary_replay_receipt.json",
                "b04_r6_expanded_canary_no_authorization_drift_receipt.json",
            ],
        },
        "replay_manifest": {
            "runtime_replay_manifest_defined": True,
            "requires_validated_packet_hash": True,
            "requires_post_run_hash_manifest": True,
        },
        "expected_artifact_manifest": {
            "expected_artifact_manifest_defined": True,
            "expected_authoritative_artifacts": [
                "expanded_canary_runtime_execution_contract",
                "expanded_canary_runtime_execution_receipt",
                "expanded_canary_runtime_result",
                "expanded_canary_runtime_report",
                "expanded_canary_case_manifest",
                "expanded_canary_no_authorization_drift_receipt",
            ],
        },
        "external_verifier_requirements": {
            "external_verifier_required": True,
            "public_replay_bundle_required": True,
            "commercial_claim_boundary_required": True,
        },
        "result_interpretation_contract": {
            "result_interpretation_contract_defined": True,
            "canary_pass_does_not_authorize_cutover": True,
            "canary_pass_does_not_open_r6": True,
            "canary_pass_does_not_promote_package": True,
            "success_routes_to": "AUTHOR_B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET",
            "allowed_runtime_outcomes": [
                "B04_R6_EXPANDED_CANARY_RUNTIME_PASSED__EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET_NEXT",
                "B04_R6_EXPANDED_CANARY_RUNTIME_FAILED__EXPANDED_CANARY_REPAIR_OR_CLOSEOUT_NEXT",
                "B04_R6_EXPANDED_CANARY_RUNTIME_INVALIDATED__FORENSIC_EXPANDED_CANARY_RUNTIME_REVIEW_NEXT",
                "B04_R6_EXPANDED_CANARY_RUNTIME_DEFERRED__NAMED_RUNTIME_DEFECT_REMAINS",
            ],
        },
    }
    return details[role]


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _contract_payload(base: Dict[str, Any], *, role: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.expanded_canary_execution.{role}.v1",
        artifact_id=f"B04_R6_EXPANDED_CANARY_EXECUTION_{role.upper()}",
        contract_status="BOUND_NON_EXECUTING",
        details=_contract_detail(role),
    )


def _prep_payload(base: Dict[str, Any], *, role: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.expanded_canary_execution.{role}.prep_only.v1",
        artifact_id=f"B04_R6_{role.upper()}",
        status="PREP_ONLY",
        purpose=f"Prep-only continuation artifact for {role.replace('_', ' ')}.",
        **_prep_guard(),
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    payloads: Dict[str, Any] = {
        "packet_contract": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_execution_packet_contract.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_CONTRACT",
            packet_status="BOUND_NON_EXECUTING",
            packet_summary="Defines expanded-canary execution law for future validation; does not execute expanded canary.",
        ),
        "packet_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_execution_packet_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_RECEIPT",
            receipt_role="expanded_canary_execution_packet_authored",
            packet_status="BOUND_NON_EXECUTING",
        ),
        "no_authorization_drift_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_execution.no_authorization_drift_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EXECUTION_NO_AUTHORIZATION_DRIFT_RECEIPT",
            no_authorization_drift=True,
        ),
        "validation_plan": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_execution_validation_plan.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EXECUTION_VALIDATION_PLAN",
            validation_lane=NEXT_LAWFUL_MOVE,
            expected_success_outcome=VALIDATION_SUCCESS_OUTCOME,
            expected_success_next_lawful_move=VALIDATION_SUCCESS_NEXT_MOVE,
            checks=list(REASON_CODES),
        ),
        "validation_reason_codes": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_execution_validation_reason_codes.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EXECUTION_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
        ),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_expanded_canary_execution_next_lawful_move_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EXECUTION_NEXT_LAWFUL_MOVE_RECEIPT",
            receipt_type="NEXT_LAWFUL_MOVE",
        ),
    }
    for role in CONTRACT_ROLES:
        payloads[role] = _contract_payload(base, role=role)
    for role in PREP_ONLY_ROLES:
        payloads[role] = _prep_payload(base, role=role)
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Expanded Canary Execution Packet",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "The expanded-canary execution packet is authored and bound for validation. It defines mode, scope,",
            "sample limits, allowed/excluded case classes, expansion delta, fallbacks, operator controls, kill switch,",
            "rollback, thresholds, incident/freeze law, receipt schema, replay manifest, expected artifacts, external",
            "verifier requirements, result interpretation, and no-authorization-drift law.",
            "",
            "This packet does not execute expanded canary, does not authorize expanded canary runtime, does not authorize runtime cutover,",
            "does not open R6, does not escalate lobes, does not promote package, and",
            "does not authorize commercial activation claims.",
            "",
            "Truth-engine and trust-zone law remain unchanged.",
            "",
        ]
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    branch = _ensure_branch_context(root)
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads = _load_inputs(root, reports_root)
    _validate_inputs(payloads)
    base = _base(
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        generated_utc=utc_now_iso_z(),
        input_bindings=_input_bindings(root),
        binding_hashes=_binding_hashes(reports_root),
    )
    output_payloads = _outputs(base)
    contract = output_payloads["packet_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "packet_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author the B04 R6 expanded-canary execution packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
