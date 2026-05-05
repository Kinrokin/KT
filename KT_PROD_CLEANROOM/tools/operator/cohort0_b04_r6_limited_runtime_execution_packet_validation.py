from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_b04_r6_limited_runtime_execution_packet as execution
from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_lane_compiler
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-limited-runtime-execution-packet-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_VALIDATION"
PREVIOUS_LANE = execution.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = execution.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = execution.NEXT_LAWFUL_MOVE
OUTCOME_VALIDATED = "B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_VALIDATED__LIMITED_RUNTIME_RUN_NEXT"
OUTCOME_DEFERRED = "B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_VALIDATED
NEXT_LAWFUL_MOVE = "RUN_B04_R6_LIMITED_RUNTIME_CANARY_OR_SHADOW_RUNTIME"

MAY_AUTHORIZE = ("LIMITED_RUNTIME_EXECUTION_PACKET_VALIDATED",)
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
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_CONTRACT_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_MAIN_HEAD_MISMATCH",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKET_BINDING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_AUTHORIZATION_VALIDATION_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_SHADOW_RESULT_BINDING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_CANDIDATE_BINDING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_SCOPE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_MODE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_MODE_NOT_SHADOW_OR_CANARY",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_SCOPE_NOT_LIMITED",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_GLOBAL_R6_SCOPE",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_STATIC_AUTHORITY_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_AFSH_OBSERVATION_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_OPERATOR_OVERRIDE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_KILL_SWITCH_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_ROLLBACK_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_ROUTE_HEALTH_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_DRIFT_MONITORING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_INCIDENT_FREEZE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_R6_OPEN_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_METRIC_MUTATION",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_COMPARATOR_WEAKENING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_TRUST_ZONE_MUTATION",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_COMPILER_SCAFFOLD_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_NEXT_MOVE_DRIFT",
)

EXECUTION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in execution.OUTPUTS.items()
    if filename.endswith(".json")
}
EXECUTION_TEXT_INPUTS = {
    "execution_packet_report": f"KT_PROD_CLEANROOM/reports/{execution.OUTPUTS['execution_packet_report']}",
    "operator_runbook_delta_prep_only": f"KT_PROD_CLEANROOM/reports/{execution.OUTPUTS['operator_runbook_delta_prep_only']}",
    "customer_safe_status_language_prep_only": f"KT_PROD_CLEANROOM/reports/{execution.OUTPUTS['customer_safe_status_language_prep_only']}",
}

CONTROL_VALIDATION_ROLES = (
    "execution_packet_binding_validation",
    "mode_validation",
    "scope_validation",
    "static_authority_validation",
    "afsh_shadow_observation_validation",
    "operator_override_validation",
    "kill_switch_validation",
    "rollback_execution_validation",
    "route_distribution_health_validation",
    "drift_monitoring_validation",
    "incident_freeze_validation",
    "runtime_receipt_schema_validation",
    "external_verifier_validation",
    "commercial_claim_boundary_validation",
    "package_promotion_boundary_validation",
)
PREP_ONLY_OUTPUT_ROLES = (
    "limited_runtime_run_plan_prep_only_draft",
    "limited_runtime_run_receipt_schema_prep_only",
    "limited_runtime_run_result_schema_prep_only",
    "limited_runtime_run_disqualifier_ledger_prep_only",
    "runtime_evidence_review_packet_prep_only_draft",
    "runtime_evidence_scorecard_prep_only",
    "runtime_operator_intervention_review_prep_only",
    "runtime_trace_completeness_review_prep_only",
    "runtime_incident_review_prep_only",
    "package_promotion_review_preconditions_prep_only_draft",
    "release_truth_derivation_prep_only",
    "commercial_claim_boundary_update_prep_only",
    "deployment_profile_delta_prep_only",
    "external_audit_delta_manifest_prep_only",
    "public_verifier_delta_requirements_prep_only",
    "runtime_replay_bundle_manifest_prep_only",
)

OUTPUTS = {
    "validation_contract": "b04_r6_limited_runtime_execution_packet_validation_contract.json",
    "validation_receipt": "b04_r6_limited_runtime_execution_packet_validation_receipt.json",
    "validation_report": "b04_r6_limited_runtime_execution_packet_validation_report.md",
    "execution_packet_binding_validation": "b04_r6_limited_runtime_execution_packet_binding_validation_receipt.json",
    "mode_validation": "b04_r6_limited_runtime_mode_validation_receipt.json",
    "scope_validation": "b04_r6_limited_runtime_scope_validation_receipt.json",
    "static_authority_validation": "b04_r6_limited_runtime_static_authority_validation_receipt.json",
    "afsh_shadow_observation_validation": "b04_r6_limited_runtime_afsh_shadow_observation_validation_receipt.json",
    "operator_override_validation": "b04_r6_limited_runtime_operator_override_validation_receipt.json",
    "kill_switch_validation": "b04_r6_limited_runtime_kill_switch_validation_receipt.json",
    "rollback_execution_validation": "b04_r6_limited_runtime_rollback_execution_validation_receipt.json",
    "route_distribution_health_validation": "b04_r6_limited_runtime_route_distribution_health_validation_receipt.json",
    "drift_monitoring_validation": "b04_r6_limited_runtime_drift_monitoring_validation_receipt.json",
    "incident_freeze_validation": "b04_r6_limited_runtime_incident_freeze_validation_receipt.json",
    "runtime_receipt_schema_validation": "b04_r6_limited_runtime_receipt_schema_validation_receipt.json",
    "external_verifier_validation": "b04_r6_limited_runtime_external_verifier_validation_receipt.json",
    "commercial_claim_boundary_validation": "b04_r6_limited_runtime_commercial_claim_boundary_validation_receipt.json",
    "package_promotion_boundary_validation": "b04_r6_limited_runtime_package_promotion_boundary_validation_receipt.json",
    "no_authorization_drift_validation": "b04_r6_limited_runtime_no_authorization_drift_validation_receipt.json",
    "lane_compiler_scaffold_receipt": "b04_r6_limited_runtime_execution_packet_validation_lane_compiler_scaffold_receipt.json",
    "limited_runtime_run_plan_prep_only_draft": "b04_r6_limited_runtime_run_plan_prep_only_draft.json",
    "limited_runtime_run_receipt_schema_prep_only": "b04_r6_limited_runtime_run_receipt_schema_prep_only.json",
    "limited_runtime_run_result_schema_prep_only": "b04_r6_limited_runtime_run_result_schema_prep_only.json",
    "limited_runtime_run_disqualifier_ledger_prep_only": "b04_r6_limited_runtime_run_disqualifier_ledger_prep_only.json",
    "runtime_evidence_review_packet_prep_only_draft": "b04_r6_runtime_evidence_review_packet_prep_only_draft.json",
    "runtime_evidence_scorecard_prep_only": "b04_r6_runtime_evidence_scorecard_prep_only.json",
    "runtime_operator_intervention_review_prep_only": "b04_r6_runtime_operator_intervention_review_prep_only.json",
    "runtime_trace_completeness_review_prep_only": "b04_r6_runtime_trace_completeness_review_prep_only.json",
    "runtime_incident_review_prep_only": "b04_r6_runtime_incident_review_prep_only.json",
    "package_promotion_review_preconditions_prep_only_draft": "b04_r6_package_promotion_review_preconditions_prep_only_draft.json",
    "release_truth_derivation_prep_only": "b04_r6_release_truth_derivation_prep_only.json",
    "commercial_claim_boundary_update_prep_only": "b04_r6_commercial_claim_boundary_update_prep_only.json",
    "deployment_profile_delta_prep_only": "b04_r6_deployment_profile_delta_prep_only.json",
    "external_audit_delta_manifest_prep_only": "b04_r6_external_audit_delta_manifest_prep_only.json",
    "public_verifier_delta_requirements_prep_only": "b04_r6_public_verifier_delta_requirements_prep_only.json",
    "runtime_replay_bundle_manifest_prep_only": "b04_r6_runtime_replay_bundle_manifest_prep_only.json",
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


def _ensure_false(payload: Dict[str, Any], key: str, *, label: str, code: str) -> None:
    if key in payload and bool(payload.get(key)):
        _fail(code, f"{label} sets forbidden true flag: {key}")


def _ensure_runtime_closed(payload: Dict[str, Any], *, label: str) -> None:
    for key, code in (
        ("r6_open", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_R6_OPEN_DRIFT"),
        ("limited_runtime_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED"),
        (
            "limited_runtime_execution_authorized",
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED",
        ),
        ("limited_runtime_executed", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED"),
        ("runtime_execution_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED"),
        ("runtime_cutover_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_RUNTIME_CUTOVER_AUTHORIZED"),
        ("activation_cutover_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_RUNTIME_CUTOVER_AUTHORIZED"),
        ("activation_cutover_executed", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_RUNTIME_CUTOVER_AUTHORIZED"),
        ("lobe_escalation_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LOBE_ESCALATION_DRIFT"),
        ("package_promotion_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKAGE_PROMOTION_DRIFT"),
        ("commercial_activation_claim_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_COMMERCIAL_CLAIM_DRIFT"),
        ("truth_engine_law_changed", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_TRUTH_ENGINE_MUTATION"),
        ("trust_zone_law_changed", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_TRUST_ZONE_MUTATION"),
        ("metric_contract_mutated", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_METRIC_MUTATION"),
        ("static_comparator_weakened", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_COMPARATOR_WEAKENING"),
    ):
        _ensure_false(payload, key, label=label, code=code)
    state = payload.get("authorization_state")
    if isinstance(state, dict):
        _ensure_runtime_closed(state, label=f"{label}.authorization_state")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKAGE_PROMOTION_DRIFT", f"{label} package promotion drift")
    if payload.get("truth_engine_derivation_law_unchanged") is False:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_TRUTH_ENGINE_MUTATION", f"{label} truth derivation drift")
    if payload.get("trust_zone_law_unchanged") is False:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_TRUST_ZONE_MUTATION", f"{label} trust-zone drift")


def _requirements(payload: Dict[str, Any]) -> set[str]:
    values = payload.get("requirements")
    if not isinstance(values, list):
        return set()
    return {str(value) for value in values}


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
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_NEXT_MOVE_DRIFT", "handoff lacks valid predecessor or self-replay lane identity")
    return {"predecessor_handoff_accepted": predecessor, "self_replay_handoff_accepted": self_replay}


def _validate_execution_payloads(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> Dict[str, bool]:
    contract = payloads["execution_packet_contract"]
    receipt = payloads["execution_packet_receipt"]
    next_move = payloads["next_lawful_move"]
    for label, payload in payloads.items():
        _ensure_runtime_closed(payload, label=label)
        if label == "next_lawful_move":
            continue
        if payload.get("status") not in (None, "PASS", "PREP_ONLY", "PREP_ONLY_SCAFFOLD"):
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKET_BINDING_MISSING", f"{label} has non-pass status")
    for label, payload in (("execution_packet_contract", contract), ("execution_packet_receipt", receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKET_BINDING_MISSING", f"{label} lane identity drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKET_BINDING_MISSING", f"{label} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_NEXT_MOVE_DRIFT", f"{label} next move drift")
        if payload.get("limited_runtime_execution_packet_authored") is not True:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKET_BINDING_MISSING", f"{label} missing authored flag")
        if payload.get("limited_runtime_execution_packet_validated") is not False:
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKET_BINDING_MISSING", f"{label} self-validates prematurely")
    acceptance = _validate_handoff(next_move)
    report = texts["execution_packet_report"].lower()
    if "does not execute limited runtime" not in report:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "report lacks non-execution boundary")
    if "static remains authoritative" not in report:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_STATIC_AUTHORITY_MISSING", "report lacks static authority boundary")
    return acceptance


def _validate_controls(payloads: Dict[str, Dict[str, Any]]) -> None:
    scope = payloads["scope_manifest"]
    if scope.get("limited_scope_required") is not True:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_SCOPE_NOT_LIMITED", "scope not limited")
    if scope.get("selected_runtime_mode") != execution.RUNTIME_MODE:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_MODE_MISSING", "scope mode drift")
    if scope.get("global_r6_scope") is not False:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_GLOBAL_R6_SCOPE", "scope opens global R6")
    if scope.get("max_live_traffic_percent_authorized_by_this_packet") != 0:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "scope authorizes live traffic")
    if scope.get("user_facing_decision_changes_allowed") is not False:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "scope allows user-facing changes")

    mode = payloads["mode_contract"]
    if mode.get("selected_mode") != execution.RUNTIME_MODE:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_MODE_MISSING", "mode contract selected mode drift")
    if mode.get("allowed_modes") != list(execution.ALLOWED_FUTURE_EXECUTION_MODES):
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_MODE_NOT_SHADOW_OR_CANARY", "mode not shadow/canary bounded")
    if mode.get("static_authoritative") is not True or mode.get("afsh_observation_only") is not True:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_MODE_MISSING", "mode does not preserve static/observation boundary")

    static = payloads["static_authority_contract"]
    if static.get("static_decision_authoritative") is not True:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_STATIC_AUTHORITY_MISSING", "static is not authoritative")
    if static.get("afsh_can_change_user_facing_decision") is not False:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_STATIC_AUTHORITY_MISSING", "AFSH can change user-facing decision")

    observation = payloads["afsh_shadow_observation_contract"]
    if observation.get("afsh_observation_only") is not True:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_AFSH_OBSERVATION_MISSING", "AFSH is not observation-only")
    if observation.get("selector_may_cutover") is not False:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "selector may cut over")

    required = {
        "case_class_contract": (
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_SCOPE_MISSING",
            ("packet_bound_cases_only", "no_global_r6_cases", "no_old_universe_fresh_proof"),
        ),
        "operator_override_contract": (
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_OPERATOR_OVERRIDE_MISSING",
            ("operator_override_required", "override_may_force_static_only", "override_receipt_required"),
        ),
        "kill_switch_execution_contract": (
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_KILL_SWITCH_MISSING",
            ("kill_switch_required", "kill_switch_halts_afsh_observation", "kill_switch_receipt_required"),
        ),
        "rollback_execution_contract": (
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_ROLLBACK_MISSING",
            ("rollback_to_static_required", "rollback_receipt_required", "rollback_replay_required"),
        ),
        "route_distribution_health_contract": (
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_ROUTE_HEALTH_MISSING",
            ("route_distribution_monitoring_required", "selector_entry_rate_monitored", "overrouting_alarm_required"),
        ),
        "drift_monitoring_contract": (
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_DRIFT_MONITORING_MISSING",
            ("metric_drift_freezes_runtime", "trust_zone_drift_freezes_runtime", "truth_engine_drift_freezes_runtime"),
        ),
        "incident_freeze_contract": (
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_INCIDENT_FREEZE_MISSING",
            ("incident_freeze_required", "freeze_receipt_required", "forensic_path_required"),
        ),
        "runtime_receipt_schema": (
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING",
            ("runtime_receipt_required", "raw_hash_bound_artifacts_required", "external_replay_refs_required"),
        ),
        "external_verifier_requirements": (
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_EXTERNAL_VERIFIER_MISSING",
            ("external_verifier_non_executing", "raw_hash_bound_artifacts_required", "public_claims_forbidden"),
        ),
        "commercial_claim_boundary": (
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_COMMERCIAL_CLAIM_DRIFT",
            ("commercial_activation_claims_unauthorized", "package_promotion_prohibited", "customer_safe_status_language_required"),
        ),
    }
    for role, (code, expected) in required.items():
        payload = payloads[role]
        missing = set(expected) - _requirements(payload)
        if missing:
            _fail(code, f"{role} missing requirements: {sorted(missing)}")
        for flag in (
            "can_execute_runtime",
            "can_authorize_runtime_cutover",
            "can_open_r6",
            "can_promote_package",
            "can_authorize_commercial_claims",
        ):
            if payload.get(flag) is not False:
                _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", f"{role} sets {flag}")

    operator = payloads["operator_override_contract"]
    if operator.get("override_may_force_afsh_authority") is not False:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_OPERATOR_OVERRIDE_MISSING", "operator can force AFSH authority")
    route_health = payloads["route_distribution_health_contract"]
    if set(execution.ROUTE_HEALTH_SIGNALS) - set(route_health.get("monitored_signals", [])):
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_ROUTE_HEALTH_MISSING", "route health signals incomplete")
    receipt_schema = payloads["runtime_receipt_schema"]
    if set(execution.RUNTIME_RECEIPT_FIELDS) - set(receipt_schema.get("required_fields", [])):
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING", "runtime receipt fields incomplete")
    incident = payloads["incident_freeze_contract"]
    if set(execution.INCIDENT_FREEZE_CONDITIONS) - set(incident.get("freeze_conditions", [])):
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_INCIDENT_FREEZE_MISSING", "incident freeze conditions incomplete")
    external = payloads["external_verifier_requirements"]
    if external.get("external_verifier_non_executing") is not True or external.get("raw_hash_bound_artifacts_required") is not True:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_EXTERNAL_VERIFIER_MISSING", "external verifier boundary missing")
    if external.get("compressed_index_source_of_truth") is not False:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_EXTERNAL_VERIFIER_MISSING", "compressed index truth drift")


def _validate_prep_only(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in execution.PREP_ONLY_OUTPUT_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{role} authority drift")
        _ensure_runtime_closed(payload, label=role)


def _input_bindings(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    output_names = set(OUTPUTS.values())
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(EXECUTION_JSON_INPUTS.items()):
        path = common.resolve_path(root, raw)
        row: Dict[str, Any] = {
            "role": role,
            "path": raw,
            "sha256": file_sha256(path),
            "binding_kind": "file_sha256_at_limited_runtime_execution_packet_validation",
        }
        if Path(raw).name in output_names:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(EXECUTION_TEXT_INPUTS.items()):
        path = common.resolve_path(root, raw)
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(path),
                "binding_kind": "file_sha256_at_limited_runtime_execution_packet_validation",
            }
        )
    return rows


def _binding_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    hashes = {
        f"{role}_hash": file_sha256(common.resolve_path(root, raw))
        for role, raw in sorted(EXECUTION_JSON_INPUTS.items())
    }
    hashes.update(
        {
            f"{role}_hash": file_sha256(common.resolve_path(root, raw))
            for role, raw in sorted(EXECUTION_TEXT_INPUTS.items())
        }
    )
    packet_hashes = payloads["execution_packet_contract"].get("binding_hashes")
    if not isinstance(packet_hashes, dict):
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKET_BINDING_MISSING", "execution packet binding hashes missing")
    for key in (
        "validated_packet_contract_hash",
        "validated_packet_receipt_hash",
        "validated_activation_review_validation_contract_hash",
        "validated_activation_review_validation_receipt_hash",
        "validated_shadow_screen_result_hash",
        "validated_candidate_hash",
        "validated_candidate_manifest_hash",
        "validated_candidate_semantic_hash",
        "validated_static_comparator_contract_hash",
        "validated_metric_contract_hash",
        "validated_trace_completeness_receipt_hash",
        "validated_trust_zone_validation_receipt_hash",
    ):
        value = packet_hashes.get(key)
        if not _is_sha256(value):
            _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKET_BINDING_MISSING", f"missing carried packet hash {key}")
        hashes[key] = str(value)
    return hashes


def _pass_row(check_id: str, reason_code: str, detail: str, *, group: str) -> Dict[str, str]:
    return {"check_id": check_id, "group": group, "status": "PASS", "reason_code": reason_code, "detail": detail}


def _validation_rows() -> list[Dict[str, str]]:
    rows = [
        _pass_row("validation_contract_preserves_current_main_head", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_MAIN_HEAD_MISMATCH", "validation binds current main head", group="core"),
        _pass_row("validation_binds_limited_runtime_execution_packet", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKET_BINDING_MISSING", "execution packet is bound", group="binding"),
        _pass_row("validation_binds_limited_runtime_authorization_validation", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_AUTHORIZATION_VALIDATION_MISSING", "authorization validation is carried", group="binding"),
        _pass_row("validation_binds_shadow_superiority_result", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_SHADOW_RESULT_BINDING_MISSING", "shadow result is carried", group="binding"),
        _pass_row("validation_binds_afsh_candidate", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_CANDIDATE_BINDING_MISSING", "candidate hashes are carried", group="binding"),
        _pass_row("limited_runtime_mode_is_defined", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_MODE_MISSING", "runtime mode exists", group="mode"),
        _pass_row("limited_runtime_mode_is_shadow_or_canary_only", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_MODE_NOT_SHADOW_OR_CANARY", "runtime mode is shadow-only", group="mode"),
        _pass_row("limited_runtime_scope_is_limited", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_SCOPE_NOT_LIMITED", "scope is limited", group="scope"),
        _pass_row("limited_runtime_scope_is_not_global_r6", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_GLOBAL_R6_SCOPE", "scope is not global R6", group="scope"),
        _pass_row("static_remains_authoritative", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_STATIC_AUTHORITY_MISSING", "static remains authoritative", group="static"),
        _pass_row("afsh_observation_does_not_cut_over_runtime", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_AFSH_OBSERVATION_MISSING", "AFSH is observation-only", group="mode"),
        _pass_row("operator_override_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_OPERATOR_OVERRIDE_MISSING", "operator override exists", group="controls"),
        _pass_row("kill_switch_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_KILL_SWITCH_MISSING", "kill switch exists", group="controls"),
        _pass_row("rollback_execution_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_ROLLBACK_MISSING", "rollback exists", group="controls"),
        _pass_row("route_distribution_health_monitoring_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_ROUTE_HEALTH_MISSING", "route health exists", group="monitoring"),
        _pass_row("drift_monitoring_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_DRIFT_MONITORING_MISSING", "drift monitoring exists", group="monitoring"),
        _pass_row("incident_freeze_conditions_exist", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_INCIDENT_FREEZE_MISSING", "incident freeze exists", group="monitoring"),
        _pass_row("runtime_receipt_schema_exists", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING", "runtime receipt schema exists", group="receipts"),
        _pass_row("external_verifier_requirements_are_non_executing", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_EXTERNAL_VERIFIER_MISSING", "external verifier non-executing", group="external"),
        _pass_row("commercial_activation_claims_remain_unauthorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_COMMERCIAL_CLAIM_DRIFT", "commercial claims unauthorized", group="claims"),
        _pass_row("package_promotion_not_authorized", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKAGE_PROMOTION_DRIFT", "package promotion unauthorized", group="claims"),
        _pass_row("validation_does_not_execute_limited_runtime", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "limited runtime not executed", group="authorization"),
        _pass_row("validation_does_not_authorize_runtime_cutover", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_RUNTIME_CUTOVER_AUTHORIZED", "runtime cutover unauthorized", group="authorization"),
        _pass_row("validation_does_not_open_r6", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_R6_OPEN_DRIFT", "R6 closed", group="authorization"),
        _pass_row("validation_does_not_authorize_lobe_escalation", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LOBE_ESCALATION_DRIFT", "lobe escalation unauthorized", group="authorization"),
        _pass_row("validation_does_not_authorize_package_promotion", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKAGE_PROMOTION_DRIFT", "package promotion deferred", group="authorization"),
        _pass_row("validation_does_not_authorize_commercial_activation_claims", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_COMMERCIAL_CLAIM_DRIFT", "commercial claims unauthorized", group="authorization"),
        _pass_row("truth_engine_law_unchanged", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_TRUTH_ENGINE_MUTATION", "truth law unchanged", group="authorization"),
        _pass_row("trust_zone_law_unchanged", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_TRUST_ZONE_MUTATION", "trust law unchanged", group="authorization"),
        _pass_row("metric_contract_not_mutated", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_METRIC_MUTATION", "metric contract unchanged", group="authorization"),
        _pass_row("comparator_not_weakened", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_COMPARATOR_WEAKENING", "comparator unchanged", group="authorization"),
        _pass_row("no_authorization_drift_receipt_passes", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "no authorization drift passes", group="authorization"),
        _pass_row("lane_compiler_scaffold_is_prep_only", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_COMPILER_SCAFFOLD_MISSING", "compiler scaffold remains prep-only", group="scaffold"),
        _pass_row("next_lawful_move_is_limited_runtime_run", "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_NEXT_MOVE_DRIFT", "next move is bounded runtime run", group="next_move"),
    ]
    rows.extend(
        _pass_row(
            f"validation_binds_{role}",
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PACKET_BINDING_MISSING",
            f"{role} input is hash-bound",
            group="binding",
        )
        for role in sorted(EXECUTION_JSON_INPUTS)
    )
    rows.extend(
        _pass_row(
            f"runtime_receipt_schema_requires_{field}",
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING",
            f"runtime receipt requires {field}",
            group="receipts",
        )
        for field in execution.RUNTIME_RECEIPT_FIELDS
    )
    rows.extend(
        _pass_row(
            f"incident_freeze_on_{condition}",
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_INCIDENT_FREEZE_MISSING",
            f"incident freezes on {condition}",
            group="incident",
        )
        for condition in execution.INCIDENT_FREEZE_CONDITIONS
    )
    rows.extend(
        _pass_row(
            f"route_health_monitors_{signal}",
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_ROUTE_HEALTH_MISSING",
            f"route health monitors {signal}",
            group="monitoring",
        )
        for signal in execution.ROUTE_HEALTH_SIGNALS
    )
    rows.extend(
        _pass_row(
            f"{role}_is_prep_only",
            "RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_PREP_ONLY_AUTHORITY_DRIFT",
            f"{role} remains prep-only",
            group="prep_only",
        )
        for role in PREP_ONLY_OUTPUT_ROLES
    )
    return rows


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "shadow_superiority_passed": True,
        "activation_review_validated": True,
        "limited_runtime_authorization_packet_validated": True,
        "limited_runtime_execution_packet_authored": True,
        "limited_runtime_execution_packet_validated": True,
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
        "lane_id": "VALIDATE_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET",
        "lane_name": "Validate B04 R6 Limited Runtime Execution Packet",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM/tools/operator",
        "summary": "Prep-only scaffold for validating the limited-runtime execution packet.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/cohort0_b04_r6_limited_runtime_execution_packet_validation.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_b04_r6_limited_runtime_execution_packet_validation.py",
        "artifacts": [f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values()],
        "lane_kind": "VALIDATION",
        "current_main_head": current_main_head,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "may_authorize": list(MAY_AUTHORIZE),
        "must_not_authorize": list(FORBIDDEN_ACTIONS),
        "authoritative_inputs": sorted(EXECUTION_JSON_INPUTS),
        "prep_only_outputs": list(PREP_ONLY_OUTPUT_ROLES),
        "json_parse_inputs": [f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values() if filename.endswith(".json")],
        "no_authorization_drift_checks": [
            "Limited runtime is not executed inside validation.",
            "Runtime cutover remains unauthorized.",
            "R6 remains closed.",
            "Package promotion and commercial activation claims remain unauthorized.",
        ],
        "future_blockers": [
            "LIMITED_RUNTIME_RUN_PLAN_NOT_YET_AUTHORED",
            "RUNTIME_EVIDENCE_REVIEW_PACKET_NOT_YET_AUTHORED",
            "PACKAGE_PROMOTION_REVIEW_NOT_YET_AUTHORED",
            "EXTERNAL_AUDIT_DELTA_NOT_YET_AUTHORED",
        ],
        "reason_codes": list(REASON_CODES),
    }
    compiled = kt_lane_compiler.build_lane_contract(spec)
    rendered = json.dumps(compiled, sort_keys=True, ensure_ascii=True)
    return {
        "schema_id": "kt.b04_r6.limited_runtime.execution_packet_validation_lane_compiler_scaffold_receipt.v1",
        "artifact_id": "B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_VALIDATION_LANE_COMPILER_SCAFFOLD_RECEIPT",
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
        "allowed_outcomes": [OUTCOME_VALIDATED, OUTCOME_DEFERRED, OUTCOME_INVALID],
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
        "runtime_mode": execution.RUNTIME_MODE,
        "allowed_future_execution_modes": list(execution.ALLOWED_FUTURE_EXECUTION_MODES),
        "r6_open": False,
        "limited_runtime_authorization_packet_validated": True,
        "limited_runtime_execution_packet_authored": True,
        "limited_runtime_execution_packet_validated": True,
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


def _contract(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.limited_runtime_execution_packet_validation.v1",
        artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_VALIDATION_CONTRACT",
        validation_scope={
            "purpose": "Validate the authored limited-runtime execution packet as complete, bounded, replay-safe, and non-executing.",
            "non_purpose": [
                "Does not execute limited runtime.",
                "Does not authorize runtime cutover.",
                "Does not open R6.",
                "Does not authorize lobe escalation.",
                "Does not authorize package promotion.",
                "Does not authorize commercial activation claims.",
            ],
        },
        validation_result={
            "execution_packet_complete": True,
            "execution_packet_bounded": True,
            "execution_packet_replay_safe": True,
            "execution_packet_non_executing": True,
            "limited_runtime_run_next": True,
        },
    )


def _validation_receipt(
    base: Dict[str, Any],
    *,
    role: str,
    schema_slug: str,
    artifact_id: str,
    subject: str,
    source_roles: Sequence[str],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = _with_artifact(
        base,
        schema_id=f"kt.b04_r6.limited_runtime.execution_packet_validation.{schema_slug}.v1",
        artifact_id=artifact_id,
        validation_role=role,
        validation_subject=subject,
        validated_hashes={f"{source_role}_hash": base["binding_hashes"][f"{source_role}_hash"] for source_role in source_roles},
        validation_status="PASS",
    )
    if extra:
        payload.update(extra)
    return payload


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
        activation_cutover_executed=False,
        r6_open=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v9",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        current_authoritative_lane="VALIDATE_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET",
        blockers=[
            {
                "blocker_id": "B04R6-FB-071",
                "future_blocker": "Execution packet validated but runtime run plan is not ready.",
                "neutralization_now": [
                    OUTPUTS["limited_runtime_run_plan_prep_only_draft"],
                    OUTPUTS["limited_runtime_run_receipt_schema_prep_only"],
                    OUTPUTS["limited_runtime_run_result_schema_prep_only"],
                    OUTPUTS["limited_runtime_run_disqualifier_ledger_prep_only"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-072",
                "future_blocker": "Runtime evidence review law missing after future limited runtime.",
                "neutralization_now": [
                    OUTPUTS["runtime_evidence_review_packet_prep_only_draft"],
                    OUTPUTS["runtime_evidence_scorecard_prep_only"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-073",
                "future_blocker": "Package promotion or commercial claims outrun runtime evidence.",
                "neutralization_now": [
                    OUTPUTS["package_promotion_review_preconditions_prep_only_draft"],
                    OUTPUTS["commercial_claim_boundary_update_prep_only"],
                    OUTPUTS["external_audit_delta_manifest_prep_only"],
                ],
            },
        ],
    )


def _pipeline_board(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.pipeline_board.v2",
        artifact_id="B04_R6_PIPELINE_BOARD",
        board=[
            {
                "lane": "AUTHOR_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET",
                "status": "BOUND_AND_VALIDATED",
                "authoritative": False,
                "expected_outcome": EXPECTED_PREVIOUS_OUTCOME,
                "next_lane": "VALIDATE_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET",
                "blocked_by": [],
                "forbidden": list(FORBIDDEN_ACTIONS),
            },
            {
                "lane": "VALIDATE_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET",
                "status": "CURRENT_VALIDATED",
                "authoritative": True,
                "expected_outcome": SELECTED_OUTCOME,
                "next_lane": NEXT_LAWFUL_MOVE,
                "blocked_by": [],
                "forbidden": list(FORBIDDEN_ACTIONS),
            },
            {
                "lane": "RUN_B04_R6_LIMITED_RUNTIME_CANARY_OR_SHADOW_RUNTIME",
                "status": "NEXT",
                "authoritative": False,
                "expected_outcome": "B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME_COMPLETED__RUNTIME_EVIDENCE_REVIEW_PACKET_NEXT",
                "blocked_by": ["runtime run lane must be separately executed"],
                "forbidden": [
                    "RUNTIME_CUTOVER_AUTHORIZED",
                    "R6_OPEN",
                    "PACKAGE_PROMOTION_AUTHORIZED",
                    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
                ],
            },
        ],
    )


def _runtime_corridor_status(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.runtime_corridor_status.v2",
        artifact_id="B04_R6_RUNTIME_CORRIDOR_STATUS",
        corridor=[
            {"lane": "limited_runtime_authorization_packet", "status": "BOUND_AND_VALIDATED"},
            {"lane": "limited_runtime_execution_packet", "status": "BOUND_AND_VALIDATED"},
            {"lane": "limited_runtime_shadow_runtime", "status": "NEXT_NOT_EXECUTED"},
            {"lane": "runtime_evidence_review", "status": "PREP_ONLY_DRAFTED"},
            {"lane": "package_promotion_review", "status": "BLOCKED_BY_RUNTIME_EVIDENCE"},
        ],
    )


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Limited-Runtime Execution Packet Validation\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "The limited-runtime execution packet is validated as complete, bounded, replay-safe, and non-executing. "
        "The future runtime path remains SHADOW_RUNTIME_ONLY with static authority preserved, AFSH observation-only, "
        "operator override, kill switch, rollback, route-health monitoring, drift monitoring, incident freeze, "
        "runtime receipts, external verifier requirements, commercial claim boundary, and package-promotion boundary bound.\n\n"
        "This validation does not execute limited runtime, authorize runtime cutover, open R6, authorize lobe escalation, "
        "promote package, authorize commercial activation claims, or mutate truth/trust law.\n"
    )


def _outputs(base: Dict[str, Any], compiler_scaffold: Dict[str, Any]) -> Dict[str, Any]:
    output_payloads: Dict[str, Any] = {
        "validation_contract": _contract(base),
        "validation_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.limited_runtime_execution_packet_validation_receipt.v1",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_VALIDATION_RECEIPT",
            verdict="EXECUTION_PACKET_VALIDATED_NON_EXECUTING",
            no_downstream_authorization_drift=True,
        ),
        "execution_packet_binding_validation": _validation_receipt(
            base,
            role="execution_packet_binding_validation",
            schema_slug="execution_packet_binding",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_BINDING_VALIDATION_RECEIPT",
            subject="limited-runtime execution packet",
            source_roles=("execution_packet_contract", "execution_packet_receipt", "execution_packet_report"),
        ),
        "mode_validation": _validation_receipt(
            base,
            role="mode_validation",
            schema_slug="mode",
            artifact_id="B04_R6_LIMITED_RUNTIME_MODE_VALIDATION_RECEIPT",
            subject="limited-runtime mode contract",
            source_roles=("mode_contract",),
            extra={"selected_mode": execution.RUNTIME_MODE, "allowed_modes": list(execution.ALLOWED_FUTURE_EXECUTION_MODES)},
        ),
        "scope_validation": _validation_receipt(
            base,
            role="scope_validation",
            schema_slug="scope",
            artifact_id="B04_R6_LIMITED_RUNTIME_SCOPE_VALIDATION_RECEIPT",
            subject="limited-runtime scope manifest",
            source_roles=("scope_manifest",),
            extra={"limited_scope_required": True, "global_r6_scope": False, "live_traffic_percent": 0},
        ),
        "static_authority_validation": _validation_receipt(
            base,
            role="static_authority_validation",
            schema_slug="static_authority",
            artifact_id="B04_R6_LIMITED_RUNTIME_STATIC_AUTHORITY_VALIDATION_RECEIPT",
            subject="static authority contract",
            source_roles=("static_authority_contract",),
            extra={"static_decision_authoritative": True, "afsh_can_change_user_facing_decision": False},
        ),
        "afsh_shadow_observation_validation": _validation_receipt(
            base,
            role="afsh_shadow_observation_validation",
            schema_slug="afsh_shadow_observation",
            artifact_id="B04_R6_LIMITED_RUNTIME_AFSH_SHADOW_OBSERVATION_VALIDATION_RECEIPT",
            subject="AFSH shadow observation contract",
            source_roles=("afsh_shadow_observation_contract",),
            extra={"afsh_observation_only": True, "selector_may_cutover": False},
        ),
        "operator_override_validation": _validation_receipt(
            base,
            role="operator_override_validation",
            schema_slug="operator_override",
            artifact_id="B04_R6_LIMITED_RUNTIME_OPERATOR_OVERRIDE_VALIDATION_RECEIPT",
            subject="operator override contract",
            source_roles=("operator_override_contract",),
        ),
        "kill_switch_validation": _validation_receipt(
            base,
            role="kill_switch_validation",
            schema_slug="kill_switch",
            artifact_id="B04_R6_LIMITED_RUNTIME_KILL_SWITCH_VALIDATION_RECEIPT",
            subject="kill switch execution contract",
            source_roles=("kill_switch_execution_contract",),
        ),
        "rollback_execution_validation": _validation_receipt(
            base,
            role="rollback_execution_validation",
            schema_slug="rollback_execution",
            artifact_id="B04_R6_LIMITED_RUNTIME_ROLLBACK_EXECUTION_VALIDATION_RECEIPT",
            subject="rollback execution contract",
            source_roles=("rollback_execution_contract",),
        ),
        "route_distribution_health_validation": _validation_receipt(
            base,
            role="route_distribution_health_validation",
            schema_slug="route_distribution_health",
            artifact_id="B04_R6_LIMITED_RUNTIME_ROUTE_DISTRIBUTION_HEALTH_VALIDATION_RECEIPT",
            subject="route-distribution health contract",
            source_roles=("route_distribution_health_contract",),
            extra={"monitored_signals": list(execution.ROUTE_HEALTH_SIGNALS)},
        ),
        "drift_monitoring_validation": _validation_receipt(
            base,
            role="drift_monitoring_validation",
            schema_slug="drift_monitoring",
            artifact_id="B04_R6_LIMITED_RUNTIME_DRIFT_MONITORING_VALIDATION_RECEIPT",
            subject="drift monitoring contract",
            source_roles=("drift_monitoring_contract",),
        ),
        "incident_freeze_validation": _validation_receipt(
            base,
            role="incident_freeze_validation",
            schema_slug="incident_freeze",
            artifact_id="B04_R6_LIMITED_RUNTIME_INCIDENT_FREEZE_VALIDATION_RECEIPT",
            subject="incident freeze contract",
            source_roles=("incident_freeze_contract",),
            extra={"freeze_conditions": list(execution.INCIDENT_FREEZE_CONDITIONS)},
        ),
        "runtime_receipt_schema_validation": _validation_receipt(
            base,
            role="runtime_receipt_schema_validation",
            schema_slug="runtime_receipt_schema",
            artifact_id="B04_R6_LIMITED_RUNTIME_RECEIPT_SCHEMA_VALIDATION_RECEIPT",
            subject="runtime receipt schema",
            source_roles=("runtime_receipt_schema",),
            extra={"required_fields": list(execution.RUNTIME_RECEIPT_FIELDS)},
        ),
        "external_verifier_validation": _validation_receipt(
            base,
            role="external_verifier_validation",
            schema_slug="external_verifier",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXTERNAL_VERIFIER_VALIDATION_RECEIPT",
            subject="external verifier requirements",
            source_roles=("external_verifier_requirements",),
            extra={"external_verifier_non_executing": True, "raw_hash_bound_artifacts_required": True},
        ),
        "commercial_claim_boundary_validation": _validation_receipt(
            base,
            role="commercial_claim_boundary_validation",
            schema_slug="commercial_claim_boundary",
            artifact_id="B04_R6_LIMITED_RUNTIME_COMMERCIAL_CLAIM_BOUNDARY_VALIDATION_RECEIPT",
            subject="commercial claim boundary",
            source_roles=("commercial_claim_boundary",),
            extra={"commercial_activation_claims_authorized": False},
        ),
        "package_promotion_boundary_validation": _validation_receipt(
            base,
            role="package_promotion_boundary_validation",
            schema_slug="package_promotion_boundary",
            artifact_id="B04_R6_LIMITED_RUNTIME_PACKAGE_PROMOTION_BOUNDARY_VALIDATION_RECEIPT",
            subject="package promotion boundary",
            source_roles=("commercial_claim_boundary",),
            extra={"package_promotion_automatic": False, "package_promotion_authorized": False},
        ),
        "no_authorization_drift_validation": _with_artifact(
            base,
            schema_id="kt.b04_r6.limited_runtime_execution_packet.no_authorization_drift_validation_receipt.v1",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            no_downstream_authorization_drift=True,
            limited_runtime_execution_authorized=False,
            limited_runtime_executed=False,
            runtime_cutover_authorized=False,
            r6_open=False,
            lobe_escalation_authorized=False,
            package_promotion_authorized=False,
            commercial_activation_claim_authorized=False,
        ),
        "lane_compiler_scaffold_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.limited_runtime.execution_packet_validation_lane_compiler_scaffold_binding_receipt.v1",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_VALIDATION_LANE_COMPILER_SCAFFOLD_BINDING_RECEIPT",
            scaffold=compiler_scaffold,
            scaffold_authority="PREP_ONLY_TOOLING",
            scaffold_can_authorize=False,
        ),
        "pipeline_board": _pipeline_board(base),
        "runtime_corridor_status": _runtime_corridor_status(base),
        "future_blocker_register": _future_blocker_register(base),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v20",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            verdict="NEXT_LAWFUL_MOVE_SET",
        ),
    }
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
    return output_payloads


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 limited-runtime execution packet validation")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in EXECUTION_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in EXECUTION_TEXT_INPUTS.items()}
    handoff_acceptance = _validate_execution_payloads(payloads, texts)
    _validate_controls(payloads)
    _validate_prep_only(payloads)

    no_auth = payloads["no_authorization_drift_receipt"]
    if no_auth.get("no_downstream_authorization_drift") is not True:
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "no-auth drift receipt missing pass")

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if current_branch != "main" else "HEAD")
    compiler_scaffold = _compiler_scaffold(current_main_head)
    if compiler_scaffold.get("authority") != "PREP_ONLY_TOOLING":
        _fail("RC_B04R6_LIMITED_RUNTIME_EXEC_PACKET_VAL_COMPILER_SCAFFOLD_MISSING", "compiler scaffold authority drift")

    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=_input_bindings(root, handoff_git_commit=head),
        binding_hashes=_binding_hashes(root, payloads),
        validation_rows=_validation_rows(),
        compiler_scaffold=compiler_scaffold,
        trust_zone_validation=fresh_trust_validation,
        handoff_acceptance=handoff_acceptance,
    )
    output_payloads = _outputs(base, compiler_scaffold)
    contract = output_payloads["validation_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "validation_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate B04 R6 limited-runtime execution packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
