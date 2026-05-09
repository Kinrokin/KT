from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_expanded_canary_authorization_packet as expanded
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/b04-r6-expanded-canary-authorization-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET_VALIDATION"
PREVIOUS_LANE = expanded.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = expanded.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = expanded.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = expanded.VALIDATION_SUCCESS_OUTCOME
NEXT_LAWFUL_MOVE = expanded.VALIDATION_SUCCESS_NEXT_MOVE

OUTCOME_DEFERRED = "B04_R6_EXPANDED_CANARY_AUTHORIZATION_VALIDATION_DEFERRED__NAMED_DEFECT_REMAINS"
OUTCOME_REJECTED = "B04_R6_EXPANDED_CANARY_AUTHORIZATION_REJECTED__EXPANDED_CANARY_NOT_JUSTIFIED"
OUTCOME_INVALID = "B04_R6_EXPANDED_CANARY_AUTHORIZATION_INVALID__FORENSIC_EXPANDED_CANARY_AUTHORIZATION_REVIEW_NEXT"

MAY_AUTHORIZE = ("EXPANDED_CANARY_AUTHORIZATION_PACKET_VALIDATED",)
FORBIDDEN_ACTIONS = (
    "EXPANDED_CANARY_RUNTIME_AUTHORIZED",
    "EXPANDED_CANARY_RUNTIME_EXECUTED",
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
AUTHORITY_DRIFT_KEYS = {
    "expanded_canary_runtime_authorized": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_RUNTIME_AUTHORIZED",
    "expanded_canary_authorized": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_RUNTIME_AUTHORIZED",
    "expanded_canary_runtime_executed": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_RUNTIME_EXECUTED",
    "expanded_canary_executed": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_RUNTIME_EXECUTED",
    "runtime_cutover_authorized": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "activation_cutover_executed": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "r6_open": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_R6_OPEN_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_COMPARATOR_WEAKENED",
}
REASON_CODES = (
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PACKET_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PACKET_OUTCOME_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_NEXT_MOVE_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_INPUT_HASH_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_SCOPE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_SAMPLE_LIMIT_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_ALLOWED_CASE_CLASSES_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_EXCLUDED_CASE_CLASSES_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_STATIC_FALLBACK_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_ABSTENTION_FALLBACK_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_NULL_ROUTE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_OPERATOR_OVERRIDE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_KILL_SWITCH_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_ROLLBACK_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_ROUTE_THRESHOLDS_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_DRIFT_THRESHOLDS_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_INCIDENT_FREEZE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_RECEIPT_SCHEMA_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_COMMERCIAL_BOUNDARY_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PREP_ONLY_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_RUNTIME_AUTHORIZED",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_RUNTIME_EXECUTED",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_R6_OPEN_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_TRUST_ZONE_MUTATION",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_METRIC_MUTATION",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_COMPARATOR_WEAKENED",
    "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_TRUST_ZONE_FAILED",
)
TERMINAL_DEFECTS = (
    "EXPANDED_CANARY_AUTHORIZATION_PACKET_MISSING",
    "EXPANDED_CANARY_AUTHORIZATION_PACKET_HASH_DRIFT",
    "EXPANDED_CANARY_SCOPE_NOT_LIMITED",
    "EXPANDED_CANARY_SAMPLE_LIMIT_MISSING",
    "EXPANDED_CANARY_RUNTIME_AUTHORITY_DRIFT",
    "RUNTIME_CUTOVER_AUTHORITY_DRIFT",
    "R6_OPEN_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL_CLAIM_DRIFT",
    "TRUTH_OR_TRUST_LAW_DRIFT",
)

EXPANDED_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in expanded.OUTPUTS.items()
    if filename.endswith(".json")
}
EXPANDED_TEXT_INPUTS = {
    "packet_report": f"KT_PROD_CLEANROOM/reports/{expanded.OUTPUTS['packet_report']}",
}
VALIDATION_RECEIPT_ROLES = (
    "packet_binding_validation",
    "scope_validation",
    "allowed_case_class_validation",
    "excluded_case_class_validation",
    "sample_limit_validation",
    "static_fallback_validation",
    "abstention_fallback_validation",
    "null_route_preservation_validation",
    "operator_override_validation",
    "kill_switch_validation",
    "rollback_validation",
    "route_distribution_threshold_validation",
    "drift_threshold_validation",
    "incident_freeze_validation",
    "runtime_receipt_schema_validation",
    "external_verifier_validation",
    "commercial_claim_boundary_validation",
    "package_promotion_prohibition_validation",
)
PREP_ONLY_OUTPUT_ROLES = (
    "expanded_canary_execution_packet_prep_only_draft",
    "expanded_canary_execution_validation_plan_prep_only",
    "expanded_canary_result_schema_prep_only",
    "expanded_canary_failure_closeout_prep_only_draft",
)
OUTPUTS = {
    "validation_contract": "b04_r6_expanded_canary_authorization_packet_validation_contract.json",
    "validation_receipt": "b04_r6_expanded_canary_authorization_packet_validation_receipt.json",
    "validation_report": "b04_r6_expanded_canary_authorization_packet_validation_report.md",
    "packet_binding_validation": "b04_r6_expanded_canary_authorization_packet_binding_validation_receipt.json",
    "scope_validation": "b04_r6_expanded_canary_scope_validation_receipt.json",
    "allowed_case_class_validation": "b04_r6_expanded_canary_allowed_case_class_validation_receipt.json",
    "excluded_case_class_validation": "b04_r6_expanded_canary_excluded_case_class_validation_receipt.json",
    "sample_limit_validation": "b04_r6_expanded_canary_sample_limit_validation_receipt.json",
    "static_fallback_validation": "b04_r6_expanded_canary_static_fallback_validation_receipt.json",
    "abstention_fallback_validation": "b04_r6_expanded_canary_abstention_fallback_validation_receipt.json",
    "null_route_preservation_validation": "b04_r6_expanded_canary_null_route_validation_receipt.json",
    "operator_override_validation": "b04_r6_expanded_canary_operator_override_validation_receipt.json",
    "kill_switch_validation": "b04_r6_expanded_canary_kill_switch_validation_receipt.json",
    "rollback_validation": "b04_r6_expanded_canary_rollback_validation_receipt.json",
    "route_distribution_threshold_validation": "b04_r6_expanded_canary_route_distribution_threshold_validation_receipt.json",
    "drift_threshold_validation": "b04_r6_expanded_canary_drift_threshold_validation_receipt.json",
    "incident_freeze_validation": "b04_r6_expanded_canary_incident_freeze_validation_receipt.json",
    "runtime_receipt_schema_validation": "b04_r6_expanded_canary_runtime_receipt_schema_validation_receipt.json",
    "external_verifier_validation": "b04_r6_expanded_canary_external_verifier_validation_receipt.json",
    "commercial_claim_boundary_validation": "b04_r6_expanded_canary_commercial_claim_boundary_validation_receipt.json",
    "package_promotion_prohibition_validation": "b04_r6_expanded_canary_package_promotion_prohibition_validation_receipt.json",
    "no_authorization_drift_validation": "b04_r6_expanded_canary_authorization_no_authorization_drift_validation_receipt.json",
    "expanded_canary_execution_packet_prep_only_draft": "b04_r6_expanded_canary_authorization_validation_execution_packet_prep_only_draft.json",
    "expanded_canary_execution_validation_plan_prep_only": "b04_r6_expanded_canary_authorization_validation_execution_validation_plan_prep_only.json",
    "expanded_canary_result_schema_prep_only": "b04_r6_expanded_canary_authorization_validation_result_schema_prep_only.json",
    "expanded_canary_failure_closeout_prep_only_draft": "b04_r6_expanded_canary_authorization_validation_failure_closeout_prep_only_draft.json",
    "next_lawful_move": "b04_r6_expanded_canary_authorization_validation_next_lawful_move_receipt.json",
}


def _fail(code: str, detail: str) -> None:
    raise RuntimeError(f"FAIL_CLOSED: {code}: {detail}")


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch not in ALLOWED_BRANCHES:
        allowed = ", ".join(sorted(ALLOWED_BRANCHES))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}; got: {branch}")
    if branch == "main":
        head = common.git_rev_parse(root, "HEAD")
        origin_main = common.git_rev_parse(root, "origin/main")
        if head != origin_main:
            raise RuntimeError("FAIL_CLOSED: main replay requires local main to equal origin/main")
    return branch


def _walk(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PACKET_MISSING", f"{label} must be an object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


def _ensure_authority_closed(payload: Dict[str, Any], *, label: str) -> None:
    for key, value in _walk(payload):
        if key in AUTHORITY_DRIFT_KEYS and value is not False:
            _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted to {value!r}")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PACKAGE_PROMOTION_DRIFT", f"{label}.package_promotion drifted")


def _load_authoring_payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in EXPANDED_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in EXPANDED_TEXT_INPUTS.items()}
    return payloads, texts


def _validate_handoff(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    contract = payloads["packet_contract"]
    receipt = payloads["packet_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PACKET_OUTCOME_DRIFT", "packet contract outcome drifted")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PACKET_OUTCOME_DRIFT", "packet receipt outcome drifted")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_NEXT_MOVE_DRIFT", "authoring next move is not validation")
    if contract.get("validation_success_next_lawful_move") != NEXT_LAWFUL_MOVE:
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_NEXT_MOVE_DRIFT", "validation success does not route to execution packet authoring")
    if "does not execute expanded canary" not in texts["packet_report"].lower():
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_RUNTIME_EXECUTED", "packet report lacks non-execution boundary")
    for role, payload in payloads.items():
        _ensure_authority_closed(payload, label=role)


def _validate_binding_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["packet_contract"]
    for role, raw in expanded.INPUTS.items():
        key = f"{role}_hash"
        expected = file_sha256(common.resolve_path(root, f"KT_PROD_CLEANROOM/reports/{raw}"))
        if contract.get("binding_hashes", {}).get(key) != expected:
            _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_INPUT_HASH_DRIFT", f"{key} drifted")


def _validate_operational_contracts(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in expanded.CONTRACT_ROLES:
        payload = payloads[role]
        if payload.get("contract_status") != "BOUND_NON_EXECUTING":
            _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PACKET_MISSING", f"{role} is not bound/non-executing")
        details = payload.get("details", {})
        if role == "scope_manifest":
            if details.get("scope_status") != "EXPANDED_CANARY_SCOPE_DEFINED_NOT_EXECUTING":
                _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_SCOPE_MISSING", "expanded canary scope not bounded")
            if details.get("global_r6_scope_allowed") is not False or details.get("runtime_cutover_allowed") is not False:
                _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_SCOPE_MISSING", "scope widened to global R6 or cutover")
            if details.get("max_case_count_per_window") != 36:
                _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_SAMPLE_LIMIT_MISSING", "sample limit drifted")
        if role == "allowed_case_class_contract":
            expected_allowed = {
                "ROUTE_ELIGIBLE_LOW_RISK_CANARY_CONFIRMED",
                "STATIC_FALLBACK_AVAILABLE_EXPANDED_ROUTE_CHECK",
                "NON_COMMERCIAL_OPERATOR_OBSERVED_EXPANDED_SAMPLE",
                "PRIOR_CANARY_COVERED_CASE_CLASS_EXTENSION",
            }
            allowed = set(details.get("allowed_case_classes", []))
            forbidden_allowed = {"GLOBAL_R6_TRAFFIC", "RUNTIME_CUTOVER_SURFACE", "COMMERCIAL_ACTIVATION_SURFACE", "PACKAGE_PROMOTION_SURFACE"}
            if allowed != expected_allowed or allowed.intersection(forbidden_allowed):
                _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_ALLOWED_CASE_CLASSES_MISSING", "allowed case classes drifted")
        if role == "excluded_case_class_contract":
            excluded = set(details.get("excluded_case_classes", []))
            if not {"GLOBAL_R6_TRAFFIC", "RUNTIME_CUTOVER_SURFACE", "COMMERCIAL_ACTIVATION_SURFACE"}.issubset(excluded):
                _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_EXCLUDED_CASE_CLASSES_MISSING", "required excluded classes missing")
        if role == "sample_limit_contract":
            if details.get("max_cases") != 36 or details.get("max_route_observations") != 24:
                _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_SAMPLE_LIMIT_MISSING", "sample limit contract drifted")
            if details.get("requires_operator_observation") is not True or details.get("may_not_expand_without_validation") is not True:
                _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_SAMPLE_LIMIT_MISSING", "sample limit guards missing")
        required_true = {
            "static_fallback_contract": ("static_fallback_required", "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_STATIC_FALLBACK_MISSING"),
            "abstention_fallback_contract": ("abstention_fallback_required", "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_ABSTENTION_FALLBACK_MISSING"),
            "null_route_preservation_contract": ("null_route_preservation_required", "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_NULL_ROUTE_MISSING"),
            "operator_override_contract": ("operator_override_required", "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_OPERATOR_OVERRIDE_MISSING"),
            "kill_switch_contract": ("kill_switch_required", "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_KILL_SWITCH_MISSING"),
            "rollback_contract": ("rollback_required", "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_ROLLBACK_MISSING"),
            "external_verifier_requirements": ("external_verifier_required", "RC_B04R6_EXPANDED_CANARY_AUTH_VAL_EXTERNAL_VERIFIER_MISSING"),
        }
        if role in required_true:
            detail_key, reason_code = required_true[role]
            if details.get(detail_key) is not True:
                _fail(reason_code, f"{role}.{detail_key} missing")
        if role == "route_distribution_health_thresholds" and details.get("route_distribution_thresholds_defined") is not True:
            _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_ROUTE_THRESHOLDS_MISSING", "route thresholds missing")
        if role == "drift_thresholds" and details.get("drift_thresholds_defined") is not True:
            _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_DRIFT_THRESHOLDS_MISSING", "drift thresholds missing")
        if role == "incident_freeze_contract" and details.get("incident_freeze_conditions_defined") is not True:
            _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_INCIDENT_FREEZE_MISSING", "incident freeze missing")
        if role == "runtime_receipt_schema" and details.get("runtime_receipt_schema_defined") is not True:
            _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_RECEIPT_SCHEMA_MISSING", "runtime receipt schema missing")
        if role == "commercial_claim_boundary" and details.get("commercial_claim_status") != "BOUNDARY_ONLY":
            _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_COMMERCIAL_BOUNDARY_MISSING", "commercial boundary drifted")
        if role == "package_promotion_prohibition_receipt" and details.get("package_promotion_authorized") is not False:
            _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PACKAGE_PROMOTION_DRIFT", "package promotion drifted")


def _validate_prep_only(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in expanded.PREP_ONLY_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY":
            _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PREP_ONLY_DRIFT", f"{role} authority drifted")
        if payload.get("cannot_authorize_expanded_canary_execution") is not True:
            _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_PREP_ONLY_DRIFT", f"{role} execution guard missing")
        _ensure_authority_closed(payload, label=role)


def _input_bindings(root: Path) -> list[Dict[str, Any]]:
    rows = [
        {
            "role": role,
            "path": raw,
            "sha256": file_sha256(common.resolve_path(root, raw)),
            "binding_kind": "file_sha256_at_expanded_canary_authorization_validation",
        }
        for role, raw in sorted(EXPANDED_JSON_INPUTS.items())
    ]
    rows.extend(
        {
            "role": role,
            "path": raw,
            "sha256": file_sha256(common.resolve_path(root, raw)),
            "binding_kind": "file_sha256_at_expanded_canary_authorization_validation",
        }
        for role, raw in sorted(EXPANDED_TEXT_INPUTS.items())
    )
    return rows


def _binding_hashes(root: Path) -> Dict[str, str]:
    hashes = {
        f"{role}_hash": file_sha256(common.resolve_path(root, raw))
        for role, raw in sorted(EXPANDED_JSON_INPUTS.items())
    }
    hashes.update({f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(EXPANDED_TEXT_INPUTS.items())})
    return hashes


def _validation_rows() -> list[Dict[str, Any]]:
    checks = [
        "expanded_canary_authorization_packet_bound",
        "authoring_receipt_bound",
        "source_input_hashes_match",
        "scope_is_expanded_but_limited",
        "allowed_case_classes_defined",
        "excluded_case_classes_block_global_r6_cutover_and_commercial",
        "sample_limit_defined",
        "static_fallback_required",
        "abstention_fallback_required",
        "null_route_preservation_required",
        "operator_override_required",
        "kill_switch_required",
        "rollback_required",
        "route_distribution_thresholds_defined",
        "drift_thresholds_defined",
        "incident_freeze_conditions_defined",
        "runtime_receipt_schema_defined",
        "external_verifier_required",
        "commercial_claim_boundary_preserved",
        "package_promotion_prohibited",
        "prep_only_execution_scaffold_non_authoritative",
        "expanded_canary_runtime_not_authorized",
        "expanded_canary_runtime_not_executed",
        "runtime_cutover_not_authorized",
        "r6_remains_closed",
        "lobe_escalation_unauthorized",
        "package_promotion_unauthorized",
        "commercial_activation_claims_unauthorized",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
        "metric_contract_not_mutated",
        "static_comparator_not_weakened",
        "next_lawful_move_is_expanded_canary_execution_packet_authoring",
    ]
    terminal = {
        "expanded_canary_authorization_packet_bound",
        "source_input_hashes_match",
        "scope_is_expanded_but_limited",
        "sample_limit_defined",
        "expanded_canary_runtime_not_authorized",
        "runtime_cutover_not_authorized",
        "r6_remains_closed",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
        "next_lawful_move_is_expanded_canary_execution_packet_authoring",
    }
    return [
        {"check_id": f"B04R6-EXPANDED-CANARY-AUTH-VALIDATION-{idx:03d}", "name": check, "status": "PASS", "terminal_if_fail": check in terminal}
        for idx, check in enumerate(checks, start=1)
    ]


def _guard() -> Dict[str, Any]:
    return {
        "expanded_canary_authorization_packet_authored": True,
        "expanded_canary_authorization_packet_validated": True,
        "expanded_canary_execution_packet_authored": False,
        "expanded_canary_execution_packet_validated": False,
        "expanded_canary_runtime_authorized": False,
        "expanded_canary_runtime_executed": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "r6_open": False,
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


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    input_bindings: list[Dict[str, Any]],
    binding_hashes: Dict[str, str],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_version": "v1",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "current_branch": branch,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "may_authorize": list(MAY_AUTHORIZE),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "allowed_outcomes": [SELECTED_OUTCOME, OUTCOME_DEFERRED, OUTCOME_REJECTED, OUTCOME_INVALID],
        "outcome_routing": {
            SELECTED_OUTCOME: NEXT_LAWFUL_MOVE,
            OUTCOME_DEFERRED: "REPAIR_B04_R6_EXPANDED_CANARY_AUTHORIZATION_VALIDATION_DEFECTS",
            OUTCOME_REJECTED: "AUTHOR_B04_R6_EXPANDED_CANARY_REJECTION_CLOSEOUT_PACKET",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_EXPANDED_CANARY_AUTHORIZATION_REVIEW_PACKET",
        },
        "reason_codes": list(REASON_CODES),
        "terminal_defects": list(TERMINAL_DEFECTS),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "validation_rows": _validation_rows(),
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        **_guard(),
    }


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _validation_receipt(base: Dict[str, Any], *, role: str, source_role: str, subject: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.expanded_canary_authorization.validation.{role}.v1",
        artifact_id=f"B04_R6_EXPANDED_CANARY_AUTHORIZATION_{role.upper()}_RECEIPT",
        validation_role=role,
        validation_status="PASS",
        subject=subject,
        source_role=source_role,
        validated_hash=base["binding_hashes"].get(f"{source_role}_hash"),
    )


def _prep_only(base: Dict[str, Any], *, role: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.expanded_canary_authorization_validation.{role}.prep_only.v1",
        artifact_id=f"B04_R6_{role.upper()}",
        status="PREP_ONLY",
        authority="PREP_ONLY",
        can_authorize=False,
        cannot_authorize_expanded_canary_execution=True,
        cannot_authorize_runtime_cutover=True,
        cannot_open_r6=True,
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        purpose=f"Prep-only continuation scaffold for {role.replace('_', ' ')}.",
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    payloads: Dict[str, Any] = {
        "validation_contract": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_authorization_packet_validation_contract.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET_VALIDATION_CONTRACT",
            validation_summary="Expanded canary authorization packet is complete, evidence-bound, bounded, and non-executing.",
        ),
        "validation_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_authorization_packet_validation_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET_VALIDATION_RECEIPT",
            verdict="EXPANDED_CANARY_AUTHORIZATION_PACKET_VALIDATED_NON_EXECUTING",
        ),
        "no_authorization_drift_validation": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_authorization.no_authorization_drift_validation_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_AUTHORIZATION_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            no_authorization_drift=True,
        ),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_expanded_canary_authorization_validation_next_lawful_move_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_AUTHORIZATION_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT",
            receipt_type="NEXT_LAWFUL_MOVE",
        ),
    }
    receipt_specs = {
        "packet_binding_validation": ("packet_contract", "Expanded canary authorization packet"),
        "scope_validation": ("scope_manifest", "Expanded canary scope"),
        "allowed_case_class_validation": ("allowed_case_class_contract", "Allowed case classes"),
        "excluded_case_class_validation": ("excluded_case_class_contract", "Excluded case classes"),
        "sample_limit_validation": ("sample_limit_contract", "Sample limit"),
        "static_fallback_validation": ("static_fallback_contract", "Static fallback"),
        "abstention_fallback_validation": ("abstention_fallback_contract", "Abstention fallback"),
        "null_route_preservation_validation": ("null_route_preservation_contract", "Null-route preservation"),
        "operator_override_validation": ("operator_override_contract", "Operator override"),
        "kill_switch_validation": ("kill_switch_contract", "Kill switch"),
        "rollback_validation": ("rollback_contract", "Rollback"),
        "route_distribution_threshold_validation": ("route_distribution_health_thresholds", "Route distribution thresholds"),
        "drift_threshold_validation": ("drift_thresholds", "Drift thresholds"),
        "incident_freeze_validation": ("incident_freeze_contract", "Incident freeze"),
        "runtime_receipt_schema_validation": ("runtime_receipt_schema", "Runtime receipt schema"),
        "external_verifier_validation": ("external_verifier_requirements", "External verifier requirements"),
        "commercial_claim_boundary_validation": ("commercial_claim_boundary", "Commercial claim boundary"),
        "package_promotion_prohibition_validation": ("package_promotion_prohibition_receipt", "Package promotion prohibition"),
    }
    for role, (source_role, subject) in receipt_specs.items():
        payloads[role] = _validation_receipt(base, role=role, source_role=source_role, subject=subject)
    for role in PREP_ONLY_OUTPUT_ROLES:
        payloads[role] = _prep_only(base, role=role)
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Expanded Canary Authorization Packet Validation",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "The expanded-canary authorization packet validates as bounded, fallback-protected, operator-reversible, "
            "externally reviewable, commercially bounded, and still non-executing.",
            "",
            "This validation does not execute expanded canary, does not authorize expanded canary runtime, does not "
            "authorize runtime cutover, does not open R6, does not promote package, and does not authorize commercial "
            "activation claims.",
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
    if common.git_status_porcelain(root):
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 expanded canary authorization validation")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _load_authoring_payloads(root)
    _validate_handoff(payloads, texts)
    _validate_binding_hashes(root, payloads)
    _validate_operational_contracts(payloads)
    _validate_prep_only(payloads)

    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_VAL_TRUST_ZONE_FAILED", "trust-zone validation failed")

    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
        binding_hashes=_binding_hashes(root),
        trust_zone_validation=trust_zone_validation,
    )
    output_payloads = _outputs(base)
    contract = output_payloads["validation_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "validation_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the B04 R6 expanded canary authorization packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
