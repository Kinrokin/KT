from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_expanded_canary_execution_packet as execution
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/b04-r6-expanded-canary-execution-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-expanded-canary-execution-packet-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_VALIDATION"
PREVIOUS_LANE = execution.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = execution.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = execution.NEXT_LAWFUL_MOVE

SELECTED_OUTCOME = execution.VALIDATION_SUCCESS_OUTCOME
NEXT_LAWFUL_MOVE = execution.VALIDATION_SUCCESS_NEXT_MOVE
OUTCOME_DEFERRED = "B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_VALIDATION_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
OUTCOME_REJECTED = "B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_REJECTED__EXPANDED_CANARY_RUNTIME_NOT_JUSTIFIED"
OUTCOME_INVALID = "B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_INVALID__FORENSIC_EXPANDED_CANARY_EXECUTION_REVIEW_NEXT"

MAY_AUTHORIZE = ("EXPANDED_CANARY_EXECUTION_PACKET_VALIDATED",)
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
    "GLOBAL_RUNTIME_SURFACE_AUTHORIZED",
)

AUTHORITY_DRIFT_KEYS = {
    "expanded_canary_runtime_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RUNTIME_AUTHORIZED",
    "expanded_canary_runtime_executed": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RUNTIME_EXECUTED",
    "expanded_canary_executed": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RUNTIME_EXECUTED",
    "runtime_cutover_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "activation_cutover_executed": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "r6_open": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_R6_OPEN_DRIFT",
    "global_runtime_surface_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_GLOBAL_RUNTIME_SURFACE",
    "lobe_escalation_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_COMPARATOR_WEAKENED",
}

REASON_CODES = (
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PACKET_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PACKET_OUTCOME_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_NEXT_MOVE_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_INPUT_HASH_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_MODE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_SCOPE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_SAMPLE_LIMIT_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_ALLOWED_CASE_CLASSES_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_EXCLUDED_CASE_CLASSES_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_STATIC_FALLBACK_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_ABSTENTION_FALLBACK_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_NULL_ROUTE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_OPERATOR_OVERRIDE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_KILL_SWITCH_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_ROLLBACK_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_ROUTE_THRESHOLDS_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_DRIFT_THRESHOLDS_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_INCIDENT_FREEZE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RECEIPT_SCHEMA_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_REPLAY_MANIFEST_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_EXPECTED_ARTIFACT_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RESULT_INTERPRETATION_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PREP_ONLY_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RUNTIME_AUTHORIZED",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RUNTIME_EXECUTED",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_R6_OPEN_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_GLOBAL_RUNTIME_SURFACE",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_TRUST_ZONE_MUTATION",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_METRIC_MUTATION",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_COMPARATOR_WEAKENED",
    "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_TRUST_ZONE_FAILED",
)

EXECUTION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in execution.OUTPUTS.items()
    if filename.endswith(".json")
}
EXECUTION_TEXT_INPUTS = {
    "packet_report": f"KT_PROD_CLEANROOM/reports/{execution.OUTPUTS['packet_report']}",
}

VALIDATION_RECEIPT_ROLES = (
    "packet_binding_validation",
    "authorization_validation_binding",
    "mode_validation",
    "scope_validation",
    "allowed_case_class_validation",
    "excluded_case_class_validation",
    "sample_limit_validation",
    "expansion_delta_validation",
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
    "replay_manifest_validation",
    "expected_artifact_manifest_validation",
    "external_verifier_validation",
    "result_interpretation_validation",
    "prep_only_validation",
)

OUTPUTS = {
    "validation_contract": "b04_r6_expanded_canary_execution_packet_validation_contract.json",
    "validation_receipt": "b04_r6_expanded_canary_execution_packet_validation_receipt.json",
    "validation_report": "b04_r6_expanded_canary_execution_packet_validation_report.md",
    "packet_binding_validation": "b04_r6_expanded_canary_execution_packet_binding_validation_receipt.json",
    "authorization_validation_binding": "b04_r6_expanded_canary_execution_authorization_validation_binding_receipt.json",
    "mode_validation": "b04_r6_expanded_canary_execution_mode_validation_receipt.json",
    "scope_validation": "b04_r6_expanded_canary_execution_scope_validation_receipt.json",
    "allowed_case_class_validation": "b04_r6_expanded_canary_execution_allowed_case_class_validation_receipt.json",
    "excluded_case_class_validation": "b04_r6_expanded_canary_execution_excluded_case_class_validation_receipt.json",
    "sample_limit_validation": "b04_r6_expanded_canary_execution_sample_limit_validation_receipt.json",
    "expansion_delta_validation": "b04_r6_expanded_canary_execution_expansion_delta_validation_receipt.json",
    "static_fallback_validation": "b04_r6_expanded_canary_execution_static_fallback_validation_receipt.json",
    "abstention_fallback_validation": "b04_r6_expanded_canary_execution_abstention_fallback_validation_receipt.json",
    "null_route_preservation_validation": "b04_r6_expanded_canary_execution_null_route_validation_receipt.json",
    "operator_override_validation": "b04_r6_expanded_canary_execution_operator_override_validation_receipt.json",
    "kill_switch_validation": "b04_r6_expanded_canary_execution_kill_switch_validation_receipt.json",
    "rollback_validation": "b04_r6_expanded_canary_execution_rollback_validation_receipt.json",
    "route_distribution_threshold_validation": "b04_r6_expanded_canary_execution_route_distribution_threshold_validation_receipt.json",
    "drift_threshold_validation": "b04_r6_expanded_canary_execution_drift_threshold_validation_receipt.json",
    "incident_freeze_validation": "b04_r6_expanded_canary_execution_incident_freeze_validation_receipt.json",
    "runtime_receipt_schema_validation": "b04_r6_expanded_canary_execution_runtime_receipt_schema_validation_receipt.json",
    "replay_manifest_validation": "b04_r6_expanded_canary_execution_replay_manifest_validation_receipt.json",
    "expected_artifact_manifest_validation": "b04_r6_expanded_canary_execution_expected_artifact_validation_receipt.json",
    "external_verifier_validation": "b04_r6_expanded_canary_execution_external_verifier_validation_receipt.json",
    "result_interpretation_validation": "b04_r6_expanded_canary_execution_result_interpretation_validation_receipt.json",
    "prep_only_validation": "b04_r6_expanded_canary_execution_prep_only_validation_receipt.json",
    "no_authorization_drift_validation": "b04_r6_expanded_canary_execution_no_authorization_drift_validation_receipt.json",
    "next_lawful_move": "b04_r6_expanded_canary_execution_validation_next_lawful_move_receipt.json",
}


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


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PACKET_MISSING", f"{label} must be object")
    return payload


def _walk_dicts(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role, payload in payloads.items():
        for nested in _walk_dicts(payload):
            for key, code in AUTHORITY_DRIFT_KEYS.items():
                if key in nested and nested.get(key) is not False:
                    _fail(code, f"{role}.{key} drifted to {nested.get(key)!r}")
            if nested.get("package_promotion") not in (None, "DEFERRED"):
                _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PACKAGE_PROMOTION_DRIFT", f"{role}.package_promotion drifted")
            if nested.get("commercial_claim_status") not in (None, "BOUNDARY_ONLY"):
                _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_COMMERCIAL_CLAIM_DRIFT", f"{role}.commercial_claim_status drifted")


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in EXECUTION_JSON_INPUTS.items()}
    texts = {role: common.read_text_required(root, raw, label=role) for role, raw in EXECUTION_TEXT_INPUTS.items()}
    return payloads, texts


def _details(payloads: Dict[str, Dict[str, Any]], role: str) -> Dict[str, Any]:
    details = payloads[role].get("details", {})
    if not isinstance(details, dict):
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PACKET_MISSING", f"{role}.details missing")
    return details


def _validate_handoff(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    contract = payloads["packet_contract"]
    receipt = payloads["packet_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PACKET_OUTCOME_DRIFT", "packet contract outcome drifted")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PACKET_OUTCOME_DRIFT", "packet receipt outcome drifted")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_NEXT_MOVE_DRIFT", "authoring next move is not validation")
    if contract.get("validation_success_next_lawful_move") != NEXT_LAWFUL_MOVE:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_NEXT_MOVE_DRIFT", "validation success does not route to runtime")
    report = texts["packet_report"].lower()
    for phrase in ("does not execute expanded canary", "does not authorize expanded canary runtime", "does not authorize runtime cutover"):
        if phrase not in report:
            _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PACKET_MISSING", f"packet report lacks boundary: {phrase}")


def _validate_binding_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["packet_contract"]
    for role, filename in execution.INPUTS.items():
        key = f"{role}_hash"
        expected = file_sha256(common.resolve_path(root, f"KT_PROD_CLEANROOM/reports/{filename}"))
        if contract.get("binding_hashes", {}).get(key) != expected:
            _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_INPUT_HASH_DRIFT", f"{key} drifted")


def _validate_contracts(payloads: Dict[str, Dict[str, Any]]) -> None:
    if _details(payloads, "execution_mode_contract").get("runtime_may_run_before_validation") is not False:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_MODE_MISSING", "mode allows runtime before validation")
    if _details(payloads, "execution_mode_contract").get("runtime_may_run_after_validation_only") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_MODE_MISSING", "mode does not route runtime after validation")

    scope = _details(payloads, "execution_scope_manifest")
    if scope.get("global_r6_scope_allowed") is not False or scope.get("runtime_cutover_allowed") is not False:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_SCOPE_MISSING", "scope widened to global/cutover")
    if scope.get("commercial_surface_allowed") is not False or scope.get("max_case_count_per_window") != 36:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_SCOPE_MISSING", "scope commercial/sample drift")

    sample = _details(payloads, "sample_limit_contract")
    if sample.get("max_cases") != 36 or sample.get("max_route_observations") != 24:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_SAMPLE_LIMIT_MISSING", "sample limits drifted")
    if sample.get("sample_limit_drift_fails_closed") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_SAMPLE_LIMIT_MISSING", "sample drift guard missing")

    allowed = tuple(_details(payloads, "allowed_case_class_contract").get("allowed_case_classes", []))
    if allowed != execution.EXPECTED_ALLOWED_CASE_CLASSES:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_ALLOWED_CASE_CLASSES_DRIFT", "allowed case classes drifted")
    excluded = set(_details(payloads, "excluded_case_class_contract").get("excluded_case_classes", []))
    if not set(execution.EXPECTED_EXCLUDED_CASE_CLASSES).issubset(excluded):
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_EXCLUDED_CASE_CLASSES_DRIFT", "excluded case classes drifted")

    if _details(payloads, "expansion_delta_contract").get("expansion_delta_defined") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_SAMPLE_LIMIT_MISSING", "expansion delta missing")
    if _details(payloads, "expansion_delta_contract").get("expanded_canary_max_cases") != 36:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_SAMPLE_LIMIT_MISSING", "expansion delta sample drift")

    required_controls = {
        "static_fallback_contract": ("static_fallback_required", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_STATIC_FALLBACK_MISSING"),
        "abstention_fallback_contract": ("abstention_fallback_required", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_ABSTENTION_FALLBACK_MISSING"),
        "null_route_preservation_contract": ("null_route_preservation_required", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_NULL_ROUTE_MISSING"),
        "operator_override_contract": ("operator_override_required", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_OPERATOR_OVERRIDE_MISSING"),
        "kill_switch_contract": ("kill_switch_required", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_KILL_SWITCH_MISSING"),
        "rollback_contract": ("rollback_required", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_ROLLBACK_MISSING"),
    }
    for role, (key, code) in required_controls.items():
        if _details(payloads, role).get(key) is not True:
            _fail(code, f"{role}.{key} missing")
        if not _details(payloads, role).get("reason_code"):
            _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PREP_ONLY_DRIFT", f"{role} lacks reason-code mapping")

    simple_true = {
        "route_distribution_thresholds": ("route_distribution_thresholds_defined", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_ROUTE_THRESHOLDS_MISSING"),
        "drift_thresholds": ("drift_thresholds_defined", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_DRIFT_THRESHOLDS_MISSING"),
        "incident_freeze_contract": ("incident_freeze_conditions_defined", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_INCIDENT_FREEZE_MISSING"),
        "runtime_receipt_schema": ("runtime_receipt_schema_defined", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RECEIPT_SCHEMA_MISSING"),
        "replay_manifest": ("runtime_replay_manifest_defined", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_REPLAY_MANIFEST_MISSING"),
        "expected_artifact_manifest": ("expected_artifact_manifest_defined", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_EXPECTED_ARTIFACT_MISSING"),
        "external_verifier_requirements": ("external_verifier_required", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_EXTERNAL_VERIFIER_MISSING"),
        "result_interpretation_contract": ("result_interpretation_contract_defined", "RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RESULT_INTERPRETATION_MISSING"),
    }
    for role, (key, code) in simple_true.items():
        if _details(payloads, role).get(key) is not True:
            _fail(code, f"{role}.{key} missing")
    result = _details(payloads, "result_interpretation_contract")
    if result.get("canary_pass_does_not_authorize_cutover") is not True or result.get("canary_pass_does_not_open_r6") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_RESULT_INTERPRETATION_MISSING", "result interpretation widens authority")


def _validate_prep_only(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in execution.PREP_ONLY_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY":
            _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PREP_ONLY_DRIFT", f"{role} authority drifted")
        for guard in (
            "cannot_execute_expanded_canary",
            "cannot_authorize_runtime_cutover",
            "cannot_open_r6",
            "cannot_authorize_package_promotion",
            "cannot_authorize_commercial_activation_claims",
        ):
            if payload.get(guard) is not True:
                _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_PREP_ONLY_DRIFT", f"{role}.{guard} missing")


def _validate_authoring_payloads(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _ensure_authority_closed(payloads)
    _validate_handoff(payloads, texts)
    _validate_binding_hashes(root, payloads)
    _validate_contracts(payloads)
    _validate_prep_only(payloads)


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows = [
        {
            "role": role,
            "path": raw,
            "sha256": file_sha256(common.resolve_path(root, raw)),
            "binding_kind": "file_sha256_at_expanded_canary_execution_validation",
        }
        for role, raw in sorted(EXECUTION_JSON_INPUTS.items())
    ]
    rows.extend(
        {
            "role": role,
            "path": raw,
            "sha256": file_sha256(common.resolve_path(root, raw)),
            "binding_kind": "file_sha256_at_expanded_canary_execution_validation",
        }
        for role, raw in sorted(EXECUTION_TEXT_INPUTS.items())
    )
    return rows


def _binding_hashes(root: Path) -> Dict[str, str]:
    hashes = {f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(EXECUTION_JSON_INPUTS.items())}
    hashes.update({f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(EXECUTION_TEXT_INPUTS.items())})
    return hashes


def _guard() -> Dict[str, Any]:
    return {
        "expanded_canary_authorization_packet_validated": True,
        "expanded_canary_execution_packet_authored": True,
        "expanded_canary_execution_packet_validated": True,
        "expanded_canary_runtime_next_lawful_lane": True,
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


def _validation_rows() -> list[Dict[str, Any]]:
    checks = [
        "expanded_canary_execution_packet_bound",
        "authorization_validation_bound",
        "execution_mode_defined",
        "scope_limited",
        "sample_limits_defined",
        "allowed_case_classes_match_expected_bounded_set",
        "excluded_case_classes_block_global_cutover_commercial",
        "fallbacks_required",
        "operator_override_required",
        "kill_switch_required",
        "rollback_required",
        "thresholds_defined",
        "runtime_receipt_schema_defined",
        "replay_manifest_defined",
        "expected_artifact_manifest_defined",
        "external_verifier_required",
        "result_interpretation_preserves_boundary",
        "prep_only_outputs_non_authoritative",
        "runtime_not_executed",
        "cutover_not_authorized",
        "r6_closed",
        "package_promotion_blocked",
        "commercial_claims_blocked",
        "truth_trust_unchanged",
        "next_lawful_move_is_expanded_canary_runtime",
    ]
    terminal = {"expanded_canary_execution_packet_bound", "scope_limited", "sample_limits_defined", "runtime_not_executed", "cutover_not_authorized", "r6_closed", "truth_trust_unchanged", "next_lawful_move_is_expanded_canary_runtime"}
    return [
        {"check_id": f"B04R6-EXPANDED-CANARY-EXEC-VALIDATION-{idx:03d}", "name": check, "status": "PASS", "terminal_if_fail": check in terminal}
        for idx, check in enumerate(checks, start=1)
    ]


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    input_bindings: list[Dict[str, str]],
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
            OUTCOME_DEFERRED: "REPAIR_B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_VALIDATION_DEFECTS",
            OUTCOME_REJECTED: "AUTHOR_B04_R6_EXPANDED_CANARY_RUNTIME_REJECTION_CLOSEOUT",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_EXPANDED_CANARY_EXECUTION_REVIEW",
        },
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "validation_rows": _validation_rows(),
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        **_guard(),
    }


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _validation_receipt(base: Dict[str, Any], *, role: str, source_roles: Sequence[str]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.expanded_canary_execution.validation.{role}.v1",
        artifact_id=f"B04_R6_EXPANDED_CANARY_EXECUTION_{role.upper()}_RECEIPT",
        validation_role=role,
        validation_status="PASS",
        source_roles=list(source_roles),
        validated_hashes={f"{source}_hash": base["binding_hashes"].get(f"{source}_hash") for source in source_roles},
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    payloads: Dict[str, Any] = {
        "validation_contract": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_execution_packet_validation_contract.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_VALIDATION_CONTRACT",
            validation_summary="Expanded-canary execution packet is complete, hash-bound, bounded, and ready only for the expanded-canary runtime lane.",
        ),
        "validation_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_execution_packet_validation_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EXECUTION_PACKET_VALIDATION_RECEIPT",
            verdict="EXPANDED_CANARY_EXECUTION_PACKET_VALIDATED_RUNTIME_NEXT",
        ),
        "no_authorization_drift_validation": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_execution.no_authorization_drift_validation_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EXECUTION_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            no_authorization_drift=True,
        ),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_expanded_canary_execution_validation_next_lawful_move_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EXECUTION_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT",
            receipt_type="NEXT_LAWFUL_MOVE",
        ),
    }
    receipt_sources = {
        "packet_binding_validation": ("packet_contract", "packet_receipt"),
        "authorization_validation_binding": ("packet_contract",),
        "mode_validation": ("execution_mode_contract",),
        "scope_validation": ("execution_scope_manifest",),
        "allowed_case_class_validation": ("allowed_case_class_contract",),
        "excluded_case_class_validation": ("excluded_case_class_contract",),
        "sample_limit_validation": ("sample_limit_contract",),
        "expansion_delta_validation": ("expansion_delta_contract",),
        "static_fallback_validation": ("static_fallback_contract",),
        "abstention_fallback_validation": ("abstention_fallback_contract",),
        "null_route_preservation_validation": ("null_route_preservation_contract",),
        "operator_override_validation": ("operator_override_contract",),
        "kill_switch_validation": ("kill_switch_contract",),
        "rollback_validation": ("rollback_contract",),
        "route_distribution_threshold_validation": ("route_distribution_thresholds",),
        "drift_threshold_validation": ("drift_thresholds",),
        "incident_freeze_validation": ("incident_freeze_contract",),
        "runtime_receipt_schema_validation": ("runtime_receipt_schema",),
        "replay_manifest_validation": ("replay_manifest",),
        "expected_artifact_manifest_validation": ("expected_artifact_manifest",),
        "external_verifier_validation": ("external_verifier_requirements",),
        "result_interpretation_validation": ("result_interpretation_contract",),
        "prep_only_validation": tuple(execution.PREP_ONLY_ROLES),
    }
    for role, source_roles in receipt_sources.items():
        payloads[role] = _validation_receipt(base, role=role, source_roles=source_roles)
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Expanded Canary Execution Packet Validation",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "The expanded-canary execution packet validates as bounded, fallback-protected, operator-observed,",
            "rollback-defined, receipt-heavy, externally reviewable, and commercially bounded.",
            "",
            "This validation makes expanded-canary runtime the next lawful lane, but does not execute expanded canary,",
            "does not authorize runtime cutover, does not open R6, does not promote package, and does not authorize",
            "commercial activation claims.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 expanded-canary execution validation")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_authoring_payloads(root, payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_EXPANDED_CANARY_EXEC_VAL_TRUST_ZONE_FAILED", "trust-zone validation failed")
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
    parser = argparse.ArgumentParser(description="Validate the B04 R6 expanded-canary execution packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
