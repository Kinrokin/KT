from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_b04_r6_limited_runtime_authorization_packet as limited
from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_lane_compiler
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-limited-runtime-authorization-packet-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_VALIDATION"
PREVIOUS_LANE = limited.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = limited.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = limited.NEXT_LAWFUL_MOVE
OUTCOME_VALIDATED = "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_VALIDATED__LIMITED_RUNTIME_EXECUTION_PACKET_NEXT"
OUTCOME_DEFERRED = "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_VALIDATED
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET"

MAY_AUTHORIZE = ("LIMITED_RUNTIME_AUTHORIZATION_PACKET_VALIDATED",)
FORBIDDEN_ACTIONS = (
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
VALIDATION_REASON_CODES = (
    "RC_B04R6_LIMITED_RUNTIME_VAL_CONTRACT_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_MAIN_HEAD_MISMATCH",
    "RC_B04R6_LIMITED_RUNTIME_VAL_PACKET_BINDING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_ACTIVATION_REVIEW_BINDING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_SHADOW_RESULT_BINDING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_CANDIDATE_BINDING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_SCOPE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_SCOPE_NOT_LIMITED",
    "RC_B04R6_LIMITED_RUNTIME_VAL_GLOBAL_R6_SCOPE",
    "RC_B04R6_LIMITED_RUNTIME_VAL_STATIC_FALLBACK_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_ABSTENTION_FALLBACK_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_NULL_ROUTE_PRESERVATION_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_OPERATOR_OVERRIDE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_KILL_SWITCH_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_ROLLBACK_PLAN_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_ROUTE_DISTRIBUTION_HEALTH_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_DRIFT_MONITORING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_INCIDENT_FREEZE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_COMMERCIAL_BOUNDARY_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_PACKAGE_PROMOTION_AUTOMATIC",
    "RC_B04R6_LIMITED_RUNTIME_VAL_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED",
    "RC_B04R6_LIMITED_RUNTIME_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_LIMITED_RUNTIME_VAL_R6_OPEN_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_VAL_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_VAL_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_VAL_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_VAL_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_LIMITED_RUNTIME_VAL_TRUST_ZONE_MUTATION",
    "RC_B04R6_LIMITED_RUNTIME_VAL_METRIC_MUTATION",
    "RC_B04R6_LIMITED_RUNTIME_VAL_COMPARATOR_WEAKENING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_COMPILER_SCAFFOLD_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_VAL_NEXT_MOVE_DRIFT",
)
TERMINAL_DEFECTS = (
    "SCOPE_NOT_LIMITED",
    "GLOBAL_R6_SCOPE",
    "LIMITED_RUNTIME_EXECUTION_AUTHORIZED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "R6_OPEN_DRIFT",
    "LOBE_ESCALATION_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL_CLAIM_DRIFT",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "METRIC_MUTATION",
    "COMPARATOR_WEAKENING",
    "NEXT_MOVE_DRIFT",
)

PACKET_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in limited.OUTPUTS.items()
    if filename.endswith(".json")
}
PACKET_TEXT_INPUTS = {
    "packet_report": f"KT_PROD_CLEANROOM/reports/{limited.OUTPUTS['packet_report']}",
    "runtime_operator_override_playbook_prep_only": (
        f"KT_PROD_CLEANROOM/reports/{limited.OUTPUTS['runtime_operator_override_playbook_prep_only']}"
    ),
}
MUTABLE_HANDOFF_ROLES = frozenset({"next_lawful_move"})

CONTROL_VALIDATION_ROLES = (
    "scope_validation",
    "static_fallback_validation",
    "abstention_fallback_validation",
    "null_route_preservation_validation",
    "operator_override_validation",
    "kill_switch_validation",
    "rollback_plan_validation",
    "route_distribution_health_validation",
    "drift_monitoring_validation",
    "runtime_receipt_schema_validation",
    "incident_freeze_validation",
    "external_verifier_validation",
    "commercial_claim_boundary_validation",
    "package_promotion_boundary_validation",
)
PREP_ONLY_OUTPUT_ROLES = (
    "limited_runtime_execution_packet_prep_only_draft",
    "runtime_evidence_review_packet_prep_only_draft",
    "package_promotion_review_preconditions_prep_only_draft",
    "external_audit_delta_manifest_prep_only_draft",
)

OUTPUTS = {
    "validation_contract": "b04_r6_limited_runtime_authorization_packet_validation_contract.json",
    "validation_receipt": "b04_r6_limited_runtime_authorization_packet_validation_receipt.json",
    "validation_report": "b04_r6_limited_runtime_authorization_packet_validation_report.md",
    "scope_validation": "b04_r6_limited_runtime_scope_validation_receipt.json",
    "static_fallback_validation": "b04_r6_limited_runtime_static_fallback_validation_receipt.json",
    "abstention_fallback_validation": "b04_r6_limited_runtime_abstention_fallback_validation_receipt.json",
    "null_route_preservation_validation": "b04_r6_limited_runtime_null_route_preservation_validation_receipt.json",
    "operator_override_validation": "b04_r6_limited_runtime_operator_override_validation_receipt.json",
    "kill_switch_validation": "b04_r6_limited_runtime_kill_switch_validation_receipt.json",
    "rollback_plan_validation": "b04_r6_limited_runtime_rollback_plan_validation_receipt.json",
    "route_distribution_health_validation": "b04_r6_limited_runtime_route_distribution_health_validation_receipt.json",
    "drift_monitoring_validation": "b04_r6_limited_runtime_drift_monitoring_validation_receipt.json",
    "runtime_receipt_schema_validation": "b04_r6_limited_runtime_receipt_schema_validation_receipt.json",
    "incident_freeze_validation": "b04_r6_limited_runtime_incident_freeze_validation_receipt.json",
    "external_verifier_validation": "b04_r6_limited_runtime_external_verifier_validation_receipt.json",
    "commercial_claim_boundary_validation": "b04_r6_limited_runtime_commercial_claim_boundary_validation_receipt.json",
    "package_promotion_boundary_validation": "b04_r6_limited_runtime_package_promotion_boundary_validation_receipt.json",
    "no_authorization_drift_validation": "b04_r6_limited_runtime_no_authorization_drift_validation_receipt.json",
    "lane_compiler_scaffold_receipt": "b04_r6_limited_runtime_authorization_packet_validation_lane_compiler_scaffold_receipt.json",
    "limited_runtime_execution_packet_prep_only_draft": "b04_r6_limited_runtime_execution_packet_prep_only_draft.json",
    "runtime_evidence_review_packet_prep_only_draft": "b04_r6_runtime_evidence_review_packet_prep_only_draft.json",
    "package_promotion_review_preconditions_prep_only_draft": (
        "b04_r6_package_promotion_review_preconditions_prep_only_draft.json"
    ),
    "external_audit_delta_manifest_prep_only_draft": "b04_r6_external_audit_delta_manifest_prep_only_draft.json",
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
        ("r6_open", "RC_B04R6_LIMITED_RUNTIME_VAL_R6_OPEN_DRIFT"),
        ("limited_runtime_authorized", "RC_B04R6_LIMITED_RUNTIME_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED"),
        ("runtime_execution_authorized", "RC_B04R6_LIMITED_RUNTIME_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED"),
        ("runtime_cutover_authorized", "RC_B04R6_LIMITED_RUNTIME_VAL_RUNTIME_CUTOVER_AUTHORIZED"),
        ("activation_cutover_authorized", "RC_B04R6_LIMITED_RUNTIME_VAL_RUNTIME_CUTOVER_AUTHORIZED"),
        ("activation_cutover_executed", "RC_B04R6_LIMITED_RUNTIME_VAL_RUNTIME_CUTOVER_AUTHORIZED"),
        ("lobe_escalation_authorized", "RC_B04R6_LIMITED_RUNTIME_VAL_LOBE_ESCALATION_DRIFT"),
        ("package_promotion_authorized", "RC_B04R6_LIMITED_RUNTIME_VAL_PACKAGE_PROMOTION_DRIFT"),
        ("commercial_activation_claim_authorized", "RC_B04R6_LIMITED_RUNTIME_VAL_COMMERCIAL_CLAIM_DRIFT"),
        ("metric_contract_mutated", "RC_B04R6_LIMITED_RUNTIME_VAL_METRIC_MUTATION"),
        ("static_comparator_weakened", "RC_B04R6_LIMITED_RUNTIME_VAL_COMPARATOR_WEAKENING"),
    ):
        _ensure_false(payload, key, label=label, code=code)
    state = payload.get("authorization_state")
    if isinstance(state, dict):
        _ensure_runtime_closed(state, label=f"{label}.authorization_state")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_PACKAGE_PROMOTION_DRIFT", f"{label} package promotion drift")
    if payload.get("truth_engine_law_changed") is True or payload.get("truth_engine_derivation_law_unchanged") is False:
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_TRUTH_ENGINE_MUTATION", f"{label} truth-engine mutation")
    if payload.get("trust_zone_law_changed") is True or payload.get("trust_zone_law_unchanged") is False:
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_TRUST_ZONE_MUTATION", f"{label} trust-zone mutation")


def _input_bindings(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(PACKET_JSON_INPUTS.items()):
        path = common.resolve_path(root, raw)
        row: Dict[str, Any] = {
            "role": role,
            "path": raw,
            "sha256": file_sha256(path),
            "binding_kind": "file_sha256_at_limited_runtime_packet_validation",
        }
        if role in MUTABLE_HANDOFF_ROLES:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(PACKET_TEXT_INPUTS.items()):
        path = common.resolve_path(root, raw)
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(path),
                "binding_kind": "file_sha256_at_limited_runtime_packet_validation",
            }
        )
    return rows


def _binding_hashes(root: Path, packet_payloads: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    hashes = {
        f"{role}_hash": file_sha256(common.resolve_path(root, raw))
        for role, raw in sorted(PACKET_JSON_INPUTS.items())
    }
    hashes.update(
        {
            f"{role}_hash": file_sha256(common.resolve_path(root, raw))
            for role, raw in sorted(PACKET_TEXT_INPUTS.items())
        }
    )
    packet_hashes = packet_payloads["packet_contract"].get("binding_hashes")
    if not isinstance(packet_hashes, dict):
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_PACKET_BINDING_MISSING", "packet binding hashes missing")
    for key in (
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
    ):
        value = packet_hashes.get(key)
        if not _is_sha256(value):
            _fail("RC_B04R6_LIMITED_RUNTIME_VAL_PACKET_BINDING_MISSING", f"packet missing carried hash {key}")
        hashes[key] = str(value)
    return hashes


def _validate_packet_payloads(packet_payloads: Dict[str, Dict[str, Any]], packet_texts: Dict[str, str]) -> None:
    contract = packet_payloads["packet_contract"]
    receipt = packet_payloads["packet_receipt"]
    next_move = packet_payloads["next_lawful_move"]
    for label, payload in packet_payloads.items():
        _ensure_runtime_closed(payload, label=label)
        if label == "next_lawful_move":
            continue
        if payload.get("status") not in (None, "PASS", "PREP_ONLY"):
            _fail("RC_B04R6_LIMITED_RUNTIME_VAL_PACKET_BINDING_MISSING", f"{label} has non-pass status")
    for label, payload in (("packet_contract", contract), ("packet_receipt", receipt), ("next_lawful_move", next_move)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_LIMITED_RUNTIME_VAL_PACKET_BINDING_MISSING", f"{label} lane identity drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_LIMITED_RUNTIME_VAL_PACKET_BINDING_MISSING", f"{label} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_LIMITED_RUNTIME_VAL_NEXT_MOVE_DRIFT", f"{label} next move drift")
    if contract.get("limited_runtime_authorization_packet_authored") is not True:
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_PACKET_BINDING_MISSING", "packet not authored")
    if contract.get("limited_runtime_authorization_packet_validated") is not False:
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_PACKET_BINDING_MISSING", "packet self-validates prematurely")
    report = packet_texts["packet_report"].lower()
    if "does not authorize limited runtime" not in report:
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "packet report lacks non-execution boundary")


def _requirements(payload: Dict[str, Any]) -> set[str]:
    values = payload.get("requirements")
    if not isinstance(values, list):
        return set()
    return {str(value) for value in values}


def _validate_controls(packet_payloads: Dict[str, Dict[str, Any]]) -> None:
    scope = packet_payloads["scope_manifest"]
    if scope.get("limited_scope_required") is not True:
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_SCOPE_NOT_LIMITED", "scope does not require limited mode")
    if scope.get("max_live_traffic_percent_authorized_by_this_packet") != 0:
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "packet authorizes live traffic")
    if scope.get("allowed_future_modes_after_validation") != ["CANARY_ONLY", "SHADOW_RUNTIME_ONLY"]:
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_SCOPE_NOT_LIMITED", "future modes not canary/shadow only")
    if "global_r6" in json.dumps(scope, sort_keys=True).lower():
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_GLOBAL_R6_SCOPE", "scope references global R6")

    required = {
        "static_fallback_contract": ("static_comparator_remains_available", "static_hold_default_preserved"),
        "abstention_fallback_contract": ("boundary_uncertainty_abstains", "trust_zone_uncertainty_abstains"),
        "null_route_preservation_contract": ("null_route_controls_do_not_enter_selector", "surface_temptations_remain_blocked"),
        "operator_override_contract": ("operator_override_required", "override_may_force_static_fallback"),
        "kill_switch_contract": ("kill_switch_required", "kill_switch_returns_to_static_comparator"),
        "rollback_plan": ("rollback_to_static_comparator_required", "rollback_execution_receipt_required"),
        "route_distribution_health_contract": ("selector_entry_rate_monitored", "overrouting_alarm_required"),
        "drift_monitoring_contract": ("metric_drift_freezes_runtime", "trust_zone_drift_freezes_runtime"),
        "external_verifier_requirements": ("external_verifier_non_executing", "raw_hash_bound_artifacts_required"),
        "commercial_claim_boundary": ("commercial_activation_claims_unauthorized", "package_promotion_prohibited"),
    }
    reason_by_role = {
        "static_fallback_contract": "RC_B04R6_LIMITED_RUNTIME_VAL_STATIC_FALLBACK_MISSING",
        "abstention_fallback_contract": "RC_B04R6_LIMITED_RUNTIME_VAL_ABSTENTION_FALLBACK_MISSING",
        "null_route_preservation_contract": "RC_B04R6_LIMITED_RUNTIME_VAL_NULL_ROUTE_PRESERVATION_MISSING",
        "operator_override_contract": "RC_B04R6_LIMITED_RUNTIME_VAL_OPERATOR_OVERRIDE_MISSING",
        "kill_switch_contract": "RC_B04R6_LIMITED_RUNTIME_VAL_KILL_SWITCH_MISSING",
        "rollback_plan": "RC_B04R6_LIMITED_RUNTIME_VAL_ROLLBACK_PLAN_MISSING",
        "route_distribution_health_contract": "RC_B04R6_LIMITED_RUNTIME_VAL_ROUTE_DISTRIBUTION_HEALTH_MISSING",
        "drift_monitoring_contract": "RC_B04R6_LIMITED_RUNTIME_VAL_DRIFT_MONITORING_MISSING",
        "external_verifier_requirements": "RC_B04R6_LIMITED_RUNTIME_VAL_EXTERNAL_VERIFIER_MISSING",
        "commercial_claim_boundary": "RC_B04R6_LIMITED_RUNTIME_VAL_COMMERCIAL_BOUNDARY_MISSING",
    }
    for role, expected in required.items():
        payload = packet_payloads[role]
        if payload.get("required_before_limited_runtime_validation") is not True:
            _fail(reason_by_role[role], f"{role} not required before validation")
        for flag in ("can_authorize_limited_runtime", "can_execute_runtime", "can_open_r6", "can_promote_package"):
            if payload.get(flag) is not False:
                _fail("RC_B04R6_LIMITED_RUNTIME_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", f"{role} sets {flag}")
        missing = set(expected) - _requirements(payload)
        if missing:
            _fail(reason_by_role[role], f"{role} missing requirements: {sorted(missing)}")

    receipt_schema = packet_payloads["runtime_receipt_schema"]
    if set(limited.RUNTIME_RECEIPT_FIELDS) - set(receipt_schema.get("required_fields", [])):
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING", "runtime receipt fields incomplete")
    incident = packet_payloads["incident_freeze_contract"]
    if set(limited.INCIDENT_FREEZE_CONDITIONS) - set(incident.get("freeze_conditions", [])):
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_INCIDENT_FREEZE_MISSING", "incident freeze fields incomplete")
    if incident.get("any_condition_freezes_runtime_consideration") is not True:
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_INCIDENT_FREEZE_MISSING", "incident freeze not terminal")


def _validate_prep_only(packet_payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in limited.PREP_ONLY_OUTPUT_ROLES:
        if role == "runtime_operator_override_playbook_prep_only":
            continue
        payload = packet_payloads[role]
        if payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_LIMITED_RUNTIME_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{role} authority drift")
        _ensure_runtime_closed(payload, label=role)


def _pass_row(check_id: str, reason_code: str, detail: str, *, group: str) -> Dict[str, str]:
    return {"check_id": check_id, "group": group, "status": "PASS", "reason_code": reason_code, "detail": detail}


def _validation_rows() -> list[Dict[str, str]]:
    rows = [
        _pass_row("validation_contract_preserves_current_main_head", "RC_B04R6_LIMITED_RUNTIME_VAL_MAIN_HEAD_MISMATCH", "validation binds current main head", group="core"),
        _pass_row("validation_binds_limited_runtime_authorization_packet", "RC_B04R6_LIMITED_RUNTIME_VAL_PACKET_BINDING_MISSING", "authored packet is bound", group="binding"),
        _pass_row("validation_binds_activation_review_validation", "RC_B04R6_LIMITED_RUNTIME_VAL_ACTIVATION_REVIEW_BINDING_MISSING", "activation-review validation is bound", group="binding"),
        _pass_row("validation_binds_shadow_superiority_result", "RC_B04R6_LIMITED_RUNTIME_VAL_SHADOW_RESULT_BINDING_MISSING", "shadow-superiority result is bound", group="binding"),
        _pass_row("validation_binds_candidate", "RC_B04R6_LIMITED_RUNTIME_VAL_CANDIDATE_BINDING_MISSING", "candidate hashes are bound", group="binding"),
        _pass_row("limited_runtime_scope_is_defined", "RC_B04R6_LIMITED_RUNTIME_VAL_SCOPE_MISSING", "limited scope exists", group="scope"),
        _pass_row("limited_runtime_scope_is_not_global_r6", "RC_B04R6_LIMITED_RUNTIME_VAL_GLOBAL_R6_SCOPE", "scope is not global R6", group="scope"),
        _pass_row("limited_runtime_scope_is_canary_or_shadow_runtime_only", "RC_B04R6_LIMITED_RUNTIME_VAL_SCOPE_NOT_LIMITED", "future modes constrained", group="scope"),
        _pass_row("static_fallback_exists", "RC_B04R6_LIMITED_RUNTIME_VAL_STATIC_FALLBACK_MISSING", "static fallback exists", group="controls"),
        _pass_row("abstention_fallback_exists", "RC_B04R6_LIMITED_RUNTIME_VAL_ABSTENTION_FALLBACK_MISSING", "abstention fallback exists", group="controls"),
        _pass_row("null_route_preservation_exists", "RC_B04R6_LIMITED_RUNTIME_VAL_NULL_ROUTE_PRESERVATION_MISSING", "null-route preservation exists", group="controls"),
        _pass_row("operator_override_exists", "RC_B04R6_LIMITED_RUNTIME_VAL_OPERATOR_OVERRIDE_MISSING", "operator override exists", group="controls"),
        _pass_row("kill_switch_exists", "RC_B04R6_LIMITED_RUNTIME_VAL_KILL_SWITCH_MISSING", "kill switch exists", group="controls"),
        _pass_row("rollback_plan_exists", "RC_B04R6_LIMITED_RUNTIME_VAL_ROLLBACK_PLAN_MISSING", "rollback plan exists", group="controls"),
        _pass_row("route_distribution_health_monitoring_exists", "RC_B04R6_LIMITED_RUNTIME_VAL_ROUTE_DISTRIBUTION_HEALTH_MISSING", "route health monitoring exists", group="controls"),
        _pass_row("drift_monitoring_exists", "RC_B04R6_LIMITED_RUNTIME_VAL_DRIFT_MONITORING_MISSING", "drift monitoring exists", group="controls"),
        _pass_row("runtime_receipt_schema_exists", "RC_B04R6_LIMITED_RUNTIME_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING", "runtime receipt schema exists", group="controls"),
        _pass_row("incident_freeze_conditions_exist", "RC_B04R6_LIMITED_RUNTIME_VAL_INCIDENT_FREEZE_MISSING", "incident freeze exists", group="controls"),
        _pass_row("external_verifier_requirements_are_non_executing", "RC_B04R6_LIMITED_RUNTIME_VAL_EXTERNAL_VERIFIER_MISSING", "external verifier remains non-executing", group="controls"),
        _pass_row("commercial_activation_claims_remain_unauthorized", "RC_B04R6_LIMITED_RUNTIME_VAL_COMMERCIAL_CLAIM_DRIFT", "commercial claims unauthorized", group="authorization"),
        _pass_row("package_promotion_not_automatic", "RC_B04R6_LIMITED_RUNTIME_VAL_PACKAGE_PROMOTION_AUTOMATIC", "package promotion not automatic", group="authorization"),
        _pass_row("validation_does_not_authorize_limited_runtime_execution", "RC_B04R6_LIMITED_RUNTIME_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "execution unauthorized", group="authorization"),
        _pass_row("validation_does_not_authorize_runtime_cutover", "RC_B04R6_LIMITED_RUNTIME_VAL_RUNTIME_CUTOVER_AUTHORIZED", "cutover unauthorized", group="authorization"),
        _pass_row("validation_does_not_open_r6", "RC_B04R6_LIMITED_RUNTIME_VAL_R6_OPEN_DRIFT", "R6 remains closed", group="authorization"),
        _pass_row("validation_does_not_authorize_lobe_escalation", "RC_B04R6_LIMITED_RUNTIME_VAL_LOBE_ESCALATION_DRIFT", "lobe escalation unauthorized", group="authorization"),
        _pass_row("validation_does_not_authorize_package_promotion", "RC_B04R6_LIMITED_RUNTIME_VAL_PACKAGE_PROMOTION_DRIFT", "package promotion deferred", group="authorization"),
        _pass_row("truth_engine_law_unchanged", "RC_B04R6_LIMITED_RUNTIME_VAL_TRUTH_ENGINE_MUTATION", "truth-engine law unchanged", group="authorization"),
        _pass_row("trust_zone_law_unchanged", "RC_B04R6_LIMITED_RUNTIME_VAL_TRUST_ZONE_MUTATION", "trust-zone law unchanged", group="authorization"),
        _pass_row("metric_contract_not_mutated", "RC_B04R6_LIMITED_RUNTIME_VAL_METRIC_MUTATION", "metric contract unchanged", group="authorization"),
        _pass_row("comparator_not_weakened", "RC_B04R6_LIMITED_RUNTIME_VAL_COMPARATOR_WEAKENING", "comparator unchanged", group="authorization"),
        _pass_row("no_authorization_drift_receipt_passes", "RC_B04R6_LIMITED_RUNTIME_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "no authorization drift passes", group="authorization"),
        _pass_row("lane_compiler_scaffold_is_prep_only", "RC_B04R6_LIMITED_RUNTIME_VAL_COMPILER_SCAFFOLD_MISSING", "compiler scaffold is prep-only", group="scaffold"),
        _pass_row("next_lawful_move_is_limited_runtime_execution_packet", "RC_B04R6_LIMITED_RUNTIME_VAL_NEXT_MOVE_DRIFT", "next move is execution-packet authorship", group="next_move"),
    ]
    rows.extend(
        _pass_row(
            f"validation_binds_{role}",
            "RC_B04R6_LIMITED_RUNTIME_VAL_PACKET_BINDING_MISSING",
            f"{role} input is hash-bound",
            group="binding",
        )
        for role in sorted(PACKET_JSON_INPUTS)
    )
    rows.extend(
        _pass_row(
            f"runtime_receipt_schema_requires_{field}",
            "RC_B04R6_LIMITED_RUNTIME_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING",
            f"runtime receipt requires {field}",
            group="controls",
        )
        for field in limited.RUNTIME_RECEIPT_FIELDS
    )
    rows.extend(
        _pass_row(
            f"incident_freeze_on_{condition}",
            "RC_B04R6_LIMITED_RUNTIME_VAL_INCIDENT_FREEZE_MISSING",
            f"incident freezes on {condition}",
            group="controls",
        )
        for condition in limited.INCIDENT_FREEZE_CONDITIONS
    )
    rows.extend(
        _pass_row(
            f"{role}_is_prep_only",
            "RC_B04R6_LIMITED_RUNTIME_VAL_PREP_ONLY_AUTHORITY_DRIFT",
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
        "limited_runtime_authorization_packet_authored": True,
        "limited_runtime_authorization_packet_validated": True,
        "limited_runtime_authorized": False,
        "limited_runtime_execution_authorized": False,
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
        "lane_id": "VALIDATE_B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET",
        "lane_name": "Validate B04 R6 Limited Runtime Authorization Packet",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM/tools/operator",
        "summary": "Prep-only scaffold for validating the limited-runtime authorization packet.",
        "operator_path": (
            "KT_PROD_CLEANROOM/tools/operator/"
            "cohort0_b04_r6_limited_runtime_authorization_packet_validation.py"
        ),
        "test_path": (
            "KT_PROD_CLEANROOM/tests/operator/"
            "test_b04_r6_limited_runtime_authorization_packet_validation.py"
        ),
        "artifacts": [f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values()],
        "lane_kind": "VALIDATION",
        "current_main_head": current_main_head,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "may_authorize": list(MAY_AUTHORIZE),
        "must_not_authorize": list(FORBIDDEN_ACTIONS),
        "authoritative_inputs": sorted(PACKET_JSON_INPUTS),
        "prep_only_outputs": list(PREP_ONLY_OUTPUT_ROLES),
        "json_parse_inputs": [f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values() if filename.endswith(".json")],
        "no_authorization_drift_checks": [
            "Limited-runtime execution remains unauthorized.",
            "Runtime cutover remains unauthorized.",
            "R6 remains closed.",
            "Package promotion and commercial claims remain unauthorized.",
        ],
        "future_blockers": [
            "LIMITED_RUNTIME_EXECUTION_PACKET_NOT_YET_AUTHORED",
            "RUNTIME_EVIDENCE_REVIEW_PACKET_NOT_YET_AUTHORED",
            "PACKAGE_PROMOTION_REVIEW_NOT_YET_AUTHORED",
        ],
        "reason_codes": list(VALIDATION_REASON_CODES),
    }
    compiled = kt_lane_compiler.build_lane_contract(spec)
    rendered = json.dumps(compiled, sort_keys=True, ensure_ascii=True)
    return {
        "schema_id": "kt.b04_r6.limited_runtime.validation_lane_compiler_scaffold_receipt.v1",
        "artifact_id": "B04_R6_LIMITED_RUNTIME_VALIDATION_LANE_COMPILER_SCAFFOLD_RECEIPT",
        "compiler_id": compiled["compiler_id"],
        "authority": compiled["authority"],
        "status": "PREP_ONLY_SCAFFOLD",
        "lane_id": spec["lane_id"],
        "lane_law_metadata": compiled["lane_law_metadata"],
        "generated_artifacts": compiled["generated_artifacts"],
        "generated_file_count": len(compiled["files"]),
        "compiled_contract_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "files_omitted_from_receipt": True,
        "can_authorize_limited_runtime": False,
        "can_execute_runtime": False,
        "can_open_r6": False,
        "can_promote_package": False,
        "can_authorize_commercial_claims": False,
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
        "reason_codes": list(VALIDATION_REASON_CODES),
        "terminal_defects": list(TERMINAL_DEFECTS),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "validation_rows": validation_rows,
        "lane_compiler_scaffold": compiler_scaffold,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": trust_zone_validation.get("failures", []),
        "authorization_state": _authorization_state(),
        "r6_open": False,
        "shadow_superiority_passed": True,
        "activation_review_validated": True,
        "limited_runtime_authorization_packet_authored": True,
        "limited_runtime_authorization_packet_validated": True,
        "limited_runtime_authorized": False,
        "limited_runtime_execution_authorized": False,
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
        schema_id="kt.b04_r6.limited_runtime_authorization_packet_validation.v1",
        artifact_id="B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_VALIDATION_CONTRACT",
        validation_scope={
            "purpose": "Validate the authored limited-runtime authorization packet as complete, bounded, replayable, and non-executing.",
            "non_purpose": [
                "Does not authorize limited runtime execution.",
                "Does not execute runtime cutover.",
                "Does not open R6.",
                "Does not authorize lobe escalation.",
                "Does not authorize package promotion.",
                "Does not authorize commercial activation claims.",
            ],
        },
        validation_result={
            "packet_complete": True,
            "packet_bounded": True,
            "packet_replayable": True,
            "packet_non_executing": True,
            "limited_runtime_execution_packet_next": True,
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
        schema_id=f"kt.b04_r6.limited_runtime.validation.{schema_slug}.v1",
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
        schema_id="kt.b04_r6.future_blocker_register.v7",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        current_authoritative_lane="VALIDATE_B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET",
        blockers=[
            {
                "blocker_id": "B04R6-FB-051",
                "future_blocker": "Limited-runtime packet is validated but no execution packet exists.",
                "neutralization_now": [OUTPUTS["limited_runtime_execution_packet_prep_only_draft"]],
            },
            {
                "blocker_id": "B04R6-FB-052",
                "future_blocker": "Runtime evidence review law missing after future limited runtime.",
                "neutralization_now": [OUTPUTS["runtime_evidence_review_packet_prep_only_draft"]],
            },
            {
                "blocker_id": "B04R6-FB-053",
                "future_blocker": "Package promotion or commercial claims outrun runtime evidence.",
                "neutralization_now": [
                    OUTPUTS["package_promotion_review_preconditions_prep_only_draft"],
                    OUTPUTS["external_audit_delta_manifest_prep_only_draft"],
                ],
            },
        ],
    )


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Limited-Runtime Authorization Packet Validation\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "The limited-runtime authorization packet is validated as complete, bounded, fallback-protected, "
        "operator-reversible, rollback-defined, receipt-heavy, externally verifiable, and still non-executing.\n\n"
        "This validation does not authorize limited-runtime execution, runtime cutover, R6 opening, lobe escalation, "
        "package promotion, commercial activation claims, or truth/trust law mutation.\n"
    )


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 limited-runtime authorization packet validation")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    packet_payloads = {role: _load(root, raw, label=role) for role, raw in PACKET_JSON_INPUTS.items()}
    packet_texts = {role: _read_text(root, raw, label=role) for role, raw in PACKET_TEXT_INPUTS.items()}
    _validate_packet_payloads(packet_payloads, packet_texts)
    _validate_controls(packet_payloads)
    _validate_prep_only(packet_payloads)

    no_auth = packet_payloads["no_authorization_drift_receipt"]
    if no_auth.get("no_downstream_authorization_drift") is not True:
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_LIMITED_RUNTIME_EXECUTION_AUTHORIZED", "no-auth drift receipt missing pass")

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    compiler_scaffold = _compiler_scaffold(current_main_head)
    if compiler_scaffold.get("authority") != "PREP_ONLY_TOOLING":
        _fail("RC_B04R6_LIMITED_RUNTIME_VAL_COMPILER_SCAFFOLD_MISSING", "compiler scaffold authority drift")

    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=_input_bindings(root, handoff_git_commit=head),
        binding_hashes=_binding_hashes(root, packet_payloads),
        validation_rows=_validation_rows(),
        compiler_scaffold=compiler_scaffold,
        trust_zone_validation=fresh_trust_validation,
    )
    contract = _contract(base)
    output_payloads: Dict[str, Any] = {
        "validation_contract": contract,
        "validation_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.limited_runtime_authorization_packet_validation_receipt.v1",
            artifact_id="B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_VALIDATION_RECEIPT",
            validation_contract_hash_preview="written_with_same_binding_hashes",
            no_downstream_authorization_drift=True,
        ),
        "scope_validation": _validation_receipt(
            base,
            role="scope_validation",
            schema_slug="scope",
            artifact_id="B04_R6_LIMITED_RUNTIME_SCOPE_VALIDATION_RECEIPT",
            subject="limited runtime scope manifest",
            source_roles=("scope_manifest",),
            extra={"limited_scope_required": True, "global_r6_scope": False, "canary_or_shadow_runtime_only": True},
        ),
        "static_fallback_validation": _validation_receipt(
            base,
            role="static_fallback_validation",
            schema_slug="static_fallback",
            artifact_id="B04_R6_LIMITED_RUNTIME_STATIC_FALLBACK_VALIDATION_RECEIPT",
            subject="static fallback contract",
            source_roles=("static_fallback_contract",),
        ),
        "abstention_fallback_validation": _validation_receipt(
            base,
            role="abstention_fallback_validation",
            schema_slug="abstention_fallback",
            artifact_id="B04_R6_LIMITED_RUNTIME_ABSTENTION_FALLBACK_VALIDATION_RECEIPT",
            subject="abstention fallback contract",
            source_roles=("abstention_fallback_contract",),
        ),
        "null_route_preservation_validation": _validation_receipt(
            base,
            role="null_route_preservation_validation",
            schema_slug="null_route_preservation",
            artifact_id="B04_R6_LIMITED_RUNTIME_NULL_ROUTE_PRESERVATION_VALIDATION_RECEIPT",
            subject="null-route preservation contract",
            source_roles=("null_route_preservation_contract",),
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
            subject="kill switch contract",
            source_roles=("kill_switch_contract",),
        ),
        "rollback_plan_validation": _validation_receipt(
            base,
            role="rollback_plan_validation",
            schema_slug="rollback_plan",
            artifact_id="B04_R6_LIMITED_RUNTIME_ROLLBACK_PLAN_VALIDATION_RECEIPT",
            subject="rollback plan",
            source_roles=("rollback_plan",),
        ),
        "route_distribution_health_validation": _validation_receipt(
            base,
            role="route_distribution_health_validation",
            schema_slug="route_distribution_health",
            artifact_id="B04_R6_LIMITED_RUNTIME_ROUTE_DISTRIBUTION_HEALTH_VALIDATION_RECEIPT",
            subject="route-distribution health contract",
            source_roles=("route_distribution_health_contract",),
        ),
        "drift_monitoring_validation": _validation_receipt(
            base,
            role="drift_monitoring_validation",
            schema_slug="drift_monitoring",
            artifact_id="B04_R6_LIMITED_RUNTIME_DRIFT_MONITORING_VALIDATION_RECEIPT",
            subject="drift monitoring contract",
            source_roles=("drift_monitoring_contract",),
        ),
        "runtime_receipt_schema_validation": _validation_receipt(
            base,
            role="runtime_receipt_schema_validation",
            schema_slug="runtime_receipt_schema",
            artifact_id="B04_R6_LIMITED_RUNTIME_RECEIPT_SCHEMA_VALIDATION_RECEIPT",
            subject="runtime receipt schema",
            source_roles=("runtime_receipt_schema",),
            extra={"required_fields": list(limited.RUNTIME_RECEIPT_FIELDS)},
        ),
        "incident_freeze_validation": _validation_receipt(
            base,
            role="incident_freeze_validation",
            schema_slug="incident_freeze",
            artifact_id="B04_R6_LIMITED_RUNTIME_INCIDENT_FREEZE_VALIDATION_RECEIPT",
            subject="incident freeze contract",
            source_roles=("incident_freeze_contract",),
            extra={"freeze_conditions": list(limited.INCIDENT_FREEZE_CONDITIONS)},
        ),
        "external_verifier_validation": _validation_receipt(
            base,
            role="external_verifier_validation",
            schema_slug="external_verifier",
            artifact_id="B04_R6_LIMITED_RUNTIME_EXTERNAL_VERIFIER_VALIDATION_RECEIPT",
            subject="external verifier requirements",
            source_roles=("external_verifier_requirements",),
            extra={"external_verifier_non_executing": True},
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
            schema_id="kt.b04_r6.limited_runtime.no_authorization_drift_validation_receipt.v1",
            artifact_id="B04_R6_LIMITED_RUNTIME_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            no_downstream_authorization_drift=True,
            limited_runtime_execution_authorized=False,
            runtime_cutover_authorized=False,
            r6_open=False,
            lobe_escalation_authorized=False,
            package_promotion_authorized=False,
            commercial_activation_claim_authorized=False,
        ),
        "lane_compiler_scaffold_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.limited_runtime.validation_lane_compiler_scaffold_binding_receipt.v1",
            artifact_id="B04_R6_LIMITED_RUNTIME_VALIDATION_LANE_COMPILER_SCAFFOLD_BINDING_RECEIPT",
            scaffold=compiler_scaffold,
            scaffold_authority="PREP_ONLY_TOOLING",
            scaffold_can_authorize=False,
        ),
        "limited_runtime_execution_packet_prep_only_draft": _prep_only(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_EXECUTION_PACKET_PREP_ONLY_DRAFT",
            schema_slug="limited_runtime_execution_packet_prep_only_draft",
            purpose="Draft future limited-runtime execution packet; not executable authority.",
        ),
        "runtime_evidence_review_packet_prep_only_draft": _prep_only(
            base,
            artifact_id="B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET_PREP_ONLY_DRAFT",
            schema_slug="runtime_evidence_review_packet_prep_only_draft",
            purpose="Draft future runtime evidence review packet.",
        ),
        "package_promotion_review_preconditions_prep_only_draft": _prep_only(
            base,
            artifact_id="B04_R6_PACKAGE_PROMOTION_REVIEW_PRECONDITIONS_PREP_ONLY_DRAFT",
            schema_slug="package_promotion_review_preconditions_prep_only_draft",
            purpose="Draft future package promotion review preconditions.",
        ),
        "external_audit_delta_manifest_prep_only_draft": _prep_only(
            base,
            artifact_id="B04_R6_EXTERNAL_AUDIT_DELTA_MANIFEST_PREP_ONLY_DRAFT",
            schema_slug="external_audit_delta_manifest_prep_only_draft",
            purpose="Draft future external audit delta manifest.",
        ),
        "future_blocker_register": _future_blocker_register(base),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v18",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            verdict="NEXT_LAWFUL_MOVE_SET",
        ),
    }

    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "validation_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
            continue
        write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate B04 R6 limited-runtime authorization packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
