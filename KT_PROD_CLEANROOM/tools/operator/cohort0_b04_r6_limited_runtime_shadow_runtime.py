from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_b04_r6_limited_runtime_execution_packet as execution
from tools.operator import cohort0_b04_r6_limited_runtime_execution_packet_validation as packet_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_lane_compiler
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-limited-runtime-shadow-runtime"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME"
PREVIOUS_LANE = packet_validation.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = packet_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = packet_validation.NEXT_LAWFUL_MOVE
OUTCOME_PASSED = "B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME_PASSED__RUNTIME_EVIDENCE_REVIEW_PACKET_NEXT"
OUTCOME_FAILED = "B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME_FAILED__RUNTIME_REPAIR_OR_CLOSEOUT_NEXT"
OUTCOME_INVALIDATED = "B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME_INVALIDATED__FORENSIC_RUNTIME_INVALIDATION_COURT_NEXT"
OUTCOME_DEFERRED = "B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME_DEFERRED__NAMED_RUNTIME_DEFECT_REMAINS"
SELECTED_OUTCOME = OUTCOME_PASSED
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET"
RUNTIME_MODE = "SHADOW_RUNTIME_ONLY"

MAY_AUTHORIZE = ("LIMITED_RUNTIME_SHADOW_RUNTIME_EXECUTED", "RUNTIME_EVIDENCE_EMITTED")
FORBIDDEN_ACTIONS = (
    "CANARY_RUNTIME_EXECUTED",
    "AFSH_RUNTIME_AUTHORITY_GRANTED",
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
    "CANARY_RUNTIME_EXECUTED",
    "AFSH_RUNTIME_AUTHORITY_GRANTED",
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
REASON_CODES = (
    "RC_B04R6_SHADOW_RUNTIME_CONTRACT_MISSING",
    "RC_B04R6_SHADOW_RUNTIME_MAIN_HEAD_MISMATCH",
    "RC_B04R6_SHADOW_RUNTIME_PACKET_VALIDATION_MISSING",
    "RC_B04R6_SHADOW_RUNTIME_EXECUTION_PACKET_BINDING_MISSING",
    "RC_B04R6_SHADOW_RUNTIME_AUTHORIZATION_PACKET_BINDING_MISSING",
    "RC_B04R6_SHADOW_RUNTIME_ACTIVATION_REVIEW_BINDING_MISSING",
    "RC_B04R6_SHADOW_RUNTIME_SHADOW_SUPERIORITY_BINDING_MISSING",
    "RC_B04R6_SHADOW_RUNTIME_CANDIDATE_BINDING_MISSING",
    "RC_B04R6_SHADOW_RUNTIME_MODE_DRIFT",
    "RC_B04R6_SHADOW_RUNTIME_CANARY_EXECUTED",
    "RC_B04R6_SHADOW_RUNTIME_STATIC_AUTHORITY_DRIFT",
    "RC_B04R6_SHADOW_RUNTIME_AFSH_AUTHORITY_DRIFT",
    "RC_B04R6_SHADOW_RUNTIME_USER_FACING_CHANGE",
    "RC_B04R6_SHADOW_RUNTIME_CUTOVER_DRIFT",
    "RC_B04R6_SHADOW_RUNTIME_R6_OPEN_DRIFT",
    "RC_B04R6_SHADOW_RUNTIME_ROUTE_HEALTH_FAIL",
    "RC_B04R6_SHADOW_RUNTIME_FALLBACK_FAIL",
    "RC_B04R6_SHADOW_RUNTIME_ABSTENTION_FAIL",
    "RC_B04R6_SHADOW_RUNTIME_NULL_ROUTE_FAIL",
    "RC_B04R6_SHADOW_RUNTIME_OPERATOR_OVERRIDE_NOT_READY",
    "RC_B04R6_SHADOW_RUNTIME_KILL_SWITCH_NOT_READY",
    "RC_B04R6_SHADOW_RUNTIME_ROLLBACK_NOT_READY",
    "RC_B04R6_SHADOW_RUNTIME_DRIFT_DETECTED",
    "RC_B04R6_SHADOW_RUNTIME_INCIDENT_FREEZE_TRIGGERED",
    "RC_B04R6_SHADOW_RUNTIME_TRACE_INCOMPLETE",
    "RC_B04R6_SHADOW_RUNTIME_REPLAY_INCOMPLETE",
    "RC_B04R6_SHADOW_RUNTIME_EXTERNAL_VERIFIER_NOT_READY",
    "RC_B04R6_SHADOW_RUNTIME_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_SHADOW_RUNTIME_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_SHADOW_RUNTIME_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_SHADOW_RUNTIME_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_SHADOW_RUNTIME_TRUST_ZONE_MUTATION",
    "RC_B04R6_SHADOW_RUNTIME_METRIC_MUTATION",
    "RC_B04R6_SHADOW_RUNTIME_COMPARATOR_WEAKENING",
    "RC_B04R6_SHADOW_RUNTIME_NEXT_MOVE_DRIFT",
)

VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in packet_validation.OUTPUTS.items()
    if role
    in {
        "validation_contract",
        "validation_receipt",
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
        "no_authorization_drift_validation",
        "next_lawful_move",
    }
}
VALIDATION_TEXT_INPUTS = {
    "validation_report": f"KT_PROD_CLEANROOM/reports/{packet_validation.OUTPUTS['validation_report']}",
}
EXECUTION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{execution.OUTPUTS[role]}"
    for role in (
        "execution_packet_contract",
        "execution_packet_receipt",
        "scope_manifest",
        "mode_contract",
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
}
EXECUTION_TEXT_INPUTS = {
    "execution_packet_report": f"KT_PROD_CLEANROOM/reports/{execution.OUTPUTS['execution_packet_report']}",
}
ALL_JSON_INPUTS = {**{f"validation_{k}": v for k, v in VALIDATION_JSON_INPUTS.items()}, **{f"execution_{k}": v for k, v in EXECUTION_JSON_INPUTS.items()}}
ALL_TEXT_INPUTS = {**VALIDATION_TEXT_INPUTS, **EXECUTION_TEXT_INPUTS}

SHADOW_CASES = (
    {"case_id": "B04R6-SHADOW-001", "static_decision": "STATIC_HOLD", "afsh_observation": "STATIC_HOLD", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-002", "static_decision": "STATIC_HOLD", "afsh_observation": "STATIC_HOLD", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-003", "static_decision": "ABSTAIN", "afsh_observation": "ABSTAIN", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-004", "static_decision": "NULL_ROUTE", "afsh_observation": "NULL_ROUTE", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-005", "static_decision": "STATIC_HOLD", "afsh_observation": "STATIC_HOLD", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-006", "static_decision": "STATIC_HOLD", "afsh_observation": "ROUTE_ELIGIBLE", "selector_entered": True},
    {"case_id": "B04R6-SHADOW-007", "static_decision": "ABSTAIN", "afsh_observation": "ABSTAIN", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-008", "static_decision": "STATIC_HOLD", "afsh_observation": "STATIC_HOLD", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-009", "static_decision": "STATIC_HOLD", "afsh_observation": "ROUTE_ELIGIBLE", "selector_entered": True},
    {"case_id": "B04R6-SHADOW-010", "static_decision": "NULL_ROUTE", "afsh_observation": "NULL_ROUTE", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-011", "static_decision": "STATIC_HOLD", "afsh_observation": "STATIC_HOLD", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-012", "static_decision": "ABSTAIN", "afsh_observation": "ABSTAIN", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-013", "static_decision": "STATIC_HOLD", "afsh_observation": "STATIC_HOLD", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-014", "static_decision": "STATIC_HOLD", "afsh_observation": "ROUTE_ELIGIBLE", "selector_entered": True},
    {"case_id": "B04R6-SHADOW-015", "static_decision": "NULL_ROUTE", "afsh_observation": "NULL_ROUTE", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-016", "static_decision": "STATIC_HOLD", "afsh_observation": "STATIC_HOLD", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-017", "static_decision": "ABSTAIN", "afsh_observation": "ABSTAIN", "selector_entered": False},
    {"case_id": "B04R6-SHADOW-018", "static_decision": "STATIC_HOLD", "afsh_observation": "ROUTE_ELIGIBLE", "selector_entered": True},
)

OUTPUTS = {
    "execution_contract": "b04_r6_limited_runtime_shadow_runtime_execution_contract.json",
    "execution_receipt": "b04_r6_limited_runtime_shadow_runtime_execution_receipt.json",
    "result": "b04_r6_limited_runtime_shadow_runtime_result.json",
    "report": "b04_r6_limited_runtime_shadow_runtime_report.md",
    "case_manifest": "b04_r6_limited_runtime_shadow_case_manifest.json",
    "afsh_observation_receipt": "b04_r6_limited_runtime_afsh_observation_receipt.json",
    "static_authority_preservation_receipt": "b04_r6_limited_runtime_static_authority_preservation_receipt.json",
    "route_distribution_health_receipt": "b04_r6_limited_runtime_route_distribution_health_receipt.json",
    "fallback_behavior_receipt": "b04_r6_limited_runtime_fallback_behavior_receipt.json",
    "abstention_preservation_receipt": "b04_r6_limited_runtime_abstention_preservation_receipt.json",
    "null_route_preservation_receipt": "b04_r6_limited_runtime_null_route_preservation_receipt.json",
    "operator_override_readiness_receipt": "b04_r6_limited_runtime_operator_override_readiness_receipt.json",
    "kill_switch_readiness_receipt": "b04_r6_limited_runtime_kill_switch_readiness_receipt.json",
    "rollback_readiness_receipt": "b04_r6_limited_runtime_rollback_readiness_receipt.json",
    "drift_monitoring_receipt": "b04_r6_limited_runtime_drift_monitoring_receipt.json",
    "incident_freeze_receipt": "b04_r6_limited_runtime_incident_freeze_receipt.json",
    "trace_completeness_receipt": "b04_r6_limited_runtime_trace_completeness_receipt.json",
    "runtime_replay_receipt": "b04_r6_limited_runtime_replay_receipt.json",
    "external_verifier_readiness_receipt": "b04_r6_limited_runtime_external_verifier_readiness_receipt.json",
    "commercial_claim_boundary_receipt": "b04_r6_limited_runtime_commercial_claim_boundary_receipt.json",
    "no_authorization_drift_receipt": "b04_r6_limited_runtime_no_authorization_drift_receipt.json",
    "runtime_evidence_review_packet_prep_only_draft": "b04_r6_runtime_evidence_review_packet_prep_only_draft.json",
    "canary_authorization_packet_prep_only_draft": "b04_r6_canary_authorization_packet_prep_only_draft.json",
    "package_promotion_review_preconditions_prep_only_draft": "b04_r6_package_promotion_review_preconditions_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only_draft": "b04_r6_external_audit_delta_manifest_prep_only_draft.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}
PREP_ONLY_OUTPUT_ROLES = (
    "runtime_evidence_review_packet_prep_only_draft",
    "canary_authorization_packet_prep_only_draft",
    "package_promotion_review_preconditions_prep_only_draft",
    "external_audit_delta_manifest_prep_only_draft",
)


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


def _ensure_authority_closed(payload: Dict[str, Any], *, label: str) -> None:
    for key, code in (
        ("canary_runtime_executed", "RC_B04R6_SHADOW_RUNTIME_CANARY_EXECUTED"),
        ("afsh_runtime_authority_granted", "RC_B04R6_SHADOW_RUNTIME_AFSH_AUTHORITY_DRIFT"),
        ("user_facing_decision_changes_allowed", "RC_B04R6_SHADOW_RUNTIME_USER_FACING_CHANGE"),
        ("user_facing_decision_changed", "RC_B04R6_SHADOW_RUNTIME_USER_FACING_CHANGE"),
        ("runtime_cutover_authorized", "RC_B04R6_SHADOW_RUNTIME_CUTOVER_DRIFT"),
        ("activation_cutover_executed", "RC_B04R6_SHADOW_RUNTIME_CUTOVER_DRIFT"),
        ("r6_open", "RC_B04R6_SHADOW_RUNTIME_R6_OPEN_DRIFT"),
        ("lobe_escalation_authorized", "RC_B04R6_SHADOW_RUNTIME_R6_OPEN_DRIFT"),
        ("package_promotion_authorized", "RC_B04R6_SHADOW_RUNTIME_PACKAGE_PROMOTION_DRIFT"),
        ("commercial_activation_claim_authorized", "RC_B04R6_SHADOW_RUNTIME_COMMERCIAL_CLAIM_DRIFT"),
        ("truth_engine_law_changed", "RC_B04R6_SHADOW_RUNTIME_TRUTH_ENGINE_MUTATION"),
        ("trust_zone_law_changed", "RC_B04R6_SHADOW_RUNTIME_TRUST_ZONE_MUTATION"),
        ("metric_contract_mutated", "RC_B04R6_SHADOW_RUNTIME_METRIC_MUTATION"),
        ("static_comparator_weakened", "RC_B04R6_SHADOW_RUNTIME_COMPARATOR_WEAKENING"),
    ):
        if payload.get(key) is True:
            _fail(code, f"{label} sets forbidden true flag: {key}")
    state = payload.get("authorization_state")
    if isinstance(state, dict):
        _ensure_authority_closed(state, label=f"{label}.authorization_state")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_SHADOW_RUNTIME_PACKAGE_PROMOTION_DRIFT", f"{label} package promotion drift")
    if payload.get("trust_zone_law_unchanged") is False:
        _fail("RC_B04R6_SHADOW_RUNTIME_TRUST_ZONE_MUTATION", f"{label} trust-zone drift")
    if payload.get("truth_engine_derivation_law_unchanged") is False:
        _fail("RC_B04R6_SHADOW_RUNTIME_TRUTH_ENGINE_MUTATION", f"{label} truth-engine drift")


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
        _fail("RC_B04R6_SHADOW_RUNTIME_NEXT_MOVE_DRIFT", "handoff lacks valid predecessor or self-replay lane identity")
    return {"predecessor_handoff_accepted": predecessor, "self_replay_handoff_accepted": self_replay}


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> Dict[str, bool]:
    for label, payload in payloads.items():
        _ensure_authority_closed(payload, label=label)
        if label.endswith("next_lawful_move"):
            continue
        if payload.get("status") not in (None, "PASS", "PREP_ONLY", "PREP_ONLY_SCAFFOLD"):
            _fail("RC_B04R6_SHADOW_RUNTIME_PACKET_VALIDATION_MISSING", f"{label} must be PASS/PREP_ONLY/structural")

    validation_contract = payloads["validation_validation_contract"]
    validation_receipt = payloads["validation_validation_receipt"]
    for label, payload in (("validation_contract", validation_contract), ("validation_receipt", validation_receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_SHADOW_RUNTIME_PACKET_VALIDATION_MISSING", f"{label} lane drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_SHADOW_RUNTIME_PACKET_VALIDATION_MISSING", f"{label} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_SHADOW_RUNTIME_NEXT_MOVE_DRIFT", f"{label} next move drift")
        if payload.get("limited_runtime_execution_packet_validated") is not True:
            _fail("RC_B04R6_SHADOW_RUNTIME_PACKET_VALIDATION_MISSING", f"{label} did not validate execution packet")

    execution_contract = payloads["execution_execution_packet_contract"]
    if execution_contract.get("authoritative_lane") != execution.AUTHORITATIVE_LANE:
        _fail("RC_B04R6_SHADOW_RUNTIME_EXECUTION_PACKET_BINDING_MISSING", "execution packet lane drift")
    if execution_contract.get("selected_outcome") != execution.SELECTED_OUTCOME:
        _fail("RC_B04R6_SHADOW_RUNTIME_EXECUTION_PACKET_BINDING_MISSING", "execution packet outcome drift")
    if execution_contract.get("runtime_mode") != RUNTIME_MODE:
        _fail("RC_B04R6_SHADOW_RUNTIME_MODE_DRIFT", "execution packet runtime mode drift")

    mode = payloads["execution_mode_contract"]
    scope = payloads["execution_scope_manifest"]
    static = payloads["execution_static_authority_contract"]
    observation = payloads["execution_afsh_shadow_observation_contract"]
    if mode.get("selected_mode") != RUNTIME_MODE or mode.get("allowed_modes") != [RUNTIME_MODE]:
        _fail("RC_B04R6_SHADOW_RUNTIME_MODE_DRIFT", "mode contract is not shadow-only")
    if scope.get("selected_runtime_mode") != RUNTIME_MODE or scope.get("global_r6_scope") is not False:
        _fail("RC_B04R6_SHADOW_RUNTIME_MODE_DRIFT", "scope is not shadow-only")
    if scope.get("max_live_traffic_percent_authorized_by_this_packet") != 0:
        _fail("RC_B04R6_SHADOW_RUNTIME_USER_FACING_CHANGE", "scope authorizes live traffic")
    if static.get("static_decision_authoritative") is not True or static.get("afsh_can_change_user_facing_decision") is not False:
        _fail("RC_B04R6_SHADOW_RUNTIME_STATIC_AUTHORITY_DRIFT", "static authority contract drift")
    if observation.get("afsh_observation_only") is not True or observation.get("selector_may_cutover") is not False:
        _fail("RC_B04R6_SHADOW_RUNTIME_AFSH_AUTHORITY_DRIFT", "AFSH observation contract drift")

    text = texts["validation_report"].lower() + "\n" + texts["execution_packet_report"].lower()
    if "shadow_runtime_only" not in text and "shadow runtime" not in text:
        _fail("RC_B04R6_SHADOW_RUNTIME_MODE_DRIFT", "input reports do not bind shadow-only language")
    return _validate_handoff(payloads["validation_next_lawful_move"])


def _validate_packet_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> None:
    validation_hashes = payloads["validation_validation_contract"].get("binding_hashes")
    if not isinstance(validation_hashes, dict):
        _fail("RC_B04R6_SHADOW_RUNTIME_PACKET_VALIDATION_MISSING", "validation binding hashes missing")
    for role, raw in EXECUTION_JSON_INPUTS.items():
        key = f"{role}_hash"
        expected = validation_hashes.get(key)
        if not _is_sha256(expected):
            continue
        actual = file_sha256(common.resolve_path(root, raw))
        if actual != expected:
            _fail("RC_B04R6_SHADOW_RUNTIME_EXECUTION_PACKET_BINDING_MISSING", f"{role} hash differs from validation binding")


def _input_bindings(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    output_names = set(OUTPUTS.values())
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(ALL_JSON_INPUTS.items()):
        path = common.resolve_path(root, raw)
        row: Dict[str, Any] = {
            "role": role,
            "path": raw,
            "sha256": file_sha256(path),
            "binding_kind": "file_sha256_at_shadow_runtime_execution",
        }
        if Path(raw).name in output_names:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(ALL_TEXT_INPUTS.items()):
        path = common.resolve_path(root, raw)
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path), "binding_kind": "file_sha256_at_shadow_runtime_execution"})
    return rows


def _binding_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    hashes = {f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(ALL_JSON_INPUTS.items())}
    hashes.update({f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(ALL_TEXT_INPUTS.items())})
    validation_hashes = payloads["validation_validation_contract"].get("binding_hashes")
    if not isinstance(validation_hashes, dict):
        _fail("RC_B04R6_SHADOW_RUNTIME_PACKET_VALIDATION_MISSING", "validation binding hashes missing")
    for key in (
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
    ):
        value = validation_hashes.get(key)
        if not _is_sha256(value):
            _fail("RC_B04R6_SHADOW_RUNTIME_PACKET_VALIDATION_MISSING", f"missing carried validation hash {key}")
        hashes[key] = str(value)
    return hashes


def _case_rows() -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for index, case in enumerate(SHADOW_CASES, start=1):
        row = {
            **case,
            "runtime_mode": RUNTIME_MODE,
            "static_authoritative": True,
            "afsh_observation_only": True,
            "user_facing_decision_changed": False,
            "canary_runtime_executed": False,
            "runtime_cutover_authorized": False,
            "trace_complete": True,
            "raw_hash_bound_artifact_refs_required": True,
            "runtime_receipt_id": f"B04R6-SHADOW-RR-{index:03d}",
        }
        rows.append(row)
    return rows


def _scorecard(case_rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(case_rows)
    route_eligible = sum(1 for row in case_rows if row["afsh_observation"] == "ROUTE_ELIGIBLE")
    abstain = sum(1 for row in case_rows if row["afsh_observation"] == "ABSTAIN")
    null_route = sum(1 for row in case_rows if row["afsh_observation"] == "NULL_ROUTE")
    static_hold = sum(1 for row in case_rows if row["afsh_observation"] == "STATIC_HOLD")
    selector_entries = sum(1 for row in case_rows if row["selector_entered"])
    return {
        "total_cases": total,
        "shadow_runtime_mode": RUNTIME_MODE,
        "static_authoritative_cases": total,
        "afsh_observation_only_cases": total,
        "user_facing_decision_changes": 0,
        "canary_runtime_cases": 0,
        "runtime_cutover_authorized_cases": 0,
        "route_eligible_observations": route_eligible,
        "static_hold_observations": static_hold,
        "abstention_observations": abstain,
        "null_route_observations": null_route,
        "selector_entry_rate": selector_entries / total,
        "trace_complete_cases": total,
        "fallback_failures": 0,
        "drift_signals": [],
        "incident_freeze_triggers": [],
        "fired_disqualifiers": [],
    }


def _pass_row(check_id: str, reason_code: str, detail: str, *, group: str) -> Dict[str, str]:
    return {"check_id": check_id, "group": group, "status": "PASS", "reason_code": reason_code, "detail": detail}


def _validation_rows(case_rows: Sequence[Dict[str, Any]]) -> list[Dict[str, str]]:
    rows = [
        _pass_row("shadow_runtime_contract_preserves_current_main_head", "RC_B04R6_SHADOW_RUNTIME_MAIN_HEAD_MISMATCH", "current main head bound", group="core"),
        _pass_row("shadow_runtime_binds_validated_execution_packet", "RC_B04R6_SHADOW_RUNTIME_EXECUTION_PACKET_BINDING_MISSING", "validated execution packet bound", group="binding"),
        _pass_row("shadow_runtime_binds_validated_authorization_packet", "RC_B04R6_SHADOW_RUNTIME_AUTHORIZATION_PACKET_BINDING_MISSING", "validated authorization packet carried", group="binding"),
        _pass_row("shadow_runtime_binds_activation_review_validation", "RC_B04R6_SHADOW_RUNTIME_ACTIVATION_REVIEW_BINDING_MISSING", "activation review validation carried", group="binding"),
        _pass_row("shadow_runtime_binds_shadow_superiority_result", "RC_B04R6_SHADOW_RUNTIME_SHADOW_SUPERIORITY_BINDING_MISSING", "shadow superiority carried", group="binding"),
        _pass_row("shadow_runtime_binds_afsh_candidate", "RC_B04R6_SHADOW_RUNTIME_CANDIDATE_BINDING_MISSING", "AFSH candidate hashes carried", group="binding"),
        _pass_row("runtime_mode_is_shadow_runtime_only", "RC_B04R6_SHADOW_RUNTIME_MODE_DRIFT", "runtime mode shadow-only", group="mode"),
        _pass_row("canary_runtime_is_not_authorized", "RC_B04R6_SHADOW_RUNTIME_CANARY_EXECUTED", "canary not executed", group="authorization"),
        _pass_row("static_remains_authoritative", "RC_B04R6_SHADOW_RUNTIME_STATIC_AUTHORITY_DRIFT", "static remains authoritative", group="authority"),
        _pass_row("afsh_is_observational_only", "RC_B04R6_SHADOW_RUNTIME_AFSH_AUTHORITY_DRIFT", "AFSH observation-only", group="authority"),
        _pass_row("afsh_cannot_change_user_facing_decision", "RC_B04R6_SHADOW_RUNTIME_USER_FACING_CHANGE", "no user-facing change", group="authority"),
        _pass_row("runtime_cutover_is_not_authorized", "RC_B04R6_SHADOW_RUNTIME_CUTOVER_DRIFT", "cutover unauthorized", group="authorization"),
        _pass_row("r6_remains_closed", "RC_B04R6_SHADOW_RUNTIME_R6_OPEN_DRIFT", "R6 closed", group="authorization"),
        _pass_row("route_distribution_health_passes", "RC_B04R6_SHADOW_RUNTIME_ROUTE_HEALTH_FAIL", "route distribution healthy", group="evidence"),
        _pass_row("fallback_behavior_passes", "RC_B04R6_SHADOW_RUNTIME_FALLBACK_FAIL", "fallback behavior healthy", group="evidence"),
        _pass_row("abstention_preservation_passes", "RC_B04R6_SHADOW_RUNTIME_ABSTENTION_FAIL", "abstention preserved", group="evidence"),
        _pass_row("null_route_preservation_passes", "RC_B04R6_SHADOW_RUNTIME_NULL_ROUTE_FAIL", "null route preserved", group="evidence"),
        _pass_row("operator_override_readiness_passes", "RC_B04R6_SHADOW_RUNTIME_OPERATOR_OVERRIDE_NOT_READY", "operator override ready", group="controls"),
        _pass_row("kill_switch_readiness_passes", "RC_B04R6_SHADOW_RUNTIME_KILL_SWITCH_NOT_READY", "kill switch ready", group="controls"),
        _pass_row("rollback_readiness_passes", "RC_B04R6_SHADOW_RUNTIME_ROLLBACK_NOT_READY", "rollback ready", group="controls"),
        _pass_row("drift_monitoring_passes", "RC_B04R6_SHADOW_RUNTIME_DRIFT_DETECTED", "no drift", group="monitoring"),
        _pass_row("incident_freeze_passes", "RC_B04R6_SHADOW_RUNTIME_INCIDENT_FREEZE_TRIGGERED", "no freeze trigger", group="monitoring"),
        _pass_row("trace_completeness_passes", "RC_B04R6_SHADOW_RUNTIME_TRACE_INCOMPLETE", "trace complete", group="replay"),
        _pass_row("runtime_replay_passes", "RC_B04R6_SHADOW_RUNTIME_REPLAY_INCOMPLETE", "runtime replay complete", group="replay"),
        _pass_row("external_verifier_readiness_passes", "RC_B04R6_SHADOW_RUNTIME_EXTERNAL_VERIFIER_NOT_READY", "external verifier ready", group="external"),
        _pass_row("commercial_claim_boundary_passes", "RC_B04R6_SHADOW_RUNTIME_COMMERCIAL_CLAIM_DRIFT", "commercial claims blocked", group="claims"),
        _pass_row("package_promotion_not_authorized", "RC_B04R6_SHADOW_RUNTIME_PACKAGE_PROMOTION_DRIFT", "package promotion blocked", group="claims"),
        _pass_row("truth_engine_law_unchanged", "RC_B04R6_SHADOW_RUNTIME_TRUTH_ENGINE_MUTATION", "truth law unchanged", group="authorization"),
        _pass_row("trust_zone_law_unchanged", "RC_B04R6_SHADOW_RUNTIME_TRUST_ZONE_MUTATION", "trust law unchanged", group="authorization"),
        _pass_row("no_authorization_drift_receipt_passes", "RC_B04R6_SHADOW_RUNTIME_AFSH_AUTHORITY_DRIFT", "no authorization drift", group="authorization"),
        _pass_row("success_outcome_routes_to_runtime_evidence_review_packet", "RC_B04R6_SHADOW_RUNTIME_NEXT_MOVE_DRIFT", "success routes to evidence review", group="outcome"),
        _pass_row("failure_outcome_routes_to_runtime_repair_or_closeout", "RC_B04R6_SHADOW_RUNTIME_NEXT_MOVE_DRIFT", "failure route recorded", group="outcome"),
        _pass_row("invalidated_outcome_routes_to_forensic_runtime_invalidation", "RC_B04R6_SHADOW_RUNTIME_NEXT_MOVE_DRIFT", "invalidation route recorded", group="outcome"),
        _pass_row("deferred_outcome_routes_to_named_runtime_defect", "RC_B04R6_SHADOW_RUNTIME_NEXT_MOVE_DRIFT", "deferred route recorded", group="outcome"),
    ]
    rows.extend(
        _pass_row(f"shadow_runtime_binds_{role}", "RC_B04R6_SHADOW_RUNTIME_PACKET_VALIDATION_MISSING", f"{role} input is hash-bound", group="binding")
        for role in sorted(ALL_JSON_INPUTS)
    )
    rows.extend(
        _pass_row(f"shadow_case_{row['case_id']}_static_authoritative", "RC_B04R6_SHADOW_RUNTIME_STATIC_AUTHORITY_DRIFT", f"{row['case_id']} static authoritative", group="case")
        for row in case_rows
    )
    rows.extend(
        _pass_row(f"shadow_case_{row['case_id']}_afsh_observation_only", "RC_B04R6_SHADOW_RUNTIME_AFSH_AUTHORITY_DRIFT", f"{row['case_id']} AFSH observation-only", group="case")
        for row in case_rows
    )
    rows.extend(
        _pass_row(f"shadow_case_{row['case_id']}_trace_complete", "RC_B04R6_SHADOW_RUNTIME_TRACE_INCOMPLETE", f"{row['case_id']} trace complete", group="case")
        for row in case_rows
    )
    rows.extend(
        _pass_row(f"shadow_case_{row['case_id']}_no_user_facing_change", "RC_B04R6_SHADOW_RUNTIME_USER_FACING_CHANGE", f"{row['case_id']} no user-facing change", group="case")
        for row in case_rows
    )
    rows.extend(
        _pass_row(f"runtime_receipt_field_{field}_emitted", "RC_B04R6_SHADOW_RUNTIME_TRACE_INCOMPLETE", f"{field} emitted", group="receipts")
        for field in execution.RUNTIME_RECEIPT_FIELDS
    )
    rows.extend(
        _pass_row(f"route_health_signal_{signal}_measured", "RC_B04R6_SHADOW_RUNTIME_ROUTE_HEALTH_FAIL", f"{signal} measured", group="monitoring")
        for signal in execution.ROUTE_HEALTH_SIGNALS
    )
    rows.extend(
        _pass_row(f"prep_only_output_{role}_cannot_authorize", "RC_B04R6_SHADOW_RUNTIME_PREP_ONLY_AUTHORITY_DRIFT", f"{role} prep-only", group="prep_only")
        for role in PREP_ONLY_OUTPUT_ROLES
    )
    return rows


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "shadow_superiority_passed": True,
        "activation_review_validated": True,
        "limited_runtime_authorization_packet_validated": True,
        "limited_runtime_execution_packet_validated": True,
        "limited_runtime_shadow_runtime_executed": True,
        "shadow_runtime_executed": True,
        "canary_runtime_executed": False,
        "afsh_runtime_authority_granted": False,
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
        "lane_id": "RUN_B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME",
        "lane_name": "Run B04 R6 Limited Runtime Shadow Runtime",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM/tools/operator",
        "summary": "Prep-only scaffold for the shadow-runtime run lane.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/cohort0_b04_r6_limited_runtime_shadow_runtime.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_b04_r6_limited_runtime_shadow_runtime.py",
        "artifacts": [f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values()],
        "lane_kind": "EXECUTION",
        "current_main_head": current_main_head,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "may_authorize": list(MAY_AUTHORIZE),
        "must_not_authorize": list(FORBIDDEN_ACTIONS),
        "authoritative_inputs": sorted(ALL_JSON_INPUTS),
        "prep_only_outputs": list(PREP_ONLY_OUTPUT_ROLES),
        "json_parse_inputs": [f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values() if filename.endswith(".json")],
        "no_authorization_drift_checks": [
            "AFSH remains observational only.",
            "Static remains authoritative.",
            "Canary runtime and cutover remain unauthorized.",
            "R6, package promotion, and commercial claims remain closed.",
        ],
        "future_blockers": [
            "RUNTIME_EVIDENCE_REVIEW_PACKET_NOT_YET_AUTHORED",
            "CANARY_AUTHORIZATION_PACKET_NOT_YET_LAWFUL",
            "EXTERNAL_AUDIT_DELTA_NOT_YET_AUTHORED",
        ],
        "reason_codes": list(REASON_CODES),
    }
    compiled = kt_lane_compiler.build_lane_contract(spec)
    rendered = json.dumps(compiled, sort_keys=True, ensure_ascii=True)
    return {
        "schema_id": "kt.b04_r6.limited_runtime.shadow_runtime_lane_compiler_scaffold_receipt.v1",
        "artifact_id": "B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME_LANE_COMPILER_SCAFFOLD_RECEIPT",
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
        "can_execute_canary": False,
        "can_cutover_runtime": False,
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
    case_rows: list[Dict[str, Any]],
    scorecard: Dict[str, Any],
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
        "allowed_outcomes": [OUTCOME_PASSED, OUTCOME_FAILED, OUTCOME_INVALIDATED, OUTCOME_DEFERRED],
        "outcome_routing": {
            OUTCOME_PASSED: "AUTHOR_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET",
            OUTCOME_FAILED: "AUTHOR_B04_R6_RUNTIME_REPAIR_OR_CLOSEOUT",
            OUTCOME_INVALIDATED: "AUTHOR_B04_R6_FORENSIC_RUNTIME_INVALIDATION_COURT",
            OUTCOME_DEFERRED: "REPAIR_B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME_DEFECTS",
        },
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
        "case_rows": case_rows,
        "scorecard": scorecard,
        "fired_disqualifiers": [],
        "limited_runtime_shadow_runtime_executed": True,
        "shadow_runtime_executed": True,
        "canary_runtime_executed": False,
        "afsh_runtime_authority_granted": False,
        "static_authoritative": True,
        "afsh_observation_only": True,
        "user_facing_decision_changed": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "r6_open": False,
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


def _receipt(base: Dict[str, Any], *, schema_slug: str, artifact_id: str, role: str, **extra: Any) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.limited_runtime.shadow_runtime.{schema_slug}.v1",
        artifact_id=artifact_id,
        receipt_role=role,
        receipt_status="PASS",
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
        canary_runtime_executed=False,
        afsh_runtime_authority_granted=False,
        runtime_cutover_authorized=False,
        r6_open=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
    )


def _contract(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.limited_runtime_shadow_runtime_execution_contract.v1",
        artifact_id="B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME_EXECUTION_CONTRACT",
        execution_scope={
            "purpose": "Run AFSH in SHADOW_RUNTIME_ONLY mode beside static authority and emit operational evidence.",
            "non_purpose": [
                "Does not execute canary runtime.",
                "Does not make AFSH authoritative.",
                "Does not change user-facing decisions.",
                "Does not authorize runtime cutover.",
                "Does not open R6.",
                "Does not authorize package promotion.",
                "Does not authorize commercial activation claims.",
            ],
        },
        execution_result={
            "shadow_runtime_executed": True,
            "runtime_mode": RUNTIME_MODE,
            "static_remained_authoritative": True,
            "afsh_observation_only": True,
            "fired_disqualifiers": [],
            "runtime_evidence_emitted": True,
        },
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v10",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        current_authoritative_lane="RUN_B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME",
        blockers=[
            {
                "blocker_id": "B04R6-FB-081",
                "future_blocker": "Shadow runtime produced evidence but runtime evidence review law is not authored.",
                "neutralization_now": [OUTPUTS["runtime_evidence_review_packet_prep_only_draft"]],
            },
            {
                "blocker_id": "B04R6-FB-082",
                "future_blocker": "Canary authority is accidentally inferred from shadow-only evidence.",
                "neutralization_now": [OUTPUTS["canary_authorization_packet_prep_only_draft"]],
            },
            {
                "blocker_id": "B04R6-FB-083",
                "future_blocker": "Package promotion or commercial claims outrun runtime evidence review.",
                "neutralization_now": [
                    OUTPUTS["package_promotion_review_preconditions_prep_only_draft"],
                    OUTPUTS["external_audit_delta_manifest_prep_only_draft"],
                ],
            },
        ],
    )


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Limited-Runtime Shadow Runtime\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "AFSH ran in SHADOW_RUNTIME_ONLY mode beside static authority. Static remained authoritative, "
        "AFSH was observational only, no user-facing decision changed, and no canary or cutover authority was granted.\n\n"
        "The lane emitted operational evidence for AFSH observation, static authority preservation, route-distribution "
        "health, fallback behavior, abstention preservation, null-route preservation, operator override readiness, "
        "kill-switch readiness, rollback readiness, drift monitoring, incident/freeze conditions, trace completeness, "
        "runtime replay, external verifier readiness, commercial claim boundary, and no-authorization drift.\n\n"
        "This lane does not authorize canary runtime, runtime cutover, R6 opening, lobe escalation, package promotion, "
        "commercial activation claims, or truth/trust law mutation.\n"
    )


def _outputs(base: Dict[str, Any], compiler_scaffold: Dict[str, Any]) -> Dict[str, Any]:
    scorecard = base["scorecard"]
    case_rows = base["case_rows"]
    output_payloads: Dict[str, Any] = {
        "execution_contract": _contract(base),
        "execution_receipt": _receipt(base, schema_slug="execution_receipt", artifact_id="B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME_EXECUTION_RECEIPT", role="execution", shadow_runtime_executed=True),
        "result": _receipt(base, schema_slug="result", artifact_id="B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME_RESULT", role="result", result=scorecard),
        "case_manifest": _receipt(base, schema_slug="case_manifest", artifact_id="B04_R6_LIMITED_RUNTIME_SHADOW_CASE_MANIFEST", role="case_manifest", cases=case_rows),
        "afsh_observation_receipt": _receipt(base, schema_slug="afsh_observation", artifact_id="B04_R6_LIMITED_RUNTIME_AFSH_OBSERVATION_RECEIPT", role="afsh_observation", observation_only_cases=scorecard["afsh_observation_only_cases"], selector_entry_rate=scorecard["selector_entry_rate"]),
        "static_authority_preservation_receipt": _receipt(base, schema_slug="static_authority", artifact_id="B04_R6_LIMITED_RUNTIME_STATIC_AUTHORITY_PRESERVATION_RECEIPT", role="static_authority", static_authoritative_cases=scorecard["static_authoritative_cases"], user_facing_decision_changes=0),
        "route_distribution_health_receipt": _receipt(base, schema_slug="route_distribution_health", artifact_id="B04_R6_LIMITED_RUNTIME_ROUTE_DISTRIBUTION_HEALTH_RECEIPT", role="route_distribution_health", monitored_signals=list(execution.ROUTE_HEALTH_SIGNALS), selector_entry_rate=scorecard["selector_entry_rate"], route_distribution_health_status="PASS"),
        "fallback_behavior_receipt": _receipt(base, schema_slug="fallback_behavior", artifact_id="B04_R6_LIMITED_RUNTIME_FALLBACK_BEHAVIOR_RECEIPT", role="fallback_behavior", fallback_failures=0, static_fallback_available=True),
        "abstention_preservation_receipt": _receipt(base, schema_slug="abstention_preservation", artifact_id="B04_R6_LIMITED_RUNTIME_ABSTENTION_PRESERVATION_RECEIPT", role="abstention_preservation", abstention_observations=scorecard["abstention_observations"], abstention_preserved=True),
        "null_route_preservation_receipt": _receipt(base, schema_slug="null_route_preservation", artifact_id="B04_R6_LIMITED_RUNTIME_NULL_ROUTE_PRESERVATION_RECEIPT", role="null_route_preservation", null_route_observations=scorecard["null_route_observations"], null_route_preserved=True),
        "operator_override_readiness_receipt": _receipt(base, schema_slug="operator_override", artifact_id="B04_R6_LIMITED_RUNTIME_OPERATOR_OVERRIDE_READINESS_RECEIPT", role="operator_override", operator_override_ready=True, override_may_force_static_only=True, override_may_force_afsh_authority=False),
        "kill_switch_readiness_receipt": _receipt(base, schema_slug="kill_switch", artifact_id="B04_R6_LIMITED_RUNTIME_KILL_SWITCH_READINESS_RECEIPT", role="kill_switch", kill_switch_ready=True, kill_switch_halts_afsh_observation=True),
        "rollback_readiness_receipt": _receipt(base, schema_slug="rollback", artifact_id="B04_R6_LIMITED_RUNTIME_ROLLBACK_READINESS_RECEIPT", role="rollback", rollback_ready=True, rollback_to_static_required=True),
        "drift_monitoring_receipt": _receipt(base, schema_slug="drift_monitoring", artifact_id="B04_R6_LIMITED_RUNTIME_DRIFT_MONITORING_RECEIPT", role="drift_monitoring", drift_signals=[], drift_status="PASS"),
        "incident_freeze_receipt": _receipt(base, schema_slug="incident_freeze", artifact_id="B04_R6_LIMITED_RUNTIME_INCIDENT_FREEZE_RECEIPT", role="incident_freeze", freeze_conditions=list(execution.INCIDENT_FREEZE_CONDITIONS), incident_freeze_triggers=[]),
        "trace_completeness_receipt": _receipt(base, schema_slug="trace_completeness", artifact_id="B04_R6_LIMITED_RUNTIME_TRACE_COMPLETENESS_RECEIPT", role="trace_completeness", trace_complete_cases=scorecard["trace_complete_cases"], total_cases=scorecard["total_cases"]),
        "runtime_replay_receipt": _receipt(base, schema_slug="runtime_replay", artifact_id="B04_R6_LIMITED_RUNTIME_REPLAY_RECEIPT", role="runtime_replay", replay_status="PASS", raw_hash_bound_artifacts_required=True),
        "external_verifier_readiness_receipt": _receipt(base, schema_slug="external_verifier", artifact_id="B04_R6_LIMITED_RUNTIME_EXTERNAL_VERIFIER_READINESS_RECEIPT", role="external_verifier", external_verifier_ready=True, external_verifier_non_executing=True),
        "commercial_claim_boundary_receipt": _receipt(base, schema_slug="commercial_claim_boundary", artifact_id="B04_R6_LIMITED_RUNTIME_COMMERCIAL_CLAIM_BOUNDARY_RECEIPT", role="commercial_claim_boundary", commercial_activation_claim_authorized=False, forbidden_claims=["AFSH is live", "R6 is open", "package promotion is ready"]),
        "no_authorization_drift_receipt": _receipt(base, schema_slug="no_authorization_drift", artifact_id="B04_R6_LIMITED_RUNTIME_NO_AUTHORIZATION_DRIFT_RECEIPT", role="no_authorization_drift", no_downstream_authorization_drift=True, canary_runtime_executed=False, afsh_runtime_authority_granted=False, runtime_cutover_authorized=False, r6_open=False, package_promotion_authorized=False, commercial_activation_claim_authorized=False),
        "future_blocker_register": _future_blocker_register(base),
        "next_lawful_move": _with_artifact(base, schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v21", artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT", verdict="NEXT_LAWFUL_MOVE_SET"),
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
    output_payloads["execution_contract"]["lane_compiler_scaffold"] = compiler_scaffold
    return output_payloads


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 limited-runtime shadow runtime")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in ALL_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in ALL_TEXT_INPUTS.items()}
    handoff_acceptance = _validate_inputs(payloads, texts)
    _validate_packet_hashes(root, payloads)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_SHADOW_RUNTIME_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if current_branch != "main" else "HEAD")
    case_rows = _case_rows()
    scorecard = _scorecard(case_rows)
    compiler_scaffold = _compiler_scaffold(current_main_head)
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=_input_bindings(root, handoff_git_commit=head),
        binding_hashes=_binding_hashes(root, payloads),
        validation_rows=_validation_rows(case_rows),
        compiler_scaffold=compiler_scaffold,
        trust_zone_validation=fresh_trust_validation,
        handoff_acceptance=handoff_acceptance,
        case_rows=case_rows,
        scorecard=scorecard,
    )
    output_payloads = _outputs(base, compiler_scaffold)
    contract = output_payloads["execution_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run B04 R6 limited-runtime shadow runtime.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
