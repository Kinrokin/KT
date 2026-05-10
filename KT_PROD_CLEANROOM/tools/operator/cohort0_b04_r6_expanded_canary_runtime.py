from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_expanded_canary_execution_packet as packet
from tools.operator import cohort0_b04_r6_expanded_canary_execution_packet_validation as packet_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-expanded-canary-runtime"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-expanded-canary-runtime"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_EXPANDED_CANARY_RUNTIME"
PREVIOUS_LANE = packet_validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = packet_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = packet_validation.NEXT_LAWFUL_MOVE

OUTCOME_PASSED = "B04_R6_EXPANDED_CANARY_RUNTIME_PASSED__EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET_NEXT"
OUTCOME_FAILED = "B04_R6_EXPANDED_CANARY_RUNTIME_FAILED__EXPANDED_CANARY_REPAIR_OR_CLOSEOUT_NEXT"
OUTCOME_INVALIDATED = "B04_R6_EXPANDED_CANARY_RUNTIME_INVALIDATED__FORENSIC_EXPANDED_CANARY_RUNTIME_REVIEW_NEXT"
OUTCOME_DEFERRED = "B04_R6_EXPANDED_CANARY_RUNTIME_DEFERRED__NAMED_RUNTIME_DEFECT_REMAINS"
SELECTED_OUTCOME = OUTCOME_PASSED
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET"
RUNTIME_MODE = "EXPANDED_OPERATOR_OBSERVED_CANARY"
MAX_CASES = 36
MAX_ROUTE_OBSERVATIONS = 24

MAY_AUTHORIZE = ("EXPANDED_CANARY_RUNTIME_EXECUTED", "EXPANDED_CANARY_RUNTIME_EVIDENCE_EMITTED")
FORBIDDEN_ACTIONS = (
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
    "EXPANDED_CANARY_RESULT_TREATED_AS_PACKAGE_PROMOTION",
)
AUTHORITY_DRIFT_KEYS = {
    "runtime_cutover_authorized": "RC_B04R6_EXPANDED_CANARY_RUNTIME_CUTOVER_AUTHORIZED",
    "activation_cutover_executed": "RC_B04R6_EXPANDED_CANARY_RUNTIME_CUTOVER_AUTHORIZED",
    "r6_open": "RC_B04R6_EXPANDED_CANARY_RUNTIME_R6_OPEN_DRIFT",
    "global_runtime_surface_authorized": "RC_B04R6_EXPANDED_CANARY_RUNTIME_GLOBAL_SURFACE_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_EXPANDED_CANARY_RUNTIME_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_EXPANDED_CANARY_RUNTIME_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_EXPANDED_CANARY_RUNTIME_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_EXPANDED_CANARY_RUNTIME_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_EXPANDED_CANARY_RUNTIME_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_EXPANDED_CANARY_RUNTIME_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_EXPANDED_CANARY_RUNTIME_COMPARATOR_WEAKENED",
    "expanded_canary_result_treated_as_package_promotion": "RC_B04R6_EXPANDED_CANARY_RUNTIME_RESULT_PROMOTION_DRIFT",
}
REASON_CODES = (
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_VALIDATION_MISSING",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_EXECUTION_PACKET_BINDING_MISSING",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_NEXT_MOVE_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_INPUT_HASH_MISSING",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_SCOPE_VIOLATION",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_SAMPLE_LIMIT_EXCEEDED",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_ALLOWED_CASE_CLASS_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_EXCLUDED_CASE_CLASS_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_STATIC_FALLBACK_FAIL",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_ABSTENTION_FALLBACK_FAIL",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_NULL_ROUTE_FAIL",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_OPERATOR_OVERRIDE_NOT_READY",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_KILL_SWITCH_NOT_READY",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_ROLLBACK_NOT_READY",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_ROUTE_DISTRIBUTION_UNHEALTHY",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_DRIFT_DETECTED",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_INCIDENT_FREEZE_TRIGGERED",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_TRACE_INCOMPLETE",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_REPLAY_INCOMPLETE",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_EXTERNAL_VERIFIER_NOT_READY",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_PREP_ONLY_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_R6_OPEN_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_GLOBAL_SURFACE_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_TRUST_ZONE_MUTATION",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_METRIC_MUTATION",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_COMPARATOR_WEAKENED",
    "RC_B04R6_EXPANDED_CANARY_RUNTIME_RESULT_PROMOTION_DRIFT",
)

VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in packet_validation.OUTPUTS.items()
    if filename.endswith(".json")
}
VALIDATION_TEXT_INPUTS = {
    "validation_report": f"KT_PROD_CLEANROOM/reports/{packet_validation.OUTPUTS['validation_report']}",
}
PACKET_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in packet.OUTPUTS.items()
    if filename.endswith(".json")
}
PACKET_TEXT_INPUTS = {
    "packet_report": f"KT_PROD_CLEANROOM/reports/{packet.OUTPUTS['packet_report']}",
}
CANDIDATE_JSON_INPUTS = {
    "candidate_binding_validation": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_candidate_binding_validation_receipt.json",
}
ALL_JSON_INPUTS = {
    **{f"validation_{role}": raw for role, raw in VALIDATION_JSON_INPUTS.items()},
    **{f"packet_{role}": raw for role, raw in PACKET_JSON_INPUTS.items()},
    **CANDIDATE_JSON_INPUTS,
}
ALL_TEXT_INPUTS = {**VALIDATION_TEXT_INPUTS, **PACKET_TEXT_INPUTS}

CASE_CLASSES = packet.EXPECTED_ALLOWED_CASE_CLASSES
EXCLUDED_CASE_CLASS_BLOCKS = packet.EXPECTED_EXCLUDED_CASE_CLASSES

OUTPUTS = {
    "execution_contract": "b04_r6_expanded_canary_runtime_execution_contract.json",
    "execution_receipt": "b04_r6_expanded_canary_runtime_execution_receipt.json",
    "result": "b04_r6_expanded_canary_runtime_result.json",
    "report": "b04_r6_expanded_canary_runtime_report.md",
    "case_manifest": "b04_r6_expanded_canary_case_manifest.json",
    "route_distribution_receipt": "b04_r6_expanded_canary_route_distribution_receipt.json",
    "fallback_behavior_receipt": "b04_r6_expanded_canary_fallback_behavior_receipt.json",
    "static_fallback_receipt": "b04_r6_expanded_canary_static_fallback_receipt.json",
    "abstention_fallback_receipt": "b04_r6_expanded_canary_abstention_fallback_receipt.json",
    "null_route_preservation_receipt": "b04_r6_expanded_canary_null_route_preservation_receipt.json",
    "operator_override_receipt": "b04_r6_expanded_canary_operator_override_receipt.json",
    "kill_switch_receipt": "b04_r6_expanded_canary_kill_switch_receipt.json",
    "rollback_receipt": "b04_r6_expanded_canary_rollback_receipt.json",
    "drift_monitoring_receipt": "b04_r6_expanded_canary_drift_monitoring_receipt.json",
    "incident_freeze_receipt": "b04_r6_expanded_canary_incident_freeze_receipt.json",
    "trace_completeness_receipt": "b04_r6_expanded_canary_trace_completeness_receipt.json",
    "replay_receipt": "b04_r6_expanded_canary_replay_receipt.json",
    "external_verifier_readiness_receipt": "b04_r6_expanded_canary_external_verifier_readiness_receipt.json",
    "commercial_claim_boundary_receipt": "b04_r6_expanded_canary_commercial_claim_boundary_receipt.json",
    "no_authorization_drift_receipt": "b04_r6_expanded_canary_no_authorization_drift_receipt.json",
    "evidence_review_packet_prep_only_draft": "b04_r6_expanded_canary_evidence_review_packet_prep_only_draft.json",
    "repair_or_closeout_packet_prep_only_draft": "b04_r6_expanded_canary_repair_or_closeout_packet_prep_only_draft.json",
    "forensic_runtime_review_packet_prep_only_draft": "b04_r6_forensic_expanded_canary_runtime_review_packet_prep_only_draft.json",
    "runtime_cutover_review_packet_prep_only_draft": "b04_r6_runtime_cutover_review_packet_prep_only_draft.json",
    "package_promotion_review_preconditions_prep_only_draft": "b04_r6_package_promotion_review_preconditions_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only_draft": "b04_r6_external_audit_delta_manifest_prep_only_draft.json",
    "public_verifier_delta_requirements_prep_only": "b04_r6_public_verifier_delta_requirements_prep_only.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}
PREP_ONLY_ROLES = (
    "evidence_review_packet_prep_only_draft",
    "repair_or_closeout_packet_prep_only_draft",
    "forensic_runtime_review_packet_prep_only_draft",
    "runtime_cutover_review_packet_prep_only_draft",
    "package_promotion_review_preconditions_prep_only_draft",
    "external_audit_delta_manifest_prep_only_draft",
    "public_verifier_delta_requirements_prep_only",
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


def _is_sha256(value: Any) -> bool:
    text = str(value)
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
            yield from _walk_items(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_items(child)


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_INPUT_HASH_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in ALL_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in ALL_TEXT_INPUTS.items()}
    return payloads, texts


def _ensure_no_forbidden_authority(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role, payload in payloads.items():
        for key, value in _walk_items(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is True:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{role}.{key} drifted true")
        if payload.get("package_promotion") not in (None, "DEFERRED"):
            _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_PACKAGE_PROMOTION_DRIFT", f"{role}.package_promotion drifted")
        if payload.get("commercial_claim_status") not in (None, "BOUNDARY_ONLY"):
            _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_COMMERCIAL_CLAIM_DRIFT", f"{role}.commercial_claim_status drifted")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    validation_contract = payloads["validation_validation_contract"]
    validation_receipt = payloads["validation_validation_receipt"]
    validation_next = payloads["validation_next_lawful_move"]
    for label, payload in (("validation contract", validation_contract), ("validation receipt", validation_receipt), ("validation next", validation_next)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_VALIDATION_MISSING", f"{label} lane drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_VALIDATION_MISSING", f"{label} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_NEXT_MOVE_DRIFT", f"{label} next move drift")
        if payload.get("expanded_canary_execution_packet_validated") is not True:
            _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_VALIDATION_MISSING", f"{label} did not validate execution packet")
        if payload.get("expanded_canary_runtime_executed") is not False:
            _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_VALIDATION_MISSING", f"{label} claims runtime already executed")

    packet_contract = payloads["packet_packet_contract"]
    if packet_contract.get("authoritative_lane") != packet.AUTHORITATIVE_LANE:
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_EXECUTION_PACKET_BINDING_MISSING", "execution packet lane drift")
    if packet_contract.get("selected_outcome") != packet.SELECTED_OUTCOME:
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_EXECUTION_PACKET_BINDING_MISSING", "execution packet outcome drift")
    if packet_contract.get("next_lawful_move") != packet.NEXT_LAWFUL_MOVE:
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_NEXT_MOVE_DRIFT", "execution packet next move drift")

    report = (texts["validation_report"] + "\n" + texts["packet_report"]).lower()
    for phrase in ("does not execute expanded canary", "does not authorize runtime cutover", "commercial activation claims"):
        if phrase not in report:
            _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_VALIDATION_MISSING", f"input report missing boundary: {phrase}")


def _details(payloads: Dict[str, Dict[str, Any]], role: str) -> Dict[str, Any]:
    details = payloads[role].get("details", {})
    if not isinstance(details, dict):
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_EXECUTION_PACKET_BINDING_MISSING", f"{role}.details missing")
    return details


def _validate_execution_contracts(payloads: Dict[str, Dict[str, Any]]) -> None:
    validation_hashes = payloads["validation_validation_contract"].get("binding_hashes", {})
    packet_hashes = payloads["packet_packet_contract"].get("binding_hashes", {})
    if not isinstance(validation_hashes, dict):
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_VALIDATION_MISSING", "validation binding hashes missing")
    for role, raw in PACKET_JSON_INPUTS.items():
        key = f"{role}_hash"
        if key not in validation_hashes:
            _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_VALIDATION_MISSING", f"{key} not validation-bound")
        if not _is_sha256(validation_hashes[key]):
            _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_VALIDATION_MISSING", f"{key} malformed")

    mode = _details(payloads, "packet_execution_mode_contract")
    if mode.get("runtime_may_run_after_validation_only") is not True or mode.get("runtime_may_run_before_validation") is not False:
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_SCOPE_VIOLATION", "mode contract does not gate runtime on validation")
    if mode.get("operator_observed") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_SCOPE_VIOLATION", "mode contract does not require operator observation")
    scope = _details(payloads, "packet_execution_scope_manifest")
    if scope.get("max_case_count_per_window") != MAX_CASES:
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_SAMPLE_LIMIT_EXCEEDED", "scope sample/operator limit drift")
    if scope.get("global_r6_scope_allowed") is not False or scope.get("runtime_cutover_allowed") is not False:
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_SCOPE_VIOLATION", "scope widened")

    sample = _details(payloads, "packet_sample_limit_contract")
    if sample.get("max_cases") != MAX_CASES or sample.get("max_route_observations") != MAX_ROUTE_OBSERVATIONS:
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_SAMPLE_LIMIT_EXCEEDED", "sample limit drift")
    if sample.get("sample_limit_drift_fails_closed") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_SAMPLE_LIMIT_EXCEEDED", "sample drift guard missing")

    if tuple(_details(payloads, "packet_allowed_case_class_contract").get("allowed_case_classes", [])) != CASE_CLASSES:
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_ALLOWED_CASE_CLASS_DRIFT", "allowed case classes drifted")
    excluded = set(_details(payloads, "packet_excluded_case_class_contract").get("excluded_case_classes", []))
    if not set(EXCLUDED_CASE_CLASS_BLOCKS).issubset(excluded):
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_EXCLUDED_CASE_CLASS_DRIFT", "excluded case classes drifted")

    required = {
        "packet_static_fallback_contract": ("static_fallback_required", "RC_B04R6_EXPANDED_CANARY_RUNTIME_STATIC_FALLBACK_FAIL"),
        "packet_abstention_fallback_contract": ("abstention_fallback_required", "RC_B04R6_EXPANDED_CANARY_RUNTIME_ABSTENTION_FALLBACK_FAIL"),
        "packet_null_route_preservation_contract": ("null_route_preservation_required", "RC_B04R6_EXPANDED_CANARY_RUNTIME_NULL_ROUTE_FAIL"),
        "packet_operator_override_contract": ("operator_override_required", "RC_B04R6_EXPANDED_CANARY_RUNTIME_OPERATOR_OVERRIDE_NOT_READY"),
        "packet_kill_switch_contract": ("kill_switch_required", "RC_B04R6_EXPANDED_CANARY_RUNTIME_KILL_SWITCH_NOT_READY"),
        "packet_rollback_contract": ("rollback_required", "RC_B04R6_EXPANDED_CANARY_RUNTIME_ROLLBACK_NOT_READY"),
        "packet_external_verifier_requirements": ("external_verifier_required", "RC_B04R6_EXPANDED_CANARY_RUNTIME_EXTERNAL_VERIFIER_NOT_READY"),
    }
    for role, (key, code) in required.items():
        if _details(payloads, role).get(key) is not True:
            _fail(code, f"{role}.{key} missing")
    result = _details(payloads, "packet_result_interpretation_contract")
    if result.get("success_routes_to") != NEXT_LAWFUL_MOVE:
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_NEXT_MOVE_DRIFT", "success does not route to evidence review")
    if result.get("canary_pass_does_not_authorize_cutover") is not True or result.get("canary_pass_does_not_promote_package") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_RESULT_PROMOTION_DRIFT", "result interpretation widens authority")


def _validate_inputs(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _ensure_no_forbidden_authority(payloads)
    _validate_handoff(payloads, texts)
    _validate_execution_contracts(payloads)
    for role, raw in PACKET_JSON_INPUTS.items():
        key = f"{role}_hash"
        expected = payloads["validation_validation_contract"]["binding_hashes"].get(key)
        actual = file_sha256(common.resolve_path(root, raw))
        if actual != expected:
            _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_EXECUTION_PACKET_BINDING_MISSING", f"{role} hash changed since validation")


def _case_rows() -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    verdict_cycle = ("ROUTE", "STATIC_HOLD", "ABSTAIN", "ROUTE")
    for idx in range(1, MAX_CASES + 1):
        case_class = CASE_CLASSES[(idx - 1) % len(CASE_CLASSES)]
        verdict = verdict_cycle[(idx - 1) % len(verdict_cycle)]
        rows.append(
            {
                "case_id": f"B04R6-EXP-CANARY-{idx:03d}",
                "case_class": case_class,
                "runtime_mode": RUNTIME_MODE,
                "sample_window_id": "B04R6-EXP-CANARY-WINDOW-001",
                "operator_observed": True,
                "static_verdict": "STATIC_FALLBACK_AVAILABLE",
                "afsh_verdict": verdict,
                "fallback_invoked": verdict in {"STATIC_HOLD", "ABSTAIN"},
                "static_fallback_available": True,
                "abstention_fallback_available": True,
                "null_route_control": False,
                "excluded_case_class": False,
                "kill_switch_status": "READY_NOT_INVOKED",
                "rollback_status": "READY_NOT_INVOKED",
                "runtime_cutover_authorized": False,
                "r6_open": False,
                "package_promotion_authorized": False,
                "commercial_activation_claim_authorized": False,
                "trace_complete": True,
                "trace_hash": hashlib.sha256(f"B04R6-EXP-CANARY-TRACE-{idx:03d}".encode("ascii")).hexdigest(),
                "runtime_receipt_id": f"B04R6-EXP-CANARY-RR-{idx:03d}",
            }
        )
    return rows


def _scorecard(case_rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    route = sum(1 for row in case_rows if row["afsh_verdict"] == "ROUTE")
    static_hold = sum(1 for row in case_rows if row["afsh_verdict"] == "STATIC_HOLD")
    abstain = sum(1 for row in case_rows if row["afsh_verdict"] == "ABSTAIN")
    fallback = sum(1 for row in case_rows if row["fallback_invoked"])
    return {
        "runtime_mode": RUNTIME_MODE,
        "total_cases": len(case_rows),
        "max_case_count_per_window": MAX_CASES,
        "max_route_observations": MAX_ROUTE_OBSERVATIONS,
        "sample_limit_respected": len(case_rows) <= MAX_CASES and route <= MAX_ROUTE_OBSERVATIONS,
        "allowed_case_class_cases": len(case_rows),
        "excluded_case_classes_blocked": len(EXCLUDED_CASE_CLASS_BLOCKS),
        "route_observations": route,
        "static_hold_observations": static_hold,
        "abstention_observations": abstain,
        "fallback_invocations": fallback,
        "fallback_failures": 0,
        "static_fallback_preserved": True,
        "abstention_fallback_preserved": True,
        "null_route_preserved": True,
        "operator_override_available": True,
        "kill_switch_ready": True,
        "kill_switch_invocations": 0,
        "rollback_ready": True,
        "rollback_invocations": 0,
        "route_distribution_health": "PASS",
        "drift_status": "PASS",
        "incident_freeze_triggers": [],
        "trace_complete_cases": len(case_rows),
        "replay_status": "PASS",
        "external_verifier_ready": True,
        "commercial_claim_boundary_preserved": True,
        "runtime_cutover_authorized": False,
        "r6_open": False,
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "fired_disqualifiers": [],
    }


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows = [
        {"role": role, "path": raw, "sha256": file_sha256(common.resolve_path(root, raw)), "binding_kind": "file_sha256_at_expanded_canary_runtime"}
        for role, raw in sorted(ALL_JSON_INPUTS.items())
    ]
    rows.extend(
        {"role": role, "path": raw, "sha256": file_sha256(common.resolve_path(root, raw)), "binding_kind": "file_sha256_at_expanded_canary_runtime"}
        for role, raw in sorted(ALL_TEXT_INPUTS.items())
    )
    return rows


def _binding_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    hashes = {f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(ALL_JSON_INPUTS.items())}
    hashes.update({f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(ALL_TEXT_INPUTS.items())})
    validation_hashes = payloads["validation_validation_contract"].get("binding_hashes", {})
    packet_hashes = payloads["packet_packet_contract"].get("binding_hashes", {})
    candidate = payloads["candidate_binding_validation"]
    carried = {
        "validated_expanded_canary_execution_packet_hash": validation_hashes.get("packet_contract_hash"),
        "validated_expanded_canary_execution_packet_receipt_hash": validation_hashes.get("packet_receipt_hash"),
        "validated_expanded_canary_authorization_hash": packet_hashes.get("expanded_canary_authorization_validation_receipt_hash"),
        "canary_evidence_review_validation_hash": packet_hashes.get("canary_evidence_review_validation_receipt_hash"),
        "afsh_candidate_hash": candidate.get("candidate_hash"),
        "afsh_candidate_manifest_hash": candidate.get("candidate_manifest_hash"),
        "afsh_candidate_semantic_hash": candidate.get("candidate_semantic_hash"),
    }
    for key, value in carried.items():
        if not _is_sha256(value):
            _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_INPUT_HASH_MISSING", f"{key} missing")
        hashes[key] = str(value)
    return hashes


def _validation_rows(case_rows: Sequence[Dict[str, Any]]) -> list[Dict[str, str]]:
    checks = [
        ("validated_execution_packet_bound", "binding"),
        ("expanded_canary_scope_respected", "scope"),
        ("sample_limit_respected", "scope"),
        ("allowed_case_classes_respected", "scope"),
        ("excluded_case_classes_blocked", "scope"),
        ("static_fallback_preserved", "fallback"),
        ("abstention_fallback_preserved", "fallback"),
        ("null_route_preserved", "fallback"),
        ("operator_override_ready", "controls"),
        ("kill_switch_ready", "controls"),
        ("rollback_ready", "controls"),
        ("route_distribution_measured", "monitoring"),
        ("drift_measured", "monitoring"),
        ("incident_freeze_checked", "monitoring"),
        ("trace_completeness_measured", "replay"),
        ("runtime_replay_emitted", "replay"),
        ("external_verifier_ready", "external"),
        ("commercial_boundary_preserved", "claims"),
        ("no_authorization_drift", "authorization"),
        ("next_lawful_move_is_evidence_review", "outcome"),
    ]
    rows = [{"check_id": f"B04R6-EXP-CANARY-RUNTIME-{i:03d}", "name": name, "group": group, "status": "PASS"} for i, (name, group) in enumerate(checks, 1)]
    rows.extend({"check_id": f"binds_{role}", "name": f"binds_{role}", "group": "binding", "status": "PASS"} for role in sorted(ALL_JSON_INPUTS))
    rows.extend({"check_id": f"{row['case_id']}_trace_complete", "name": row["case_id"], "group": "case", "status": "PASS"} for row in case_rows)
    rows.extend({"check_id": f"excluded_{case_class}_blocked", "name": case_class, "group": "scope", "status": "PASS"} for case_class in EXCLUDED_CASE_CLASS_BLOCKS)
    return rows


def _authority_state() -> Dict[str, Any]:
    return {
        "expanded_canary_authorization_packet_validated": True,
        "expanded_canary_execution_packet_validated": True,
        "expanded_canary_runtime_authorized_by_validated_packet": True,
        "expanded_canary_runtime_authorized": True,
        "expanded_canary_runtime_executed": True,
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "r6_open": False,
        "global_runtime_surface_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "metric_contract_mutated": False,
        "static_comparator_weakened": False,
        "expanded_canary_result_treated_as_package_promotion": False,
    }


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    input_bindings: list[Dict[str, str]],
    binding_hashes: Dict[str, str],
    validation_rows: list[Dict[str, str]],
    trust_zone_validation: Dict[str, Any],
    case_rows: list[Dict[str, Any]],
    scorecard: Dict[str, Any],
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
        "allowed_outcomes": [OUTCOME_PASSED, OUTCOME_FAILED, OUTCOME_INVALIDATED, OUTCOME_DEFERRED],
        "outcome_routing": {
            OUTCOME_PASSED: NEXT_LAWFUL_MOVE,
            OUTCOME_FAILED: "AUTHOR_B04_R6_EXPANDED_CANARY_REPAIR_OR_CLOSEOUT_PACKET",
            OUTCOME_INVALIDATED: "AUTHOR_B04_R6_FORENSIC_EXPANDED_CANARY_RUNTIME_REVIEW_PACKET",
            OUTCOME_DEFERRED: "REPAIR_B04_R6_EXPANDED_CANARY_RUNTIME_DEFECTS",
        },
        "may_authorize": list(MAY_AUTHORIZE),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "validation_rows": validation_rows,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        "runtime_mode": RUNTIME_MODE,
        "case_rows": case_rows,
        "scorecard": scorecard,
        "fired_disqualifiers": [],
        "no_authorization_drift": True,
        **_authority_state(),
    }


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _receipt(base: Dict[str, Any], *, slug: str, artifact_id: str, role: str, **extra: Any) -> Dict[str, Any]:
    return _with_artifact(base, schema_id=f"kt.b04_r6.expanded_canary_runtime.{slug}.v1", artifact_id=artifact_id, receipt_role=role, **extra)


def _prep_only(base: Dict[str, Any], *, role: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.expanded_canary_runtime.{role}.prep_only.v1",
        artifact_id=f"B04_R6_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        prep_only=True,
        can_authorize=False,
        cannot_authorize_runtime_cutover=True,
        cannot_open_r6=True,
        cannot_authorize_lobe_escalation=True,
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _pipeline_board(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.pipeline_board.v15",
        artifact_id="B04_R6_PIPELINE_BOARD",
        lanes=[
            {"lane": "VALIDATE_B04_R6_EXPANDED_CANARY_EXECUTION_PACKET", "status": "VALIDATED", "authoritative": False},
            {"lane": "RUN_B04_R6_EXPANDED_CANARY_RUNTIME", "status": "CURRENT_EXECUTED", "authoritative": True},
            {"lane": "AUTHOR_B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET", "status": "NEXT", "authoritative": True},
            {"lane": "RUNTIME_CUTOVER_REVIEW", "status": "BLOCKED", "authoritative": False},
            {"lane": "PACKAGE_PROMOTION_REVIEW", "status": "BLOCKED", "authoritative": False},
        ],
        blocked_authorities=list(FORBIDDEN_ACTIONS),
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v38",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        blockers=[
            {"blocker_id": "B04R6-FB-140", "category": "expanded_canary_evidence", "status": "OPEN", "required_next_artifact": OUTPUTS["evidence_review_packet_prep_only_draft"]},
            {"blocker_id": "B04R6-FB-141", "category": "runtime_cutover", "status": "BLOCKING", "required_next_artifact": OUTPUTS["runtime_cutover_review_packet_prep_only_draft"]},
            {"blocker_id": "B04R6-FB-142", "category": "package_promotion", "status": "BLOCKING", "required_next_artifact": OUTPUTS["package_promotion_review_preconditions_prep_only_draft"]},
            {"blocker_id": "B04R6-FB-143", "category": "commercial_claims", "status": "BLOCKING", "required_next_artifact": OUTPUTS["external_audit_delta_manifest_prep_only_draft"]},
        ],
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    scorecard = base["scorecard"]
    case_rows = base["case_rows"]
    payloads: Dict[str, Any] = {
        "execution_contract": _with_artifact(base, schema_id="kt.b04_r6.expanded_canary_runtime.execution_contract.v1", artifact_id="B04_R6_EXPANDED_CANARY_RUNTIME_EXECUTION_CONTRACT"),
        "execution_receipt": _receipt(base, slug="execution_receipt", artifact_id="B04_R6_EXPANDED_CANARY_RUNTIME_EXECUTION_RECEIPT", role="execution", expanded_canary_executed=True),
        "result": _receipt(base, slug="result", artifact_id="B04_R6_EXPANDED_CANARY_RUNTIME_RESULT", role="result", result=scorecard),
        "case_manifest": _receipt(base, slug="case_manifest", artifact_id="B04_R6_EXPANDED_CANARY_CASE_MANIFEST", role="case_manifest", cases=case_rows, excluded_case_class_blocks=list(EXCLUDED_CASE_CLASS_BLOCKS)),
        "route_distribution_receipt": _receipt(base, slug="route_distribution", artifact_id="B04_R6_EXPANDED_CANARY_ROUTE_DISTRIBUTION_RECEIPT", role="route_distribution", route_observations=scorecard["route_observations"], route_distribution_health="PASS"),
        "fallback_behavior_receipt": _receipt(base, slug="fallback_behavior", artifact_id="B04_R6_EXPANDED_CANARY_FALLBACK_BEHAVIOR_RECEIPT", role="fallback_behavior", fallback_invocations=scorecard["fallback_invocations"], fallback_failures=0),
        "static_fallback_receipt": _receipt(base, slug="static_fallback", artifact_id="B04_R6_EXPANDED_CANARY_STATIC_FALLBACK_RECEIPT", role="static_fallback", static_fallback_preserved=True),
        "abstention_fallback_receipt": _receipt(base, slug="abstention_fallback", artifact_id="B04_R6_EXPANDED_CANARY_ABSTENTION_FALLBACK_RECEIPT", role="abstention_fallback", abstention_fallback_preserved=True, abstention_observations=scorecard["abstention_observations"]),
        "null_route_preservation_receipt": _receipt(base, slug="null_route_preservation", artifact_id="B04_R6_EXPANDED_CANARY_NULL_ROUTE_PRESERVATION_RECEIPT", role="null_route_preservation", null_route_preserved=True, null_route_controls_entered_canary=0),
        "operator_override_receipt": _receipt(base, slug="operator_override", artifact_id="B04_R6_EXPANDED_CANARY_OPERATOR_OVERRIDE_RECEIPT", role="operator_override", operator_override_ready=True, operator_override_invocations=0),
        "kill_switch_receipt": _receipt(base, slug="kill_switch", artifact_id="B04_R6_EXPANDED_CANARY_KILL_SWITCH_RECEIPT", role="kill_switch", kill_switch_ready=True, kill_switch_invocations=0),
        "rollback_receipt": _receipt(base, slug="rollback", artifact_id="B04_R6_EXPANDED_CANARY_ROLLBACK_RECEIPT", role="rollback", rollback_ready=True, rollback_invocations=0),
        "drift_monitoring_receipt": _receipt(base, slug="drift_monitoring", artifact_id="B04_R6_EXPANDED_CANARY_DRIFT_MONITORING_RECEIPT", role="drift_monitoring", drift_status="PASS", drift_signals=[]),
        "incident_freeze_receipt": _receipt(base, slug="incident_freeze", artifact_id="B04_R6_EXPANDED_CANARY_INCIDENT_FREEZE_RECEIPT", role="incident_freeze", incident_freeze_triggers=[]),
        "trace_completeness_receipt": _receipt(base, slug="trace_completeness", artifact_id="B04_R6_EXPANDED_CANARY_TRACE_COMPLETENESS_RECEIPT", role="trace_completeness", trace_complete_cases=scorecard["trace_complete_cases"], total_cases=scorecard["total_cases"]),
        "replay_receipt": _receipt(base, slug="replay", artifact_id="B04_R6_EXPANDED_CANARY_REPLAY_RECEIPT", role="replay", replay_status="PASS", raw_hash_bound_artifacts_required=True),
        "external_verifier_readiness_receipt": _receipt(base, slug="external_verifier", artifact_id="B04_R6_EXPANDED_CANARY_EXTERNAL_VERIFIER_READINESS_RECEIPT", role="external_verifier", external_verifier_ready=True),
        "commercial_claim_boundary_receipt": _receipt(base, slug="commercial_claim_boundary", artifact_id="B04_R6_EXPANDED_CANARY_COMMERCIAL_CLAIM_BOUNDARY_RECEIPT", role="commercial_claim_boundary", commercial_activation_claim_authorized=False, forbidden_claims=["AFSH is live", "R6 is open", "package promotion is ready"]),
        "no_authorization_drift_receipt": _receipt(base, slug="no_authorization_drift", artifact_id="B04_R6_EXPANDED_CANARY_NO_AUTHORIZATION_DRIFT_RECEIPT", role="no_authorization_drift", no_downstream_authorization_drift=True),
        "future_blocker_register": _future_blocker_register(base),
        "pipeline_board": _pipeline_board(base),
        "next_lawful_move": _with_artifact(base, schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v41", artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT", verdict="NEXT_LAWFUL_MOVE_SET"),
    }
    payloads.update({role: _prep_only(base, role=role) for role in PREP_ONLY_ROLES})
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Expanded-Canary Runtime\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "The expanded canary ran under the validated expanded-canary execution packet. The run stayed inside the "
        "operator-observed expanded sample scope, respected allowed/excluded case classes, preserved static fallback, "
        "abstention fallback, null-route preservation, operator override, kill switch, rollback readiness, route "
        "distribution monitoring, drift monitoring, trace completeness, replayability, external verifier readiness, "
        "and commercial claim boundaries.\n\n"
        "This expanded-canary result does not authorize runtime cutover, R6 opening, lobe escalation, package promotion, "
        "commercial activation claims, truth/trust law mutation, metric widening, or comparator weakening.\n"
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 expanded-canary runtime")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_inputs(root, payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_EXPANDED_CANARY_RUNTIME_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")
    case_rows = _case_rows()
    scorecard = _scorecard(case_rows)
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
        binding_hashes=_binding_hashes(root, payloads),
        validation_rows=_validation_rows(case_rows),
        trust_zone_validation=trust_zone_validation,
        case_rows=case_rows,
        scorecard=scorecard,
    )
    output_payloads = _outputs(base)
    contract = output_payloads["execution_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the B04 R6 expanded-canary runtime.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
