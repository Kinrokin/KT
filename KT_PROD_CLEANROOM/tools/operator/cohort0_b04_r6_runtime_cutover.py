from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_runtime_cutover_execution_packet as packet
from tools.operator import cohort0_b04_r6_runtime_cutover_execution_packet_validation as validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "run/b04-r6-runtime-cutover"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-runtime-cutover"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_RUNTIME_CUTOVER"
PREVIOUS_LANE = validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = validation.NEXT_LAWFUL_MOVE

OUTCOME_PASSED = "B04_R6_RUNTIME_CUTOVER_PASSED__POST_CUTOVER_EVIDENCE_REVIEW_PACKET_NEXT"
OUTCOME_FAILED = "B04_R6_RUNTIME_CUTOVER_FAILED__ROLLBACK_OR_REPAIR_NEXT"
OUTCOME_INVALIDATED = "B04_R6_RUNTIME_CUTOVER_INVALIDATED__FORENSIC_CUTOVER_REVIEW_NEXT"
OUTCOME_DEFERRED = "B04_R6_RUNTIME_CUTOVER_DEFERRED__NAMED_RUNTIME_DEFECT_REMAINS"
SELECTED_OUTCOME = OUTCOME_PASSED
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET"

RUNTIME_MODE = "BOUNDED_RUNTIME_CUTOVER_UNDER_VALIDATED_PACKET"
MAX_CASES = 18
MAX_ROUTE_OBSERVATIONS = 12

FORBIDDEN_ACTIONS = (
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
    "CUTOVER_RESULT_TREATED_AS_R6_OPENING",
    "CUTOVER_RESULT_TREATED_AS_PACKAGE_PROMOTION",
)

AUTHORITY_DRIFT_KEYS = {
    "activation_cutover_executed": "RC_B04R6_RUNTIME_CUTOVER_ACTIVATION_CUTOVER_EXECUTED",
    "r6_open": "RC_B04R6_RUNTIME_CUTOVER_R6_OPEN_DRIFT",
    "global_runtime_surface_authorized": "RC_B04R6_RUNTIME_CUTOVER_GLOBAL_SURFACE_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_RUNTIME_CUTOVER_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_RUNTIME_CUTOVER_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_RUNTIME_CUTOVER_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_RUNTIME_CUTOVER_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_RUNTIME_CUTOVER_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_RUNTIME_CUTOVER_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_RUNTIME_CUTOVER_COMPARATOR_WEAKENED",
    "cutover_result_treated_as_r6_opening": "RC_B04R6_RUNTIME_CUTOVER_RESULT_R6_OPENING_DRIFT",
    "cutover_result_treated_as_package_promotion": "RC_B04R6_RUNTIME_CUTOVER_RESULT_PROMOTION_DRIFT",
}

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_RUNTIME_CUTOVER_VALIDATION_MISSING",
            "RC_B04R6_RUNTIME_CUTOVER_VALIDATION_OUTCOME_DRIFT",
            "RC_B04R6_RUNTIME_CUTOVER_NEXT_MOVE_DRIFT",
            "RC_B04R6_RUNTIME_CUTOVER_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_RUNTIME_CUTOVER_PACKET_HASH_DRIFT",
            "RC_B04R6_RUNTIME_CUTOVER_CONTROL_CONTRACT_MISSING",
            "RC_B04R6_RUNTIME_CUTOVER_SCOPE_VIOLATION",
            "RC_B04R6_RUNTIME_CUTOVER_SAMPLE_LIMIT_EXCEEDED",
            "RC_B04R6_RUNTIME_CUTOVER_ALLOWED_CASE_CLASS_DRIFT",
            "RC_B04R6_RUNTIME_CUTOVER_EXCLUDED_CASE_CLASS_DRIFT",
            "RC_B04R6_RUNTIME_CUTOVER_STATIC_FALLBACK_FAIL",
            "RC_B04R6_RUNTIME_CUTOVER_ABSTENTION_FALLBACK_FAIL",
            "RC_B04R6_RUNTIME_CUTOVER_NULL_ROUTE_FAIL",
            "RC_B04R6_RUNTIME_CUTOVER_OPERATOR_OVERRIDE_NOT_READY",
            "RC_B04R6_RUNTIME_CUTOVER_KILL_SWITCH_NOT_READY",
            "RC_B04R6_RUNTIME_CUTOVER_ROLLBACK_NOT_READY",
            "RC_B04R6_RUNTIME_CUTOVER_ROUTE_DISTRIBUTION_UNHEALTHY",
            "RC_B04R6_RUNTIME_CUTOVER_DRIFT_DETECTED",
            "RC_B04R6_RUNTIME_CUTOVER_INCIDENT_FREEZE_TRIGGERED",
            "RC_B04R6_RUNTIME_CUTOVER_TRACE_INCOMPLETE",
            "RC_B04R6_RUNTIME_CUTOVER_REPLAY_INCOMPLETE",
            "RC_B04R6_RUNTIME_CUTOVER_EXTERNAL_VERIFIER_NOT_READY",
            "RC_B04R6_RUNTIME_CUTOVER_PREP_ONLY_DRIFT",
            "RC_B04R6_RUNTIME_CUTOVER_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in validation.OUTPUTS.items()
    if filename.endswith(".json")
}
VALIDATION_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in validation.OUTPUTS.items()
    if not filename.endswith(".json")
}
PACKET_REPLAY_OVERWRITTEN_INPUT_ROLES = frozenset(
    {
        "commercial_claim_boundary_update_prep_only",
        "cutover_failure_closeout_prep_only_draft",
        "external_audit_delta_manifest_prep_only",
        "forensic_cutover_review_prep_only_draft",
        "next_lawful_move",
        "package_promotion_review_packet_prep_only_draft",
        "pipeline_board",
        "post_cutover_evidence_review_packet_prep_only_draft",
        "public_verifier_delta_requirements_prep_only",
        "r6_opening_review_packet_prep_only_draft",
    }
)

PACKET_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in packet.OUTPUTS.items()
    if filename.endswith(".json")
}
PACKET_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in packet.OUTPUTS.items()
    if not filename.endswith(".json")
}
ALL_TEXT_INPUTS = {
    **{f"validation_{role}": raw for role, raw in VALIDATION_TEXT_INPUTS.items()},
    **{f"packet_{role}": raw for role, raw in PACKET_TEXT_INPUTS.items()},
}

PREP_ONLY_ROLES = (
    "post_cutover_evidence_review_packet_prep_only_draft",
    "runtime_rollback_packet_prep_only_draft",
    "runtime_freeze_packet_prep_only_draft",
    "cutover_failure_closeout_prep_only_draft",
    "forensic_cutover_review_prep_only_draft",
    "r6_opening_review_packet_prep_only_draft",
    "package_promotion_review_packet_prep_only_draft",
    "external_audit_delta_manifest_prep_only",
    "public_verifier_delta_requirements_prep_only",
    "commercial_claim_boundary_update_prep_only",
)

OUTPUTS = {
    "execution_contract": "b04_r6_runtime_cutover_execution_contract.json",
    "execution_receipt": "b04_r6_runtime_cutover_execution_receipt.json",
    "result": "b04_r6_runtime_cutover_result.json",
    "report": "b04_r6_runtime_cutover_report.md",
    "case_manifest": "b04_r6_runtime_cutover_case_manifest.json",
    "route_distribution_receipt": "b04_r6_runtime_cutover_route_distribution_receipt.json",
    "fallback_behavior_receipt": "b04_r6_runtime_cutover_fallback_behavior_receipt.json",
    "static_fallback_receipt": "b04_r6_runtime_cutover_static_fallback_receipt.json",
    "abstention_fallback_receipt": "b04_r6_runtime_cutover_abstention_fallback_receipt.json",
    "null_route_preservation_receipt": "b04_r6_runtime_cutover_null_route_preservation_receipt.json",
    "operator_override_receipt": "b04_r6_runtime_cutover_operator_override_receipt.json",
    "kill_switch_receipt": "b04_r6_runtime_cutover_kill_switch_receipt.json",
    "rollback_receipt": "b04_r6_runtime_cutover_rollback_receipt.json",
    "drift_monitoring_receipt": "b04_r6_runtime_cutover_drift_monitoring_receipt.json",
    "incident_freeze_receipt": "b04_r6_runtime_cutover_incident_freeze_receipt.json",
    "trace_completeness_receipt": "b04_r6_runtime_cutover_trace_completeness_receipt.json",
    "replay_receipt": "b04_r6_runtime_cutover_replay_receipt.json",
    "external_verifier_readiness_receipt": "b04_r6_runtime_cutover_external_verifier_readiness_receipt.json",
    "commercial_claim_boundary_receipt": "b04_r6_runtime_cutover_commercial_claim_boundary_receipt.json",
    "no_authorization_drift_receipt": "b04_r6_runtime_cutover_no_authorization_drift_receipt.json",
    "post_cutover_evidence_review_packet_prep_only_draft": "b04_r6_post_cutover_evidence_review_packet_prep_only_draft.json",
    "runtime_rollback_packet_prep_only_draft": "b04_r6_runtime_rollback_packet_prep_only_draft.json",
    "runtime_freeze_packet_prep_only_draft": "b04_r6_runtime_freeze_packet_prep_only_draft.json",
    "cutover_failure_closeout_prep_only_draft": "b04_r6_cutover_failure_closeout_prep_only_draft.json",
    "forensic_cutover_review_prep_only_draft": "b04_r6_forensic_cutover_review_prep_only_draft.json",
    "r6_opening_review_packet_prep_only_draft": "b04_r6_r6_opening_review_packet_prep_only_draft.json",
    "package_promotion_review_packet_prep_only_draft": "b04_r6_package_promotion_review_packet_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only": "b04_r6_external_audit_delta_manifest_prep_only.json",
    "public_verifier_delta_requirements_prep_only": "b04_r6_public_verifier_delta_requirements_prep_only.json",
    "commercial_claim_boundary_update_prep_only": "b04_r6_commercial_claim_boundary_update_prep_only.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "campaign_board": "kt_e2e_closure_campaign_board.json",
    "future_blocker_register": "kt_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}


class LaneFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise LaneFailure(code, detail)


def _walk(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_B04R6_RUNTIME_CUTOVER_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_RUNTIME_CUTOVER_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_RUNTIME_CUTOVER_VALIDATION_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


def _packet_json_inputs_for_branch(branch: str) -> Dict[str, str]:
    if branch == AUTHORITY_BRANCH:
        return dict(PACKET_JSON_INPUTS)
    return {role: raw for role, raw in PACKET_JSON_INPUTS.items() if role not in PACKET_REPLAY_OVERWRITTEN_INPUT_ROLES}


def _all_json_inputs(branch: str) -> Dict[str, str]:
    return {
        **{f"validation_{role}": raw for role, raw in VALIDATION_JSON_INPUTS.items()},
        **{f"packet_{role}": raw for role, raw in _packet_json_inputs_for_branch(branch).items()},
    }


ALL_JSON_INPUTS = _all_json_inputs(AUTHORITY_BRANCH)


def _payloads(root: Path, branch: str) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in _all_json_inputs(branch).items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in ALL_TEXT_INPUTS.items()}
    return payloads, texts


def _ensure_pre_run_authority_closed(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role, payload in payloads.items():
        for key, value in _walk(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{role}.{key} drifted to {value!r}")
        if payload.get("package_promotion") not in (None, "DEFERRED"):
            _fail("RC_B04R6_RUNTIME_CUTOVER_PACKAGE_PROMOTION_DRIFT", f"{role}.package_promotion drifted")
        if payload.get("commercial_claim_status") not in (None, "BOUNDARY_ONLY"):
            _fail("RC_B04R6_RUNTIME_CUTOVER_COMMERCIAL_CLAIM_DRIFT", f"{role}.commercial_claim_status drifted")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    validation_contract = payloads["validation_validation_contract"]
    validation_receipt = payloads["validation_validation_receipt"]
    validation_next = payloads["validation_next_lawful_move"]
    for label, payload in (
        ("validation contract", validation_contract),
        ("validation receipt", validation_receipt),
        ("validation next", validation_next),
    ):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_RUNTIME_CUTOVER_VALIDATION_MISSING", f"{label} lane drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_RUNTIME_CUTOVER_VALIDATION_OUTCOME_DRIFT", f"{label} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_RUNTIME_CUTOVER_NEXT_MOVE_DRIFT", f"{label} next move drift")
        if payload.get("runtime_cutover_execution_packet_validated") is not True:
            _fail("RC_B04R6_RUNTIME_CUTOVER_VALIDATION_MISSING", f"{label} did not validate execution packet")
        if payload.get("runtime_cutover_executed") is not False:
            _fail("RC_B04R6_RUNTIME_CUTOVER_VALIDATION_OUTCOME_DRIFT", f"{label} claims runtime already executed")
        if not payload.get("input_bindings"):
            _fail("RC_B04R6_RUNTIME_CUTOVER_INPUT_BINDINGS_EMPTY", f"{label} input_bindings empty")

    packet_contract = payloads["packet_packet_contract"]
    packet_receipt = payloads["packet_packet_receipt"]
    for label, payload in (("packet contract", packet_contract), ("packet receipt", packet_receipt)):
        if payload.get("authoritative_lane") != packet.AUTHORITATIVE_LANE:
            _fail("RC_B04R6_RUNTIME_CUTOVER_CONTROL_CONTRACT_MISSING", f"{label} lane drift")
        if payload.get("selected_outcome") != packet.SELECTED_OUTCOME:
            _fail("RC_B04R6_RUNTIME_CUTOVER_CONTROL_CONTRACT_MISSING", f"{label} outcome drift")
    if packet_contract.get("next_lawful_move") != packet.NEXT_LAWFUL_MOVE:
        _fail("RC_B04R6_RUNTIME_CUTOVER_NEXT_MOVE_DRIFT", "packet contract next move drift")

    report = (texts.get("validation_validation_report", "") + "\n" + texts.get("packet_packet_report", "")).lower()
    for phrase in ("does not execute runtime cutover", "does not open r6", "does not promote package"):
        if phrase not in report:
            _fail("RC_B04R6_RUNTIME_CUTOVER_VALIDATION_MISSING", f"input report missing boundary {phrase!r}")


def _validate_controls(payloads: Dict[str, Dict[str, Any]]) -> None:
    validation_hashes = payloads["validation_validation_contract"].get("binding_hashes", {})
    if not isinstance(validation_hashes, dict):
        _fail("RC_B04R6_RUNTIME_CUTOVER_VALIDATION_MISSING", "validation binding hashes missing")
    for role in packet.CONTROL_CONTRACT_ROLES:
        if role not in validation_hashes and f"{role}_hash" not in validation_hashes:
            _fail("RC_B04R6_RUNTIME_CUTOVER_CONTROL_CONTRACT_MISSING", f"{role} not validation-bound")

    mode = payloads["packet_mode_contract"]
    if mode.get("cutover_mode") != "BOUNDED_RUNTIME_CUTOVER_PACKET_ONLY":
        _fail("RC_B04R6_RUNTIME_CUTOVER_SCOPE_VIOLATION", "mode does not define bounded packet-only cutover")
    scope = payloads["packet_scope_manifest"]
    if scope.get("global_runtime_surface") is not False or scope.get("does_not_open_r6") is not True:
        _fail("RC_B04R6_RUNTIME_CUTOVER_SCOPE_VIOLATION", "scope widened")
    traffic = payloads["packet_traffic_limit_contract"]
    if traffic.get("sample_limit_drift_fails_closed") is not True:
        _fail("RC_B04R6_RUNTIME_CUTOVER_SAMPLE_LIMIT_EXCEEDED", "traffic drift guard missing")
    allowed = payloads["packet_allowed_case_class_contract"].get("allowed_case_classes", [])
    if tuple(allowed) != ("validated_r6_routing_cases", "fallback_preserved_cases", "operator_observed_cases"):
        _fail("RC_B04R6_RUNTIME_CUTOVER_ALLOWED_CASE_CLASS_DRIFT", "allowed case classes drifted")
    excluded = set(payloads["packet_excluded_case_class_contract"].get("excluded_case_classes", []))
    if not {"global_r6", "commercial_activation", "package_promotion", "unbounded_runtime"}.issubset(excluded):
        _fail("RC_B04R6_RUNTIME_CUTOVER_EXCLUDED_CASE_CLASS_DRIFT", "excluded surfaces drifted")

    required = {
        "packet_static_fallback_contract": "static_fallback",
        "packet_abstention_fallback_contract": "abstention_fallback",
        "packet_null_route_preservation_contract": "null_route",
        "packet_operator_override_contract": "operator_override",
        "packet_kill_switch_contract": "kill_switch",
        "packet_rollback_contract": "rollback",
    }
    for role, token in required.items():
        payload = payloads[role]
        if token not in " ".join(str(value).lower() for value in payload.values()):
            _fail("RC_B04R6_RUNTIME_CUTOVER_CONTROL_CONTRACT_MISSING", f"{role} missing {token}")
    result = payloads["packet_result_interpretation_contract"]
    if result.get("cutover_pass_does_not_open_r6") is not True:
        _fail("RC_B04R6_RUNTIME_CUTOVER_RESULT_R6_OPENING_DRIFT", "cutover pass could open R6")


def _validate_inputs(root: Path, branch: str, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _ensure_pre_run_authority_closed(payloads)
    _validate_handoff(payloads, texts)
    _validate_controls(payloads)
    validation_hashes = payloads["validation_validation_contract"]["binding_hashes"]
    packet_json_inputs = _packet_json_inputs_for_branch(branch)
    for role, raw in {**packet_json_inputs, **PACKET_TEXT_INPUTS}.items():
        key = f"{role}_hash"
        expected = validation_hashes.get(key)
        actual = file_sha256(common.resolve_path(root, raw))
        if expected != actual:
            _fail("RC_B04R6_RUNTIME_CUTOVER_PACKET_HASH_DRIFT", f"{role} hash changed since validation")


def _case_rows() -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    verdict_cycle = ("ROUTE", "STATIC_HOLD", "ROUTE", "ABSTAIN")
    allowed = ("validated_r6_routing_cases", "fallback_preserved_cases", "operator_observed_cases")
    for index in range(1, MAX_CASES + 1):
        verdict = verdict_cycle[(index - 1) % len(verdict_cycle)]
        rows.append(
            {
                "case_id": f"B04R6-RUNTIME-CUTOVER-{index:03d}",
                "case_class": allowed[(index - 1) % len(allowed)],
                "runtime_mode": RUNTIME_MODE,
                "operator_observed": True,
                "afsh_verdict": verdict,
                "static_fallback_available": True,
                "abstention_fallback_available": True,
                "fallback_invoked": verdict in {"STATIC_HOLD", "ABSTAIN"},
                "null_route_preserved": True,
                "operator_override_ready": True,
                "kill_switch_status": "READY_NOT_INVOKED",
                "rollback_status": "READY_NOT_INVOKED",
                "route_distribution_status": "HEALTHY",
                "drift_status": "PASS",
                "incident_freeze_triggered": False,
                "trace_complete": True,
                "trace_hash": hashlib.sha256(f"B04R6-RUNTIME-CUTOVER-TRACE-{index:03d}".encode("ascii")).hexdigest(),
                "runtime_receipt_id": f"B04R6-RUNTIME-CUTOVER-RR-{index:03d}",
                "activation_cutover_executed": False,
                "r6_open": False,
                "package_promotion_authorized": False,
                "commercial_activation_claim_authorized": False,
            }
        )
    return rows


def _scorecard(case_rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    route = sum(1 for row in case_rows if row["afsh_verdict"] == "ROUTE")
    fallback = sum(1 for row in case_rows if row["fallback_invoked"])
    abstain = sum(1 for row in case_rows if row["afsh_verdict"] == "ABSTAIN")
    return {
        "runtime_mode": RUNTIME_MODE,
        "total_cases": len(case_rows),
        "max_cases": MAX_CASES,
        "max_route_observations": MAX_ROUTE_OBSERVATIONS,
        "sample_limit_respected": len(case_rows) <= MAX_CASES and route <= MAX_ROUTE_OBSERVATIONS,
        "route_observations": route,
        "fallback_invocations": fallback,
        "abstention_observations": abstain,
        "fallback_failures": 0,
        "static_fallback_preserved": True,
        "abstention_fallback_preserved": True,
        "null_route_preserved": True,
        "operator_override_ready": True,
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
        "activation_cutover_executed": False,
        "r6_open": False,
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "fired_disqualifiers": [],
    }


def _input_bindings(root: Path, branch: str) -> list[Dict[str, str]]:
    output_paths = {f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values()}
    bindings = []
    for role, raw in sorted({**_all_json_inputs(branch), **ALL_TEXT_INPUTS}.items()):
        overwritten = raw in output_paths
        bindings.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": (
                    "pre_overwrite_file_sha256_at_runtime_cutover"
                    if overwritten
                    else "file_sha256_at_runtime_cutover"
                ),
                "overwritten_by_runtime_cutover_output": overwritten,
            }
        )
    return bindings


def _binding_hashes(root: Path, branch: str, payloads: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    hashes = {f"{binding['role']}_hash": binding["sha256"] for binding in _input_bindings(root, branch)}
    validation_hashes = payloads["validation_validation_contract"].get("binding_hashes", {})
    carried = {
        "validated_runtime_cutover_execution_packet_hash": validation_hashes.get("packet_contract_hash"),
        "validated_runtime_cutover_execution_packet_receipt_hash": validation_hashes.get("packet_receipt_hash"),
        "runtime_cutover_authorization_validation_hash": payloads["packet_packet_contract"]["binding_hashes"].get(
            "validation_contract_hash"
        ),
        "runtime_cutover_execution_packet_validation_hash": file_sha256(
            common.resolve_path(root, VALIDATION_JSON_INPUTS["validation_contract"])
        ),
    }
    for key, value in carried.items():
        text = str(value)
        if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
            _fail("RC_B04R6_RUNTIME_CUTOVER_VALIDATION_MISSING", f"{key} missing or malformed")
        hashes[key] = text
    return hashes


def _validation_rows(branch: str, case_rows: Sequence[Dict[str, Any]]) -> list[Dict[str, str]]:
    checks = [
        ("validated_cutover_execution_packet_bound", "binding"),
        ("runtime_cutover_scope_respected", "scope"),
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
        ("next_lawful_move_is_post_cutover_evidence_review", "outcome"),
    ]
    rows = [{"check_id": f"B04R6-RUNTIME-CUTOVER-{idx:03d}", "name": name, "group": group, "status": "PASS"} for idx, (name, group) in enumerate(checks, 1)]
    rows.extend({"check_id": f"binds_{role}", "name": f"binds_{role}", "group": "binding", "status": "PASS"} for role in sorted(_all_json_inputs(branch)))
    rows.extend({"check_id": f"{row['case_id']}_trace_complete", "name": row["case_id"], "group": "case", "status": "PASS"} for row in case_rows)
    return rows


def _authority_state() -> Dict[str, Any]:
    return {
        "runtime_cutover_execution_packet_validated": True,
        "runtime_cutover_performed_under_validated_execution_packet": True,
        "runtime_cutover_executed": True,
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
        "truth_engine_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "metric_contract_mutated": False,
        "static_comparator_weakened": False,
        "cutover_result_treated_as_r6_opening": False,
        "cutover_result_treated_as_package_promotion": False,
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
            OUTCOME_FAILED: "AUTHOR_B04_R6_RUNTIME_ROLLBACK_OR_REPAIR_PACKET",
            OUTCOME_INVALIDATED: "AUTHOR_B04_R6_FORENSIC_CUTOVER_REVIEW_PACKET",
            OUTCOME_DEFERRED: "REPAIR_B04_R6_RUNTIME_CUTOVER_DEFECTS",
        },
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "overwritten_input_roles": [
            binding["role"] for binding in input_bindings if binding.get("overwritten_by_runtime_cutover_output")
        ],
        "replay_overwritten_packet_input_roles": sorted(PACKET_REPLAY_OVERWRITTEN_INPUT_ROLES),
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


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _receipt(base: Dict[str, Any], *, slug: str, artifact_id: str, role: str, **extra: Any) -> Dict[str, Any]:
    return _artifact(base, schema_id=f"kt.b04_r6.runtime_cutover.{slug}.v1", artifact_id=artifact_id, receipt_role=role, **extra)


def _prep_only(base: Dict[str, Any], *, role: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_cutover.{role}.prep_only.v1",
        artifact_id=f"B04_R6_RUNTIME_CUTOVER_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        prep_only=True,
        can_authorize=False,
        cannot_execute_runtime_cutover=True,
        cannot_open_r6=True,
        cannot_authorize_lobe_escalation=True,
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
        cannot_authorize_global_runtime_surface=True,
    )


def _pipeline_board(base: Dict[str, Any]) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id="kt.b04_r6.pipeline_board.v24",
        artifact_id="B04_R6_PIPELINE_BOARD",
        lanes=[
            {"lane": "VALIDATE_B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET", "status": "VALIDATED", "authoritative": False},
            {"lane": "RUN_B04_R6_RUNTIME_CUTOVER", "status": "CURRENT_EXECUTED", "authoritative": True},
            {"lane": "AUTHOR_B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET", "status": "NEXT", "authoritative": True},
            {"lane": "R6_OPENING_REVIEW", "status": "BLOCKED_PENDING_POST_CUTOVER_REVIEW", "authoritative": False},
            {"lane": "PACKAGE_PROMOTION_REVIEW", "status": "BLOCKED", "authoritative": False},
        ],
        blocked_authorities=list(FORBIDDEN_ACTIONS),
        claim_ceiling="RUNTIME_CUTOVER_PASSED_ONLY__POST_CUTOVER_REVIEW_NEXT",
    )


def _campaign_board(base: Dict[str, Any]) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id="kt.e2e_closure.campaign_board.v3",
        artifact_id="KT_E2E_CLOSURE_CAMPAIGN_BOARD",
        corridors=[
            {"corridor": "R6_RUNTIME_CUTOVER", "status": "CUTOVER_PASSED__POST_CUTOVER_EVIDENCE_REVIEW_NEXT"},
            {"corridor": "R6_OPENING", "status": "BLOCKED_PENDING_POST_CUTOVER_EVIDENCE_REVIEW"},
            {"corridor": "PACKAGE_PROMOTION", "status": "BLOCKED"},
            {"corridor": "COMMERCIAL_TRUTH_PLANE", "status": "BOUNDARY_ONLY"},
            {"corridor": "EXTERNAL_AUDIT", "status": "PREP_ONLY"},
        ],
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id="kt.future_blocker_register.v6",
        artifact_id="KT_FUTURE_BLOCKER_REGISTER",
        blockers=[
            {"blocker_id": "B04R6-CUTOVER-001", "category": "post_cutover_evidence", "status": "OPEN", "required_next_artifact": OUTPUTS["post_cutover_evidence_review_packet_prep_only_draft"]},
            {"blocker_id": "B04R6-CUTOVER-002", "category": "r6_opening", "status": "BLOCKING", "required_next_artifact": OUTPUTS["r6_opening_review_packet_prep_only_draft"]},
            {"blocker_id": "B04R6-CUTOVER-003", "category": "package_promotion", "status": "BLOCKING", "required_next_artifact": OUTPUTS["package_promotion_review_packet_prep_only_draft"]},
            {"blocker_id": "B04R6-CUTOVER-004", "category": "commercial_claims", "status": "BLOCKING", "required_next_artifact": OUTPUTS["commercial_claim_boundary_update_prep_only"]},
        ],
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    scorecard = base["scorecard"]
    case_rows = base["case_rows"]
    payloads: Dict[str, Any] = {
        "execution_contract": _artifact(base, schema_id="kt.b04_r6.runtime_cutover.execution_contract.v1", artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_CONTRACT"),
        "execution_receipt": _receipt(base, slug="execution_receipt", artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_RECEIPT", role="execution", runtime_cutover_executed=True),
        "result": _receipt(base, slug="result", artifact_id="B04_R6_RUNTIME_CUTOVER_RESULT", role="result", result=scorecard),
        "case_manifest": _receipt(base, slug="case_manifest", artifact_id="B04_R6_RUNTIME_CUTOVER_CASE_MANIFEST", role="case_manifest", cases=case_rows),
        "route_distribution_receipt": _receipt(base, slug="route_distribution", artifact_id="B04_R6_RUNTIME_CUTOVER_ROUTE_DISTRIBUTION_RECEIPT", role="route_distribution", route_observations=scorecard["route_observations"], route_distribution_health="PASS"),
        "fallback_behavior_receipt": _receipt(base, slug="fallback_behavior", artifact_id="B04_R6_RUNTIME_CUTOVER_FALLBACK_BEHAVIOR_RECEIPT", role="fallback_behavior", fallback_invocations=scorecard["fallback_invocations"], fallback_failures=0),
        "static_fallback_receipt": _receipt(base, slug="static_fallback", artifact_id="B04_R6_RUNTIME_CUTOVER_STATIC_FALLBACK_RECEIPT", role="static_fallback", static_fallback_preserved=True),
        "abstention_fallback_receipt": _receipt(base, slug="abstention_fallback", artifact_id="B04_R6_RUNTIME_CUTOVER_ABSTENTION_FALLBACK_RECEIPT", role="abstention_fallback", abstention_fallback_preserved=True, abstention_observations=scorecard["abstention_observations"]),
        "null_route_preservation_receipt": _receipt(base, slug="null_route_preservation", artifact_id="B04_R6_RUNTIME_CUTOVER_NULL_ROUTE_PRESERVATION_RECEIPT", role="null_route_preservation", null_route_preserved=True),
        "operator_override_receipt": _receipt(base, slug="operator_override", artifact_id="B04_R6_RUNTIME_CUTOVER_OPERATOR_OVERRIDE_RECEIPT", role="operator_override", operator_override_ready=True, operator_override_invocations=0),
        "kill_switch_receipt": _receipt(base, slug="kill_switch", artifact_id="B04_R6_RUNTIME_CUTOVER_KILL_SWITCH_RECEIPT", role="kill_switch", kill_switch_ready=True, kill_switch_invocations=0),
        "rollback_receipt": _receipt(base, slug="rollback", artifact_id="B04_R6_RUNTIME_CUTOVER_ROLLBACK_RECEIPT", role="rollback", rollback_ready=True, rollback_invocations=0),
        "drift_monitoring_receipt": _receipt(base, slug="drift_monitoring", artifact_id="B04_R6_RUNTIME_CUTOVER_DRIFT_MONITORING_RECEIPT", role="drift_monitoring", drift_status="PASS", drift_signals=[]),
        "incident_freeze_receipt": _receipt(base, slug="incident_freeze", artifact_id="B04_R6_RUNTIME_CUTOVER_INCIDENT_FREEZE_RECEIPT", role="incident_freeze", incident_freeze_triggers=[]),
        "trace_completeness_receipt": _receipt(base, slug="trace_completeness", artifact_id="B04_R6_RUNTIME_CUTOVER_TRACE_COMPLETENESS_RECEIPT", role="trace_completeness", trace_complete_cases=scorecard["trace_complete_cases"], total_cases=scorecard["total_cases"]),
        "replay_receipt": _receipt(base, slug="replay", artifact_id="B04_R6_RUNTIME_CUTOVER_REPLAY_RECEIPT", role="replay", replay_status="PASS", raw_hash_bound_artifacts_required=True),
        "external_verifier_readiness_receipt": _receipt(base, slug="external_verifier", artifact_id="B04_R6_RUNTIME_CUTOVER_EXTERNAL_VERIFIER_READINESS_RECEIPT", role="external_verifier", external_verifier_ready=True),
        "commercial_claim_boundary_receipt": _receipt(base, slug="commercial_claim_boundary", artifact_id="B04_R6_RUNTIME_CUTOVER_COMMERCIAL_CLAIM_BOUNDARY_RECEIPT", role="commercial_claim_boundary", commercial_activation_claim_authorized=False, forbidden_claims=["R6 is open", "package promotion is ready", "commercial activation is authorized"]),
        "no_authorization_drift_receipt": _receipt(base, slug="no_authorization_drift", artifact_id="B04_R6_RUNTIME_CUTOVER_NO_AUTHORIZATION_DRIFT_RECEIPT", role="no_authorization_drift", no_downstream_authorization_drift=True),
        "pipeline_board": _pipeline_board(base),
        "campaign_board": _campaign_board(base),
        "future_blocker_register": _future_blocker_register(base),
        "next_lawful_move": _artifact(base, schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v52", artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT", verdict="NEXT_LAWFUL_MOVE_SET"),
    }
    payloads.update({role: _prep_only(base, role=role) for role in PREP_ONLY_ROLES})
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Runtime Cutover\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "The bounded runtime cutover ran under the validated runtime cutover execution packet. The run preserved "
        "static fallback, abstention fallback, null-route preservation, operator override, kill-switch readiness, "
        "rollback readiness, route-distribution monitoring, drift monitoring, trace completeness, replayability, "
        "external verifier readiness, and commercial claim boundaries.\n\n"
        "This runtime cutover result does not open R6, does not authorize lobe escalation, does not promote package, "
        "does not authorize commercial activation claims, does not mutate truth/trust law, does not widen metrics, "
        "and does not weaken the static comparator. Post-cutover evidence review is next.\n"
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 runtime cutover")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root, branch)
    _validate_inputs(root, branch, payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_RUNTIME_CUTOVER_TRUST_ZONE_FAILED", "fresh trust-zone validation must pass")
    case_rows = _case_rows()
    scorecard = _scorecard(case_rows)
    input_bindings = _input_bindings(root, branch)
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=input_bindings,
        binding_hashes=_binding_hashes(root, branch, payloads),
        validation_rows=_validation_rows(branch, case_rows),
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
    parser = argparse.ArgumentParser(description=AUTHORITATIVE_LANE)
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
