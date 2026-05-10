from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from tools.operator import cohort0_b04_r6_runtime_cutover_authorization_packet_validation as auth_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-runtime-cutover-execution-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-runtime-cutover-execution-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET"
PREVIOUS_LANE = auth_validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = auth_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = auth_validation.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = "B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_BOUND__RUNTIME_CUTOVER_EXECUTION_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_REJECTED = "B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_REJECTED__CUTOVER_EXECUTION_NOT_JUSTIFIED"
OUTCOME_INVALID = "B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_INVALID__FORENSIC_CUTOVER_EXECUTION_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET"

VALIDATION_SUCCESS_OUTCOME = "B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_VALIDATED__RUNTIME_CUTOVER_NEXT"
VALIDATION_SUCCESS_NEXT_MOVE = "RUN_B04_R6_RUNTIME_CUTOVER"

FORBIDDEN_ACTIONS = (
    "RUNTIME_CUTOVER_EXECUTED",
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
    "runtime_cutover_authorized": "RC_B04R6_CUTOVER_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
    "runtime_cutover_executed": "RC_B04R6_CUTOVER_EXEC_PACKET_RUNTIME_CUTOVER_EXECUTED",
    "activation_cutover_executed": "RC_B04R6_CUTOVER_EXEC_PACKET_ACTIVATION_CUTOVER_EXECUTED",
    "r6_open": "RC_B04R6_CUTOVER_EXEC_PACKET_R6_OPEN_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_CUTOVER_EXEC_PACKET_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_CUTOVER_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_CUTOVER_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_CUTOVER_EXEC_PACKET_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_CUTOVER_EXEC_PACKET_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_CUTOVER_EXEC_PACKET_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_CUTOVER_EXEC_PACKET_COMPARATOR_WEAKENED",
}

CLAIM_BEARING_FIELD_MARKERS = (
    "authorization_state",
    "authority_state",
    "claim",
    "commercial",
    "cutover",
    "package_promotion",
    "r6_status",
)
POSITIVE_AUTHORITY_TOKENS = (
    "AUTHORIZED",
    "ACTIVE",
    "ENABLED",
    "EXECUTED",
    "LIVE",
    "OPEN",
    "PROMOTED",
    "PRODUCTION",
    "COMMERCIAL_ACTIVATION",
    "PACKAGE_PROMOTION",
    "R6_OPEN",
)
NEGATIVE_AUTHORITY_QUALIFIERS = (
    "BLOCKED",
    "BOUNDARY_ONLY",
    "CANNOT_AUTHORIZE",
    "CLOSED",
    "DEFERRED",
    "DOES NOT",
    "DOES_NOT_AUTHORIZE",
    "FORBIDDEN",
    "NO_COMMERCIAL",
    "NO_CUTOVER",
    "NO_PACKAGE_PROMOTION",
    "NO_PROMOTION",
    "NOT AUTHORIZED",
    "NOT_AUTHORIZED",
    "NOT_OPEN",
    "PACKET",
    "PREP_ONLY",
    "PROHIBITED",
    "REMAINS UNAUTHORIZED",
    "REMAINS_CLOSED",
    "STILL_BLOCKED",
    "UNAUTHORIZED",
    "UNEXECUTED",
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_CUTOVER_EXEC_PACKET_PREVIOUS_VALIDATION_MISSING",
            "RC_B04R6_CUTOVER_EXEC_PACKET_PREVIOUS_OUTCOME_DRIFT",
            "RC_B04R6_CUTOVER_EXEC_PACKET_NEXT_MOVE_DRIFT",
            "RC_B04R6_CUTOVER_EXEC_PACKET_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_CUTOVER_EXEC_PACKET_PREP_ONLY_DRIFT",
            "RC_B04R6_CUTOVER_EXEC_PACKET_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_CUTOVER_EXEC_PACKET_GLOBAL_SURFACE_DRIFT",
            "RC_B04R6_CUTOVER_EXEC_PACKET_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in auth_validation.OUTPUTS.items()
    if filename.endswith(".json")
}
VALIDATION_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in auth_validation.OUTPUTS.items()
    if not filename.endswith(".json")
}

CONTROL_CONTRACT_ROLES = (
    "mode_contract",
    "scope_manifest",
    "allowed_case_class_contract",
    "excluded_case_class_contract",
    "traffic_limit_contract",
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
    "commercial_claim_boundary",
    "package_promotion_prohibition_receipt",
)
AUTHORITATIVE_OUTPUT_ROLES = (
    "packet_contract",
    "packet_receipt",
    "packet_report",
    *CONTROL_CONTRACT_ROLES,
    "validation_plan",
    "validation_reason_codes",
    "no_authorization_drift_receipt",
    "next_lawful_move",
)
PREP_ONLY_OUTPUT_ROLES = (
    "runtime_cutover_run_result_schema_prep_only",
    "post_cutover_evidence_review_packet_prep_only_draft",
    "cutover_failure_closeout_prep_only_draft",
    "forensic_cutover_review_prep_only_draft",
    "r6_opening_review_packet_prep_only_draft",
    "package_promotion_review_packet_prep_only_draft",
    "external_audit_delta_manifest_prep_only",
    "public_verifier_delta_requirements_prep_only",
    "commercial_claim_boundary_update_prep_only",
    "pipeline_board",
    "future_blocker_register",
)

OUTPUTS = {
    "packet_contract": "b04_r6_runtime_cutover_execution_packet_contract.json",
    "packet_receipt": "b04_r6_runtime_cutover_execution_packet_receipt.json",
    "packet_report": "b04_r6_runtime_cutover_execution_packet_report.md",
    "mode_contract": "b04_r6_runtime_cutover_execution_mode_contract.json",
    "scope_manifest": "b04_r6_runtime_cutover_execution_scope_manifest.json",
    "allowed_case_class_contract": "b04_r6_runtime_cutover_execution_allowed_case_class_contract.json",
    "excluded_case_class_contract": "b04_r6_runtime_cutover_execution_excluded_case_class_contract.json",
    "traffic_limit_contract": "b04_r6_runtime_cutover_execution_traffic_limit_contract.json",
    "static_fallback_contract": "b04_r6_runtime_cutover_execution_static_fallback_contract.json",
    "abstention_fallback_contract": "b04_r6_runtime_cutover_execution_abstention_fallback_contract.json",
    "null_route_preservation_contract": "b04_r6_runtime_cutover_execution_null_route_preservation_contract.json",
    "operator_override_contract": "b04_r6_runtime_cutover_execution_operator_override_contract.json",
    "kill_switch_contract": "b04_r6_runtime_cutover_execution_kill_switch_contract.json",
    "rollback_contract": "b04_r6_runtime_cutover_execution_rollback_contract.json",
    "route_distribution_thresholds": "b04_r6_runtime_cutover_execution_route_distribution_thresholds.json",
    "drift_thresholds": "b04_r6_runtime_cutover_execution_drift_thresholds.json",
    "incident_freeze_contract": "b04_r6_runtime_cutover_execution_incident_freeze_contract.json",
    "runtime_receipt_schema": "b04_r6_runtime_cutover_execution_runtime_receipt_schema.json",
    "replay_manifest": "b04_r6_runtime_cutover_execution_replay_manifest.json",
    "expected_artifact_manifest": "b04_r6_runtime_cutover_execution_expected_artifact_manifest.json",
    "external_verifier_requirements": "b04_r6_runtime_cutover_execution_external_verifier_requirements.json",
    "result_interpretation_contract": "b04_r6_runtime_cutover_execution_result_interpretation_contract.json",
    "commercial_claim_boundary": "b04_r6_runtime_cutover_execution_commercial_claim_boundary.json",
    "package_promotion_prohibition_receipt": "b04_r6_runtime_cutover_execution_package_promotion_prohibition_receipt.json",
    "validation_plan": "b04_r6_runtime_cutover_execution_validation_plan.json",
    "validation_reason_codes": "b04_r6_runtime_cutover_execution_validation_reason_codes.json",
    "no_authorization_drift_receipt": "b04_r6_runtime_cutover_execution_no_authorization_drift_receipt.json",
    "runtime_cutover_run_result_schema_prep_only": "b04_r6_runtime_cutover_run_result_schema_prep_only.json",
    "post_cutover_evidence_review_packet_prep_only_draft": (
        "b04_r6_post_cutover_evidence_review_packet_prep_only_draft.json"
    ),
    "cutover_failure_closeout_prep_only_draft": "b04_r6_cutover_failure_closeout_prep_only_draft.json",
    "forensic_cutover_review_prep_only_draft": "b04_r6_forensic_cutover_review_prep_only_draft.json",
    "r6_opening_review_packet_prep_only_draft": "b04_r6_r6_opening_review_packet_prep_only_draft.json",
    "package_promotion_review_packet_prep_only_draft": (
        "b04_r6_package_promotion_review_packet_prep_only_draft.json"
    ),
    "external_audit_delta_manifest_prep_only": "b04_r6_external_audit_delta_manifest_prep_only.json",
    "public_verifier_delta_requirements_prep_only": "b04_r6_public_verifier_delta_requirements_prep_only.json",
    "commercial_claim_boundary_update_prep_only": "b04_r6_commercial_claim_boundary_update_prep_only.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
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
            _fail("RC_B04R6_CUTOVER_EXEC_PACKET_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_CUTOVER_EXEC_PACKET_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_CUTOVER_EXEC_PACKET_PREVIOUS_VALIDATION_MISSING", f"{label} must be an object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


def _ensure_authority_closed(payload: Dict[str, Any], *, label: str) -> None:
    for key, value in _walk(payload):
        if key in AUTHORITY_DRIFT_KEYS and value is not False:
            _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted to {value!r}")
        if key == "r6" and isinstance(value, str) and value.upper() == "OPEN":
            _fail("RC_B04R6_CUTOVER_EXEC_PACKET_R6_OPEN_DRIFT", f"{label}.{key} contains OPEN")
    if payload.get("package_promotion") not in (None, "DEFERRED", "BLOCKED"):
        _fail("RC_B04R6_CUTOVER_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT", f"{label}.package_promotion drifted")


def _ensure_claim_boundary(payload: Dict[str, Any], *, label: str) -> None:
    for key, value in _walk(payload):
        if not isinstance(value, str):
            continue
        key_lower = str(key).lower()
        if not any(marker in key_lower for marker in CLAIM_BEARING_FIELD_MARKERS):
            continue
        upper = value.upper()
        if not any(token in upper for token in POSITIVE_AUTHORITY_TOKENS):
            continue
        if any(qualifier in upper for qualifier in NEGATIVE_AUTHORITY_QUALIFIERS):
            continue
        _fail("RC_B04R6_CUTOVER_EXEC_PACKET_CLAIM_TOKEN_DRIFT", f"{label}.{key} contains {value!r}")


def _payloads_from_inputs(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in VALIDATION_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in VALIDATION_TEXT_INPUTS.items()}
    return payloads, texts


def _validate_previous(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    contract = payloads.get("validation_contract")
    receipt = payloads.get("validation_receipt")
    next_move = payloads.get("next_lawful_move")
    if not contract or not receipt or not next_move:
        _fail("RC_B04R6_CUTOVER_EXEC_PACKET_PREVIOUS_VALIDATION_MISSING", "authorization validation missing")
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_CUTOVER_EXEC_PACKET_PREVIOUS_OUTCOME_DRIFT", "authorization validation outcome drifted")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_CUTOVER_EXEC_PACKET_PREVIOUS_OUTCOME_DRIFT", "authorization validation receipt drifted")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_CUTOVER_EXEC_PACKET_NEXT_MOVE_DRIFT", "authorization validation next move drifted")
    if not contract.get("input_bindings"):
        _fail("RC_B04R6_CUTOVER_EXEC_PACKET_INPUT_BINDINGS_EMPTY", "authorization validation input bindings empty")
    if contract.get("runtime_cutover_authorization_validated") is not True:
        _fail("RC_B04R6_CUTOVER_EXEC_PACKET_PREVIOUS_VALIDATION_MISSING", "authorization validation not true")
    if contract.get("runtime_cutover_execution_packet_authored") is not False:
        _fail("RC_B04R6_CUTOVER_EXEC_PACKET_PREVIOUS_VALIDATION_MISSING", "execution packet was already authored")
    for role in auth_validation.PREP_ONLY_OUTPUT_ROLES:
        payload = payloads.get(role)
        if not payload or payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_CUTOVER_EXEC_PACKET_PREP_ONLY_DRIFT", f"{role} is not prep-only")
    for role, payload in payloads.items():
        _ensure_authority_closed(payload, label=role)
        _ensure_claim_boundary(payload, label=role)
    for role, text in texts.items():
        upper = text.upper()
        for token in (
            "RUNTIME CUTOVER AUTHORIZED",
            "RUNTIME_CUTOVER_AUTHORIZED",
            "RUNTIME CUTOVER EXECUTED",
            "RUNTIME_CUTOVER_EXECUTED",
            "PACKAGE PROMOTION AUTHORIZED",
            "PACKAGE_PROMOTION_AUTHORIZED",
            "COMMERCIAL ACTIVATION CLAIM AUTHORIZED",
            "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
            "R6 OPEN",
            "R6_OPEN",
        ):
            if token in upper:
                _fail("RC_B04R6_CUTOVER_EXEC_PACKET_CLAIM_TOKEN_DRIFT", f"{role} contains {token!r}")


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    bindings: list[Dict[str, str]] = []
    for role, raw in {**VALIDATION_JSON_INPUTS, **VALIDATION_TEXT_INPUTS}.items():
        bindings.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(root / raw),
                "binding_kind": "file_sha256_at_runtime_cutover_execution_packet_authoring",
            }
        )
    return sorted(bindings, key=lambda item: item["role"])


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    input_bindings: list[Dict[str, str]],
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
        "validation_success_outcome": VALIDATION_SUCCESS_OUTCOME,
        "validation_success_next_move": VALIDATION_SUCCESS_NEXT_MOVE,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_REJECTED, OUTCOME_INVALID],
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "input_bindings": input_bindings,
        "binding_hashes": {f"{binding['role']}_hash": binding["sha256"] for binding in input_bindings},
        "runtime_cutover_review_validated": True,
        "runtime_cutover_authorization_packet_authored": True,
        "runtime_cutover_authorization_validated": True,
        "runtime_cutover_execution_packet_authored": True,
        "runtime_cutover_execution_packet_validated": False,
        "runtime_cutover_authorized": False,
        "runtime_cutover_executed": False,
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


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    payload = dict(base)
    payload.update({"schema_id": schema_id, "artifact_id": artifact_id})
    payload.update(extra)
    return payload


def _control(base: Dict[str, Any], *, role: str, purpose: str, **extra: Any) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_cutover_execution_packet.{role}.v1",
        artifact_id=f"B04_R6_RUNTIME_CUTOVER_EXECUTION_{role.upper()}",
        control_status="DEFINED_FOR_VALIDATION",
        does_not_execute_runtime_cutover=True,
        does_not_open_r6=True,
        requires_future_validation=NEXT_LAWFUL_MOVE,
        purpose=purpose,
        **extra,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str, **extra: Any) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_cutover_execution_packet.{role}.prep_only.v1",
        artifact_id=f"B04_R6_RUNTIME_CUTOVER_EXECUTION_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_authorize_runtime_cutover=True,
        cannot_execute_runtime_cutover=True,
        cannot_open_r6=True,
        cannot_authorize_lobe_escalation=True,
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
        **extra,
    )


def _output_payloads(base: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    controls = {
        "mode_contract": _control(
            base,
            role="mode_contract",
            purpose="Define bounded runtime cutover execution mode for validation.",
            cutover_mode="BOUNDED_RUNTIME_CUTOVER_PACKET_ONLY",
        ),
        "scope_manifest": _control(
            base,
            role="scope_manifest",
            purpose="Define limited cutover scope.",
            scope_status="LIMITED_SCOPE_DEFINED",
            global_runtime_surface=False,
        ),
        "allowed_case_class_contract": _control(
            base,
            role="allowed_case_class_contract",
            purpose="Define allowed bounded case classes.",
            allowed_case_classes=["validated_r6_routing_cases", "fallback_preserved_cases", "operator_observed_cases"],
        ),
        "excluded_case_class_contract": _control(
            base,
            role="excluded_case_class_contract",
            purpose="Define excluded surfaces and case classes.",
            excluded_case_classes=["global_r6", "commercial_activation", "package_promotion", "unbounded_runtime"],
        ),
        "traffic_limit_contract": _control(
            base,
            role="traffic_limit_contract",
            purpose="Define exposure limits for future cutover run.",
            traffic_limit="bounded_r6_cutover_surface_only",
            sample_limit_drift_fails_closed=True,
        ),
        "static_fallback_contract": _control(
            base,
            role="static_fallback_contract",
            purpose="Require static fallback.",
            static_fallback_required=True,
        ),
        "abstention_fallback_contract": _control(
            base,
            role="abstention_fallback_contract",
            purpose="Require abstention fallback.",
            abstention_fallback_required=True,
        ),
        "null_route_preservation_contract": _control(
            base,
            role="null_route_preservation_contract",
            purpose="Require null-route preservation.",
            null_route_preservation_required=True,
        ),
        "operator_override_contract": _control(
            base,
            role="operator_override_contract",
            purpose="Require operator override path.",
            operator_override_required=True,
        ),
        "kill_switch_contract": _control(
            base,
            role="kill_switch_contract",
            purpose="Require kill-switch procedure.",
            kill_switch_required=True,
        ),
        "rollback_contract": _control(
            base,
            role="rollback_contract",
            purpose="Require rollback execution procedure.",
            rollback_required=True,
        ),
        "route_distribution_thresholds": _control(
            base, role="route_distribution_thresholds", purpose="Define route-distribution thresholds."
        ),
        "drift_thresholds": _control(base, role="drift_thresholds", purpose="Define drift thresholds."),
        "incident_freeze_contract": _control(
            base, role="incident_freeze_contract", purpose="Define incident and freeze conditions."
        ),
        "runtime_receipt_schema": _control(
            base, role="runtime_receipt_schema", purpose="Define required runtime cutover receipts."
        ),
        "replay_manifest": _control(base, role="replay_manifest", purpose="Define runtime replay manifest."),
        "expected_artifact_manifest": _control(
            base,
            role="expected_artifact_manifest",
            purpose="Define required runtime cutover output artifacts.",
            expected_artifacts=[
                "b04_r6_runtime_cutover_execution_contract.json",
                "b04_r6_runtime_cutover_execution_receipt.json",
                "b04_r6_runtime_cutover_result.json",
                "b04_r6_runtime_cutover_report.md",
            ],
        ),
        "external_verifier_requirements": _control(
            base, role="external_verifier_requirements", purpose="Define external verifier requirements."
        ),
        "result_interpretation_contract": _control(
            base,
            role="result_interpretation_contract",
            purpose="Define result interpretation without opening R6.",
            cutover_pass_does_not_open_r6=True,
        ),
        "commercial_claim_boundary": _control(
            base,
            role="commercial_claim_boundary",
            purpose="Preserve commercial claim boundary.",
            allowed_claim_ceiling="CUTOVER_EXECUTION_PACKET_AUTHORED_ONLY",
            forbidden_claims=["AFSH is live", "R6 is open", "package is promoted", "commercial activation is authorized"],
        ),
        "package_promotion_prohibition_receipt": _control(
            base,
            role="package_promotion_prohibition_receipt",
            purpose="Preserve package promotion prohibition.",
            package_promotion_status="DEFERRED",
        ),
    }
    payloads: Dict[str, Dict[str, Any]] = {
        "packet_contract": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_execution_packet.contract.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_CONTRACT",
            packet_status="BOUND_FOR_VALIDATION_ONLY",
            execution_packet_summary="Defines future runtime cutover execution law. It does not execute cutover.",
        ),
        "packet_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_execution_packet.receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_RECEIPT",
            verdict="BOUND_FOR_RUNTIME_CUTOVER_EXECUTION_VALIDATION_ONLY",
        ),
        **controls,
        "validation_plan": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_execution_packet.validation_plan.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_VALIDATION_PLAN",
            validation_targets=list(CONTROL_CONTRACT_ROLES),
            validation_success_outcome=VALIDATION_SUCCESS_OUTCOME,
        ),
        "validation_reason_codes": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_execution_packet.reason_codes.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
        ),
        "no_authorization_drift_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_execution_packet.no_authorization_drift.receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_NO_AUTHORIZATION_DRIFT_RECEIPT",
            validation_status="PASS",
            drift_detected=False,
        ),
        "runtime_cutover_run_result_schema_prep_only": _prep_only(
            base,
            role="runtime_cutover_run_result_schema_prep_only",
            purpose="Prepare future runtime cutover run result schema.",
        ),
        "post_cutover_evidence_review_packet_prep_only_draft": _prep_only(
            base,
            role="post_cutover_evidence_review_packet_prep_only_draft",
            purpose="Prepare post-cutover evidence review packet.",
        ),
        "cutover_failure_closeout_prep_only_draft": _prep_only(
            base,
            role="cutover_failure_closeout_prep_only_draft",
            purpose="Prepare cutover failure closeout path.",
        ),
        "forensic_cutover_review_prep_only_draft": _prep_only(
            base,
            role="forensic_cutover_review_prep_only_draft",
            purpose="Prepare forensic cutover review path.",
        ),
        "r6_opening_review_packet_prep_only_draft": _prep_only(
            base,
            role="r6_opening_review_packet_prep_only_draft",
            purpose="Prepare R6 opening review if later evidence justifies it.",
        ),
        "package_promotion_review_packet_prep_only_draft": _prep_only(
            base,
            role="package_promotion_review_packet_prep_only_draft",
            purpose="Prepare package-promotion review while keeping promotion blocked.",
        ),
        "external_audit_delta_manifest_prep_only": _prep_only(
            base,
            role="external_audit_delta_manifest_prep_only",
            purpose="Prepare external audit delta manifest.",
        ),
        "public_verifier_delta_requirements_prep_only": _prep_only(
            base,
            role="public_verifier_delta_requirements_prep_only",
            purpose="Prepare public verifier delta requirements.",
        ),
        "commercial_claim_boundary_update_prep_only": _prep_only(
            base,
            role="commercial_claim_boundary_update_prep_only",
            purpose="Prepare customer-safe claim boundary update.",
        ),
        "pipeline_board": _prep_only(
            base,
            role="pipeline_board",
            purpose="Update B04 R6 board for cutover execution packet authoring.",
            board_state={
                "runtime_cutover_authorization": "VALIDATED",
                "runtime_cutover_execution_packet": "BOUND_FOR_VALIDATION",
                "runtime_cutover": "UNEXECUTED",
                "r6": "CLOSED",
                "package_promotion": "BLOCKED",
            },
        ),
        "future_blocker_register": _prep_only(
            base,
            role="future_blocker_register",
            purpose="Track blockers after cutover execution packet authoring.",
            blockers=[
                "runtime_cutover_execution_packet_not_validated",
                "runtime_cutover_not_executed",
                "post_cutover_evidence_not_reviewed",
                "r6_opening_not_reviewed",
            ],
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_execution_packet.next_lawful_move.receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_NEXT_LAWFUL_MOVE_RECEIPT",
        ),
    }
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Runtime Cutover Execution Packet",
            "",
            f"Outcome: `{contract['selected_outcome']}`",
            f"Next lawful move: `{contract['next_lawful_move']}`",
            "",
            "This packet defines future runtime cutover execution law.",
            "It does not execute runtime cutover, does not open R6, does not promote package, and does not authorize commercial activation claims.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 runtime cutover execution packet authoring")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    packet_head = current_main_head if branch != "main" else head
    payloads, texts = _payloads_from_inputs(root)
    _validate_previous(payloads, texts)
    trust = validate_trust_zones(root=root)
    if trust.get("status") != "PASS":
        _fail("RC_B04R6_CUTOVER_EXEC_PACKET_TRUST_ZONE_FAILED", str(trust.get("failures", [])))
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=packet_head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
    )
    output_payloads = _output_payloads(base)
    contract = output_payloads["packet_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "packet_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=AUTHORITATIVE_LANE)
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
