from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_runtime_cutover_review_packet_validation as review_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-runtime-cutover-authorization-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-runtime-cutover-authorization-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_PACKET"
PREVIOUS_LANE = review_validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = review_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = review_validation.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = "B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_PACKET_BOUND__RUNTIME_CUTOVER_AUTHORIZATION_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_PACKET_INVALID__FORENSIC_CUTOVER_AUTHORIZATION_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_PACKET"

VALIDATION_SUCCESS_OUTCOME = "B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_VALIDATED__RUNTIME_CUTOVER_EXECUTION_PACKET_NEXT"
VALIDATION_OUTCOMES_PREPARED = (
    VALIDATION_SUCCESS_OUTCOME,
    "B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS",
    "B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_REJECTED__CUTOVER_NOT_JUSTIFIED",
    "B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_INVALID__FORENSIC_CUTOVER_AUTHORIZATION_REVIEW_NEXT",
)

FORBIDDEN_ACTIONS = (
    "RUNTIME_CUTOVER_EXECUTED",
    "ACTIVATION_CUTOVER_EXECUTED",
    "RUNTIME_CUTOVER_AUTHORIZED_AS_EXECUTED",
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
    "runtime_cutover_executed": "RC_B04R6_CUTOVER_AUTH_RUNTIME_CUTOVER_EXECUTED",
    "activation_cutover_executed": "RC_B04R6_CUTOVER_AUTH_ACTIVATION_CUTOVER_EXECUTED",
    "r6_open": "RC_B04R6_CUTOVER_AUTH_R6_OPEN_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_CUTOVER_AUTH_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_CUTOVER_AUTH_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_CUTOVER_AUTH_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_CUTOVER_AUTH_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_CUTOVER_AUTH_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_CUTOVER_AUTH_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_CUTOVER_AUTH_COMPARATOR_WEAKENED",
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
    "ACTIVE",
    "ENABLED",
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
    "PREP_ONLY",
    "PROHIBITED",
    "REMAINS UNAUTHORIZED",
    "REMAINS_CLOSED",
    "REVIEW_PACKET",
    "STILL_BLOCKED",
    "UNAUTHORIZED",
)

_REASON_CODES_RAW = (
    "RC_B04R6_CUTOVER_AUTH_PREVIOUS_VALIDATION_MISSING",
    "RC_B04R6_CUTOVER_AUTH_PREVIOUS_OUTCOME_DRIFT",
    "RC_B04R6_CUTOVER_AUTH_NEXT_MOVE_DRIFT",
    "RC_B04R6_CUTOVER_AUTH_INPUT_HASH_MISSING",
    "RC_B04R6_CUTOVER_AUTH_INPUT_HASH_MALFORMED",
    "RC_B04R6_CUTOVER_AUTH_REVIEW_VALIDATION_INCOMPLETE",
    "RC_B04R6_CUTOVER_AUTH_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_CUTOVER_AUTH_CLAIM_TOKEN_DRIFT",
    "RC_B04R6_CUTOVER_AUTH_TRUST_ZONE_FAILED",
    *tuple(AUTHORITY_DRIFT_KEYS.values()),
)
REASON_CODES = tuple(dict.fromkeys(_REASON_CODES_RAW))

VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in review_validation.OUTPUTS.items()
    if filename.endswith(".json")
}
VALIDATION_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in review_validation.OUTPUTS.items()
    if not filename.endswith(".json")
}

CONTROL_CONTRACT_ROLES = (
    "scope_contract",
    "allowed_surface_contract",
    "excluded_surface_contract",
    "traffic_limit_contract",
    "static_fallback_contract",
    "abstention_fallback_contract",
    "null_route_preservation_contract",
    "operator_override_contract",
    "kill_switch_contract",
    "rollback_contract",
    "monitoring_window_contract",
    "route_distribution_thresholds",
    "drift_thresholds",
    "incident_freeze_contract",
    "runtime_receipt_schema",
    "external_verifier_requirements",
    "commercial_claim_boundary",
    "package_promotion_prohibition_receipt",
)
AUTHORITATIVE_OUTPUT_ROLES = (
    "packet_contract",
    "packet_receipt",
    *CONTROL_CONTRACT_ROLES,
    "validation_plan",
    "validation_reason_codes",
    "no_authorization_drift_receipt",
    "next_lawful_move",
)
PREP_ONLY_OUTPUT_ROLES = (
    "runtime_cutover_execution_packet_prep_only_draft",
    "runtime_cutover_execution_validation_plan_prep_only",
    "post_cutover_evidence_review_packet_prep_only_draft",
    "rollback_freeze_incident_path_prep_only",
    "external_audit_delta_prep_only_draft",
    "commercial_claim_ceiling_update_prep_only",
    "package_promotion_blocker_update_prep_only",
    "pipeline_board",
    "future_blocker_register",
)

OUTPUTS = {
    "packet_contract": "b04_r6_runtime_cutover_authorization_packet_contract.json",
    "packet_receipt": "b04_r6_runtime_cutover_authorization_packet_receipt.json",
    "packet_report": "b04_r6_runtime_cutover_authorization_packet_report.md",
    "scope_contract": "b04_r6_runtime_cutover_authorization_scope_contract.json",
    "allowed_surface_contract": "b04_r6_runtime_cutover_authorization_allowed_surface_contract.json",
    "excluded_surface_contract": "b04_r6_runtime_cutover_authorization_excluded_surface_contract.json",
    "traffic_limit_contract": "b04_r6_runtime_cutover_authorization_traffic_limit_contract.json",
    "static_fallback_contract": "b04_r6_runtime_cutover_authorization_static_fallback_contract.json",
    "abstention_fallback_contract": "b04_r6_runtime_cutover_authorization_abstention_fallback_contract.json",
    "null_route_preservation_contract": "b04_r6_runtime_cutover_authorization_null_route_preservation_contract.json",
    "operator_override_contract": "b04_r6_runtime_cutover_authorization_operator_override_contract.json",
    "kill_switch_contract": "b04_r6_runtime_cutover_authorization_kill_switch_contract.json",
    "rollback_contract": "b04_r6_runtime_cutover_authorization_rollback_contract.json",
    "monitoring_window_contract": "b04_r6_runtime_cutover_authorization_monitoring_window_contract.json",
    "route_distribution_thresholds": "b04_r6_runtime_cutover_authorization_route_distribution_thresholds.json",
    "drift_thresholds": "b04_r6_runtime_cutover_authorization_drift_thresholds.json",
    "incident_freeze_contract": "b04_r6_runtime_cutover_authorization_incident_freeze_contract.json",
    "runtime_receipt_schema": "b04_r6_runtime_cutover_authorization_runtime_receipt_schema.json",
    "external_verifier_requirements": "b04_r6_runtime_cutover_authorization_external_verifier_requirements.json",
    "commercial_claim_boundary": "b04_r6_runtime_cutover_authorization_commercial_claim_boundary.json",
    "package_promotion_prohibition_receipt": (
        "b04_r6_runtime_cutover_authorization_package_promotion_prohibition_receipt.json"
    ),
    "validation_plan": "b04_r6_runtime_cutover_authorization_validation_plan.json",
    "validation_reason_codes": "b04_r6_runtime_cutover_authorization_validation_reason_codes.json",
    "no_authorization_drift_receipt": "b04_r6_runtime_cutover_authorization_no_authorization_drift_receipt.json",
    "runtime_cutover_execution_packet_prep_only_draft": (
        "b04_r6_runtime_cutover_authorization_execution_packet_prep_only_draft.json"
    ),
    "runtime_cutover_execution_validation_plan_prep_only": (
        "b04_r6_runtime_cutover_authorization_execution_validation_plan_prep_only.json"
    ),
    "post_cutover_evidence_review_packet_prep_only_draft": (
        "b04_r6_post_cutover_evidence_review_packet_prep_only_draft.json"
    ),
    "rollback_freeze_incident_path_prep_only": (
        "b04_r6_runtime_cutover_authorization_rollback_freeze_incident_path_prep_only.json"
    ),
    "external_audit_delta_prep_only_draft": (
        "b04_r6_runtime_cutover_authorization_external_audit_delta_prep_only_draft.json"
    ),
    "commercial_claim_ceiling_update_prep_only": (
        "b04_r6_runtime_cutover_authorization_commercial_claim_ceiling_update_prep_only.json"
    ),
    "package_promotion_blocker_update_prep_only": (
        "b04_r6_runtime_cutover_authorization_package_promotion_blocker_update_prep_only.json"
    ),
    "pipeline_board": "b04_r6_runtime_cutover_authorization_pipeline_board.json",
    "future_blocker_register": "b04_r6_runtime_cutover_authorization_future_blocker_register.json",
    "next_lawful_move": "b04_r6_runtime_cutover_authorization_next_lawful_move_receipt.json",
}


class LaneFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise LaneFailure(code, detail)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_B04R6_CUTOVER_AUTH_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_CUTOVER_AUTH_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    try:
        return common.load_json_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_CUTOVER_AUTH_PREVIOUS_VALIDATION_MISSING", str(exc))


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_CUTOVER_AUTH_PREVIOUS_VALIDATION_MISSING", str(exc))


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in VALIDATION_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in VALIDATION_TEXT_INPUTS.items()}
    return payloads, texts


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk_items(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_items(item)


def _is_claim_bearing_field(key: str) -> bool:
    lowered = key.lower()
    if lowered == "r6":
        return True
    return any(marker in lowered for marker in CLAIM_BEARING_FIELD_MARKERS)


def _contains_positive_authority_token(value: str) -> bool:
    normalized = value.upper().replace("-", "_")
    if any(qualifier in normalized for qualifier in NEGATIVE_AUTHORITY_QUALIFIERS):
        return False
    return any(token in normalized for token in POSITIVE_AUTHORITY_TOKENS)


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk_items(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted non-false")
            if _is_claim_bearing_field(key) and isinstance(value, str) and _contains_positive_authority_token(value):
                _fail("RC_B04R6_CUTOVER_AUTH_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        for phrase in (
            "RUNTIME CUTOVER EXECUTED",
            "CUTOVER EXECUTED",
            "R6 OPEN",
            "PACKAGE PROMOTION AUTHORIZED",
            "COMMERCIAL ACTIVATION AUTHORIZED",
            "COMMERCIAL ACTIVATION CLAIM AUTHORIZED",
        ):
            if phrase in normalized:
                _fail("RC_B04R6_CUTOVER_AUTH_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**VALIDATION_JSON_INPUTS, **VALIDATION_TEXT_INPUTS}.items()):
        path = common.resolve_path(root, raw)
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(path),
                "binding_kind": "file_sha256_at_runtime_cutover_authorization_packet_authoring",
            }
        )
    return rows


def _binding_hashes(root: Path) -> Dict[str, str]:
    return {f"{row['role']}_hash": row["sha256"] for row in _input_bindings(root)}


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["validation_contract"]
    receipt = payloads["validation_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_CUTOVER_AUTH_PREVIOUS_OUTCOME_DRIFT", "validation contract outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_CUTOVER_AUTH_PREVIOUS_OUTCOME_DRIFT", "validation receipt outcome drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_CUTOVER_AUTH_NEXT_MOVE_DRIFT", "validation contract next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_CUTOVER_AUTH_NEXT_MOVE_DRIFT", "next-lawful-move receipt drift")
    if contract.get("runtime_cutover_authorization_packet_next") is not True:
        _fail("RC_B04R6_CUTOVER_AUTH_REVIEW_VALIDATION_INCOMPLETE", "authorization packet next flag missing")


def _validate_hashes(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["validation_contract"]
    binding_hashes = contract.get("binding_hashes", {})
    if not isinstance(binding_hashes, dict):
        _fail("RC_B04R6_CUTOVER_AUTH_INPUT_HASH_MISSING", "validation missing binding_hashes")
    input_bindings = contract.get("input_bindings")
    if not isinstance(input_bindings, list) or not input_bindings:
        _fail("RC_B04R6_CUTOVER_AUTH_INPUT_HASH_MISSING", "validation missing input_bindings")
    for row in input_bindings:
        if not isinstance(row, dict) or not _is_sha256(row.get("sha256")):
            _fail("RC_B04R6_CUTOVER_AUTH_INPUT_HASH_MALFORMED", "malformed validation binding row")
        role = str(row.get("role", "")).strip()
        if binding_hashes.get(f"{role}_hash") != row["sha256"]:
            _fail("RC_B04R6_CUTOVER_AUTH_INPUT_HASH_MISSING", f"binding hash mismatch for {role}")


def _validate_validation_receipts(payloads: Dict[str, Dict[str, Any]]) -> None:
    required_pass = (
        "packet_binding_validation",
        "decision_matrix_validation",
        "commercial_claim_boundary_validation",
        "package_promotion_blocker_validation",
        "prep_only_boundary_validation",
    )
    for role in required_pass:
        if payloads[role].get("validation_status") != "PASS":
            _fail("RC_B04R6_CUTOVER_AUTH_REVIEW_VALIDATION_INCOMPLETE", f"{role} did not pass")
    if payloads["no_authorization_drift_validation"].get("no_authorization_drift") is not True:
        _fail("RC_B04R6_CUTOVER_AUTH_REVIEW_VALIDATION_INCOMPLETE", "no authorization drift validation missing")
    if payloads["claim_token_boundary_validation"].get("claim_bearing_authority_tokens_absent") is not True:
        _fail("RC_B04R6_CUTOVER_AUTH_REVIEW_VALIDATION_INCOMPLETE", "claim token validation missing")


def _validate_validation_payloads(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _validate_handoff(payloads)
    _validate_hashes(payloads)
    _validate_validation_receipts(payloads)
    _ensure_authority_closed(payloads, texts)
    for role, raw in VALIDATION_JSON_INPUTS.items():
        if not _is_sha256(file_sha256(common.resolve_path(root, raw))):
            _fail("RC_B04R6_CUTOVER_AUTH_INPUT_HASH_MALFORMED", f"{role} hash malformed")


def _guard() -> Dict[str, Any]:
    return {
        "runtime_cutover_review_validated": True,
        "runtime_cutover_authorization_packet_authored": True,
        "runtime_cutover_authorization_validated": False,
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
        "cannot_execute_runtime_cutover": True,
        "cannot_open_r6": True,
        "cannot_authorize_lobe_escalation": True,
        "cannot_authorize_package_promotion": True,
        "cannot_authorize_commercial_activation_claims": True,
        "cannot_mutate_truth_engine_law": True,
        "cannot_mutate_trust_zone_law": True,
    }


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
        "validation_success_outcome": VALIDATION_SUCCESS_OUTCOME,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "validation_outcomes_prepared": list(VALIDATION_OUTCOMES_PREPARED),
        "outcome_routing": {
            OUTCOME_BOUND: NEXT_LAWFUL_MOVE,
            OUTCOME_DEFERRED: "REPAIR_B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_PACKET_DEFECTS",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_CUTOVER_AUTHORIZATION_REVIEW_PACKET",
        },
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        **_guard(),
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _control_contract(base: Dict[str, Any], role: str, *, purpose: str, **extra: Any) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_cutover_authorization.{role}.v1",
        artifact_id=f"B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_{role.upper()}",
        control_role=role,
        purpose=purpose,
        control_status="DEFINED_FOR_VALIDATION",
        does_not_execute_runtime_cutover=True,
        requires_future_validation=NEXT_LAWFUL_MOVE,
        **extra,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str, **extra: Any) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_cutover_authorization.{role}.prep_only.v1",
        artifact_id=f"B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_execute_runtime_cutover=True,
        cannot_open_r6=True,
        cannot_authorize_lobe_escalation=True,
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
        **extra,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    payloads: Dict[str, Any] = {
        "packet_contract": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_authorization_packet_contract.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_PACKET_CONTRACT",
            authorization_packet_summary=(
                "Defines bounded runtime cutover authorization law for validation. "
                "It does not execute runtime cutover or open R6."
            ),
        ),
        "packet_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_authorization_packet_receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_PACKET_RECEIPT",
            receipt_type="RUNTIME_CUTOVER_AUTHORIZATION_PACKET_BOUND",
            verdict="BOUND_FOR_RUNTIME_CUTOVER_AUTHORIZATION_VALIDATION_ONLY",
        ),
        "scope_contract": _control_contract(
            base,
            "scope_contract",
            purpose="Define the bounded runtime cutover authorization scope.",
            cutover_authorization_scope="B04_R6_BOUNDED_RUNTIME_CUTOVER_REVIEW_SCOPE",
        ),
        "allowed_surface_contract": _control_contract(
            base,
            "allowed_surface_contract",
            purpose="Define allowed cutover surfaces for validation.",
            allowed_surfaces=["B04_R6_ROUTER_DECISION_SURFACE_BOUNDED", "STATIC_FALLBACK_PROTECTED_SURFACE"],
        ),
        "excluded_surface_contract": _control_contract(
            base,
            "excluded_surface_contract",
            purpose="Define surfaces excluded from cutover authorization.",
            excluded_surfaces=[
                "GLOBAL_RUNTIME_SURFACE",
                "COMMERCIAL_ACTIVATION_SURFACE",
                "PACKAGE_PROMOTION_SURFACE",
                "LOBE_ESCALATION_SURFACE",
            ],
        ),
        "traffic_limit_contract": _control_contract(
            base,
            "traffic_limit_contract",
            purpose="Define bounded traffic and case limits for any future cutover execution packet.",
            max_traffic_percent="BOUNDED_BY_FUTURE_EXECUTION_PACKET",
            max_case_classes="B04_R6_VALIDATED_ROUTER_CASE_CLASSES_ONLY",
        ),
        "static_fallback_contract": _control_contract(
            base,
            "static_fallback_contract",
            purpose="Require static fallback preservation.",
            static_fallback_required=True,
        ),
        "abstention_fallback_contract": _control_contract(
            base,
            "abstention_fallback_contract",
            purpose="Require abstention fallback preservation.",
            abstention_fallback_required=True,
        ),
        "null_route_preservation_contract": _control_contract(
            base,
            "null_route_preservation_contract",
            purpose="Require null-route preservation.",
            null_route_preservation_required=True,
        ),
        "operator_override_contract": _control_contract(
            base,
            "operator_override_contract",
            purpose="Require operator override readiness.",
            operator_override_required=True,
        ),
        "kill_switch_contract": _control_contract(
            base,
            "kill_switch_contract",
            purpose="Require kill-switch readiness.",
            kill_switch_required=True,
        ),
        "rollback_contract": _control_contract(
            base,
            "rollback_contract",
            purpose="Require rollback execution plan for future execution packet.",
            rollback_required=True,
        ),
        "monitoring_window_contract": _control_contract(
            base,
            "monitoring_window_contract",
            purpose="Define monitoring window requirements.",
            monitoring_window_required=True,
        ),
        "route_distribution_thresholds": _control_contract(
            base,
            "route_distribution_thresholds",
            purpose="Define route-distribution thresholds.",
            thresholds_defined=True,
        ),
        "drift_thresholds": _control_contract(
            base,
            "drift_thresholds",
            purpose="Define drift thresholds.",
            thresholds_defined=True,
        ),
        "incident_freeze_contract": _control_contract(
            base,
            "incident_freeze_contract",
            purpose="Define incident and freeze conditions.",
            incident_freeze_required=True,
        ),
        "runtime_receipt_schema": _control_contract(
            base,
            "runtime_receipt_schema",
            purpose="Define required runtime receipt schema for future execution.",
            receipt_schema_required=True,
        ),
        "external_verifier_requirements": _control_contract(
            base,
            "external_verifier_requirements",
            purpose="Define external verifier requirements.",
            external_verifier_required=True,
        ),
        "commercial_claim_boundary": _control_contract(
            base,
            "commercial_claim_boundary",
            purpose="Preserve commercial claim boundary.",
            allowed_claims=[
                "Runtime cutover authorization packet is authored for validation.",
                "Runtime cutover remains unexecuted.",
                "R6 remains closed.",
            ],
            forbidden_claims=[
                "Runtime cutover executed.",
                "R6 is open.",
                "Package promotion authorized.",
                "Commercial activation authorized.",
            ],
        ),
        "package_promotion_prohibition_receipt": _control_contract(
            base,
            "package_promotion_prohibition_receipt",
            purpose="Prohibit package promotion from this packet.",
            package_promotion_prohibited=True,
        ),
        "validation_plan": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_authorization_validation_plan.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_VALIDATION_PLAN",
            validation_targets=list(AUTHORITATIVE_OUTPUT_ROLES),
            validation_outcomes_prepared=list(VALIDATION_OUTCOMES_PREPARED),
        ),
        "validation_reason_codes": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_authorization_validation_reason_codes.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
        ),
        "no_authorization_drift_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_authorization.no_authorization_drift_receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_NO_AUTHORIZATION_DRIFT_RECEIPT",
            no_authorization_drift=True,
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_authorization_next_lawful_move_receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_AUTHORIZATION_NEXT_LAWFUL_MOVE_RECEIPT",
            receipt_type="NEXT_LAWFUL_MOVE",
        ),
    }
    payloads.update(
        {
            "runtime_cutover_execution_packet_prep_only_draft": _prep_only(
                base,
                role="runtime_cutover_execution_packet_prep_only_draft",
                purpose="Prepare a future runtime cutover execution packet; does not execute cutover.",
            ),
            "runtime_cutover_execution_validation_plan_prep_only": _prep_only(
                base,
                role="runtime_cutover_execution_validation_plan_prep_only",
                purpose="Prepare validation plan for a future execution packet.",
            ),
            "post_cutover_evidence_review_packet_prep_only_draft": _prep_only(
                base,
                role="post_cutover_evidence_review_packet_prep_only_draft",
                purpose="Prepare post-cutover evidence review structure.",
            ),
            "rollback_freeze_incident_path_prep_only": _prep_only(
                base,
                role="rollback_freeze_incident_path_prep_only",
                purpose="Prepare rollback, freeze, and incident closeout paths.",
            ),
            "external_audit_delta_prep_only_draft": _prep_only(
                base,
                role="external_audit_delta_prep_only_draft",
                purpose="Prepare external audit delta material.",
            ),
            "commercial_claim_ceiling_update_prep_only": _prep_only(
                base,
                role="commercial_claim_ceiling_update_prep_only",
                purpose="Update claim ceiling without authorizing commercial activation.",
                claim_ceiling="RUNTIME_CUTOVER_AUTHORIZATION_PACKET_AUTHORED_ONLY",
            ),
            "package_promotion_blocker_update_prep_only": _prep_only(
                base,
                role="package_promotion_blocker_update_prep_only",
                purpose="Update package promotion blockers.",
                blockers=[
                    "runtime_cutover_authorization_not_validated",
                    "runtime_cutover_execution_not_authored_or_validated",
                    "post_cutover_evidence_not_reviewed",
                    "external_audit_delta_not_validated",
                ],
            ),
            "pipeline_board": _prep_only(
                base,
                role="pipeline_board",
                purpose="Update B04 R6 board for runtime cutover authorization packet authoring.",
                board={
                    "runtime_cutover_review": "VALIDATED",
                    "runtime_cutover_authorization_packet": "BOUND",
                    "runtime_cutover_authorization_validation": "NEXT",
                    "runtime_cutover_execution_packet": "PREP_ONLY",
                    "runtime_cutover": "UNEXECUTED",
                    "r6": "CLOSED",
                    "package_promotion": "BLOCKED",
                    "commercial_activation_claims": "UNAUTHORIZED",
                },
            ),
            "future_blocker_register": _prep_only(
                base,
                role="future_blocker_register",
                purpose="Track blockers after runtime cutover authorization packet authoring.",
                blockers=[
                    "runtime_cutover_authorization_validation_not_complete",
                    "runtime_cutover_execution_packet_not_authored_or_validated",
                    "runtime_cutover_not_executed",
                    "post_cutover_evidence_review_not_authored",
                    "package_promotion_remains_blocked",
                    "commercial_activation_claims_remain_forbidden",
                ],
            ),
        }
    )
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Runtime Cutover Authorization Packet",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "The runtime cutover authorization packet is authored for validation.",
            "It defines bounded scope, excluded surfaces, fallbacks, operator controls, kill switch, rollback, monitoring,",
            "drift thresholds, incident/freeze conditions, receipt schema, external verifier requirements, and claim boundaries.",
            "",
            "This packet does not execute runtime cutover, does not open R6, does not authorize lobe escalation,",
            "does not promote package, and does not authorize commercial activation claims.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 runtime cutover authorization packet authoring")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    # Branch commits may be squash-merged away; branch-authored packets bind the
    # canonical source base, while main replays bind the post-merge main head.
    packet_head = current_main_head if branch != "main" else head
    payloads, texts = _payloads(root)
    _validate_validation_payloads(root, payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_CUTOVER_AUTH_TRUST_ZONE_FAILED", "trust-zone validation failed")
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=packet_head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
        binding_hashes=_binding_hashes(root),
        trust_zone_validation=trust_zone_validation,
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
    parser = argparse.ArgumentParser(description="Author the B04 R6 runtime cutover authorization packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
