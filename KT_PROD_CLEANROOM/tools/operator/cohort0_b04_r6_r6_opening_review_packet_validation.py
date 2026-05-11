from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_r6_opening_review_packet as review
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/b04-r6-r6-opening-review-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-r6-opening-review-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_R6_OPENING_REVIEW_PACKET_VALIDATION"
PREVIOUS_LANE = review.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = review.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = review.NEXT_LAWFUL_MOVE

SELECTED_OUTCOME = review.VALIDATION_SUCCESS_OUTCOME
NEXT_LAWFUL_MOVE = review.VALIDATION_SUCCESS_NEXT_MOVE
OUTCOME_LIMITED_CONTINUATION = "B04_R6_R6_OPENING_REVIEW_VALIDATED__LIMITED_CONTINUATION_PACKET_NEXT"
OUTCOME_ROLLBACK_FREEZE = "B04_R6_R6_OPENING_REVIEW_VALIDATED__ROLLBACK_FREEZE_PACKET_NEXT"
OUTCOME_EXTERNAL_AUDIT = "B04_R6_R6_OPENING_REVIEW_VALIDATED__EXTERNAL_AUDIT_DELTA_PACKET_NEXT"
OUTCOME_DEFERRED = "B04_R6_R6_OPENING_REVIEW_DEFERRED__NAMED_REVIEW_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_R6_OPENING_REVIEW_INVALID__FORENSIC_R6_OPENING_REVIEW_NEXT"

FORBIDDEN_ACTIONS = (
    "R6_OPEN",
    "R6_OPENING_AUTHORIZED",
    "R6_OPENING_EXECUTED",
    "GLOBAL_RUNTIME_SURFACE_AUTHORIZED",
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "METRIC_CONTRACT_MUTATED",
    "STATIC_COMPARATOR_WEAKENED",
    "OPENING_REVIEW_VALIDATION_TREATED_AS_R6_OPENING",
    "OPENING_REVIEW_VALIDATION_TREATED_AS_PACKAGE_PROMOTION",
)

AUTHORITY_DRIFT_KEYS = {
    "r6_open": "RC_B04R6_R6_OPENING_REVIEW_VAL_R6_OPEN_DRIFT",
    "r6_opening_authorized": "RC_B04R6_R6_OPENING_REVIEW_VAL_AUTHORIZATION_DRIFT",
    "r6_opening_executed": "RC_B04R6_R6_OPENING_REVIEW_VAL_EXECUTION_DRIFT",
    "global_runtime_surface_authorized": "RC_B04R6_R6_OPENING_REVIEW_VAL_GLOBAL_SURFACE_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_R6_OPENING_REVIEW_VAL_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_R6_OPENING_REVIEW_VAL_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_R6_OPENING_REVIEW_VAL_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_R6_OPENING_REVIEW_VAL_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_R6_OPENING_REVIEW_VAL_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_R6_OPENING_REVIEW_VAL_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_R6_OPENING_REVIEW_VAL_COMPARATOR_WEAKENED",
    "opening_review_treated_as_r6_opening": "RC_B04R6_R6_OPENING_REVIEW_VAL_R6_OPEN_DRIFT",
    "opening_review_treated_as_package_promotion": (
        "RC_B04R6_R6_OPENING_REVIEW_VAL_PACKAGE_PROMOTION_DRIFT"
    ),
}

CLAIM_BEARING_FIELD_MARKERS = (
    "authorization_state",
    "authority_state",
    "claim",
    "commercial",
    "package_promotion",
    "r6_status",
)
POSITIVE_AUTHORITY_TOKENS = (
    "AUTHORIZED",
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
    "RC_B04R6_R6_OPENING_REVIEW_VAL_PACKET_MISSING",
    "RC_B04R6_R6_OPENING_REVIEW_VAL_PACKET_OUTCOME_DRIFT",
    "RC_B04R6_R6_OPENING_REVIEW_VAL_NEXT_MOVE_DRIFT",
    "RC_B04R6_R6_OPENING_REVIEW_VAL_INPUT_HASH_MISSING",
    "RC_B04R6_R6_OPENING_REVIEW_VAL_INPUT_HASH_MALFORMED",
    "RC_B04R6_R6_OPENING_REVIEW_VAL_INVENTORY_MISSING",
    "RC_B04R6_R6_OPENING_REVIEW_VAL_SCORECARD_INCOMPLETE",
    "RC_B04R6_R6_OPENING_REVIEW_VAL_DECISION_MATRIX_UNJUSTIFIED",
    "RC_B04R6_R6_OPENING_REVIEW_VAL_READINESS_MATRIX_MISSING",
    "RC_B04R6_R6_OPENING_REVIEW_VAL_REVIEW_CONTRACT_MISSING",
    "RC_B04R6_R6_OPENING_REVIEW_VAL_PREP_ONLY_DRIFT",
    "RC_B04R6_R6_OPENING_REVIEW_VAL_CLAIM_TOKEN_DRIFT",
    "RC_B04R6_R6_OPENING_REVIEW_VAL_TRUST_ZONE_FAILED",
    *tuple(AUTHORITY_DRIFT_KEYS.values()),
)
REASON_CODES = tuple(dict.fromkeys(_REASON_CODES_RAW))

REVIEW_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in review.OUTPUTS.items()
    if filename.endswith(".json")
}
REVIEW_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in review.OUTPUTS.items()
    if not filename.endswith(".json")
}

VALIDATION_RECEIPT_ROLES = (
    "packet_binding_validation",
    "evidence_inventory_validation",
    "opening_review_scorecard_validation",
    "opening_decision_matrix_validation",
    "opening_authorization_readiness_validation",
    "limited_continuation_readiness_validation",
    "rollback_freeze_readiness_validation",
    "package_promotion_blocker_validation",
    "external_audit_delta_readiness_validation",
    "commercial_claim_ceiling_validation",
    "post_cutover_evidence_validation_review_validation",
    "r6_opening_readiness_review_validation",
    "scope_review_validation",
    "fallback_preservation_review_validation",
    "operator_control_review_validation",
    "kill_switch_review_validation",
    "rollback_review_validation",
    "drift_monitoring_review_validation",
    "incident_freeze_review_validation",
    "trace_replay_review_validation",
    "external_verifier_review_validation",
    "commercial_claim_boundary_review_validation",
    "package_promotion_blocker_review_validation",
    "prep_only_boundary_validation",
)

PREP_ONLY_OUTPUT_ROLES = (
    "r6_opening_authorization_validation_plan_prep_only",
    "r6_opening_execution_packet_prep_only_draft",
    "post_opening_evidence_review_validation_plan_prep_only",
    "rollback_freeze_validation_plan_prep_only",
    "external_audit_delta_validation_plan_prep_only",
    "package_promotion_review_validation_plan_prep_only",
    "commercial_activation_claim_validation_plan_prep_only",
)

OUTPUTS = {
    "validation_contract": "b04_r6_r6_opening_review_validation_contract.json",
    "validation_receipt": "b04_r6_r6_opening_review_validation_receipt.json",
    "validation_report": "b04_r6_r6_opening_review_validation_report.md",
    "packet_binding_validation": "b04_r6_r6_opening_review_packet_binding_validation_receipt.json",
    "evidence_inventory_validation": "b04_r6_r6_opening_evidence_inventory_validation_receipt.json",
    "opening_review_scorecard_validation": "b04_r6_r6_opening_review_scorecard_validation_receipt.json",
    "opening_decision_matrix_validation": "b04_r6_r6_opening_decision_matrix_validation_receipt.json",
    "opening_authorization_readiness_validation": (
        "b04_r6_r6_opening_authorization_readiness_validation_receipt.json"
    ),
    "limited_continuation_readiness_validation": (
        "b04_r6_r6_opening_limited_continuation_readiness_validation_receipt.json"
    ),
    "rollback_freeze_readiness_validation": (
        "b04_r6_r6_opening_rollback_freeze_readiness_validation_receipt.json"
    ),
    "package_promotion_blocker_validation": (
        "b04_r6_r6_opening_package_promotion_blocker_validation_receipt.json"
    ),
    "external_audit_delta_readiness_validation": (
        "b04_r6_r6_opening_external_audit_delta_readiness_validation_receipt.json"
    ),
    "commercial_claim_ceiling_validation": "b04_r6_r6_opening_commercial_claim_ceiling_validation_receipt.json",
    "post_cutover_evidence_validation_review_validation": (
        "b04_r6_r6_opening_post_cutover_evidence_validation_review_validation_receipt.json"
    ),
    "r6_opening_readiness_review_validation": (
        "b04_r6_r6_opening_readiness_review_validation_receipt.json"
    ),
    "scope_review_validation": "b04_r6_r6_opening_scope_review_validation_receipt.json",
    "fallback_preservation_review_validation": (
        "b04_r6_r6_opening_fallback_preservation_review_validation_receipt.json"
    ),
    "operator_control_review_validation": "b04_r6_r6_opening_operator_control_review_validation_receipt.json",
    "kill_switch_review_validation": "b04_r6_r6_opening_kill_switch_review_validation_receipt.json",
    "rollback_review_validation": "b04_r6_r6_opening_rollback_review_validation_receipt.json",
    "drift_monitoring_review_validation": "b04_r6_r6_opening_drift_monitoring_review_validation_receipt.json",
    "incident_freeze_review_validation": "b04_r6_r6_opening_incident_freeze_review_validation_receipt.json",
    "trace_replay_review_validation": "b04_r6_r6_opening_trace_replay_review_validation_receipt.json",
    "external_verifier_review_validation": (
        "b04_r6_r6_opening_external_verifier_review_validation_receipt.json"
    ),
    "commercial_claim_boundary_review_validation": (
        "b04_r6_r6_opening_commercial_claim_boundary_review_validation_receipt.json"
    ),
    "package_promotion_blocker_review_validation": (
        "b04_r6_r6_opening_package_promotion_blocker_review_validation_receipt.json"
    ),
    "prep_only_boundary_validation": "b04_r6_r6_opening_review_prep_only_boundary_validation_receipt.json",
    "no_authorization_drift_validation": (
        "b04_r6_r6_opening_review_no_authorization_drift_validation_receipt.json"
    ),
    "claim_token_boundary_validation": "b04_r6_r6_opening_review_claim_token_boundary_validation_receipt.json",
    "r6_opening_authorization_validation_plan_prep_only": (
        "b04_r6_r6_opening_authorization_validation_plan_prep_only.json"
    ),
    "r6_opening_execution_packet_prep_only_draft": (
        "b04_r6_r6_opening_validation_execution_packet_prep_only_draft.json"
    ),
    "post_opening_evidence_review_validation_plan_prep_only": (
        "b04_r6_post_opening_evidence_review_validation_plan_prep_only.json"
    ),
    "rollback_freeze_validation_plan_prep_only": "b04_r6_r6_opening_rollback_freeze_validation_plan_prep_only.json",
    "external_audit_delta_validation_plan_prep_only": (
        "b04_r6_r6_opening_external_audit_delta_validation_plan_prep_only.json"
    ),
    "package_promotion_review_validation_plan_prep_only": (
        "b04_r6_r6_opening_package_promotion_review_validation_plan_prep_only.json"
    ),
    "commercial_activation_claim_validation_plan_prep_only": (
        "b04_r6_commercial_activation_claim_validation_plan_prep_only.json"
    ),
    "pipeline_board": "b04_r6_r6_opening_review_validation_pipeline_board.json",
    "campaign_board": "b04_r6_r6_opening_review_validation_campaign_board.json",
    "future_blocker_register": "b04_r6_r6_opening_review_validation_future_blocker_register.json",
    "next_lawful_move": "b04_r6_r6_opening_review_validation_next_lawful_move_receipt.json",
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
            _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    try:
        payload = common.load_json_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_PACKET_MISSING", str(exc))
    if not isinstance(payload, dict):
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_PACKET_MISSING", f"{label} must be an object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_PACKET_MISSING", str(exc))


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in REVIEW_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in REVIEW_TEXT_INPUTS.items()}
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
                _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        for phrase in (
            "R6 IS OPEN",
            "R6 OPENED",
            "R6 OPENING AUTHORIZED",
            "PACKAGE PROMOTION AUTHORIZED",
            "COMMERCIAL ACTIVATION AUTHORIZED",
            "COMMERCIAL ACTIVATION CLAIM AUTHORIZED",
        ):
            if phrase in normalized:
                _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**REVIEW_JSON_INPUTS, **REVIEW_TEXT_INPUTS}.items()):
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": "file_sha256_at_r6_opening_review_validation",
            }
        )
    return rows


def _binding_hashes(root: Path) -> Dict[str, str]:
    return {f"{row['role']}_hash": row["sha256"] for row in _input_bindings(root)}


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["packet_contract"]
    receipt = payloads["packet_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_PACKET_MISSING", "packet contract lane drift")
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_PACKET_OUTCOME_DRIFT", "packet contract outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_PACKET_OUTCOME_DRIFT", "packet receipt outcome drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_NEXT_MOVE_DRIFT", "packet contract next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_NEXT_MOVE_DRIFT", "next-lawful-move receipt drift")


def _validate_hashes(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["packet_contract"]
    binding_hashes = contract.get("binding_hashes", {})
    input_bindings = contract.get("input_bindings")
    if not isinstance(binding_hashes, dict):
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_INPUT_HASH_MISSING", "packet missing binding_hashes")
    if not isinstance(input_bindings, list) or not input_bindings:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_INPUT_HASH_MISSING", "packet missing input_bindings")
    for row in input_bindings:
        if not isinstance(row, dict) or not _is_sha256(row.get("sha256")):
            _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_INPUT_HASH_MALFORMED", "malformed packet binding row")
        role = str(row.get("role", "")).strip()
        if binding_hashes.get(f"{role}_hash") != row["sha256"]:
            _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_INPUT_HASH_MISSING", f"binding hash mismatch for {role}")


def _validate_inventory(payloads: Dict[str, Dict[str, Any]]) -> None:
    inventory = payloads["evidence_inventory"].get("inventory", {})
    if inventory.get("previous_validated_outcome") != review.EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_INVENTORY_MISSING", "inventory predecessor drift")
    if not isinstance(inventory.get("input_bindings"), list) or not inventory["input_bindings"]:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_INVENTORY_MISSING", "inventory missing bindings")


def _validate_scorecard(payloads: Dict[str, Dict[str, Any]]) -> None:
    scorecard = payloads["opening_review_scorecard"].get("scorecard", {})
    required = {
        "post_cutover_evidence_review_validated": True,
        "runtime_cutover_passed": True,
        "fallbacks_preserved": True,
        "operator_controls_preserved": True,
        "kill_switch_ready": True,
        "rollback_ready": True,
        "drift_bounded": True,
        "incident_freeze_clean": True,
        "trace_replay_complete": True,
        "external_verifier_ready": True,
        "commercial_claim_boundary_preserved": True,
        "package_promotion_ready": False,
        "r6_open_ready": False,
        "recommendation_is_authority": False,
        "r6_opening_authorization_review_ready": True,
    }
    for key, expected in required.items():
        if scorecard.get(key) != expected:
            _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_SCORECARD_INCOMPLETE", f"scorecard.{key} drifted")
    if scorecard.get("overall_grade") != "A_READY_FOR_R6_OPENING_AUTHORIZATION_REVIEW":
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_SCORECARD_INCOMPLETE", "scorecard grade drift")


def _validate_decision_matrix(payloads: Dict[str, Dict[str, Any]]) -> None:
    matrix = payloads["opening_decision_matrix"].get("decision_matrix", {})
    if matrix.get("recommended_next_path") != review.RECOMMENDED_VALIDATED_PATH:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_DECISION_MATRIX_UNJUSTIFIED", "recommended path drift")
    if matrix.get("r6_opening_authorization_review_ready") is not True:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_DECISION_MATRIX_UNJUSTIFIED", "authorization packet not ready")
    if matrix.get("recommendation_is_authority") is not False:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_DECISION_MATRIX_UNJUSTIFIED", "recommendation became authority")
    if matrix.get("package_promotion_ready") is not False:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_DECISION_MATRIX_UNJUSTIFIED", "package promotion readiness drift")
    if matrix.get("commercial_claim_status") != "BOUNDARY_ONLY":
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_DECISION_MATRIX_UNJUSTIFIED", "commercial boundary drift")


def _validate_readiness(payloads: Dict[str, Dict[str, Any]]) -> None:
    if payloads["r6_opening_authorization_readiness_matrix"].get("r6_opening_authorization_ready") is not True:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_READINESS_MATRIX_MISSING", "authorization readiness drift")
    if payloads["r6_opening_authorization_readiness_matrix"].get("r6_opening_authorized") is not False:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_READINESS_MATRIX_MISSING", "authorization authority drift")
    if payloads["limited_continuation_readiness_matrix"].get("limited_continuation_ready") is not False:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_READINESS_MATRIX_MISSING", "limited continuation drift")
    if payloads["rollback_freeze_readiness_matrix"].get("rollback_freeze_ready") is not False:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_READINESS_MATRIX_MISSING", "rollback/freeze drift")
    if payloads["package_promotion_blocker_matrix"].get("package_promotion_ready") is not False:
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_READINESS_MATRIX_MISSING", "package promotion readiness drift")
    if payloads["external_audit_delta_readiness"].get("external_audit_delta_ready") != "READY_FOR_PACKET":
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_READINESS_MATRIX_MISSING", "external audit readiness drift")


def _validate_review_contracts(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in review.REVIEW_CONTRACT_ROLES:
        payload = payloads[role]
        if payload.get("review_status") != "PASS":
            _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_REVIEW_CONTRACT_MISSING", f"{role} did not pass")


def _validate_prep_only(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in review.PREP_ONLY_OUTPUT_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_PREP_ONLY_DRIFT", f"{role} is not PREP_ONLY")
        for key in (
            "cannot_open_r6",
            "cannot_authorize_package_promotion",
            "cannot_authorize_commercial_activation_claims",
        ):
            if payload.get(key) is not True:
                _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_PREP_ONLY_DRIFT", f"{role}.{key} drifted")


def _validate_report(text: str) -> None:
    lowered = text.lower()
    for phrase in ("does not open r6", "authorize package promotion", "commercial activation claims"):
        if phrase not in lowered:
            _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_REVIEW_CONTRACT_MISSING", f"report missing {phrase}")


def _validate_review_payloads(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _validate_handoff(payloads)
    _validate_hashes(payloads)
    _validate_inventory(payloads)
    _validate_scorecard(payloads)
    _validate_decision_matrix(payloads)
    _validate_readiness(payloads)
    _validate_review_contracts(payloads)
    _validate_prep_only(payloads)
    _validate_report(texts["packet_report"])
    _ensure_authority_closed(payloads, texts)
    for role, raw in REVIEW_JSON_INPUTS.items():
        if not _is_sha256(file_sha256(common.resolve_path(root, raw))):
            _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_INPUT_HASH_MALFORMED", f"{role} hash malformed")


def _guard() -> Dict[str, Any]:
    return {
        "runtime_cutover_executed": True,
        "post_cutover_evidence_review_validated": True,
        "r6_opening_review_packet_authored": True,
        "r6_opening_review_validated": True,
        "r6_opening_authorization_packet_next": True,
        "r6_opening_authorization_packet_authored": False,
        "r6_opening_authorized": False,
        "r6_opening_executed": False,
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
        "opening_review_validation_treated_as_r6_opening": False,
        "opening_review_validation_treated_as_package_promotion": False,
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
        "allowed_outcomes": [
            SELECTED_OUTCOME,
            OUTCOME_LIMITED_CONTINUATION,
            OUTCOME_ROLLBACK_FREEZE,
            OUTCOME_EXTERNAL_AUDIT,
            OUTCOME_DEFERRED,
            OUTCOME_INVALID,
        ],
        "outcome_routing": {
            SELECTED_OUTCOME: NEXT_LAWFUL_MOVE,
            OUTCOME_LIMITED_CONTINUATION: "AUTHOR_B04_R6_LIMITED_CONTINUATION_PACKET",
            OUTCOME_ROLLBACK_FREEZE: "AUTHOR_B04_R6_R6_OPENING_ROLLBACK_FREEZE_PACKET",
            OUTCOME_EXTERNAL_AUDIT: "AUTHOR_B04_R6_EXTERNAL_AUDIT_DELTA_PACKET",
            OUTCOME_DEFERRED: "REPAIR_B04_R6_R6_OPENING_REVIEW_VALIDATION_DEFECTS",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_R6_OPENING_REVIEW_PACKET",
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


def _validation_receipt(base: Dict[str, Any], *, role: str, source_roles: Sequence[str]) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.r6_opening_review.validation.{role}.v1",
        artifact_id=f"B04_R6_R6_OPENING_REVIEW_{role.upper()}_RECEIPT",
        validation_role=role,
        validation_status="PASS",
        source_roles=list(source_roles),
        validated_hashes={f"{source}_hash": base["binding_hashes"].get(f"{source}_hash") for source in source_roles},
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.r6_opening_review.validation.{role}.prep_only.v1",
        artifact_id=f"B04_R6_R6_OPENING_REVIEW_VALIDATION_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_open_r6=True,
        cannot_authorize_lobe_escalation=True,
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    payloads: Dict[str, Any] = {
        "validation_contract": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_review_validation_contract.v1",
            artifact_id="B04_R6_R6_OPENING_REVIEW_VALIDATION_CONTRACT",
            validation_summary=(
                "R6 opening review packet is complete, hash-bound, and sufficient only to author "
                "an R6 opening authorization packet."
            ),
        ),
        "validation_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_review_validation_receipt.v1",
            artifact_id="B04_R6_R6_OPENING_REVIEW_VALIDATION_RECEIPT",
            verdict="R6_OPENING_REVIEW_VALIDATED_R6_OPENING_AUTHORIZATION_PACKET_NEXT",
        ),
        "no_authorization_drift_validation": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_review.no_authorization_drift_validation_receipt.v1",
            artifact_id="B04_R6_R6_OPENING_REVIEW_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            no_authorization_drift=True,
        ),
        "claim_token_boundary_validation": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_review.claim_token_boundary_validation_receipt.v1",
            artifact_id="B04_R6_R6_OPENING_REVIEW_CLAIM_TOKEN_BOUNDARY_VALIDATION_RECEIPT",
            claim_bearing_authority_tokens_absent=True,
        ),
        "pipeline_board": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_review.validation.pipeline_board.v1",
            artifact_id="B04_R6_R6_OPENING_REVIEW_VALIDATION_PIPELINE_BOARD",
            board={
                "r6_opening_review_packet": "VALIDATED",
                "r6_opening_authorization_packet": "NEXT_AUTHORING_LANE",
                "r6_opening_execution": "BLOCKED",
                "r6": "CLOSED",
                "package_promotion": "BLOCKED",
                "commercial_activation_claims": "UNAUTHORIZED",
            },
        ),
        "campaign_board": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_review.validation.campaign_board.v1",
            artifact_id="B04_R6_R6_OPENING_REVIEW_VALIDATION_CAMPAIGN_BOARD",
            corridors=[
                {"corridor": "R6_OPENING", "status": "AUTHORIZATION_PACKET_NEXT"},
                {"corridor": "PACKAGE_PROMOTION", "status": "BLOCKED"},
                {"corridor": "COMMERCIAL_TRUTH_PLANE", "status": "BOUNDARY_ONLY"},
                {"corridor": "EXTERNAL_AUDIT", "status": "READY_FOR_PACKET"},
            ],
        ),
        "future_blocker_register": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_review.validation.future_blocker_register.v1",
            artifact_id="B04_R6_R6_OPENING_REVIEW_VALIDATION_FUTURE_BLOCKER_REGISTER",
            blockers=[
                "r6_opening_authorization_packet_not_authored_or_validated",
                "r6_opening_execution_packet_not_authored_or_validated",
                "post_opening_evidence_review_not_authored_or_validated",
                "package_promotion_requires_r6_opening_evidence_review_external_audit_and_package_review",
                "commercial_activation_claims_remain_forbidden",
            ],
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_review_validation_next_lawful_move_receipt.v1",
            artifact_id="B04_R6_R6_OPENING_REVIEW_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT",
            receipt_type="NEXT_LAWFUL_MOVE",
        ),
    }
    receipt_sources = {
        "packet_binding_validation": ("packet_contract", "packet_receipt"),
        "evidence_inventory_validation": ("evidence_inventory",),
        "opening_review_scorecard_validation": ("opening_review_scorecard",),
        "opening_decision_matrix_validation": ("opening_decision_matrix",),
        "opening_authorization_readiness_validation": ("r6_opening_authorization_readiness_matrix",),
        "limited_continuation_readiness_validation": ("limited_continuation_readiness_matrix",),
        "rollback_freeze_readiness_validation": ("rollback_freeze_readiness_matrix",),
        "package_promotion_blocker_validation": ("package_promotion_blocker_matrix",),
        "external_audit_delta_readiness_validation": ("external_audit_delta_readiness",),
        "commercial_claim_ceiling_validation": ("commercial_claim_ceiling_update",),
        "post_cutover_evidence_validation_review_validation": ("post_cutover_evidence_validation_review",),
        "r6_opening_readiness_review_validation": ("r6_opening_readiness_review",),
        "scope_review_validation": ("scope_review",),
        "fallback_preservation_review_validation": ("fallback_preservation_review",),
        "operator_control_review_validation": ("operator_control_review",),
        "kill_switch_review_validation": ("kill_switch_review",),
        "rollback_review_validation": ("rollback_review",),
        "drift_monitoring_review_validation": ("drift_monitoring_review",),
        "incident_freeze_review_validation": ("incident_freeze_review",),
        "trace_replay_review_validation": ("trace_replay_review",),
        "external_verifier_review_validation": ("external_verifier_review",),
        "commercial_claim_boundary_review_validation": ("commercial_claim_boundary_review",),
        "package_promotion_blocker_review_validation": ("package_promotion_blocker_review",),
        "prep_only_boundary_validation": tuple(review.PREP_ONLY_OUTPUT_ROLES),
    }
    for role, source_roles in receipt_sources.items():
        payloads[role] = _validation_receipt(base, role=role, source_roles=source_roles)
    prep_purposes = {
        "r6_opening_authorization_validation_plan_prep_only": (
            "Prepare validation law for the future R6 opening authorization packet."
        ),
        "r6_opening_execution_packet_prep_only_draft": (
            "Prepare execution packet shape; this draft does not open R6."
        ),
        "post_opening_evidence_review_validation_plan_prep_only": (
            "Prepare post-opening evidence review validation for later authority."
        ),
        "rollback_freeze_validation_plan_prep_only": (
            "Prepare rollback/freeze validation if later evidence routes there."
        ),
        "external_audit_delta_validation_plan_prep_only": (
            "Prepare external audit delta validation for later authority."
        ),
        "package_promotion_review_validation_plan_prep_only": (
            "Track package-promotion validation preconditions; promotion remains blocked."
        ),
        "commercial_activation_claim_validation_plan_prep_only": (
            "Track commercial claim validation preconditions; commercial activation remains unauthorized."
        ),
    }
    payloads.update({role: _prep_only(base, role=role, purpose=prep_purposes[role]) for role in PREP_ONLY_OUTPUT_ROLES})
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 R6 Opening Review Validation",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "The R6 opening review packet validates as complete, hash-bound, and evidence-supported.",
            "The validated recommendation permits only R6 opening authorization packet authorship.",
            "",
            "This validation does not open R6, does not authorize R6 opening execution,",
            "does not authorize lobe escalation, does not promote package, and does not authorize",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 R6 opening review validation")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_review_payloads(root, payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_R6_OPENING_REVIEW_VAL_TRUST_ZONE_FAILED", "trust-zone validation failed")
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
    parser = argparse.ArgumentParser(description="Validate the B04 R6 R6 opening review packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
