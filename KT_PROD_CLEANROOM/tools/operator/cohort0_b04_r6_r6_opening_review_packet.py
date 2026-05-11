from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from tools.operator import cohort0_b04_r6_post_cutover_evidence_review_packet_validation as prior
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/b04-r6-r6-opening-review-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-r6-opening-review-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_R6_OPENING_REVIEW_PACKET"
PREVIOUS_LANE = prior.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = prior.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = prior.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = "B04_R6_R6_OPENING_REVIEW_PACKET_BOUND__R6_OPENING_REVIEW_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_R6_OPENING_REVIEW_PACKET_DEFERRED__NAMED_REVIEW_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_R6_OPENING_REVIEW_PACKET_INVALID__FORENSIC_R6_OPENING_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_R6_OPENING_REVIEW_PACKET"

RECOMMENDED_VALIDATED_PATH = "R6_OPENING_AUTHORIZATION_PACKET_NEXT"
VALIDATION_SUCCESS_OUTCOME = "B04_R6_R6_OPENING_REVIEW_VALIDATED__R6_OPENING_AUTHORIZATION_PACKET_NEXT"
VALIDATION_SUCCESS_NEXT_MOVE = "AUTHOR_B04_R6_R6_OPENING_AUTHORIZATION_PACKET"

FORBIDDEN_ACTIONS = (
    "R6_OPEN",
    "R6_OPENING_AUTHORIZED",
    "GLOBAL_RUNTIME_SURFACE_AUTHORIZED",
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "METRIC_CONTRACT_MUTATED",
    "STATIC_COMPARATOR_WEAKENED",
    "OPENING_REVIEW_TREATED_AS_R6_OPENING",
    "OPENING_REVIEW_TREATED_AS_PACKAGE_PROMOTION",
)

AUTHORITY_DRIFT_KEYS = {
    "r6_open": "RC_B04R6_R6_OPENING_REVIEW_R6_OPEN_DRIFT",
    "r6_opening_authorized": "RC_B04R6_R6_OPENING_REVIEW_AUTHORIZATION_DRIFT",
    "global_runtime_surface_authorized": "RC_B04R6_R6_OPENING_REVIEW_GLOBAL_SURFACE_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_R6_OPENING_REVIEW_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_R6_OPENING_REVIEW_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_R6_OPENING_REVIEW_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_R6_OPENING_REVIEW_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_R6_OPENING_REVIEW_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_R6_OPENING_REVIEW_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_R6_OPENING_REVIEW_COMPARATOR_WEAKENED",
    "opening_review_treated_as_r6_opening": "RC_B04R6_R6_OPENING_REVIEW_R6_OPEN_DRIFT",
    "opening_review_treated_as_package_promotion": "RC_B04R6_R6_OPENING_REVIEW_PACKAGE_PROMOTION_DRIFT",
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

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_R6_OPENING_REVIEW_PREVIOUS_VALIDATION_MISSING",
            "RC_B04R6_R6_OPENING_REVIEW_PREVIOUS_OUTCOME_DRIFT",
            "RC_B04R6_R6_OPENING_REVIEW_NEXT_MOVE_DRIFT",
            "RC_B04R6_R6_OPENING_REVIEW_INPUT_HASH_MISSING",
            "RC_B04R6_R6_OPENING_REVIEW_INPUT_HASH_MALFORMED",
            "RC_B04R6_R6_OPENING_REVIEW_SCORECARD_INCOMPLETE",
            "RC_B04R6_R6_OPENING_REVIEW_DECISION_MATRIX_UNLAWFUL",
            "RC_B04R6_R6_OPENING_REVIEW_CONTRACT_MISSING",
            "RC_B04R6_R6_OPENING_REVIEW_PREP_ONLY_DRIFT",
            "RC_B04R6_R6_OPENING_REVIEW_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_R6_OPENING_REVIEW_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

PRIOR_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in prior.OUTPUTS.items()
    if filename.endswith(".json")
}
PRIOR_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in prior.OUTPUTS.items()
    if not filename.endswith(".json")
}
SOURCE_REVIEW_JSON_INPUTS = {
    f"source_{role}": raw for role, raw in prior.REVIEW_JSON_INPUTS.items()
}
SOURCE_REVIEW_TEXT_INPUTS = {
    f"source_{role}": raw for role, raw in prior.REVIEW_TEXT_INPUTS.items()
}

REVIEW_CONTRACT_ROLES = (
    "post_cutover_evidence_validation_review",
    "r6_opening_readiness_review",
    "scope_review",
    "fallback_preservation_review",
    "operator_control_review",
    "kill_switch_review",
    "rollback_review",
    "drift_monitoring_review",
    "incident_freeze_review",
    "trace_replay_review",
    "external_verifier_review",
    "commercial_claim_boundary_review",
    "package_promotion_blocker_review",
)
AUTHORITATIVE_OUTPUT_ROLES = (
    "packet_contract",
    "packet_receipt",
    "evidence_inventory",
    "opening_review_scorecard",
    "opening_decision_matrix",
    "r6_opening_authorization_readiness_matrix",
    "limited_continuation_readiness_matrix",
    "rollback_freeze_readiness_matrix",
    "package_promotion_blocker_matrix",
    "external_audit_delta_readiness",
    "commercial_claim_ceiling_update",
    *REVIEW_CONTRACT_ROLES,
    "no_authorization_drift_receipt",
    "next_lawful_move",
)
PREP_ONLY_OUTPUT_ROLES = (
    "validation_plan",
    "validation_reason_codes",
    "r6_opening_authorization_packet_prep_only_draft",
    "r6_opening_execution_packet_prep_only_draft",
    "post_opening_evidence_review_packet_prep_only_draft",
    "limited_continuation_packet_prep_only_draft",
    "rollback_freeze_packet_prep_only_draft",
    "external_audit_delta_packet_prep_only_draft",
    "package_promotion_review_preconditions_prep_only_draft",
    "commercial_activation_claim_review_prep_only_draft",
    "pipeline_board",
    "campaign_board",
    "future_blocker_register",
)

OUTPUTS = {
    "packet_contract": "b04_r6_r6_opening_review_packet_contract.json",
    "packet_receipt": "b04_r6_r6_opening_review_packet_receipt.json",
    "packet_report": "b04_r6_r6_opening_review_packet_report.md",
    "evidence_inventory": "b04_r6_r6_opening_evidence_inventory.json",
    "opening_review_scorecard": "b04_r6_r6_opening_review_scorecard.json",
    "opening_decision_matrix": "b04_r6_r6_opening_decision_matrix.json",
    "r6_opening_authorization_readiness_matrix": "b04_r6_r6_opening_authorization_readiness_matrix.json",
    "limited_continuation_readiness_matrix": "b04_r6_r6_opening_limited_continuation_readiness_matrix.json",
    "rollback_freeze_readiness_matrix": "b04_r6_r6_opening_rollback_freeze_readiness_matrix.json",
    "package_promotion_blocker_matrix": "b04_r6_r6_opening_package_promotion_blocker_matrix.json",
    "external_audit_delta_readiness": "b04_r6_r6_opening_external_audit_delta_readiness.json",
    "commercial_claim_ceiling_update": "b04_r6_r6_opening_commercial_claim_ceiling_update.json",
    "post_cutover_evidence_validation_review": "b04_r6_r6_opening_post_cutover_evidence_validation_review_contract.json",
    "r6_opening_readiness_review": "b04_r6_r6_opening_readiness_review_contract.json",
    "scope_review": "b04_r6_r6_opening_scope_review_contract.json",
    "fallback_preservation_review": "b04_r6_r6_opening_fallback_preservation_review_contract.json",
    "operator_control_review": "b04_r6_r6_opening_operator_control_review_contract.json",
    "kill_switch_review": "b04_r6_r6_opening_kill_switch_review_contract.json",
    "rollback_review": "b04_r6_r6_opening_rollback_review_contract.json",
    "drift_monitoring_review": "b04_r6_r6_opening_drift_monitoring_review_contract.json",
    "incident_freeze_review": "b04_r6_r6_opening_incident_freeze_review_contract.json",
    "trace_replay_review": "b04_r6_r6_opening_trace_replay_review_contract.json",
    "external_verifier_review": "b04_r6_r6_opening_external_verifier_review_contract.json",
    "commercial_claim_boundary_review": "b04_r6_r6_opening_commercial_claim_boundary_review_contract.json",
    "package_promotion_blocker_review": "b04_r6_r6_opening_package_promotion_blocker_review_contract.json",
    "no_authorization_drift_receipt": "b04_r6_r6_opening_review_no_authorization_drift_receipt.json",
    "validation_plan": "b04_r6_r6_opening_review_validation_plan.json",
    "validation_reason_codes": "b04_r6_r6_opening_review_validation_reason_codes.json",
    "r6_opening_authorization_packet_prep_only_draft": (
        "b04_r6_r6_opening_authorization_packet_prep_only_draft.json"
    ),
    "r6_opening_execution_packet_prep_only_draft": "b04_r6_r6_opening_execution_packet_prep_only_draft.json",
    "post_opening_evidence_review_packet_prep_only_draft": (
        "b04_r6_post_opening_evidence_review_packet_prep_only_draft.json"
    ),
    "limited_continuation_packet_prep_only_draft": (
        "b04_r6_r6_opening_limited_continuation_packet_prep_only_draft.json"
    ),
    "rollback_freeze_packet_prep_only_draft": "b04_r6_r6_opening_rollback_freeze_packet_prep_only_draft.json",
    "external_audit_delta_packet_prep_only_draft": (
        "b04_r6_r6_opening_external_audit_delta_packet_prep_only_draft.json"
    ),
    "package_promotion_review_preconditions_prep_only_draft": (
        "b04_r6_r6_opening_package_promotion_review_preconditions_prep_only_draft.json"
    ),
    "commercial_activation_claim_review_prep_only_draft": (
        "b04_r6_commercial_activation_claim_review_prep_only_draft.json"
    ),
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


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk_items(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_items(item)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_B04R6_R6_OPENING_REVIEW_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_R6_OPENING_REVIEW_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    try:
        payload = common.load_json_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_R6_OPENING_REVIEW_PREVIOUS_VALIDATION_MISSING", str(exc))
    if not isinstance(payload, dict):
        _fail("RC_B04R6_R6_OPENING_REVIEW_PREVIOUS_VALIDATION_MISSING", f"{label} must be an object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_R6_OPENING_REVIEW_PREVIOUS_VALIDATION_MISSING", str(exc))


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {
        role: _load(root, raw, label=role)
        for role, raw in {**PRIOR_JSON_INPUTS, **SOURCE_REVIEW_JSON_INPUTS}.items()
    }
    texts = {
        role: _read_text(root, raw, label=role)
        for role, raw in {**PRIOR_TEXT_INPUTS, **SOURCE_REVIEW_TEXT_INPUTS}.items()
    }
    return payloads, texts


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
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted to {value!r}")
            if _is_claim_bearing_field(key) and isinstance(value, str) and _contains_positive_authority_token(value):
                _fail("RC_B04R6_R6_OPENING_REVIEW_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        for phrase in (
            "R6 IS OPEN",
            "R6 OPENED",
            "PACKAGE PROMOTION AUTHORIZED",
            "COMMERCIAL ACTIVATION AUTHORIZED",
            "COMMERCIAL ACTIVATION CLAIM AUTHORIZED",
        ):
            if phrase in normalized:
                _fail("RC_B04R6_R6_OPENING_REVIEW_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


def _validate_previous_handoff(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    contract = payloads["validation_contract"]
    receipt = payloads["validation_receipt"]
    next_move = payloads["next_lawful_move"]
    for label, payload in (("validation_contract", contract), ("validation_receipt", receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_R6_OPENING_REVIEW_PREVIOUS_VALIDATION_MISSING", f"{label} lane drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_R6_OPENING_REVIEW_PREVIOUS_OUTCOME_DRIFT", f"{label} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_R6_OPENING_REVIEW_NEXT_MOVE_DRIFT", f"{label} next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_R6_OPENING_REVIEW_NEXT_MOVE_DRIFT", "validated next-lawful-move receipt drift")
    report = texts.get("validation_report", "").lower()
    for phrase in ("does not open r6", "does not promote package", "commercial activation"):
        if phrase not in report:
            _fail("RC_B04R6_R6_OPENING_REVIEW_PREVIOUS_VALIDATION_MISSING", f"validation report missing {phrase!r}")


def _validate_previous_scorecard(payloads: Dict[str, Dict[str, Any]]) -> None:
    scorecard = _previous_scorecard(payloads)
    required = {
        "sample_limit_respected": True,
        "route_distribution_health": "PASS",
        "fallback_behavior": "PASS",
        "static_fallback_preserved": True,
        "operator_override_ready": True,
        "kill_switch_ready": True,
        "rollback_ready": True,
        "drift_status": "PASS",
        "incident_freeze_clean": True,
        "trace_completeness": "PASS",
        "replay_status": "PASS",
        "external_verifier_ready": True,
        "commercial_claim_boundary_preserved": True,
        "r6_opening_review_ready": True,
        "package_promotion_ready": False,
    }
    for key, expected in required.items():
        if scorecard.get(key) != expected:
            _fail("RC_B04R6_R6_OPENING_REVIEW_SCORECARD_INCOMPLETE", f"previous scorecard.{key} drifted")


def _validate_inputs(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _ensure_authority_closed(payloads, texts)
    _validate_previous_handoff(payloads, texts)
    _validate_previous_scorecard(payloads)
    for raw in {**PRIOR_JSON_INPUTS, **PRIOR_TEXT_INPUTS, **SOURCE_REVIEW_JSON_INPUTS, **SOURCE_REVIEW_TEXT_INPUTS}.values():
        file_sha256(common.resolve_path(root, raw))


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    return [
        {
            "role": role,
            "path": raw,
            "sha256": file_sha256(common.resolve_path(root, raw)),
            "binding_kind": "file_sha256_at_r6_opening_review_authoring",
        }
        for role, raw in sorted(
            {**PRIOR_JSON_INPUTS, **PRIOR_TEXT_INPUTS, **SOURCE_REVIEW_JSON_INPUTS, **SOURCE_REVIEW_TEXT_INPUTS}.items()
        )
    ]


def _binding_hashes(input_bindings: list[Dict[str, str]]) -> Dict[str, str]:
    return {f"{row['role']}_hash": row["sha256"] for row in input_bindings}


def _previous_scorecard(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    source_scorecard = payloads.get("source_evidence_scorecard", {}).get("scorecard", {})
    if isinstance(source_scorecard, dict) and source_scorecard:
        return dict(source_scorecard)
    scorecard = payloads["evidence_scorecard_validation"].get("validated_scorecard", {})
    if isinstance(scorecard, dict) and scorecard:
        return dict(scorecard)
    return dict(payloads["validation_contract"].get("evidence_scorecard", {}))


def _opening_scorecard(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    previous = _previous_scorecard(payloads)
    pass_fields = {
        "post_cutover_evidence_review_validated": True,
        "runtime_cutover_passed": True,
        "fallbacks_preserved": previous.get("fallback_behavior") == "PASS"
        and previous.get("static_fallback_preserved") is True,
        "operator_controls_preserved": previous.get("operator_override_ready") is True,
        "kill_switch_ready": previous.get("kill_switch_ready") is True,
        "rollback_ready": previous.get("rollback_ready") is True,
        "drift_bounded": previous.get("drift_status") == "PASS",
        "incident_freeze_clean": previous.get("incident_freeze_clean") is True,
        "trace_replay_complete": previous.get("trace_completeness") == "PASS"
        and previous.get("replay_status") == "PASS",
        "external_verifier_ready": previous.get("external_verifier_ready") is True,
        "commercial_claim_boundary_preserved": previous.get("commercial_claim_boundary_preserved") is True,
        "package_promotion_ready": False,
    }
    ready = all(value is True for key, value in pass_fields.items() if key != "package_promotion_ready")
    return {
        "scorecard_id": "B04_R6_R6_OPENING_REVIEW_SCORECARD_V1",
        "overall_grade": "A_READY_FOR_R6_OPENING_AUTHORIZATION_REVIEW" if ready else "C_REPAIR_REQUIRED",
        "r6_opening_authorization_review_ready": ready,
        "r6_open_ready": False,
        "recommendation_is_authority": False,
        **pass_fields,
    }


def _decision_matrix(scorecard: Dict[str, Any]) -> Dict[str, Any]:
    ready = scorecard["r6_opening_authorization_review_ready"] is True
    return {
        "decision_matrix_id": "B04_R6_R6_OPENING_DECISION_MATRIX_V1",
        "runtime_cutover_review_validated": True,
        "r6_opening_authorization_review_ready": ready,
        "limited_continuation_ready": not ready,
        "rollback_freeze_ready": not ready,
        "external_audit_delta_ready": "READY_FOR_PACKET" if ready else "BLOCKED_BY_OPENING_REVIEW_DEFECT",
        "package_promotion_ready": False,
        "commercial_claim_status": "BOUNDARY_ONLY",
        "recommended_next_path": RECOMMENDED_VALIDATED_PATH if ready else "LIMITED_CONTINUATION_PACKET_NEXT",
        "recommendation_is_authority": False,
        "blocking_reasons": [
            "r6_opening_requires_r6_opening_review_validation",
            "r6_opening_authorization_requires_separate_authorization_packet",
            "r6_opening_execution_requires_authorization_and_execution_packet_validation",
            "package_promotion_requires_r6_opening_evidence_review_and_external_audit_delta",
            "commercial_activation_claims_remain_forbidden",
        ],
        "supporting_evidence": [
            "post_cutover_evidence_review_validation_passed",
            "runtime_cutover_passed_under_bounded_packet_law",
            "fallback_operator_rollback_controls_preserved",
            "trace_replay_external_verifier_readiness_passed",
        ]
        if ready
        else ["post_cutover_evidence_review_validation_present_but_opening_review_scorecard_incomplete"],
    }


def _inventory(input_bindings: list[Dict[str, str]], payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "inventory_id": "B04_R6_R6_OPENING_EVIDENCE_INVENTORY_V1",
        "previous_validated_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "bound_artifact_count": len(input_bindings),
        "validation_receipts": sorted(role for role in payloads if role.endswith("_validation")),
        "input_bindings": input_bindings,
    }


def _authority_state() -> Dict[str, Any]:
    return {
        "runtime_cutover_executed": True,
        "post_cutover_evidence_review_validated": True,
        "r6_opening_review_packet_authored": True,
        "r6_opening_review_validated": False,
        "r6_opening_authorized": False,
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
        "opening_review_treated_as_r6_opening": False,
        "opening_review_treated_as_package_promotion": False,
    }


def _base(
    *,
    generated_utc: str,
    branch: str,
    head: str,
    current_main_head: str,
    input_bindings: list[Dict[str, str]],
    trust_zone_validation: Dict[str, Any],
    inventory: Dict[str, Any],
    scorecard: Dict[str, Any],
    decision_matrix: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_version": "v1",
        "generated_utc": generated_utc,
        "current_branch": branch,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "validation_success_outcome": VALIDATION_SUCCESS_OUTCOME,
        "validation_success_next_move": VALIDATION_SUCCESS_NEXT_MOVE,
        "recommended_validated_path": RECOMMENDED_VALIDATED_PATH,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "binding_hashes": _binding_hashes(input_bindings),
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        "evidence_inventory": inventory,
        "opening_review_scorecard": scorecard,
        "opening_decision_matrix": decision_matrix,
        "recommendation_is_authority": False,
        "no_authorization_drift": True,
        **_authority_state(),
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _prep_only(base: Dict[str, Any], *, role: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.r6_opening_review.{role}.prep_only.v1",
        artifact_id=f"B04_R6_R6_OPENING_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        prep_only=True,
        can_authorize=False,
        cannot_open_r6=True,
        cannot_authorize_lobe_escalation=True,
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _pass_fail(condition: bool) -> str:
    return "PASS" if condition else "FAIL"


def _review(base: Dict[str, Any], *, role: str, condition: bool, **extra: Any) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.r6_opening_review.{role}.v1",
        artifact_id=f"B04_R6_R6_OPENING_{role.upper()}",
        review_role=role,
        review_status=_pass_fail(condition),
        **extra,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    scorecard = base["opening_review_scorecard"]
    decision = base["opening_decision_matrix"]
    payloads: Dict[str, Any] = {
        "packet_contract": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.packet_contract.v1", artifact_id="B04_R6_R6_OPENING_REVIEW_PACKET_CONTRACT"),
        "packet_receipt": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.packet_receipt.v1", artifact_id="B04_R6_R6_OPENING_REVIEW_PACKET_RECEIPT", verdict="BOUND_FOR_VALIDATION"),
        "evidence_inventory": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.inventory.v1", artifact_id="B04_R6_R6_OPENING_EVIDENCE_INVENTORY", inventory=base["evidence_inventory"]),
        "opening_review_scorecard": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.scorecard.v1", artifact_id="B04_R6_R6_OPENING_REVIEW_SCORECARD", scorecard=scorecard),
        "opening_decision_matrix": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.decision_matrix.v1", artifact_id="B04_R6_R6_OPENING_DECISION_MATRIX", decision_matrix=decision),
        "r6_opening_authorization_readiness_matrix": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.authorization_readiness.v1", artifact_id="B04_R6_R6_OPENING_AUTHORIZATION_READINESS_MATRIX", readiness="READY_FOR_AUTHORIZATION_PACKET" if decision["r6_opening_authorization_review_ready"] else "BLOCKED", r6_opening_authorization_ready=decision["r6_opening_authorization_review_ready"], r6_opening_authorized=False),
        "limited_continuation_readiness_matrix": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.limited_continuation_readiness.v1", artifact_id="B04_R6_R6_OPENING_LIMITED_CONTINUATION_READINESS_MATRIX", limited_continuation_ready=decision["limited_continuation_ready"]),
        "rollback_freeze_readiness_matrix": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.rollback_freeze_readiness.v1", artifact_id="B04_R6_R6_OPENING_ROLLBACK_FREEZE_READINESS_MATRIX", rollback_freeze_ready=decision["rollback_freeze_ready"]),
        "package_promotion_blocker_matrix": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.package_promotion_blockers.v1", artifact_id="B04_R6_R6_OPENING_PACKAGE_PROMOTION_BLOCKER_MATRIX", package_promotion_ready=False, blockers=decision["blocking_reasons"]),
        "external_audit_delta_readiness": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.external_audit_delta_readiness.v1", artifact_id="B04_R6_R6_OPENING_EXTERNAL_AUDIT_DELTA_READINESS", external_audit_delta_ready=decision["external_audit_delta_ready"]),
        "commercial_claim_ceiling_update": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.commercial_claim_ceiling.v1", artifact_id="B04_R6_R6_OPENING_COMMERCIAL_CLAIM_CEILING_UPDATE", allowed_claims=["B04 R6 post-cutover evidence review validated and R6 opening review packet is authored"], forbidden_claims=["R6 is open", "R6 opening is authorized", "package promotion is authorized", "commercial activation is authorized"]),
        "post_cutover_evidence_validation_review": _review(base, role="post_cutover_evidence_validation_review", condition=True, validated_outcome=EXPECTED_PREVIOUS_OUTCOME),
        "r6_opening_readiness_review": _review(base, role="r6_opening_readiness_review", condition=decision["r6_opening_authorization_review_ready"] is True),
        "scope_review": _review(base, role="scope_review", condition=True, scope="review_packet_only_not_r6_opening"),
        "fallback_preservation_review": _review(base, role="fallback_preservation_review", condition=scorecard["fallbacks_preserved"] is True),
        "operator_control_review": _review(base, role="operator_control_review", condition=scorecard["operator_controls_preserved"] is True),
        "kill_switch_review": _review(base, role="kill_switch_review", condition=scorecard["kill_switch_ready"] is True),
        "rollback_review": _review(base, role="rollback_review", condition=scorecard["rollback_ready"] is True),
        "drift_monitoring_review": _review(base, role="drift_monitoring_review", condition=scorecard["drift_bounded"] is True),
        "incident_freeze_review": _review(base, role="incident_freeze_review", condition=scorecard["incident_freeze_clean"] is True),
        "trace_replay_review": _review(base, role="trace_replay_review", condition=scorecard["trace_replay_complete"] is True),
        "external_verifier_review": _review(base, role="external_verifier_review", condition=scorecard["external_verifier_ready"] is True),
        "commercial_claim_boundary_review": _review(base, role="commercial_claim_boundary_review", condition=scorecard["commercial_claim_boundary_preserved"] is True, commercial_claim_status="BOUNDARY_ONLY"),
        "package_promotion_blocker_review": _review(base, role="package_promotion_blocker_review", condition=scorecard["package_promotion_ready"] is False, package_promotion_ready=False),
        "no_authorization_drift_receipt": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.no_authorization_drift.v1", artifact_id="B04_R6_R6_OPENING_REVIEW_NO_AUTHORIZATION_DRIFT_RECEIPT", validation_status="PASS", no_downstream_authorization_drift=True),
        "validation_plan": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.validation_plan.v1", artifact_id="B04_R6_R6_OPENING_REVIEW_VALIDATION_PLAN", validation_success_outcome=VALIDATION_SUCCESS_OUTCOME),
        "validation_reason_codes": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.validation_reason_codes.v1", artifact_id="B04_R6_R6_OPENING_REVIEW_VALIDATION_REASON_CODES", reason_codes=list(REASON_CODES)),
        "pipeline_board": _artifact(base, schema_id="kt.b04_r6.pipeline_board.v26", artifact_id="B04_R6_PIPELINE_BOARD", lanes=[
            {"lane": "VALIDATE_B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET", "status": "VALIDATED", "authoritative": False},
            {"lane": "AUTHOR_B04_R6_R6_OPENING_REVIEW_PACKET", "status": "CURRENT_BOUND", "authoritative": True},
            {"lane": "VALIDATE_B04_R6_R6_OPENING_REVIEW_PACKET", "status": "NEXT", "authoritative": True},
            {"lane": "R6_OPEN", "status": "BLOCKED_NOT_AUTHORIZED", "authoritative": False},
        ]),
        "campaign_board": _artifact(base, schema_id="kt.e2e_closure.campaign_board.v5", artifact_id="KT_E2E_CLOSURE_CAMPAIGN_BOARD", corridors=[
            {"corridor": "R6_OPENING", "status": "REVIEW_PACKET_BOUND_VALIDATION_NEXT"},
            {"corridor": "PACKAGE_PROMOTION", "status": "BLOCKED"},
            {"corridor": "COMMERCIAL_TRUTH_PLANE", "status": "BOUNDARY_ONLY"},
            {"corridor": "EXTERNAL_AUDIT", "status": decision["external_audit_delta_ready"]},
        ]),
        "future_blocker_register": _artifact(base, schema_id="kt.future_blocker_register.v8", artifact_id="KT_FUTURE_BLOCKER_REGISTER", blockers=[
            {"blocker_id": "B04R6-R6-OPENING-001", "category": "r6_opening", "status": "OPEN", "required_next_artifact": OUTPUTS["validation_plan"]},
            {"blocker_id": "B04R6-R6-OPENING-002", "category": "package_promotion", "status": "BLOCKING", "required_next_artifact": OUTPUTS["package_promotion_review_preconditions_prep_only_draft"]},
            {"blocker_id": "B04R6-R6-OPENING-003", "category": "commercial_claims", "status": "BLOCKING", "required_next_artifact": OUTPUTS["commercial_claim_ceiling_update"]},
        ]),
        "next_lawful_move": _artifact(base, schema_id="kt.b04_r6.r6_opening_review.next_lawful_move.v1", artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT", verdict="NEXT_LAWFUL_MOVE_SET"),
    }
    payloads.update({role: _prep_only(base, role=role) for role in PREP_ONLY_OUTPUT_ROLES})
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 R6 Opening Review Packet\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        f"Recommended validated path: {contract['recommended_validated_path']}.\n\n"
        "The packet binds post-cutover evidence review validation and organizes the R6 opening review question. "
        "It prepares authorization, execution, post-opening evidence, rollback/freeze, external audit, package blocker, "
        "and commercial-claim paths as prep-only artifacts.\n\n"
        "This packet does not open R6, authorize R6 opening, authorize package promotion, authorize commercial activation "
        "claims, escalate lobes, or mutate truth/trust law. Validation is next.\n"
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 R6 opening review packet")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_inputs(root, payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_R6_OPENING_REVIEW_TRUST_ZONE_FAILED", "fresh trust-zone validation must pass")
    input_bindings = _input_bindings(root)
    scorecard = _opening_scorecard(payloads)
    decision_matrix = _decision_matrix(scorecard)
    base = _base(
        generated_utc=utc_now_iso_z(),
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        input_bindings=input_bindings,
        trust_zone_validation=trust_zone_validation,
        inventory=_inventory(input_bindings, payloads),
        scorecard=scorecard,
        decision_matrix=decision_matrix,
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


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=AUTHORITATIVE_LANE)
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
