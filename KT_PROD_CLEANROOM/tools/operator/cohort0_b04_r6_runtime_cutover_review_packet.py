from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_expanded_canary_evidence_review_packet_validation as evidence_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-runtime-cutover-review-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-runtime-cutover-review-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET"
PREVIOUS_LANE = evidence_validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = evidence_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = evidence_validation.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = "B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET_BOUND__RUNTIME_CUTOVER_REVIEW_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET_DEFERRED__NAMED_REVIEW_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET_INVALID__FORENSIC_RUNTIME_CUTOVER_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET"

RECOMMENDED_NEXT_PATH = "RUNTIME_CUTOVER_AUTHORIZATION_PACKET_NEXT"
ALLOWED_RECOMMENDED_NEXT_PATHS = (
    "RUNTIME_CUTOVER_AUTHORIZATION_PACKET_NEXT",
    "ADDITIONAL_EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT",
    "EXTERNAL_AUDIT_DELTA_PACKET_NEXT",
    "REPAIR_OR_CLOSEOUT_NEXT",
    "FORENSIC_RUNTIME_CUTOVER_REVIEW_NEXT",
)
VALIDATION_OUTCOMES_PREPARED = (
    "B04_R6_RUNTIME_CUTOVER_REVIEW_VALIDATED__RUNTIME_CUTOVER_AUTHORIZATION_PACKET_NEXT",
    "B04_R6_RUNTIME_CUTOVER_REVIEW_VALIDATED__ADDITIONAL_EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT",
    "B04_R6_RUNTIME_CUTOVER_REVIEW_VALIDATED__EXTERNAL_AUDIT_DELTA_PACKET_NEXT",
    "B04_R6_RUNTIME_CUTOVER_REVIEW_DEFERRED__NAMED_REVIEW_DEFECT_REMAINS",
    "B04_R6_RUNTIME_CUTOVER_REVIEW_INVALID__FORENSIC_RUNTIME_CUTOVER_REVIEW_NEXT",
)

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
    "RUNTIME_CUTOVER_REVIEW_TREATED_AS_CUTOVER_AUTHORIZATION",
)
AUTHORITY_DRIFT_KEYS = {
    "runtime_cutover_authorized": "RC_B04R6_RUNTIME_CUTOVER_REVIEW_RUNTIME_CUTOVER_AUTHORIZED",
    "activation_cutover_executed": "RC_B04R6_RUNTIME_CUTOVER_REVIEW_ACTIVATION_CUTOVER_EXECUTED",
    "r6_open": "RC_B04R6_RUNTIME_CUTOVER_REVIEW_R6_OPEN_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_RUNTIME_CUTOVER_REVIEW_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_RUNTIME_CUTOVER_REVIEW_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_RUNTIME_CUTOVER_REVIEW_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_RUNTIME_CUTOVER_REVIEW_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_RUNTIME_CUTOVER_REVIEW_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_RUNTIME_CUTOVER_REVIEW_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_RUNTIME_CUTOVER_REVIEW_COMPARATOR_WEAKENED",
    "runtime_cutover_review_treated_as_cutover_authorization": (
        "RC_B04R6_RUNTIME_CUTOVER_REVIEW_AUTHORIZATION_DRIFT"
    ),
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
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_PREVIOUS_VALIDATION_MISSING",
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_PREVIOUS_OUTCOME_DRIFT",
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_NEXT_MOVE_DRIFT",
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_INPUT_HASH_MISSING",
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_INPUT_HASH_MALFORMED",
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_INVENTORY_MISSING",
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_SCORECARD_MISSING",
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_DECISION_MATRIX_UNLAWFUL",
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_BLOCKER_LEDGER_MISSING",
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_CONTRACT_MISSING",
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_CLAIM_TOKEN_DRIFT",
    "RC_B04R6_RUNTIME_CUTOVER_REVIEW_TRUST_ZONE_FAILED",
    *tuple(AUTHORITY_DRIFT_KEYS.values()),
)
REASON_CODES = tuple(dict.fromkeys(_REASON_CODES_RAW))

VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in evidence_validation.OUTPUTS.items()
    if filename.endswith(".json")
}
VALIDATION_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in evidence_validation.OUTPUTS.items()
    if not filename.endswith(".json")
}

REVIEW_CATEGORIES = (
    "validated_expanded_canary_evidence",
    "scope_sufficiency",
    "sample_sufficiency",
    "route_distribution_health",
    "fallback_behavior",
    "static_fallback_preservation",
    "operator_override_readiness",
    "kill_switch_readiness",
    "rollback_readiness",
    "drift_stability",
    "incident_freeze_cleanliness",
    "trace_completeness",
    "runtime_replayability",
    "external_verifier_readiness",
    "commercial_boundary_safety",
    "package_promotion_blockers",
    "cutover_authorization_readiness",
    "cutover_execution_blockers",
)
REVIEW_CONTRACT_ROLES = (
    "scope_review_contract",
    "static_fallback_review_contract",
    "operator_override_review_contract",
    "kill_switch_review_contract",
    "rollback_review_contract",
    "monitoring_review_contract",
    "drift_review_contract",
    "incident_freeze_review_contract",
    "external_verifier_review_contract",
    "commercial_claim_boundary_review_contract",
    "package_promotion_blocker_review_contract",
)
AUTHORITATIVE_OUTPUT_ROLES = (
    "packet_contract",
    "packet_receipt",
    "evidence_inventory",
    "review_scorecard",
    "decision_matrix",
    "blocker_ledger",
    *REVIEW_CONTRACT_ROLES,
    "no_authorization_drift_receipt",
    "next_lawful_move",
)
PREP_ONLY_OUTPUT_ROLES = (
    "validation_plan",
    "validation_reason_codes",
    "runtime_cutover_authorization_packet_prep_only_draft",
    "runtime_cutover_execution_packet_prep_only_draft",
    "additional_expanded_canary_authorization_prep_only_draft",
    "external_audit_delta_prep_only_draft",
    "package_promotion_review_preconditions_prep_only_draft",
    "commercial_claim_boundary_update_prep_only",
    "pipeline_board",
    "future_blocker_register",
)

OUTPUTS = {
    "packet_contract": "b04_r6_runtime_cutover_review_packet_contract.json",
    "packet_receipt": "b04_r6_runtime_cutover_review_packet_receipt.json",
    "packet_report": "b04_r6_runtime_cutover_review_packet_report.md",
    "evidence_inventory": "b04_r6_runtime_cutover_evidence_inventory.json",
    "review_scorecard": "b04_r6_runtime_cutover_review_scorecard.json",
    "decision_matrix": "b04_r6_runtime_cutover_decision_matrix.json",
    "blocker_ledger": "b04_r6_runtime_cutover_blocker_ledger.json",
    "scope_review_contract": "b04_r6_runtime_cutover_scope_review_contract.json",
    "static_fallback_review_contract": "b04_r6_runtime_cutover_static_fallback_review_contract.json",
    "operator_override_review_contract": "b04_r6_runtime_cutover_operator_override_review_contract.json",
    "kill_switch_review_contract": "b04_r6_runtime_cutover_kill_switch_review_contract.json",
    "rollback_review_contract": "b04_r6_runtime_cutover_rollback_review_contract.json",
    "monitoring_review_contract": "b04_r6_runtime_cutover_monitoring_review_contract.json",
    "drift_review_contract": "b04_r6_runtime_cutover_drift_review_contract.json",
    "incident_freeze_review_contract": "b04_r6_runtime_cutover_incident_freeze_review_contract.json",
    "external_verifier_review_contract": "b04_r6_runtime_cutover_external_verifier_review_contract.json",
    "commercial_claim_boundary_review_contract": "b04_r6_runtime_cutover_commercial_claim_boundary_review_contract.json",
    "package_promotion_blocker_review_contract": "b04_r6_runtime_cutover_package_promotion_blocker_review_contract.json",
    "no_authorization_drift_receipt": "b04_r6_runtime_cutover_no_authorization_drift_receipt.json",
    "validation_plan": "b04_r6_runtime_cutover_review_packet_validation_plan.json",
    "validation_reason_codes": "b04_r6_runtime_cutover_review_packet_validation_reason_codes.json",
    "runtime_cutover_authorization_packet_prep_only_draft": (
        "b04_r6_runtime_cutover_authorization_packet_prep_only_draft.json"
    ),
    "runtime_cutover_execution_packet_prep_only_draft": (
        "b04_r6_runtime_cutover_execution_packet_prep_only_draft.json"
    ),
    "additional_expanded_canary_authorization_prep_only_draft": (
        "b04_r6_runtime_cutover_review_additional_expanded_canary_authorization_prep_only_draft.json"
    ),
    "external_audit_delta_prep_only_draft": "b04_r6_runtime_cutover_review_external_audit_delta_prep_only_draft.json",
    "package_promotion_review_preconditions_prep_only_draft": (
        "b04_r6_runtime_cutover_review_package_promotion_preconditions_prep_only_draft.json"
    ),
    "commercial_claim_boundary_update_prep_only": (
        "b04_r6_runtime_cutover_review_commercial_claim_boundary_update_prep_only.json"
    ),
    "pipeline_board": "b04_r6_runtime_cutover_review_pipeline_board.json",
    "future_blocker_register": "b04_r6_runtime_cutover_review_future_blocker_register.json",
    "next_lawful_move": "b04_r6_runtime_cutover_review_next_lawful_move_receipt.json",
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
            _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    try:
        return common.load_json_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001 - normalize lower-level defects into this lane's taxonomy.
        _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_PREVIOUS_VALIDATION_MISSING", str(exc))


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001 - normalize lower-level defects into this lane's taxonomy.
        _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_PREVIOUS_VALIDATION_MISSING", str(exc))


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
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted truthy")
            if _is_claim_bearing_field(key) and isinstance(value, str) and _contains_positive_authority_token(value):
                _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        forbidden_phrases = (
            "RUNTIME CUTOVER AUTHORIZED",
            "CUTOVER AUTHORIZED",
            "R6 OPEN",
            "PACKAGE PROMOTION AUTHORIZED",
            "COMMERCIAL ACTIVATION AUTHORIZED",
            "COMMERCIAL ACTIVATION CLAIM AUTHORIZED",
        )
        for phrase in forbidden_phrases:
            if phrase in normalized:
                _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


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
                "binding_kind": "file_sha256_at_runtime_cutover_review_packet_authoring",
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
        _fail(
            "RC_B04R6_RUNTIME_CUTOVER_REVIEW_PREVIOUS_OUTCOME_DRIFT",
            f"expected {EXPECTED_PREVIOUS_OUTCOME}, got {contract.get('selected_outcome')!r}",
        )
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_PREVIOUS_OUTCOME_DRIFT", "validation receipt outcome drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_NEXT_MOVE_DRIFT", "validation contract next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_NEXT_MOVE_DRIFT", "next-lawful-move receipt drift")
    if contract.get("recommended_next_path_validated") != evidence_validation.review.RECOMMENDED_NEXT_PATH:
        _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_DECISION_MATRIX_UNLAWFUL", "validated recommendation drift")


def _validate_validation_payloads(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _validate_handoff(payloads)
    _ensure_authority_closed(payloads, texts)
    contract = payloads["validation_contract"]
    binding_hashes = contract.get("binding_hashes", {})
    if not isinstance(binding_hashes, dict):
        _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_INPUT_HASH_MISSING", "validation contract missing binding_hashes")
    for row in contract.get("input_bindings", []):
        if not isinstance(row, dict) or not _is_sha256(row.get("sha256")):
            _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_INPUT_HASH_MALFORMED", "malformed predecessor binding row")
        role = str(row.get("role", "")).strip()
        if binding_hashes.get(f"{role}_hash") != row["sha256"]:
            _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_INPUT_HASH_MISSING", f"binding hash mismatch for {role}")
    required_roles = (
        "evidence_inventory_validation",
        "evidence_scorecard_validation",
        "post_run_decision_matrix_validation",
        "runtime_cutover_readiness_validation",
        "commercial_claim_boundary_validation",
        "package_promotion_blocker_validation",
        "no_authorization_drift_validation",
        "claim_token_boundary_validation",
    )
    for role in required_roles:
        payload = payloads[role]
        if role == "claim_token_boundary_validation":
            status = payload.get("claim_bearing_authority_tokens_absent")
        elif role == "no_authorization_drift_validation":
            status = payload.get("no_authorization_drift")
        else:
            status = payload.get("validation_status")
        if status not in ("PASS", True):
            _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_PREVIOUS_VALIDATION_MISSING", f"{role} did not pass")
    if "does not authorize runtime cutover" not in texts["validation_report"].lower():
        _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_CONTRACT_MISSING", "validation report missing boundary sentence")
    for role, raw in VALIDATION_JSON_INPUTS.items():
        if not _is_sha256(file_sha256(common.resolve_path(root, raw))):
            _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_INPUT_HASH_MALFORMED", f"{role} hash malformed")


def _guard() -> Dict[str, Any]:
    return {
        "expanded_canary_evidence_review_validated": True,
        "runtime_cutover_review_packet_authored": True,
        "runtime_cutover_review_treated_as_cutover_authorization": False,
        "runtime_cutover_authorization_packet_authored": False,
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
        "cannot_authorize_runtime_cutover": True,
        "cannot_execute_runtime_cutover": True,
        "cannot_open_r6": True,
        "cannot_authorize_lobe_escalation": True,
        "cannot_authorize_package_promotion": True,
        "cannot_authorize_commercial_activation_claims": True,
        "cannot_mutate_truth_engine_law": True,
        "cannot_mutate_trust_zone_law": True,
    }


def _scorecard() -> Dict[str, Any]:
    return {
        "overall_grade": "A_READY_FOR_RUNTIME_CUTOVER_AUTHORIZATION_PACKET_AUTHORSHIP_REVIEW",
        "runtime_cutover_review_ready": True,
        "runtime_cutover_authorization_ready": "PENDING_REVIEW_VALIDATION",
        "runtime_cutover_execution_ready": False,
        "commercial_claim_status": "BOUNDARY_ONLY",
        "package_promotion_ready": False,
        "categories": [
            {
                "category": category,
                "status": "PASS" if category != "cutover_execution_blockers" else "BLOCKED_BY_AUTHORITY",
                "review_notes": (
                    "Evidence supports authoring a runtime cutover authorization packet if this review validates."
                    if category == "cutover_authorization_readiness"
                    else "Cutover execution remains blocked by future authorization and execution-packet lanes."
                    if category == "cutover_execution_blockers"
                    else "Validated expanded-canary evidence supports review."
                ),
            }
            for category in REVIEW_CATEGORIES
        ],
    }


def _decision_matrix(scorecard: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "decision_matrix_id": "B04_R6_RUNTIME_CUTOVER_REVIEW_DECISION_MATRIX_V1",
        "source_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "overall_grade": scorecard["overall_grade"],
        "recommended_next_path": RECOMMENDED_NEXT_PATH,
        "allowed_recommended_next_paths": list(ALLOWED_RECOMMENDED_NEXT_PATHS),
        "runtime_cutover_review_ready": True,
        "runtime_cutover_authorization_packet_authoring_ready": True,
        "runtime_cutover_execution_ready": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "r6_open": False,
        "package_promotion_ready": False,
        "commercial_claim_status": "BOUNDARY_ONLY",
        "supporting_evidence": [
            "expanded_canary_evidence_review_validation",
            "runtime_cutover_readiness_validation",
            "external_verifier_readiness_validation",
            "commercial_claim_boundary_validation",
            "package_promotion_blocker_validation",
        ],
        "blocking_reasons": [
            "runtime_cutover_review_packet_requires_validation",
            "runtime_cutover_authorization_packet_not_authored",
            "runtime_cutover_execution_packet_not_authored_or_validated",
            "package_promotion_requires_cutover_evidence_external_audit_and_package_review",
            "commercial_activation_claims_remain_forbidden",
        ],
        "required_next_artifacts": [
            "b04_r6_runtime_cutover_review_packet_validation",
            "b04_r6_runtime_cutover_authorization_packet_if_validation_passes",
        ],
    }


def _blockers() -> list[Dict[str, Any]]:
    rows = [
        ("runtime_cutover", "runtime_cutover_review_packet_not_validated"),
        ("runtime_cutover_authorization", "runtime_cutover_authorization_packet_not_authored"),
        ("runtime_cutover_execution", "runtime_cutover_execution_packet_not_authored_or_validated"),
        ("r6_open", "r6_open_requires_future_cutover_and_r6_opening_authority"),
        ("package_promotion", "package_promotion_requires_external_audit_and_package_review"),
        ("commercial_claims", "commercial_activation_claims_remain_forbidden"),
        ("external_audit", "external_audit_delta_packet_not_authored_or_validated"),
        ("public_verifier", "public_replay_bundle_requires_cutover_review_validation"),
    ]
    return [
        {
            "blocker_id": f"B04R6-RCR-{index:04d}",
            "category": category,
            "severity": "BLOCKING",
            "blocks": [category.upper()],
            "evidence_source": "expanded_canary_evidence_review_validation",
            "required_repair_or_next_artifact": next_artifact,
            "status": "OPEN",
        }
        for index, (category, next_artifact) in enumerate(rows, start=1)
    ]


def _review_contract(base: Dict[str, Any], role: str, *, category: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_cutover_review.{role}.v1",
        artifact_id=f"B04_R6_RUNTIME_CUTOVER_REVIEW_{role.upper()}",
        review_category=category,
        review_status="PASS",
        source_validation=EXPECTED_PREVIOUS_OUTCOME,
        does_not_authorize_runtime_cutover=True,
        required_future_validation=NEXT_LAWFUL_MOVE,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str, **extra: Any) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_cutover_review.{role}.prep_only.v1",
        artifact_id=f"B04_R6_RUNTIME_CUTOVER_REVIEW_{role.upper()}",
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
        "recommended_next_path": RECOMMENDED_NEXT_PATH,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "validation_outcomes_prepared": list(VALIDATION_OUTCOMES_PREPARED),
        "outcome_routing": {
            OUTCOME_BOUND: NEXT_LAWFUL_MOVE,
            OUTCOME_DEFERRED: "REPAIR_B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET_DEFECTS",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_RUNTIME_CUTOVER_REVIEW_PACKET",
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


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    scorecard = _scorecard()
    decision_matrix = _decision_matrix(scorecard)
    payloads: Dict[str, Any] = {
        "packet_contract": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_review_packet_contract.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET_CONTRACT",
            review_summary=(
                "Validated expanded-canary evidence supports authoring a runtime cutover authorization packet "
                "only after this review packet validates."
            ),
            decision_matrix_id=decision_matrix["decision_matrix_id"],
        ),
        "packet_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_review_packet_receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET_RECEIPT",
            receipt_type="RUNTIME_CUTOVER_REVIEW_PACKET_BOUND",
            verdict="BOUND_FOR_RUNTIME_CUTOVER_REVIEW_VALIDATION_ONLY",
        ),
        "evidence_inventory": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_evidence_inventory.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_EVIDENCE_INVENTORY",
            evidence_inventory=[
                {"role": row["role"], "path": row["path"], "sha256": row["sha256"]} for row in base["input_bindings"]
            ],
        ),
        "review_scorecard": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_review_scorecard.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_REVIEW_SCORECARD",
            scorecard=scorecard,
        ),
        "decision_matrix": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_decision_matrix.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_DECISION_MATRIX",
            decision_matrix=decision_matrix,
        ),
        "blocker_ledger": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_blocker_ledger.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_BLOCKER_LEDGER",
            blockers=_blockers(),
        ),
        "no_authorization_drift_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover.no_authorization_drift_receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_NO_AUTHORIZATION_DRIFT_RECEIPT",
            no_authorization_drift=True,
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.runtime_cutover_review_next_lawful_move_receipt.v1",
            artifact_id="B04_R6_RUNTIME_CUTOVER_REVIEW_NEXT_LAWFUL_MOVE_RECEIPT",
            receipt_type="NEXT_LAWFUL_MOVE",
        ),
    }
    review_contract_categories = {
        "scope_review_contract": "scope_sufficiency",
        "static_fallback_review_contract": "static_fallback_preservation",
        "operator_override_review_contract": "operator_override_readiness",
        "kill_switch_review_contract": "kill_switch_readiness",
        "rollback_review_contract": "rollback_readiness",
        "monitoring_review_contract": "route_distribution_health",
        "drift_review_contract": "drift_stability",
        "incident_freeze_review_contract": "incident_freeze_cleanliness",
        "external_verifier_review_contract": "external_verifier_readiness",
        "commercial_claim_boundary_review_contract": "commercial_boundary_safety",
        "package_promotion_blocker_review_contract": "package_promotion_blockers",
    }
    for role, category in review_contract_categories.items():
        payloads[role] = _review_contract(base, role, category=category)
    payloads.update(
        {
            "validation_plan": _prep_only(
                base,
                role="validation_plan",
                purpose="Prepare validation of this runtime cutover review packet.",
                validation_outcomes_prepared=list(VALIDATION_OUTCOMES_PREPARED),
            ),
            "validation_reason_codes": _prep_only(
                base,
                role="validation_reason_codes",
                purpose="Prepare reason-code routing for runtime cutover review validation.",
                reason_codes=list(REASON_CODES),
            ),
            "runtime_cutover_authorization_packet_prep_only_draft": _prep_only(
                base,
                role="runtime_cutover_authorization_packet_prep_only_draft",
                purpose="Prepare a future authorization packet; does not authorize runtime cutover.",
            ),
            "runtime_cutover_execution_packet_prep_only_draft": _prep_only(
                base,
                role="runtime_cutover_execution_packet_prep_only_draft",
                purpose="Prepare a future execution packet; does not execute runtime cutover.",
            ),
            "additional_expanded_canary_authorization_prep_only_draft": _prep_only(
                base,
                role="additional_expanded_canary_authorization_prep_only_draft",
                purpose="Prepare fallback path if cutover review validation selects another expanded canary.",
            ),
            "external_audit_delta_prep_only_draft": _prep_only(
                base,
                role="external_audit_delta_prep_only_draft",
                purpose="Prepare external audit delta material for later authority.",
            ),
            "package_promotion_review_preconditions_prep_only_draft": _prep_only(
                base,
                role="package_promotion_review_preconditions_prep_only_draft",
                purpose="Track package-promotion preconditions; promotion remains blocked.",
            ),
            "commercial_claim_boundary_update_prep_only": _prep_only(
                base,
                role="commercial_claim_boundary_update_prep_only",
                purpose="Keep commercial claim language bounded to validated canary evidence and review authorship.",
                allowed_claims=[
                    "Expanded-canary evidence review validated.",
                    "Runtime cutover review packet authoring is in progress.",
                    "Runtime cutover remains unauthorized.",
                    "R6 remains closed.",
                ],
                forbidden_claims=[
                    "Runtime cutover is authorized.",
                    "R6 is open.",
                    "Package promotion is complete.",
                    "Commercial activation is authorized.",
                ],
            ),
            "pipeline_board": _prep_only(
                base,
                role="pipeline_board",
                purpose="Update the B04 R6 board for the runtime cutover review packet lane.",
                board={
                    "expanded_canary_evidence_review": "VALIDATED",
                    "runtime_cutover_review_packet": "BOUND",
                    "runtime_cutover_review_validation": "NEXT",
                    "runtime_cutover": "UNAUTHORIZED",
                    "r6": "CLOSED",
                    "package_promotion": "BLOCKED",
                    "commercial_activation_claims": "UNAUTHORIZED",
                },
            ),
            "future_blocker_register": _prep_only(
                base,
                role="future_blocker_register",
                purpose="Track blockers after runtime cutover review packet authoring.",
                blockers=[row["required_repair_or_next_artifact"] for row in _blockers()],
            ),
        }
    )
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Runtime Cutover Review Packet",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "The packet binds the validated expanded-canary evidence review and opens only the review-validation lane.",
            "It recommends future runtime cutover authorization packet authorship if validation accepts the packet.",
            "",
            "This packet does not authorize runtime cutover, does not execute cutover, does not open R6,",
            "does not authorize lobe escalation, does not promote package, and does not authorize commercial activation claims.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 runtime cutover review packet authoring")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_validation_payloads(root, payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_RUNTIME_CUTOVER_REVIEW_TRUST_ZONE_FAILED", "trust-zone validation failed")
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
    contract = output_payloads["packet_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "packet_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author the B04 R6 runtime cutover review packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
