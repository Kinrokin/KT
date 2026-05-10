from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_expanded_canary_evidence_review_packet as review
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/b04-r6-expanded-canary-evidence-review-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-expanded-canary-evidence-review-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET_VALIDATION"
PREVIOUS_LANE = review.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = review.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = review.NEXT_LAWFUL_MOVE

SELECTED_OUTCOME = "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATED__RUNTIME_CUTOVER_REVIEW_PACKET_NEXT"
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET"
OUTCOME_VALIDATED_ADDITIONAL_CANARY = (
    "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATED__ADDITIONAL_EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT"
)
OUTCOME_VALIDATED_EXTERNAL_AUDIT = (
    "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATED__EXTERNAL_AUDIT_DELTA_PACKET_NEXT"
)
OUTCOME_DEFERRED = "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_DEFERRED__NAMED_REVIEW_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_INVALID__FORENSIC_EXPANDED_CANARY_EVIDENCE_REVIEW_NEXT"

MAY_AUTHORIZE = (
    "EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET_VALIDATED",
    "RUNTIME_CUTOVER_REVIEW_PACKET_AUTHORSHIP_NEXT",
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
    "EXPANDED_CANARY_EVIDENCE_TREATED_AS_PACKAGE_PROMOTION",
)

AUTHORITY_DRIFT_KEYS = {
    "runtime_cutover_authorized": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "activation_cutover_executed": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "r6_open": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_R6_OPEN_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_COMPARATOR_WEAKENED",
    "expanded_canary_evidence_treated_as_package_promotion": (
        "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT"
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
    "CUTOVER",
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
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKET_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKET_OUTCOME_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_NEXT_MOVE_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_INPUT_HASH_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_INPUT_HASH_MALFORMED",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_INVENTORY_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_SCORECARD_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_DECISION_MATRIX_UNJUSTIFIED",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_BLOCKER_LEDGER_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_READINESS_MATRIX_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_REVIEW_CONTRACT_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PREP_ONLY_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_CLAIM_TOKEN_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_TRUST_ZONE_FAILED",
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
REVIEW_CONTRACT_ROLES = (
    "route_distribution_review_contract",
    "fallback_behavior_review_contract",
    "static_fallback_review_contract",
    "abstention_fallback_review_contract",
    "null_route_review_contract",
    "operator_override_review_contract",
    "kill_switch_review_contract",
    "rollback_review_contract",
    "drift_monitoring_review_contract",
    "incident_freeze_review_contract",
    "trace_completeness_review_contract",
    "replay_readiness_review_contract",
    "external_verifier_readiness_review_contract",
    "commercial_claim_boundary_review_contract",
    "package_promotion_blocker_review_contract",
)
VALIDATION_RECEIPT_ROLES = (
    "packet_binding_validation",
    "evidence_inventory_validation",
    "evidence_scorecard_validation",
    "post_run_decision_matrix_validation",
    "post_expanded_canary_blocker_ledger_validation",
    "runtime_cutover_readiness_validation",
    "additional_expanded_canary_readiness_validation",
    "external_audit_readiness_validation",
    "route_distribution_review_validation",
    "fallback_behavior_review_validation",
    "static_fallback_review_validation",
    "abstention_fallback_review_validation",
    "null_route_review_validation",
    "operator_override_review_validation",
    "kill_switch_review_validation",
    "rollback_review_validation",
    "drift_monitoring_review_validation",
    "incident_freeze_review_validation",
    "trace_completeness_review_validation",
    "replay_readiness_review_validation",
    "external_verifier_readiness_validation",
    "commercial_claim_boundary_validation",
    "package_promotion_blocker_validation",
    "prep_only_boundary_validation",
)
PREP_ONLY_OUTPUT_ROLES = (
    "runtime_cutover_review_validation_plan_prep_only",
    "runtime_cutover_review_packet_prep_only_draft",
    "additional_expanded_canary_authorization_validation_plan_prep_only",
    "external_audit_delta_validation_plan_prep_only",
    "package_promotion_review_preconditions_prep_only_draft",
)

OUTPUTS = {
    "validation_contract": "b04_r6_expanded_canary_evidence_review_validation_contract.json",
    "validation_receipt": "b04_r6_expanded_canary_evidence_review_validation_receipt.json",
    "validation_report": "b04_r6_expanded_canary_evidence_review_validation_report.md",
    "packet_binding_validation": "b04_r6_expanded_canary_evidence_review_packet_binding_validation_receipt.json",
    "evidence_inventory_validation": "b04_r6_expanded_canary_evidence_inventory_validation_receipt.json",
    "evidence_scorecard_validation": "b04_r6_expanded_canary_evidence_scorecard_validation_receipt.json",
    "post_run_decision_matrix_validation": "b04_r6_expanded_canary_post_run_decision_matrix_validation_receipt.json",
    "post_expanded_canary_blocker_ledger_validation": "b04_r6_post_expanded_canary_blocker_ledger_validation_receipt.json",
    "runtime_cutover_readiness_validation": (
        "b04_r6_post_expanded_canary_runtime_cutover_readiness_validation_receipt.json"
    ),
    "additional_expanded_canary_readiness_validation": (
        "b04_r6_additional_expanded_canary_readiness_validation_receipt.json"
    ),
    "external_audit_readiness_validation": "b04_r6_post_expanded_canary_external_audit_readiness_validation_receipt.json",
    "route_distribution_review_validation": "b04_r6_expanded_canary_route_distribution_review_validation_receipt.json",
    "fallback_behavior_review_validation": "b04_r6_expanded_canary_fallback_behavior_review_validation_receipt.json",
    "static_fallback_review_validation": "b04_r6_expanded_canary_static_fallback_review_validation_receipt.json",
    "abstention_fallback_review_validation": (
        "b04_r6_expanded_canary_abstention_fallback_review_validation_receipt.json"
    ),
    "null_route_review_validation": "b04_r6_expanded_canary_null_route_review_validation_receipt.json",
    "operator_override_review_validation": "b04_r6_expanded_canary_operator_override_review_validation_receipt.json",
    "kill_switch_review_validation": "b04_r6_expanded_canary_kill_switch_review_validation_receipt.json",
    "rollback_review_validation": "b04_r6_expanded_canary_rollback_review_validation_receipt.json",
    "drift_monitoring_review_validation": "b04_r6_expanded_canary_drift_monitoring_review_validation_receipt.json",
    "incident_freeze_review_validation": "b04_r6_expanded_canary_incident_freeze_review_validation_receipt.json",
    "trace_completeness_review_validation": "b04_r6_expanded_canary_trace_completeness_review_validation_receipt.json",
    "replay_readiness_review_validation": "b04_r6_expanded_canary_replay_readiness_review_validation_receipt.json",
    "external_verifier_readiness_validation": (
        "b04_r6_expanded_canary_external_verifier_readiness_validation_receipt.json"
    ),
    "commercial_claim_boundary_validation": (
        "b04_r6_expanded_canary_evidence_commercial_claim_boundary_validation_receipt.json"
    ),
    "package_promotion_blocker_validation": (
        "b04_r6_expanded_canary_package_promotion_blocker_validation_receipt.json"
    ),
    "prep_only_boundary_validation": "b04_r6_expanded_canary_evidence_prep_only_boundary_validation_receipt.json",
    "no_authorization_drift_validation": (
        "b04_r6_expanded_canary_evidence_no_authorization_drift_validation_receipt.json"
    ),
    "claim_token_boundary_validation": "b04_r6_expanded_canary_evidence_claim_token_boundary_validation_receipt.json",
    "runtime_cutover_review_validation_plan_prep_only": (
        "b04_r6_runtime_cutover_review_validation_plan_prep_only.json"
    ),
    "runtime_cutover_review_packet_prep_only_draft": (
        "b04_r6_expanded_canary_evidence_validation_runtime_cutover_review_packet_prep_only_draft.json"
    ),
    "additional_expanded_canary_authorization_validation_plan_prep_only": (
        "b04_r6_additional_expanded_canary_authorization_validation_plan_prep_only.json"
    ),
    "external_audit_delta_validation_plan_prep_only": (
        "b04_r6_external_audit_delta_validation_plan_prep_only.json"
    ),
    "package_promotion_review_preconditions_prep_only_draft": (
        "b04_r6_expanded_canary_evidence_validation_package_promotion_review_preconditions_prep_only_draft.json"
    ),
    "pipeline_board": "b04_r6_expanded_canary_evidence_review_validation_pipeline_board.json",
    "future_blocker_register": "b04_r6_expanded_canary_evidence_review_validation_future_blocker_register.json",
    "next_lawful_move": "b04_r6_expanded_canary_evidence_review_validation_next_lawful_move_receipt.json",
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
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKET_MISSING", f"{label} must be object")
    return payload


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in REVIEW_JSON_INPUTS.items()}
    texts = {role: common.read_text_required(root, raw, label=role) for role, raw in REVIEW_TEXT_INPUTS.items()}
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
    return any(marker in lowered for marker in CLAIM_BEARING_FIELD_MARKERS)


def _contains_positive_authority_token(value: str) -> bool:
    separators = "\n|,;"
    segments = [value]
    for separator in separators:
        next_segments: list[str] = []
        for segment in segments:
            next_segments.extend(segment.split(separator))
        segments = next_segments
    for segment in [part.strip().upper() for part in segments]:
        if not segment:
            continue
        if not any(token in segment for token in POSITIVE_AUTHORITY_TOKENS):
            continue
        if any(qualifier in segment for qualifier in NEGATIVE_AUTHORITY_QUALIFIERS):
            continue
        return True
    return False


def _ensure_text_authority_closed(text: str, *, label: str) -> None:
    for line_number, line in enumerate(text.splitlines(), start=1):
        if _contains_positive_authority_token(line):
            _fail(
                "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_CLAIM_TOKEN_DRIFT",
                f"{label}:{line_number} carries authority token {line!r}",
            )


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    allowed_states = {
        "runtime_cutover": {"UNAUTHORIZED", "RECOMMENDED_AFTER_VALIDATION_NOT_AUTHORIZED"},
        "r6": {"CLOSED"},
        "package_promotion": {"UNAUTHORIZED", "DEFERRED", "BLOCKED"},
        "commercial_activation_claims": {"UNAUTHORIZED", "BOUNDARY_ONLY"},
    }
    for role, payload in payloads.items():
        for key, value in _walk_items(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{role}.{key} drifted to {value!r}")
            if key in allowed_states and value not in allowed_states[key]:
                code = {
                    "runtime_cutover": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED",
                    "r6": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_R6_OPEN_DRIFT",
                    "package_promotion": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT",
                    "commercial_activation_claims": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_COMMERCIAL_CLAIM_DRIFT",
                }[key]
                _fail(code, f"{role}.{key} drifted to {value!r}")
            if _is_claim_bearing_field(key) and isinstance(value, str) and _contains_positive_authority_token(value):
                _fail(
                    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_CLAIM_TOKEN_DRIFT",
                    f"{role}.{key} carries authority token {value!r}",
                )
    for role, text in texts.items():
        _ensure_text_authority_closed(text, label=role)


def _is_sha256(value: Any) -> bool:
    text = str(value)
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows = [
        {
            "role": role,
            "path": raw,
            "sha256": file_sha256(common.resolve_path(root, raw)),
            "binding_kind": "file_sha256_at_expanded_canary_evidence_review_validation",
        }
        for role, raw in sorted(REVIEW_JSON_INPUTS.items())
    ]
    rows.extend(
        {
            "role": role,
            "path": raw,
            "sha256": file_sha256(common.resolve_path(root, raw)),
            "binding_kind": "file_sha256_at_expanded_canary_evidence_review_validation",
        }
        for role, raw in sorted(REVIEW_TEXT_INPUTS.items())
    )
    return rows


def _binding_hashes(root: Path) -> Dict[str, str]:
    hashes = {f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(REVIEW_JSON_INPUTS.items())}
    hashes.update({f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(REVIEW_TEXT_INPUTS.items())})
    return hashes


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["packet_contract"]
    receipt = payloads["packet_receipt"]
    next_move = payloads["next_lawful_move"]
    for role, payload in (("packet_contract", contract), ("packet_receipt", receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKET_OUTCOME_DRIFT", f"{role} lane identity drifted")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKET_OUTCOME_DRIFT", f"{role} outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_NEXT_MOVE_DRIFT", f"{role} next move drifted")
        if payload.get("expanded_canary_evidence_review_packet_authored") is not True:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKET_MISSING", f"{role} missing authored flag")
        if payload.get("expanded_canary_evidence_review_validated") is not False:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKET_OUTCOME_DRIFT", f"{role} self-validates")
    if next_move.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_NEXT_MOVE_DRIFT", "handoff lane identity drifted")
    if next_move.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_NEXT_MOVE_DRIFT", "handoff outcome drifted")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_NEXT_MOVE_DRIFT", "handoff next move drifted")


def _validate_hash_maps(root: Path, contract: Dict[str, Any]) -> None:
    input_bindings = contract.get("input_bindings", {})
    binding_hashes = contract.get("binding_hashes", {})
    if not isinstance(input_bindings, dict) or not isinstance(binding_hashes, dict):
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_INPUT_HASH_MISSING", "packet hash maps missing")
    for role, raw in sorted({**review.ALL_JSON_INPUTS, **review.ALL_TEXT_INPUTS}.items()):
        key = f"{role}_hash"
        expected = file_sha256(common.resolve_path(root, raw))
        if key not in input_bindings or key not in binding_hashes:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_INPUT_HASH_MISSING", f"{key} missing")
        if not _is_sha256(input_bindings[key]) or not _is_sha256(binding_hashes[key]):
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_INPUT_HASH_MALFORMED", f"{key} malformed")
        if input_bindings[key] != expected or binding_hashes[key] != expected:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_INPUT_HASH_MISSING", f"{key} mismatched source evidence")
    for key, value in {**input_bindings, **binding_hashes}.items():
        if key.endswith("_hash") and not _is_sha256(value):
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_INPUT_HASH_MALFORMED", f"{key} malformed")


def _validate_inventory(inventory_payload: Dict[str, Any], binding_hashes: Dict[str, str]) -> None:
    rows = inventory_payload.get("evidence_inventory", [])
    if not isinstance(rows, list) or not rows:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_INVENTORY_MISSING", "inventory rows missing")
    expected_roles = set(review.ALL_JSON_INPUTS) | set(review.ALL_TEXT_INPUTS)
    found_roles = {row.get("role") for row in rows}
    if found_roles != expected_roles:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_INVENTORY_MISSING", "inventory role set drifted")
    for row in rows:
        key = f"{row.get('role')}_hash"
        if row.get("sha256") != binding_hashes.get(key):
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_INVENTORY_MISSING", f"{key} inventory hash drifted")


def _validate_scorecard(scorecard: Dict[str, Any]) -> None:
    if scorecard.get("overall_grade") != "A_READY_FOR_RUNTIME_CUTOVER_REVIEW_PACKET":
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_SCORECARD_MISSING", "overall grade drifted")
    for key in ("route_distribution_health", "drift_status", "trace_completeness", "replay_status"):
        if scorecard.get(key) != "PASS":
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_SCORECARD_MISSING", f"{key} did not pass")
    if scorecard.get("trace_complete_cases") != review.runtime.MAX_CASES:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_SCORECARD_MISSING", "trace complete cases drifted")
    rows = {row.get("category"): row for row in scorecard.get("categories", [])}
    for category in review.REVIEW_CATEGORIES:
        row = rows.get(category)
        if not row or row.get("status") != "PASS":
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_SCORECARD_MISSING", f"{category} missing or failed")
    if rows["package_promotion_readiness"].get("grade") != "BLOCKED_BY_LAW":
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT", "package readiness not blocked")


def _validate_decision_matrix(matrix: Dict[str, Any], scorecard: Dict[str, Any]) -> None:
    if matrix.get("recommended_next_path") != review.RECOMMENDED_NEXT_PATH:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_DECISION_MATRIX_UNJUSTIFIED", "recommended next path drifted")
    if matrix.get("recommended_next_path") not in review.ALLOWED_RECOMMENDED_NEXT_PATHS:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_DECISION_MATRIX_UNJUSTIFIED", "recommended path not allowed")
    expected = {
        "expanded_canary_result": "PASSED",
        "overall_grade": scorecard.get("overall_grade"),
        "runtime_cutover_review_ready": True,
        "runtime_cutover_authorized": False,
        "additional_expanded_canary_ready": True,
        "external_audit_delta_ready": "READY_FOR_PACKET",
        "package_promotion_ready": False,
        "commercial_claim_status": "BOUNDARY_ONLY",
    }
    for key, value in expected.items():
        if matrix.get(key) != value:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_DECISION_MATRIX_UNJUSTIFIED", f"{key} drifted")
    blockers = " ".join(matrix.get("blocking_reasons", []))
    if "runtime_cutover_requires_dedicated_review_packet_and_validation" not in blockers:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED", "cutover review blocker missing")
    if "commercial_activation_claims_remain_forbidden" not in blockers:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_COMMERCIAL_CLAIM_DRIFT", "commercial blocker missing")
    supporting = " ".join(matrix.get("supporting_evidence", []))
    for phrase in ("expanded canary runtime passed", "sample and case limits remained bounded", "commercial boundary receipts passed"):
        if phrase not in supporting:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_DECISION_MATRIX_UNJUSTIFIED", f"support missing {phrase}")


def _validate_readiness(payloads: Dict[str, Dict[str, Any]]) -> None:
    cutover = payloads["runtime_cutover_readiness_matrix"].get("readiness", {})
    if cutover.get("ready_for_review_packet") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_READINESS_MATRIX_MISSING", "cutover review not packet-ready")
    if cutover.get("runtime_cutover_authorized") is not False:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED", "cutover readiness authorized cutover")
    additional = payloads["additional_expanded_canary_readiness_matrix"].get("readiness", {})
    if additional.get("ready_for_authorization_packet") is not True or additional.get("execution_authorized") is not False:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_READINESS_MATRIX_MISSING", "additional canary readiness drifted")
    audit = payloads["external_audit_readiness_matrix"].get("readiness", {})
    if audit.get("ready_for_delta_packet") is not True or audit.get("public_claims_authorized") is not False:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_READINESS_MATRIX_MISSING", "external audit readiness drifted")


def _validate_blockers(blocker_payload: Dict[str, Any]) -> None:
    rows = blocker_payload.get("blockers", [])
    required = {
        "runtime_cutover",
        "package_promotion",
        "commercial_claims",
        "external_audit",
        "public_verifier",
        "operator_readiness",
        "deployment_profile",
        "rollback_proof",
        "data_governance",
        "benchmark_reaudit",
    }
    categories = {row.get("category") for row in rows}
    if not required.issubset(categories):
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_BLOCKER_LEDGER_MISSING", "blocker categories incomplete")
    for row in rows:
        if row.get("status") != "OPEN" or row.get("severity") != "BLOCKING" or not row.get("required_repair_or_next_artifact"):
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_BLOCKER_LEDGER_MISSING", "blocker row malformed")


def _validate_review_contracts(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in REVIEW_CONTRACT_ROLES:
        payload = payloads[role]
        if payload.get("status") != "PASS":
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_REVIEW_CONTRACT_MISSING", f"{role} did not pass")
        if payload.get("cannot_authorize_runtime_cutover") is not True:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED", f"{role} can authorize cutover")
        if payload.get("cannot_authorize_package_promotion") is not True:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT", f"{role} can authorize package")


def _validate_prep_only(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in review.PREP_ONLY_OUTPUT_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY":
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PREP_ONLY_DRIFT", f"{role} authority drifted")
        for guard in (
            "cannot_authorize_runtime_cutover",
            "cannot_open_r6",
            "cannot_authorize_lobe_escalation",
            "cannot_authorize_package_promotion",
            "cannot_authorize_commercial_activation_claims",
            "cannot_mutate_truth_engine_law",
            "cannot_mutate_trust_zone_law",
        ):
            if payload.get(guard) is not True:
                _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PREP_ONLY_DRIFT", f"{role}.{guard} missing")


def _validate_boards(payloads: Dict[str, Dict[str, Any]]) -> None:
    board = payloads["pipeline_board"].get("board", {})
    expected = {
        "expanded_canary_runtime": "PASSED_REPLAYED",
        "expanded_canary_evidence_review_packet": "BOUND_NEXT_VALIDATION",
        "runtime_cutover_review": "RECOMMENDED_AFTER_VALIDATION_NOT_AUTHORIZED",
        "runtime_cutover": "UNAUTHORIZED",
        "r6": "CLOSED",
        "package_promotion": "BLOCKED",
        "commercial_activation_claims": "UNAUTHORIZED",
    }
    for key, value in expected.items():
        if board.get(key) != value:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_NEXT_MOVE_DRIFT", f"pipeline board {key} drifted")


def _validate_report(text: str) -> None:
    lowered = text.lower()
    for phrase in (
        "runtime cutover remains unauthorized",
        "r6 remains closed",
        "package promotion and commercial activation claims remain unauthorized",
        "truth-engine and trust-zone law remain unchanged",
    ):
        if phrase not in lowered:
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_PACKET_MISSING", f"report missing {phrase}")


def _validate_review_payloads(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _ensure_authority_closed(payloads, texts)
    _validate_handoff(payloads)
    contract = payloads["packet_contract"]
    scorecard = payloads["evidence_scorecard"].get("scorecard", {})
    _validate_hash_maps(root, contract)
    _validate_inventory(payloads["evidence_inventory"], contract.get("binding_hashes", {}))
    _validate_scorecard(scorecard)
    _validate_decision_matrix(payloads["post_run_decision_matrix"].get("decision_matrix", {}), scorecard)
    _validate_readiness(payloads)
    _validate_blockers(payloads["post_expanded_canary_blocker_ledger"])
    _validate_review_contracts(payloads)
    _validate_prep_only(payloads)
    _validate_boards(payloads)
    _validate_report(texts["packet_report"])


def _guard() -> Dict[str, Any]:
    return {
        "expanded_canary_runtime_executed": True,
        "expanded_canary_evidence_review_packet_authored": True,
        "expanded_canary_evidence_review_validated": True,
        "runtime_cutover_review_packet_next": True,
        "runtime_cutover_review_packet_authored": False,
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
        "expanded_canary_evidence_treated_as_package_promotion": False,
    }


def _validation_rows() -> list[Dict[str, Any]]:
    checks = [
        "expanded_canary_evidence_review_packet_bound",
        "expanded_canary_evidence_inventory_bound",
        "expanded_canary_evidence_scorecard_bound",
        "post_run_decision_matrix_bound",
        "runtime_cutover_review_recommendation_supported",
        "runtime_cutover_not_authorized",
        "runtime_cutover_review_packet_not_authored_yet",
        "additional_expanded_canary_readiness_bound",
        "external_audit_readiness_bound",
        "post_expanded_canary_blocker_ledger_complete",
        "direct_review_contracts_bound",
        "prep_only_outputs_non_authoritative",
        "claim_bearing_authority_tokens_absent",
        "r6_remains_closed",
        "lobe_escalation_unauthorized",
        "package_promotion_blocked",
        "commercial_claims_blocked",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
        "next_lawful_move_runtime_cutover_review_packet_authoring",
    ]
    terminal = {
        "expanded_canary_evidence_review_packet_bound",
        "post_run_decision_matrix_bound",
        "runtime_cutover_review_recommendation_supported",
        "runtime_cutover_not_authorized",
        "prep_only_outputs_non_authoritative",
        "claim_bearing_authority_tokens_absent",
        "r6_remains_closed",
        "package_promotion_blocked",
        "commercial_claims_blocked",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
        "next_lawful_move_runtime_cutover_review_packet_authoring",
    }
    return [
        {
            "check_id": f"B04R6-EXPANDED-CANARY-EVIDENCE-VALIDATION-{idx:03d}",
            "name": check,
            "status": "PASS",
            "terminal_if_fail": check in terminal,
        }
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
        "recommended_next_path_validated": review.RECOMMENDED_NEXT_PATH,
        "may_authorize": list(MAY_AUTHORIZE),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "allowed_outcomes": [
            SELECTED_OUTCOME,
            OUTCOME_VALIDATED_ADDITIONAL_CANARY,
            OUTCOME_VALIDATED_EXTERNAL_AUDIT,
            OUTCOME_DEFERRED,
            OUTCOME_INVALID,
        ],
        "outcome_routing": {
            SELECTED_OUTCOME: NEXT_LAWFUL_MOVE,
            OUTCOME_VALIDATED_ADDITIONAL_CANARY: "AUTHOR_B04_R6_ADDITIONAL_EXPANDED_CANARY_AUTHORIZATION_PACKET",
            OUTCOME_VALIDATED_EXTERNAL_AUDIT: "AUTHOR_B04_R6_EXTERNAL_AUDIT_DELTA_PACKET",
            OUTCOME_DEFERRED: "REPAIR_B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATION_DEFECTS",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_EXPANDED_CANARY_EVIDENCE_REVIEW",
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
        schema_id=f"kt.b04_r6.expanded_canary_evidence_review.validation.{role}.v1",
        artifact_id=f"B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_{role.upper()}_RECEIPT",
        validation_role=role,
        validation_status="PASS",
        source_roles=list(source_roles),
        validated_hashes={f"{source}_hash": base["binding_hashes"].get(f"{source}_hash") for source in source_roles},
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str, **extra: Any) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.expanded_canary_evidence_review.validation.{role}.prep_only.v1",
        artifact_id=f"B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATION_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_authorize_runtime_cutover=True,
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
        "validation_contract": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review_validation_contract.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATION_CONTRACT",
            validation_summary=(
                "Expanded-canary evidence review is complete, hash-bound, and sufficient only to author "
                "a runtime cutover review packet."
            ),
        ),
        "validation_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review_validation_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATION_RECEIPT",
            verdict="EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATED_RUNTIME_CUTOVER_REVIEW_PACKET_NEXT",
        ),
        "no_authorization_drift_validation": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.no_authorization_drift_validation_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            no_authorization_drift=True,
        ),
        "claim_token_boundary_validation": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.claim_token_boundary_validation_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_CLAIM_TOKEN_BOUNDARY_VALIDATION_RECEIPT",
            claim_bearing_authority_tokens_absent=True,
        ),
        "pipeline_board": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.validation.pipeline_board.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATION_PIPELINE_BOARD",
            board={
                "expanded_canary_evidence_review": "VALIDATED",
                "runtime_cutover_review_packet": "NEXT_AUTHORING_LANE",
                "runtime_cutover": "UNAUTHORIZED",
                "r6": "CLOSED",
                "package_promotion": "BLOCKED",
                "commercial_activation_claims": "UNAUTHORIZED",
            },
        ),
        "future_blocker_register": _with_artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.validation.future_blocker_register.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATION_FUTURE_BLOCKER_REGISTER",
            blockers=[
                "runtime_cutover_review_packet_not_authored_or_validated",
                "runtime_cutover_execution_not_authorized",
                "r6_open_not_authorized",
                "package_promotion_requires_cutover_review_external_audit_and_package_review",
                "commercial_activation_claims_remain_forbidden",
            ],
        ),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_expanded_canary_evidence_review_validation_next_lawful_move_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT",
            receipt_type="NEXT_LAWFUL_MOVE",
        ),
    }
    receipt_sources = {
        "packet_binding_validation": ("packet_contract", "packet_receipt"),
        "evidence_inventory_validation": ("evidence_inventory",),
        "evidence_scorecard_validation": ("evidence_scorecard",),
        "post_run_decision_matrix_validation": ("post_run_decision_matrix",),
        "post_expanded_canary_blocker_ledger_validation": ("post_expanded_canary_blocker_ledger",),
        "runtime_cutover_readiness_validation": ("runtime_cutover_readiness_matrix",),
        "additional_expanded_canary_readiness_validation": ("additional_expanded_canary_readiness_matrix",),
        "external_audit_readiness_validation": ("external_audit_readiness_matrix",),
        "route_distribution_review_validation": ("route_distribution_review_contract",),
        "fallback_behavior_review_validation": ("fallback_behavior_review_contract",),
        "static_fallback_review_validation": ("static_fallback_review_contract",),
        "abstention_fallback_review_validation": ("abstention_fallback_review_contract",),
        "null_route_review_validation": ("null_route_review_contract",),
        "operator_override_review_validation": ("operator_override_review_contract",),
        "kill_switch_review_validation": ("kill_switch_review_contract",),
        "rollback_review_validation": ("rollback_review_contract",),
        "drift_monitoring_review_validation": ("drift_monitoring_review_contract",),
        "incident_freeze_review_validation": ("incident_freeze_review_contract",),
        "trace_completeness_review_validation": ("trace_completeness_review_contract",),
        "replay_readiness_review_validation": ("replay_readiness_review_contract",),
        "external_verifier_readiness_validation": ("external_verifier_readiness_review_contract",),
        "commercial_claim_boundary_validation": ("commercial_claim_boundary_review_contract",),
        "package_promotion_blocker_validation": ("package_promotion_blocker_review_contract",),
        "prep_only_boundary_validation": tuple(review.PREP_ONLY_OUTPUT_ROLES),
    }
    for role, source_roles in receipt_sources.items():
        payloads[role] = _validation_receipt(base, role=role, source_roles=source_roles)
    payloads.update(
        {
            "runtime_cutover_review_validation_plan_prep_only": _prep_only(
                base,
                role="runtime_cutover_review_validation_plan_prep_only",
                purpose="Prepare validation law for a future runtime cutover review packet.",
            ),
            "runtime_cutover_review_packet_prep_only_draft": _prep_only(
                base,
                role="runtime_cutover_review_packet_prep_only_draft",
                purpose="Draft the future runtime cutover review packet; does not authorize cutover.",
            ),
            "additional_expanded_canary_authorization_validation_plan_prep_only": _prep_only(
                base,
                role="additional_expanded_canary_authorization_validation_plan_prep_only",
                purpose="Prepare fallback validation if another expanded canary is selected later.",
            ),
            "external_audit_delta_validation_plan_prep_only": _prep_only(
                base,
                role="external_audit_delta_validation_plan_prep_only",
                purpose="Prepare validation law for a future external audit delta packet.",
            ),
            "package_promotion_review_preconditions_prep_only_draft": _prep_only(
                base,
                role="package_promotion_review_preconditions_prep_only_draft",
                purpose="Track package-promotion preconditions; promotion remains blocked.",
            ),
        }
    )
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Expanded Canary Evidence Review Validation",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "The expanded-canary evidence review packet validates as complete, hash-bound, and evidence-supported.",
            "The validated recommendation permits only runtime cutover review packet authorship.",
            "",
            "This validation does not authorize runtime cutover, does not open R6, does not authorize lobe escalation,",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 expanded-canary evidence review validation")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_review_payloads(root, payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_VAL_TRUST_ZONE_FAILED", "trust-zone validation failed")
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
    parser = argparse.ArgumentParser(description="Validate the B04 R6 expanded-canary evidence review packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
