from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_r6_opening_authorization_packet as auth
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/b04-r6-r6-opening-authorization-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-r6-opening-authorization-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_R6_OPENING_AUTHORIZATION_PACKET_VALIDATION"
PREVIOUS_LANE = auth.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = auth.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = auth.NEXT_LAWFUL_MOVE

SELECTED_OUTCOME = auth.VALIDATION_SUCCESS_OUTCOME
NEXT_LAWFUL_MOVE = auth.VALIDATION_SUCCESS_NEXT_MOVE
OUTCOME_DEFERRED = "B04_R6_R6_OPENING_AUTHORIZATION_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
OUTCOME_REJECTED = "B04_R6_R6_OPENING_AUTHORIZATION_REJECTED__R6_OPENING_NOT_JUSTIFIED"
OUTCOME_INVALID = "B04_R6_R6_OPENING_AUTHORIZATION_INVALID__FORENSIC_R6_OPENING_AUTHORIZATION_REVIEW_NEXT"

FORBIDDEN_ACTIONS = (
    "R6_OPENING_EXECUTED",
    "R6_OPEN",
    "GLOBAL_RUNTIME_SURFACE_AUTHORIZED",
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "METRIC_CONTRACT_MUTATED",
    "STATIC_COMPARATOR_WEAKENED",
)
TEXT_FORBIDDEN_CLAIMS = {
    "R6 IS OPEN": "RC_B04R6_R6_OPENING_AUTH_VAL_R6_OPEN_DRIFT",
    "R6 OPENED": "RC_B04R6_R6_OPENING_AUTH_VAL_R6_OPEN_DRIFT",
    "R6 OPENING EXECUTED": "RC_B04R6_R6_OPENING_AUTH_VAL_EXECUTION_DRIFT",
    "R6_OPENING_EXECUTED": "RC_B04R6_R6_OPENING_AUTH_VAL_EXECUTION_DRIFT",
    "PACKAGE PROMOTION AUTHORIZED": "RC_B04R6_R6_OPENING_AUTH_VAL_PACKAGE_PROMOTION_DRIFT",
    "PACKAGE_PROMOTION_AUTHORIZED": "RC_B04R6_R6_OPENING_AUTH_VAL_PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL ACTIVATION CLAIM AUTHORIZED": "RC_B04R6_R6_OPENING_AUTH_VAL_COMMERCIAL_CLAIM_DRIFT",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED": "RC_B04R6_R6_OPENING_AUTH_VAL_COMMERCIAL_CLAIM_DRIFT",
}
AUTHORITY_DRIFT_KEYS = {
    "r6_opening_authorized": "RC_B04R6_R6_OPENING_AUTH_VAL_AUTHORIZATION_DRIFT",
    "r6_opening_executed": "RC_B04R6_R6_OPENING_AUTH_VAL_EXECUTION_DRIFT",
    "r6_open": "RC_B04R6_R6_OPENING_AUTH_VAL_R6_OPEN_DRIFT",
    "global_runtime_surface_authorized": "RC_B04R6_R6_OPENING_AUTH_VAL_GLOBAL_SURFACE_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_R6_OPENING_AUTH_VAL_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_R6_OPENING_AUTH_VAL_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_R6_OPENING_AUTH_VAL_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_R6_OPENING_AUTH_VAL_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_R6_OPENING_AUTH_VAL_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_R6_OPENING_AUTH_VAL_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_R6_OPENING_AUTH_VAL_COMPARATOR_WEAKENED",
    "r6_opening_authorization_treated_as_r6_open": "RC_B04R6_R6_OPENING_AUTH_VAL_R6_OPEN_DRIFT",
    "r6_opening_authorization_treated_as_package_promotion": "RC_B04R6_R6_OPENING_AUTH_VAL_PACKAGE_PROMOTION_DRIFT",
}

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_MISSING",
            "RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_OUTCOME_DRIFT",
            "RC_B04R6_R6_OPENING_AUTH_VAL_NEXT_MOVE_DRIFT",
            "RC_B04R6_R6_OPENING_AUTH_VAL_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_R6_OPENING_AUTH_VAL_INPUT_HASH_DRIFT",
            "RC_B04R6_R6_OPENING_AUTH_VAL_CONTROL_CONTRACT_MISSING",
            "RC_B04R6_R6_OPENING_AUTH_VAL_SHARED_BOARD_SHAPE_DRIFT",
            "RC_B04R6_R6_OPENING_AUTH_VAL_PREP_ONLY_DRIFT",
            "RC_B04R6_R6_OPENING_AUTH_VAL_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_R6_OPENING_AUTH_VAL_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

AUTH_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in auth.OUTPUTS.items()
    if filename.endswith(".json")
}
AUTH_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in auth.OUTPUTS.items()
    if not filename.endswith(".json")
}

VALIDATION_MAP = {
    "packet_binding_validation": "packet_contract",
    "scope_validation": "scope_contract",
    "allowed_surface_validation": "allowed_surface_contract",
    "excluded_surface_validation": "excluded_surface_contract",
    "opening_preconditions_validation": "opening_preconditions_contract",
    "static_fallback_validation": "static_fallback_contract",
    "operator_override_validation": "operator_override_contract",
    "kill_switch_validation": "kill_switch_contract",
    "rollback_validation": "rollback_contract",
    "monitoring_window_validation": "monitoring_window_contract",
    "route_distribution_threshold_validation": "route_distribution_thresholds",
    "drift_threshold_validation": "drift_thresholds",
    "incident_freeze_validation": "incident_freeze_contract",
    "runtime_receipt_schema_validation": "runtime_receipt_schema",
    "external_verifier_validation": "external_verifier_requirements",
    "commercial_claim_ceiling_validation": "commercial_claim_ceiling",
    "package_promotion_prohibition_validation": "package_promotion_prohibition_receipt",
    "pipeline_board_validation": "pipeline_board",
    "campaign_board_validation": "campaign_board",
    "future_blocker_register_validation": "future_blocker_register",
}
VALIDATION_RECEIPT_ROLES = tuple(VALIDATION_MAP)
PREP_ONLY_OUTPUT_ROLES = (
    "r6_opening_execution_packet_prep_only_draft",
    "r6_opening_execution_validation_plan_prep_only",
    "post_opening_evidence_review_packet_prep_only_draft",
    "rollback_freeze_forensic_path_prep_only",
)

OUTPUTS = {
    "validation_contract": "b04_r6_r6_opening_authorization_validation_contract.json",
    "validation_receipt": "b04_r6_r6_opening_authorization_validation_receipt.json",
    "validation_report": "b04_r6_r6_opening_authorization_validation_report.md",
    "packet_binding_validation": "b04_r6_r6_opening_authorization_packet_binding_validation_receipt.json",
    "scope_validation": "b04_r6_r6_opening_authorization_scope_validation_receipt.json",
    "allowed_surface_validation": "b04_r6_r6_opening_authorization_allowed_surface_validation_receipt.json",
    "excluded_surface_validation": "b04_r6_r6_opening_authorization_excluded_surface_validation_receipt.json",
    "opening_preconditions_validation": "b04_r6_r6_opening_authorization_preconditions_validation_receipt.json",
    "static_fallback_validation": "b04_r6_r6_opening_authorization_static_fallback_validation_receipt.json",
    "operator_override_validation": "b04_r6_r6_opening_authorization_operator_override_validation_receipt.json",
    "kill_switch_validation": "b04_r6_r6_opening_authorization_kill_switch_validation_receipt.json",
    "rollback_validation": "b04_r6_r6_opening_authorization_rollback_validation_receipt.json",
    "monitoring_window_validation": "b04_r6_r6_opening_authorization_monitoring_window_validation_receipt.json",
    "route_distribution_threshold_validation": (
        "b04_r6_r6_opening_authorization_route_distribution_threshold_validation_receipt.json"
    ),
    "drift_threshold_validation": "b04_r6_r6_opening_authorization_drift_threshold_validation_receipt.json",
    "incident_freeze_validation": "b04_r6_r6_opening_authorization_incident_freeze_validation_receipt.json",
    "runtime_receipt_schema_validation": "b04_r6_r6_opening_authorization_runtime_receipt_schema_validation_receipt.json",
    "external_verifier_validation": "b04_r6_r6_opening_authorization_external_verifier_validation_receipt.json",
    "commercial_claim_ceiling_validation": "b04_r6_r6_opening_authorization_commercial_claim_ceiling_validation_receipt.json",
    "package_promotion_prohibition_validation": (
        "b04_r6_r6_opening_authorization_package_promotion_prohibition_validation_receipt.json"
    ),
    "pipeline_board_validation": "b04_r6_r6_opening_authorization_pipeline_board_validation_receipt.json",
    "campaign_board_validation": "b04_r6_r6_opening_authorization_campaign_board_validation_receipt.json",
    "future_blocker_register_validation": (
        "b04_r6_r6_opening_authorization_future_blocker_register_validation_receipt.json"
    ),
    "no_authorization_drift_validation": (
        "b04_r6_r6_opening_authorization_no_authorization_drift_validation_receipt.json"
    ),
    "r6_opening_execution_packet_prep_only_draft": (
        "b04_r6_r6_opening_execution_packet_after_authorization_validation_prep_only_draft.json"
    ),
    "r6_opening_execution_validation_plan_prep_only": (
        "b04_r6_r6_opening_execution_validation_plan_after_authorization_validation_prep_only.json"
    ),
    "post_opening_evidence_review_packet_prep_only_draft": (
        "b04_r6_post_opening_evidence_review_after_authorization_validation_prep_only_draft.json"
    ),
    "rollback_freeze_forensic_path_prep_only": (
        "b04_r6_r6_opening_rollback_freeze_forensic_after_authorization_validation_prep_only.json"
    ),
    "next_lawful_move": "b04_r6_r6_opening_authorization_validation_next_lawful_move_receipt.json",
}


class LaneFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise LaneFailure(code, detail)


def _walk(value: Any, *, context_key: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            yield key_text, item
            yield from _walk(item, context_key=key_text)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                yield from _walk(item, context_key=context_key)
            else:
                yield context_key, item


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_B04R6_R6_OPENING_AUTH_VAL_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_R6_OPENING_AUTH_VAL_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


def _claim_field_allows_positive_tokens(key: str) -> bool:
    lowered = key.lower()
    return "forbidden_claim" in lowered or "forbidden_commercial_claim" in lowered


def _token_words(value: str) -> list[str]:
    return re.findall(r"[A-Z0-9]+", value.upper().replace("-", "_"))


def _contains_sequence(words: Sequence[str], token: str) -> bool:
    token_words = token.split("_")
    if len(token_words) == 1:
        return token_words[0] in words
    return any(words[index : index + len(token_words)] == token_words for index in range(len(words)))


def _contains_positive_authority_token(value: str) -> bool:
    words = _token_words(value)
    return any(_contains_sequence(words, token) for token in auth.POSITIVE_AUTHORITY_TOKENS)


def _contains_negative_authority_qualifier(value: str) -> bool:
    words = _token_words(value)
    return any(_contains_sequence(words, qualifier.replace(" ", "_")) for qualifier in auth.NEGATIVE_AUTHORITY_QUALIFIERS)


def _ensure_authority_closed(payload: Dict[str, Any], *, label: str) -> None:
    for key, value in _walk(payload):
        if key in AUTHORITY_DRIFT_KEYS and value is not False:
            _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted to {value!r}")
        if key == "r6" and isinstance(value, str) and value.upper() == "OPEN":
            _fail("RC_B04R6_R6_OPENING_AUTH_VAL_R6_OPEN_DRIFT", f"{label}.{key} contains OPEN")
    if payload.get("package_promotion") not in (None, "DEFERRED", "BLOCKED"):
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_PACKAGE_PROMOTION_DRIFT", f"{label}.package_promotion drifted")


def _ensure_claim_boundary(payload: Dict[str, Any], *, label: str) -> None:
    for key, value in _walk(payload):
        if not isinstance(value, str):
            continue
        key_text = str(key)
        if not auth._is_claim_bearing_field(key_text):
            continue
        if not _contains_positive_authority_token(value):
            continue
        if _contains_negative_authority_qualifier(value):
            continue
        if _claim_field_allows_positive_tokens(key_text):
            continue
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_CLAIM_TOKEN_DRIFT", f"{label}.{key_text} contains {value!r}")


def _ensure_text_authority_closed(text: str, *, label: str) -> None:
    upper = text.upper()
    for token, reason in TEXT_FORBIDDEN_CLAIMS.items():
        if token in upper:
            _fail(reason, f"{label} contains forbidden claim token {token!r}")


def _load_authorization_payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in AUTH_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in AUTH_TEXT_INPUTS.items()}
    return payloads, texts


def _validate_authorization_payloads(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    contract = payloads.get("packet_contract")
    receipt = payloads.get("packet_receipt")
    next_move = payloads.get("next_lawful_move")
    if not contract or not receipt or not next_move:
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_MISSING", "authorization packet core artifacts missing")
    if contract.get("authoritative_lane") != PREVIOUS_LANE or receipt.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_OUTCOME_DRIFT", "authorization packet lane mismatch")
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_OUTCOME_DRIFT", "authorization packet outcome drifted")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_OUTCOME_DRIFT", "authorization receipt outcome drifted")
    if next_move.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_NEXT_MOVE_DRIFT", "authorization next move lane drifted")
    if next_move.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_OUTCOME_DRIFT", "authorization next move outcome drifted")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_NEXT_MOVE_DRIFT", "authorization next move drifted")
    if not contract.get("input_bindings"):
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_INPUT_BINDINGS_EMPTY", "authorization packet input_bindings empty")
    if contract.get("r6_opening_authorization_packet_authored") is not True:
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_MISSING", "authorization packet was not authored")
    if contract.get("r6_opening_authorization_validated") is not False:
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_OUTCOME_DRIFT", "input already claims validation")
    for role in auth.CONTROL_CONTRACT_ROLES:
        payload = payloads.get(role)
        if not payload or payload.get("control_status") != "DEFINED_FOR_VALIDATION":
            _fail("RC_B04R6_R6_OPENING_AUTH_VAL_CONTROL_CONTRACT_MISSING", f"{role} missing or unbound")
    for role in auth.PREP_ONLY_OUTPUT_ROLES:
        payload = payloads.get(role)
        if not payload or payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_R6_OPENING_AUTH_VAL_PREP_ONLY_DRIFT", f"{role} not prep-only")
    if payloads["pipeline_board"].get("artifact_id") != "B04_R6_PIPELINE_BOARD" or not isinstance(
        payloads["pipeline_board"].get("lanes"), list
    ):
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_SHARED_BOARD_SHAPE_DRIFT", "pipeline board shape drift")
    if payloads["campaign_board"].get("artifact_id") != "KT_E2E_CLOSURE_CAMPAIGN_BOARD" or not isinstance(
        payloads["campaign_board"].get("corridors"), list
    ):
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_SHARED_BOARD_SHAPE_DRIFT", "campaign board shape drift")
    if payloads["future_blocker_register"].get("artifact_id") != "KT_FUTURE_BLOCKER_REGISTER" or not isinstance(
        payloads["future_blocker_register"].get("blockers"), list
    ):
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_SHARED_BOARD_SHAPE_DRIFT", "future blocker register shape drift")
    report = texts.get("packet_report", "").lower()
    for phrase in ("does not execute r6 opening", "does not open r6", "does not promote package"):
        if phrase not in report:
            _fail("RC_B04R6_R6_OPENING_AUTH_VAL_PACKET_MISSING", f"packet report missing {phrase!r}")
    for role, payload in payloads.items():
        _ensure_authority_closed(payload, label=role)
        _ensure_claim_boundary(payload, label=role)
    for role, text in texts.items():
        _ensure_text_authority_closed(text, label=role)


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows = [
        {
            "role": role,
            "path": raw,
            "sha256": file_sha256(root / raw),
            "binding_kind": "file_sha256_at_r6_opening_authorization_validation",
        }
        for role, raw in {**AUTH_JSON_INPUTS, **AUTH_TEXT_INPUTS}.items()
    ]
    return sorted(rows, key=lambda row: row["role"])


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    input_bindings: list[Dict[str, str]],
    binding_hashes: Dict[str, str],
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
        "allowed_outcomes": [SELECTED_OUTCOME, OUTCOME_DEFERRED, OUTCOME_REJECTED, OUTCOME_INVALID],
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "runtime_cutover_executed": True,
        "post_cutover_evidence_review_validated": True,
        "r6_opening_review_validated": True,
        "r6_opening_authorization_packet_authored": True,
        "r6_opening_authorization_validated": True,
        "r6_opening_execution_packet_authored": False,
        "r6_opening_execution_packet_validated": False,
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
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _validation_receipt(base: Dict[str, Any], *, role: str, validated_role: str, validated_hash: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.r6_opening_authorization_validation.{role}.receipt.v1",
        artifact_id=f"B04_R6_R6_OPENING_AUTHORIZATION_{role.upper()}",
        validation_status="PASS",
        validated_role=validated_role,
        validated_hash=validated_hash,
        reason_code=None,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.r6_opening_authorization_validation.{role}.prep_only.v1",
        artifact_id=f"B04_R6_R6_OPENING_AUTHORIZATION_VALIDATION_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_execute_r6_opening=True,
        cannot_open_r6=True,
        cannot_authorize_lobe_escalation=True,
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _payloads(base: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    binding_hashes = base["binding_hashes"]
    output: Dict[str, Dict[str, Any]] = {
        "validation_contract": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_authorization_validation.contract.v1",
            artifact_id="B04_R6_R6_OPENING_AUTHORIZATION_VALIDATION_CONTRACT",
            validation_scope="VALIDATE_R6_OPENING_AUTHORIZATION_PACKET_ONLY",
            validation_success_next_authority=NEXT_LAWFUL_MOVE,
            does_not_execute_r6_opening=True,
            does_not_open_r6=True,
        ),
        "validation_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_authorization_validation.receipt.v1",
            artifact_id="B04_R6_R6_OPENING_AUTHORIZATION_VALIDATION_RECEIPT",
            verdict="VALIDATED_FOR_R6_OPENING_EXECUTION_PACKET_AUTHORING_ONLY",
        ),
        "no_authorization_drift_validation": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_authorization_validation.no_authorization_drift.receipt.v1",
            artifact_id="B04_R6_R6_OPENING_AUTHORIZATION_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            validation_status="PASS",
            drift_detected=False,
        ),
        "r6_opening_execution_packet_prep_only_draft": _prep_only(
            base,
            role="r6_opening_execution_packet_prep_only_draft",
            purpose="Prepare future R6 opening execution packet authoring; does not open R6.",
        ),
        "r6_opening_execution_validation_plan_prep_only": _prep_only(
            base,
            role="r6_opening_execution_validation_plan_prep_only",
            purpose="Prepare validation plan for a future R6 opening execution packet.",
        ),
        "post_opening_evidence_review_packet_prep_only_draft": _prep_only(
            base,
            role="post_opening_evidence_review_packet_prep_only_draft",
            purpose="Prepare post-opening evidence review structure.",
        ),
        "rollback_freeze_forensic_path_prep_only": _prep_only(
            base,
            role="rollback_freeze_forensic_path_prep_only",
            purpose="Prepare rollback, freeze, and forensic paths for future R6 opening law.",
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_authorization_validation.next_lawful_move.receipt.v1",
            artifact_id="B04_R6_R6_OPENING_AUTHORIZATION_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT",
        ),
    }
    for role, validated_role in VALIDATION_MAP.items():
        output[role] = _validation_receipt(
            base,
            role=role,
            validated_role=validated_role,
            validated_hash=binding_hashes[f"{validated_role}_hash"],
        )
    return output


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 R6 Opening Authorization Validation",
            "",
            f"Outcome: `{contract['selected_outcome']}`",
            f"Next lawful move: `{contract['next_lawful_move']}`",
            "",
            "This validates the R6 opening authorization packet for future R6 opening execution packet authoring only.",
            "It does not execute R6 opening, does not open R6, does not promote package, and does not authorize commercial activation claims.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 R6 opening authorization validation")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    packet_head = current_main_head if branch != "main" else head
    payloads, texts = _load_authorization_payloads(root)
    _validate_authorization_payloads(payloads, texts)
    trust = validate_trust_zones(root=root)
    if trust.get("status") != "PASS":
        _fail("RC_B04R6_R6_OPENING_AUTH_VAL_TRUST_ZONE_FAILED", str(trust.get("failures", [])))
    input_bindings = _input_bindings(root)
    binding_hashes = {f"{row['role']}_hash": row["sha256"] for row in input_bindings}
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=packet_head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=input_bindings,
        binding_hashes=binding_hashes,
    )
    output_payloads = _payloads(base)
    contract = output_payloads["validation_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "validation_report":
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
