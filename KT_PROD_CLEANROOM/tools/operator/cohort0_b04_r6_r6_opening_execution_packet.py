from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_r6_opening_authorization_packet_validation as auth_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/b04-r6-r6-opening-execution-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-r6-opening-execution-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_R6_OPENING_EXECUTION_PACKET"
PREVIOUS_LANE = auth_validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = auth_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = auth_validation.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = "B04_R6_R6_OPENING_EXECUTION_PACKET_BOUND__R6_OPENING_EXECUTION_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_R6_OPENING_EXECUTION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_REJECTED = "B04_R6_R6_OPENING_EXECUTION_PACKET_REJECTED__R6_OPENING_EXECUTION_NOT_JUSTIFIED"
OUTCOME_INVALID = "B04_R6_R6_OPENING_EXECUTION_PACKET_INVALID__FORENSIC_R6_OPENING_EXECUTION_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_R6_OPENING_EXECUTION_PACKET"

VALIDATION_SUCCESS_OUTCOME = "B04_R6_R6_OPENING_EXECUTION_PACKET_VALIDATED__R6_OPENING_NEXT"
VALIDATION_SUCCESS_NEXT_MOVE = "RUN_B04_R6_R6_OPENING"

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
AUTHORITY_DRIFT_KEYS = {
    "r6_opening_authorized": "RC_B04R6_R6_OPENING_EXEC_PACKET_AUTHORIZATION_DRIFT",
    "r6_opening_executed": "RC_B04R6_R6_OPENING_EXEC_PACKET_EXECUTION_DRIFT",
    "r6_open": "RC_B04R6_R6_OPENING_EXEC_PACKET_R6_OPEN_DRIFT",
    "global_runtime_surface_authorized": "RC_B04R6_R6_OPENING_EXEC_PACKET_GLOBAL_SURFACE_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_R6_OPENING_EXEC_PACKET_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_R6_OPENING_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_R6_OPENING_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_R6_OPENING_EXEC_PACKET_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_R6_OPENING_EXEC_PACKET_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_R6_OPENING_EXEC_PACKET_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_R6_OPENING_EXEC_PACKET_COMPARATOR_WEAKENED",
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
    "ACTIVE",
    "AUTHORIZED",
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
    "DOES_NOT_AUTHORIZE",
    "FORBIDDEN",
    "NO_PACKAGE_PROMOTION",
    "NOT_AUTHORIZED",
    "NOT_OPEN",
    "PACKET",
    "PREP_ONLY",
    "PROHIBITED",
    "REMAINS_CLOSED",
    "UNAUTHORIZED",
    "UNEXECUTED",
)
TEXT_FORBIDDEN_CLAIMS = {
    "R6 IS OPEN": "RC_B04R6_R6_OPENING_EXEC_PACKET_R6_OPEN_DRIFT",
    "R6 OPENED": "RC_B04R6_R6_OPENING_EXEC_PACKET_R6_OPEN_DRIFT",
    "R6 OPENING EXECUTED": "RC_B04R6_R6_OPENING_EXEC_PACKET_EXECUTION_DRIFT",
    "R6_OPENING_EXECUTED": "RC_B04R6_R6_OPENING_EXEC_PACKET_EXECUTION_DRIFT",
    "PACKAGE PROMOTION AUTHORIZED": "RC_B04R6_R6_OPENING_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT",
    "PACKAGE_PROMOTION_AUTHORIZED": "RC_B04R6_R6_OPENING_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL ACTIVATION CLAIM AUTHORIZED": "RC_B04R6_R6_OPENING_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED": "RC_B04R6_R6_OPENING_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT",
}
FORBIDDEN_ACTION_REASON_CODES = {
    "R6_OPENING_EXECUTED": "RC_B04R6_R6_OPENING_EXEC_PACKET_EXECUTION_DRIFT",
    "R6_OPEN": "RC_B04R6_R6_OPENING_EXEC_PACKET_R6_OPEN_DRIFT",
    "GLOBAL_RUNTIME_SURFACE_AUTHORIZED": "RC_B04R6_R6_OPENING_EXEC_PACKET_GLOBAL_SURFACE_DRIFT",
    "LOBE_ESCALATION_AUTHORIZED": "RC_B04R6_R6_OPENING_EXEC_PACKET_LOBE_ESCALATION_DRIFT",
    "PACKAGE_PROMOTION_AUTHORIZED": "RC_B04R6_R6_OPENING_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED": "RC_B04R6_R6_OPENING_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "TRUTH_ENGINE_LAW_MUTATED": "RC_B04R6_R6_OPENING_EXEC_PACKET_TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_LAW_MUTATED": "RC_B04R6_R6_OPENING_EXEC_PACKET_TRUST_ZONE_MUTATION",
    "METRIC_CONTRACT_MUTATED": "RC_B04R6_R6_OPENING_EXEC_PACKET_METRIC_MUTATION",
    "STATIC_COMPARATOR_WEAKENED": "RC_B04R6_R6_OPENING_EXEC_PACKET_COMPARATOR_WEAKENED",
}

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_R6_OPENING_EXEC_PACKET_PREVIOUS_VALIDATION_MISSING",
            "RC_B04R6_R6_OPENING_EXEC_PACKET_PREVIOUS_OUTCOME_DRIFT",
            "RC_B04R6_R6_OPENING_EXEC_PACKET_NEXT_MOVE_DRIFT",
            "RC_B04R6_R6_OPENING_EXEC_PACKET_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_R6_OPENING_EXEC_PACKET_PREP_ONLY_DRIFT",
            "RC_B04R6_R6_OPENING_EXEC_PACKET_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_R6_OPENING_EXEC_PACKET_CONTROL_MISSING",
            "RC_B04R6_R6_OPENING_EXEC_PACKET_TRUST_ZONE_FAILED",
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
    "allowed_surface_contract",
    "excluded_surface_contract",
    "opening_preconditions_contract",
    "static_fallback_contract",
    "operator_override_contract",
    "kill_switch_contract",
    "rollback_contract",
    "monitoring_window_contract",
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
    "r6_opening_run_result_schema_prep_only",
    "post_opening_evidence_review_packet_prep_only_draft",
    "r6_opening_failure_closeout_prep_only_draft",
    "forensic_r6_opening_review_prep_only_draft",
    "package_promotion_review_packet_prep_only_draft",
    "external_audit_delta_manifest_prep_only",
    "public_verifier_delta_requirements_prep_only",
    "commercial_claim_boundary_update_prep_only",
    "pipeline_board",
    "future_blocker_register",
)
SHARED_CANONICAL_INPUTS = {
    "source_pipeline_board": "KT_PROD_CLEANROOM/reports/b04_r6_pipeline_board.json",
    "source_future_blocker_register": "KT_PROD_CLEANROOM/reports/b04_r6_future_blocker_register.json",
    "source_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}

OUTPUTS = {
    "packet_contract": "b04_r6_r6_opening_execution_packet_contract.json",
    "packet_receipt": "b04_r6_r6_opening_execution_packet_receipt.json",
    "packet_report": "b04_r6_r6_opening_execution_packet_report.md",
    "mode_contract": "b04_r6_r6_opening_execution_mode_contract.json",
    "scope_manifest": "b04_r6_r6_opening_execution_scope_manifest.json",
    "allowed_surface_contract": "b04_r6_r6_opening_execution_allowed_surface_contract.json",
    "excluded_surface_contract": "b04_r6_r6_opening_execution_excluded_surface_contract.json",
    "opening_preconditions_contract": "b04_r6_r6_opening_execution_preconditions_contract.json",
    "static_fallback_contract": "b04_r6_r6_opening_execution_static_fallback_contract.json",
    "operator_override_contract": "b04_r6_r6_opening_execution_operator_override_contract.json",
    "kill_switch_contract": "b04_r6_r6_opening_execution_kill_switch_contract.json",
    "rollback_contract": "b04_r6_r6_opening_execution_rollback_contract.json",
    "monitoring_window_contract": "b04_r6_r6_opening_execution_monitoring_window_contract.json",
    "route_distribution_thresholds": "b04_r6_r6_opening_execution_route_distribution_thresholds.json",
    "drift_thresholds": "b04_r6_r6_opening_execution_drift_thresholds.json",
    "incident_freeze_contract": "b04_r6_r6_opening_execution_incident_freeze_contract.json",
    "runtime_receipt_schema": "b04_r6_r6_opening_execution_runtime_receipt_schema.json",
    "replay_manifest": "b04_r6_r6_opening_execution_replay_manifest.json",
    "expected_artifact_manifest": "b04_r6_r6_opening_execution_expected_artifact_manifest.json",
    "external_verifier_requirements": "b04_r6_r6_opening_execution_external_verifier_requirements.json",
    "result_interpretation_contract": "b04_r6_r6_opening_execution_result_interpretation_contract.json",
    "commercial_claim_boundary": "b04_r6_r6_opening_execution_commercial_claim_boundary.json",
    "package_promotion_prohibition_receipt": "b04_r6_r6_opening_execution_package_promotion_prohibition_receipt.json",
    "validation_plan": "b04_r6_r6_opening_execution_validation_plan.json",
    "validation_reason_codes": "b04_r6_r6_opening_execution_validation_reason_codes.json",
    "no_authorization_drift_receipt": "b04_r6_r6_opening_execution_no_authorization_drift_receipt.json",
    "r6_opening_run_result_schema_prep_only": "b04_r6_r6_opening_run_result_schema_prep_only.json",
    "post_opening_evidence_review_packet_prep_only_draft": (
        "b04_r6_post_opening_evidence_review_packet_prep_only_draft.json"
    ),
    "r6_opening_failure_closeout_prep_only_draft": "b04_r6_r6_opening_failure_closeout_prep_only_draft.json",
    "forensic_r6_opening_review_prep_only_draft": "b04_r6_forensic_r6_opening_review_prep_only_draft.json",
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


def _token_words(value: str) -> list[str]:
    return re.findall(r"[A-Z0-9]+", value.upper().replace("-", "_"))


def _contains_sequence(words: Sequence[str], token: str) -> bool:
    token_words = token.split("_")
    if len(token_words) == 1:
        return token_words[0] in words
    return any(words[index : index + len(token_words)] == token_words for index in range(len(words)))


def _contains_positive_authority_token(value: str) -> bool:
    words = _token_words(value)
    return any(_contains_sequence(words, token) for token in POSITIVE_AUTHORITY_TOKENS)


def _contains_negative_authority_qualifier(value: str) -> bool:
    words = _token_words(value)
    return any(_contains_sequence(words, qualifier.replace(" ", "_")) for qualifier in NEGATIVE_AUTHORITY_QUALIFIERS)


def _claim_field_allows_positive_tokens(key: str) -> bool:
    lowered = key.lower()
    return "forbidden_claim" in lowered or "forbidden_commercial_claim" in lowered


def _is_claim_bearing_field(key: str) -> bool:
    lowered = key.lower()
    if lowered == "r6":
        return True
    return any(marker in lowered for marker in CLAIM_BEARING_FIELD_MARKERS)


def _forbidden_claim_phrase_reason(value: str) -> Optional[str]:
    words = _token_words(value)
    for phrase, reason in TEXT_FORBIDDEN_CLAIMS.items():
        if _contains_sequence(words, phrase.replace(" ", "_")):
            return reason
    return None


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_PREVIOUS_VALIDATION_MISSING", f"{label} must be object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


def _git_blob_sha256(root: Path, commit: str, raw: str) -> str:
    blob_ref = f"{commit}:{raw.replace(chr(92), '/')}"
    try:
        result = subprocess.run(["git", "show", blob_ref], cwd=root, capture_output=True, check=True)
    except subprocess.CalledProcessError as exc:
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_INPUT_BINDINGS_EMPTY", f"missing git blob {blob_ref}: {exc}")
    return hashlib.sha256(result.stdout).hexdigest()


def _ensure_authority_closed(payload: Dict[str, Any], *, label: str) -> None:
    for key, value in _walk(payload):
        if key in AUTHORITY_DRIFT_KEYS and value is not False:
            _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted to {value!r}")
        if key == "r6" and isinstance(value, str) and value.upper() == "OPEN":
            _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_R6_OPEN_DRIFT", f"{label}.{key} contains OPEN")
    if payload.get("package_promotion") not in (None, "DEFERRED", "BLOCKED"):
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT", f"{label}.package_promotion drifted")


def _ensure_claim_boundary(payload: Dict[str, Any], *, label: str) -> None:
    for key, value in _walk(payload):
        if not isinstance(value, str):
            continue
        key_text = str(key)
        if not _is_claim_bearing_field(key_text):
            continue
        forbidden_reason = _forbidden_claim_phrase_reason(value)
        if forbidden_reason and not _claim_field_allows_positive_tokens(key_text):
            _fail(forbidden_reason, f"{label}.{key_text} contains {value!r}")
        if not _contains_positive_authority_token(value):
            continue
        if _contains_negative_authority_qualifier(value):
            continue
        if _claim_field_allows_positive_tokens(key_text):
            continue
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_CLAIM_TOKEN_DRIFT", f"{label}.{key_text} contains {value!r}")


def _ensure_text_authority_closed(text: str, *, label: str) -> None:
    words = _token_words(text)
    for phrase, reason in TEXT_FORBIDDEN_CLAIMS.items():
        if _contains_sequence(words, phrase.replace(" ", "_")):
            _fail(reason, f"{label} contains forbidden claim phrase {phrase!r}")
    for token, reason in FORBIDDEN_ACTION_REASON_CODES.items():
        if _contains_sequence(words, token):
            _fail(reason, f"{label} contains forbidden action token {token!r}")


def _payloads_from_inputs(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in VALIDATION_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in VALIDATION_TEXT_INPUTS.items()}
    return payloads, texts


def _validate_previous(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    contract = payloads.get("validation_contract")
    receipt = payloads.get("validation_receipt")
    next_move = payloads.get("next_lawful_move")
    if not contract or not receipt or not next_move:
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_PREVIOUS_VALIDATION_MISSING", "authorization validation missing")
    if contract.get("authoritative_lane") != PREVIOUS_LANE or receipt.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_PREVIOUS_VALIDATION_MISSING", "authorization validation lane drifted")
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_PREVIOUS_OUTCOME_DRIFT", "authorization validation outcome drifted")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_PREVIOUS_OUTCOME_DRIFT", "authorization validation receipt drifted")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_NEXT_MOVE_DRIFT", "authorization validation next move drifted")
    if not contract.get("input_bindings"):
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_INPUT_BINDINGS_EMPTY", "authorization validation input bindings empty")
    if contract.get("r6_opening_authorization_validated") is not True:
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_PREVIOUS_VALIDATION_MISSING", "authorization validation not true")
    if contract.get("r6_opening_execution_packet_authored") is not False:
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_PREVIOUS_VALIDATION_MISSING", "execution packet already authored")
    for role in auth_validation.PREP_ONLY_OUTPUT_ROLES:
        payload = payloads.get(role)
        if not payload or payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_PREP_ONLY_DRIFT", f"{role} is not prep-only")
    for role, payload in payloads.items():
        _ensure_authority_closed(payload, label=role)
        _ensure_claim_boundary(payload, label=role)
    for role, text in texts.items():
        _ensure_text_authority_closed(text, label=role)


def _input_bindings(root: Path, *, current_main_head: str) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted({**VALIDATION_JSON_INPUTS, **VALIDATION_TEXT_INPUTS}.items()):
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(root / raw),
                "binding_kind": "file_sha256_at_r6_opening_execution_packet_authoring",
            }
        )
    for role, raw in sorted(SHARED_CANONICAL_INPUTS.items()):
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": _git_blob_sha256(root, current_main_head, raw),
                "binding_kind": "git_object_before_overwrite",
                "git_commit": current_main_head,
                "mutable_canonical_path_overwritten_by_this_lane": True,
            }
        )
    return sorted(rows, key=lambda row: str(row["role"]))


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    input_bindings: list[Dict[str, Any]],
) -> Dict[str, Any]:
    binding_hashes = {f"{row['role']}_hash": row["sha256"] for row in input_bindings}
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
        "binding_hashes": binding_hashes,
        "runtime_cutover_executed": True,
        "post_cutover_evidence_review_validated": True,
        "r6_opening_review_validated": True,
        "r6_opening_authorization_packet_authored": True,
        "r6_opening_authorization_validated": True,
        "r6_opening_execution_packet_authored": True,
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


def _control(base: Dict[str, Any], role: str, **extra: Any) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.r6_opening_execution_packet.{role}.v1",
        artifact_id=f"B04_R6_R6_OPENING_EXECUTION_{role.upper()}",
        control_status="DEFINED_FOR_VALIDATION",
        requires_future_validation=NEXT_LAWFUL_MOVE,
        does_not_execute_r6_opening=True,
        does_not_open_r6=True,
        safety_control_reason_codes={
            "static_fallback_required": "RC_B04R6_R6_OPENING_EXEC_PACKET_STATIC_FALLBACK_REQUIRED",
            "operator_override_required": "RC_B04R6_R6_OPENING_EXEC_PACKET_OPERATOR_OVERRIDE_REQUIRED",
            "kill_switch_required": "RC_B04R6_R6_OPENING_EXEC_PACKET_KILL_SWITCH_REQUIRED",
            "rollback_required": "RC_B04R6_R6_OPENING_EXEC_PACKET_ROLLBACK_REQUIRED",
        },
        **extra,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.r6_opening_execution_packet.{role}.prep_only.v1",
        artifact_id=f"B04_R6_R6_OPENING_EXECUTION_{role.upper()}",
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
        cannot_authorize_global_runtime_surface=True,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    validation_targets = list(CONTROL_CONTRACT_ROLES)
    payloads: Dict[str, Dict[str, Any]] = {
        "packet_contract": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_execution_packet.contract.v1",
            artifact_id="B04_R6_R6_OPENING_EXECUTION_PACKET_CONTRACT",
            packet_scope="AUTHOR_R6_OPENING_EXECUTION_PACKET_ONLY",
            does_not_execute_r6_opening=True,
            does_not_open_r6=True,
        ),
        "packet_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_execution_packet.receipt.v1",
            artifact_id="B04_R6_R6_OPENING_EXECUTION_PACKET_RECEIPT",
            verdict="BOUND_FOR_R6_OPENING_EXECUTION_VALIDATION_ONLY",
        ),
        "mode_contract": _control(base, "mode_contract", execution_mode="BOUNDED_R6_OPENING_EXECUTION"),
        "scope_manifest": _control(
            base,
            "scope_manifest",
            scope_status="LIMITED_SCOPE_DEFINED",
            allowed_scope=["B04_R6_BOUNDED_RUNTIME_SURFACE"],
            global_runtime_surface=False,
            r6_opening_execution_authorized=False,
        ),
        "allowed_surface_contract": _control(
            base,
            "allowed_surface_contract",
            allowed_surfaces=["B04_R6_BOUNDED_RUNTIME_SURFACE", "STATIC_FALLBACK_PROTECTED_SURFACE"],
        ),
        "excluded_surface_contract": _control(
            base,
            "excluded_surface_contract",
            excluded_surfaces=[
                "GLOBAL_RUNTIME_SURFACE",
                "PACKAGE_PROMOTION_SURFACE",
                "COMMERCIAL_ACTIVATION_SURFACE",
                "LOBE_ESCALATION_SURFACE",
            ],
        ),
        "opening_preconditions_contract": _control(
            base,
            "opening_preconditions_contract",
            required_preconditions=[
                "r6_opening_authorization_validation",
                "r6_opening_execution_packet_authoring",
                "r6_opening_execution_packet_validation",
            ],
            r6_opening_executed=False,
        ),
        "static_fallback_contract": _control(base, "static_fallback_contract", static_fallback_required=True),
        "operator_override_contract": _control(base, "operator_override_contract", operator_override_required=True),
        "kill_switch_contract": _control(base, "kill_switch_contract", kill_switch_required=True),
        "rollback_contract": _control(base, "rollback_contract", rollback_required=True),
        "monitoring_window_contract": _control(base, "monitoring_window_contract", monitoring_window_required=True),
        "route_distribution_thresholds": _control(base, "route_distribution_thresholds", thresholds_defined=True),
        "drift_thresholds": _control(base, "drift_thresholds", thresholds_defined=True),
        "incident_freeze_contract": _control(base, "incident_freeze_contract", incident_freeze_required=True),
        "runtime_receipt_schema": _control(base, "runtime_receipt_schema", receipt_schema_required=True),
        "replay_manifest": _control(base, "replay_manifest", replay_manifest_required=True),
        "expected_artifact_manifest": _control(
            base,
            "expected_artifact_manifest",
            expected_artifacts=[
                "b04_r6_r6_opening_execution_contract.json",
                "b04_r6_r6_opening_execution_receipt.json",
                "b04_r6_r6_opening_result.json",
                "b04_r6_r6_opening_report.md",
            ],
        ),
        "external_verifier_requirements": _control(
            base, "external_verifier_requirements", external_verifier_required=True
        ),
        "result_interpretation_contract": _control(
            base,
            "result_interpretation_contract",
            allowed_run_outcomes=[
                "B04_R6_R6_OPENING_PASSED__R6_OPENING_EVIDENCE_REVIEW_PACKET_NEXT",
                "B04_R6_R6_OPENING_FAILED__ROLLBACK_OR_REPAIR_NEXT",
                "B04_R6_R6_OPENING_INVALIDATED__FORENSIC_R6_OPENING_REVIEW_NEXT",
                "B04_R6_R6_OPENING_DEFERRED__NAMED_RUNTIME_DEFECT_REMAINS",
            ],
            opening_result_does_not_promote_package=True,
        ),
        "commercial_claim_boundary": _control(
            base,
            "commercial_claim_boundary",
            allowed_claims=["R6 opening execution packet is authored for validation."],
            forbidden_claims=["R6 is open.", "R6 opening executed.", "Commercial activation authorized."],
        ),
        "package_promotion_prohibition_receipt": _control(
            base,
            "package_promotion_prohibition_receipt",
            package_promotion_prohibited=True,
            package_promotion_authorized=False,
        ),
        "validation_plan": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_execution_packet.validation_plan.v1",
            artifact_id="B04_R6_R6_OPENING_EXECUTION_VALIDATION_PLAN",
            validation_targets=validation_targets,
            validation_success_outcome=VALIDATION_SUCCESS_OUTCOME,
        ),
        "validation_reason_codes": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_execution_packet.reason_codes.v1",
            artifact_id="B04_R6_R6_OPENING_EXECUTION_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
        ),
        "no_authorization_drift_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_execution_packet.no_authorization_drift.receipt.v1",
            artifact_id="B04_R6_R6_OPENING_EXECUTION_NO_AUTHORIZATION_DRIFT_RECEIPT",
            validation_status="PASS",
            drift_detected=False,
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.r6_opening_execution_packet.next_lawful_move.receipt.v1",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
        ),
        "pipeline_board": _artifact(
            base,
            schema_id="kt.b04_r6.pipeline_board.v1",
            artifact_id="B04_R6_PIPELINE_BOARD",
            lanes=[
                {"lane": "VALIDATE_B04_R6_R6_OPENING_AUTHORIZATION_PACKET", "status": "VALIDATED"},
                {"lane": AUTHORITATIVE_LANE, "status": "CURRENT_BOUND"},
                {"lane": NEXT_LAWFUL_MOVE, "status": "NEXT"},
                {"lane": "RUN_B04_R6_R6_OPENING", "status": "BLOCKED_PENDING_EXECUTION_PACKET_VALIDATION"},
            ],
        ),
        "future_blocker_register": _artifact(
            base,
            schema_id="kt.future_blocker_register.v1",
            artifact_id="KT_FUTURE_BLOCKER_REGISTER",
            blockers=[
                {
                    "category": "r6_opening_execution",
                    "status": "BLOCKED_PENDING_EXECUTION_PACKET_VALIDATION",
                    "blocks": ["RUN_B04_R6_R6_OPENING"],
                },
                {"category": "package_promotion", "status": "BLOCKED", "blocks": ["PACKAGE_PROMOTION_AUTHORIZED"]},
                {"category": "commercial_claims", "status": "BLOCKED", "blocks": ["COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED"]},
            ],
        ),
    }
    prep_purposes = {
        "r6_opening_run_result_schema_prep_only": "Prepare future R6 opening run result schema.",
        "post_opening_evidence_review_packet_prep_only_draft": "Prepare future post-opening evidence review packet.",
        "r6_opening_failure_closeout_prep_only_draft": "Prepare failure closeout if opening fails.",
        "forensic_r6_opening_review_prep_only_draft": "Prepare forensic review if opening invalidates.",
        "package_promotion_review_packet_prep_only_draft": "Prepare package promotion review blockers only.",
        "external_audit_delta_manifest_prep_only": "Prepare external audit delta manifest.",
        "public_verifier_delta_requirements_prep_only": "Prepare public verifier delta requirements.",
        "commercial_claim_boundary_update_prep_only": "Prepare commercial claim boundary update.",
    }
    for role, purpose in prep_purposes.items():
        payloads[role] = _prep_only(base, role=role, purpose=purpose)
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 R6 Opening Execution Packet",
            "",
            f"Outcome: `{contract['selected_outcome']}`",
            f"Next lawful move: `{contract['next_lawful_move']}`",
            "",
            "This authors the R6 opening execution packet for validation only.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 R6 opening execution packet authoring")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    packet_head = current_main_head if branch != "main" else head
    payloads, texts = _payloads_from_inputs(root)
    _validate_previous(payloads, texts)
    trust = validate_trust_zones(root=root)
    if trust.get("status") != "PASS":
        _fail("RC_B04R6_R6_OPENING_EXEC_PACKET_TRUST_ZONE_FAILED", str(trust.get("failures", [])))
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=packet_head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root, current_main_head=current_main_head),
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
    parser = argparse.ArgumentParser(description=AUTHORITATIVE_LANE)
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
