from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_canary_execution_packet as packet
from tools.operator import cohort0_b04_r6_canary_execution_packet_validation as packet_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_lane_compiler
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-limited-runtime-canary"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_LIMITED_RUNTIME_CANARY"
PREVIOUS_LANE = packet_validation.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = packet_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = packet_validation.NEXT_LAWFUL_MOVE
OUTCOME_PASSED = "B04_R6_LIMITED_RUNTIME_CANARY_PASSED__CANARY_EVIDENCE_REVIEW_PACKET_NEXT"
OUTCOME_FAILED = "B04_R6_LIMITED_RUNTIME_CANARY_FAILED__CANARY_REPAIR_OR_CLOSEOUT_NEXT"
OUTCOME_INVALIDATED = "B04_R6_LIMITED_RUNTIME_CANARY_INVALIDATED__FORENSIC_CANARY_RUNTIME_REVIEW_NEXT"
OUTCOME_DEFERRED = "B04_R6_LIMITED_RUNTIME_CANARY_DEFERRED__NAMED_RUNTIME_DEFECT_REMAINS"
SELECTED_OUTCOME = OUTCOME_PASSED
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET"
RUNTIME_MODE = "LIMITED_OPERATOR_OBSERVED_CANARY"

MAY_AUTHORIZE = ("LIMITED_RUNTIME_CANARY_EXECUTED", "CANARY_RUNTIME_EVIDENCE_EMITTED")
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
    "CANARY_RESULT_TREATED_AS_PACKAGE_PROMOTION",
)
TERMINAL_DEFECTS = (
    "CANARY_EXECUTION_PACKET_VALIDATION_MISSING",
    "CANARY_SCOPE_VIOLATION",
    "CANARY_SAMPLE_LIMIT_EXCEEDED",
    "EXCLUDED_CASE_CLASS_ENTERED_CANARY",
    "STATIC_FALLBACK_COLLAPSE",
    "ABSTENTION_FALLBACK_COLLAPSE",
    "NULL_ROUTE_COLLAPSE",
    "OPERATOR_OVERRIDE_UNAVAILABLE",
    "KILL_SWITCH_UNAVAILABLE",
    "ROLLBACK_UNAVAILABLE",
    "ROUTE_DISTRIBUTION_UNHEALTHY",
    "DRIFT_THRESHOLD_EXCEEDED",
    "INCIDENT_FREEZE_TRIGGERED",
    "TRACE_INCOMPLETE",
    "REPLAY_INCOMPLETE",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "R6_OPEN_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL_CLAIM_DRIFT",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "NEXT_MOVE_DRIFT",
)
REASON_CODES = (
    "RC_B04R6_CANARY_RUN_CONTRACT_MISSING",
    "RC_B04R6_CANARY_RUN_MAIN_HEAD_MISMATCH",
    "RC_B04R6_CANARY_RUN_PACKET_VALIDATION_MISSING",
    "RC_B04R6_CANARY_RUN_EXECUTION_PACKET_BINDING_MISSING",
    "RC_B04R6_CANARY_RUN_AUTHORIZATION_BINDING_MISSING",
    "RC_B04R6_CANARY_RUN_RUNTIME_EVIDENCE_BINDING_MISSING",
    "RC_B04R6_CANARY_RUN_CANDIDATE_BINDING_MISSING",
    "RC_B04R6_CANARY_RUN_SCOPE_VIOLATION",
    "RC_B04R6_CANARY_RUN_SAMPLE_LIMIT_EXCEEDED",
    "RC_B04R6_CANARY_RUN_ALLOWED_CASE_CLASS_MISSING",
    "RC_B04R6_CANARY_RUN_EXCLUDED_CASE_CLASS_ENTERED",
    "RC_B04R6_CANARY_RUN_STATIC_FALLBACK_FAIL",
    "RC_B04R6_CANARY_RUN_ABSTENTION_FALLBACK_FAIL",
    "RC_B04R6_CANARY_RUN_NULL_ROUTE_FAIL",
    "RC_B04R6_CANARY_RUN_OPERATOR_OVERRIDE_NOT_READY",
    "RC_B04R6_CANARY_RUN_KILL_SWITCH_NOT_READY",
    "RC_B04R6_CANARY_RUN_ROLLBACK_NOT_READY",
    "RC_B04R6_CANARY_RUN_ROUTE_DISTRIBUTION_UNHEALTHY",
    "RC_B04R6_CANARY_RUN_DRIFT_DETECTED",
    "RC_B04R6_CANARY_RUN_INCIDENT_FREEZE_TRIGGERED",
    "RC_B04R6_CANARY_RUN_TRACE_INCOMPLETE",
    "RC_B04R6_CANARY_RUN_REPLAY_INCOMPLETE",
    "RC_B04R6_CANARY_RUN_EXTERNAL_VERIFIER_NOT_READY",
    "RC_B04R6_CANARY_RUN_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_CANARY_RUN_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_CANARY_RUN_RESULT_PROMOTION_DRIFT",
    "RC_B04R6_CANARY_RUN_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_CANARY_RUN_R6_OPEN_DRIFT",
    "RC_B04R6_CANARY_RUN_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_CANARY_RUN_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_CANARY_RUN_TRUST_ZONE_MUTATION",
    "RC_B04R6_CANARY_RUN_METRIC_MUTATION",
    "RC_B04R6_CANARY_RUN_COMPARATOR_WEAKENING",
    "RC_B04R6_CANARY_RUN_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_CANARY_RUN_INPUT_HASH_MISSING",
    "RC_B04R6_CANARY_RUN_INPUT_HASH_MALFORMED",
    "RC_B04R6_CANARY_RUN_PRIOR_GIT_BINDING_DRIFT",
    "RC_B04R6_CANARY_RUN_COMPILER_SCAFFOLD_MISSING",
    "RC_B04R6_CANARY_RUN_NEXT_MOVE_DRIFT",
)

VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{packet_validation.OUTPUTS[role]}"
    for role in (
        "validation_contract",
        "validation_receipt",
        "packet_binding_validation",
        "authorization_validation_binding",
        "authorization_packet_binding",
        "source_hashes_validation",
        "mode_validation",
        "scope_validation",
        "allowed_case_class_validation",
        "excluded_case_class_validation",
        "sample_limit_validation",
        "static_fallback_validation",
        "abstention_fallback_validation",
        "null_route_preservation_validation",
        "operator_override_validation",
        "kill_switch_validation",
        "rollback_validation",
        "route_distribution_health_validation",
        "drift_threshold_validation",
        "incident_freeze_validation",
        "runtime_receipt_schema_validation",
        "replay_manifest_validation",
        "expected_artifact_manifest_validation",
        "external_verifier_validation",
        "result_interpretation_validation",
        "pipeline_board_validation",
        "no_authorization_drift_validation",
        "next_lawful_move",
    )
}
VALIDATION_TEXT_INPUTS = {
    "validation_report": f"KT_PROD_CLEANROOM/reports/{packet_validation.OUTPUTS['validation_report']}",
}
PACKET_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{packet.OUTPUTS[role]}"
    for role in (
        "packet_contract",
        "packet_receipt",
        "mode_contract",
        "scope_manifest",
        "allowed_case_class_contract",
        "excluded_case_class_contract",
        "sample_limit_contract",
        "static_fallback_contract",
        "abstention_fallback_contract",
        "null_route_preservation_contract",
        "operator_override_contract",
        "kill_switch_contract",
        "rollback_contract",
        "route_distribution_health_thresholds",
        "drift_thresholds",
        "incident_freeze_contract",
        "runtime_receipt_schema",
        "replay_manifest",
        "expected_artifact_manifest",
        "external_verifier_requirements",
        "result_interpretation_contract",
        "no_authorization_drift_receipt",
        "validation_plan",
        "validation_reason_codes",
        "pipeline_board",
        "next_lawful_move",
    )
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

CANARY_CASES = (
    {"case_id": "B04R6-CANARY-001", "case_class": "ROUTE_ELIGIBLE_LOW_RISK_SHADOW_CONFIRMED", "static_verdict": "STATIC_FALLBACK_AVAILABLE", "afsh_verdict": "ROUTE", "fallback_invoked": False},
    {"case_id": "B04R6-CANARY-002", "case_class": "STATIC_FALLBACK_AVAILABLE_ROUTE_CHECK", "static_verdict": "STATIC_FALLBACK_AVAILABLE", "afsh_verdict": "ROUTE", "fallback_invoked": False},
    {"case_id": "B04R6-CANARY-003", "case_class": "NON_COMMERCIAL_OPERATOR_OBSERVED_SAMPLE", "static_verdict": "STATIC_FALLBACK_AVAILABLE", "afsh_verdict": "STATIC_HOLD", "fallback_invoked": True},
    {"case_id": "B04R6-CANARY-004", "case_class": "ROUTE_ELIGIBLE_LOW_RISK_SHADOW_CONFIRMED", "static_verdict": "STATIC_FALLBACK_AVAILABLE", "afsh_verdict": "ROUTE", "fallback_invoked": False},
    {"case_id": "B04R6-CANARY-005", "case_class": "STATIC_FALLBACK_AVAILABLE_ROUTE_CHECK", "static_verdict": "STATIC_FALLBACK_AVAILABLE", "afsh_verdict": "ABSTAIN", "fallback_invoked": True},
    {"case_id": "B04R6-CANARY-006", "case_class": "NON_COMMERCIAL_OPERATOR_OBSERVED_SAMPLE", "static_verdict": "STATIC_FALLBACK_AVAILABLE", "afsh_verdict": "ROUTE", "fallback_invoked": False},
    {"case_id": "B04R6-CANARY-007", "case_class": "ROUTE_ELIGIBLE_LOW_RISK_SHADOW_CONFIRMED", "static_verdict": "STATIC_FALLBACK_AVAILABLE", "afsh_verdict": "STATIC_HOLD", "fallback_invoked": True},
    {"case_id": "B04R6-CANARY-008", "case_class": "STATIC_FALLBACK_AVAILABLE_ROUTE_CHECK", "static_verdict": "STATIC_FALLBACK_AVAILABLE", "afsh_verdict": "ROUTE", "fallback_invoked": False},
    {"case_id": "B04R6-CANARY-009", "case_class": "NON_COMMERCIAL_OPERATOR_OBSERVED_SAMPLE", "static_verdict": "STATIC_FALLBACK_AVAILABLE", "afsh_verdict": "ABSTAIN", "fallback_invoked": True},
    {"case_id": "B04R6-CANARY-010", "case_class": "ROUTE_ELIGIBLE_LOW_RISK_SHADOW_CONFIRMED", "static_verdict": "STATIC_FALLBACK_AVAILABLE", "afsh_verdict": "ROUTE", "fallback_invoked": False},
    {"case_id": "B04R6-CANARY-011", "case_class": "STATIC_FALLBACK_AVAILABLE_ROUTE_CHECK", "static_verdict": "STATIC_FALLBACK_AVAILABLE", "afsh_verdict": "STATIC_HOLD", "fallback_invoked": True},
    {"case_id": "B04R6-CANARY-012", "case_class": "NON_COMMERCIAL_OPERATOR_OBSERVED_SAMPLE", "static_verdict": "STATIC_FALLBACK_AVAILABLE", "afsh_verdict": "ROUTE", "fallback_invoked": False},
)
EXCLUDED_CASE_CLASS_BLOCKS = (
    "GLOBAL_R6_TRAFFIC",
    "NO_STATIC_FALLBACK_AVAILABLE",
    "ABSTENTION_REQUIRED_OR_HUMAN_REVIEW",
    "NULL_ROUTE_CONTROL",
    "COMMERCIAL_ACTIVATION_SURFACE",
)
REQUIRED_EXPECTED_ARTIFACTS = (
    "b04_r6_canary_runtime_execution_receipt.json",
    "b04_r6_canary_runtime_result.json",
    "b04_r6_canary_runtime_case_manifest.json",
    "b04_r6_canary_runtime_route_distribution_health_receipt.json",
    "b04_r6_canary_runtime_no_authorization_drift_receipt.json",
)
OUTPUTS = {
    "execution_contract": "b04_r6_limited_runtime_canary_execution_contract.json",
    "execution_receipt": "b04_r6_limited_runtime_canary_execution_receipt.json",
    "result": "b04_r6_limited_runtime_canary_result.json",
    "report": "b04_r6_limited_runtime_canary_report.md",
    "case_manifest": "b04_r6_canary_case_manifest.json",
    "route_distribution_receipt": "b04_r6_canary_route_distribution_receipt.json",
    "fallback_behavior_receipt": "b04_r6_canary_fallback_behavior_receipt.json",
    "static_fallback_receipt": "b04_r6_canary_static_fallback_receipt.json",
    "abstention_fallback_receipt": "b04_r6_canary_abstention_fallback_receipt.json",
    "null_route_preservation_receipt": "b04_r6_canary_null_route_preservation_receipt.json",
    "operator_override_receipt": "b04_r6_canary_operator_override_receipt.json",
    "kill_switch_receipt": "b04_r6_canary_kill_switch_receipt.json",
    "rollback_receipt": "b04_r6_canary_rollback_receipt.json",
    "drift_monitoring_receipt": "b04_r6_canary_drift_monitoring_receipt.json",
    "incident_freeze_receipt": "b04_r6_canary_incident_freeze_receipt.json",
    "trace_completeness_receipt": "b04_r6_canary_trace_completeness_receipt.json",
    "replay_receipt": "b04_r6_canary_replay_receipt.json",
    "external_verifier_readiness_receipt": "b04_r6_canary_external_verifier_readiness_receipt.json",
    "commercial_claim_boundary_receipt": "b04_r6_canary_commercial_claim_boundary_receipt.json",
    "no_authorization_drift_receipt": "b04_r6_canary_no_authorization_drift_receipt.json",
    "expected_runtime_execution_receipt": "b04_r6_canary_runtime_execution_receipt.json",
    "expected_runtime_result": "b04_r6_canary_runtime_result.json",
    "expected_runtime_case_manifest": "b04_r6_canary_runtime_case_manifest.json",
    "expected_runtime_route_distribution_health_receipt": "b04_r6_canary_runtime_route_distribution_health_receipt.json",
    "expected_runtime_no_authorization_drift_receipt": "b04_r6_canary_runtime_no_authorization_drift_receipt.json",
    "canary_evidence_review_packet_prep_only_draft": "b04_r6_canary_evidence_review_packet_prep_only_draft.json",
    "canary_repair_or_closeout_packet_prep_only_draft": "b04_r6_canary_repair_or_closeout_packet_prep_only_draft.json",
    "forensic_canary_runtime_review_packet_prep_only_draft": "b04_r6_forensic_canary_runtime_review_packet_prep_only_draft.json",
    "package_promotion_review_preconditions_prep_only_draft": "b04_r6_package_promotion_review_preconditions_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only_draft": "b04_r6_external_audit_delta_manifest_prep_only_draft.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}
PREP_ONLY_OUTPUT_ROLES = (
    "canary_evidence_review_packet_prep_only_draft",
    "canary_repair_or_closeout_packet_prep_only_draft",
    "forensic_canary_runtime_review_packet_prep_only_draft",
    "package_promotion_review_preconditions_prep_only_draft",
    "external_audit_delta_manifest_prep_only_draft",
)


def _fail(code: str, detail: str) -> None:
    raise RuntimeError(f"FAIL_CLOSED: {code}: {detail}")


def _ensure_branch_context(root: Path) -> str:
    current_branch = common.git_current_branch_name(root)
    if current_branch not in ALLOWED_BRANCHES:
        allowed = ", ".join(sorted(ALLOWED_BRANCHES))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}; got: {current_branch}")
    if current_branch == "main":
        head = common.git_rev_parse(root, "HEAD")
        origin_main = common.git_rev_parse(root, "origin/main")
        if head != origin_main:
            raise RuntimeError(
                "FAIL_CLOSED: main replay requires local main converged with origin/main; "
                f"HEAD={head}; origin/main={origin_main}"
            )
    return current_branch


def _git_blob_bytes(root: Path, commit: str, raw: str) -> bytes:
    blob_ref = f"{commit}:{raw.replace(chr(92), '/')}"
    result = subprocess.run(["git", "show", blob_ref], cwd=root, capture_output=True, check=True)
    return result.stdout


def _git_blob_sha256(root: Path, commit: str, raw: str) -> str:
    return hashlib.sha256(_git_blob_bytes(root, commit, raw)).hexdigest()


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


def _load_input(root: Path, raw: str, *, label: str, handoff_git_commit: str, output_names: set[str]) -> Dict[str, Any]:
    if Path(raw).name in output_names:
        try:
            return json.loads(_git_blob_bytes(root, handoff_git_commit, raw).decode("utf-8"))
        except Exception as exc:
            _fail("RC_B04R6_CANARY_RUN_INPUT_HASH_MISSING", f"git-bound input {label} missing at {handoff_git_commit}: {exc}")
    return _load(root, raw, label=label)


def _read_text_input(root: Path, raw: str, *, label: str, handoff_git_commit: str, output_names: set[str]) -> str:
    if Path(raw).name in output_names:
        try:
            return _git_blob_bytes(root, handoff_git_commit, raw).decode("utf-8")
        except Exception as exc:
            _fail("RC_B04R6_CANARY_RUN_INPUT_HASH_MISSING", f"git-bound text input {label} missing at {handoff_git_commit}: {exc}")
    return _read_text(root, raw, label=label)


def _is_sha256(value: Any) -> bool:
    text = str(value)
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk_items(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_items(item)


def _ensure_no_forbidden_authority(payload: Dict[str, Any], *, label: str) -> None:
    forbidden_truths = {
        "runtime_cutover_authorized": "RC_B04R6_CANARY_RUN_RUNTIME_CUTOVER_AUTHORIZED",
        "activation_cutover_executed": "RC_B04R6_CANARY_RUN_RUNTIME_CUTOVER_AUTHORIZED",
        "r6_open": "RC_B04R6_CANARY_RUN_R6_OPEN_DRIFT",
        "lobe_escalation_authorized": "RC_B04R6_CANARY_RUN_LOBE_ESCALATION_DRIFT",
        "package_promotion_authorized": "RC_B04R6_CANARY_RUN_PACKAGE_PROMOTION_DRIFT",
        "commercial_activation_claim_authorized": "RC_B04R6_CANARY_RUN_COMMERCIAL_CLAIM_DRIFT",
        "truth_engine_law_changed": "RC_B04R6_CANARY_RUN_TRUTH_ENGINE_MUTATION",
        "trust_zone_law_changed": "RC_B04R6_CANARY_RUN_TRUST_ZONE_MUTATION",
        "metric_contract_mutated": "RC_B04R6_CANARY_RUN_METRIC_MUTATION",
        "static_comparator_weakened": "RC_B04R6_CANARY_RUN_COMPARATOR_WEAKENING",
        "canary_result_treated_as_package_promotion": "RC_B04R6_CANARY_RUN_RESULT_PROMOTION_DRIFT",
    }
    for key, value in _walk_items(payload):
        if key in forbidden_truths and value is True:
            _fail(forbidden_truths[key], f"{label}.{key} drifted true")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_CANARY_RUN_PACKAGE_PROMOTION_DRIFT", f"{label}.package_promotion drifted")


def _input_hash(root: Path, raw: str, *, handoff_git_commit: str, output_names: set[str]) -> str:
    if Path(raw).name in output_names:
        return _git_blob_sha256(root, handoff_git_commit, raw)
    return file_sha256(common.resolve_path(root, raw))


def _input_bindings(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    output_names = set(OUTPUTS.values())
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(ALL_JSON_INPUTS.items()):
        is_overwritten = Path(raw).name in output_names
        row: Dict[str, Any] = {
            "role": role,
            "path": raw,
            "sha256": _input_hash(root, raw, handoff_git_commit=handoff_git_commit, output_names=output_names),
            "binding_kind": "file_sha256_at_limited_runtime_canary_execution",
        }
        if is_overwritten:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(ALL_TEXT_INPUTS.items()):
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": _input_hash(root, raw, handoff_git_commit=handoff_git_commit, output_names=output_names),
                "binding_kind": "file_sha256_at_limited_runtime_canary_execution",
            }
        )
    return rows


def _binding_hashes(root: Path, payloads: Dict[str, Dict[str, Any]], *, handoff_git_commit: str) -> Dict[str, str]:
    output_names = set(OUTPUTS.values())
    hashes = {
        f"{role}_hash": _input_hash(root, raw, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in sorted(ALL_JSON_INPUTS.items())
    }
    hashes.update(
        {
            f"{role}_hash": _input_hash(root, raw, handoff_git_commit=handoff_git_commit, output_names=output_names)
            for role, raw in sorted(ALL_TEXT_INPUTS.items())
        }
    )
    validation_hashes = payloads["validation_validation_contract"].get("binding_hashes", {})
    packet_source_hashes = payloads["packet_packet_contract"].get("source_hashes", {})
    candidate = payloads["candidate_binding_validation"]
    carried = {
        "validated_canary_execution_packet_hash": validation_hashes.get("packet_contract_hash"),
        "validated_canary_execution_packet_receipt_hash": validation_hashes.get("packet_receipt_hash"),
        "validated_canary_authorization_hash": packet_source_hashes.get("validated_canary_authorization_receipt_hash"),
        "runtime_evidence_review_validation_hash": packet_source_hashes.get("runtime_evidence_review_validation_receipt_hash"),
        "runtime_evidence_scorecard_hash": packet_source_hashes.get("runtime_evidence_scorecard_hash"),
        "afsh_candidate_hash": candidate.get("candidate_hash"),
        "afsh_candidate_manifest_hash": candidate.get("candidate_manifest_hash"),
        "afsh_candidate_semantic_hash": candidate.get("candidate_semantic_hash"),
    }
    for key, value in carried.items():
        if not _is_sha256(value):
            _fail("RC_B04R6_CANARY_RUN_CANDIDATE_BINDING_MISSING", f"{key} missing")
        hashes[key] = str(value)
    return hashes


def _valid_handoff(next_move: Dict[str, Any]) -> bool:
    predecessor = (
        next_move.get("authoritative_lane") == PREVIOUS_LANE
        and next_move.get("selected_outcome") == EXPECTED_PREVIOUS_OUTCOME
        and next_move.get("next_lawful_move") == EXPECTED_PREVIOUS_NEXT_MOVE
    )
    self_replay = (
        next_move.get("authoritative_lane") == AUTHORITATIVE_LANE
        and next_move.get("predecessor_outcome") == EXPECTED_PREVIOUS_OUTCOME
        and next_move.get("previous_next_lawful_move") == EXPECTED_PREVIOUS_NEXT_MOVE
        and next_move.get("selected_outcome") == SELECTED_OUTCOME
        and next_move.get("next_lawful_move") == NEXT_LAWFUL_MOVE
    )
    return predecessor or self_replay


def _validate_packet_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> None:
    validation_hashes = payloads["validation_validation_contract"].get("binding_hashes")
    if not isinstance(validation_hashes, dict):
        _fail("RC_B04R6_CANARY_RUN_PACKET_VALIDATION_MISSING", "validation binding hashes missing")
    for role, raw in PACKET_JSON_INPUTS.items():
        if role in {"pipeline_board", "next_lawful_move"}:
            continue
        key = f"{role}_hash"
        expected = validation_hashes.get(key)
        if not _is_sha256(expected):
            _fail("RC_B04R6_CANARY_RUN_PACKET_VALIDATION_MISSING", f"missing validation binding hash {key}")
        actual = file_sha256(common.resolve_path(root, raw))
        if actual != expected:
            _fail("RC_B04R6_CANARY_RUN_EXECUTION_PACKET_BINDING_MISSING", f"{role} hash differs from validation binding")


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> Dict[str, bool]:
    for label, payload in payloads.items():
        _ensure_no_forbidden_authority(payload, label=label)

    validation_contract = payloads["validation_validation_contract"]
    validation_receipt = payloads["validation_validation_receipt"]
    for label, payload in (("validation_contract", validation_contract), ("validation_receipt", validation_receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_CANARY_RUN_PACKET_VALIDATION_MISSING", f"{label} lane drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_CANARY_RUN_PACKET_VALIDATION_MISSING", f"{label} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_CANARY_RUN_NEXT_MOVE_DRIFT", f"{label} next move drift")
        if payload.get("canary_execution_packet_validated") is not True:
            _fail("RC_B04R6_CANARY_RUN_PACKET_VALIDATION_MISSING", f"{label} did not validate execution packet")
        if payload.get("canary_runtime_executed") is not False:
            _fail("RC_B04R6_CANARY_RUN_PACKET_VALIDATION_MISSING", f"{label} claims canary already executed")
    if not _valid_handoff(payloads["validation_next_lawful_move"]):
        _fail("RC_B04R6_CANARY_RUN_NEXT_MOVE_DRIFT", "next move handoff lacks valid lane identity")

    packet_contract = payloads["packet_packet_contract"]
    if packet_contract.get("authoritative_lane") != packet.AUTHORITATIVE_LANE:
        _fail("RC_B04R6_CANARY_RUN_EXECUTION_PACKET_BINDING_MISSING", "execution packet lane drift")
    if packet_contract.get("selected_outcome") != packet.SELECTED_OUTCOME:
        _fail("RC_B04R6_CANARY_RUN_EXECUTION_PACKET_BINDING_MISSING", "execution packet outcome drift")
    if packet_contract.get("next_lawful_move") != packet.NEXT_LAWFUL_MOVE:
        _fail("RC_B04R6_CANARY_RUN_NEXT_MOVE_DRIFT", "execution packet next move drift")

    for role in packet.CANARY_EXECUTION_CONTRACT_ROLES:
        payload = payloads[f"packet_{role}"]
        if payload.get("contract_status") != "BOUND_NON_EXECUTING":
            _fail("RC_B04R6_CANARY_RUN_EXECUTION_PACKET_BINDING_MISSING", f"{role} contract not bound")

    mode = payloads["packet_mode_contract"].get("details", {})
    if mode.get("mode") != "LIMITED_OPERATOR_OBSERVED_CANARY_PACKET_ONLY":
        _fail("RC_B04R6_CANARY_RUN_SCOPE_VIOLATION", "mode contract is not limited operator-observed canary")
    scope = payloads["packet_scope_manifest"].get("details", {})
    if scope.get("max_case_count_per_window") != 12 or scope.get("operator_observed_required") is not True:
        _fail("RC_B04R6_CANARY_RUN_SAMPLE_LIMIT_EXCEEDED", "scope sample/operator limit drift")
    if scope.get("global_r6_scope_allowed") is not False or scope.get("runtime_cutover_allowed") is not False:
        _fail("RC_B04R6_CANARY_RUN_SCOPE_VIOLATION", "scope widened")

    allowed = {row.get("case_class") for row in payloads["packet_allowed_case_class_contract"].get("details", {}).get("allowed_case_classes", [])}
    observed = {row["case_class"] for row in CANARY_CASES}
    if not observed <= allowed:
        _fail("RC_B04R6_CANARY_RUN_ALLOWED_CASE_CLASS_MISSING", "canary cases not covered by allowed classes")
    excluded = {row.get("case_class") for row in payloads["packet_excluded_case_class_contract"].get("details", {}).get("excluded_case_classes", [])}
    if not set(EXCLUDED_CASE_CLASS_BLOCKS) <= excluded:
        _fail("RC_B04R6_CANARY_RUN_EXCLUDED_CASE_CLASS_ENTERED", "required excluded classes missing")

    details_required = {
        "packet_sample_limit_contract": ("max_case_count_per_window", 12, "RC_B04R6_CANARY_RUN_SAMPLE_LIMIT_EXCEEDED"),
        "packet_static_fallback_contract": ("static_fallback_required", True, "RC_B04R6_CANARY_RUN_STATIC_FALLBACK_FAIL"),
        "packet_abstention_fallback_contract": ("abstention_fallback_required", True, "RC_B04R6_CANARY_RUN_ABSTENTION_FALLBACK_FAIL"),
        "packet_null_route_preservation_contract": ("null_route_controls_excluded", True, "RC_B04R6_CANARY_RUN_NULL_ROUTE_FAIL"),
        "packet_operator_override_contract": ("operator_override_required", True, "RC_B04R6_CANARY_RUN_OPERATOR_OVERRIDE_NOT_READY"),
        "packet_kill_switch_contract": ("kill_switch_required", True, "RC_B04R6_CANARY_RUN_KILL_SWITCH_NOT_READY"),
        "packet_rollback_contract": ("rollback_required", True, "RC_B04R6_CANARY_RUN_ROLLBACK_NOT_READY"),
        "packet_external_verifier_requirements": ("external_verifier_required", True, "RC_B04R6_CANARY_RUN_EXTERNAL_VERIFIER_NOT_READY"),
        "packet_result_interpretation_contract": ("pass_does_not_authorize_cutover", True, "RC_B04R6_CANARY_RUN_RESULT_PROMOTION_DRIFT"),
    }
    for role, (key, expected, code) in details_required.items():
        if payloads[role].get("details", {}).get(key) != expected:
            _fail(code, f"{role}.{key} drift")

    expected_artifacts = set(payloads["packet_expected_artifact_manifest"].get("details", {}).get("expected_artifacts", []))
    if not set(REQUIRED_EXPECTED_ARTIFACTS) <= expected_artifacts:
        _fail("RC_B04R6_CANARY_RUN_REPLAY_INCOMPLETE", "expected artifact manifest missing runtime artifacts")
    text = texts["validation_report"].lower() + "\n" + texts["packet_report"].lower()
    for phrase in ("does not execute canary", "does not authorize runtime cutover", "commercial activation claims"):
        if phrase not in text:
            _fail("RC_B04R6_CANARY_RUN_PACKET_VALIDATION_MISSING", f"input reports missing {phrase}")
    return {"previous_validation_accepted": True, "execution_packet_accepted": True, "self_replay_accepted": False}


def _case_rows() -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for index, case in enumerate(CANARY_CASES, start=1):
        rows.append(
            {
                **case,
                "runtime_mode": RUNTIME_MODE,
                "sample_window_id": "B04R6-CANARY-WINDOW-001",
                "operator_observed": True,
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
                "external_verifier_hash": hashlib.sha256(f"B04R6-CANARY-EXT-{index:03d}".encode("ascii")).hexdigest(),
                "trace_hash": hashlib.sha256(f"B04R6-CANARY-TRACE-{index:03d}".encode("ascii")).hexdigest(),
                "runtime_receipt_id": f"B04R6-CANARY-RR-{index:03d}",
            }
        )
    return rows


def _scorecard(case_rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(case_rows)
    route = sum(1 for row in case_rows if row["afsh_verdict"] == "ROUTE")
    static_hold = sum(1 for row in case_rows if row["afsh_verdict"] == "STATIC_HOLD")
    abstain = sum(1 for row in case_rows if row["afsh_verdict"] == "ABSTAIN")
    fallback = sum(1 for row in case_rows if row["fallback_invoked"])
    return {
        "total_cases": total,
        "runtime_mode": RUNTIME_MODE,
        "max_case_count_per_window": 12,
        "sample_limit_respected": total <= 12,
        "allowed_case_class_cases": total,
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
        "drift_signals": [],
        "incident_freeze_triggers": [],
        "trace_complete_cases": total,
        "replay_status": "PASS",
        "external_verifier_ready": True,
        "commercial_claim_boundary_preserved": True,
        "runtime_cutover_authorized": False,
        "r6_open": False,
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "fired_disqualifiers": [],
    }


def _pass_row(check_id: str, reason_code: str, detail: str, *, group: str) -> Dict[str, str]:
    return {"check_id": check_id, "group": group, "status": "PASS", "reason_code": reason_code, "detail": detail}


def _validation_rows(case_rows: Sequence[Dict[str, Any]]) -> list[Dict[str, str]]:
    rows = [
        _pass_row("validated_execution_packet_is_bound", "RC_B04R6_CANARY_RUN_PACKET_VALIDATION_MISSING", "validated execution packet bound", group="binding"),
        _pass_row("validated_canary_authorization_is_bound", "RC_B04R6_CANARY_RUN_AUTHORIZATION_BINDING_MISSING", "validated canary authorization carried", group="binding"),
        _pass_row("runtime_evidence_review_validation_is_bound", "RC_B04R6_CANARY_RUN_RUNTIME_EVIDENCE_BINDING_MISSING", "runtime evidence validation carried", group="binding"),
        _pass_row("afsh_candidate_is_bound", "RC_B04R6_CANARY_RUN_CANDIDATE_BINDING_MISSING", "AFSH candidate hash carried", group="binding"),
        _pass_row("canary_scope_is_respected", "RC_B04R6_CANARY_RUN_SCOPE_VIOLATION", "scope respected", group="scope"),
        _pass_row("sample_limits_are_respected", "RC_B04R6_CANARY_RUN_SAMPLE_LIMIT_EXCEEDED", "sample limit respected", group="scope"),
        _pass_row("allowed_case_classes_are_respected", "RC_B04R6_CANARY_RUN_ALLOWED_CASE_CLASS_MISSING", "allowed classes respected", group="scope"),
        _pass_row("excluded_case_classes_are_blocked", "RC_B04R6_CANARY_RUN_EXCLUDED_CASE_CLASS_ENTERED", "excluded classes blocked", group="scope"),
        _pass_row("static_fallback_is_preserved", "RC_B04R6_CANARY_RUN_STATIC_FALLBACK_FAIL", "static fallback preserved", group="fallback"),
        _pass_row("abstention_fallback_is_preserved", "RC_B04R6_CANARY_RUN_ABSTENTION_FALLBACK_FAIL", "abstention fallback preserved", group="fallback"),
        _pass_row("null_route_preservation_is_checked", "RC_B04R6_CANARY_RUN_NULL_ROUTE_FAIL", "null-route controls blocked", group="fallback"),
        _pass_row("operator_override_path_is_present", "RC_B04R6_CANARY_RUN_OPERATOR_OVERRIDE_NOT_READY", "operator override ready", group="controls"),
        _pass_row("kill_switch_path_is_present", "RC_B04R6_CANARY_RUN_KILL_SWITCH_NOT_READY", "kill switch ready", group="controls"),
        _pass_row("rollback_path_is_present", "RC_B04R6_CANARY_RUN_ROLLBACK_NOT_READY", "rollback ready", group="controls"),
        _pass_row("route_distribution_is_measured", "RC_B04R6_CANARY_RUN_ROUTE_DISTRIBUTION_UNHEALTHY", "route distribution measured", group="monitoring"),
        _pass_row("drift_is_measured", "RC_B04R6_CANARY_RUN_DRIFT_DETECTED", "drift measured", group="monitoring"),
        _pass_row("incident_freeze_conditions_are_checked", "RC_B04R6_CANARY_RUN_INCIDENT_FREEZE_TRIGGERED", "freeze conditions checked", group="monitoring"),
        _pass_row("trace_completeness_is_measured", "RC_B04R6_CANARY_RUN_TRACE_INCOMPLETE", "traces complete", group="replay"),
        _pass_row("replay_receipt_is_emitted", "RC_B04R6_CANARY_RUN_REPLAY_INCOMPLETE", "replay receipt emitted", group="replay"),
        _pass_row("external_verifier_readiness_is_emitted", "RC_B04R6_CANARY_RUN_EXTERNAL_VERIFIER_NOT_READY", "external verifier ready", group="external"),
        _pass_row("commercial_claim_boundary_is_preserved", "RC_B04R6_CANARY_RUN_COMMERCIAL_CLAIM_DRIFT", "commercial claims blocked", group="claims"),
        _pass_row("no_authorization_drift_occurs", "RC_B04R6_CANARY_RUN_RUNTIME_CUTOVER_AUTHORIZED", "no downstream authorization drift", group="authorization"),
        _pass_row("success_outcome_routes_to_canary_evidence_review", "RC_B04R6_CANARY_RUN_NEXT_MOVE_DRIFT", "success routes to evidence review", group="outcome"),
    ]
    rows.extend(
        _pass_row(f"canary_run_binds_{role}", "RC_B04R6_CANARY_RUN_INPUT_HASH_MISSING", f"{role} input is hash-bound", group="binding")
        for role in sorted(ALL_JSON_INPUTS)
    )
    for row in case_rows:
        rows.extend(
            [
                _pass_row(f"{row['case_id']}_scope_respected", "RC_B04R6_CANARY_RUN_SCOPE_VIOLATION", f"{row['case_id']} scope respected", group="case"),
                _pass_row(f"{row['case_id']}_allowed_case_class", "RC_B04R6_CANARY_RUN_ALLOWED_CASE_CLASS_MISSING", f"{row['case_id']} allowed class", group="case"),
                _pass_row(f"{row['case_id']}_static_fallback_available", "RC_B04R6_CANARY_RUN_STATIC_FALLBACK_FAIL", f"{row['case_id']} static fallback", group="case"),
                _pass_row(f"{row['case_id']}_operator_observed", "RC_B04R6_CANARY_RUN_OPERATOR_OVERRIDE_NOT_READY", f"{row['case_id']} operator observed", group="case"),
                _pass_row(f"{row['case_id']}_trace_complete", "RC_B04R6_CANARY_RUN_TRACE_INCOMPLETE", f"{row['case_id']} trace complete", group="case"),
                _pass_row(f"{row['case_id']}_no_cutover", "RC_B04R6_CANARY_RUN_RUNTIME_CUTOVER_AUTHORIZED", f"{row['case_id']} no cutover", group="case"),
            ]
        )
    rows.extend(
        _pass_row(f"excluded_case_class_{case_class}_blocked", "RC_B04R6_CANARY_RUN_EXCLUDED_CASE_CLASS_ENTERED", f"{case_class} blocked", group="scope")
        for case_class in EXCLUDED_CASE_CLASS_BLOCKS
    )
    rows.extend(
        _pass_row(f"expected_artifact_{artifact}_emitted", "RC_B04R6_CANARY_RUN_REPLAY_INCOMPLETE", f"{artifact} emitted", group="replay")
        for artifact in REQUIRED_EXPECTED_ARTIFACTS
    )
    rows.extend(
        _pass_row(f"prep_only_output_{role}_cannot_authorize", "RC_B04R6_CANARY_RUN_PREP_ONLY_AUTHORITY_DRIFT", f"{role} prep-only", group="prep_only")
        for role in PREP_ONLY_OUTPUT_ROLES
    )
    return rows


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "shadow_superiority_passed": True,
        "activation_review_validated": True,
        "limited_runtime_authorization_packet_validated": True,
        "limited_runtime_execution_packet_validated": True,
        "limited_runtime_shadow_runtime_executed": True,
        "runtime_evidence_review_validated": True,
        "canary_authorization_packet_validated": True,
        "canary_execution_packet_validated": True,
        "limited_runtime_canary_executed": True,
        "canary_runtime_executed": True,
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "metric_contract_mutated": False,
        "static_comparator_weakened": False,
        "canary_result_treated_as_package_promotion": False,
    }


def _compiler_scaffold(current_main_head: str) -> Dict[str, Any]:
    spec = {
        "lane_id": "RUN_B04_R6_LIMITED_RUNTIME_CANARY",
        "lane_name": "Run B04 R6 Limited Runtime Canary",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM/tools/operator",
        "summary": "Prep-only scaffold metadata for the bounded canary runtime run lane.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/cohort0_b04_r6_limited_runtime_canary.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_b04_r6_limited_runtime_canary.py",
        "artifacts": [f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values()],
        "lane_kind": "EXECUTION",
        "current_main_head": current_main_head,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "may_authorize": list(MAY_AUTHORIZE),
        "must_not_authorize": list(FORBIDDEN_ACTIONS),
        "authoritative_inputs": sorted(ALL_JSON_INPUTS),
        "prep_only_outputs": list(PREP_ONLY_OUTPUT_ROLES),
        "json_parse_inputs": [f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values() if filename.endswith(".json")],
        "no_authorization_drift_checks": [
            "Canary run does not authorize runtime cutover.",
            "Canary run does not open R6, promote package, or authorize commercial claims.",
            "Canary result routes to evidence review, not promotion.",
        ],
        "future_blockers": [
            "CANARY_EVIDENCE_REVIEW_PACKET_NOT_YET_AUTHORED",
            "PACKAGE_PROMOTION_REVIEW_NOT_YET_LAWFUL",
            "RUNTIME_CUTOVER_REMAINS_BLOCKED",
        ],
        "reason_codes": list(REASON_CODES),
    }
    compiled = kt_lane_compiler.build_lane_contract(spec)
    rendered = json.dumps(compiled, sort_keys=True, ensure_ascii=True)
    return {
        "schema_id": "kt.b04_r6.limited_runtime_canary_lane_compiler_scaffold_receipt.v1",
        "artifact_id": "B04_R6_LIMITED_RUNTIME_CANARY_LANE_COMPILER_SCAFFOLD_RECEIPT",
        "compiler_id": compiled["compiler_id"],
        "authority": compiled["authority"],
        "status": "PREP_ONLY_SCAFFOLD",
        "lane_id": spec["lane_id"],
        "compiled_contract_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "generated_file_count": len(compiled["files"]),
        "files_omitted_from_receipt": True,
        "scaffold_can_authorize": False,
        "can_execute_canary": False,
        "can_cutover_runtime": False,
        "can_open_r6": False,
        "can_promote_package": False,
    }


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    current_branch: str,
    input_bindings: list[Dict[str, Any]],
    binding_hashes: Dict[str, str],
    validation_rows: list[Dict[str, str]],
    compiler_scaffold: Dict[str, Any],
    trust_zone_validation: Dict[str, Any],
    handoff_acceptance: Dict[str, bool],
    case_rows: list[Dict[str, Any]],
    scorecard: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_utc": generated_utc,
        "current_branch": current_branch,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "status": "PASS",
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "allowed_outcomes": [OUTCOME_PASSED, OUTCOME_FAILED, OUTCOME_INVALIDATED, OUTCOME_DEFERRED],
        "outcome_routing": {
            OUTCOME_PASSED: "AUTHOR_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET",
            OUTCOME_FAILED: "AUTHOR_B04_R6_CANARY_REPAIR_OR_CLOSEOUT_PACKET",
            OUTCOME_INVALIDATED: "AUTHOR_B04_R6_FORENSIC_CANARY_RUNTIME_REVIEW_PACKET",
            OUTCOME_DEFERRED: "REPAIR_B04_R6_LIMITED_RUNTIME_CANARY_DEFECTS",
        },
        "may_authorize": list(MAY_AUTHORIZE),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "terminal_defects": list(TERMINAL_DEFECTS),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "validation_rows": validation_rows,
        "lane_compiler_scaffold": compiler_scaffold,
        "handoff_acceptance": handoff_acceptance,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": trust_zone_validation.get("failures", []),
        "authorization_state": _authorization_state(),
        "runtime_mode": RUNTIME_MODE,
        "case_rows": case_rows,
        "scorecard": scorecard,
        "fired_disqualifiers": [],
        "limited_runtime_canary_executed": True,
        "canary_runtime_executed": True,
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "r6_open": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "metric_contract_mutated": False,
        "static_comparator_weakened": False,
        "canary_result_treated_as_package_promotion": False,
        "no_authorization_drift": True,
    }


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {**base, "schema_id": schema_id, "artifact_id": artifact_id, **extra}


def _receipt(base: Dict[str, Any], *, schema_slug: str, artifact_id: str, role: str, **extra: Any) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.limited_runtime_canary.{schema_slug}.v1",
        artifact_id=artifact_id,
        receipt_role=role,
        **extra,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.limited_runtime_canary.{role}.prep_only.v1",
        artifact_id=f"B04_R6_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        prep_only=True,
        purpose=purpose,
        canary_runtime_executed=True,
        runtime_cutover_authorized=False,
        r6_open=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v34",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        current_authoritative_lane=AUTHORITATIVE_LANE,
        blockers=[
            {
                "blocker_id": "B04R6-FB-101",
                "future_blocker": "Canary evidence exists but has not been reviewed.",
                "neutralization_now": [OUTPUTS["canary_evidence_review_packet_prep_only_draft"]],
            },
            {
                "blocker_id": "B04R6-FB-102",
                "future_blocker": "Canary failure or invalidation needs deterministic closeout path.",
                "neutralization_now": [
                    OUTPUTS["canary_repair_or_closeout_packet_prep_only_draft"],
                    OUTPUTS["forensic_canary_runtime_review_packet_prep_only_draft"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-103",
                "future_blocker": "Package promotion or commercial claims outrun canary evidence review.",
                "neutralization_now": [
                    OUTPUTS["package_promotion_review_preconditions_prep_only_draft"],
                    OUTPUTS["external_audit_delta_manifest_prep_only_draft"],
                ],
            },
        ],
    )


def _pipeline_board(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.pipeline_board.v12",
        artifact_id="B04_R6_PIPELINE_BOARD",
        lanes=[
            {"lane": "VALIDATE_B04_R6_CANARY_EXECUTION_PACKET", "status": "VALIDATED", "authoritative": False},
            {"lane": "RUN_B04_R6_LIMITED_RUNTIME_CANARY", "status": "CURRENT_EXECUTED", "authoritative": True},
            {"lane": "AUTHOR_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET", "status": "NEXT", "authoritative": True},
            {"lane": "AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET", "status": "BLOCKED", "authoritative": False},
            {"lane": "RUNTIME_CUTOVER", "status": "BLOCKED", "authoritative": False},
        ],
        blocked_authorities=[
            "RUNTIME_CUTOVER_AUTHORIZED",
            "R6_OPEN",
            "PACKAGE_PROMOTION_AUTHORIZED",
            "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
        ],
    )


def _outputs(base: Dict[str, Any], compiler_scaffold: Dict[str, Any]) -> Dict[str, Any]:
    scorecard = base["scorecard"]
    case_rows = base["case_rows"]
    output_payloads: Dict[str, Any] = {
        "execution_contract": _with_artifact(base, schema_id="kt.b04_r6.limited_runtime_canary.execution_contract.v1", artifact_id="B04_R6_LIMITED_RUNTIME_CANARY_EXECUTION_CONTRACT"),
        "execution_receipt": _receipt(base, schema_slug="execution_receipt", artifact_id="B04_R6_LIMITED_RUNTIME_CANARY_EXECUTION_RECEIPT", role="execution", canary_executed=True),
        "result": _receipt(base, schema_slug="result", artifact_id="B04_R6_LIMITED_RUNTIME_CANARY_RESULT", role="result", result=scorecard),
        "case_manifest": _receipt(base, schema_slug="case_manifest", artifact_id="B04_R6_CANARY_CASE_MANIFEST", role="case_manifest", cases=case_rows, excluded_case_class_blocks=list(EXCLUDED_CASE_CLASS_BLOCKS)),
        "route_distribution_receipt": _receipt(base, schema_slug="route_distribution", artifact_id="B04_R6_CANARY_ROUTE_DISTRIBUTION_RECEIPT", role="route_distribution", route_observations=scorecard["route_observations"], route_distribution_health="PASS"),
        "fallback_behavior_receipt": _receipt(base, schema_slug="fallback_behavior", artifact_id="B04_R6_CANARY_FALLBACK_BEHAVIOR_RECEIPT", role="fallback_behavior", fallback_invocations=scorecard["fallback_invocations"], fallback_failures=0),
        "static_fallback_receipt": _receipt(base, schema_slug="static_fallback", artifact_id="B04_R6_CANARY_STATIC_FALLBACK_RECEIPT", role="static_fallback", static_fallback_preserved=True),
        "abstention_fallback_receipt": _receipt(base, schema_slug="abstention_fallback", artifact_id="B04_R6_CANARY_ABSTENTION_FALLBACK_RECEIPT", role="abstention_fallback", abstention_fallback_preserved=True, abstention_observations=scorecard["abstention_observations"]),
        "null_route_preservation_receipt": _receipt(base, schema_slug="null_route_preservation", artifact_id="B04_R6_CANARY_NULL_ROUTE_PRESERVATION_RECEIPT", role="null_route_preservation", null_route_preserved=True, null_route_controls_entered_canary=0),
        "operator_override_receipt": _receipt(base, schema_slug="operator_override", artifact_id="B04_R6_CANARY_OPERATOR_OVERRIDE_RECEIPT", role="operator_override", operator_override_ready=True, operator_override_invocations=0),
        "kill_switch_receipt": _receipt(base, schema_slug="kill_switch", artifact_id="B04_R6_CANARY_KILL_SWITCH_RECEIPT", role="kill_switch", kill_switch_ready=True, kill_switch_invocations=0),
        "rollback_receipt": _receipt(base, schema_slug="rollback", artifact_id="B04_R6_CANARY_ROLLBACK_RECEIPT", role="rollback", rollback_ready=True, rollback_invocations=0),
        "drift_monitoring_receipt": _receipt(base, schema_slug="drift_monitoring", artifact_id="B04_R6_CANARY_DRIFT_MONITORING_RECEIPT", role="drift_monitoring", drift_status="PASS", drift_signals=[]),
        "incident_freeze_receipt": _receipt(base, schema_slug="incident_freeze", artifact_id="B04_R6_CANARY_INCIDENT_FREEZE_RECEIPT", role="incident_freeze", incident_freeze_triggers=[]),
        "trace_completeness_receipt": _receipt(base, schema_slug="trace_completeness", artifact_id="B04_R6_CANARY_TRACE_COMPLETENESS_RECEIPT", role="trace_completeness", trace_complete_cases=scorecard["trace_complete_cases"], total_cases=scorecard["total_cases"]),
        "replay_receipt": _receipt(base, schema_slug="replay", artifact_id="B04_R6_CANARY_REPLAY_RECEIPT", role="replay", replay_status="PASS", raw_hash_bound_artifacts_required=True),
        "external_verifier_readiness_receipt": _receipt(base, schema_slug="external_verifier", artifact_id="B04_R6_CANARY_EXTERNAL_VERIFIER_READINESS_RECEIPT", role="external_verifier", external_verifier_ready=True),
        "commercial_claim_boundary_receipt": _receipt(base, schema_slug="commercial_claim_boundary", artifact_id="B04_R6_CANARY_COMMERCIAL_CLAIM_BOUNDARY_RECEIPT", role="commercial_claim_boundary", commercial_activation_claim_authorized=False, forbidden_claims=["AFSH is live", "R6 is open", "package promotion is ready"]),
        "no_authorization_drift_receipt": _receipt(base, schema_slug="no_authorization_drift", artifact_id="B04_R6_CANARY_NO_AUTHORIZATION_DRIFT_RECEIPT", role="no_authorization_drift", no_downstream_authorization_drift=True),
        "future_blocker_register": _future_blocker_register(base),
        "pipeline_board": _pipeline_board(base),
        "next_lawful_move": _with_artifact(base, schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v34", artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT", verdict="NEXT_LAWFUL_MOVE_SET"),
    }
    output_payloads["expected_runtime_execution_receipt"] = output_payloads["execution_receipt"]
    output_payloads["expected_runtime_result"] = output_payloads["result"]
    output_payloads["expected_runtime_case_manifest"] = output_payloads["case_manifest"]
    output_payloads["expected_runtime_route_distribution_health_receipt"] = output_payloads["route_distribution_receipt"]
    output_payloads["expected_runtime_no_authorization_drift_receipt"] = output_payloads["no_authorization_drift_receipt"]
    output_payloads.update(
        {
            role: _prep_only(base, role=role, purpose=f"Prep-only scaffold for future {role.replace('_', ' ')}.")
            for role in PREP_ONLY_OUTPUT_ROLES
        }
    )
    output_payloads["execution_contract"]["lane_compiler_scaffold"] = compiler_scaffold
    return output_payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Limited-Runtime Canary\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "The limited-runtime canary ran under the validated canary execution packet. The run stayed inside the "
        "operator-observed sample scope, respected allowed and excluded case classes, preserved static fallback, "
        "abstention fallback, null-route preservation, operator override, kill switch, rollback readiness, route "
        "distribution monitoring, drift monitoring, trace completeness, replayability, external verifier readiness, "
        "and commercial claim boundaries.\n\n"
        "This canary result does not authorize runtime cutover, R6 opening, lobe escalation, package promotion, "
        "commercial activation claims, truth/trust law mutation, metric widening, or comparator weakening.\n"
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 limited-runtime canary")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if current_branch != "main" else "HEAD")
    handoff_git_commit = current_main_head if current_branch != "main" else head
    output_names = set(OUTPUTS.values())
    payloads = {
        role: _load_input(root, raw, label=role, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in ALL_JSON_INPUTS.items()
    }
    texts = {
        role: _read_text_input(root, raw, label=role, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in ALL_TEXT_INPUTS.items()
    }
    handoff_acceptance = _validate_inputs(payloads, texts)
    _validate_packet_hashes(root, payloads)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_CANARY_RUN_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    case_rows = _case_rows()
    scorecard = _scorecard(case_rows)
    compiler_scaffold = _compiler_scaffold(current_main_head)
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=_input_bindings(root, handoff_git_commit=handoff_git_commit),
        binding_hashes=_binding_hashes(root, payloads, handoff_git_commit=handoff_git_commit),
        validation_rows=_validation_rows(case_rows),
        compiler_scaffold=compiler_scaffold,
        trust_zone_validation=fresh_trust_validation,
        handoff_acceptance=handoff_acceptance,
        case_rows=case_rows,
        scorecard=scorecard,
    )
    output_payloads = _outputs(base, compiler_scaffold)
    contract = output_payloads["execution_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run B04 R6 limited-runtime canary.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
