from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_canary_execution_packet as execution
from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_lane_compiler
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-canary-execution-packet-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_CANARY_EXECUTION_PACKET_VALIDATION"
PREVIOUS_LANE = execution.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = execution.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = execution.NEXT_LAWFUL_MOVE
OUTCOME_VALIDATED = "B04_R6_CANARY_EXECUTION_PACKET_VALIDATED__CANARY_RUNTIME_NEXT"
OUTCOME_DEFERRED = "B04_R6_CANARY_EXECUTION_PACKET_VALIDATION_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
OUTCOME_REJECTED = "B04_R6_CANARY_EXECUTION_PACKET_REJECTED__CANARY_RUNTIME_NOT_JUSTIFIED"
OUTCOME_INVALID = "B04_R6_CANARY_EXECUTION_PACKET_INVALID__FORENSIC_CANARY_EXECUTION_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_VALIDATED
NEXT_LAWFUL_MOVE = "RUN_B04_R6_LIMITED_RUNTIME_CANARY"

MAY_AUTHORIZE = ("CANARY_EXECUTION_PACKET_VALIDATED",)
FORBIDDEN_ACTIONS = (
    "CANARY_RUNTIME_EXECUTED",
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
)
TERMINAL_DEFECTS = (
    "CANARY_EXECUTION_PACKET_MISSING",
    "CANARY_EXECUTION_PACKET_HASH_MISMATCH",
    "CANARY_AUTHORIZATION_VALIDATION_UNBOUND",
    "CANARY_EXECUTION_SCOPE_MISSING",
    "CANARY_EXECUTION_SAMPLE_LIMIT_MISSING",
    "CANARY_RUNTIME_EXECUTED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "R6_OPEN_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL_CLAIM_DRIFT",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "PREP_ONLY_AUTHORITY_DRIFT",
    "NEXT_MOVE_DRIFT",
)
REASON_CODES = (
    "RC_B04R6_CANARY_EXEC_VAL_CONTRACT_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_MAIN_HEAD_MISMATCH",
    "RC_B04R6_CANARY_EXEC_VAL_PACKET_BINDING_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_RECEIPT_BINDING_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_AUTHORIZATION_VALIDATION_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_AUTHORIZATION_PACKET_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_SOURCE_HASH_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_SOURCE_HASH_MISMATCH",
    "RC_B04R6_CANARY_EXEC_VAL_MODE_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_SCOPE_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_ALLOWED_CASE_CLASSES_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_EXCLUDED_CASE_CLASSES_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_SAMPLE_LIMIT_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_STATIC_FALLBACK_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_ABSTENTION_FALLBACK_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_NULL_ROUTE_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_OPERATOR_OVERRIDE_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_KILL_SWITCH_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_ROLLBACK_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_ROUTE_HEALTH_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_DRIFT_THRESHOLDS_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_INCIDENT_FREEZE_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_REPLAY_MANIFEST_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_EXPECTED_ARTIFACT_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_RESULT_INTERPRETATION_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_PRIOR_GIT_BINDING_DRIFT",
    "RC_B04R6_CANARY_EXEC_VAL_INPUT_HASH_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_INPUT_HASH_MALFORMED",
    "RC_B04R6_CANARY_EXEC_VAL_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_CANARY_EXEC_VAL_CANARY_EXECUTED",
    "RC_B04R6_CANARY_EXEC_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_CANARY_EXEC_VAL_R6_OPEN_DRIFT",
    "RC_B04R6_CANARY_EXEC_VAL_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_CANARY_EXEC_VAL_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_CANARY_EXEC_VAL_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_CANARY_EXEC_VAL_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_CANARY_EXEC_VAL_TRUST_ZONE_MUTATION",
    "RC_B04R6_CANARY_EXEC_VAL_COMPILER_SCAFFOLD_MISSING",
    "RC_B04R6_CANARY_EXEC_VAL_NEXT_MOVE_DRIFT",
)

EXECUTION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in execution.OUTPUTS.items()
    if filename.endswith(".json")
}
EXECUTION_TEXT_INPUTS = {
    "packet_report": f"KT_PROD_CLEANROOM/reports/{execution.OUTPUTS['packet_report']}",
}
DIRECT_SOURCE_HASH_BINDING_KEYS = {
    "validated_canary_authorization_receipt_hash": "validation_validation_receipt_hash",
    "canary_scope_manifest_hash": "canary_scope_manifest_hash",
    "canary_authorization_packet_hash": "canary_packet_contract_hash",
}
CANARY_VALIDATION_SOURCE_HASH_BINDING_KEYS = {
    "canary_scope_manifest_hash": "scope_manifest_hash",
    "canary_authorization_packet_hash": "packet_contract_hash",
}
CANARY_PACKET_SOURCE_EVIDENCE_KEYS = {
    "runtime_evidence_review_validation_receipt_hash": "validated_runtime_evidence_review_receipt_hash",
    "runtime_evidence_inventory_hash": "runtime_evidence_inventory_hash",
    "runtime_evidence_scorecard_hash": "runtime_evidence_scorecard_hash",
    "shadow_runtime_result_hash": "shadow_runtime_result_hash",
    "static_authority_preservation_evidence_hash": "static_authority_preservation_evidence_hash",
    "route_distribution_health_evidence_hash": "route_distribution_health_evidence_hash",
    "fallback_behavior_evidence_hash": "fallback_behavior_evidence_hash",
    "operator_override_readiness_evidence_hash": "operator_override_readiness_evidence_hash",
    "kill_switch_readiness_evidence_hash": "kill_switch_readiness_evidence_hash",
    "rollback_readiness_evidence_hash": "rollback_readiness_evidence_hash",
    "drift_monitoring_evidence_hash": "drift_monitoring_evidence_hash",
    "incident_freeze_evidence_hash": "incident_freeze_evidence_hash",
    "trace_completeness_evidence_hash": "trace_completeness_evidence_hash",
    "runtime_replay_evidence_hash": "runtime_replay_evidence_hash",
    "external_verifier_readiness_evidence_hash": "external_verifier_readiness_evidence_hash",
    "commercial_claim_boundary_hash": "commercial_claim_boundary_hash",
    "package_promotion_blocker_review_hash": "package_promotion_blocker_review_hash",
}
VALIDATION_RECEIPT_ROLES = (
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
)
PREP_ONLY_OUTPUT_ROLES = (
    "canary_run_plan_prep_only",
    "canary_run_receipt_schema_prep_only",
    "canary_run_result_schema_prep_only",
    "canary_run_disqualifier_ledger_prep_only",
    "canary_evidence_review_packet_prep_only_draft",
    "canary_evidence_scorecard_prep_only",
    "canary_failure_closeout_prep_only_draft",
    "canary_forensic_invalidation_court_prep_only_draft",
    "package_promotion_review_preconditions_prep_only_draft",
    "external_audit_delta_manifest_prep_only_draft",
    "public_verifier_delta_requirements_prep_only",
)
OUTPUTS = {
    "validation_contract": "b04_r6_canary_execution_packet_validation_contract.json",
    "validation_receipt": "b04_r6_canary_execution_packet_validation_receipt.json",
    "validation_report": "b04_r6_canary_execution_packet_validation_report.md",
    "packet_binding_validation": "b04_r6_canary_execution_packet_binding_validation_receipt.json",
    "authorization_validation_binding": "b04_r6_canary_execution_authorization_validation_binding_receipt.json",
    "authorization_packet_binding": "b04_r6_canary_execution_authorization_packet_binding_receipt.json",
    "source_hashes_validation": "b04_r6_canary_execution_source_hashes_validation_receipt.json",
    "mode_validation": "b04_r6_canary_execution_mode_validation_receipt.json",
    "scope_validation": "b04_r6_canary_execution_scope_validation_receipt.json",
    "allowed_case_class_validation": "b04_r6_canary_execution_allowed_case_class_validation_receipt.json",
    "excluded_case_class_validation": "b04_r6_canary_execution_excluded_case_class_validation_receipt.json",
    "sample_limit_validation": "b04_r6_canary_execution_sample_limit_validation_receipt.json",
    "static_fallback_validation": "b04_r6_canary_execution_static_fallback_validation_receipt.json",
    "abstention_fallback_validation": "b04_r6_canary_execution_abstention_fallback_validation_receipt.json",
    "null_route_preservation_validation": "b04_r6_canary_execution_null_route_preservation_validation_receipt.json",
    "operator_override_validation": "b04_r6_canary_execution_operator_override_validation_receipt.json",
    "kill_switch_validation": "b04_r6_canary_execution_kill_switch_validation_receipt.json",
    "rollback_validation": "b04_r6_canary_execution_rollback_validation_receipt.json",
    "route_distribution_health_validation": "b04_r6_canary_execution_route_distribution_health_validation_receipt.json",
    "drift_threshold_validation": "b04_r6_canary_execution_drift_threshold_validation_receipt.json",
    "incident_freeze_validation": "b04_r6_canary_execution_incident_freeze_validation_receipt.json",
    "runtime_receipt_schema_validation": "b04_r6_canary_execution_runtime_receipt_schema_validation_receipt.json",
    "replay_manifest_validation": "b04_r6_canary_execution_replay_manifest_validation_receipt.json",
    "expected_artifact_manifest_validation": "b04_r6_canary_execution_expected_artifact_manifest_validation_receipt.json",
    "external_verifier_validation": "b04_r6_canary_execution_external_verifier_validation_receipt.json",
    "result_interpretation_validation": "b04_r6_canary_execution_result_interpretation_validation_receipt.json",
    "pipeline_board_validation": "b04_r6_canary_execution_pipeline_board_validation_receipt.json",
    "no_authorization_drift_validation": "b04_r6_canary_execution_no_authorization_drift_validation_receipt.json",
    "paired_lane_compiler_scaffold_receipt": "b04_r6_canary_execution_validation_paired_lane_compiler_scaffold_receipt.json",
    "canary_run_plan_prep_only": "b04_r6_limited_runtime_canary_run_plan_prep_only.json",
    "canary_run_receipt_schema_prep_only": "b04_r6_canary_run_receipt_schema_prep_only.json",
    "canary_run_result_schema_prep_only": "b04_r6_canary_run_result_schema_prep_only.json",
    "canary_run_disqualifier_ledger_prep_only": "b04_r6_canary_run_disqualifier_ledger_prep_only.json",
    "canary_evidence_review_packet_prep_only_draft": "b04_r6_canary_evidence_review_packet_prep_only_draft.json",
    "canary_evidence_scorecard_prep_only": "b04_r6_canary_evidence_scorecard_prep_only.json",
    "canary_failure_closeout_prep_only_draft": "b04_r6_canary_failure_closeout_prep_only_draft.json",
    "canary_forensic_invalidation_court_prep_only_draft": "b04_r6_canary_forensic_invalidation_court_prep_only_draft.json",
    "package_promotion_review_preconditions_prep_only_draft": "b04_r6_package_promotion_review_preconditions_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only_draft": "b04_r6_external_audit_delta_manifest_prep_only_draft.json",
    "public_verifier_delta_requirements_prep_only": "b04_r6_public_verifier_delta_requirements_prep_only.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}


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
            _fail("RC_B04R6_CANARY_EXEC_VAL_PACKET_BINDING_MISSING", f"git-bound input {label} missing at {handoff_git_commit}: {exc}")
    return _load(root, raw, label=label)


def _read_text_input(root: Path, raw: str, *, label: str, handoff_git_commit: str, output_names: set[str]) -> str:
    if Path(raw).name in output_names:
        try:
            return _git_blob_bytes(root, handoff_git_commit, raw).decode("utf-8")
        except Exception as exc:
            _fail("RC_B04R6_CANARY_EXEC_VAL_PACKET_BINDING_MISSING", f"git-bound text input {label} missing at {handoff_git_commit}: {exc}")
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


def _ensure_authority_closed(payload: Dict[str, Any], *, label: str) -> None:
    forbidden_truths = {
        "canary_runtime_executed": "RC_B04R6_CANARY_EXEC_VAL_CANARY_EXECUTED",
        "runtime_cutover_authorized": "RC_B04R6_CANARY_EXEC_VAL_RUNTIME_CUTOVER_AUTHORIZED",
        "activation_cutover_executed": "RC_B04R6_CANARY_EXEC_VAL_RUNTIME_CUTOVER_AUTHORIZED",
        "r6_open": "RC_B04R6_CANARY_EXEC_VAL_R6_OPEN_DRIFT",
        "lobe_escalation_authorized": "RC_B04R6_CANARY_EXEC_VAL_LOBE_ESCALATION_DRIFT",
        "package_promotion_authorized": "RC_B04R6_CANARY_EXEC_VAL_PACKAGE_PROMOTION_DRIFT",
        "commercial_activation_claim_authorized": "RC_B04R6_CANARY_EXEC_VAL_COMMERCIAL_CLAIM_DRIFT",
        "truth_engine_law_changed": "RC_B04R6_CANARY_EXEC_VAL_TRUTH_ENGINE_MUTATION",
        "trust_zone_law_changed": "RC_B04R6_CANARY_EXEC_VAL_TRUST_ZONE_MUTATION",
        "metric_contract_mutated": "RC_B04R6_CANARY_EXEC_VAL_PREP_ONLY_AUTHORITY_DRIFT",
        "static_comparator_weakened": "RC_B04R6_CANARY_EXEC_VAL_PREP_ONLY_AUTHORITY_DRIFT",
    }
    for key, value in _walk_items(payload):
        if key in forbidden_truths and value is True:
            _fail(forbidden_truths[key], f"{label}.{key} drifted true")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_CANARY_EXEC_VAL_PACKAGE_PROMOTION_DRIFT", f"{label}.package_promotion drifted")


def _input_hash(root: Path, raw: str, *, handoff_git_commit: str, output_names: set[str]) -> str:
    if Path(raw).name in output_names:
        return _git_blob_sha256(root, handoff_git_commit, raw)
    return file_sha256(common.resolve_path(root, raw))


def _input_bindings(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    output_names = set(OUTPUTS.values())
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(EXECUTION_JSON_INPUTS.items()):
        is_overwritten = Path(raw).name in output_names
        row: Dict[str, Any] = {
            "role": role,
            "path": raw,
            "sha256": _input_hash(root, raw, handoff_git_commit=handoff_git_commit, output_names=output_names),
            "binding_kind": "file_sha256_at_canary_execution_packet_validation",
        }
        if is_overwritten:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(EXECUTION_TEXT_INPUTS.items()):
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": "file_sha256_at_canary_execution_packet_validation",
            }
        )
    return rows


def _binding_hashes(root: Path, *, handoff_git_commit: str) -> Dict[str, str]:
    output_names = set(OUTPUTS.values())
    hashes = {
        f"{role}_hash": _input_hash(root, raw, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in sorted(EXECUTION_JSON_INPUTS.items())
    }
    hashes.update({f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(EXECUTION_TEXT_INPUTS.items())})
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


def _validate_prior_git_bindings(root: Path, contract: Dict[str, Any]) -> None:
    prior_main_head = contract.get("current_main_head")
    if not prior_main_head:
        _fail("RC_B04R6_CANARY_EXEC_VAL_PRIOR_GIT_BINDING_DRIFT", "execution contract lacks prior main head")
    output_names = set(OUTPUTS.values())
    for row in contract.get("input_bindings", []):
        role = row.get("role")
        raw = row.get("path")
        sha = row.get("sha256")
        if not role or not raw or not _is_sha256(sha):
            _fail("RC_B04R6_CANARY_EXEC_VAL_INPUT_HASH_MALFORMED", f"malformed input binding row: {role}")
        overwritten_by_this_lane = Path(str(raw)).name in output_names
        if row.get("binding_kind") == "git_object_before_overwrite":
            if row.get("git_commit") != prior_main_head:
                _fail("RC_B04R6_CANARY_EXEC_VAL_PRIOR_GIT_BINDING_DRIFT", f"{role} not bound to prior canonical main")
            actual = _git_blob_sha256(root, str(row["git_commit"]), str(raw))
        elif overwritten_by_this_lane:
            actual = _git_blob_sha256(root, str(prior_main_head), str(raw))
        else:
            actual = file_sha256(common.resolve_path(root, str(raw)))
        if actual != sha:
            _fail("RC_B04R6_CANARY_EXEC_VAL_INPUT_HASH_MALFORMED", f"{role} hash mismatch")
        binding_key = f"{role}_hash"
        if contract.get("binding_hashes", {}).get(binding_key) != sha:
            _fail("RC_B04R6_CANARY_EXEC_VAL_INPUT_HASH_MISSING", f"{binding_key} missing or mismatched")


def _bound_input_path(contract: Dict[str, Any], role: str) -> str:
    for row in contract.get("input_bindings", []):
        if row.get("role") == role and row.get("path"):
            return str(row["path"])
    _fail("RC_B04R6_CANARY_EXEC_VAL_INPUT_HASH_MISSING", f"{role} input binding missing")


def _validate_source_hashes(root: Path, contract: Dict[str, Any]) -> None:
    source_hashes = contract.get("source_hashes", {})
    for key in execution.REQUIRED_SOURCE_HASHES:
        if not _is_sha256(source_hashes.get(key)):
            _fail("RC_B04R6_CANARY_EXEC_VAL_SOURCE_HASH_MISSING", f"{key} missing")

    binding_hashes = contract.get("binding_hashes", {})
    for source_key, binding_key in DIRECT_SOURCE_HASH_BINDING_KEYS.items():
        if source_hashes[source_key] != binding_hashes.get(binding_key):
            _fail("RC_B04R6_CANARY_EXEC_VAL_SOURCE_HASH_MISMATCH", f"{source_key} does not match {binding_key}")

    canary_validation_contract = _load(
        root,
        _bound_input_path(contract, "validation_validation_contract"),
        label="bound canary authorization validation contract",
    )
    canary_validation_hashes = canary_validation_contract.get("binding_hashes", {})
    for source_key, binding_key in CANARY_VALIDATION_SOURCE_HASH_BINDING_KEYS.items():
        if source_hashes[source_key] != canary_validation_hashes.get(binding_key):
            _fail("RC_B04R6_CANARY_EXEC_VAL_SOURCE_HASH_MISMATCH", f"{source_key} does not match validated {binding_key}")

    canary_packet_contract = _load(root, _bound_input_path(contract, "canary_packet_contract"), label="bound canary authorization packet")
    source_evidence_hashes = canary_packet_contract.get("source_evidence_hashes", {})
    for source_key, evidence_key in CANARY_PACKET_SOURCE_EVIDENCE_KEYS.items():
        if source_hashes[source_key] != source_evidence_hashes.get(evidence_key):
            _fail("RC_B04R6_CANARY_EXEC_VAL_SOURCE_HASH_MISMATCH", f"{source_key} does not match canary packet {evidence_key}")


def _validate_operational_contracts(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in execution.CANARY_EXECUTION_CONTRACT_ROLES:
        payload = payloads[role]
        if payload.get("contract_status") != "BOUND_NON_EXECUTING":
            _fail("RC_B04R6_CANARY_EXEC_VAL_PACKET_BINDING_MISSING", f"{role} is not bound/non-executing")
        if payload.get("canary_runtime_executed") is not False:
            _fail("RC_B04R6_CANARY_EXEC_VAL_CANARY_EXECUTED", f"{role} execution drift")
        if payload.get("runtime_cutover_authorized") is not False:
            _fail("RC_B04R6_CANARY_EXEC_VAL_RUNTIME_CUTOVER_AUTHORIZED", f"{role} cutover drift")

    if payloads["mode_contract"].get("details", {}).get("mode") != "LIMITED_OPERATOR_OBSERVED_CANARY_PACKET_ONLY":
        _fail("RC_B04R6_CANARY_EXEC_VAL_MODE_MISSING", "canary execution mode drift")
    scope = payloads["scope_manifest"].get("details", {})
    if scope.get("scope_status") != "LIMITED_CANARY_EXECUTION_SCOPE_BOUND_NOT_VALIDATED":
        _fail("RC_B04R6_CANARY_EXEC_VAL_SCOPE_MISSING", "scope status drift")
    if scope.get("global_r6_scope_allowed") is not False or scope.get("runtime_cutover_allowed") is not False:
        _fail("RC_B04R6_CANARY_EXEC_VAL_R6_OPEN_DRIFT", "scope widened")
    if scope.get("max_case_count_per_window") != 12 or scope.get("operator_observed_required") is not True:
        _fail("RC_B04R6_CANARY_EXEC_VAL_SAMPLE_LIMIT_MISSING", "sample limit/operator observation missing")
    allowed = {row.get("case_class") for row in payloads["allowed_case_class_contract"].get("details", {}).get("allowed_case_classes", [])}
    if allowed != {"ROUTE_ELIGIBLE_LOW_RISK_SHADOW_CONFIRMED", "STATIC_FALLBACK_AVAILABLE_ROUTE_CHECK", "NON_COMMERCIAL_OPERATOR_OBSERVED_SAMPLE"}:
        _fail("RC_B04R6_CANARY_EXEC_VAL_ALLOWED_CASE_CLASSES_MISSING", "allowed case classes drift")
    excluded = {row.get("case_class") for row in payloads["excluded_case_class_contract"].get("details", {}).get("excluded_case_classes", [])}
    for required in {"GLOBAL_R6_TRAFFIC", "NO_STATIC_FALLBACK_AVAILABLE", "NULL_ROUTE_CONTROL", "COMMERCIAL_ACTIVATION_SURFACE"}:
        if required not in excluded:
            _fail("RC_B04R6_CANARY_EXEC_VAL_EXCLUDED_CASE_CLASSES_MISSING", f"excluded case class missing {required}")
    required_details = {
        "sample_limit_contract": ("max_case_count_per_window", 12),
        "static_fallback_contract": ("static_fallback_required", True),
        "abstention_fallback_contract": ("abstention_fallback_required", True),
        "null_route_preservation_contract": ("null_route_controls_excluded", True),
        "operator_override_contract": ("operator_override_required", True),
        "kill_switch_contract": ("kill_switch_required", True),
        "rollback_contract": ("rollback_required", True),
        "external_verifier_requirements": ("external_verifier_required", True),
        "result_interpretation_contract": ("pass_does_not_authorize_cutover", True),
    }
    for role, (key, expected) in required_details.items():
        if payloads[role].get("details", {}).get(key) != expected:
            _fail("RC_B04R6_CANARY_EXEC_VAL_PACKET_BINDING_MISSING", f"{role}.{key} drift")
    if payloads["route_distribution_health_thresholds"].get("details", {}).get("zero_null_route_selector_entries_required") is not True:
        _fail("RC_B04R6_CANARY_EXEC_VAL_ROUTE_HEALTH_MISSING", "route health threshold missing")
    if payloads["drift_thresholds"].get("details", {}).get("metric_widening_allowed") is not False:
        _fail("RC_B04R6_CANARY_EXEC_VAL_DRIFT_THRESHOLDS_MISSING", "metric widening drift")
    receipt_schema = payloads["runtime_receipt_schema"].get("details", {})
    if receipt_schema.get("raw_hash_bound_artifacts_required") is not True or receipt_schema.get("compressed_index_source_of_truth") is not False:
        _fail("RC_B04R6_CANARY_EXEC_VAL_RUNTIME_RECEIPT_SCHEMA_MISSING", "receipt schema weakens raw artifact truth")
    replay = payloads["replay_manifest"].get("details", {})
    if replay.get("raw_hash_bound_artifacts_required") is not True or replay.get("compressed_index_source_of_truth") is not False:
        _fail("RC_B04R6_CANARY_EXEC_VAL_REPLAY_MANIFEST_MISSING", "replay manifest weakens raw artifact truth")
    expected = set(payloads["expected_artifact_manifest"].get("details", {}).get("expected_artifacts", []))
    if "b04_r6_canary_runtime_execution_receipt.json" not in expected:
        _fail("RC_B04R6_CANARY_EXEC_VAL_EXPECTED_ARTIFACT_MISSING", "expected runtime execution receipt missing")


def _validate_authoring_payloads(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        _ensure_authority_closed(payload, label=label)
    for role in execution.PREP_ONLY_OUTPUT_ROLES:
        payload = payloads[role]
        if payload.get("status") != "PREP_ONLY" or payload.get("authority") != "PREP_ONLY_NON_AUTHORITY":
            _fail("RC_B04R6_CANARY_EXEC_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{role} is not prep-only")

    contract = payloads["packet_contract"]
    receipt = payloads["packet_receipt"]
    next_move = payloads["next_lawful_move"]
    for role, payload in (("packet_contract", contract), ("packet_receipt", receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_CANARY_EXEC_VAL_PACKET_BINDING_MISSING", f"{role} lane identity drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_CANARY_EXEC_VAL_PACKET_BINDING_MISSING", f"{role} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_CANARY_EXEC_VAL_NEXT_MOVE_DRIFT", f"{role} next move drift")
        if payload.get("canary_execution_packet_authored") is not True:
            _fail("RC_B04R6_CANARY_EXEC_VAL_PACKET_BINDING_MISSING", f"{role} missing authored flag")
        if payload.get("canary_execution_packet_validated") is not False:
            _fail("RC_B04R6_CANARY_EXEC_VAL_PACKET_BINDING_MISSING", f"{role} self-validates prematurely")
    if not _valid_handoff(next_move):
        _fail("RC_B04R6_CANARY_EXEC_VAL_NEXT_MOVE_DRIFT", "next move handoff lacks valid lane identity")

    _validate_prior_git_bindings(root, contract)
    _validate_source_hashes(root, contract)
    _validate_operational_contracts(payloads)

    validation_plan = payloads["validation_plan"]
    if validation_plan.get("validation_lane") != "VALIDATE_B04_R6_CANARY_EXECUTION_PACKET":
        _fail("RC_B04R6_CANARY_EXEC_VAL_PACKET_BINDING_MISSING", "execution validation plan targets wrong lane")
    if "execution_mode_defined" not in validation_plan.get("required_checks", []):
        _fail("RC_B04R6_CANARY_EXEC_VAL_MODE_MISSING", "validation plan missing mode check")

    scaffold = payloads["paired_lane_compiler_scaffold_receipt"]
    if scaffold.get("scaffold_authority") != "PREP_ONLY_TOOLING" or scaffold.get("scaffold_can_authorize") is not False:
        _fail("RC_B04R6_CANARY_EXEC_VAL_COMPILER_SCAFFOLD_MISSING", "paired scaffold authority drift")

    board = payloads["pipeline_board"]
    lanes = {row.get("lane"): row for row in board.get("lanes", [])}
    validation_status = lanes.get("VALIDATE_B04_R6_CANARY_EXECUTION_PACKET", {}).get("status")
    runtime_status = lanes.get("RUN_B04_R6_LIMITED_RUNTIME_CANARY", {}).get("status")
    predecessor_board = validation_status == "NEXT" and runtime_status == "BLOCKED"
    self_replay_board = validation_status == "CURRENT_VALIDATED" and runtime_status == "NEXT"
    if not (predecessor_board or self_replay_board):
        _fail("RC_B04R6_CANARY_EXEC_VAL_NEXT_MOVE_DRIFT", "pipeline board does not show lawful validation/runtime handoff")

    report = texts["packet_report"].lower()
    for phrase in ("does not execute canary", "does not authorize runtime cutover", "commercial activation claims"):
        if phrase not in report:
            _fail("RC_B04R6_CANARY_EXEC_VAL_PACKET_BINDING_MISSING", f"packet report missing {phrase}")


def _validation_spec(current_main_head: str) -> Dict[str, Any]:
    return {
        "lane_id": "VALIDATE_B04_R6_CANARY_EXECUTION_PACKET",
        "lane_name": "B04 R6 canary execution packet validation",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM",
        "summary": "Prep-only paired scaffold for validating the canary execution packet.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/cohort0_b04_r6_canary_execution_packet_validation.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_b04_r6_canary_execution_packet_validation.py",
        "artifacts": sorted(OUTPUTS.values()),
        "json_parse_inputs": sorted(filename for filename in OUTPUTS.values() if filename.endswith(".json")),
        "no_authorization_drift_checks": [
            "Validation does not execute canary runtime.",
            "Validation does not authorize runtime cutover, R6 open, package promotion, or commercial claims.",
            "Truth-engine and trust-zone law remain unchanged.",
        ],
        "future_blockers": [
            "Canary runtime is next lawful lane but remains unexecuted in validation.",
            "Canary evidence review must pass before package promotion review.",
            "Runtime cutover remains blocked until future cutover law.",
        ],
        "reason_codes": list(REASON_CODES),
        "lane_kind": "VALIDATION",
        "current_main_head": current_main_head,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "may_authorize": list(MAY_AUTHORIZE),
        "must_not_authorize": list(FORBIDDEN_ACTIONS),
        "authoritative_inputs": sorted(EXECUTION_JSON_INPUTS),
        "prep_only_outputs": sorted(PREP_ONLY_OUTPUT_ROLES),
    }


def _runtime_run_spec(current_main_head: str) -> Dict[str, Any]:
    return {
        "lane_id": "RUN_B04_R6_LIMITED_RUNTIME_CANARY",
        "lane_name": "B04 R6 limited-runtime canary run",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM",
        "summary": "Prep-only paired scaffold for the future canary run lane.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/cohort0_b04_r6_limited_runtime_canary.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_b04_r6_limited_runtime_canary.py",
        "artifacts": [
            "b04_r6_canary_runtime_execution_receipt.json",
            "b04_r6_canary_runtime_result.json",
            "b04_r6_canary_runtime_case_manifest.json",
        ],
        "json_parse_inputs": [
            "b04_r6_canary_runtime_execution_receipt.json",
            "b04_r6_canary_runtime_result.json",
            "b04_r6_canary_runtime_case_manifest.json",
        ],
        "no_authorization_drift_checks": [
            "Canary run does not authorize runtime cutover.",
            "Canary run does not open R6, promote package, or authorize commercial claims.",
        ],
        "future_blockers": [
            "Canary evidence review must be authored and validated after canary run.",
            "Package promotion remains blocked until evidence review and external audit.",
        ],
        "reason_codes": list(REASON_CODES),
        "lane_kind": "EXECUTION",
        "current_main_head": current_main_head,
        "predecessor_outcome": SELECTED_OUTCOME,
        "selected_outcome": "B04_R6_LIMITED_RUNTIME_CANARY_PASSED__CANARY_EVIDENCE_REVIEW_PACKET_NEXT",
        "next_lawful_move": "AUTHOR_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET",
        "may_authorize": ["CANARY_RUNTIME_EXECUTED_WITHIN_VALIDATED_SCOPE"],
        "must_not_authorize": list(FORBIDDEN_ACTIONS),
        "authoritative_inputs": sorted(EXECUTION_JSON_INPUTS),
        "prep_only_outputs": ["b04_r6_canary_evidence_review_packet_prep_only_draft.json"],
    }


def _paired_compiler_scaffold(current_main_head: str) -> Dict[str, Any]:
    paired = kt_lane_compiler.build_paired_lane_contract(_validation_spec(current_main_head), _runtime_run_spec(current_main_head))
    rendered = json.dumps(paired, sort_keys=True, ensure_ascii=True)
    return {
        "compiler_id": kt_lane_compiler.COMPILER_ID,
        "authority": kt_lane_compiler.AUTHORITY,
        "status": "PREP_ONLY_VALIDATION_TO_RUN_SCAFFOLD_USED",
        "paired_contract_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "author_lane_id": paired["author_lane_id"],
        "validation_lane_id": paired["validation_lane_id"],
        "paired_lane_law": paired["paired_lane_law"],
        "generated_artifacts": paired["paired_generated_artifacts"],
        "non_authorization_guards": paired["non_authorization_guards"],
    }


def _validation_rows() -> list[Dict[str, Any]]:
    checks = [
        "canary_execution_packet_bound",
        "canary_authorization_validation_bound",
        "canary_authorization_packet_bound",
        "source_hashes_bound",
        "execution_mode_defined",
        "execution_scope_limited",
        "allowed_case_classes_defined",
        "excluded_case_classes_defined",
        "sample_limit_defined",
        "static_fallback_required",
        "abstention_fallback_required",
        "null_route_preservation_required",
        "operator_override_required",
        "kill_switch_required",
        "rollback_required",
        "route_distribution_thresholds_defined",
        "drift_thresholds_defined",
        "incident_freeze_conditions_defined",
        "runtime_receipt_schema_defined",
        "runtime_replay_manifest_defined",
        "expected_artifact_manifest_defined",
        "external_verifier_requirements_defined",
        "result_interpretation_contract_defined",
        "prior_git_object_bindings_stable",
        "prep_only_drafts_remain_prep_only",
        "canary_not_executed_in_validation",
        "runtime_cutover_not_authorized",
        "r6_remains_closed",
        "lobe_escalation_unauthorized",
        "package_promotion_blocked",
        "commercial_claims_blocked",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
        "next_lawful_move_canary_runtime",
    ]
    terminal = {
        "canary_execution_packet_bound",
        "canary_authorization_validation_bound",
        "execution_mode_defined",
        "execution_scope_limited",
        "sample_limit_defined",
        "runtime_receipt_schema_defined",
        "canary_not_executed_in_validation",
        "runtime_cutover_not_authorized",
        "r6_remains_closed",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
        "next_lawful_move_canary_runtime",
    }
    return [
        {
            "check_id": f"B04R6-CANARY-EXEC-VALIDATION-{index:03d}",
            "name": check,
            "status": "PASS",
            "terminal_if_fail": check in terminal,
        }
        for index, check in enumerate(checks, start=1)
    ]


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    current_branch: str,
    input_bindings: list[Dict[str, Any]],
    binding_hashes: Dict[str, str],
    validation_rows: list[Dict[str, Any]],
    paired_scaffold: Dict[str, Any],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "current_branch": current_branch,
        "schema_version": "v1",
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "canary_authorization_packet_authored": True,
        "canary_authorization_packet_validated": True,
        "canary_execution_packet_authored": True,
        "canary_execution_packet_validated": True,
        "canary_runtime_next_lawful_lane": True,
        "canary_runtime_authorized": False,
        "canary_runtime_executed": False,
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
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "validation_rows": validation_rows,
        "may_authorize": list(MAY_AUTHORIZE),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "allowed_outcomes": [OUTCOME_VALIDATED, OUTCOME_DEFERRED, OUTCOME_REJECTED, OUTCOME_INVALID],
        "outcome_routing": {
            OUTCOME_VALIDATED: NEXT_LAWFUL_MOVE,
            OUTCOME_DEFERRED: "REPAIR_B04_R6_CANARY_EXECUTION_PACKET_VALIDATION_DEFECTS",
            OUTCOME_REJECTED: "AUTHOR_B04_R6_CANARY_RUNTIME_REJECTION_CLOSEOUT",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_CANARY_EXECUTION_REVIEW",
        },
        "terminal_defects": list(TERMINAL_DEFECTS),
        "reason_codes": list(REASON_CODES),
        "paired_lane_compiler_scaffold": paired_scaffold,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
    }


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _validation_receipt(base: Dict[str, Any], *, role: str, subject: str, source_roles: Sequence[str]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.canary_execution.validation.{role}.v1",
        artifact_id=f"B04_R6_CANARY_EXECUTION_{role.upper()}_RECEIPT",
        validation_role=role,
        validation_status="PASS",
        subject=subject,
        source_roles=list(source_roles),
        validated_hashes={f"{source}_hash": base["binding_hashes"].get(f"{source}_hash") for source in source_roles},
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.canary_execution_validation.{role}.prep_only.v1",
        artifact_id=f"B04_R6_{role.upper()}",
        status="PREP_ONLY",
        authority="PREP_ONLY_NON_AUTHORITY",
        purpose=purpose,
        can_authorize=False,
        canary_runtime_executed=False,
        runtime_cutover_authorized=False,
        r6_open=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
    )


def _pipeline_board(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.pipeline_board.v12",
        artifact_id="B04_R6_PIPELINE_BOARD",
        board_status="CANARY_EXECUTION_PACKET_VALIDATED_CANARY_RUNTIME_NEXT",
        lanes=[
            {"lane": "AUTHOR_B04_R6_CANARY_EXECUTION_PACKET", "status": "BOUND_ON_MAIN", "authoritative": True},
            {"lane": "VALIDATE_B04_R6_CANARY_EXECUTION_PACKET", "status": "CURRENT_VALIDATED", "authoritative": True},
            {"lane": "RUN_B04_R6_LIMITED_RUNTIME_CANARY", "status": "NEXT", "authoritative": True},
            {"lane": "AUTHOR_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET", "status": "PREP_ONLY", "authoritative": False},
            {"lane": "AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET", "status": "BLOCKED", "authoritative": False},
            {"lane": "AUTHOR_B04_R6_EXTERNAL_AUDIT_DELTA_PACKET", "status": "PREP_ONLY", "authoritative": False},
        ],
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    blockers = [
        "CANARY_RUNTIME_NOT_EXECUTED",
        "CANARY_EVIDENCE_REVIEW_NOT_AUTHORED",
        "CANARY_EVIDENCE_REVIEW_NOT_VALIDATED",
        "RUNTIME_CUTOVER_REVIEW_NOT_AUTHORED",
        "PACKAGE_PROMOTION_REQUIRES_CANARY_EVIDENCE_EXTERNAL_AUDIT_AND_PROMOTION_REVIEW",
        "COMMERCIAL_ACTIVATION_CLAIMS_UNAUTHORIZED",
    ]
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v20",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        blockers=[{"blocker_id": blocker, "status": "OPEN"} for blocker in blockers],
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    output_payloads: Dict[str, Any] = {
        "validation_contract": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_execution_packet_validation_contract.v1",
            artifact_id="B04_R6_CANARY_EXECUTION_PACKET_VALIDATION_CONTRACT",
            validation_summary="Canary execution packet is complete, hash-bound, replay-safe, and non-cutover.",
            validated_conditions=[
                "canary_execution_packet_bound",
                "canary_authorization_validation_bound",
                "execution_mode_limited_operator_observed",
                "scope_sample_fallback_operator_kill_switch_rollback_bound",
                "runtime_receipts_replay_expected_artifacts_defined",
                "commercial_claim_boundary_preserved",
                "package_promotion_not_automatic",
            ],
        ),
        "validation_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_execution_packet_validation_receipt.v1",
            artifact_id="B04_R6_CANARY_EXECUTION_PACKET_VALIDATION_RECEIPT",
            verdict="CANARY_EXECUTION_PACKET_VALIDATED_CANARY_RUNTIME_NEXT",
            canary_execution_packet_validated=True,
            canary_runtime_next_lawful_lane=True,
        ),
        "no_authorization_drift_validation": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_execution.no_authorization_drift_validation_receipt.v1",
            artifact_id="B04_R6_CANARY_EXECUTION_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            no_authorization_drift=True,
            canary_runtime_executed=False,
            runtime_cutover_authorized=False,
            r6_open=False,
            package_promotion_authorized=False,
            commercial_activation_claim_authorized=False,
        ),
        "paired_lane_compiler_scaffold_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_execution_validation.paired_lane_compiler_scaffold_receipt.v1",
            artifact_id="B04_R6_CANARY_EXECUTION_VALIDATION_PAIRED_LANE_COMPILER_SCAFFOLD_RECEIPT",
            scaffold=base["paired_lane_compiler_scaffold"],
            scaffold_authority="PREP_ONLY_TOOLING",
            scaffold_can_authorize=False,
        ),
        "pipeline_board": _pipeline_board(base),
        "future_blocker_register": _future_blocker_register(base),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v28",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            verdict="NEXT_LAWFUL_MOVE_SET",
        ),
    }
    receipt_specs = {
        "packet_binding_validation": ("packet_contract", "Canary execution packet"),
        "authorization_validation_binding": ("authorization_validation_binding", "Canary authorization validation"),
        "authorization_packet_binding": ("authorization_packet_binding", "Canary authorization packet"),
        "source_hashes_validation": ("packet_contract", "Execution packet source hashes"),
        "mode_validation": ("mode_contract", "Execution mode"),
        "scope_validation": ("scope_manifest", "Execution scope"),
        "allowed_case_class_validation": ("allowed_case_class_contract", "Allowed case classes"),
        "excluded_case_class_validation": ("excluded_case_class_contract", "Excluded case classes"),
        "sample_limit_validation": ("sample_limit_contract", "Sample limits"),
        "static_fallback_validation": ("static_fallback_contract", "Static fallback"),
        "abstention_fallback_validation": ("abstention_fallback_contract", "Abstention fallback"),
        "null_route_preservation_validation": ("null_route_preservation_contract", "Null-route preservation"),
        "operator_override_validation": ("operator_override_contract", "Operator override"),
        "kill_switch_validation": ("kill_switch_contract", "Kill switch"),
        "rollback_validation": ("rollback_contract", "Rollback"),
        "route_distribution_health_validation": ("route_distribution_health_thresholds", "Route distribution thresholds"),
        "drift_threshold_validation": ("drift_thresholds", "Drift thresholds"),
        "incident_freeze_validation": ("incident_freeze_contract", "Incident freeze"),
        "runtime_receipt_schema_validation": ("runtime_receipt_schema", "Runtime receipt schema"),
        "replay_manifest_validation": ("replay_manifest", "Replay manifest"),
        "expected_artifact_manifest_validation": ("expected_artifact_manifest", "Expected artifact manifest"),
        "external_verifier_validation": ("external_verifier_requirements", "External verifier requirements"),
        "result_interpretation_validation": ("result_interpretation_contract", "Result interpretation"),
        "pipeline_board_validation": ("pipeline_board", "Pipeline board"),
    }
    for role, (source_role, subject) in receipt_specs.items():
        if source_role == "authorization_validation_binding":
            source_roles = ("packet_contract",)
        elif source_role == "authorization_packet_binding":
            source_roles = ("packet_contract",)
        else:
            source_roles = (source_role,)
        output_payloads[role] = _validation_receipt(base, role=role, subject=subject, source_roles=source_roles)
    output_payloads.update(
        {
            role: _prep_only(base, role=role, purpose=f"Prep-only continuation scaffold for {role.replace('_', ' ')}.")
            for role in PREP_ONLY_OUTPUT_ROLES
        }
    )
    return output_payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Canary Execution Packet Validation",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "The canary execution packet validates as complete, evidence-bound, replay-safe, limited, "
            "operator-observed, fallback-protected, rollback-defined, receipt-heavy, and commercially bounded.",
            "",
            "This validation makes canary runtime the next lawful lane, but does not execute canary, does not "
            "authorize runtime cutover, does not open R6, does not promote package, and does not authorize "
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
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root):
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 canary execution validation")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if current_branch != "main" else "HEAD")
    handoff_git_commit = current_main_head if current_branch != "main" else head
    output_names = set(OUTPUTS.values())
    payloads = {
        role: _load_input(root, raw, label=role, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in EXECUTION_JSON_INPUTS.items()
    }
    texts = {
        role: _read_text_input(root, raw, label=role, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in EXECUTION_TEXT_INPUTS.items()
    }
    _validate_authoring_payloads(root, payloads, texts)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_CANARY_EXEC_VAL_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    paired_scaffold = _paired_compiler_scaffold(current_main_head)
    if paired_scaffold.get("authority") != "PREP_ONLY_TOOLING" or paired_scaffold.get("paired_lane_law", {}).get("compiler_can_authorize") is not False:
        _fail("RC_B04R6_CANARY_EXEC_VAL_COMPILER_SCAFFOLD_MISSING", "paired compiler scaffold authority drift")

    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=_input_bindings(root, handoff_git_commit=handoff_git_commit),
        binding_hashes=_binding_hashes(root, handoff_git_commit=handoff_git_commit),
        validation_rows=_validation_rows(),
        paired_scaffold=paired_scaffold,
        trust_zone_validation=fresh_trust_validation,
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
    parser = argparse.ArgumentParser(description="Validate B04 R6 canary execution packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
