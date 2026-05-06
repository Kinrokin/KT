from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_runtime_evidence_review_packet as review
from tools.operator import cohort0_b04_r6_runtime_evidence_review_packet_validation as evidence_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_lane_compiler
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-canary-authorization-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_CANARY_AUTHORIZATION_PACKET"
PREVIOUS_LANE = evidence_validation.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = evidence_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = evidence_validation.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = "B04_R6_CANARY_AUTHORIZATION_PACKET_BOUND__CANARY_AUTHORIZATION_VALIDATION_NEXT"
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_CANARY_AUTHORIZATION_PACKET"

MAY_AUTHORIZE = ("CANARY_AUTHORIZATION_PACKET_AUTHORED",)
FORBIDDEN_ACTIONS = (
    "CANARY_RUNTIME_EXECUTED",
    "CANARY_RUNTIME_AUTHORIZED",
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
    "RUNTIME_EVIDENCE_REVIEW_VALIDATION_MISSING",
    "RUNTIME_EVIDENCE_INVENTORY_MISSING",
    "RUNTIME_EVIDENCE_SCORECARD_MISSING",
    "SHADOW_RUNTIME_RESULT_UNBOUND",
    "STATIC_AUTHORITY_EVIDENCE_MISSING",
    "OPERATOR_CONTROL_EVIDENCE_MISSING",
    "KILL_SWITCH_EVIDENCE_MISSING",
    "ROLLBACK_EVIDENCE_MISSING",
    "CANARY_SCOPE_MISSING",
    "CANARY_SAMPLE_LIMIT_MISSING",
    "CANARY_RUNTIME_AUTHORIZED",
    "CANARY_RUNTIME_EXECUTED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "R6_OPEN_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL_CLAIM_DRIFT",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "NEXT_MOVE_DRIFT",
)
REASON_CODES = (
    "RC_B04R6_CANARY_AUTH_PACKET_CONTRACT_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_MAIN_HEAD_MISMATCH",
    "RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_VALIDATION_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_INVENTORY_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_SCORECARD_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_SHADOW_RUNTIME_RESULT_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_STATIC_AUTHORITY_EVIDENCE_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_AFSH_OBSERVATION_EVIDENCE_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_ROUTE_HEALTH_EVIDENCE_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_FALLBACK_EVIDENCE_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_ABSTENTION_EVIDENCE_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_NULL_ROUTE_EVIDENCE_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_OPERATOR_OVERRIDE_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_KILL_SWITCH_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_ROLLBACK_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_DRIFT_EVIDENCE_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_INCIDENT_FREEZE_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_TRACE_COMPLETENESS_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_REPLAY_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_COMMERCIAL_BOUNDARY_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_PACKAGE_PROMOTION_BLOCKER_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_SCOPE_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_ALLOWED_CASE_CLASSES_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_EXCLUDED_CASE_CLASSES_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_SAMPLE_LIMIT_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_CANARY_AUTH_PACKET_CANARY_AUTHORIZED",
    "RC_B04R6_CANARY_AUTH_PACKET_CANARY_EXECUTED",
    "RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_CANARY_AUTH_PACKET_R6_OPEN_DRIFT",
    "RC_B04R6_CANARY_AUTH_PACKET_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_CANARY_AUTH_PACKET_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_CANARY_AUTH_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_CANARY_AUTH_PACKET_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_CANARY_AUTH_PACKET_TRUST_ZONE_MUTATION",
    "RC_B04R6_CANARY_AUTH_PACKET_COMPILER_SCAFFOLD_MISSING",
    "RC_B04R6_CANARY_AUTH_PACKET_NEXT_MOVE_DRIFT",
)

VALIDATION_JSON_INPUTS = {
    "runtime_evidence_validation_contract": f"KT_PROD_CLEANROOM/reports/{evidence_validation.OUTPUTS['validation_contract']}",
    "runtime_evidence_validation_receipt": f"KT_PROD_CLEANROOM/reports/{evidence_validation.OUTPUTS['validation_receipt']}",
    "runtime_evidence_validation_no_authorization_drift": f"KT_PROD_CLEANROOM/reports/{evidence_validation.OUTPUTS['no_authorization_drift_validation']}",
    "runtime_evidence_validation_next_lawful_move": f"KT_PROD_CLEANROOM/reports/{evidence_validation.OUTPUTS['next_lawful_move']}",
}
REVIEW_EVIDENCE_JSON_INPUTS = {
    "runtime_evidence_inventory": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['evidence_inventory']}",
    "runtime_evidence_scorecard": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['evidence_scorecard']}",
    "runtime_static_authority_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['static_authority_review']}",
    "runtime_afsh_observation_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['afsh_observation_review']}",
    "runtime_route_distribution_health_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['route_distribution_health_review']}",
    "runtime_fallback_behavior_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['fallback_behavior_review']}",
    "runtime_abstention_preservation_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['abstention_preservation_review']}",
    "runtime_null_route_preservation_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['null_route_preservation_review']}",
    "runtime_operator_control_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['operator_control_review']}",
    "runtime_kill_switch_readiness_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['kill_switch_readiness_review']}",
    "runtime_rollback_readiness_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['rollback_readiness_review']}",
    "runtime_drift_monitoring_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['drift_monitoring_review']}",
    "runtime_incident_freeze_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['incident_freeze_review']}",
    "runtime_trace_completeness_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['trace_completeness_review']}",
    "runtime_replay_readiness_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['replay_readiness_review']}",
    "runtime_external_verifier_readiness_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['external_verifier_readiness_review']}",
    "runtime_commercial_claim_boundary_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['commercial_claim_boundary_review']}",
    "runtime_package_promotion_blocker_review": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['package_promotion_blocker_review']}",
    "runtime_canary_readiness_matrix": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['canary_readiness_matrix']}",
    "runtime_pipeline_board": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['pipeline_board']}",
}
TEXT_INPUTS = {
    "runtime_evidence_validation_report": f"KT_PROD_CLEANROOM/reports/{evidence_validation.OUTPUTS['validation_report']}",
    "runtime_evidence_review_report": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['review_report']}",
}
ALL_JSON_INPUTS = {**VALIDATION_JSON_INPUTS, **REVIEW_EVIDENCE_JSON_INPUTS}

OUTPUTS = {
    "packet_contract": "b04_r6_canary_authorization_packet_contract.json",
    "packet_receipt": "b04_r6_canary_authorization_packet_receipt.json",
    "packet_report": "b04_r6_canary_authorization_packet_report.md",
    "scope_manifest": "b04_r6_canary_scope_manifest.json",
    "allowed_case_class_contract": "b04_r6_canary_allowed_case_class_contract.json",
    "excluded_case_class_contract": "b04_r6_canary_excluded_case_class_contract.json",
    "sample_limit_contract": "b04_r6_canary_sample_limit_contract.json",
    "static_fallback_contract": "b04_r6_canary_static_fallback_contract.json",
    "abstention_fallback_contract": "b04_r6_canary_abstention_fallback_contract.json",
    "null_route_preservation_contract": "b04_r6_canary_null_route_preservation_contract.json",
    "operator_override_contract": "b04_r6_canary_operator_override_contract.json",
    "kill_switch_contract": "b04_r6_canary_kill_switch_contract.json",
    "rollback_contract": "b04_r6_canary_rollback_contract.json",
    "route_distribution_health_thresholds": "b04_r6_canary_route_distribution_health_thresholds.json",
    "drift_thresholds": "b04_r6_canary_drift_thresholds.json",
    "incident_freeze_contract": "b04_r6_canary_incident_freeze_contract.json",
    "runtime_receipt_schema": "b04_r6_canary_runtime_receipt_schema.json",
    "external_verifier_requirements": "b04_r6_canary_external_verifier_requirements.json",
    "commercial_claim_boundary": "b04_r6_canary_commercial_claim_boundary.json",
    "package_promotion_prohibition_receipt": "b04_r6_canary_package_promotion_prohibition_receipt.json",
    "no_authorization_drift_receipt": "b04_r6_canary_no_authorization_drift_receipt.json",
    "validation_plan": "b04_r6_canary_authorization_validation_plan.json",
    "validation_reason_codes": "b04_r6_canary_authorization_validation_reason_codes.json",
    "lane_compiler_scaffold_receipt": "b04_r6_canary_authorization_lane_compiler_scaffold_receipt.json",
    "canary_execution_packet_prep_only_draft": "b04_r6_canary_execution_packet_prep_only_draft.json",
    "canary_execution_validation_plan_prep_only": "b04_r6_canary_execution_validation_plan_prep_only.json",
    "canary_result_schema_prep_only": "b04_r6_canary_result_schema_prep_only.json",
    "canary_failure_closeout_prep_only_draft": "b04_r6_canary_failure_closeout_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only": "b04_r6_external_audit_delta_manifest_prep_only.json",
    "package_promotion_review_preconditions_prep_only_draft": "b04_r6_package_promotion_review_preconditions_prep_only_draft.json",
    "public_verifier_delta_requirements_prep_only": "b04_r6_public_verifier_delta_requirements_prep_only.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}
PREP_ONLY_OUTPUT_ROLES = (
    "canary_execution_packet_prep_only_draft",
    "canary_execution_validation_plan_prep_only",
    "canary_result_schema_prep_only",
    "canary_failure_closeout_prep_only_draft",
    "external_audit_delta_manifest_prep_only",
    "package_promotion_review_preconditions_prep_only_draft",
    "public_verifier_delta_requirements_prep_only",
)
CANARY_CONTRACT_ROLES = (
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
    "external_verifier_requirements",
    "commercial_claim_boundary",
    "package_promotion_prohibition_receipt",
)
REQUIRED_SOURCE_EVIDENCE_HASHES = (
    "validated_runtime_evidence_review_receipt_hash",
    "runtime_evidence_inventory_hash",
    "runtime_evidence_scorecard_hash",
    "shadow_runtime_result_hash",
    "static_authority_preservation_evidence_hash",
    "afsh_observation_evidence_hash",
    "route_distribution_health_evidence_hash",
    "fallback_behavior_evidence_hash",
    "abstention_preservation_evidence_hash",
    "null_route_preservation_evidence_hash",
    "operator_override_readiness_evidence_hash",
    "kill_switch_readiness_evidence_hash",
    "rollback_readiness_evidence_hash",
    "drift_monitoring_evidence_hash",
    "incident_freeze_evidence_hash",
    "trace_completeness_evidence_hash",
    "runtime_replay_evidence_hash",
    "external_verifier_readiness_evidence_hash",
    "commercial_claim_boundary_hash",
    "package_promotion_blocker_review_hash",
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
            _fail("RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_VALIDATION_MISSING", f"git-bound input {label} missing at {handoff_git_commit}: {exc}")
    return _load(root, raw, label=label)


def _read_text_input(root: Path, raw: str, *, label: str, handoff_git_commit: str, output_names: set[str]) -> str:
    if Path(raw).name in output_names:
        try:
            return _git_blob_bytes(root, handoff_git_commit, raw).decode("utf-8")
        except Exception as exc:
            _fail("RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_VALIDATION_MISSING", f"git-bound text input {label} missing at {handoff_git_commit}: {exc}")
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
        "canary_runtime_authorized": "RC_B04R6_CANARY_AUTH_PACKET_CANARY_AUTHORIZED",
        "canary_runtime_executed": "RC_B04R6_CANARY_AUTH_PACKET_CANARY_EXECUTED",
        "runtime_cutover_authorized": "RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
        "activation_cutover_executed": "RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
        "r6_open": "RC_B04R6_CANARY_AUTH_PACKET_R6_OPEN_DRIFT",
        "lobe_escalation_authorized": "RC_B04R6_CANARY_AUTH_PACKET_LOBE_ESCALATION_DRIFT",
        "package_promotion_authorized": "RC_B04R6_CANARY_AUTH_PACKET_PACKAGE_PROMOTION_DRIFT",
        "commercial_activation_claim_authorized": "RC_B04R6_CANARY_AUTH_PACKET_COMMERCIAL_CLAIM_DRIFT",
        "truth_engine_law_changed": "RC_B04R6_CANARY_AUTH_PACKET_TRUTH_ENGINE_MUTATION",
        "trust_zone_law_changed": "RC_B04R6_CANARY_AUTH_PACKET_TRUST_ZONE_MUTATION",
        "metric_contract_mutated": "RC_B04R6_CANARY_AUTH_PACKET_PREP_ONLY_AUTHORITY_DRIFT",
        "static_comparator_weakened": "RC_B04R6_CANARY_AUTH_PACKET_PREP_ONLY_AUTHORITY_DRIFT",
    }
    for key, value in _walk_items(payload):
        if key in forbidden_truths and value is True:
            _fail(forbidden_truths[key], f"{label}.{key} drifted true")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_CANARY_AUTH_PACKET_PACKAGE_PROMOTION_DRIFT", f"{label}.package_promotion drifted")


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
            "binding_kind": "file_sha256_at_canary_authorization_packet_authoring",
        }
        if is_overwritten:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(TEXT_INPUTS.items()):
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": "file_sha256_at_canary_authorization_packet_authoring",
            }
        )
    return rows


def _binding_hashes(root: Path, *, handoff_git_commit: str) -> Dict[str, str]:
    output_names = set(OUTPUTS.values())
    hashes = {
        f"{role}_hash": _input_hash(root, raw, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in sorted(ALL_JSON_INPUTS.items())
    }
    hashes.update({f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(TEXT_INPUTS.items())})
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


def _inventory_hash(inventory: Dict[str, Any], role: str, code: str) -> str:
    for artifact in inventory.get("artifacts", []):
        if artifact.get("role") == role and _is_sha256(artifact.get("sha256")):
            return str(artifact["sha256"])
    _fail(code, f"runtime evidence inventory missing {role}")
    raise AssertionError("unreachable")


def _source_evidence_hashes(payloads: Dict[str, Dict[str, Any]], binding_hashes: Dict[str, str]) -> Dict[str, str]:
    inventory = payloads["runtime_evidence_inventory"]
    binding = payloads["runtime_evidence_validation_contract"].get("binding_hashes", {})
    source_hashes = {
        "validated_runtime_evidence_review_receipt_hash": binding_hashes.get("runtime_evidence_validation_receipt_hash"),
        "runtime_evidence_inventory_hash": binding_hashes.get("runtime_evidence_inventory_hash"),
        "runtime_evidence_scorecard_hash": binding_hashes.get("runtime_evidence_scorecard_hash"),
        "shadow_runtime_result_hash": _inventory_hash(inventory, "shadow_result", "RC_B04R6_CANARY_AUTH_PACKET_SHADOW_RUNTIME_RESULT_MISSING"),
        "static_authority_preservation_evidence_hash": binding.get("static_authority_review_hash"),
        "afsh_observation_evidence_hash": binding.get("afsh_observation_review_hash"),
        "route_distribution_health_evidence_hash": binding.get("route_distribution_health_review_hash"),
        "fallback_behavior_evidence_hash": binding.get("fallback_behavior_review_hash"),
        "abstention_preservation_evidence_hash": binding.get("abstention_preservation_review_hash"),
        "null_route_preservation_evidence_hash": binding.get("null_route_preservation_review_hash"),
        "operator_override_readiness_evidence_hash": binding.get("operator_control_review_hash"),
        "kill_switch_readiness_evidence_hash": binding.get("kill_switch_readiness_review_hash"),
        "rollback_readiness_evidence_hash": binding.get("rollback_readiness_review_hash"),
        "drift_monitoring_evidence_hash": binding.get("drift_monitoring_review_hash"),
        "incident_freeze_evidence_hash": binding.get("incident_freeze_review_hash"),
        "trace_completeness_evidence_hash": binding.get("trace_completeness_review_hash"),
        "runtime_replay_evidence_hash": binding.get("replay_readiness_review_hash"),
        "external_verifier_readiness_evidence_hash": binding.get("external_verifier_readiness_review_hash"),
        "commercial_claim_boundary_hash": binding.get("commercial_claim_boundary_review_hash"),
        "package_promotion_blocker_review_hash": binding.get("package_promotion_blocker_review_hash"),
    }
    for key in REQUIRED_SOURCE_EVIDENCE_HASHES:
        if not _is_sha256(source_hashes.get(key)):
            _fail("RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_VALIDATION_MISSING", f"{key} missing")
    return {key: str(source_hashes[key]) for key in REQUIRED_SOURCE_EVIDENCE_HASHES}


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str], binding_hashes: Dict[str, str]) -> Dict[str, str]:
    for label, payload in payloads.items():
        _ensure_authority_closed(payload, label=label)

    validation_contract = payloads["runtime_evidence_validation_contract"]
    validation_receipt = payloads["runtime_evidence_validation_receipt"]
    next_move = payloads["runtime_evidence_validation_next_lawful_move"]
    scorecard = payloads["runtime_evidence_scorecard"].get("scorecard", {})
    matrix = payloads["runtime_canary_readiness_matrix"]

    for role, payload in (("validation_contract", validation_contract), ("validation_receipt", validation_receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_VALIDATION_MISSING", f"{role} lane identity drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_VALIDATION_MISSING", f"{role} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_CANARY_AUTH_PACKET_NEXT_MOVE_DRIFT", f"{role} next move drift")
        if payload.get("runtime_evidence_review_validated") is not True:
            _fail("RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_VALIDATION_MISSING", f"{role} not validated")
    if not _valid_handoff(next_move):
        _fail("RC_B04R6_CANARY_AUTH_PACKET_NEXT_MOVE_DRIFT", "next move handoff lacks valid lane identity")
    if payloads["runtime_evidence_inventory"].get("raw_hash_bound_artifacts_required") is not True:
        _fail("RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_INVENTORY_MISSING", "inventory does not require raw hash-bound artifacts")
    if payloads["runtime_evidence_inventory"].get("compressed_index_source_of_truth") is not False:
        _fail("RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_INVENTORY_MISSING", "compressed index became source of truth")

    required_score = {
        "runtime_mode": review.RUNTIME_MODE,
        "shadow_runtime_passed": True,
        "evidence_review_status": "PASS",
        "canary_readiness_status": "PREP_READY_NOT_AUTHORIZED",
        "user_facing_decision_changes": 0,
        "canary_runtime_cases": 0,
        "runtime_cutover_authorized_cases": 0,
        "fallback_failures": 0,
        "drift_signals": [],
        "incident_freeze_triggers": [],
        "fired_disqualifiers": [],
    }
    for key, expected in required_score.items():
        if scorecard.get(key) != expected:
            _fail("RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_SCORECARD_MISSING", f"scorecard {key} drifted")
    if scorecard.get("static_authoritative_cases") != scorecard.get("total_cases"):
        _fail("RC_B04R6_CANARY_AUTH_PACKET_STATIC_AUTHORITY_EVIDENCE_MISSING", "static authority was not universal")
    if scorecard.get("trace_complete_cases") != scorecard.get("total_cases"):
        _fail("RC_B04R6_CANARY_AUTH_PACKET_TRACE_COMPLETENESS_MISSING", "trace completeness was not universal")

    statuses = {row.get("readiness_item"): row.get("status") for row in matrix.get("rows", [])}
    if matrix.get("readiness_status") != "PREP_READY_NOT_AUTHORIZED" or matrix.get("canary_runtime_authorized") is not False:
        _fail("RC_B04R6_CANARY_AUTH_PACKET_SCOPE_MISSING", "canary readiness matrix authority drift")
    for key in ("shadow_runtime_passed", "static_authority_preserved", "no_user_facing_change", "operator_controls_ready"):
        if statuses.get(key) != "PASS":
            _fail("RC_B04R6_CANARY_AUTH_PACKET_SCOPE_MISSING", f"canary readiness matrix missing {key}")

    for phrase in ("does not authorize canary runtime", "runtime evidence review packet is validated"):
        if phrase not in texts["runtime_evidence_validation_report"].lower():
            _fail("RC_B04R6_CANARY_AUTH_PACKET_RUNTIME_EVIDENCE_VALIDATION_MISSING", f"validation report missing {phrase}")

    return _source_evidence_hashes(payloads, binding_hashes)


def _compiler_scaffold(current_main_head: str) -> Dict[str, Any]:
    spec = {
        "lane_id": "AUTHOR_B04_R6_CANARY_AUTHORIZATION_PACKET",
        "lane_name": "B04 R6 canary authorization packet",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM",
        "summary": "Prep-only compiler scaffold for authoring the canary authorization packet.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/cohort0_b04_r6_canary_authorization_packet.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_b04_r6_canary_authorization_packet.py",
        "artifacts": sorted(OUTPUTS.values()),
        "json_parse_inputs": sorted(filename for filename in OUTPUTS.values() if filename.endswith(".json")),
        "no_authorization_drift_checks": [
            "Canary authorization packet does not execute canary runtime.",
            "Canary authorization packet does not authorize runtime cutover, R6 open, package promotion, or commercial claims.",
            "Truth-engine and trust-zone law remain unchanged.",
        ],
        "future_blockers": [
            "Canary authorization packet must validate before canary execution packet authorship.",
            "Canary execution remains blocked until canary authorization validation, execution packet authoring, and execution packet validation.",
            "Package promotion remains blocked until canary evidence, external audit, and package promotion review pass.",
        ],
        "reason_codes": list(REASON_CODES),
        "lane_kind": "AUTHORING",
        "current_main_head": current_main_head,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "may_authorize": list(MAY_AUTHORIZE),
        "must_not_authorize": list(FORBIDDEN_ACTIONS),
        "authoritative_inputs": sorted(ALL_JSON_INPUTS),
        "prep_only_outputs": sorted(PREP_ONLY_OUTPUT_ROLES),
    }
    contract = kt_lane_compiler.build_lane_contract(spec)
    rendered = json.dumps(contract, sort_keys=True, ensure_ascii=True)
    return {
        "compiler_id": kt_lane_compiler.COMPILER_ID,
        "authority": kt_lane_compiler.AUTHORITY,
        "status": "PREP_ONLY_TOOLING_USED_AS_SCAFFOLD",
        "contract_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "generated_artifacts": contract["generated_artifacts"],
        "non_authorization_guards": contract["non_authorization_guards"],
    }


def _validation_rows() -> list[Dict[str, Any]]:
    checks = [
        "runtime_evidence_review_validation_bound",
        "runtime_evidence_inventory_bound",
        "runtime_evidence_scorecard_bound",
        "shadow_runtime_result_bound",
        "static_authority_evidence_bound",
        "afsh_observation_evidence_bound",
        "route_distribution_health_evidence_bound",
        "fallback_behavior_evidence_bound",
        "abstention_preservation_evidence_bound",
        "null_route_preservation_evidence_bound",
        "operator_override_readiness_bound",
        "kill_switch_readiness_bound",
        "rollback_readiness_bound",
        "drift_monitoring_evidence_bound",
        "incident_freeze_evidence_bound",
        "trace_completeness_evidence_bound",
        "runtime_replay_evidence_bound",
        "external_verifier_readiness_bound",
        "commercial_claim_boundary_bound",
        "package_promotion_blocker_bound",
        "canary_scope_defined",
        "allowed_case_classes_defined",
        "excluded_case_classes_defined",
        "sample_limits_defined",
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
        "external_verifier_requirements_defined",
        "commercial_claim_boundary_defined",
        "package_promotion_prohibited",
        "canary_not_executed",
        "canary_runtime_not_authorized",
        "runtime_cutover_not_authorized",
        "r6_remains_closed",
        "lobe_escalation_unauthorized",
        "package_promotion_blocked",
        "commercial_claims_blocked",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
        "next_lawful_move_canary_authorization_validation",
    ]
    return [
        {
            "check_id": f"B04R6-CANARY-AUTH-PACKET-{index:03d}",
            "name": check,
            "status": "PASS",
            "terminal_if_fail": check
            in {
                "runtime_evidence_review_validation_bound",
                "shadow_runtime_result_bound",
                "static_authority_evidence_bound",
                "canary_scope_defined",
                "sample_limits_defined",
                "canary_not_executed",
                "canary_runtime_not_authorized",
                "runtime_cutover_not_authorized",
                "r6_remains_closed",
                "truth_engine_law_unchanged",
                "trust_zone_law_unchanged",
                "next_lawful_move_canary_authorization_validation",
            },
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
    source_evidence_hashes: Dict[str, str],
    validation_rows: list[Dict[str, Any]],
    compiler_scaffold: Dict[str, Any],
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
        "runtime_mode_precondition": review.RUNTIME_MODE,
        "shadow_runtime_passed": True,
        "runtime_evidence_review_validated": True,
        "canary_authorization_packet_authored": True,
        "canary_authorization_packet_validated": False,
        "canary_execution_packet_authored": False,
        "canary_execution_packet_validated": False,
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
        "source_evidence_hashes": source_evidence_hashes,
        "validation_rows": validation_rows,
        "may_authorize": list(MAY_AUTHORIZE),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "allowed_outcomes": [
            SELECTED_OUTCOME,
            "B04_R6_CANARY_AUTHORIZATION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS",
            "B04_R6_CANARY_AUTHORIZATION_PACKET_REJECTED__CANARY_NOT_JUSTIFIED",
            "B04_R6_CANARY_AUTHORIZATION_PACKET_INVALID__FORENSIC_CANARY_AUTHORIZATION_REVIEW_NEXT",
        ],
        "outcome_routing": {
            SELECTED_OUTCOME: NEXT_LAWFUL_MOVE,
            "B04_R6_CANARY_AUTHORIZATION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS": "REPAIR_B04_R6_CANARY_AUTHORIZATION_PACKET_DEFECTS",
            "B04_R6_CANARY_AUTHORIZATION_PACKET_REJECTED__CANARY_NOT_JUSTIFIED": "AUTHOR_B04_R6_CANARY_REJECTION_CLOSEOUT",
            "B04_R6_CANARY_AUTHORIZATION_PACKET_INVALID__FORENSIC_CANARY_AUTHORIZATION_REVIEW_NEXT": "AUTHOR_B04_R6_FORENSIC_CANARY_AUTHORIZATION_REVIEW",
        },
        "terminal_defects": list(TERMINAL_DEFECTS),
        "reason_codes": list(REASON_CODES),
        "lane_compiler_scaffold": compiler_scaffold,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
    }


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _scope_manifest() -> Dict[str, Any]:
    return {
        "scope_status": "LIMITED_CANARY_SCOPE_DEFINED_NOT_AUTHORIZED",
        "canary_execution_requires_future_packet_validation": True,
        "global_r6_scope_allowed": False,
        "runtime_cutover_allowed": False,
        "max_case_count_per_window": 12,
        "window": "one validation-bound canary window",
        "operator_observed_required": True,
        "static_fallback_required": True,
    }


def _allowed_case_classes() -> list[Dict[str, Any]]:
    return [
        {
            "case_class": "ROUTE_ELIGIBLE_LOW_RISK_SHADOW_CONFIRMED",
            "conditions": [
                "prior shadow-runtime trace complete",
                "static fallback available",
                "operator observes execution",
                "no commercial claim surface",
            ],
        },
        {
            "case_class": "STATIC_FALLBACK_AVAILABLE_ROUTE_CHECK",
            "conditions": ["static remains reversible fallback", "kill switch reachable", "rollback receipt can be emitted"],
        },
        {
            "case_class": "NON_COMMERCIAL_OPERATOR_OBSERVED_SAMPLE",
            "conditions": ["sample limit applies", "external verifier receipt emitted", "incident freeze active"],
        },
    ]


def _excluded_case_classes() -> list[Dict[str, Any]]:
    return [
        {"case_class": "GLOBAL_R6_TRAFFIC", "reason": "R6 remains closed."},
        {"case_class": "NO_STATIC_FALLBACK_AVAILABLE", "reason": "Canary requires static fallback."},
        {"case_class": "ABSTENTION_REQUIRED_OR_HUMAN_REVIEW", "reason": "Abstention fallback must preserve review boundary."},
        {"case_class": "NULL_ROUTE_CONTROL", "reason": "Null-route preservation must not be converted into canary routing."},
        {"case_class": "COMMERCIAL_ACTIVATION_SURFACE", "reason": "Commercial activation claims remain unauthorized."},
    ]


def _thresholds() -> Dict[str, Any]:
    return {
        "route_distribution_health": {
            "max_selector_entry_rate_delta_vs_shadow": 0.05,
            "zero_null_route_selector_entries_required": True,
            "zero_abstention_override_required": True,
            "freeze_on_unexplained_distribution_shift": True,
        },
        "drift": {
            "max_unexplained_trace_delta": 0,
            "mirror_masked_instability_allowed": False,
            "metric_widening_allowed": False,
            "comparator_weakening_allowed": False,
        },
    }


def _contract_payload(base: Dict[str, Any], role: str, *, schema_slug: str, artifact_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.canary_authorization.{schema_slug}.v1",
        artifact_id=artifact_id,
        contract_role=role,
        contract_status="BOUND_NON_EXECUTING",
        canary_runtime_authorized=False,
        canary_runtime_executed=False,
        runtime_cutover_authorized=False,
        r6_open=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
        details=details,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.canary_authorization.{role}.prep_only.v1",
        artifact_id=f"B04_R6_{role.upper()}",
        status="PREP_ONLY",
        authority="PREP_ONLY_NON_AUTHORITY",
        purpose=purpose,
        canary_runtime_authorized=False,
        canary_runtime_executed=False,
        runtime_cutover_authorized=False,
        r6_open=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    blockers = [
        ("B04R6-FB-091", "Canary authorization packet must validate before canary execution packet authorship.", "VALIDATE_B04_R6_CANARY_AUTHORIZATION_PACKET"),
        ("B04R6-FB-092", "Canary runtime remains blocked until canary execution packet authoring and validation.", "RUN_B04_R6_LIMITED_RUNTIME_CANARY"),
        ("B04R6-FB-093", "Runtime cutover remains blocked until future canary evidence review and cutover law.", "AUTHOR_B04_R6_RUNTIME_CUTOVER_REVIEW_PACKET"),
        ("B04R6-FB-094", "Package promotion remains blocked until future canary evidence, external audit, and package review.", "VALIDATE_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET"),
        ("B04R6-FB-095", "Commercial activation claims remain blocked until a future commercial-claim authority lane exists.", "AUTHOR_B04_R6_COMMERCIAL_CLAIM_REVIEW_PACKET"),
    ]
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v25",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        current_authoritative_lane=AUTHORITATIVE_LANE,
        blockers=[
            {"blocker_id": blocker_id, "status": "OPEN", "description": description, "blocked_until": blocked_until}
            for blocker_id, description, blocked_until in blockers
        ],
    )


def _pipeline_board(base: Dict[str, Any]) -> Dict[str, Any]:
    lanes = [
        ("VALIDATE_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET", "VALIDATED", False, EXPECTED_PREVIOUS_OUTCOME, AUTHORITATIVE_LANE),
        ("AUTHOR_B04_R6_CANARY_AUTHORIZATION_PACKET", "CURRENT_BOUND", True, SELECTED_OUTCOME, NEXT_LAWFUL_MOVE),
        ("VALIDATE_B04_R6_CANARY_AUTHORIZATION_PACKET", "NEXT", True, "B04_R6_CANARY_AUTHORIZATION_PACKET_VALIDATED__CANARY_EXECUTION_PACKET_NEXT", "AUTHOR_B04_R6_CANARY_EXECUTION_PACKET"),
        ("AUTHOR_B04_R6_CANARY_EXECUTION_PACKET", "BLOCKED", False, "NOT_AUTHORIZED", "BLOCKED"),
        ("RUN_B04_R6_LIMITED_RUNTIME_CANARY", "BLOCKED", False, "NOT_AUTHORIZED", "BLOCKED"),
        ("AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET", "BLOCKED", False, "NOT_AUTHORIZED", "BLOCKED"),
    ]
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.pipeline_board.v4",
        artifact_id="B04_R6_PIPELINE_BOARD",
        board_status="CANARY_AUTHORIZATION_PACKET_BOUND_VALIDATION_NEXT",
        lanes=[
            {
                "lane": lane,
                "status": status,
                "authoritative": authoritative,
                "expected_outcome": outcome,
                "next_lane": next_lane,
                "forbidden": list(FORBIDDEN_ACTIONS),
            }
            for lane, status, authoritative, outcome, next_lane in lanes
        ],
    )


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Canary Authorization Packet\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "This packet binds the validated runtime evidence review and defines the limited canary authorization law. "
        "It defines scope, allowed/excluded case classes, sample limits, fallbacks, operator override, kill switch, "
        "rollback, route-distribution thresholds, drift thresholds, incident/freeze conditions, runtime receipts, "
        "external verifier requirements, commercial claim boundaries, and package-promotion prohibition.\n\n"
        "It does not execute canary, does not authorize runtime cutover, does not open R6, does not promote package, "
        "does not authorize commercial activation claims, and does not mutate truth/trust law.\n"
    )


def _outputs(base: Dict[str, Any], compiler_scaffold: Dict[str, Any]) -> Dict[str, Any]:
    scope = _scope_manifest()
    allowed = _allowed_case_classes()
    excluded = _excluded_case_classes()
    thresholds = _thresholds()
    common_runtime_schema = {
        "required_fields": [
            "case_id",
            "canary_mode",
            "static_fallback_available",
            "operator_observed",
            "afsh_verdict",
            "static_verdict",
            "fallback_invoked",
            "kill_switch_ready",
            "rollback_receipt_id",
            "trace_hash",
            "external_verifier_hash",
        ],
        "raw_hash_bound_artifacts_required": True,
        "compressed_index_source_of_truth": False,
    }
    output_payloads: Dict[str, Any] = {
        "packet_contract": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_authorization_packet_contract.v1",
            artifact_id="B04_R6_CANARY_AUTHORIZATION_PACKET_CONTRACT",
            packet_scope={
                "purpose": "Author canary authorization law after validated runtime evidence review.",
                "non_purpose": [
                    "Does not execute canary.",
                    "Does not authorize runtime cutover.",
                    "Does not open R6.",
                    "Does not authorize lobe escalation.",
                    "Does not authorize package promotion.",
                    "Does not authorize commercial activation claims.",
                ],
            },
            source_evidence_requirements={key: True for key in REQUIRED_SOURCE_EVIDENCE_HASHES},
            canary_scope=scope,
            allowed_case_classes=allowed,
            excluded_case_classes=excluded,
            sample_limits={"max_case_count_per_window": scope["max_case_count_per_window"], "requires_future_execution_packet_validation": True},
            success_requirements=[
                "runtime_evidence_review_validation_bound",
                "canary_scope_limited",
                "static_fallback_defined",
                "abstention_fallback_defined",
                "null_route_preservation_defined",
                "operator_override_defined",
                "kill_switch_defined",
                "rollback_defined",
                "runtime_receipt_schema_defined",
                "commercial_claim_boundary_preserved",
                "package_promotion_not_automatic",
            ],
        ),
        "packet_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_authorization_packet_receipt.v1",
            artifact_id="B04_R6_CANARY_AUTHORIZATION_PACKET_RECEIPT",
            verdict="CANARY_AUTHORIZATION_PACKET_BOUND_NON_EXECUTING",
            canary_packet_bound=True,
        ),
        "scope_manifest": _contract_payload(base, "scope_manifest", schema_slug="scope_manifest", artifact_id="B04_R6_CANARY_SCOPE_MANIFEST", details=scope),
        "allowed_case_class_contract": _contract_payload(base, "allowed_case_classes", schema_slug="allowed_case_classes", artifact_id="B04_R6_CANARY_ALLOWED_CASE_CLASS_CONTRACT", details={"allowed_case_classes": allowed}),
        "excluded_case_class_contract": _contract_payload(base, "excluded_case_classes", schema_slug="excluded_case_classes", artifact_id="B04_R6_CANARY_EXCLUDED_CASE_CLASS_CONTRACT", details={"excluded_case_classes": excluded}),
        "sample_limit_contract": _contract_payload(base, "sample_limits", schema_slug="sample_limits", artifact_id="B04_R6_CANARY_SAMPLE_LIMIT_CONTRACT", details={"max_case_count_per_window": 12, "requires_future_execution_packet_validation": True}),
        "static_fallback_contract": _contract_payload(base, "static_fallback", schema_slug="static_fallback", artifact_id="B04_R6_CANARY_STATIC_FALLBACK_CONTRACT", details={"static_fallback_required": True, "static_can_override_afsh": True}),
        "abstention_fallback_contract": _contract_payload(base, "abstention_fallback", schema_slug="abstention_fallback", artifact_id="B04_R6_CANARY_ABSTENTION_FALLBACK_CONTRACT", details={"abstention_fallback_required": True, "human_review_boundary_preserved": True}),
        "null_route_preservation_contract": _contract_payload(base, "null_route_preservation", schema_slug="null_route_preservation", artifact_id="B04_R6_CANARY_NULL_ROUTE_PRESERVATION_CONTRACT", details={"null_route_controls_excluded": True, "zero_null_route_selector_entries_required": True}),
        "operator_override_contract": _contract_payload(base, "operator_override", schema_slug="operator_override", artifact_id="B04_R6_CANARY_OPERATOR_OVERRIDE_CONTRACT", details={"operator_override_required": True, "operator_can_freeze_canary": True}),
        "kill_switch_contract": _contract_payload(base, "kill_switch", schema_slug="kill_switch", artifact_id="B04_R6_CANARY_KILL_SWITCH_CONTRACT", details={"kill_switch_required": True, "kill_switch_must_be_preverified": True}),
        "rollback_contract": _contract_payload(base, "rollback", schema_slug="rollback", artifact_id="B04_R6_CANARY_ROLLBACK_CONTRACT", details={"rollback_required": True, "rollback_receipt_required": True}),
        "route_distribution_health_thresholds": _contract_payload(base, "route_distribution_health_thresholds", schema_slug="route_distribution_health_thresholds", artifact_id="B04_R6_CANARY_ROUTE_DISTRIBUTION_HEALTH_THRESHOLDS", details=thresholds["route_distribution_health"]),
        "drift_thresholds": _contract_payload(base, "drift_thresholds", schema_slug="drift_thresholds", artifact_id="B04_R6_CANARY_DRIFT_THRESHOLDS", details=thresholds["drift"]),
        "incident_freeze_contract": _contract_payload(base, "incident_freeze", schema_slug="incident_freeze", artifact_id="B04_R6_CANARY_INCIDENT_FREEZE_CONTRACT", details={"freeze_on_incident": True, "freeze_on_trace_incomplete": True, "freeze_on_boundary_drift": True}),
        "runtime_receipt_schema": _contract_payload(base, "runtime_receipt_schema", schema_slug="runtime_receipt_schema", artifact_id="B04_R6_CANARY_RUNTIME_RECEIPT_SCHEMA", details=common_runtime_schema),
        "external_verifier_requirements": _contract_payload(base, "external_verifier_requirements", schema_slug="external_verifier_requirements", artifact_id="B04_R6_CANARY_EXTERNAL_VERIFIER_REQUIREMENTS", details={"external_verifier_required": True, "non_executing": True, "raw_hash_bound_bundle_required": True}),
        "commercial_claim_boundary": _contract_payload(base, "commercial_claim_boundary", schema_slug="commercial_claim_boundary", artifact_id="B04_R6_CANARY_COMMERCIAL_CLAIM_BOUNDARY", details={"commercial_activation_claim_authorized": False, "allowed_status_language": "Canary authorization packet authored; canary not executed."}),
        "package_promotion_prohibition_receipt": _contract_payload(base, "package_promotion_prohibition", schema_slug="package_promotion_prohibition", artifact_id="B04_R6_CANARY_PACKAGE_PROMOTION_PROHIBITION_RECEIPT", details={"package_promotion_authorized": False, "package_promotion": "DEFERRED"}),
        "no_authorization_drift_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_authorization.no_authorization_drift_receipt.v1",
            artifact_id="B04_R6_CANARY_NO_AUTHORIZATION_DRIFT_RECEIPT",
            no_authorization_drift=True,
            canary_runtime_authorized=False,
            canary_runtime_executed=False,
            runtime_cutover_authorized=False,
            r6_open=False,
            package_promotion_authorized=False,
            commercial_activation_claim_authorized=False,
        ),
        "validation_plan": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_authorization.validation_plan.v1",
            artifact_id="B04_R6_CANARY_AUTHORIZATION_VALIDATION_PLAN",
            validation_lane="VALIDATE_B04_R6_CANARY_AUTHORIZATION_PACKET",
            required_checks=[row["name"] for row in base["validation_rows"]],
        ),
        "validation_reason_codes": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_authorization.validation_reason_codes.v1",
            artifact_id="B04_R6_CANARY_AUTHORIZATION_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
            terminal_defects=list(TERMINAL_DEFECTS),
        ),
        "lane_compiler_scaffold_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_authorization.lane_compiler_scaffold_receipt.v1",
            artifact_id="B04_R6_CANARY_AUTHORIZATION_LANE_COMPILER_SCAFFOLD_RECEIPT",
            scaffold=compiler_scaffold,
            scaffold_authority="PREP_ONLY_TOOLING",
            scaffold_can_authorize=False,
        ),
        "pipeline_board": _pipeline_board(base),
        "future_blocker_register": _future_blocker_register(base),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v25",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            verdict="NEXT_LAWFUL_MOVE_SET",
        ),
    }
    output_payloads.update(
        {
            role: _prep_only(base, role=role, purpose=f"Prep-only continuation scaffold for {role.replace('_', ' ')}.")
            for role in PREP_ONLY_OUTPUT_ROLES
        }
    )
    return output_payloads


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root):
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 canary authorization packet")

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
        for role, raw in TEXT_INPUTS.items()
    }
    input_bindings = _input_bindings(root, handoff_git_commit=handoff_git_commit)
    binding_hashes = _binding_hashes(root, handoff_git_commit=handoff_git_commit)
    source_evidence_hashes = _validate_inputs(payloads, texts, binding_hashes)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_CANARY_AUTH_PACKET_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    compiler_scaffold = _compiler_scaffold(current_main_head)
    if compiler_scaffold.get("authority") != "PREP_ONLY_TOOLING":
        _fail("RC_B04R6_CANARY_AUTH_PACKET_COMPILER_SCAFFOLD_MISSING", "compiler scaffold authority drift")

    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=input_bindings,
        binding_hashes=binding_hashes,
        source_evidence_hashes=source_evidence_hashes,
        validation_rows=_validation_rows(),
        compiler_scaffold=compiler_scaffold,
        trust_zone_validation=fresh_trust_validation,
    )
    output_payloads = _outputs(base, compiler_scaffold)
    contract = output_payloads["packet_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "packet_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author B04 R6 canary authorization packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
