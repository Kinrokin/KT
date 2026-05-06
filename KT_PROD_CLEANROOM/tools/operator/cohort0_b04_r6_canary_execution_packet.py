from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_canary_authorization_packet as canary
from tools.operator import cohort0_b04_r6_canary_authorization_packet_validation as canary_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_lane_compiler
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-canary-execution-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_CANARY_EXECUTION_PACKET"
PREVIOUS_LANE = canary_validation.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = canary_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = canary_validation.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = "B04_R6_CANARY_EXECUTION_PACKET_BOUND__CANARY_EXECUTION_VALIDATION_NEXT"
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_CANARY_EXECUTION_PACKET"

MAY_AUTHORIZE = ("CANARY_EXECUTION_PACKET_AUTHORED",)
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
    "CANARY_AUTHORIZATION_VALIDATION_MISSING",
    "CANARY_AUTHORIZATION_PACKET_HASH_MISSING",
    "RUNTIME_EVIDENCE_REVIEW_VALIDATION_UNBOUND",
    "CANARY_EXECUTION_SCOPE_MISSING",
    "CANARY_EXECUTION_SAMPLE_LIMIT_MISSING",
    "CANARY_RUNTIME_AUTHORIZED",
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
    "RC_B04R6_CANARY_EXEC_PACKET_CONTRACT_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_MAIN_HEAD_MISMATCH",
    "RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_PACKET_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_RUNTIME_EVIDENCE_VALIDATION_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_RUNTIME_EVIDENCE_INVENTORY_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_RUNTIME_EVIDENCE_SCORECARD_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_SHADOW_RUNTIME_RESULT_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_STATIC_AUTHORITY_EVIDENCE_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_ROUTE_HEALTH_EVIDENCE_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_FALLBACK_EVIDENCE_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_OPERATOR_OVERRIDE_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_KILL_SWITCH_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_ROLLBACK_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_DRIFT_MONITORING_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_INCIDENT_FREEZE_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_COMMERCIAL_BOUNDARY_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_PACKAGE_PROMOTION_BLOCKER_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_SCOPE_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_ALLOWED_CASE_CLASSES_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_EXCLUDED_CASE_CLASSES_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_SAMPLE_LIMIT_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_RUNTIME_RECEIPT_SCHEMA_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_REPLAY_MANIFEST_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_EXPECTED_ARTIFACT_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_RESULT_INTERPRETATION_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_PRIOR_GIT_BINDING_DRIFT",
    "RC_B04R6_CANARY_EXEC_PACKET_INPUT_HASH_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_INPUT_HASH_MALFORMED",
    "RC_B04R6_CANARY_EXEC_PACKET_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_CANARY_EXEC_PACKET_CANARY_AUTHORIZED",
    "RC_B04R6_CANARY_EXEC_PACKET_CANARY_EXECUTED",
    "RC_B04R6_CANARY_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_CANARY_EXEC_PACKET_R6_OPEN_DRIFT",
    "RC_B04R6_CANARY_EXEC_PACKET_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_CANARY_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_CANARY_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_CANARY_EXEC_PACKET_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_CANARY_EXEC_PACKET_TRUST_ZONE_MUTATION",
    "RC_B04R6_CANARY_EXEC_PACKET_COMPILER_SCAFFOLD_MISSING",
    "RC_B04R6_CANARY_EXEC_PACKET_NEXT_MOVE_DRIFT",
)

VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in canary_validation.OUTPUTS.items()
    if filename.endswith(".json")
}
VALIDATION_TEXT_INPUTS = {
    "canary_authorization_validation_report": f"KT_PROD_CLEANROOM/reports/{canary_validation.OUTPUTS['validation_report']}",
}
CANARY_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in canary.OUTPUTS.items()
    if filename.endswith(".json")
}
CANARY_TEXT_INPUTS = {
    "canary_authorization_packet_report": f"KT_PROD_CLEANROOM/reports/{canary.OUTPUTS['packet_report']}",
}
ALL_JSON_INPUTS = {
    **{f"validation_{role}": raw for role, raw in VALIDATION_JSON_INPUTS.items()},
    **{f"canary_{role}": raw for role, raw in CANARY_JSON_INPUTS.items()},
}
ALL_TEXT_INPUTS = {**VALIDATION_TEXT_INPUTS, **CANARY_TEXT_INPUTS}

OUTPUTS = {
    "packet_contract": "b04_r6_canary_execution_packet_contract.json",
    "packet_receipt": "b04_r6_canary_execution_packet_receipt.json",
    "packet_report": "b04_r6_canary_execution_packet_report.md",
    "mode_contract": "b04_r6_canary_execution_mode_contract.json",
    "scope_manifest": "b04_r6_canary_execution_scope_manifest.json",
    "allowed_case_class_contract": "b04_r6_canary_execution_allowed_case_class_contract.json",
    "excluded_case_class_contract": "b04_r6_canary_execution_excluded_case_class_contract.json",
    "sample_limit_contract": "b04_r6_canary_execution_sample_limit_contract.json",
    "static_fallback_contract": "b04_r6_canary_execution_static_fallback_contract.json",
    "abstention_fallback_contract": "b04_r6_canary_execution_abstention_fallback_contract.json",
    "null_route_preservation_contract": "b04_r6_canary_execution_null_route_preservation_contract.json",
    "operator_override_contract": "b04_r6_canary_execution_operator_override_contract.json",
    "kill_switch_contract": "b04_r6_canary_execution_kill_switch_contract.json",
    "rollback_contract": "b04_r6_canary_execution_rollback_contract.json",
    "route_distribution_health_thresholds": "b04_r6_canary_execution_route_distribution_health_thresholds.json",
    "drift_thresholds": "b04_r6_canary_execution_drift_thresholds.json",
    "incident_freeze_contract": "b04_r6_canary_execution_incident_freeze_contract.json",
    "runtime_receipt_schema": "b04_r6_canary_execution_runtime_receipt_schema.json",
    "replay_manifest": "b04_r6_canary_execution_replay_manifest.json",
    "expected_artifact_manifest": "b04_r6_canary_execution_expected_artifact_manifest.json",
    "external_verifier_requirements": "b04_r6_canary_execution_external_verifier_requirements.json",
    "result_interpretation_contract": "b04_r6_canary_execution_result_interpretation_contract.json",
    "no_authorization_drift_receipt": "b04_r6_canary_execution_no_authorization_drift_receipt.json",
    "validation_plan": "b04_r6_canary_execution_validation_plan.json",
    "validation_reason_codes": "b04_r6_canary_execution_validation_reason_codes.json",
    "paired_lane_compiler_scaffold_receipt": "b04_r6_canary_execution_paired_lane_compiler_scaffold_receipt.json",
    "canary_run_result_schema_prep_only": "b04_r6_canary_run_result_schema_prep_only.json",
    "canary_evidence_review_packet_prep_only_draft": "b04_r6_canary_evidence_review_packet_prep_only_draft.json",
    "canary_failure_closeout_prep_only_draft": "b04_r6_canary_failure_closeout_prep_only_draft.json",
    "canary_forensic_invalidation_court_prep_only_draft": "b04_r6_canary_forensic_invalidation_court_prep_only_draft.json",
    "package_promotion_review_preconditions_prep_only_draft": "b04_r6_package_promotion_review_preconditions_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only_draft": "b04_r6_external_audit_delta_manifest_prep_only_draft.json",
    "public_verifier_delta_requirements_prep_only": "b04_r6_public_verifier_delta_requirements_prep_only.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}
CANARY_EXECUTION_CONTRACT_ROLES = (
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
)
PREP_ONLY_OUTPUT_ROLES = (
    "canary_run_result_schema_prep_only",
    "canary_evidence_review_packet_prep_only_draft",
    "canary_failure_closeout_prep_only_draft",
    "canary_forensic_invalidation_court_prep_only_draft",
    "package_promotion_review_preconditions_prep_only_draft",
    "external_audit_delta_manifest_prep_only_draft",
    "public_verifier_delta_requirements_prep_only",
)
REQUIRED_SOURCE_HASHES = (
    "validated_canary_authorization_receipt_hash",
    "runtime_evidence_review_validation_receipt_hash",
    "runtime_evidence_inventory_hash",
    "runtime_evidence_scorecard_hash",
    "shadow_runtime_result_hash",
    "static_authority_preservation_evidence_hash",
    "route_distribution_health_evidence_hash",
    "fallback_behavior_evidence_hash",
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
    "canary_scope_manifest_hash",
    "canary_authorization_packet_hash",
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
            _fail("RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"git-bound input {label} missing at {handoff_git_commit}: {exc}")
    return _load(root, raw, label=label)


def _read_text_input(root: Path, raw: str, *, label: str, handoff_git_commit: str, output_names: set[str]) -> str:
    if Path(raw).name in output_names:
        try:
            return _git_blob_bytes(root, handoff_git_commit, raw).decode("utf-8")
        except Exception as exc:
            _fail("RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"git-bound text input {label} missing at {handoff_git_commit}: {exc}")
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
        "canary_runtime_authorized": "RC_B04R6_CANARY_EXEC_PACKET_CANARY_AUTHORIZED",
        "canary_runtime_executed": "RC_B04R6_CANARY_EXEC_PACKET_CANARY_EXECUTED",
        "runtime_cutover_authorized": "RC_B04R6_CANARY_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
        "activation_cutover_executed": "RC_B04R6_CANARY_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
        "r6_open": "RC_B04R6_CANARY_EXEC_PACKET_R6_OPEN_DRIFT",
        "lobe_escalation_authorized": "RC_B04R6_CANARY_EXEC_PACKET_LOBE_ESCALATION_DRIFT",
        "package_promotion_authorized": "RC_B04R6_CANARY_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT",
        "commercial_activation_claim_authorized": "RC_B04R6_CANARY_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT",
        "truth_engine_law_changed": "RC_B04R6_CANARY_EXEC_PACKET_TRUTH_ENGINE_MUTATION",
        "trust_zone_law_changed": "RC_B04R6_CANARY_EXEC_PACKET_TRUST_ZONE_MUTATION",
        "metric_contract_mutated": "RC_B04R6_CANARY_EXEC_PACKET_PREP_ONLY_AUTHORITY_DRIFT",
        "static_comparator_weakened": "RC_B04R6_CANARY_EXEC_PACKET_PREP_ONLY_AUTHORITY_DRIFT",
    }
    for key, value in _walk_items(payload):
        if key in forbidden_truths and value is True:
            _fail(forbidden_truths[key], f"{label}.{key} drifted true")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_CANARY_EXEC_PACKET_PACKAGE_PROMOTION_DRIFT", f"{label}.package_promotion drifted")


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
            "binding_kind": "file_sha256_at_canary_execution_packet_authoring",
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
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": "file_sha256_at_canary_execution_packet_authoring",
            }
        )
    return rows


def _binding_hashes(root: Path, *, handoff_git_commit: str) -> Dict[str, str]:
    output_names = set(OUTPUTS.values())
    hashes = {
        f"{role}_hash": _input_hash(root, raw, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in sorted(ALL_JSON_INPUTS.items())
    }
    hashes.update({f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(ALL_TEXT_INPUTS.items())})
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
        _fail("RC_B04R6_CANARY_EXEC_PACKET_PRIOR_GIT_BINDING_DRIFT", "canary validation contract lacks prior main head")
    for row in contract.get("input_bindings", []):
        role = row.get("role")
        raw = row.get("path")
        sha = row.get("sha256")
        if not role or not raw or not _is_sha256(sha):
            _fail("RC_B04R6_CANARY_EXEC_PACKET_INPUT_HASH_MALFORMED", f"malformed input binding row: {role}")
        overwritten_by_this_lane = Path(str(raw)).name in set(OUTPUTS.values())
        if row.get("binding_kind") == "git_object_before_overwrite":
            if row.get("git_commit") != prior_main_head:
                _fail("RC_B04R6_CANARY_EXEC_PACKET_PRIOR_GIT_BINDING_DRIFT", f"{role} not bound to prior canonical main")
            actual = _git_blob_sha256(root, str(row["git_commit"]), str(raw))
        elif overwritten_by_this_lane:
            actual = _git_blob_sha256(root, str(prior_main_head), str(raw))
        else:
            actual = file_sha256(common.resolve_path(root, str(raw)))
        if actual != sha:
            _fail("RC_B04R6_CANARY_EXEC_PACKET_INPUT_HASH_MALFORMED", f"{role} hash mismatch")
        binding_key = f"{role}_hash"
        if contract.get("binding_hashes", {}).get(binding_key) != sha:
            _fail("RC_B04R6_CANARY_EXEC_PACKET_INPUT_HASH_MISSING", f"{binding_key} missing or mismatched")


def _source_hashes(payloads: Dict[str, Dict[str, Any]], binding_hashes: Dict[str, str]) -> Dict[str, str]:
    validation_contract = payloads["validation_validation_contract"]
    canary_contract = payloads["canary_packet_contract"]
    canary_binding = validation_contract.get("binding_hashes", {})
    source = {
        "validated_canary_authorization_receipt_hash": binding_hashes.get("validation_validation_receipt_hash"),
        "runtime_evidence_review_validation_receipt_hash": canary_contract.get("source_evidence_hashes", {}).get("validated_runtime_evidence_review_receipt_hash"),
        "runtime_evidence_inventory_hash": canary_contract.get("source_evidence_hashes", {}).get("runtime_evidence_inventory_hash"),
        "runtime_evidence_scorecard_hash": canary_contract.get("source_evidence_hashes", {}).get("runtime_evidence_scorecard_hash"),
        "shadow_runtime_result_hash": canary_contract.get("source_evidence_hashes", {}).get("shadow_runtime_result_hash"),
        "static_authority_preservation_evidence_hash": canary_contract.get("source_evidence_hashes", {}).get("static_authority_preservation_evidence_hash"),
        "route_distribution_health_evidence_hash": canary_contract.get("source_evidence_hashes", {}).get("route_distribution_health_evidence_hash"),
        "fallback_behavior_evidence_hash": canary_contract.get("source_evidence_hashes", {}).get("fallback_behavior_evidence_hash"),
        "operator_override_readiness_evidence_hash": canary_contract.get("source_evidence_hashes", {}).get("operator_override_readiness_evidence_hash"),
        "kill_switch_readiness_evidence_hash": canary_contract.get("source_evidence_hashes", {}).get("kill_switch_readiness_evidence_hash"),
        "rollback_readiness_evidence_hash": canary_contract.get("source_evidence_hashes", {}).get("rollback_readiness_evidence_hash"),
        "drift_monitoring_evidence_hash": canary_contract.get("source_evidence_hashes", {}).get("drift_monitoring_evidence_hash"),
        "incident_freeze_evidence_hash": canary_contract.get("source_evidence_hashes", {}).get("incident_freeze_evidence_hash"),
        "trace_completeness_evidence_hash": canary_contract.get("source_evidence_hashes", {}).get("trace_completeness_evidence_hash"),
        "runtime_replay_evidence_hash": canary_contract.get("source_evidence_hashes", {}).get("runtime_replay_evidence_hash"),
        "external_verifier_readiness_evidence_hash": canary_contract.get("source_evidence_hashes", {}).get("external_verifier_readiness_evidence_hash"),
        "commercial_claim_boundary_hash": canary_contract.get("source_evidence_hashes", {}).get("commercial_claim_boundary_hash"),
        "package_promotion_blocker_review_hash": canary_contract.get("source_evidence_hashes", {}).get("package_promotion_blocker_review_hash"),
        "canary_scope_manifest_hash": canary_binding.get("scope_manifest_hash"),
        "canary_authorization_packet_hash": canary_binding.get("packet_contract_hash"),
    }
    for key in REQUIRED_SOURCE_HASHES:
        if not _is_sha256(source.get(key)):
            _fail("RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"{key} missing")
    return {key: str(source[key]) for key in REQUIRED_SOURCE_HASHES}


def _validate_operational_contracts(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in canary.CANARY_CONTRACT_ROLES:
        payload = payloads[f"canary_{role}"]
        if payload.get("contract_status") != "BOUND_NON_EXECUTING":
            _fail("RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_PACKET_MISSING", f"{role} is not bound/non-executing")
        if payload.get("canary_runtime_authorized") is not False or payload.get("canary_runtime_executed") is not False:
            _fail("RC_B04R6_CANARY_EXEC_PACKET_CANARY_AUTHORIZED", f"{role} authority drift")
        if payload.get("runtime_cutover_authorized") is not False:
            _fail("RC_B04R6_CANARY_EXEC_PACKET_RUNTIME_CUTOVER_AUTHORIZED", f"{role} cutover drift")
    scope = payloads["canary_scope_manifest"].get("details", {})
    if scope.get("scope_status") != "LIMITED_CANARY_SCOPE_DEFINED_NOT_AUTHORIZED":
        _fail("RC_B04R6_CANARY_EXEC_PACKET_SCOPE_MISSING", "canary authorization scope drift")
    if scope.get("global_r6_scope_allowed") is not False or scope.get("runtime_cutover_allowed") is not False:
        _fail("RC_B04R6_CANARY_EXEC_PACKET_R6_OPEN_DRIFT", "scope widened")
    if scope.get("max_case_count_per_window") != 12 or scope.get("operator_observed_required") is not True:
        _fail("RC_B04R6_CANARY_EXEC_PACKET_SAMPLE_LIMIT_MISSING", "sample limit/operator observation missing")


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str], binding_hashes: Dict[str, str], root: Path) -> Dict[str, str]:
    for label, payload in payloads.items():
        _ensure_authority_closed(payload, label=label)
    for role in canary_validation.PREP_ONLY_OUTPUT_ROLES:
        payload = payloads.get(f"validation_{role}")
        if payload and (payload.get("status") != "PREP_ONLY" or payload.get("authority") != "PREP_ONLY_NON_AUTHORITY"):
            _fail("RC_B04R6_CANARY_EXEC_PACKET_PREP_ONLY_AUTHORITY_DRIFT", f"{role} is not prep-only")

    validation_contract = payloads["validation_validation_contract"]
    validation_receipt = payloads["validation_validation_receipt"]
    validation_next = payloads["validation_next_lawful_move"]
    canary_contract = payloads["canary_packet_contract"]

    for role, payload in (("validation_contract", validation_contract), ("validation_receipt", validation_receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"{role} lane identity drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"{role} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_CANARY_EXEC_PACKET_NEXT_MOVE_DRIFT", f"{role} next move drift")
        if payload.get("canary_authorization_packet_validated") is not True:
            _fail("RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"{role} not validated")
    if not _valid_handoff(validation_next):
        _fail("RC_B04R6_CANARY_EXEC_PACKET_NEXT_MOVE_DRIFT", "next move handoff lacks valid lane identity")

    if canary_contract.get("authoritative_lane") != canary.AUTHORITATIVE_LANE:
        _fail("RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_PACKET_MISSING", "canary packet lane identity drift")
    if canary_contract.get("selected_outcome") != canary.SELECTED_OUTCOME:
        _fail("RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_PACKET_MISSING", "canary packet outcome drift")
    if canary_contract.get("next_lawful_move") != canary.NEXT_LAWFUL_MOVE:
        _fail("RC_B04R6_CANARY_EXEC_PACKET_NEXT_MOVE_DRIFT", "canary packet next move drift")
    if canary_contract.get("canary_authorization_packet_authored") is not True or canary_contract.get("canary_authorization_packet_validated") is not False:
        _fail("RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_PACKET_MISSING", "canary packet authoring/validation flags drift")

    _validate_prior_git_bindings(root, validation_contract)
    _validate_operational_contracts(payloads)

    board = payloads["validation_pipeline_board"]
    lanes = {row.get("lane"): row for row in board.get("lanes", [])}
    author_status = lanes.get("AUTHOR_B04_R6_CANARY_EXECUTION_PACKET", {}).get("status")
    validation_status = lanes.get("VALIDATE_B04_R6_CANARY_EXECUTION_PACKET", {}).get("status")
    predecessor_board = author_status == "NEXT"
    self_replay_board = author_status == "CURRENT_BOUND" and validation_status == "NEXT"
    if not (predecessor_board or self_replay_board):
        _fail("RC_B04R6_CANARY_EXEC_PACKET_NEXT_MOVE_DRIFT", "pipeline board does not show canary execution packet handoff")
    if lanes.get("RUN_B04_R6_LIMITED_RUNTIME_CANARY", {}).get("status") != "BLOCKED":
        _fail("RC_B04R6_CANARY_EXEC_PACKET_CANARY_AUTHORIZED", "pipeline board canary runtime not blocked")

    report = texts["canary_authorization_validation_report"].lower()
    for phrase in ("does not authorize canary runtime", "does not execute canary", "does not authorize runtime cutover"):
        if phrase not in report:
            _fail("RC_B04R6_CANARY_EXEC_PACKET_AUTHORIZATION_VALIDATION_MISSING", f"validation report missing {phrase}")
    return _source_hashes(payloads, binding_hashes)


def _author_spec(current_main_head: str) -> Dict[str, Any]:
    return {
        "lane_id": "AUTHOR_B04_R6_CANARY_EXECUTION_PACKET",
        "lane_name": "B04 R6 canary execution packet",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM",
        "summary": "Prep-only paired scaffold for the canary execution packet authoring lane.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/cohort0_b04_r6_canary_execution_packet.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_b04_r6_canary_execution_packet.py",
        "artifacts": sorted(OUTPUTS.values()),
        "json_parse_inputs": sorted(filename for filename in OUTPUTS.values() if filename.endswith(".json")),
        "no_authorization_drift_checks": [
            "Authoring does not execute canary runtime.",
            "Authoring does not authorize runtime cutover, R6 open, package promotion, or commercial claims.",
        ],
        "future_blockers": [
            "Canary execution packet must validate before canary runtime may run.",
            "Canary evidence review must pass before package promotion review.",
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


def _validation_spec(current_main_head: str) -> Dict[str, Any]:
    return {
        "lane_id": "VALIDATE_B04_R6_CANARY_EXECUTION_PACKET",
        "lane_name": "B04 R6 canary execution packet validation",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM",
        "summary": "Prep-only paired scaffold for validating the canary execution packet.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/cohort0_b04_r6_canary_execution_packet_validation.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_b04_r6_canary_execution_packet_validation.py",
        "artifacts": [
            "b04_r6_canary_execution_packet_validation_contract.json",
            "b04_r6_canary_execution_packet_validation_receipt.json",
            "b04_r6_canary_execution_packet_validation_report.md",
        ],
        "json_parse_inputs": [
            "b04_r6_canary_execution_packet_validation_contract.json",
            "b04_r6_canary_execution_packet_validation_receipt.json",
        ],
        "no_authorization_drift_checks": [
            "Validation does not execute canary runtime.",
            "Validation does not authorize runtime cutover, R6 open, package promotion, or commercial claims.",
        ],
        "future_blockers": [
            "Canary runtime remains blocked until canary execution packet validation passes.",
            "Runtime cutover remains blocked until canary evidence review and cutover law.",
        ],
        "reason_codes": list(REASON_CODES),
        "lane_kind": "VALIDATION",
        "current_main_head": current_main_head,
        "predecessor_outcome": SELECTED_OUTCOME,
        "selected_outcome": "B04_R6_CANARY_EXECUTION_PACKET_VALIDATED__CANARY_RUN_NEXT",
        "next_lawful_move": "RUN_B04_R6_LIMITED_RUNTIME_CANARY",
        "may_authorize": ["CANARY_EXECUTION_PACKET_VALIDATED"],
        "must_not_authorize": list(FORBIDDEN_ACTIONS),
        "authoritative_inputs": sorted(OUTPUTS),
        "prep_only_outputs": ["b04_r6_canary_evidence_review_packet_prep_only_draft.json"],
    }


def _paired_compiler_scaffold(current_main_head: str) -> Dict[str, Any]:
    paired = kt_lane_compiler.build_paired_lane_contract(_author_spec(current_main_head), _validation_spec(current_main_head))
    rendered = json.dumps(paired, sort_keys=True, ensure_ascii=True)
    return {
        "compiler_id": kt_lane_compiler.COMPILER_ID,
        "authority": kt_lane_compiler.AUTHORITY,
        "status": "PREP_ONLY_PAIRED_SCAFFOLD_USED",
        "paired_contract_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "author_lane_id": paired["author_lane_id"],
        "validation_lane_id": paired["validation_lane_id"],
        "paired_lane_law": paired["paired_lane_law"],
        "generated_artifacts": paired["paired_generated_artifacts"],
        "non_authorization_guards": paired["non_authorization_guards"],
    }


def _validation_rows() -> list[Dict[str, Any]]:
    checks = [
        "canary_authorization_validation_bound",
        "canary_authorization_packet_bound",
        "runtime_evidence_review_validation_bound",
        "runtime_evidence_inventory_bound",
        "runtime_evidence_scorecard_bound",
        "shadow_runtime_result_bound",
        "static_authority_evidence_bound",
        "route_distribution_health_evidence_bound",
        "fallback_behavior_evidence_bound",
        "operator_override_bound",
        "kill_switch_bound",
        "rollback_bound",
        "drift_monitoring_bound",
        "incident_freeze_bound",
        "external_verifier_bound",
        "commercial_claim_boundary_bound",
        "package_promotion_blocker_bound",
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
        "result_interpretation_contract_defined",
        "prior_git_object_bindings_stable",
        "validation_scaffold_ready",
        "prep_only_drafts_remain_prep_only",
        "canary_not_executed",
        "canary_runtime_not_authorized",
        "runtime_cutover_not_authorized",
        "r6_remains_closed",
        "lobe_escalation_unauthorized",
        "package_promotion_blocked",
        "commercial_claims_blocked",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
        "paired_lane_scaffold_non_authoritative",
        "next_lawful_move_canary_execution_validation",
    ]
    terminal = {
        "canary_authorization_validation_bound",
        "canary_authorization_packet_bound",
        "execution_mode_defined",
        "execution_scope_limited",
        "sample_limit_defined",
        "canary_not_executed",
        "canary_runtime_not_authorized",
        "runtime_cutover_not_authorized",
        "r6_remains_closed",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
        "next_lawful_move_canary_execution_validation",
    }
    return [
        {"check_id": f"B04R6-CANARY-EXEC-PACKET-{index:03d}", "name": check, "status": "PASS", "terminal_if_fail": check in terminal}
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
    source_hashes: Dict[str, str],
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
        "source_hashes": source_hashes,
        "validation_rows": validation_rows,
        "may_authorize": list(MAY_AUTHORIZE),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "allowed_outcomes": [
            SELECTED_OUTCOME,
            "B04_R6_CANARY_EXECUTION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS",
            "B04_R6_CANARY_EXECUTION_PACKET_REJECTED__CANARY_EXECUTION_NOT_JUSTIFIED",
            "B04_R6_CANARY_EXECUTION_PACKET_INVALID__FORENSIC_CANARY_EXECUTION_REVIEW_NEXT",
        ],
        "outcome_routing": {
            SELECTED_OUTCOME: NEXT_LAWFUL_MOVE,
            "B04_R6_CANARY_EXECUTION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS": "REPAIR_B04_R6_CANARY_EXECUTION_PACKET_DEFECTS",
            "B04_R6_CANARY_EXECUTION_PACKET_REJECTED__CANARY_EXECUTION_NOT_JUSTIFIED": "AUTHOR_B04_R6_CANARY_REJECTION_CLOSEOUT",
            "B04_R6_CANARY_EXECUTION_PACKET_INVALID__FORENSIC_CANARY_EXECUTION_REVIEW_NEXT": "AUTHOR_B04_R6_FORENSIC_CANARY_EXECUTION_REVIEW",
        },
        "terminal_defects": list(TERMINAL_DEFECTS),
        "reason_codes": list(REASON_CODES),
        "paired_lane_compiler_scaffold": paired_scaffold,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
    }


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _scope() -> Dict[str, Any]:
    return {
        "scope_status": "LIMITED_CANARY_EXECUTION_SCOPE_BOUND_NOT_VALIDATED",
        "execution_requires_future_packet_validation": True,
        "global_r6_scope_allowed": False,
        "runtime_cutover_allowed": False,
        "operator_observed_required": True,
        "max_case_count_per_window": 12,
        "window": "one validation-bound canary window",
        "static_fallback_required": True,
    }


def _allowed_case_classes() -> list[Dict[str, Any]]:
    return [
        {"case_class": "ROUTE_ELIGIBLE_LOW_RISK_SHADOW_CONFIRMED", "conditions": ["static fallback available", "operator observed", "receipt emitted"]},
        {"case_class": "STATIC_FALLBACK_AVAILABLE_ROUTE_CHECK", "conditions": ["kill switch reachable", "rollback receipt can be emitted"]},
        {"case_class": "NON_COMMERCIAL_OPERATOR_OBSERVED_SAMPLE", "conditions": ["sample limit applies", "external verifier receipt emitted"]},
    ]


def _excluded_case_classes() -> list[Dict[str, Any]]:
    return [
        {"case_class": "GLOBAL_R6_TRAFFIC", "reason": "R6 remains closed."},
        {"case_class": "NO_STATIC_FALLBACK_AVAILABLE", "reason": "Canary requires static fallback."},
        {"case_class": "ABSTENTION_REQUIRED_OR_HUMAN_REVIEW", "reason": "Abstention fallback preserves review boundary."},
        {"case_class": "NULL_ROUTE_CONTROL", "reason": "Null-route preservation must not become canary routing."},
        {"case_class": "COMMERCIAL_ACTIVATION_SURFACE", "reason": "Commercial activation claims remain unauthorized."},
    ]


def _contract_payload(base: Dict[str, Any], role: str, *, schema_slug: str, artifact_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.canary_execution.{schema_slug}.v1",
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
        schema_id=f"kt.b04_r6.canary_execution.{role}.prep_only.v1",
        artifact_id=f"B04_R6_{role.upper()}",
        status="PREP_ONLY",
        authority="PREP_ONLY_NON_AUTHORITY",
        purpose=purpose,
        can_authorize=False,
        canary_runtime_authorized=False,
        canary_runtime_executed=False,
        runtime_cutover_authorized=False,
        r6_open=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
    )


def _pipeline_board(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.pipeline_board.v11",
        artifact_id="B04_R6_PIPELINE_BOARD",
        board_status="CANARY_EXECUTION_PACKET_BOUND_VALIDATION_NEXT",
        lanes=[
            {"lane": "VALIDATE_B04_R6_CANARY_AUTHORIZATION_PACKET", "status": "VALIDATED", "authoritative": True},
            {"lane": "AUTHOR_B04_R6_CANARY_EXECUTION_PACKET", "status": "CURRENT_BOUND", "authoritative": True},
            {"lane": "VALIDATE_B04_R6_CANARY_EXECUTION_PACKET", "status": "NEXT", "authoritative": True},
            {"lane": "RUN_B04_R6_LIMITED_RUNTIME_CANARY", "status": "BLOCKED", "authoritative": False},
            {"lane": "AUTHOR_B04_R6_CANARY_EVIDENCE_REVIEW_PACKET", "status": "PREP_ONLY", "authoritative": False},
            {"lane": "AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET", "status": "BLOCKED", "authoritative": False},
            {"lane": "AUTHOR_B04_R6_EXTERNAL_AUDIT_DELTA_PACKET", "status": "PREP_ONLY", "authoritative": False},
        ],
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    blockers = [
        "CANARY_EXECUTION_PACKET_NOT_VALIDATED",
        "CANARY_RUNTIME_NOT_EXECUTED",
        "CANARY_EVIDENCE_REVIEW_NOT_AUTHORED",
        "PACKAGE_PROMOTION_REQUIRES_CANARY_EVIDENCE_EXTERNAL_AUDIT_AND_PROMOTION_REVIEW",
        "COMMERCIAL_ACTIVATION_CLAIMS_UNAUTHORIZED",
    ]
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v19",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        blockers=[{"blocker_id": blocker, "status": "OPEN"} for blocker in blockers],
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    scope = _scope()
    allowed = _allowed_case_classes()
    excluded = _excluded_case_classes()
    runtime_receipt_schema = {
        "required_fields": [
            "case_id",
            "canary_mode",
            "sample_window_id",
            "static_fallback_available",
            "operator_observed",
            "afsh_verdict",
            "static_verdict",
            "fallback_invoked",
            "kill_switch_status",
            "rollback_receipt_id",
            "trace_hash",
            "external_verifier_hash",
        ],
        "raw_hash_bound_artifacts_required": True,
        "compressed_index_source_of_truth": False,
    }
    expected_artifacts = [
        "b04_r6_canary_runtime_execution_receipt.json",
        "b04_r6_canary_runtime_result.json",
        "b04_r6_canary_runtime_case_manifest.json",
        "b04_r6_canary_runtime_route_distribution_health_receipt.json",
        "b04_r6_canary_runtime_no_authorization_drift_receipt.json",
    ]
    output_payloads: Dict[str, Any] = {
        "packet_contract": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_execution_packet_contract.v1",
            artifact_id="B04_R6_CANARY_EXECUTION_PACKET_CONTRACT",
            packet_scope={
                "purpose": "Author exact canary execution law after canary authorization validation.",
                "non_purpose": [
                    "Does not execute canary.",
                    "Does not authorize runtime cutover.",
                    "Does not open R6.",
                    "Does not authorize lobe escalation.",
                    "Does not authorize package promotion.",
                    "Does not authorize commercial activation claims.",
                ],
            },
            canary_execution_mode="LIMITED_OPERATOR_OBSERVED_CANARY_PACKET_ONLY",
            canary_execution_runtime_authorized=False,
            canary_execution_requires_future_packet_validation=True,
            execution_scope=scope,
            allowed_case_classes=allowed,
            excluded_case_classes=excluded,
            expected_artifacts=expected_artifacts,
            success_requirements=[
                "canary_authorization_validation_bound",
                "scope_limited",
                "sample_limit_defined",
                "fallbacks_operator_override_kill_switch_rollback_bound",
                "runtime_receipts_defined",
                "replay_manifest_defined",
                "commercial_claim_boundary_preserved",
                "package_promotion_not_automatic",
            ],
        ),
        "packet_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_execution_packet_receipt.v1",
            artifact_id="B04_R6_CANARY_EXECUTION_PACKET_RECEIPT",
            verdict="CANARY_EXECUTION_PACKET_BOUND_NON_EXECUTING",
            canary_execution_packet_bound=True,
        ),
        "mode_contract": _contract_payload(base, "mode", schema_slug="mode", artifact_id="B04_R6_CANARY_EXECUTION_MODE_CONTRACT", details={"mode": "LIMITED_OPERATOR_OBSERVED_CANARY_PACKET_ONLY", "canary_runtime_may_run_only_after_validation": True}),
        "scope_manifest": _contract_payload(base, "scope", schema_slug="scope", artifact_id="B04_R6_CANARY_EXECUTION_SCOPE_MANIFEST", details=scope),
        "allowed_case_class_contract": _contract_payload(base, "allowed_case_classes", schema_slug="allowed_case_classes", artifact_id="B04_R6_CANARY_EXECUTION_ALLOWED_CASE_CLASS_CONTRACT", details={"allowed_case_classes": allowed}),
        "excluded_case_class_contract": _contract_payload(base, "excluded_case_classes", schema_slug="excluded_case_classes", artifact_id="B04_R6_CANARY_EXECUTION_EXCLUDED_CASE_CLASS_CONTRACT", details={"excluded_case_classes": excluded}),
        "sample_limit_contract": _contract_payload(base, "sample_limits", schema_slug="sample_limits", artifact_id="B04_R6_CANARY_EXECUTION_SAMPLE_LIMIT_CONTRACT", details={"max_case_count_per_window": 12, "requires_future_validation": True}),
        "static_fallback_contract": _contract_payload(base, "static_fallback", schema_slug="static_fallback", artifact_id="B04_R6_CANARY_EXECUTION_STATIC_FALLBACK_CONTRACT", details={"static_fallback_required": True, "static_can_override_afsh": True}),
        "abstention_fallback_contract": _contract_payload(base, "abstention_fallback", schema_slug="abstention_fallback", artifact_id="B04_R6_CANARY_EXECUTION_ABSTENTION_FALLBACK_CONTRACT", details={"abstention_fallback_required": True, "human_review_boundary_preserved": True}),
        "null_route_preservation_contract": _contract_payload(base, "null_route_preservation", schema_slug="null_route_preservation", artifact_id="B04_R6_CANARY_EXECUTION_NULL_ROUTE_PRESERVATION_CONTRACT", details={"null_route_controls_excluded": True, "zero_null_route_selector_entries_required": True}),
        "operator_override_contract": _contract_payload(base, "operator_override", schema_slug="operator_override", artifact_id="B04_R6_CANARY_EXECUTION_OPERATOR_OVERRIDE_CONTRACT", details={"operator_override_required": True, "operator_can_freeze_canary": True}),
        "kill_switch_contract": _contract_payload(base, "kill_switch", schema_slug="kill_switch", artifact_id="B04_R6_CANARY_EXECUTION_KILL_SWITCH_CONTRACT", details={"kill_switch_required": True, "kill_switch_invocation_receipt_required": True}),
        "rollback_contract": _contract_payload(base, "rollback", schema_slug="rollback", artifact_id="B04_R6_CANARY_EXECUTION_ROLLBACK_CONTRACT", details={"rollback_required": True, "rollback_execution_receipt_required": True}),
        "route_distribution_health_thresholds": _contract_payload(base, "route_distribution_health", schema_slug="route_distribution_health", artifact_id="B04_R6_CANARY_EXECUTION_ROUTE_DISTRIBUTION_HEALTH_THRESHOLDS", details={"max_selector_entry_rate_delta_vs_shadow": 0.05, "zero_null_route_selector_entries_required": True, "freeze_on_unexplained_distribution_shift": True}),
        "drift_thresholds": _contract_payload(base, "drift", schema_slug="drift", artifact_id="B04_R6_CANARY_EXECUTION_DRIFT_THRESHOLDS", details={"max_unexplained_trace_delta": 0, "metric_widening_allowed": False, "comparator_weakening_allowed": False}),
        "incident_freeze_contract": _contract_payload(base, "incident_freeze", schema_slug="incident_freeze", artifact_id="B04_R6_CANARY_EXECUTION_INCIDENT_FREEZE_CONTRACT", details={"freeze_on_incident": True, "freeze_on_trace_incomplete": True, "freeze_on_boundary_drift": True}),
        "runtime_receipt_schema": _contract_payload(base, "runtime_receipt_schema", schema_slug="runtime_receipt_schema", artifact_id="B04_R6_CANARY_EXECUTION_RUNTIME_RECEIPT_SCHEMA", details=runtime_receipt_schema),
        "replay_manifest": _contract_payload(base, "replay_manifest", schema_slug="replay_manifest", artifact_id="B04_R6_CANARY_EXECUTION_REPLAY_MANIFEST", details={"raw_hash_bound_artifacts_required": True, "compressed_index_source_of_truth": False, "required_artifacts": expected_artifacts}),
        "expected_artifact_manifest": _contract_payload(base, "expected_artifacts", schema_slug="expected_artifacts", artifact_id="B04_R6_CANARY_EXECUTION_EXPECTED_ARTIFACT_MANIFEST", details={"expected_artifacts": expected_artifacts}),
        "external_verifier_requirements": _contract_payload(base, "external_verifier", schema_slug="external_verifier", artifact_id="B04_R6_CANARY_EXECUTION_EXTERNAL_VERIFIER_REQUIREMENTS", details={"external_verifier_required": True, "non_executing": True, "raw_hash_bound_bundle_required": True}),
        "result_interpretation_contract": _contract_payload(base, "result_interpretation", schema_slug="result_interpretation", artifact_id="B04_R6_CANARY_EXECUTION_RESULT_INTERPRETATION_CONTRACT", details={"success_outcome": "B04_R6_LIMITED_RUNTIME_CANARY_PASSED__CANARY_EVIDENCE_REVIEW_PACKET_NEXT", "failure_outcome": "B04_R6_LIMITED_RUNTIME_CANARY_FAILED__CANARY_REPAIR_OR_CLOSEOUT_NEXT", "invalidation_outcome": "B04_R6_LIMITED_RUNTIME_CANARY_INVALIDATED__FORENSIC_CANARY_INVALIDATION_COURT_NEXT", "pass_does_not_authorize_cutover": True}),
        "no_authorization_drift_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_execution.no_authorization_drift_receipt.v1",
            artifact_id="B04_R6_CANARY_EXECUTION_NO_AUTHORIZATION_DRIFT_RECEIPT",
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
            schema_id="kt.b04_r6.canary_execution.validation_plan.v1",
            artifact_id="B04_R6_CANARY_EXECUTION_VALIDATION_PLAN",
            validation_lane="VALIDATE_B04_R6_CANARY_EXECUTION_PACKET",
            required_checks=[row["name"] for row in base["validation_rows"]],
        ),
        "validation_reason_codes": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_execution.validation_reason_codes.v1",
            artifact_id="B04_R6_CANARY_EXECUTION_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
            terminal_defects=list(TERMINAL_DEFECTS),
        ),
        "paired_lane_compiler_scaffold_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.canary_execution.paired_lane_compiler_scaffold_receipt.v1",
            artifact_id="B04_R6_CANARY_EXECUTION_PAIRED_LANE_COMPILER_SCAFFOLD_RECEIPT",
            scaffold=base["paired_lane_compiler_scaffold"],
            scaffold_authority="PREP_ONLY_TOOLING",
            scaffold_can_authorize=False,
        ),
        "pipeline_board": _pipeline_board(base),
        "future_blocker_register": _future_blocker_register(base),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v27",
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


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Canary Execution Packet",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "This packet binds the validated canary authorization lane and defines exact canary execution law: "
            "mode, scope, case classes, sample limits, fallbacks, operator override, kill switch, rollback, "
            "route-distribution thresholds, drift thresholds, incident/freeze conditions, runtime receipts, "
            "replay manifest, expected artifacts, external verifier requirements, and result interpretation.",
            "",
            "It does not execute canary, does not authorize runtime cutover, does not open R6, does not authorize "
            "lobe escalation, does not promote package, and does not authorize commercial activation claims.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 canary execution packet")

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
    input_bindings = _input_bindings(root, handoff_git_commit=handoff_git_commit)
    binding_hashes = _binding_hashes(root, handoff_git_commit=handoff_git_commit)
    source_hashes = _validate_inputs(payloads, texts, binding_hashes, root)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_CANARY_EXEC_PACKET_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    paired_scaffold = _paired_compiler_scaffold(current_main_head)
    if paired_scaffold.get("authority") != "PREP_ONLY_TOOLING" or paired_scaffold.get("paired_lane_law", {}).get("compiler_can_authorize") is not False:
        _fail("RC_B04R6_CANARY_EXEC_PACKET_COMPILER_SCAFFOLD_MISSING", "paired compiler scaffold authority drift")

    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=input_bindings,
        binding_hashes=binding_hashes,
        source_hashes=source_hashes,
        validation_rows=_validation_rows(),
        paired_scaffold=paired_scaffold,
        trust_zone_validation=fresh_trust_validation,
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
    parser = argparse.ArgumentParser(description="Author B04 R6 canary execution packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
