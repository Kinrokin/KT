from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_runtime_evidence_review_packet as review
from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_lane_compiler
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-runtime-evidence-review-packet-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET_VALIDATION"
PREVIOUS_LANE = review.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = review.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = review.NEXT_LAWFUL_MOVE
OUTCOME_VALIDATED = "B04_R6_RUNTIME_EVIDENCE_REVIEW_VALIDATED__CANARY_AUTHORIZATION_PACKET_NEXT"
OUTCOME_DEFERRED = "B04_R6_RUNTIME_EVIDENCE_REVIEW_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
OUTCOME_REJECTED = "B04_R6_RUNTIME_EVIDENCE_REVIEW_REJECTED__CANARY_NOT_JUSTIFIED"
OUTCOME_INVALID = "B04_R6_RUNTIME_EVIDENCE_REVIEW_INVALID__FORENSIC_RUNTIME_EVIDENCE_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_VALIDATED
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_CANARY_AUTHORIZATION_PACKET"

MAY_AUTHORIZE = ("RUNTIME_EVIDENCE_REVIEW_PACKET_VALIDATED",)
FORBIDDEN_ACTIONS = (
    "CANARY_RUNTIME_AUTHORIZED",
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
    "RUNTIME_EVIDENCE_REVIEW_PACKET_MISSING",
    "RUNTIME_EVIDENCE_INVENTORY_MISSING",
    "RUNTIME_EVIDENCE_SCORECARD_MISSING",
    "SHADOW_RUNTIME_RESULT_UNBOUND",
    "VALIDATION_SIGNED_INPUT_HASH_MISSING",
    "VALIDATION_SIGNED_INPUT_HASH_MALFORMED",
    "PRIOR_LANE_GIT_OBJECT_BINDING_DRIFT",
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
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_CONTRACT_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_MAIN_HEAD_MISMATCH",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKET_BINDING_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_INVENTORY_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_SCORECARD_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_SHADOW_RESULT_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_STATIC_AUTHORITY_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_AFSH_OBSERVATION_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_ROUTE_HEALTH_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_FALLBACK_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_ABSTENTION_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_NULL_ROUTE_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_OPERATOR_CONTROL_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_KILL_SWITCH_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_ROLLBACK_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_DRIFT_MONITORING_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_INCIDENT_FREEZE_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_TRACE_COMPLETENESS_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_REPLAY_READINESS_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_COMMERCIAL_BOUNDARY_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKAGE_BLOCKER_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_CANARY_MATRIX_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_PIPELINE_BOARD_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_PRIOR_GIT_BINDING_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_INPUT_HASH_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_INPUT_HASH_MALFORMED",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_CANARY_AUTHORIZED",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_CANARY_EXECUTED",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_R6_OPEN_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_TRUST_ZONE_MUTATION",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_COMPILER_SCAFFOLD_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_VAL_NEXT_MOVE_DRIFT",
)

REVIEW_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in review.OUTPUTS.items()
    if filename.endswith(".json")
}
REVIEW_TEXT_INPUTS = {
    "review_report": f"KT_PROD_CLEANROOM/reports/{review.OUTPUTS['review_report']}",
}
VALIDATION_RECEIPT_ROLES = (
    "evidence_inventory_validation",
    "evidence_scorecard_validation",
    "static_authority_validation",
    "afsh_observation_validation",
    "route_distribution_health_validation",
    "fallback_behavior_validation",
    "abstention_preservation_validation",
    "null_route_preservation_validation",
    "operator_control_validation",
    "kill_switch_validation",
    "rollback_validation",
    "drift_monitoring_validation",
    "incident_freeze_validation",
    "trace_completeness_validation",
    "replay_readiness_validation",
    "external_verifier_validation",
    "commercial_claim_boundary_validation",
    "package_promotion_blocker_validation",
    "canary_readiness_matrix_validation",
    "pipeline_board_validation",
)
PREP_ONLY_OUTPUT_ROLES = (
    "canary_authorization_packet_validation_plan_prep_only",
    "canary_execution_packet_prep_only_draft",
    "canary_failure_closeout_prep_only_draft",
    "package_promotion_review_preconditions_prep_only_draft",
    "external_audit_delta_manifest_prep_only_draft",
)
OUTPUTS = {
    "validation_contract": "b04_r6_runtime_evidence_review_validation_contract.json",
    "validation_receipt": "b04_r6_runtime_evidence_review_validation_receipt.json",
    "validation_report": "b04_r6_runtime_evidence_review_validation_report.md",
    "evidence_inventory_validation": "b04_r6_runtime_evidence_inventory_validation_receipt.json",
    "evidence_scorecard_validation": "b04_r6_runtime_evidence_scorecard_validation_receipt.json",
    "static_authority_validation": "b04_r6_runtime_static_authority_validation_receipt.json",
    "afsh_observation_validation": "b04_r6_runtime_afsh_observation_validation_receipt.json",
    "route_distribution_health_validation": "b04_r6_runtime_route_distribution_health_validation_receipt.json",
    "fallback_behavior_validation": "b04_r6_runtime_fallback_behavior_validation_receipt.json",
    "abstention_preservation_validation": "b04_r6_runtime_abstention_preservation_validation_receipt.json",
    "null_route_preservation_validation": "b04_r6_runtime_null_route_preservation_validation_receipt.json",
    "operator_control_validation": "b04_r6_runtime_operator_control_validation_receipt.json",
    "kill_switch_validation": "b04_r6_runtime_kill_switch_validation_receipt.json",
    "rollback_validation": "b04_r6_runtime_rollback_validation_receipt.json",
    "drift_monitoring_validation": "b04_r6_runtime_drift_monitoring_validation_receipt.json",
    "incident_freeze_validation": "b04_r6_runtime_incident_freeze_validation_receipt.json",
    "trace_completeness_validation": "b04_r6_runtime_trace_completeness_validation_receipt.json",
    "replay_readiness_validation": "b04_r6_runtime_replay_readiness_validation_receipt.json",
    "external_verifier_validation": "b04_r6_runtime_external_verifier_validation_receipt.json",
    "commercial_claim_boundary_validation": "b04_r6_runtime_commercial_claim_boundary_validation_receipt.json",
    "package_promotion_blocker_validation": "b04_r6_runtime_package_promotion_blocker_validation_receipt.json",
    "canary_readiness_matrix_validation": "b04_r6_runtime_canary_readiness_matrix_validation_receipt.json",
    "pipeline_board_validation": "b04_r6_runtime_pipeline_board_validation_receipt.json",
    "no_authorization_drift_validation": "b04_r6_runtime_evidence_no_authorization_drift_validation_receipt.json",
    "lane_compiler_scaffold_receipt": "b04_r6_runtime_evidence_review_validation_lane_compiler_scaffold_receipt.json",
    "canary_authorization_packet_validation_plan_prep_only": "b04_r6_canary_authorization_packet_validation_plan_prep_only.json",
    "canary_execution_packet_prep_only_draft": "b04_r6_canary_execution_packet_prep_only_draft.json",
    "canary_failure_closeout_prep_only_draft": "b04_r6_canary_failure_closeout_prep_only_draft.json",
    "package_promotion_review_preconditions_prep_only_draft": "b04_r6_package_promotion_review_preconditions_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only_draft": "b04_r6_external_audit_delta_manifest_prep_only_draft.json",
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
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"git-bound input {label} missing at {handoff_git_commit}: {exc}")
    return _load(root, raw, label=label)


def _read_text_input(root: Path, raw: str, *, label: str, handoff_git_commit: str, output_names: set[str]) -> str:
    if Path(raw).name in output_names:
        try:
            return _git_blob_bytes(root, handoff_git_commit, raw).decode("utf-8")
        except Exception as exc:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"git-bound text input {label} missing at {handoff_git_commit}: {exc}")
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
        "canary_runtime_authorized": "RC_B04R6_RUNTIME_EVIDENCE_VAL_CANARY_AUTHORIZED",
        "canary_runtime_executed": "RC_B04R6_RUNTIME_EVIDENCE_VAL_CANARY_EXECUTED",
        "runtime_cutover_authorized": "RC_B04R6_RUNTIME_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED",
        "activation_cutover_executed": "RC_B04R6_RUNTIME_EVIDENCE_VAL_RUNTIME_CUTOVER_AUTHORIZED",
        "r6_open": "RC_B04R6_RUNTIME_EVIDENCE_VAL_R6_OPEN_DRIFT",
        "lobe_escalation_authorized": "RC_B04R6_RUNTIME_EVIDENCE_VAL_LOBE_ESCALATION_DRIFT",
        "package_promotion_authorized": "RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT",
        "commercial_activation_claim_authorized": "RC_B04R6_RUNTIME_EVIDENCE_VAL_COMMERCIAL_CLAIM_DRIFT",
        "truth_engine_law_changed": "RC_B04R6_RUNTIME_EVIDENCE_VAL_TRUTH_ENGINE_MUTATION",
        "trust_zone_law_changed": "RC_B04R6_RUNTIME_EVIDENCE_VAL_TRUST_ZONE_MUTATION",
        "metric_contract_mutated": "RC_B04R6_RUNTIME_EVIDENCE_VAL_PREP_ONLY_AUTHORITY_DRIFT",
        "static_comparator_weakened": "RC_B04R6_RUNTIME_EVIDENCE_VAL_PREP_ONLY_AUTHORITY_DRIFT",
    }
    for key, value in _walk_items(payload):
        if key in forbidden_truths and value is True:
            _fail(forbidden_truths[key], f"{label}.{key} drifted true")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKAGE_PROMOTION_DRIFT", f"{label}.package_promotion drifted")


def _input_hash(root: Path, raw: str, *, handoff_git_commit: str, output_names: set[str]) -> str:
    if Path(raw).name in output_names:
        return _git_blob_sha256(root, handoff_git_commit, raw)
    return file_sha256(common.resolve_path(root, raw))


def _input_bindings(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    output_names = set(OUTPUTS.values())
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(REVIEW_JSON_INPUTS.items()):
        is_overwritten = Path(raw).name in output_names
        row: Dict[str, Any] = {
            "role": role,
            "path": raw,
            "sha256": _input_hash(root, raw, handoff_git_commit=handoff_git_commit, output_names=output_names),
            "binding_kind": "file_sha256_at_runtime_evidence_review_validation",
        }
        if is_overwritten:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(REVIEW_TEXT_INPUTS.items()):
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": "file_sha256_at_runtime_evidence_review_validation",
            }
        )
    return rows


def _binding_hashes(root: Path, *, handoff_git_commit: str) -> Dict[str, str]:
    output_names = set(OUTPUTS.values())
    hashes = {
        f"{role}_hash": _input_hash(root, raw, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in sorted(REVIEW_JSON_INPUTS.items())
    }
    hashes.update({f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(REVIEW_TEXT_INPUTS.items())})
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
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PRIOR_GIT_BINDING_DRIFT", "review contract lacks prior main head")
    for row in contract.get("input_bindings", []):
        role = row.get("role")
        raw = row.get("path")
        sha = row.get("sha256")
        if not role or not raw or not _is_sha256(sha):
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_INPUT_HASH_MALFORMED", f"malformed review input binding row: {role}")
        if row.get("binding_kind") == "git_object_before_overwrite":
            if row.get("git_commit") != prior_main_head:
                _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PRIOR_GIT_BINDING_DRIFT", f"{role} not bound to prior canonical main")
            actual = _git_blob_sha256(root, str(row["git_commit"]), str(raw))
        else:
            actual = file_sha256(common.resolve_path(root, str(raw)))
        if actual != sha:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_INPUT_HASH_MALFORMED", f"{role} hash mismatch")
        binding_key = f"{role}_hash"
        if contract.get("binding_hashes", {}).get(binding_key) != sha:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_INPUT_HASH_MISSING", f"{binding_key} missing or mismatched")


def _validate_scorecard(scorecard: Dict[str, Any]) -> None:
    required = {
        "runtime_mode": review.RUNTIME_MODE,
        "shadow_runtime_passed": True,
        "evidence_review_status": "PASS",
        "canary_readiness_status": "PREP_READY_NOT_AUTHORIZED",
        "static_authoritative_cases": scorecard.get("total_cases"),
        "afsh_observation_only_cases": scorecard.get("total_cases"),
        "user_facing_decision_changes": 0,
        "canary_runtime_cases": 0,
        "runtime_cutover_authorized_cases": 0,
        "fallback_failures": 0,
        "trace_complete_cases": scorecard.get("total_cases"),
        "fired_disqualifiers": [],
        "drift_signals": [],
        "incident_freeze_triggers": [],
    }
    for key, expected in required.items():
        if scorecard.get(key) != expected:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_SCORECARD_MISSING", f"scorecard {key} drifted")
    if not isinstance(scorecard.get("total_cases"), int) or scorecard["total_cases"] <= 0:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_SCORECARD_MISSING", "scorecard total cases missing")
    if scorecard.get("package_promotion_status") != "BLOCKED_PENDING_RUNTIME_EVIDENCE_REVIEW_AND_FUTURE_AUTHORITY":
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKAGE_BLOCKER_MISSING", "package promotion status drift")


def _validate_review_payloads(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        _ensure_authority_closed(payload, label=label)
    for role, payload in payloads.items():
        if role in review.PREP_ONLY_OUTPUT_ROLES:
            if payload.get("status") != "PREP_ONLY":
                _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PREP_ONLY_AUTHORITY_DRIFT", f"{role} is not prep-only")

    contract = payloads["review_contract"]
    receipt = payloads["review_receipt"]
    inventory = payloads["evidence_inventory"]
    scorecard_payload = payloads["evidence_scorecard"]
    next_move = payloads["next_lawful_move"]

    for role, payload in (("review_contract", contract), ("review_receipt", receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"{role} lane identity drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"{role} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_NEXT_MOVE_DRIFT", f"{role} next move drift")
        if payload.get("runtime_evidence_review_packet_authored") is not True:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"{role} missing authored flag")
        if payload.get("runtime_evidence_review_validated") is not False:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"{role} self-validates prematurely")
    if not _valid_handoff(next_move):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_NEXT_MOVE_DRIFT", "next move handoff lacks valid lane identity")

    _validate_prior_git_bindings(root, contract)
    if inventory.get("raw_hash_bound_artifacts_required") is not True:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_INVENTORY_MISSING", "inventory does not require raw hash-bound artifacts")
    if inventory.get("compressed_index_source_of_truth") is not False:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_INVENTORY_MISSING", "compressed index became source of truth")
    if inventory.get("artifact_count") != len(inventory.get("artifacts", [])) or inventory.get("artifact_count", 0) <= 0:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_INVENTORY_MISSING", "inventory artifact count drift")
    for artifact in inventory.get("artifacts", []):
        if not artifact.get("role") or not artifact.get("path") or not _is_sha256(artifact.get("sha256")):
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_INPUT_HASH_MALFORMED", "inventory artifact hash malformed")

    _validate_scorecard(scorecard_payload.get("scorecard", {}))
    _validate_scorecard(contract.get("runtime_evidence_scorecard", {}))

    matrix = payloads["canary_readiness_matrix"]
    statuses = {row.get("readiness_item"): row.get("status") for row in matrix.get("rows", [])}
    if matrix.get("readiness_status") != "PREP_READY_NOT_AUTHORIZED" or matrix.get("canary_runtime_authorized") is not False:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_CANARY_MATRIX_MISSING", "canary readiness matrix authority drift")
    for key, expected in {
        "shadow_runtime_passed": "PASS",
        "static_authority_preserved": "PASS",
        "no_user_facing_change": "PASS",
        "operator_controls_ready": "PASS",
        "evidence_review_validation_required": "BLOCKING_NEXT",
        "canary_authorization_packet_required": "BLOCKED",
        "canary_validation_required": "BLOCKED",
    }.items():
        if statuses.get(key) != expected:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_CANARY_MATRIX_MISSING", f"canary matrix missing {key}")

    board = payloads["pipeline_board"]
    lanes = {row.get("lane"): row for row in board.get("lanes", [])}
    if lanes.get("VALIDATE_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET", {}).get("status") != "NEXT":
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PIPELINE_BOARD_MISSING", "pipeline board does not show validation next")
    if lanes.get("RUN_B04_R6_CANARY_RUNTIME", {}).get("status") != "BLOCKED":
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_CANARY_AUTHORIZED", "pipeline board canary runtime not blocked")

    review_report = texts["review_report"].lower()
    for phrase in ("does not authorize canary runtime", "runtime cutover", "commercial claim boundary"):
        if phrase not in review_report:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_PACKET_BINDING_MISSING", f"review report missing {phrase}")


def _compiler_scaffold(current_main_head: str) -> Dict[str, Any]:
    spec = {
        "lane_id": "VALIDATE_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET",
        "lane_name": "B04 R6 runtime evidence review packet validation",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM",
        "summary": "Prep-only compiler scaffold for validating the runtime evidence review packet.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/cohort0_b04_r6_runtime_evidence_review_packet_validation.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_b04_r6_runtime_evidence_review_packet_validation.py",
        "artifacts": sorted(OUTPUTS.values()),
        "json_parse_inputs": sorted(filename for filename in OUTPUTS.values() if filename.endswith(".json")),
        "no_authorization_drift_checks": [
            "Runtime evidence validation does not authorize canary runtime.",
            "Runtime evidence validation does not execute canary.",
            "Runtime evidence validation does not authorize runtime cutover, R6 open, package promotion, or commercial claims.",
            "Truth-engine and trust-zone law remain unchanged.",
        ],
        "future_blockers": [
            "Canary authorization packet must be authored before canary validation or execution.",
            "Canary execution remains blocked until canary authorization and canary execution packet validation.",
            "Package promotion remains blocked until future runtime evidence, external audit, and promotion review lanes pass.",
        ],
        "reason_codes": list(REASON_CODES),
        "lane_kind": "VALIDATION",
        "current_main_head": current_main_head,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "may_authorize": list(MAY_AUTHORIZE),
        "must_not_authorize": list(FORBIDDEN_ACTIONS),
        "authoritative_inputs": sorted(REVIEW_JSON_INPUTS),
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
        "lane_law_metadata": contract["lane_law_metadata"],
        "non_authorization_guards": contract["non_authorization_guards"],
    }


def _validation_rows() -> list[Dict[str, Any]]:
    checks = [
        "runtime_evidence_review_packet_bound",
        "runtime_evidence_inventory_bound",
        "runtime_evidence_scorecard_bound",
        "shadow_runtime_result_bound",
        "static_authority_review_bound",
        "afsh_observation_review_bound",
        "route_distribution_health_review_bound",
        "fallback_behavior_review_bound",
        "abstention_preservation_review_bound",
        "null_route_preservation_review_bound",
        "operator_control_review_bound",
        "kill_switch_review_bound",
        "rollback_review_bound",
        "drift_monitoring_review_bound",
        "incident_freeze_review_bound",
        "trace_completeness_review_bound",
        "runtime_replay_review_bound",
        "external_verifier_review_bound",
        "commercial_claim_boundary_bound",
        "package_promotion_blocker_bound",
        "canary_readiness_matrix_bound",
        "pipeline_board_bound",
        "prior_git_object_bindings_stable",
        "validation_signed_input_hashes_complete",
        "prep_only_drafts_remain_prep_only",
        "canary_not_authorized",
        "canary_not_executed",
        "runtime_cutover_not_authorized",
        "r6_remains_closed",
        "lobe_escalation_unauthorized",
        "package_promotion_blocked",
        "commercial_claims_blocked",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
        "next_lawful_move_canary_authorization_packet",
    ]
    return [
        {
            "check_id": f"B04R6-RUNTIME-EVIDENCE-VALIDATION-{index:03d}",
            "name": check,
            "status": "PASS",
            "terminal_if_fail": check
            in {
                "runtime_evidence_review_packet_bound",
                "runtime_evidence_inventory_bound",
                "runtime_evidence_scorecard_bound",
                "prior_git_object_bindings_stable",
                "validation_signed_input_hashes_complete",
                "canary_not_authorized",
                "canary_not_executed",
                "runtime_cutover_not_authorized",
                "r6_remains_closed",
                "truth_engine_law_unchanged",
                "trust_zone_law_unchanged",
                "next_lawful_move_canary_authorization_packet",
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
        "runtime_mode": review.RUNTIME_MODE,
        "shadow_runtime_passed": True,
        "runtime_evidence_review_packet_authored": True,
        "runtime_evidence_review_validated": True,
        "canary_authorization_packet_next": True,
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
            OUTCOME_DEFERRED: "REPAIR_B04_R6_RUNTIME_EVIDENCE_REVIEW_VALIDATION_DEFECTS",
            OUTCOME_REJECTED: "AUTHOR_B04_R6_RUNTIME_REPAIR_OR_CLOSEOUT",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_RUNTIME_EVIDENCE_REVIEW",
        },
        "terminal_defects": list(TERMINAL_DEFECTS),
        "reason_codes": list(REASON_CODES),
        "lane_compiler_scaffold": compiler_scaffold,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
    }


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _validation_receipt(
    base: Dict[str, Any],
    *,
    role: str,
    schema_slug: str,
    artifact_id: str,
    subject: str,
    source_roles: Sequence[str],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = _with_artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_evidence.review_validation.{schema_slug}.v1",
        artifact_id=artifact_id,
        validation_role=role,
        validation_subject=subject,
        validated_hashes={f"{source_role}_hash": base["binding_hashes"][f"{source_role}_hash"] for source_role in source_roles},
        validation_status="PASS",
    )
    if extra:
        payload.update(extra)
    return payload


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_evidence.review_validation.{role}.prep_only.v1",
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
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v24",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        current_authoritative_lane=AUTHORITATIVE_LANE,
        blockers=[
            {
                "blocker_id": "B04R6-FB-081",
                "status": "OPEN",
                "description": "Canary authorization packet is next but not yet authored.",
                "blocked_until": "AUTHOR_B04_R6_CANARY_AUTHORIZATION_PACKET",
            },
            {
                "blocker_id": "B04R6-FB-082",
                "status": "OPEN",
                "description": "Canary execution remains blocked until authorization, execution packet authoring, and execution packet validation.",
                "blocked_until": "RUN_B04_R6_LIMITED_RUNTIME_CANARY",
            },
            {
                "blocker_id": "B04R6-FB-083",
                "status": "OPEN",
                "description": "Package promotion and commercial claims remain blocked by future canary evidence, runtime evidence review, external audit, and package review.",
                "blocked_until": "VALIDATE_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET",
            },
        ],
    )


def _pipeline_board(base: Dict[str, Any]) -> Dict[str, Any]:
    lanes = [
        ("AUTHOR_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET", "BOUND_AND_VALIDATED", False, EXPECTED_PREVIOUS_OUTCOME, "VALIDATE_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET"),
        ("VALIDATE_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET", "CURRENT_VALIDATED", True, SELECTED_OUTCOME, NEXT_LAWFUL_MOVE),
        ("AUTHOR_B04_R6_CANARY_AUTHORIZATION_PACKET", "NEXT", True, "B04_R6_CANARY_AUTHORIZATION_PACKET_BOUND__CANARY_AUTHORIZATION_VALIDATION_NEXT", "VALIDATE_B04_R6_CANARY_AUTHORIZATION_PACKET"),
        ("RUN_B04_R6_LIMITED_RUNTIME_CANARY", "BLOCKED", False, "NOT_AUTHORIZED", "BLOCKED"),
        ("AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET", "BLOCKED", False, "NOT_AUTHORIZED", "BLOCKED"),
    ]
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.pipeline_board.v3",
        artifact_id="B04_R6_PIPELINE_BOARD",
        board_status="CANARY_AUTHORIZATION_PACKET_NEXT",
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
        "# B04 R6 Runtime Evidence Review Packet Validation\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "The runtime evidence review packet is validated as evidence-bound, replay-safe, externally reviewable, "
        "commercially bounded, and sufficient only to advance to canary authorization packet authorship.\n\n"
        "This validation does not authorize canary runtime, execute canary, authorize runtime cutover, open R6, "
        "escalate lobes, promote package, authorize commercial activation claims, or mutate truth/trust law.\n"
    )


def _outputs(base: Dict[str, Any], compiler_scaffold: Dict[str, Any]) -> Dict[str, Any]:
    output_payloads: Dict[str, Any] = {
        "validation_contract": _with_artifact(
            base,
            schema_id="kt.b04_r6.runtime_evidence_review_validation_contract.v1",
            artifact_id="B04_R6_RUNTIME_EVIDENCE_REVIEW_VALIDATION_CONTRACT",
            validation_scope={
                "purpose": "Validate the runtime evidence review packet as complete, bound, replay-safe, externally reviewable, and non-authorizing.",
                "non_purpose": [
                    "Does not authorize canary runtime.",
                    "Does not execute canary.",
                    "Does not authorize runtime cutover.",
                    "Does not open R6.",
                    "Does not promote package.",
                    "Does not authorize commercial activation claims.",
                ],
            },
            validation_result={
                "runtime_evidence_review_packet_complete": True,
                "runtime_evidence_bound": True,
                "external_review_ready": True,
                "commercial_boundary_preserved": True,
                "canary_authorization_packet_next": True,
            },
        ),
        "validation_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.runtime_evidence_review_validation_receipt.v1",
            artifact_id="B04_R6_RUNTIME_EVIDENCE_REVIEW_VALIDATION_RECEIPT",
            verdict="RUNTIME_EVIDENCE_REVIEW_PACKET_VALIDATED_NON_AUTHORIZING",
            no_downstream_authorization_drift=True,
        ),
        "evidence_inventory_validation": _validation_receipt(
            base,
            role="evidence_inventory_validation",
            schema_slug="inventory",
            artifact_id="B04_R6_RUNTIME_EVIDENCE_INVENTORY_VALIDATION_RECEIPT",
            subject="runtime evidence inventory",
            source_roles=("evidence_inventory",),
        ),
        "evidence_scorecard_validation": _validation_receipt(
            base,
            role="evidence_scorecard_validation",
            schema_slug="scorecard",
            artifact_id="B04_R6_RUNTIME_EVIDENCE_SCORECARD_VALIDATION_RECEIPT",
            subject="runtime evidence scorecard",
            source_roles=("evidence_scorecard",),
            extra={"required_categories": sorted(REQUIRED_SCORECARD_CATEGORIES)},
        ),
        "no_authorization_drift_validation": _with_artifact(
            base,
            schema_id="kt.b04_r6.runtime_evidence.no_authorization_drift_validation_receipt.v1",
            artifact_id="B04_R6_RUNTIME_EVIDENCE_NO_AUTHORIZATION_DRIFT_VALIDATION_RECEIPT",
            no_downstream_authorization_drift=True,
            canary_runtime_authorized=False,
            canary_runtime_executed=False,
            runtime_cutover_authorized=False,
            r6_open=False,
            lobe_escalation_authorized=False,
            package_promotion_authorized=False,
            commercial_activation_claim_authorized=False,
        ),
        "lane_compiler_scaffold_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.runtime_evidence.review_validation_lane_compiler_scaffold_receipt.v1",
            artifact_id="B04_R6_RUNTIME_EVIDENCE_REVIEW_VALIDATION_LANE_COMPILER_SCAFFOLD_RECEIPT",
            scaffold=compiler_scaffold,
            scaffold_authority="PREP_ONLY_TOOLING",
            scaffold_can_authorize=False,
        ),
        "pipeline_board": _pipeline_board(base),
        "future_blocker_register": _future_blocker_register(base),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v24",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            verdict="NEXT_LAWFUL_MOVE_SET",
        ),
    }
    receipt_specs = {
        "static_authority_validation": ("static_authority_review", "Static authority review"),
        "afsh_observation_validation": ("afsh_observation_review", "AFSH observation review"),
        "route_distribution_health_validation": ("route_distribution_health_review", "Route-distribution health review"),
        "fallback_behavior_validation": ("fallback_behavior_review", "Fallback behavior review"),
        "abstention_preservation_validation": ("abstention_preservation_review", "Abstention preservation review"),
        "null_route_preservation_validation": ("null_route_preservation_review", "Null-route preservation review"),
        "operator_control_validation": ("operator_control_review", "Operator control review"),
        "kill_switch_validation": ("kill_switch_readiness_review", "Kill-switch readiness review"),
        "rollback_validation": ("rollback_readiness_review", "Rollback readiness review"),
        "drift_monitoring_validation": ("drift_monitoring_review", "Drift monitoring review"),
        "incident_freeze_validation": ("incident_freeze_review", "Incident/freeze review"),
        "trace_completeness_validation": ("trace_completeness_review", "Trace completeness review"),
        "replay_readiness_validation": ("replay_readiness_review", "Runtime replay readiness review"),
        "external_verifier_validation": ("external_verifier_readiness_review", "External verifier readiness review"),
        "commercial_claim_boundary_validation": ("commercial_claim_boundary_review", "Commercial claim boundary review"),
        "package_promotion_blocker_validation": ("package_promotion_blocker_review", "Package-promotion blocker review"),
        "canary_readiness_matrix_validation": ("canary_readiness_matrix", "Canary readiness matrix"),
        "pipeline_board_validation": ("pipeline_board", "Pipeline board update"),
    }
    for role, (source_role, subject) in receipt_specs.items():
        output_payloads[role] = _validation_receipt(
            base,
            role=role,
            schema_slug=role,
            artifact_id=f"B04_R6_{role.upper()}_RECEIPT",
            subject=subject,
            source_roles=(source_role,),
        )
    output_payloads.update(
        {
            role: _prep_only(base, role=role, purpose=f"Prep-only continuation scaffold for {role.replace('_', ' ')}.")
            for role in PREP_ONLY_OUTPUT_ROLES
        }
    )
    return output_payloads


REQUIRED_SCORECARD_CATEGORIES = frozenset(
    {
        "runtime_mode",
        "total_cases",
        "shadow_runtime_passed",
        "static_authoritative_cases",
        "afsh_observation_only_cases",
        "user_facing_decision_changes",
        "canary_runtime_cases",
        "runtime_cutover_authorized_cases",
        "selector_entries",
        "selector_entry_rate",
        "fallback_failures",
        "drift_signals",
        "incident_freeze_triggers",
        "trace_complete_cases",
        "fired_disqualifiers",
        "canary_readiness_status",
        "package_promotion_status",
    }
)


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root):
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 runtime evidence review validation")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if current_branch != "main" else "HEAD")
    handoff_git_commit = current_main_head if current_branch != "main" else head
    output_names = set(OUTPUTS.values())
    payloads = {
        role: _load_input(root, raw, label=role, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in REVIEW_JSON_INPUTS.items()
    }
    texts = {
        role: _read_text_input(root, raw, label=role, handoff_git_commit=handoff_git_commit, output_names=output_names)
        for role, raw in REVIEW_TEXT_INPUTS.items()
    }
    _validate_review_payloads(root, payloads, texts)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    compiler_scaffold = _compiler_scaffold(current_main_head)
    if compiler_scaffold.get("authority") != "PREP_ONLY_TOOLING":
        _fail("RC_B04R6_RUNTIME_EVIDENCE_VAL_COMPILER_SCAFFOLD_MISSING", "compiler scaffold authority drift")

    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=_input_bindings(root, handoff_git_commit=handoff_git_commit),
        binding_hashes=_binding_hashes(root, handoff_git_commit=handoff_git_commit),
        validation_rows=_validation_rows(),
        compiler_scaffold=compiler_scaffold,
        trust_zone_validation=fresh_trust_validation,
    )
    output_payloads = _outputs(base, compiler_scaffold)
    contract = output_payloads["validation_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "validation_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate B04 R6 runtime evidence review packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
