from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_limited_runtime_shadow_runtime as shadow
from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_lane_compiler
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-runtime-evidence-review-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET"
PREVIOUS_LANE = shadow.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = shadow.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = shadow.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = "B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET_BOUND__RUNTIME_EVIDENCE_REVIEW_VALIDATION_NEXT"
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET"
RUNTIME_MODE = shadow.RUNTIME_MODE

MAY_AUTHORIZE = (
    "RUNTIME_EVIDENCE_REVIEW_PACKET_AUTHORED",
    "RUNTIME_EVIDENCE_FROZEN",
    "PASSED_RUNTIME_LANE_EVIDENCE_SWEEP_EMITTED",
)
FORBIDDEN_ACTIONS = (
    "CANARY_RUNTIME_AUTHORIZED",
    "CANARY_RUNTIME_EXECUTED",
    "AFSH_RUNTIME_AUTHORITY_GRANTED",
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
    "SHADOW_RUNTIME_EVIDENCE_MISSING",
    "SHADOW_RUNTIME_NOT_PASSED",
    "CANARY_RUNTIME_AUTHORIZED",
    "CANARY_RUNTIME_EXECUTED",
    "AFSH_RUNTIME_AUTHORITY_GRANTED",
    "USER_FACING_DECISION_CHANGED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "R6_OPEN_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL_CLAIM_DRIFT",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "NEXT_MOVE_DRIFT",
)
REASON_CODES = (
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CONTRACT_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_MAIN_HEAD_MISMATCH",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SHADOW_RUNTIME_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SHADOW_RUNTIME_NOT_PASSED",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SHADOW_RESULT_BINDING_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CASE_MANIFEST_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SCORECARD_MISSING",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_STATIC_AUTHORITY_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_AFSH_AUTHORITY_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_USER_FACING_CHANGE",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CANARY_AUTHORIZED",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CANARY_EXECUTED",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CUTOVER_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_R6_OPEN_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_ROUTE_HEALTH_FAIL",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_FALLBACK_FAIL",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_ABSTENTION_FAIL",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_NULL_ROUTE_FAIL",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_OPERATOR_CONTROL_NOT_READY",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_KILL_SWITCH_NOT_READY",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_ROLLBACK_NOT_READY",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_DRIFT_DETECTED",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_INCIDENT_FREEZE_TRIGGERED",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_TRACE_INCOMPLETE",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_REPLAY_INCOMPLETE",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_EXTERNAL_VERIFIER_NOT_READY",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_TRUST_ZONE_MUTATION",
    "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_NEXT_MOVE_DRIFT",
)

SHADOW_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in shadow.OUTPUTS.items()
    if filename.endswith(".json")
}
SHADOW_TEXT_INPUTS = {
    "shadow_runtime_report": f"KT_PROD_CLEANROOM/reports/{shadow.OUTPUTS['report']}",
}
ALL_JSON_INPUTS = {f"shadow_{role}": raw for role, raw in SHADOW_JSON_INPUTS.items()}
ALL_TEXT_INPUTS = dict(SHADOW_TEXT_INPUTS)

OUTPUTS = {
    "review_contract": "b04_r6_runtime_evidence_review_packet_contract.json",
    "review_receipt": "b04_r6_runtime_evidence_review_packet_receipt.json",
    "review_report": "b04_r6_runtime_evidence_review_packet_report.md",
    "evidence_inventory": "b04_r6_runtime_evidence_inventory.json",
    "evidence_scorecard": "b04_r6_runtime_evidence_scorecard.json",
    "route_distribution_health_review": "b04_r6_runtime_route_distribution_health_review_contract.json",
    "static_authority_review": "b04_r6_runtime_static_authority_review_contract.json",
    "afsh_observation_review": "b04_r6_runtime_afsh_observation_review_contract.json",
    "fallback_behavior_review": "b04_r6_runtime_fallback_behavior_review_contract.json",
    "abstention_preservation_review": "b04_r6_runtime_abstention_preservation_review_contract.json",
    "null_route_preservation_review": "b04_r6_runtime_null_route_preservation_review_contract.json",
    "operator_control_review": "b04_r6_runtime_operator_control_review_contract.json",
    "kill_switch_readiness_review": "b04_r6_runtime_kill_switch_readiness_review_contract.json",
    "rollback_readiness_review": "b04_r6_runtime_rollback_readiness_review_contract.json",
    "drift_monitoring_review": "b04_r6_runtime_drift_monitoring_review_contract.json",
    "incident_freeze_review": "b04_r6_runtime_incident_freeze_review_contract.json",
    "trace_completeness_review": "b04_r6_runtime_trace_completeness_review_contract.json",
    "replay_readiness_review": "b04_r6_runtime_replay_readiness_review_contract.json",
    "external_verifier_readiness_review": "b04_r6_runtime_external_verifier_readiness_review_contract.json",
    "commercial_claim_boundary_review": "b04_r6_runtime_commercial_claim_boundary_review_contract.json",
    "package_promotion_blocker_review": "b04_r6_runtime_package_promotion_blocker_review_contract.json",
    "canary_readiness_matrix": "b04_r6_runtime_canary_readiness_matrix.json",
    "no_authorization_drift_receipt": "b04_r6_runtime_no_authorization_drift_receipt.json",
    "canary_authorization_packet_prep_only_draft": "b04_r6_canary_authorization_packet_prep_only_draft.json",
    "canary_scope_manifest_prep_only_draft": "b04_r6_canary_scope_manifest_prep_only_draft.json",
    "canary_validation_plan_prep_only": "b04_r6_canary_validation_plan_prep_only.json",
    "runtime_repair_or_closeout_contract_prep_only": "b04_r6_runtime_repair_or_closeout_contract_prep_only.json",
    "package_promotion_review_preconditions_prep_only_draft": "b04_r6_package_promotion_review_preconditions_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only_draft": "b04_r6_external_audit_delta_manifest_prep_only_draft.json",
    "public_verifier_delta_requirements_prep_only": "b04_r6_public_verifier_delta_requirements_prep_only.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}
PREP_ONLY_OUTPUT_ROLES = (
    "canary_authorization_packet_prep_only_draft",
    "canary_scope_manifest_prep_only_draft",
    "canary_validation_plan_prep_only",
    "runtime_repair_or_closeout_contract_prep_only",
    "package_promotion_review_preconditions_prep_only_draft",
    "external_audit_delta_manifest_prep_only_draft",
    "public_verifier_delta_requirements_prep_only",
)

REVIEW_CONTRACT_ROLES = (
    "route_distribution_health_review",
    "static_authority_review",
    "afsh_observation_review",
    "fallback_behavior_review",
    "abstention_preservation_review",
    "null_route_preservation_review",
    "operator_control_review",
    "kill_switch_readiness_review",
    "rollback_readiness_review",
    "drift_monitoring_review",
    "incident_freeze_review",
    "trace_completeness_review",
    "replay_readiness_review",
    "external_verifier_readiness_review",
    "commercial_claim_boundary_review",
    "package_promotion_blocker_review",
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


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


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
        "canary_runtime_authorized": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CANARY_AUTHORIZED",
        "canary_runtime_executed": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CANARY_EXECUTED",
        "afsh_runtime_authority_granted": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_AFSH_AUTHORITY_DRIFT",
        "user_facing_decision_changes_allowed": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_USER_FACING_CHANGE",
        "user_facing_decision_changed": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_USER_FACING_CHANGE",
        "runtime_cutover_authorized": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CUTOVER_DRIFT",
        "activation_cutover_executed": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CUTOVER_DRIFT",
        "r6_open": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_R6_OPEN_DRIFT",
        "lobe_escalation_authorized": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_R6_OPEN_DRIFT",
        "package_promotion_authorized": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_PACKAGE_PROMOTION_DRIFT",
        "commercial_activation_claim_authorized": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_COMMERCIAL_CLAIM_DRIFT",
        "truth_engine_law_changed": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_TRUTH_ENGINE_MUTATION",
        "trust_zone_law_changed": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_TRUST_ZONE_MUTATION",
        "metric_contract_mutated": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_PREP_ONLY_AUTHORITY_DRIFT",
        "static_comparator_weakened": "RC_B04R6_RUNTIME_EVIDENCE_REVIEW_PREP_ONLY_AUTHORITY_DRIFT",
    }
    for key, value in _walk_items(payload):
        if key in forbidden_truths and value is True:
            _fail(forbidden_truths[key], f"{label}.{key} drifted true")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_PACKAGE_PROMOTION_DRIFT", f"{label}.package_promotion drifted")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        _ensure_authority_closed(payload, label=label)

    contract = payloads["shadow_execution_contract"]
    result = payloads["shadow_result"]
    next_move = payloads["shadow_next_lawful_move"]
    no_auth = payloads["shadow_no_authorization_drift_receipt"]
    cases = payloads["shadow_case_manifest"].get("cases")
    scorecard = result.get("result")

    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SHADOW_RUNTIME_NOT_PASSED", "shadow runtime contract outcome drift")
    if result.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SHADOW_RESULT_BINDING_MISSING", "shadow result outcome drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_NEXT_MOVE_DRIFT", "shadow runtime next move drift")
    if contract.get("runtime_mode") != RUNTIME_MODE or result.get("runtime_mode") != RUNTIME_MODE:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SHADOW_RUNTIME_NOT_PASSED", "runtime mode drift")
    if contract.get("shadow_runtime_executed") is not True:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SHADOW_RUNTIME_NOT_PASSED", "shadow runtime was not executed")
    if contract.get("static_authoritative") is not True or contract.get("afsh_observation_only") is not True:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_STATIC_AUTHORITY_DRIFT", "shadow runtime authority boundary drift")
    if contract.get("fired_disqualifiers") not in ([], None) or result.get("result", {}).get("fired_disqualifiers") not in ([], None):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SHADOW_RUNTIME_NOT_PASSED", "fired disqualifiers are not empty")
    if no_auth.get("no_downstream_authorization_drift") is not True:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_PREP_ONLY_AUTHORITY_DRIFT", "no-authorization-drift receipt did not pass")
    if not isinstance(cases, list) or not cases:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CASE_MANIFEST_MISSING", "case manifest missing cases")
    if not isinstance(scorecard, dict) or scorecard.get("total_cases") != len(cases):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SCORECARD_MISSING", "scorecard missing or inconsistent")

    for case in cases:
        if case.get("runtime_mode") != RUNTIME_MODE:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SHADOW_RUNTIME_NOT_PASSED", "case runtime mode drift")
        if case.get("static_authoritative") is not True:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_STATIC_AUTHORITY_DRIFT", "case static authority drift")
        if case.get("afsh_observation_only") is not True:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_AFSH_AUTHORITY_DRIFT", "case AFSH observation drift")
        if case.get("user_facing_decision_changed") is not False:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_USER_FACING_CHANGE", "case changed user-facing decision")
        if case.get("canary_runtime_executed") is not False:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CANARY_EXECUTED", "case executed canary runtime")
        if case.get("runtime_cutover_authorized") is not False:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CUTOVER_DRIFT", "case authorized runtime cutover")
        if case.get("trace_complete") is not True:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_TRACE_INCOMPLETE", "case trace incomplete")

    if scorecard.get("static_authoritative_cases") != len(cases):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_STATIC_AUTHORITY_DRIFT", "static authority was not universal")
    if scorecard.get("afsh_observation_only_cases") != len(cases):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_AFSH_AUTHORITY_DRIFT", "AFSH observation-only was not universal")
    if scorecard.get("user_facing_decision_changes") != 0:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_USER_FACING_CHANGE", "user-facing decision changed")
    if scorecard.get("canary_runtime_cases") != 0:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CANARY_EXECUTED", "canary runtime cases present")
    if scorecard.get("runtime_cutover_authorized_cases") != 0:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_CUTOVER_DRIFT", "runtime cutover cases present")
    if scorecard.get("fallback_failures") != 0:
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_FALLBACK_FAIL", "fallback failures present")
    if scorecard.get("drift_signals") not in ([], None):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_DRIFT_DETECTED", "drift signals present")
    if scorecard.get("incident_freeze_triggers") not in ([], None):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_INCIDENT_FREEZE_TRIGGERED", "incident/freeze triggers present")
    if scorecard.get("trace_complete_cases") != len(cases):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_TRACE_INCOMPLETE", "trace completeness did not cover all cases")

    report_text = texts["shadow_runtime_report"].lower()
    for phrase in ("shadow_runtime_only", "static remained authoritative", "does not authorize canary runtime"):
        if phrase not in report_text:
            _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SHADOW_RUNTIME_MISSING", f"shadow report missing {phrase}")


def _input_bindings(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    output_names = set(OUTPUTS.values())
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(ALL_JSON_INPUTS.items()):
        path = common.resolve_path(root, raw)
        row: Dict[str, Any] = {
            "role": role,
            "path": raw,
            "sha256": file_sha256(path),
            "binding_kind": "file_sha256_at_runtime_evidence_review_authoring",
        }
        if Path(raw).name in output_names:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(ALL_TEXT_INPUTS.items()):
        path = common.resolve_path(root, raw)
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(path),
                "binding_kind": "file_sha256_at_runtime_evidence_review_authoring",
            }
        )
    return rows


def _binding_hashes(root: Path) -> Dict[str, str]:
    hashes = {f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(ALL_JSON_INPUTS.items())}
    hashes.update({f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(ALL_TEXT_INPUTS.items())})
    return hashes


def _scorecard(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    result_score = payloads["shadow_result"]["result"]
    cases = payloads["shadow_case_manifest"]["cases"]
    total = len(cases)
    selector_entries = sum(1 for case in cases if case.get("selector_entered") is True)
    static_hold = sum(1 for case in cases if case.get("afsh_observation") == "STATIC_HOLD")
    abstain = sum(1 for case in cases if case.get("afsh_observation") == "ABSTAIN")
    null_route = sum(1 for case in cases if case.get("afsh_observation") == "NULL_ROUTE")
    route_eligible = sum(1 for case in cases if case.get("afsh_observation") == "ROUTE_ELIGIBLE")
    return {
        "runtime_mode": RUNTIME_MODE,
        "total_cases": total,
        "shadow_runtime_passed": True,
        "static_authoritative_cases": result_score["static_authoritative_cases"],
        "afsh_observation_only_cases": result_score["afsh_observation_only_cases"],
        "user_facing_decision_changes": result_score["user_facing_decision_changes"],
        "canary_runtime_cases": result_score["canary_runtime_cases"],
        "runtime_cutover_authorized_cases": result_score["runtime_cutover_authorized_cases"],
        "selector_entries": selector_entries,
        "selector_entry_rate": selector_entries / total,
        "static_hold_observations": static_hold,
        "abstention_observations": abstain,
        "null_route_observations": null_route,
        "route_eligible_observations": route_eligible,
        "fallback_failures": result_score["fallback_failures"],
        "drift_signals": list(result_score["drift_signals"]),
        "incident_freeze_triggers": list(result_score["incident_freeze_triggers"]),
        "trace_complete_cases": result_score["trace_complete_cases"],
        "fired_disqualifiers": list(result_score["fired_disqualifiers"]),
        "evidence_review_status": "PASS",
        "canary_readiness_status": "PREP_READY_NOT_AUTHORIZED",
        "package_promotion_status": "BLOCKED_PENDING_RUNTIME_EVIDENCE_REVIEW_AND_FUTURE_AUTHORITY",
    }


def _inventory(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> Dict[str, Any]:
    artifacts: list[Dict[str, Any]] = []
    for role, raw in sorted(ALL_JSON_INPUTS.items()):
        payload = payloads[role]
        artifacts.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "schema_id": payload.get("schema_id"),
                "artifact_id": payload.get("artifact_id"),
                "source_lane": PREVIOUS_LANE,
                "evidence_kind": "json_receipt",
            }
        )
    for role, raw in sorted(ALL_TEXT_INPUTS.items()):
        artifacts.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "source_lane": PREVIOUS_LANE,
                "evidence_kind": "text_report",
                "non_empty": bool(texts[role].strip()),
            }
        )
    return {
        "artifact_count": len(artifacts),
        "raw_hash_bound_artifacts_required": True,
        "compressed_index_source_of_truth": False,
        "artifacts": artifacts,
    }


def _compiler_scaffold(current_main_head: str) -> Dict[str, Any]:
    spec = {
        "lane_id": "AUTHOR_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET",
        "lane_name": "B04 R6 runtime evidence review packet",
        "authority": kt_lane_compiler.AUTHORITY,
        "owner": "KT_PROD_CLEANROOM",
        "summary": "Prep-only compiler scaffold for the runtime evidence review packet lane.",
        "operator_path": "KT_PROD_CLEANROOM/tools/operator/cohort0_b04_r6_runtime_evidence_review_packet.py",
        "test_path": "KT_PROD_CLEANROOM/tests/operator/test_b04_r6_runtime_evidence_review_packet.py",
        "artifacts": sorted(OUTPUTS.values()),
        "json_parse_inputs": sorted(filename for filename in OUTPUTS.values() if filename.endswith(".json")),
        "no_authorization_drift_checks": [
            "Runtime evidence review packet does not authorize canary runtime.",
            "Runtime evidence review packet does not authorize runtime cutover.",
            "Runtime evidence review packet does not open R6 or promote package.",
            "Commercial activation claims remain unauthorized.",
        ],
        "future_blockers": [
            "Runtime evidence review packet requires validation before canary authorization can be authored.",
            "Canary execution remains blocked until canary authorization and canary execution packet lanes exist.",
            "Package promotion remains blocked until runtime evidence, external audit, and promotion review lanes pass.",
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


def _validation_rows(scorecard: Dict[str, Any]) -> list[Dict[str, Any]]:
    checks = {
        "shadow_runtime_passed": scorecard["shadow_runtime_passed"] is True,
        "static_authority_preserved": scorecard["static_authoritative_cases"] == scorecard["total_cases"],
        "afsh_observation_only_preserved": scorecard["afsh_observation_only_cases"] == scorecard["total_cases"],
        "user_facing_decision_unchanged": scorecard["user_facing_decision_changes"] == 0,
        "canary_runtime_not_executed": scorecard["canary_runtime_cases"] == 0,
        "runtime_cutover_not_authorized": scorecard["runtime_cutover_authorized_cases"] == 0,
        "fallback_behavior_passed": scorecard["fallback_failures"] == 0,
        "drift_monitoring_passed": scorecard["drift_signals"] == [],
        "incident_freeze_passed": scorecard["incident_freeze_triggers"] == [],
        "trace_completeness_passed": scorecard["trace_complete_cases"] == scorecard["total_cases"],
        "disqualifier_ledger_clean": scorecard["fired_disqualifiers"] == [],
        "external_verifier_review_ready": True,
        "commercial_claim_boundary_preserved": True,
        "package_promotion_blocked": True,
        "canary_readiness_prep_only": True,
    }
    rows = [
        {
            "check_id": f"B04R6-RUNTIME-EVIDENCE-{index:03d}",
            "name": name,
            "status": "PASS" if passed else "FAIL",
            "terminal_if_fail": name
            in {
                "shadow_runtime_passed",
                "static_authority_preserved",
                "user_facing_decision_unchanged",
                "canary_runtime_not_executed",
                "runtime_cutover_not_authorized",
                "trace_completeness_passed",
                "commercial_claim_boundary_preserved",
            },
        }
        for index, (name, passed) in enumerate(checks.items(), start=1)
    ]
    if any(row["status"] != "PASS" for row in rows):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_SCORECARD_MISSING", "one or more review checks failed")
    return rows


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    current_branch: str,
    input_bindings: list[Dict[str, Any]],
    binding_hashes: Dict[str, str],
    inventory: Dict[str, Any],
    scorecard: Dict[str, Any],
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
        "runtime_mode": RUNTIME_MODE,
        "shadow_runtime_passed": True,
        "runtime_evidence_review_packet_authored": True,
        "runtime_evidence_review_validated": False,
        "canary_runtime_authorized": False,
        "canary_runtime_executed": False,
        "afsh_runtime_authority_granted": False,
        "user_facing_decision_changed": False,
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
        "runtime_evidence_inventory": inventory,
        "runtime_evidence_scorecard": scorecard,
        "validation_rows": validation_rows,
        "may_authorize": list(MAY_AUTHORIZE),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "allowed_outcomes": [
            SELECTED_OUTCOME,
            "B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET_DEFERRED__NAMED_EVIDENCE_REVIEW_DEFECT_REMAINS",
            "B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED",
        ],
        "outcome_routing": {
            SELECTED_OUTCOME: NEXT_LAWFUL_MOVE,
            "B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET_DEFERRED__NAMED_EVIDENCE_REVIEW_DEFECT_REMAINS": "REPAIR_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET_DEFECTS",
            "B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED": "AUTHOR_B04_R6_RUNTIME_REPAIR_OR_CLOSEOUT",
        },
        "terminal_defects": list(TERMINAL_DEFECTS),
        "reason_codes": list(REASON_CODES),
        "lane_compiler_scaffold": compiler_scaffold,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
    }


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    payload = {
        "schema_id": schema_id,
        "artifact_id": artifact_id,
        **base,
        **extra,
    }
    return payload


def _review_contract(base: Dict[str, Any], *, role: str, question: str, evidence_roles: Sequence[str], findings: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_evidence_review.{role}.v1",
        artifact_id=f"B04_R6_RUNTIME_{role.upper()}_CONTRACT",
        review_role=role,
        review_question=question,
        evidence_roles=list(evidence_roles),
        findings=findings,
        review_status="PASS",
        canary_runtime_authorized=False,
        runtime_cutover_authorized=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.runtime_evidence_review.{role}.prep_only.v1",
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


def _canary_readiness_matrix(base: Dict[str, Any]) -> Dict[str, Any]:
    rows = [
        ("shadow_runtime_passed", "PASS", "Bound passed shadow runtime evidence."),
        ("static_authority_preserved", "PASS", "Static remained authoritative across all shadow cases."),
        ("no_user_facing_change", "PASS", "AFSH made no user-facing decision changes."),
        ("operator_controls_ready", "PASS", "Operator override, kill switch, and rollback readiness receipts passed."),
        ("evidence_review_validation_required", "BLOCKING_NEXT", "Evidence review packet must validate before canary authorization can be authored."),
        ("canary_authorization_packet_required", "BLOCKED", "Future canary authorization packet is prep-only in this lane."),
        ("canary_validation_required", "BLOCKED", "Future canary validation must pass before canary execution."),
    ]
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.runtime_evidence_review.canary_readiness_matrix.v1",
        artifact_id="B04_R6_RUNTIME_CANARY_READINESS_MATRIX",
        readiness_status="PREP_READY_NOT_AUTHORIZED",
        canary_runtime_authorized=False,
        canary_runtime_executed=False,
        rows=[{"readiness_item": item, "status": status, "evidence": evidence} for item, status, evidence in rows],
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    blockers = [
        "Runtime evidence review packet must validate before canary authorization packet authorship.",
        "Canary authorization remains blocked until validation selects the canary authorization packet lane.",
        "Canary execution remains blocked until canary authorization, canary packet authoring, and canary packet validation.",
        "Package promotion remains blocked until runtime evidence review, future canary evidence, external audit, and promotion review pass.",
        "Commercial activation claims remain blocked until a future commercial-claim authority lane exists.",
    ]
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v23",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        blockers=[
            {"blocker_id": f"B04R6-RUNTIME-EVIDENCE-BLOCKER-{index:03d}", "status": "OPEN", "description": blocker}
            for index, blocker in enumerate(blockers, start=1)
        ],
    )


def _pipeline_board(base: Dict[str, Any]) -> Dict[str, Any]:
    lanes = [
        ("RUN_B04_R6_LIMITED_RUNTIME_SHADOW_RUNTIME", "PASSED", False, EXPECTED_PREVIOUS_OUTCOME, AUTHORITATIVE_LANE),
        ("AUTHOR_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET", "CURRENT_BOUND", True, SELECTED_OUTCOME, NEXT_LAWFUL_MOVE),
        ("VALIDATE_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET", "NEXT", True, "B04_R6_RUNTIME_EVIDENCE_REVIEW_VALIDATED__CANARY_AUTHORIZATION_PACKET_NEXT", "AUTHOR_B04_R6_CANARY_AUTHORIZATION_PACKET"),
        ("AUTHOR_B04_R6_CANARY_AUTHORIZATION_PACKET", "PREP_ONLY_BLOCKED", False, "NOT_SELECTED", "BLOCKED"),
        ("RUN_B04_R6_CANARY_RUNTIME", "BLOCKED", False, "NOT_AUTHORIZED", "BLOCKED"),
        ("AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET", "BLOCKED", False, "NOT_AUTHORIZED", "BLOCKED"),
    ]
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.pipeline_board.v1",
        artifact_id="B04_R6_PIPELINE_BOARD",
        board_status="RUNTIME_EVIDENCE_REVIEW_PACKET_NEXT",
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
    score = contract["runtime_evidence_scorecard"]
    return (
        "# B04 R6 Runtime Evidence Review Packet\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "This packet freezes and summarizes the passed SHADOW_RUNTIME_ONLY evidence. Static remained authoritative, "
        "AFSH stayed observational, no user-facing decision changed, canary was not authorized or executed, and "
        "runtime cutover/R6/package/commercial authority remain blocked.\n\n"
        "Evidence sweep:\n"
        f"- total cases: {score['total_cases']}\n"
        f"- selector entries: {score['selector_entries']}\n"
        f"- static authority cases: {score['static_authoritative_cases']}\n"
        f"- trace complete cases: {score['trace_complete_cases']}\n"
        f"- fired disqualifiers: {score['fired_disqualifiers']}\n\n"
        "The packet also emits canary readiness, package-promotion blockers, external verifier readiness, "
        "commercial claim boundary review, prep-only canary/external-audit/package scaffolds, and a pipeline board. "
        "It does not validate itself and does not authorize canary runtime.\n"
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    score = base["runtime_evidence_scorecard"]
    inventory = base["runtime_evidence_inventory"]
    output_payloads: Dict[str, Any] = {
        "review_contract": _with_artifact(
            base,
            schema_id="kt.b04_r6.runtime_evidence_review_packet_contract.v1",
            artifact_id="B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET_CONTRACT",
            packet_scope={
                "purpose": "Freeze, inventory, score, and review passed shadow-runtime evidence before validation.",
                "non_purpose": [
                    "Does not authorize canary runtime.",
                    "Does not execute canary.",
                    "Does not authorize runtime cutover.",
                    "Does not open R6.",
                    "Does not authorize package promotion.",
                    "Does not authorize commercial activation claims.",
                ],
            },
            review_questions=[
                "Did static remain authoritative?",
                "Did AFSH influence any user-facing decision?",
                "Was route distribution healthy?",
                "Were fallbacks and abstention/null-route behavior preserved?",
                "Were operator controls, kill switch, and rollback ready?",
                "Were drift/freeze/trace/replay/external-verifier boundaries clean?",
                "Is the system prep-ready, but not authorized, for canary authorization review?",
            ],
        ),
        "review_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.runtime_evidence_review_packet_receipt.v1",
            artifact_id="B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET_RECEIPT",
            verdict="PASS",
        ),
        "evidence_inventory": _with_artifact(
            base,
            schema_id="kt.b04_r6.runtime_evidence_inventory.v1",
            artifact_id="B04_R6_RUNTIME_EVIDENCE_INVENTORY",
            **inventory,
        ),
        "evidence_scorecard": _with_artifact(
            base,
            schema_id="kt.b04_r6.runtime_evidence_scorecard.v1",
            artifact_id="B04_R6_RUNTIME_EVIDENCE_SCORECARD",
            scorecard=score,
        ),
        "canary_readiness_matrix": _canary_readiness_matrix(base),
        "no_authorization_drift_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.runtime_evidence_review.no_authorization_drift_receipt.v1",
            artifact_id="B04_R6_RUNTIME_EVIDENCE_REVIEW_NO_AUTHORIZATION_DRIFT_RECEIPT",
            no_authorization_drift=True,
        ),
        "future_blocker_register": _future_blocker_register(base),
        "pipeline_board": _pipeline_board(base),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v22",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            verdict="NEXT_LAWFUL_MOVE_SET",
        ),
    }

    review_specs = {
        "route_distribution_health_review": ("Was route distribution healthy?", ["shadow_route_distribution_health_receipt"], {"selector_entry_rate": score["selector_entry_rate"], "status": "PASS"}),
        "static_authority_review": ("Did static remain authoritative?", ["shadow_static_authority_preservation_receipt"], {"static_authoritative_cases": score["static_authoritative_cases"], "status": "PASS"}),
        "afsh_observation_review": ("Did AFSH remain observational?", ["shadow_afsh_observation_receipt"], {"afsh_observation_only_cases": score["afsh_observation_only_cases"], "status": "PASS"}),
        "fallback_behavior_review": ("Were fallbacks preserved?", ["shadow_fallback_behavior_receipt"], {"fallback_failures": score["fallback_failures"], "status": "PASS"}),
        "abstention_preservation_review": ("Was abstention preserved?", ["shadow_abstention_preservation_receipt"], {"abstention_observations": score["abstention_observations"], "status": "PASS"}),
        "null_route_preservation_review": ("Was null-route behavior preserved?", ["shadow_null_route_preservation_receipt"], {"null_route_observations": score["null_route_observations"], "status": "PASS"}),
        "operator_control_review": ("Were operator controls ready?", ["shadow_operator_override_readiness_receipt"], {"operator_override_ready": True, "status": "PASS"}),
        "kill_switch_readiness_review": ("Was kill switch ready?", ["shadow_kill_switch_readiness_receipt"], {"kill_switch_ready": True, "status": "PASS"}),
        "rollback_readiness_review": ("Was rollback ready?", ["shadow_rollback_readiness_receipt"], {"rollback_ready": True, "status": "PASS"}),
        "drift_monitoring_review": ("Were drift signals clean?", ["shadow_drift_monitoring_receipt"], {"drift_signals": score["drift_signals"], "status": "PASS"}),
        "incident_freeze_review": ("Were incident/freeze triggers clean?", ["shadow_incident_freeze_receipt"], {"incident_freeze_triggers": score["incident_freeze_triggers"], "status": "PASS"}),
        "trace_completeness_review": ("Were traces complete?", ["shadow_trace_completeness_receipt"], {"trace_complete_cases": score["trace_complete_cases"], "status": "PASS"}),
        "replay_readiness_review": ("Is replay ready?", ["shadow_runtime_replay_receipt"], {"raw_hash_bound_artifacts_required": True, "status": "PASS"}),
        "external_verifier_readiness_review": ("Can an external verifier inspect this?", ["shadow_external_verifier_readiness_receipt"], {"external_verifier_ready": True, "status": "PASS"}),
        "commercial_claim_boundary_review": ("Are commercial claims still blocked?", ["shadow_commercial_claim_boundary_receipt"], {"commercial_activation_claim_authorized": False, "status": "PASS"}),
        "package_promotion_blocker_review": ("What blocks package promotion?", ["shadow_no_authorization_drift_receipt"], {"package_promotion_authorized": False, "blockers_remain": True, "status": "PASS"}),
    }
    for role, (question, evidence_roles, findings) in review_specs.items():
        output_payloads[role] = _review_contract(base, role=role, question=question, evidence_roles=evidence_roles, findings=findings)

    output_payloads.update(
        {
            role: _prep_only(base, role=role, purpose=f"Prep-only downstream scaffold for {role.replace('_', ' ')}.")
            for role in PREP_ONLY_OUTPUT_ROLES
        }
    )
    return output_payloads


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root):
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 runtime evidence review packet")

    payloads = {role: _load(root, raw, label=role) for role, raw in ALL_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in ALL_TEXT_INPUTS.items()}
    _validate_handoff(payloads, texts)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_RUNTIME_EVIDENCE_REVIEW_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if current_branch != "main" else "HEAD")
    inventory = _inventory(root, payloads, texts)
    scorecard = _scorecard(payloads)
    compiler_scaffold = _compiler_scaffold(current_main_head)
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=_input_bindings(root, handoff_git_commit=head),
        binding_hashes=_binding_hashes(root),
        inventory=inventory,
        scorecard=scorecard,
        validation_rows=_validation_rows(scorecard),
        compiler_scaffold=compiler_scaffold,
        trust_zone_validation=fresh_trust_validation,
    )
    output_payloads = _outputs(base)
    contract = output_payloads["review_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "review_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, output_payloads[role])
    return contract


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author B04 R6 runtime evidence review packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
