from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_learned_router_activation_review_packet_validation as activation_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-limited-runtime-authorization-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET"
PREVIOUS_LANE = activation_validation.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = activation_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = activation_validation.NEXT_LAWFUL_MOVE
OUTCOME_BOUND = "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_BOUND__LIMITED_RUNTIME_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET"

SELECTED_ARCHITECTURE_ID = activation_validation.SELECTED_ARCHITECTURE_ID
SELECTED_ARCHITECTURE_NAME = activation_validation.SELECTED_ARCHITECTURE_NAME
CANDIDATE_ID = activation_validation.CANDIDATE_ID
CANDIDATE_VERSION = activation_validation.CANDIDATE_VERSION

MAY_AUTHORIZE = ("LIMITED_RUNTIME_AUTHORIZATION_PACKET_AUTHORED",)
FORBIDDEN_ACTIONS = (
    "LIMITED_RUNTIME_AUTHORIZED",
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
REASON_CODES = (
    "RC_B04R6_LIMITED_RUNTIME_PACKET_CONTRACT_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_MAIN_HEAD_MISMATCH",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_ACTIVATION_REVIEW_VALIDATION_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_SHADOW_RESULT_BINDING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_CANDIDATE_BINDING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_SCOPE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_SCOPE_NOT_LIMITED",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_STATIC_FALLBACK_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_ABSTENTION_FALLBACK_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_NULL_ROUTE_PRESERVATION_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_OPERATOR_OVERRIDE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_KILL_SWITCH_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_ROLLBACK_PLAN_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_ROUTE_DISTRIBUTION_HEALTH_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_DRIFT_MONITORING_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_RUNTIME_RECEIPT_SCHEMA_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_INCIDENT_FREEZE_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_COMMERCIAL_BOUNDARY_MISSING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_PREP_ONLY_AUTHORITY_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_LIMITED_RUNTIME_AUTHORIZED",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_R6_OPEN_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_TRUST_ZONE_MUTATION",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_METRIC_MUTATION",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_COMPARATOR_WEAKENING",
    "RC_B04R6_LIMITED_RUNTIME_PACKET_NEXT_MOVE_DRIFT",
)
TERMINAL_DEFECTS = (
    "SCOPE_NOT_LIMITED",
    "LIMITED_RUNTIME_AUTHORIZED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "R6_OPEN_DRIFT",
    "LOBE_ESCALATION_DRIFT",
    "PACKAGE_PROMOTION_DRIFT",
    "COMMERCIAL_CLAIM_DRIFT",
    "TRUTH_ENGINE_MUTATION",
    "TRUST_ZONE_MUTATION",
    "METRIC_MUTATION",
    "COMPARATOR_WEAKENING",
    "NEXT_MOVE_DRIFT",
)

INPUTS = {
    "activation_review_validation_contract": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_validation_contract.json",
    "activation_review_validation_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_validation_receipt.json",
    "activation_review_packet_contract": "KT_PROD_CLEANROOM/reports/b04_r6_learned_router_activation_review_packet_contract.json",
    "activation_review_scope_contract": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_scope_contract.json",
    "activation_review_runtime_preconditions_contract": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_runtime_preconditions_contract.json",
    "activation_review_static_fallback_contract": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_static_fallback_contract.json",
    "activation_review_operator_override_contract": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_operator_override_contract.json",
    "activation_review_kill_switch_contract": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_kill_switch_contract.json",
    "activation_review_rollback_plan_contract": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_rollback_plan_contract.json",
    "activation_review_route_distribution_health_contract": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_route_distribution_health_contract.json",
    "activation_review_drift_monitoring_contract": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_drift_monitoring_contract.json",
    "activation_review_runtime_receipt_schema_contract": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_runtime_receipt_schema_contract.json",
    "activation_review_external_verifier_requirements": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_external_verifier_requirements.json",
    "activation_review_commercial_claim_boundary": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_commercial_claim_boundary.json",
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}
TEXT_INPUTS = {
    "activation_review_validation_report": "KT_PROD_CLEANROOM/reports/b04_r6_activation_review_validation_report.md",
}
MUTABLE_HANDOFF_ROLES = frozenset({"previous_next_lawful_move"})

CONTROL_OUTPUT_ROLES = (
    "scope_manifest",
    "static_fallback_contract",
    "abstention_fallback_contract",
    "null_route_preservation_contract",
    "operator_override_contract",
    "kill_switch_contract",
    "rollback_plan",
    "route_distribution_health_contract",
    "drift_monitoring_contract",
    "runtime_receipt_schema",
    "incident_freeze_contract",
    "external_verifier_requirements",
    "commercial_claim_boundary",
)
PREP_ONLY_OUTPUT_ROLES = (
    "limited_runtime_validation_plan_prep_only",
    "runtime_canary_execution_contract_prep_only",
    "runtime_evidence_packet_prep_only",
    "runtime_incident_freeze_contract_prep_only",
    "runtime_operator_override_playbook_prep_only",
    "runtime_rollback_execution_receipt_schema_prep_only",
    "runtime_authorization_rejection_closeout_prep_only",
    "activation_review_repair_packet_prep_only",
    "operational_safety_defect_ledger_prep_only",
    "runtime_authorization_redesign_court_prep_only",
    "package_promotion_review_preconditions_prep_only",
    "external_audit_delta_manifest_prep_only",
    "public_verifier_delta_requirements_prep_only",
)

OUTPUTS = {
    "packet_contract": "b04_r6_limited_runtime_authorization_packet_contract.json",
    "packet_receipt": "b04_r6_limited_runtime_authorization_packet_receipt.json",
    "packet_report": "b04_r6_limited_runtime_authorization_packet_report.md",
    "activation_review_validation_binding_receipt": "b04_r6_limited_runtime_activation_review_validation_binding_receipt.json",
    "shadow_result_binding_receipt": "b04_r6_limited_runtime_shadow_result_binding_receipt.json",
    "candidate_binding_receipt": "b04_r6_limited_runtime_candidate_binding_receipt.json",
    "scope_manifest": "b04_r6_limited_runtime_scope_manifest.json",
    "static_fallback_contract": "b04_r6_limited_runtime_static_fallback_contract.json",
    "abstention_fallback_contract": "b04_r6_limited_runtime_abstention_fallback_contract.json",
    "null_route_preservation_contract": "b04_r6_limited_runtime_null_route_preservation_contract.json",
    "operator_override_contract": "b04_r6_limited_runtime_operator_override_contract.json",
    "kill_switch_contract": "b04_r6_limited_runtime_kill_switch_contract.json",
    "rollback_plan": "b04_r6_limited_runtime_rollback_plan.json",
    "route_distribution_health_contract": "b04_r6_limited_runtime_route_distribution_health_contract.json",
    "drift_monitoring_contract": "b04_r6_limited_runtime_drift_monitoring_contract.json",
    "runtime_receipt_schema": "b04_r6_limited_runtime_receipt_schema.json",
    "incident_freeze_contract": "b04_r6_limited_runtime_incident_freeze_contract.json",
    "external_verifier_requirements": "b04_r6_limited_runtime_external_verifier_requirements.json",
    "commercial_claim_boundary": "b04_r6_limited_runtime_commercial_claim_boundary.json",
    "no_authorization_drift_receipt": "b04_r6_limited_runtime_no_authorization_drift_receipt.json",
    "validation_plan": "b04_r6_limited_runtime_validation_plan.json",
    "validation_reason_codes": "b04_r6_limited_runtime_validation_reason_codes.json",
    "limited_runtime_validation_plan_prep_only": "b04_r6_limited_runtime_validation_plan_prep_only.json",
    "runtime_canary_execution_contract_prep_only": "b04_r6_runtime_canary_execution_contract_prep_only.json",
    "runtime_evidence_packet_prep_only": "b04_r6_runtime_evidence_packet_prep_only.json",
    "runtime_incident_freeze_contract_prep_only": "b04_r6_runtime_incident_freeze_contract_prep_only.json",
    "runtime_operator_override_playbook_prep_only": "b04_r6_runtime_operator_override_playbook_prep_only.md",
    "runtime_rollback_execution_receipt_schema_prep_only": "b04_r6_runtime_rollback_execution_receipt_schema_prep_only.json",
    "runtime_authorization_rejection_closeout_prep_only": "b04_r6_limited_runtime_rejection_closeout_prep_only.json",
    "activation_review_repair_packet_prep_only": "b04_r6_activation_review_repair_packet_prep_only.json",
    "operational_safety_defect_ledger_prep_only": "b04_r6_operational_safety_defect_ledger_prep_only.json",
    "runtime_authorization_redesign_court_prep_only": "b04_r6_runtime_authorization_redesign_court_prep_only.json",
    "package_promotion_review_preconditions_prep_only": "b04_r6_package_promotion_review_preconditions_prep_only.json",
    "external_audit_delta_manifest_prep_only": "b04_r6_external_audit_delta_manifest_prep_only.json",
    "public_verifier_delta_requirements_prep_only": "b04_r6_public_verifier_delta_requirements_prep_only.json",
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


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, raw, label=label)


def _read_text(root: Path, raw: str, *, label: str) -> str:
    return common.read_text_required(root, raw, label=label)


def _input_hashes(root: Path, *, handoff_git_commit: str) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted(INPUTS.items()):
        path = common.resolve_path(root, raw)
        row: Dict[str, Any] = {
            "role": role,
            "path": raw,
            "sha256": file_sha256(path),
            "binding_kind": "file_sha256_at_limited_runtime_packet_authoring",
        }
        if role in MUTABLE_HANDOFF_ROLES:
            row["binding_kind"] = "git_object_before_overwrite"
            row["git_commit"] = handoff_git_commit
            row["mutable_canonical_path_overwritten_by_this_lane"] = True
        rows.append(row)
    for role, raw in sorted(TEXT_INPUTS.items()):
        path = common.resolve_path(root, raw)
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(path),
                "binding_kind": "file_sha256_at_limited_runtime_packet_authoring",
            }
        )
    return rows


def _ensure_false(payload: Dict[str, Any], key: str, *, label: str, code: str) -> None:
    if key in payload and bool(payload.get(key)):
        _fail(code, f"{label} sets forbidden true flag: {key}")


def _ensure_runtime_closed(payload: Dict[str, Any], *, label: str) -> None:
    for key, code in (
        ("r6_open", "RC_B04R6_LIMITED_RUNTIME_PACKET_R6_OPEN_DRIFT"),
        ("limited_runtime_authorized", "RC_B04R6_LIMITED_RUNTIME_PACKET_LIMITED_RUNTIME_AUTHORIZED"),
        ("runtime_cutover_authorized", "RC_B04R6_LIMITED_RUNTIME_PACKET_RUNTIME_CUTOVER_AUTHORIZED"),
        ("activation_cutover_authorized", "RC_B04R6_LIMITED_RUNTIME_PACKET_RUNTIME_CUTOVER_AUTHORIZED"),
        ("activation_cutover_executed", "RC_B04R6_LIMITED_RUNTIME_PACKET_RUNTIME_CUTOVER_AUTHORIZED"),
        ("runtime_execution_authorized", "RC_B04R6_LIMITED_RUNTIME_PACKET_RUNTIME_CUTOVER_AUTHORIZED"),
        ("lobe_escalation_authorized", "RC_B04R6_LIMITED_RUNTIME_PACKET_LOBE_ESCALATION_DRIFT"),
        ("package_promotion_authorized", "RC_B04R6_LIMITED_RUNTIME_PACKET_PACKAGE_PROMOTION_DRIFT"),
        ("commercial_activation_claim_authorized", "RC_B04R6_LIMITED_RUNTIME_PACKET_COMMERCIAL_CLAIM_DRIFT"),
        ("metric_contract_mutated", "RC_B04R6_LIMITED_RUNTIME_PACKET_METRIC_MUTATION"),
        ("static_comparator_weakened", "RC_B04R6_LIMITED_RUNTIME_PACKET_COMPARATOR_WEAKENING"),
    ):
        _ensure_false(payload, key, label=label, code=code)
    state = payload.get("authorization_state")
    if isinstance(state, dict):
        _ensure_runtime_closed(state, label=f"{label}.authorization_state")
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_PACKAGE_PROMOTION_DRIFT", f"{label} package promotion drift")
    if payload.get("truth_engine_law_changed") is True or payload.get("truth_engine_derivation_law_unchanged") is False:
        _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_TRUTH_ENGINE_MUTATION", f"{label} truth-engine mutation")
    if payload.get("trust_zone_law_changed") is True or payload.get("trust_zone_law_unchanged") is False:
        _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_TRUST_ZONE_MUTATION", f"{label} trust-zone mutation")


def _validate_handoff(payload: Dict[str, Any]) -> Dict[str, bool]:
    predecessor = (
        payload.get("authoritative_lane") == PREVIOUS_LANE
        and payload.get("selected_outcome") == EXPECTED_PREVIOUS_OUTCOME
        and payload.get("next_lawful_move") == EXPECTED_PREVIOUS_NEXT_MOVE
    )
    self_replay = (
        payload.get("authoritative_lane") == AUTHORITATIVE_LANE
        and payload.get("selected_outcome") == SELECTED_OUTCOME
        and payload.get("next_lawful_move") == NEXT_LAWFUL_MOVE
    )
    if not (predecessor or self_replay):
        _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_NEXT_MOVE_DRIFT", "handoff lacks valid predecessor or self-replay lane identity")
    return {"predecessor_handoff_accepted": predecessor, "self_replay_handoff_accepted": self_replay}


def _validate_activation_review_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> Dict[str, bool]:
    contract = payloads["activation_review_validation_contract"]
    receipt = payloads["activation_review_validation_receipt"]
    if "activation-review" not in texts["activation_review_validation_report"].lower():
        _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_ACTIVATION_REVIEW_VALIDATION_MISSING", "activation-review validation report missing")
    for label, payload in payloads.items():
        _ensure_runtime_closed(payload, label=label)
        if label == "previous_next_lawful_move":
            continue
        if payload.get("status") not in (None, "PASS"):
            _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_ACTIVATION_REVIEW_VALIDATION_MISSING", f"{label} must be PASS or structural input")
    for label, payload in (("activation_review_validation_contract", contract), ("activation_review_validation_receipt", receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_ACTIVATION_REVIEW_VALIDATION_MISSING", f"{label} lane identity drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_ACTIVATION_REVIEW_VALIDATION_MISSING", f"{label} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_NEXT_MOVE_DRIFT", f"{label} next move drift")
        if payload.get("activation_review_validated") is not True:
            _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_ACTIVATION_REVIEW_VALIDATION_MISSING", f"{label} did not validate activation review")
        if payload.get("limited_runtime_authorized") is not False:
            _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_LIMITED_RUNTIME_AUTHORIZED", f"{label} already authorizes limited runtime")
    return _validate_handoff(payloads["previous_next_lawful_move"])


def _binding_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    validation_contract = payloads["activation_review_validation_contract"]
    validation_hashes = validation_contract.get("binding_hashes")
    if not isinstance(validation_hashes, dict):
        _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_ACTIVATION_REVIEW_VALIDATION_MISSING", "activation validation binding hashes missing")
    hashes: Dict[str, str] = {
        "activation_review_validation_contract_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_validation_contract"])),
        "activation_review_validation_receipt_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_validation_receipt"])),
        "activation_review_validation_report_hash": file_sha256(common.resolve_path(root, TEXT_INPUTS["activation_review_validation_report"])),
        "activation_review_packet_contract_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_packet_contract"])),
        "activation_review_scope_contract_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_scope_contract"])),
        "activation_review_runtime_preconditions_contract_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_runtime_preconditions_contract"])),
        "activation_review_static_fallback_contract_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_static_fallback_contract"])),
        "activation_review_operator_override_contract_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_operator_override_contract"])),
        "activation_review_kill_switch_contract_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_kill_switch_contract"])),
        "activation_review_rollback_plan_contract_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_rollback_plan_contract"])),
        "activation_review_route_distribution_health_contract_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_route_distribution_health_contract"])),
        "activation_review_drift_monitoring_contract_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_drift_monitoring_contract"])),
        "activation_review_runtime_receipt_schema_contract_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_runtime_receipt_schema_contract"])),
        "activation_review_external_verifier_requirements_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_external_verifier_requirements"])),
        "activation_review_commercial_claim_boundary_hash": file_sha256(common.resolve_path(root, INPUTS["activation_review_commercial_claim_boundary"])),
    }
    for key in (
        "shadow_screen_result_hash",
        "shadow_screen_execution_receipt_hash",
        "candidate_hash",
        "candidate_manifest_hash",
        "candidate_semantic_hash",
        "validated_shadow_screen_packet_hash",
        "validated_blind_universe_hash",
        "validated_route_economics_court_hash",
        "validated_source_packet_hash",
        "admissibility_receipt_hash",
        "numeric_triage_emit_core_hash",
        "static_comparator_contract_hash",
        "metric_contract_hash",
        "disqualifier_ledger_hash",
        "trace_completeness_receipt_hash",
        "trust_zone_validation_receipt_hash",
        "no_authorization_drift_receipt_hash",
    ):
        value = str(validation_hashes.get(key, "")).strip()
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_ACTIVATION_REVIEW_VALIDATION_MISSING", f"missing activation-validation carried hash {key}")
        hashes[key] = value
    return hashes


def _pass_row(check_id: str, reason_code: str, detail: str, *, group: str) -> Dict[str, str]:
    return {"check_id": check_id, "group": group, "status": "PASS", "reason_code": reason_code, "detail": detail}


def _validation_rows() -> list[Dict[str, str]]:
    rows = [
        _pass_row("limited_runtime_packet_preserves_current_main_head", "RC_B04R6_LIMITED_RUNTIME_PACKET_MAIN_HEAD_MISMATCH", "packet binds current main head", group="core"),
        _pass_row("limited_runtime_packet_binds_activation_review_validation", "RC_B04R6_LIMITED_RUNTIME_PACKET_ACTIVATION_REVIEW_VALIDATION_MISSING", "activation-review validation is bound", group="binding"),
        _pass_row("limited_runtime_packet_binds_shadow_result", "RC_B04R6_LIMITED_RUNTIME_PACKET_SHADOW_RESULT_BINDING_MISSING", "shadow result is bound", group="binding"),
        _pass_row("limited_runtime_packet_binds_candidate", "RC_B04R6_LIMITED_RUNTIME_PACKET_CANDIDATE_BINDING_MISSING", "candidate hashes are bound", group="binding"),
        _pass_row("limited_runtime_scope_manifest_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_SCOPE_MISSING", "scope manifest exists", group="scope"),
        _pass_row("limited_runtime_scope_is_limited", "RC_B04R6_LIMITED_RUNTIME_PACKET_SCOPE_NOT_LIMITED", "scope is limited and non-executing", group="scope"),
        _pass_row("limited_runtime_static_fallback_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_STATIC_FALLBACK_MISSING", "static fallback exists", group="controls"),
        _pass_row("limited_runtime_abstention_fallback_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_ABSTENTION_FALLBACK_MISSING", "abstention fallback exists", group="controls"),
        _pass_row("limited_runtime_null_route_preservation_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_NULL_ROUTE_PRESERVATION_MISSING", "null-route preservation exists", group="controls"),
        _pass_row("limited_runtime_operator_override_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_OPERATOR_OVERRIDE_MISSING", "operator override exists", group="controls"),
        _pass_row("limited_runtime_kill_switch_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_KILL_SWITCH_MISSING", "kill switch exists", group="controls"),
        _pass_row("limited_runtime_rollback_plan_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_ROLLBACK_PLAN_MISSING", "rollback plan exists", group="controls"),
        _pass_row("limited_runtime_route_distribution_health_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_ROUTE_DISTRIBUTION_HEALTH_MISSING", "route distribution health exists", group="controls"),
        _pass_row("limited_runtime_drift_monitoring_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_DRIFT_MONITORING_MISSING", "drift monitoring exists", group="controls"),
        _pass_row("limited_runtime_receipt_schema_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_RUNTIME_RECEIPT_SCHEMA_MISSING", "runtime receipt schema exists", group="controls"),
        _pass_row("limited_runtime_incident_freeze_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_INCIDENT_FREEZE_MISSING", "incident freeze exists", group="controls"),
        _pass_row("limited_runtime_external_verifier_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_EXTERNAL_VERIFIER_MISSING", "external verifier requirements exist", group="controls"),
        _pass_row("limited_runtime_commercial_boundary_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_COMMERCIAL_BOUNDARY_MISSING", "commercial claim boundary exists", group="controls"),
        _pass_row("limited_runtime_validation_plan_exists", "RC_B04R6_LIMITED_RUNTIME_PACKET_SCOPE_MISSING", "validator scaffold exists", group="scaffold"),
        _pass_row("limited_runtime_reason_codes_exist", "RC_B04R6_LIMITED_RUNTIME_PACKET_CONTRACT_MISSING", "reason-code taxonomy exists", group="scaffold"),
        _pass_row("limited_runtime_prep_only_outputs_remain_prep_only", "RC_B04R6_LIMITED_RUNTIME_PACKET_PREP_ONLY_AUTHORITY_DRIFT", "future scaffolds prep-only", group="prep_only"),
        _pass_row("limited_runtime_packet_does_not_authorize_limited_runtime", "RC_B04R6_LIMITED_RUNTIME_PACKET_LIMITED_RUNTIME_AUTHORIZED", "limited runtime remains unauthorized", group="authorization"),
        _pass_row("limited_runtime_packet_does_not_authorize_runtime_cutover", "RC_B04R6_LIMITED_RUNTIME_PACKET_RUNTIME_CUTOVER_AUTHORIZED", "runtime cutover unauthorized", group="authorization"),
        _pass_row("limited_runtime_packet_does_not_open_r6", "RC_B04R6_LIMITED_RUNTIME_PACKET_R6_OPEN_DRIFT", "R6 remains closed", group="authorization"),
        _pass_row("limited_runtime_packet_does_not_authorize_lobe_escalation", "RC_B04R6_LIMITED_RUNTIME_PACKET_LOBE_ESCALATION_DRIFT", "lobe escalation unauthorized", group="authorization"),
        _pass_row("limited_runtime_packet_does_not_authorize_package_promotion", "RC_B04R6_LIMITED_RUNTIME_PACKET_PACKAGE_PROMOTION_DRIFT", "package promotion deferred", group="authorization"),
        _pass_row("limited_runtime_packet_does_not_authorize_commercial_claims", "RC_B04R6_LIMITED_RUNTIME_PACKET_COMMERCIAL_CLAIM_DRIFT", "commercial claims unauthorized", group="authorization"),
        _pass_row("limited_runtime_packet_truth_engine_law_unchanged", "RC_B04R6_LIMITED_RUNTIME_PACKET_TRUTH_ENGINE_MUTATION", "truth-engine law unchanged", group="authorization"),
        _pass_row("limited_runtime_packet_trust_zone_law_unchanged", "RC_B04R6_LIMITED_RUNTIME_PACKET_TRUST_ZONE_MUTATION", "trust-zone law unchanged", group="authorization"),
        _pass_row("limited_runtime_packet_metric_contract_not_mutated", "RC_B04R6_LIMITED_RUNTIME_PACKET_METRIC_MUTATION", "metric contract not mutated", group="authorization"),
        _pass_row("limited_runtime_packet_comparator_not_weakened", "RC_B04R6_LIMITED_RUNTIME_PACKET_COMPARATOR_WEAKENING", "static comparator not weakened", group="authorization"),
        _pass_row("limited_runtime_packet_no_authorization_drift_receipt_passes", "RC_B04R6_LIMITED_RUNTIME_PACKET_LIMITED_RUNTIME_AUTHORIZED", "no authorization drift passes", group="authorization"),
        _pass_row("limited_runtime_next_lawful_move_is_validation", "RC_B04R6_LIMITED_RUNTIME_PACKET_NEXT_MOVE_DRIFT", "next move is packet validation", group="next_move"),
    ]
    rows.extend(
        _pass_row(
            f"limited_runtime_runtime_receipt_requires_{field}",
            "RC_B04R6_LIMITED_RUNTIME_PACKET_RUNTIME_RECEIPT_SCHEMA_MISSING",
            f"runtime receipt schema requires {field}",
            group="controls",
        )
        for field in RUNTIME_RECEIPT_FIELDS
    )
    rows.extend(
        _pass_row(
            f"limited_runtime_incident_freeze_on_{condition}",
            "RC_B04R6_LIMITED_RUNTIME_PACKET_INCIDENT_FREEZE_MISSING",
            f"incident freeze condition {condition}",
            group="controls",
        )
        for condition in INCIDENT_FREEZE_CONDITIONS
    )
    rows.extend(
        _pass_row(
            f"limited_runtime_prep_only_{role}",
            "RC_B04R6_LIMITED_RUNTIME_PACKET_PREP_ONLY_AUTHORITY_DRIFT",
            f"{role} remains prep-only",
            group="prep_only",
        )
        for role in PREP_ONLY_OUTPUT_ROLES
    )
    return rows


RUNTIME_RECEIPT_FIELDS = (
    "runtime_receipt_id",
    "case_id",
    "candidate_id",
    "top_level_verdict",
    "triage_subtype",
    "selector_entry_authorized",
    "static_fallback_available",
    "abstention_fallback_available",
    "null_route_preserved",
    "operator_override_status",
    "kill_switch_status",
    "rollback_readiness_status",
    "route_distribution_snapshot",
    "drift_monitoring_snapshot",
    "external_verifier_trace_id",
    "commercial_claim_status",
)
INCIDENT_FREEZE_CONDITIONS = (
    "blind_label_access",
    "route_success_label_access",
    "static_hold_collapse",
    "abstention_collapse",
    "null_route_collapse",
    "overrouting_collapse",
    "kill_switch_unavailable",
    "rollback_unavailable",
    "operator_override_unavailable",
    "metric_contract_mutation",
    "comparator_weakening",
    "trust_zone_drift",
    "truth_engine_mutation",
)


def _authorization_state() -> Dict[str, Any]:
    return {
        "r6_open": False,
        "shadow_superiority_passed": True,
        "activation_review_validated": True,
        "limited_runtime_authorization_packet_authored": True,
        "limited_runtime_authorization_packet_validated": False,
        "limited_runtime_authorized": False,
        "runtime_execution_authorized": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_authorized": False,
        "activation_cutover_executed": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
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
    handoff: Dict[str, bool],
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
        "selected_architecture_id": SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": SELECTED_ARCHITECTURE_NAME,
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "status": "PASS",
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "may_authorize": list(MAY_AUTHORIZE),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "terminal_defects": list(TERMINAL_DEFECTS),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "validation_rows": validation_rows,
        "handoff_validation": handoff,
        "authorization_state": _authorization_state(),
        "r6_open": False,
        "shadow_superiority_passed": True,
        "activation_review_validated": True,
        "limited_runtime_authorization_packet_authored": True,
        "limited_runtime_authorization_packet_validated": False,
        "limited_runtime_authorized": False,
        "runtime_execution_authorized": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_authorized": False,
        "activation_cutover_executed": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _with_artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    payload = dict(base)
    payload.update({"schema_id": schema_id, "artifact_id": artifact_id})
    payload.update(extra)
    return payload


def _contract(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.limited_runtime_authorization_packet.v1",
        artifact_id="B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET",
        packet_scope={
            "purpose": "Author limited-runtime authorization law before any runtime execution packet can be considered.",
            "non_purpose": [
                "Does not authorize limited runtime execution.",
                "Does not execute runtime cutover.",
                "Does not open R6.",
                "Does not authorize lobe escalation.",
                "Does not authorize package promotion.",
                "Does not authorize commercial activation claims.",
            ],
        },
        authorization_surface={
            "packet_authored": True,
            "packet_validated": False,
            "limited_runtime_authorized": False,
            "runtime_execution_requires_packet_validation": True,
            "runtime_execution_requires_separate_execution_packet": True,
        },
        required_operational_controls=[
            "limited_scope_manifest",
            "static_fallback",
            "abstention_fallback",
            "null_route_preservation",
            "operator_override",
            "kill_switch",
            "rollback_plan",
            "route_distribution_health",
            "drift_monitoring",
            "runtime_receipt_schema",
            "incident_freeze",
            "external_verifier_requirements",
            "commercial_claim_boundary",
        ],
    )


def _binding_receipt(base: Dict[str, Any], *, artifact_id: str, schema_slug: str, subject: str, keys: Sequence[str]) -> Dict[str, Any]:
    hashes = base["binding_hashes"]
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.limited_runtime.{schema_slug}.v1",
        artifact_id=artifact_id,
        binding_subject=subject,
        bound_hashes={key: hashes[key] for key in keys},
        binding_status="BOUND",
    )


def _control_contract(
    base: Dict[str, Any],
    *,
    artifact_id: str,
    schema_slug: str,
    control_id: str,
    requirements: Sequence[str],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = _with_artifact(
        base,
        schema_id=f"kt.b04_r6.limited_runtime.{schema_slug}.v1",
        artifact_id=artifact_id,
        control_id=control_id,
        requirements=list(requirements),
        required_before_limited_runtime_validation=True,
        can_authorize_limited_runtime=False,
        can_execute_runtime=False,
        can_open_r6=False,
        can_promote_package=False,
        can_authorize_commercial_claims=False,
    )
    if extra:
        payload.update(extra)
    return payload


def _prep_only(base: Dict[str, Any], *, artifact_id: str, schema_slug: str, purpose: str) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.{schema_slug}.v1",
        artifact_id=artifact_id,
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_authorize=list(FORBIDDEN_ACTIONS),
        limited_runtime_authorized=False,
        runtime_execution_authorized=False,
        runtime_cutover_authorized=False,
        activation_cutover_executed=False,
        r6_open=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
    )


def _validation_plan(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.limited_runtime.validation_plan.v1",
        artifact_id="B04_R6_LIMITED_RUNTIME_AUTHORIZATION_VALIDATION_PLAN",
        validator_role="hostile verifier of authored limited-runtime authorization packet",
        expected_successful_validation_outcome="B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_VALIDATED__LIMITED_RUNTIME_EXECUTION_PACKET_NEXT",
        expected_next_lawful_move_after_validation="AUTHOR_B04_R6_LIMITED_RUNTIME_EXECUTION_OR_CANARY_PACKET",
        validation_checks=[
            "scope is limited",
            "runtime execution remains unauthorized",
            "static fallback exists",
            "abstention fallback exists",
            "null-route preservation exists",
            "operator override exists",
            "kill switch exists",
            "rollback plan exists",
            "route-distribution health exists",
            "drift monitoring exists",
            "runtime receipts exist",
            "incident freeze conditions exist",
            "commercial claims remain blocked",
            "package promotion remains blocked",
            "R6 does not open",
            "truth/trust law unchanged",
            "next lawful move correctness",
        ],
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v6",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        current_authoritative_lane="AUTHOR_B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET",
        blockers=[
            {
                "blocker_id": "B04R6-FB-041",
                "future_blocker": "Limited-runtime authorization packet mistaken for runtime execution.",
                "neutralization_now": [OUTPUTS["no_authorization_drift_receipt"], OUTPUTS["validation_plan"]],
            },
            {
                "blocker_id": "B04R6-FB-042",
                "future_blocker": "Runtime canary lacks execution packet, incident freeze, or rollback receipts.",
                "neutralization_now": [
                    OUTPUTS["runtime_canary_execution_contract_prep_only"],
                    OUTPUTS["runtime_incident_freeze_contract_prep_only"],
                    OUTPUTS["runtime_rollback_execution_receipt_schema_prep_only"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-043",
                "future_blocker": "External or commercial claims outrun limited-runtime evidence.",
                "neutralization_now": [
                    OUTPUTS["commercial_claim_boundary"],
                    OUTPUTS["external_audit_delta_manifest_prep_only"],
                    OUTPUTS["public_verifier_delta_requirements_prep_only"],
                ],
            },
        ],
    )


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Limited-Runtime Authorization Packet\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "This packet defines the limited-runtime authorization surface that must be validated before any runtime "
        "execution or canary packet may be considered. It does not authorize limited runtime, execute cutover, open R6, "
        "escalate to lobes, promote package, mutate truth/trust law, weaken comparator, widen metrics, or authorize "
        "commercial activation claims. It does not authorize commercial activation claims.\n"
    )


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 limited-runtime authorization packet authoring")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in TEXT_INPUTS.items()}
    handoff = _validate_activation_review_inputs(payloads, texts)
    hashes = _binding_hashes(root, payloads)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_LIMITED_RUNTIME_PACKET_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main") if current_branch != "main" else head
    input_bindings = _input_hashes(root, handoff_git_commit=head)
    rows = _validation_rows()
    generated_utc = utc_now_iso_z()
    base = _base(
        generated_utc=generated_utc,
        head=head,
        current_main_head=current_main_head,
        current_branch=current_branch,
        input_bindings=input_bindings,
        binding_hashes=hashes,
        validation_rows=rows,
        handoff=handoff,
    )
    contract = _contract(base)
    no_auth = _with_artifact(
        base,
        schema_id="kt.b04_r6.limited_runtime.no_authorization_drift_receipt.v1",
        artifact_id="B04_R6_LIMITED_RUNTIME_NO_AUTHORIZATION_DRIFT_RECEIPT",
        no_downstream_authorization_drift=True,
        limited_runtime_authorized=False,
        runtime_execution_authorized=False,
        runtime_cutover_authorized=False,
        activation_cutover_executed=False,
        r6_open=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
    )

    output_payloads: Dict[str, Any] = {
        "packet_contract": contract,
        "packet_receipt": _with_artifact(
            base,
            schema_id="kt.b04_r6.limited_runtime_authorization_packet_receipt.v1",
            artifact_id="B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_RECEIPT",
            packet_contract_hash_preview="written_with_same_binding_hashes",
            no_downstream_authorization_drift=True,
        ),
        "activation_review_validation_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_ACTIVATION_REVIEW_VALIDATION_BINDING_RECEIPT",
            schema_slug="activation_review_validation_binding_receipt",
            subject="validated activation-review packet",
            keys=("activation_review_validation_contract_hash", "activation_review_validation_receipt_hash", "activation_review_validation_report_hash"),
        ),
        "shadow_result_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_SHADOW_RESULT_BINDING_RECEIPT",
            schema_slug="shadow_result_binding_receipt",
            subject="passed shadow-superiority result",
            keys=("shadow_screen_result_hash", "shadow_screen_execution_receipt_hash"),
        ),
        "candidate_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_CANDIDATE_BINDING_RECEIPT",
            schema_slug="candidate_binding_receipt",
            subject="admissible AFSH candidate",
            keys=("candidate_hash", "candidate_manifest_hash", "candidate_semantic_hash"),
        ),
        "scope_manifest": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_SCOPE_MANIFEST",
            schema_slug="scope_manifest",
            control_id="LIMITED_RUNTIME_SCOPE",
            requirements=("scope_must_be_limited", "canary_or_shadow_runtime_only", "execution_packet_required_before_any_runtime", "commercial_claims_forbidden"),
            extra={
                "limited_scope_required": True,
                "allowed_future_modes_after_validation": ["CANARY_ONLY", "SHADOW_RUNTIME_ONLY"],
                "max_live_traffic_percent_authorized_by_this_packet": 0,
                "future_initial_canary_percent_cap_requires_execution_packet": True,
            },
        ),
        "static_fallback_contract": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_STATIC_FALLBACK_CONTRACT",
            schema_slug="static_fallback_contract",
            control_id="STATIC_FALLBACK",
            requirements=("static_comparator_remains_available", "static_hold_default_preserved", "fallback_receipt_required"),
        ),
        "abstention_fallback_contract": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_ABSTENTION_FALLBACK_CONTRACT",
            schema_slug="abstention_fallback_contract",
            control_id="ABSTENTION_FALLBACK",
            requirements=("boundary_uncertainty_abstains", "trust_zone_uncertainty_abstains", "abstention_receipt_required"),
        ),
        "null_route_preservation_contract": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_NULL_ROUTE_PRESERVATION_CONTRACT",
            schema_slug="null_route_preservation_contract",
            control_id="NULL_ROUTE_PRESERVATION",
            requirements=("null_route_controls_do_not_enter_selector", "surface_temptations_remain_blocked", "null_route_receipt_required"),
        ),
        "operator_override_contract": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_OPERATOR_OVERRIDE_CONTRACT",
            schema_slug="operator_override_contract",
            control_id="OPERATOR_OVERRIDE",
            requirements=("operator_override_required", "override_may_force_static_fallback", "override_may_force_abstention", "override_cannot_promote_package"),
        ),
        "kill_switch_contract": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_KILL_SWITCH_CONTRACT",
            schema_slug="kill_switch_contract",
            control_id="KILL_SWITCH",
            requirements=("kill_switch_required", "kill_switch_returns_to_static_comparator", "kill_switch_receipt_required", "kill_switch_test_required_before_execution"),
        ),
        "rollback_plan": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_ROLLBACK_PLAN",
            schema_slug="rollback_plan",
            control_id="ROLLBACK_PLAN",
            requirements=("rollback_to_static_comparator_required", "rollback_execution_receipt_required", "rollback_drill_required_before_execution"),
        ),
        "route_distribution_health_contract": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_ROUTE_DISTRIBUTION_HEALTH_CONTRACT",
            schema_slug="route_distribution_health_contract",
            control_id="ROUTE_DISTRIBUTION_HEALTH",
            requirements=("selector_entry_rate_monitored", "static_hold_rate_monitored", "abstention_rate_monitored", "null_route_rate_monitored", "overrouting_alarm_required"),
        ),
        "drift_monitoring_contract": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_DRIFT_MONITORING_CONTRACT",
            schema_slug="drift_monitoring_contract",
            control_id="DRIFT_MONITORING",
            requirements=("metric_drift_freezes_runtime", "comparator_drift_freezes_runtime", "trust_zone_drift_freezes_runtime", "truth_engine_drift_freezes_runtime"),
        ),
        "runtime_receipt_schema": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_RECEIPT_SCHEMA",
            schema_slug="runtime_receipt_schema",
            control_id="RUNTIME_RECEIPT_SCHEMA",
            requirements=RUNTIME_RECEIPT_FIELDS,
            extra={"required_fields": list(RUNTIME_RECEIPT_FIELDS)},
        ),
        "incident_freeze_contract": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_INCIDENT_FREEZE_CONTRACT",
            schema_slug="incident_freeze_contract",
            control_id="INCIDENT_FREEZE",
            requirements=INCIDENT_FREEZE_CONDITIONS,
            extra={"freeze_conditions": list(INCIDENT_FREEZE_CONDITIONS), "any_condition_freezes_runtime_consideration": True},
        ),
        "external_verifier_requirements": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_EXTERNAL_VERIFIER_REQUIREMENTS",
            schema_slug="external_verifier_requirements",
            control_id="EXTERNAL_VERIFIER",
            requirements=("external_verifier_non_executing", "raw_hash_bound_artifacts_required", "runtime_claims_require_later_evidence_review"),
        ),
        "commercial_claim_boundary": _control_contract(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_COMMERCIAL_CLAIM_BOUNDARY",
            schema_slug="commercial_claim_boundary",
            control_id="COMMERCIAL_CLAIM_BOUNDARY",
            requirements=("commercial_activation_claims_unauthorized", "package_promotion_prohibited", "shadow_superiority_must_remain_shadow_qualified", "runtime_authorization_packet_is_not_commercial_claim"),
        ),
        "no_authorization_drift_receipt": no_auth,
        "validation_plan": _validation_plan(base),
        "validation_reason_codes": _with_artifact(
            base,
            schema_id="kt.b04_r6.limited_runtime.validation_reason_codes.v1",
            artifact_id="B04_R6_LIMITED_RUNTIME_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
            terminal_defects=list(TERMINAL_DEFECTS),
        ),
        "limited_runtime_validation_plan_prep_only": _prep_only(base, artifact_id="B04_R6_LIMITED_RUNTIME_VALIDATION_PLAN_PREP_ONLY", schema_slug="limited_runtime_validation_plan_prep_only", purpose="Prep-only duplicate of validation plan for downstream lane-ahead tooling."),
        "runtime_canary_execution_contract_prep_only": _prep_only(base, artifact_id="B04_R6_RUNTIME_CANARY_EXECUTION_CONTRACT_PREP_ONLY", schema_slug="runtime_canary_execution_contract_prep_only", purpose="Draft future limited runtime canary execution packet."),
        "runtime_evidence_packet_prep_only": _prep_only(base, artifact_id="B04_R6_RUNTIME_EVIDENCE_PACKET_PREP_ONLY", schema_slug="runtime_evidence_packet_prep_only", purpose="Draft future runtime evidence review packet."),
        "runtime_incident_freeze_contract_prep_only": _prep_only(base, artifact_id="B04_R6_RUNTIME_INCIDENT_FREEZE_CONTRACT_PREP_ONLY", schema_slug="runtime_incident_freeze_contract_prep_only", purpose="Draft future runtime incident freeze execution law."),
        "runtime_operator_override_playbook_prep_only": "# B04 R6 Runtime Operator Override Playbook PREP_ONLY\n\nAuthority: PREP_ONLY\n\nThis playbook cannot authorize limited runtime, execute runtime, open R6, promote package, or authorize commercial activation claims.\n",
        "runtime_rollback_execution_receipt_schema_prep_only": _prep_only(base, artifact_id="B04_R6_RUNTIME_ROLLBACK_EXECUTION_RECEIPT_SCHEMA_PREP_ONLY", schema_slug="runtime_rollback_execution_receipt_schema_prep_only", purpose="Draft future rollback execution receipt schema."),
        "runtime_authorization_rejection_closeout_prep_only": _prep_only(base, artifact_id="B04_R6_LIMITED_RUNTIME_REJECTION_CLOSEOUT_PREP_ONLY", schema_slug="limited_runtime_rejection_closeout_prep_only", purpose="Draft failure path if limited runtime authorization is rejected."),
        "activation_review_repair_packet_prep_only": _prep_only(base, artifact_id="B04_R6_ACTIVATION_REVIEW_REPAIR_PACKET_PREP_ONLY", schema_slug="activation_review_repair_packet_prep_only", purpose="Draft repair path for activation-review defects."),
        "operational_safety_defect_ledger_prep_only": _prep_only(base, artifact_id="B04_R6_OPERATIONAL_SAFETY_DEFECT_LEDGER_PREP_ONLY", schema_slug="operational_safety_defect_ledger_prep_only", purpose="Draft defect ledger for operational safety findings."),
        "runtime_authorization_redesign_court_prep_only": _prep_only(base, artifact_id="B04_R6_RUNTIME_AUTHORIZATION_REDESIGN_COURT_PREP_ONLY", schema_slug="runtime_authorization_redesign_court_prep_only", purpose="Draft redesign court if limited runtime law is unsafe."),
        "package_promotion_review_preconditions_prep_only": _prep_only(base, artifact_id="B04_R6_PACKAGE_PROMOTION_REVIEW_PRECONDITIONS_PREP_ONLY", schema_slug="package_promotion_review_preconditions_prep_only", purpose="Draft future package promotion preconditions without authorizing promotion."),
        "external_audit_delta_manifest_prep_only": _prep_only(base, artifact_id="B04_R6_EXTERNAL_AUDIT_DELTA_MANIFEST_PREP_ONLY", schema_slug="external_audit_delta_manifest_prep_only", purpose="Draft future external audit delta manifest."),
        "public_verifier_delta_requirements_prep_only": _prep_only(base, artifact_id="B04_R6_PUBLIC_VERIFIER_DELTA_REQUIREMENTS_PREP_ONLY", schema_slug="public_verifier_delta_requirements_prep_only", purpose="Draft future public verifier delta requirements."),
        "future_blocker_register": _future_blocker_register(base),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v17",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            verdict="NEXT_LAWFUL_MOVE_SET",
        ),
    }

    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "packet_report":
            path.write_text(_report_text(contract), encoding="utf-8", newline="\n")
        else:
            payload = output_payloads[role]
            if isinstance(payload, str):
                path.write_text(payload, encoding="utf-8", newline="\n")
            else:
                write_json_stable(path, payload)
    return output_payloads["packet_contract"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author B04 R6 limited-runtime authorization packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
