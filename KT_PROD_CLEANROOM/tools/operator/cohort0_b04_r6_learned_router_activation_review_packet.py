from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_afsh_shadow_screen as screen
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-learned-router-activation-review-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})
AUTHORITATIVE_LANE = "B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET"
PREVIOUS_LANE = screen.AUTHORITATIVE_LANE

EXPECTED_PREVIOUS_OUTCOME = screen.OUTCOME_PASSED
EXPECTED_PREVIOUS_NEXT_MOVE = screen.NEXT_BY_OUTCOME[screen.OUTCOME_PASSED]
OUTCOME_BOUND = "B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET_BOUND__ACTIVATION_REVIEW_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET_INVALID__REPAIR_OR_CLOSEOUT_REQUIRED"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET"

SELECTED_ARCHITECTURE_ID = screen.SELECTED_ARCHITECTURE_ID
SELECTED_ARCHITECTURE_NAME = screen.SELECTED_ARCHITECTURE_NAME
CANDIDATE_ID = screen.CANDIDATE_ID
CANDIDATE_VERSION = screen.CANDIDATE_VERSION

FORBIDDEN_ACTIONS = (
    "R6_OPEN",
    "LIMITED_RUNTIME_AUTHORIZED",
    "RUNTIME_CUTOVER_AUTHORIZED",
    "ACTIVATION_CUTOVER_EXECUTED",
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
)
ACTIVATION_SUCCESS_REQUIREMENTS = (
    "shadow_result_binding_valid",
    "zero_fired_disqualifiers_confirmed",
    "candidate_binding_stable",
    "runtime_scope_limited",
    "static_fallback_defined",
    "kill_switch_defined",
    "rollback_plan_defined",
    "operator_override_defined",
    "route_distribution_health_defined",
    "drift_monitoring_defined",
    "runtime_receipt_schema_defined",
    "truth_engine_law_unchanged",
    "trust_zone_law_unchanged",
    "commercial_claim_boundary_defined",
    "package_promotion_not_automatic",
)
RUNTIME_PRECONDITION_KEYS = (
    "limited_scope_required",
    "canary_or_shadow_runtime_required",
    "static_fallback_required",
    "abstention_fallback_required",
    "null_route_preservation_required",
    "operator_override_required",
    "kill_switch_required",
    "rollback_plan_required",
    "route_distribution_health_required",
    "drift_monitoring_required",
    "runtime_receipt_schema_required",
    "external_verifier_requirements_required",
)
REASON_CODES = (
    "RC_B04R6_ACT_REVIEW_PACKET_CONTRACT_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_MAIN_HEAD_MISMATCH",
    "RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RECEIPT_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_CANDIDATE_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_SHADOW_PACKET_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_UNIVERSE_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_COURT_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_SOURCE_PACKET_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_ADMISSIBILITY_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_TRIAGE_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_COMPARATOR_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_METRIC_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_DISQUALIFIER_BINDING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_FIRED_DISQUALIFIERS_NOT_ZERO",
    "RC_B04R6_ACT_REVIEW_PACKET_SCOPE_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_RUNTIME_PRECONDITIONS_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_STATIC_FALLBACK_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_OPERATOR_OVERRIDE_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_KILL_SWITCH_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_ROLLBACK_PLAN_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_ROUTE_DISTRIBUTION_HEALTH_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_DRIFT_MONITORING_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_RUNTIME_RECEIPT_SCHEMA_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_EXTERNAL_VERIFIER_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_COMMERCIAL_BOUNDARY_MISSING",
    "RC_B04R6_ACT_REVIEW_PACKET_SELF_VALIDATION_DRIFT",
    "RC_B04R6_ACT_REVIEW_PACKET_LIMITED_RUNTIME_AUTHORIZED",
    "RC_B04R6_ACT_REVIEW_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_ACT_REVIEW_PACKET_R6_OPEN_DRIFT",
    "RC_B04R6_ACT_REVIEW_PACKET_LOBE_ESCALATION_DRIFT",
    "RC_B04R6_ACT_REVIEW_PACKET_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_ACT_REVIEW_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_ACT_REVIEW_PACKET_TRUTH_ENGINE_MUTATION",
    "RC_B04R6_ACT_REVIEW_PACKET_TRUST_ZONE_MUTATION",
    "RC_B04R6_ACT_REVIEW_PACKET_METRIC_MUTATION",
    "RC_B04R6_ACT_REVIEW_PACKET_COMPARATOR_WEAKENING",
    "RC_B04R6_ACT_REVIEW_PACKET_NEXT_MOVE_DRIFT",
)
TERMINAL_DEFECTS = (
    "FIRED_DISQUALIFIERS_NOT_ZERO",
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
    "shadow_screen_result": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_result.json",
    "shadow_execution_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_execution_receipt.json",
    "shadow_disqualifier_result_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_disqualifier_result_receipt.json",
    "shadow_trace_completeness_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_trace_completeness_receipt.json",
    "shadow_trust_zone_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_trust_zone_receipt.json",
    "shadow_no_authorization_drift_receipt": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_no_authorization_drift_receipt.json",
    "candidate_manifest": screen.INPUTS["candidate_manifest"],
    "candidate_artifact": screen.INPUTS["candidate_artifact"],
    "candidate_hash_receipt": screen.INPUTS["candidate_hash_receipt"],
    "validated_shadow_packet_contract": screen.INPUTS["packet_contract"],
    "validated_shadow_packet_validation_receipt": screen.INPUTS["packet_validation_receipt"],
    "validated_blind_universe_receipt": screen.INPUTS["universe_validation_receipt"],
    "validated_route_economics_court_receipt": screen.INPUTS["court_validation_receipt"],
    "validated_source_packet_receipt": screen.INPUTS["source_packet_validation_receipt"],
    "admissibility_receipt": screen.INPUTS["admissibility_receipt"],
    "numeric_triage_emit_core": screen.INPUTS["numeric_triage_emit_core"],
    "static_comparator_contract": screen.INPUTS["static_comparator_contract"],
    "metric_contract": screen.INPUTS["metric_contract"],
    "disqualifier_ledger": screen.INPUTS["disqualifier_ledger"],
    "previous_next_lawful_move": "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
}
TEXT_INPUTS = {
    "shadow_result_report": "KT_PROD_CLEANROOM/reports/b04_r6_afsh_shadow_screen_result_report.md",
}
MUTABLE_HANDOFF_ROLES = frozenset({"previous_next_lawful_move"})

OUTPUTS = {
    "packet_contract": "b04_r6_learned_router_activation_review_packet_contract.json",
    "packet_receipt": "b04_r6_learned_router_activation_review_packet_receipt.json",
    "packet_report": "b04_r6_learned_router_activation_review_packet_report.md",
    "shadow_result_binding_receipt": "b04_r6_activation_review_shadow_result_binding_receipt.json",
    "candidate_binding_receipt": "b04_r6_activation_review_candidate_binding_receipt.json",
    "screen_packet_binding_receipt": "b04_r6_activation_review_screen_packet_binding_receipt.json",
    "universe_binding_receipt": "b04_r6_activation_review_universe_binding_receipt.json",
    "court_binding_receipt": "b04_r6_activation_review_court_binding_receipt.json",
    "source_packet_binding_receipt": "b04_r6_activation_review_source_packet_binding_receipt.json",
    "admissibility_binding_receipt": "b04_r6_activation_review_admissibility_binding_receipt.json",
    "triage_core_binding_receipt": "b04_r6_activation_review_triage_core_binding_receipt.json",
    "static_comparator_binding_receipt": "b04_r6_activation_review_static_comparator_binding_receipt.json",
    "metric_contract_binding_receipt": "b04_r6_activation_review_metric_contract_binding_receipt.json",
    "disqualifier_binding_receipt": "b04_r6_activation_review_disqualifier_binding_receipt.json",
    "trace_completeness_binding_receipt": "b04_r6_activation_review_trace_completeness_binding_receipt.json",
    "no_authorization_drift_receipt": "b04_r6_activation_review_no_authorization_drift_receipt.json",
    "scope_contract": "b04_r6_activation_review_scope_contract.json",
    "runtime_preconditions_contract": "b04_r6_activation_review_runtime_preconditions_contract.json",
    "static_fallback_contract": "b04_r6_activation_review_static_fallback_contract.json",
    "operator_override_contract": "b04_r6_activation_review_operator_override_contract.json",
    "kill_switch_contract": "b04_r6_activation_review_kill_switch_contract.json",
    "rollback_plan_contract": "b04_r6_activation_review_rollback_plan_contract.json",
    "route_distribution_health_contract": "b04_r6_activation_review_route_distribution_health_contract.json",
    "drift_monitoring_contract": "b04_r6_activation_review_drift_monitoring_contract.json",
    "runtime_receipt_schema_contract": "b04_r6_activation_review_runtime_receipt_schema_contract.json",
    "external_verifier_requirements": "b04_r6_activation_review_external_verifier_requirements.json",
    "commercial_claim_boundary": "b04_r6_activation_review_commercial_claim_boundary.json",
    "validation_plan": "b04_r6_activation_review_validation_plan.json",
    "validation_reason_codes": "b04_r6_activation_review_validation_reason_codes.json",
    "limited_runtime_authorization_prep_only_draft": "b04_r6_limited_runtime_authorization_packet_prep_only_draft.json",
    "limited_runtime_scope_manifest_prep_only_draft": "b04_r6_limited_runtime_scope_manifest_prep_only_draft.json",
    "limited_runtime_monitoring_prep_only_draft": "b04_r6_limited_runtime_monitoring_contract_prep_only_draft.json",
    "limited_runtime_rollback_receipt_schema_prep_only_draft": "b04_r6_limited_runtime_rollback_execution_receipt_schema_prep_only_draft.json",
    "package_promotion_review_preconditions_prep_only_draft": "b04_r6_package_promotion_review_preconditions_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only_draft": "b04_r6_external_audit_delta_manifest_prep_only_draft.json",
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
            "binding_kind": "file_sha256_at_activation_review_packet_authoring",
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
                "binding_kind": "file_sha256_at_activation_review_packet_authoring",
            }
        )
    return rows


def _input_binding_sha(bindings: Iterable[Dict[str, Any]], role: str) -> str:
    matches = [str(row.get("sha256", "")).strip() for row in bindings if row.get("role") == role]
    if len(matches) != 1:
        _fail("RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", f"expected one input binding for {role}")
    return matches[0]


def _ensure_false(payload: Dict[str, Any], key: str, *, label: str, code: str) -> None:
    if key in payload and bool(payload.get(key)):
        _fail(code, f"{label} sets forbidden true flag: {key}")


def _ensure_runtime_closed(payload: Dict[str, Any], *, label: str) -> None:
    for key, code in (
        ("r6_open", "RC_B04R6_ACT_REVIEW_PACKET_R6_OPEN_DRIFT"),
        ("limited_runtime_authorized", "RC_B04R6_ACT_REVIEW_PACKET_LIMITED_RUNTIME_AUTHORIZED"),
        ("runtime_cutover_authorized", "RC_B04R6_ACT_REVIEW_PACKET_RUNTIME_CUTOVER_AUTHORIZED"),
        ("activation_cutover_authorized", "RC_B04R6_ACT_REVIEW_PACKET_RUNTIME_CUTOVER_AUTHORIZED"),
        ("activation_cutover_executed", "RC_B04R6_ACT_REVIEW_PACKET_RUNTIME_CUTOVER_AUTHORIZED"),
        ("lobe_escalation_authorized", "RC_B04R6_ACT_REVIEW_PACKET_LOBE_ESCALATION_DRIFT"),
        ("package_promotion_authorized", "RC_B04R6_ACT_REVIEW_PACKET_PACKAGE_PROMOTION_DRIFT"),
        ("commercial_activation_claim_authorized", "RC_B04R6_ACT_REVIEW_PACKET_COMMERCIAL_CLAIM_DRIFT"),
    ):
        _ensure_false(payload, key, label=label, code=code)
    if payload.get("package_promotion") not in (None, "DEFERRED"):
        _fail("RC_B04R6_ACT_REVIEW_PACKET_PACKAGE_PROMOTION_DRIFT", f"{label} package promotion is not deferred")
    if payload.get("truth_engine_law_changed") is True or payload.get("truth_engine_derivation_law_unchanged") is False:
        _fail("RC_B04R6_ACT_REVIEW_PACKET_TRUTH_ENGINE_MUTATION", f"{label} mutates truth-engine law")
    if payload.get("trust_zone_law_changed") is True or payload.get("trust_zone_law_unchanged") is False:
        _fail("RC_B04R6_ACT_REVIEW_PACKET_TRUST_ZONE_MUTATION", f"{label} mutates trust-zone law")


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
        _fail("RC_B04R6_ACT_REVIEW_PACKET_NEXT_MOVE_DRIFT", "handoff lacks valid predecessor or self-replay lane identity")
    return {"predecessor_handoff_accepted": predecessor, "self_replay_handoff_accepted": self_replay}


def _require_shadow_pass(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> Dict[str, bool]:
    result = payloads["shadow_screen_result"]
    receipt = payloads["shadow_execution_receipt"]
    disq = payloads["shadow_disqualifier_result_receipt"]
    trace = payloads["shadow_trace_completeness_receipt"]
    no_auth = payloads["shadow_no_authorization_drift_receipt"]
    report_raw = texts["shadow_result_report"].lower()
    report_text = report_raw.replace("-", " ")
    if "shadow superiority" not in report_text and EXPECTED_PREVIOUS_OUTCOME.lower() not in report_raw:
        _fail("RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", "shadow result report missing shadow superiority marker")
    for label, payload in payloads.items():
        _ensure_runtime_closed(payload, label=label)
        if label in {"previous_next_lawful_move"}:
            _validate_handoff(payload)
            continue
        if payload.get("status") not in (None, "PASS"):
            _fail("RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", f"{label} must be PASS or structural input")
    for label, payload in (("shadow_screen_result", result), ("shadow_execution_receipt", receipt)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", f"{label} lane identity drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", f"{label} selected outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_ACT_REVIEW_PACKET_NEXT_MOVE_DRIFT", f"{label} next lawful move drift")
        shadow_passed = payload.get("shadow_superiority_passed") is True or str(payload.get("shadow_superiority_verdict", "")).strip() == "PASSED"
        if shadow_passed is not True or payload.get("shadow_superiority_earned") is not True:
            _fail("RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", f"{label} did not bind shadow-superiority pass")
        if payload.get("shadow_screen_executed") is not True:
            _fail("RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", f"{label} did not execute the prior shadow screen")
    fired = result.get("disqualifier_result", {}).get("fired_disqualifiers")
    if fired != []:
        _fail("RC_B04R6_ACT_REVIEW_PACKET_FIRED_DISQUALIFIERS_NOT_ZERO", f"shadow result fired disqualifiers: {fired}")
    if disq.get("disqualifier_result", {}).get("fired_disqualifiers") != []:
        _fail("RC_B04R6_ACT_REVIEW_PACKET_FIRED_DISQUALIFIERS_NOT_ZERO", "disqualifier receipt is not zero-fired")
    if no_auth.get("no_downstream_authorization_drift") is not True:
        _fail("RC_B04R6_ACT_REVIEW_PACKET_LIMITED_RUNTIME_AUTHORIZED", "shadow no-authorization-drift receipt failed")
    if trace.get("status") != "PASS":
        _fail("RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", "trace completeness receipt did not pass")
    return _validate_handoff(payloads["previous_next_lawful_move"])


def _validate_bindings(root: Path, payloads: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    result = payloads["shadow_screen_result"]
    execution_receipt = payloads["shadow_execution_receipt"]
    binding_hashes = dict(result.get("binding_hashes", {}))
    if binding_hashes != dict(execution_receipt.get("binding_hashes", {})):
        _fail("RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", "shadow result and execution receipt binding hashes diverged")
    input_rows = result.get("input_bindings", [])
    if not isinstance(input_rows, list):
        _fail("RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", "shadow result missing input bindings")

    required_from_result = {
        "candidate_artifact_hash": "candidate_artifact",
        "candidate_manifest_hash": "candidate_manifest",
        "candidate_semantic_hash": "candidate_semantic_hash",
        "validated_shadow_packet_hash": "packet_contract",
        "validated_shadow_packet_validation_receipt_hash": "packet_validation_receipt",
        "validated_blind_universe_hash": "validated_blind_universe_hash",
        "validated_route_economics_court_hash": "validated_court_hash",
        "validated_source_packet_hash": "validated_source_packet_hash",
        "admissibility_receipt_hash": "admissibility_receipt",
        "numeric_triage_emit_core_hash": "numeric_triage_emit_core",
        "static_comparator_contract_hash": "static_comparator_contract",
        "metric_contract_hash": "metric_contract",
        "disqualifier_ledger_hash": "disqualifier_ledger",
    }
    hashes: Dict[str, str] = {
        "shadow_screen_result_hash": file_sha256(common.resolve_path(root, INPUTS["shadow_screen_result"])),
        "shadow_screen_execution_receipt_hash": file_sha256(common.resolve_path(root, INPUTS["shadow_execution_receipt"])),
        "shadow_screen_result_report_hash": file_sha256(common.resolve_path(root, TEXT_INPUTS["shadow_result_report"])),
        "fired_disqualifier_receipt_hash": file_sha256(common.resolve_path(root, INPUTS["shadow_disqualifier_result_receipt"])),
        "trace_completeness_receipt_hash": file_sha256(common.resolve_path(root, INPUTS["shadow_trace_completeness_receipt"])),
        "trust_zone_validation_receipt_hash": file_sha256(common.resolve_path(root, INPUTS["shadow_trust_zone_receipt"])),
        "no_authorization_drift_receipt_hash": file_sha256(common.resolve_path(root, INPUTS["shadow_no_authorization_drift_receipt"])),
        "candidate_hash_receipt_hash": file_sha256(common.resolve_path(root, INPUTS["candidate_hash_receipt"])),
    }
    for target, source in required_from_result.items():
        if source.endswith("_hash"):
            value = str(result.get(source, "")).strip()
        else:
            value = _input_binding_sha(input_rows, source)
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            _fail("RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", f"missing hash for {target}")
        hashes[target] = value
    upstream_validation_receipts = {
        "validated_blind_universe_receipt_hash": "universe_validation_receipt",
        "validated_route_economics_court_receipt_hash": "court_validation_receipt",
        "validated_source_packet_receipt_hash": "source_packet_validation_receipt",
    }
    for target, source_role in upstream_validation_receipts.items():
        value = _input_binding_sha(input_rows, source_role)
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            _fail("RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", f"missing upstream receipt hash for {target}")
        hashes[target] = value
    direct_checks = {
        "candidate_artifact_hash": "candidate_artifact",
        "candidate_manifest_hash": "candidate_manifest",
        "validated_shadow_packet_hash": "validated_shadow_packet_contract",
        "validated_shadow_packet_validation_receipt_hash": "validated_shadow_packet_validation_receipt",
        "validated_blind_universe_receipt_hash": "validated_blind_universe_receipt",
        "validated_route_economics_court_receipt_hash": "validated_route_economics_court_receipt",
        "validated_source_packet_receipt_hash": "validated_source_packet_receipt",
        "admissibility_receipt_hash": "admissibility_receipt",
        "numeric_triage_emit_core_hash": "numeric_triage_emit_core",
        "static_comparator_contract_hash": "static_comparator_contract",
        "metric_contract_hash": "metric_contract",
        "disqualifier_ledger_hash": "disqualifier_ledger",
    }
    for hash_key, role in direct_checks.items():
        actual = file_sha256(common.resolve_path(root, INPUTS[role]))
        if actual != hashes[hash_key]:
            _fail("RC_B04R6_ACT_REVIEW_PACKET_CANDIDATE_BINDING_MISSING", f"{role} hash mismatch for {hash_key}")
    packet_validation_hashes = payloads["validated_shadow_packet_validation_receipt"].get("binding_hashes", {})
    packet_contract = payloads["validated_shadow_packet_contract"]
    semantic_anchors = {
        "validated_blind_universe_hash": "validated_blind_universe_hash",
        "validated_route_economics_court_hash": "validated_court_hash",
        "validated_source_packet_hash": "validated_source_packet_hash",
    }
    packet_contract_hashes = packet_contract.get("binding_hashes", {})
    for activation_key, packet_key in semantic_anchors.items():
        expected = str(packet_validation_hashes.get(packet_key, "")).strip()
        packet_contract_value = str(packet_contract_hashes.get(packet_key) or packet_contract.get(packet_key, "")).strip()
        if hashes[activation_key] != expected or packet_contract_value != expected:
            _fail(
                "RC_B04R6_ACT_REVIEW_PACKET_SHADOW_PACKET_BINDING_MISSING",
                f"{activation_key} does not match validated shadow-packet binding {packet_key}",
            )
    for alias, source_key in (
        ("candidate_hash", "candidate_artifact_hash"),
        ("candidate_manifest_hash", "candidate_manifest_hash"),
        ("candidate_semantic_hash", "candidate_semantic_hash"),
        ("validated_shadow_screen_packet_hash", "validated_shadow_packet_hash"),
    ):
        hashes[alias] = hashes[source_key]
    if binding_hashes:
        for key in ("candidate_manifest_hash", "candidate_artifact_hash", "candidate_semantic_hash"):
            if binding_hashes.get(key) and binding_hashes[key] != hashes[key]:
                _fail("RC_B04R6_ACT_REVIEW_PACKET_CANDIDATE_BINDING_MISSING", f"result binding hash drift: {key}")
    return hashes


def _pass_row(check_id: str, reason_code: str, detail: str, *, group: str) -> Dict[str, str]:
    return {"check_id": check_id, "group": group, "status": "PASS", "reason_code": reason_code, "detail": detail}


def _validation_rows() -> list[Dict[str, str]]:
    rows = [
        _pass_row("shadow_superiority_result_bound", "RC_B04R6_ACT_REVIEW_PACKET_SHADOW_RESULT_BINDING_MISSING", "shadow-superiority result hash is bound", group="binding"),
        _pass_row("zero_fired_disqualifiers_bound", "RC_B04R6_ACT_REVIEW_PACKET_FIRED_DISQUALIFIERS_NOT_ZERO", "zero fired disqualifiers are bound", group="binding"),
        _pass_row("candidate_binding_bound", "RC_B04R6_ACT_REVIEW_PACKET_CANDIDATE_BINDING_MISSING", "candidate hashes are bound", group="binding"),
        _pass_row("screen_packet_binding_bound", "RC_B04R6_ACT_REVIEW_PACKET_SHADOW_PACKET_BINDING_MISSING", "validated shadow packet is bound", group="binding"),
        _pass_row("runtime_preconditions_defined", "RC_B04R6_ACT_REVIEW_PACKET_RUNTIME_PRECONDITIONS_MISSING", "runtime preconditions are defined but non-authorizing", group="runtime_controls"),
        _pass_row("static_fallback_defined", "RC_B04R6_ACT_REVIEW_PACKET_STATIC_FALLBACK_MISSING", "static fallback remains mandatory", group="runtime_controls"),
        _pass_row("operator_override_defined", "RC_B04R6_ACT_REVIEW_PACKET_OPERATOR_OVERRIDE_MISSING", "operator override is mandatory", group="runtime_controls"),
        _pass_row("kill_switch_defined", "RC_B04R6_ACT_REVIEW_PACKET_KILL_SWITCH_MISSING", "kill switch is mandatory", group="runtime_controls"),
        _pass_row("rollback_plan_defined", "RC_B04R6_ACT_REVIEW_PACKET_ROLLBACK_PLAN_MISSING", "rollback plan is mandatory", group="runtime_controls"),
        _pass_row("commercial_claim_boundary_defined", "RC_B04R6_ACT_REVIEW_PACKET_COMMERCIAL_BOUNDARY_MISSING", "commercial activation claims remain unauthorized", group="claim_boundary"),
        _pass_row("limited_runtime_not_authorized", "RC_B04R6_ACT_REVIEW_PACKET_LIMITED_RUNTIME_AUTHORIZED", "limited runtime remains unauthorized", group="authorization"),
        _pass_row("r6_not_open", "RC_B04R6_ACT_REVIEW_PACKET_R6_OPEN_DRIFT", "R6 remains closed", group="authorization"),
        _pass_row("truth_engine_unchanged", "RC_B04R6_ACT_REVIEW_PACKET_TRUTH_ENGINE_MUTATION", "truth-engine law unchanged", group="authorization"),
        _pass_row("trust_zone_unchanged", "RC_B04R6_ACT_REVIEW_PACKET_TRUST_ZONE_MUTATION", "trust-zone law unchanged", group="authorization"),
        _pass_row("next_move_exact", "RC_B04R6_ACT_REVIEW_PACKET_NEXT_MOVE_DRIFT", "next lawful move is activation-review validation", group="handoff"),
    ]
    return rows


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
    authorization_state = {
        "r6_open": False,
        "shadow_superiority_passed": True,
        "activation_review_packet_authored": True,
        "activation_review_validated": False,
        "limited_runtime_authorized": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
    }
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
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "terminal_defects": list(TERMINAL_DEFECTS),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "validation_rows": validation_rows,
        "handoff_validation": handoff,
        "authorization_state": authorization_state,
        "r6_open": False,
        "shadow_superiority_passed": True,
        "activation_review_packet_authored": True,
        "activation_review_validated": False,
        "limited_runtime_authorized": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "activation_cutover_authorized": False,
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


def _contract(base: Dict[str, Any], shadow_result: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.learned_router_activation_review_packet.v1",
        artifact_id="B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET",
        predecessor_outcome=EXPECTED_PREVIOUS_OUTCOME,
        shadow_screen_result={
            "status": "SHADOW_SUPERIORITY_PASSED",
            "selected_outcome": shadow_result.get("selected_outcome"),
            "fired_disqualifiers": shadow_result.get("disqualifier_result", {}).get("fired_disqualifiers", []),
            "runtime_activation_earned": False,
            "r6_open_earned": False,
            "package_promotion_earned": False,
        },
        packet_scope={
            "purpose": "Author the activation-review law required before any limited runtime authorization can be considered.",
            "non_purpose": [
                "Does not open R6.",
                "Does not authorize runtime cutover.",
                "Does not execute activation.",
                "Does not authorize lobe escalation.",
                "Does not authorize package promotion.",
                "Does not create commercial activation claims.",
            ],
        },
        binding_requirements={
            "shadow_screen_result_hash_required": True,
            "shadow_screen_execution_receipt_hash_required": True,
            "shadow_screen_result_report_hash_required": True,
            "candidate_hash_required": True,
            "candidate_manifest_hash_required": True,
            "validated_shadow_packet_hash_required": True,
            "validated_universe_hash_required": True,
            "validated_court_hash_required": True,
            "validated_source_packet_hash_required": True,
            "admissibility_hash_required": True,
            "triage_core_hash_required": True,
            "static_comparator_hash_required": True,
            "metric_contract_hash_required": True,
            "disqualifier_ledger_hash_required": True,
            "trace_completeness_hash_required": True,
        },
        runtime_preconditions={key: True for key in RUNTIME_PRECONDITION_KEYS},
        activation_review_success_requirements=list(ACTIVATION_SUCCESS_REQUIREMENTS),
    )


def _binding_receipt(base: Dict[str, Any], *, artifact_id: str, schema_slug: str, subject: str, keys: Sequence[str]) -> Dict[str, Any]:
    hashes = base["binding_hashes"]
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.activation_review.{schema_slug}.v1",
        artifact_id=artifact_id,
        binding_subject=subject,
        bound_hashes={key: hashes[key] for key in keys},
        binding_status="BOUND",
    )


def _control_contract(base: Dict[str, Any], *, artifact_id: str, schema_slug: str, control_id: str, requirements: Sequence[str]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id=f"kt.b04_r6.activation_review.{schema_slug}.v1",
        artifact_id=artifact_id,
        control_id=control_id,
        requirements=list(requirements),
        required_before_limited_runtime_authorization=True,
        can_authorize_limited_runtime=False,
        can_execute_runtime=False,
        can_open_r6=False,
    )


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
        runtime_cutover_authorized=False,
        r6_open=False,
        package_promotion_authorized=False,
    )


def _validation_plan(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.activation_review.validation_plan.v1",
        artifact_id="B04_R6_ACTIVATION_REVIEW_VALIDATION_PLAN",
        validator_role="hostile verifier of authored activation-review packet",
        expected_successful_validation_outcome="B04_R6_ACTIVATION_REVIEW_VALIDATED__LIMITED_RUNTIME_AUTHORIZATION_PACKET_NEXT",
        expected_next_lawful_move_after_validation="AUTHOR_B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET",
        validation_checks=[
            "shadow proof binding stable",
            "zero disqualifiers bound",
            "candidate binding stable",
            "fallbacks present",
            "operator override present",
            "kill switch present",
            "rollback plan present",
            "route-distribution health present",
            "drift monitoring present",
            "runtime receipt schema present",
            "truth/trust law unchanged",
            "commercial claim boundary present",
            "package promotion not automatic",
            "limited runtime not authorized prematurely",
            "next lawful move correctness",
        ],
    )


def _future_blocker_register(base: Dict[str, Any]) -> Dict[str, Any]:
    return _with_artifact(
        base,
        schema_id="kt.b04_r6.future_blocker_register.v5",
        artifact_id="B04_R6_FUTURE_BLOCKER_REGISTER",
        current_authoritative_lane="AUTHOR_B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET",
        blockers=[
            {
                "blocker_id": "B04R6-FB-031",
                "future_blocker": "Shadow-superiority is mistaken for runtime activation.",
                "neutralization_now": ["activation review non-purpose boundary", "no authorization drift receipt"],
            },
            {
                "blocker_id": "B04R6-FB-032",
                "future_blocker": "Limited runtime lacks fallback, override, kill-switch, or rollback law.",
                "neutralization_now": [
                    OUTPUTS["static_fallback_contract"],
                    OUTPUTS["operator_override_contract"],
                    OUTPUTS["kill_switch_contract"],
                    OUTPUTS["rollback_plan_contract"],
                ],
            },
            {
                "blocker_id": "B04R6-FB-033",
                "future_blocker": "Commercial or package-promotion claims outrun activation evidence.",
                "neutralization_now": [
                    OUTPUTS["commercial_claim_boundary"],
                    OUTPUTS["package_promotion_review_preconditions_prep_only_draft"],
                ],
            },
        ],
    )


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Learned-Router Activation-Review Packet\n\n"
        "Outcome: "
        f"{contract['selected_outcome']}\n\n"
        "Next lawful move: "
        f"{contract['next_lawful_move']}\n\n"
        "The packet binds the passed AFSH shadow-screen result and defines the operational review law required before "
        "any limited runtime authorization can be considered. It does not open R6, authorize limited runtime, execute "
        "activation/cutover, escalate to lobes, promote package, mutate truth/trust law, widen metrics, weaken the "
        "static comparator, or authorize commercial activation claims.\n"
    )


def run(*, reports_root: Path) -> Dict[str, Any]:
    root = repo_root()
    current_branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 activation-review packet authoring")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in TEXT_INPUTS.items()}
    handoff = _require_shadow_pass(payloads, texts)
    binding_hashes = _validate_bindings(root, payloads)

    fresh_trust_validation = validate_trust_zones(root=root)
    if fresh_trust_validation.get("status") != "PASS" or fresh_trust_validation.get("failures"):
        _fail("RC_B04R6_ACT_REVIEW_PACKET_TRUST_ZONE_MUTATION", "fresh trust-zone validation must pass")

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
        binding_hashes=binding_hashes,
        validation_rows=rows,
        handoff=handoff,
    )

    shadow_result = payloads["shadow_screen_result"]
    contract = _contract(base, shadow_result)
    receipt = _with_artifact(
        base,
        schema_id="kt.b04_r6.learned_router_activation_review_packet_receipt.v1",
        artifact_id="B04_R6_LEARNED_ROUTER_ACTIVATION_REVIEW_PACKET_RECEIPT",
        packet_contract_hash_preview="written_with_same_binding_hashes",
        no_downstream_authorization_drift=True,
    )
    no_auth = _with_artifact(
        base,
        schema_id="kt.b04_r6.activation_review.no_authorization_drift_receipt.v1",
        artifact_id="B04_R6_ACTIVATION_REVIEW_NO_AUTHORIZATION_DRIFT_RECEIPT",
        no_downstream_authorization_drift=True,
        limited_runtime_authorized=False,
        runtime_cutover_authorized=False,
        activation_cutover_executed=False,
        r6_open=False,
        package_promotion_authorized=False,
        commercial_activation_claim_authorized=False,
    )

    output_payloads: Dict[str, Any] = {
        "packet_contract": contract,
        "packet_receipt": receipt,
        "shadow_result_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_SHADOW_RESULT_BINDING_RECEIPT",
            schema_slug="shadow_result_binding_receipt",
            subject="passed shadow-superiority result",
            keys=("shadow_screen_result_hash", "shadow_screen_execution_receipt_hash", "shadow_screen_result_report_hash", "fired_disqualifier_receipt_hash"),
        ),
        "candidate_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_CANDIDATE_BINDING_RECEIPT",
            schema_slug="candidate_binding_receipt",
            subject="admissible AFSH candidate",
            keys=("candidate_hash", "candidate_manifest_hash", "candidate_semantic_hash", "candidate_hash_receipt_hash"),
        ),
        "screen_packet_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_SCREEN_PACKET_BINDING_RECEIPT",
            schema_slug="screen_packet_binding_receipt",
            subject="validated shadow-screen packet",
            keys=("validated_shadow_screen_packet_hash", "validated_shadow_packet_validation_receipt_hash"),
        ),
        "universe_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_UNIVERSE_BINDING_RECEIPT",
            schema_slug="universe_binding_receipt",
            subject="validated blind universe",
            keys=("validated_blind_universe_hash",),
        ),
        "court_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_COURT_BINDING_RECEIPT",
            schema_slug="court_binding_receipt",
            subject="validated route-economics court",
            keys=("validated_route_economics_court_hash",),
        ),
        "source_packet_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_SOURCE_PACKET_BINDING_RECEIPT",
            schema_slug="source_packet_binding_receipt",
            subject="validated AFSH source packet",
            keys=("validated_source_packet_hash",),
        ),
        "admissibility_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_ADMISSIBILITY_BINDING_RECEIPT",
            schema_slug="admissibility_binding_receipt",
            subject="candidate admissibility receipt",
            keys=("admissibility_receipt_hash",),
        ),
        "triage_core_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_TRIAGE_CORE_BINDING_RECEIPT",
            schema_slug="triage_core_binding_receipt",
            subject="numeric triage emit core",
            keys=("numeric_triage_emit_core_hash",),
        ),
        "static_comparator_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_STATIC_COMPARATOR_BINDING_RECEIPT",
            schema_slug="static_comparator_binding_receipt",
            subject="frozen static comparator",
            keys=("static_comparator_contract_hash",),
        ),
        "metric_contract_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_METRIC_CONTRACT_BINDING_RECEIPT",
            schema_slug="metric_contract_binding_receipt",
            subject="frozen metric contract",
            keys=("metric_contract_hash",),
        ),
        "disqualifier_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_DISQUALIFIER_BINDING_RECEIPT",
            schema_slug="disqualifier_binding_receipt",
            subject="shadow-screen disqualifier ledger",
            keys=("disqualifier_ledger_hash", "fired_disqualifier_receipt_hash"),
        ),
        "trace_completeness_binding_receipt": _binding_receipt(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_TRACE_COMPLETENESS_BINDING_RECEIPT",
            schema_slug="trace_completeness_binding_receipt",
            subject="shadow-screen trace completeness",
            keys=("trace_completeness_receipt_hash",),
        ),
        "no_authorization_drift_receipt": no_auth,
        "scope_contract": _control_contract(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_SCOPE_CONTRACT",
            schema_slug="scope_contract",
            control_id="ACTIVATION_REVIEW_SCOPE",
            requirements=("review_considers_operational_safety_only", "shadow_superiority_is_not_activation", "limited_runtime_requires_later_authorization_packet"),
        ),
        "runtime_preconditions_contract": _control_contract(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_RUNTIME_PRECONDITIONS_CONTRACT",
            schema_slug="runtime_preconditions_contract",
            control_id="RUNTIME_PRECONDITIONS",
            requirements=RUNTIME_PRECONDITION_KEYS,
        ),
        "static_fallback_contract": _control_contract(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_STATIC_FALLBACK_CONTRACT",
            schema_slug="static_fallback_contract",
            control_id="STATIC_ABSTAIN_NULL_ROUTE_FALLBACKS",
            requirements=("static_fallback_required", "abstention_fallback_required", "null_route_preservation_required", "static_comparator_remains_available"),
        ),
        "operator_override_contract": _control_contract(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_OPERATOR_OVERRIDE_CONTRACT",
            schema_slug="operator_override_contract",
            control_id="OPERATOR_OVERRIDE",
            requirements=("human_operator_override_required", "override_receipts_required", "override_cannot_promote_package"),
        ),
        "kill_switch_contract": _control_contract(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_KILL_SWITCH_CONTRACT",
            schema_slug="kill_switch_contract",
            control_id="KILL_SWITCH",
            requirements=("kill_switch_required", "kill_switch_must_return_to_static_fallback", "kill_switch_activation_receipt_required"),
        ),
        "rollback_plan_contract": _control_contract(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_ROLLBACK_PLAN_CONTRACT",
            schema_slug="rollback_plan_contract",
            control_id="ROLLBACK_PLAN",
            requirements=("rollback_plan_required", "rollback_to_static_comparator_required", "rollback_receipt_schema_required"),
        ),
        "route_distribution_health_contract": _control_contract(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_ROUTE_DISTRIBUTION_HEALTH_CONTRACT",
            schema_slug="route_distribution_health_contract",
            control_id="ROUTE_DISTRIBUTION_HEALTH",
            requirements=("selector_entry_rate_monitored", "static_hold_rate_monitored", "abstention_rate_monitored", "null_route_rate_monitored"),
        ),
        "drift_monitoring_contract": _control_contract(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_DRIFT_MONITORING_CONTRACT",
            schema_slug="drift_monitoring_contract",
            control_id="DRIFT_MONITORING",
            requirements=("metric_drift_freezes_runtime_consideration", "comparator_drift_freezes_runtime_consideration", "trust_zone_drift_freezes_runtime_consideration"),
        ),
        "runtime_receipt_schema_contract": _control_contract(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_RUNTIME_RECEIPT_SCHEMA_CONTRACT",
            schema_slug="runtime_receipt_schema_contract",
            control_id="RUNTIME_RECEIPT_SCHEMA",
            requirements=("verdict_mode_required", "triage_subtype_required", "fallback_status_required", "operator_override_status_required", "kill_switch_status_required"),
        ),
        "external_verifier_requirements": _control_contract(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_EXTERNAL_VERIFIER_REQUIREMENTS",
            schema_slug="external_verifier_requirements",
            control_id="EXTERNAL_VERIFIER_REQUIREMENTS",
            requirements=("external_verifier_non_executing", "raw_hash_bound_artifacts_required", "no_public_superiority_claims_from_activation_review"),
        ),
        "commercial_claim_boundary": _control_contract(
            base,
            artifact_id="B04_R6_ACTIVATION_REVIEW_COMMERCIAL_CLAIM_BOUNDARY",
            schema_slug="commercial_claim_boundary",
            control_id="COMMERCIAL_CLAIM_BOUNDARY",
            requirements=("commercial_activation_claims_unauthorized", "package_promotion_prohibited", "shadow_superiority_claim_must_remain_shadow_qualified"),
        ),
        "validation_plan": _validation_plan(base),
        "validation_reason_codes": _with_artifact(
            base,
            schema_id="kt.b04_r6.activation_review.validation_reason_codes.v1",
            artifact_id="B04_R6_ACTIVATION_REVIEW_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
            terminal_defects=list(TERMINAL_DEFECTS),
        ),
        "limited_runtime_authorization_prep_only_draft": _prep_only(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_AUTHORIZATION_PACKET_PREP_ONLY_DRAFT",
            schema_slug="limited_runtime_authorization_packet_prep_only_draft",
            purpose="Draft future limited-runtime authorization packet shape after activation-review validation.",
        ),
        "limited_runtime_scope_manifest_prep_only_draft": _prep_only(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_SCOPE_MANIFEST_PREP_ONLY_DRAFT",
            schema_slug="limited_runtime_scope_manifest_prep_only_draft",
            purpose="Draft future canary/scope boundaries for limited runtime.",
        ),
        "limited_runtime_monitoring_prep_only_draft": _prep_only(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_MONITORING_CONTRACT_PREP_ONLY_DRAFT",
            schema_slug="limited_runtime_monitoring_contract_prep_only_draft",
            purpose="Draft future runtime monitoring requirements.",
        ),
        "limited_runtime_rollback_receipt_schema_prep_only_draft": _prep_only(
            base,
            artifact_id="B04_R6_LIMITED_RUNTIME_ROLLBACK_EXECUTION_RECEIPT_SCHEMA_PREP_ONLY_DRAFT",
            schema_slug="limited_runtime_rollback_execution_receipt_schema_prep_only_draft",
            purpose="Draft future rollback execution receipt schema.",
        ),
        "package_promotion_review_preconditions_prep_only_draft": _prep_only(
            base,
            artifact_id="B04_R6_PACKAGE_PROMOTION_REVIEW_PRECONDITIONS_PREP_ONLY_DRAFT",
            schema_slug="package_promotion_review_preconditions_prep_only_draft",
            purpose="Draft future package-promotion review preconditions without authorizing promotion.",
        ),
        "external_audit_delta_manifest_prep_only_draft": _prep_only(
            base,
            artifact_id="B04_R6_EXTERNAL_AUDIT_DELTA_MANIFEST_PREP_ONLY_DRAFT",
            schema_slug="external_audit_delta_manifest_prep_only_draft",
            purpose="Draft future external-audit delta manifest.",
        ),
        "future_blocker_register": _future_blocker_register(base),
        "next_lawful_move": _with_artifact(
            base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v15",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            verdict="NEXT_LAWFUL_MOVE_SET",
        ),
    }

    for role, filename in OUTPUTS.items():
        if role == "packet_report":
            continue
        write_json_stable(reports_root / filename, output_payloads[role])
    common.write_text(reports_root / OUTPUTS["packet_report"], _report_text(contract))
    return output_payloads["packet_contract"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author the B04 R6 learned-router activation-review packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
