from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from tools.operator import cohort0_b04_r6_runtime_cutover as runtime
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/b04-r6-post-cutover-evidence-review-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-post-cutover-evidence-review-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET"
PREVIOUS_LANE = runtime.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = runtime.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = runtime.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = "B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET_BOUND__POST_CUTOVER_EVIDENCE_REVIEW_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET_INVALID__FORENSIC_CUTOVER_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET"

RECOMMENDED_VALIDATED_PATH = "R6_OPENING_REVIEW_PACKET_NEXT"
VALIDATION_SUCCESS_OUTCOME = "B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_VALIDATED__R6_OPENING_REVIEW_PACKET_NEXT"
VALIDATION_SUCCESS_NEXT_MOVE = "AUTHOR_B04_R6_R6_OPENING_REVIEW_PACKET"

FORBIDDEN_ACTIONS = (
    "R6_OPEN",
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "METRIC_CONTRACT_MUTATED",
    "STATIC_COMPARATOR_WEAKENED",
    "CUTOVER_RESULT_TREATED_AS_R6_OPENING",
    "CUTOVER_RESULT_TREATED_AS_PACKAGE_PROMOTION",
)

AUTHORITY_DRIFT_KEYS = {
    "activation_cutover_executed": "RC_B04R6_POST_CUTOVER_REVIEW_ACTIVATION_CUTOVER_EXECUTED",
    "r6_open": "RC_B04R6_POST_CUTOVER_REVIEW_R6_OPEN_DRIFT",
    "global_runtime_surface_authorized": "RC_B04R6_POST_CUTOVER_REVIEW_GLOBAL_SURFACE_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_POST_CUTOVER_REVIEW_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_POST_CUTOVER_REVIEW_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_POST_CUTOVER_REVIEW_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_POST_CUTOVER_REVIEW_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_POST_CUTOVER_REVIEW_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_POST_CUTOVER_REVIEW_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_POST_CUTOVER_REVIEW_COMPARATOR_WEAKENED",
    "cutover_result_treated_as_r6_opening": "RC_B04R6_POST_CUTOVER_REVIEW_RESULT_R6_OPENING_DRIFT",
    "cutover_result_treated_as_package_promotion": "RC_B04R6_POST_CUTOVER_REVIEW_RESULT_PROMOTION_DRIFT",
}

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_POST_CUTOVER_REVIEW_RUNTIME_EVIDENCE_MISSING",
            "RC_B04R6_POST_CUTOVER_REVIEW_RUNTIME_OUTCOME_DRIFT",
            "RC_B04R6_POST_CUTOVER_REVIEW_NEXT_MOVE_DRIFT",
            "RC_B04R6_POST_CUTOVER_REVIEW_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_POST_CUTOVER_REVIEW_SCORECARD_INCOMPLETE",
            "RC_B04R6_POST_CUTOVER_REVIEW_R6_OPENING_RECOMMENDATION_UNSUPPORTED",
            "RC_B04R6_POST_CUTOVER_REVIEW_PREP_ONLY_DRIFT",
            "RC_B04R6_POST_CUTOVER_REVIEW_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

RUNTIME_REPLAY_OVERWRITTEN_INPUT_ROLES = frozenset(
    {
        "post_cutover_evidence_review_packet_prep_only_draft",
        "r6_opening_review_packet_prep_only_draft",
        "package_promotion_review_packet_prep_only_draft",
        "external_audit_delta_manifest_prep_only",
        "public_verifier_delta_requirements_prep_only",
        "commercial_claim_boundary_update_prep_only",
        "campaign_board",
        "pipeline_board",
        "future_blocker_register",
        "next_lawful_move",
    }
)

RUNTIME_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in runtime.OUTPUTS.items()
    if filename.endswith(".json")
}
RUNTIME_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in runtime.OUTPUTS.items()
    if not filename.endswith(".json")
}

PREP_ONLY_ROLES = (
    "r6_opening_review_packet_prep_only_draft",
    "limited_continuation_packet_prep_only_draft",
    "rollback_closeout_packet_prep_only_draft",
    "external_audit_delta_packet_prep_only_draft",
    "package_promotion_review_preconditions_prep_only_draft",
)

OUTPUTS = {
    "packet_contract": "b04_r6_post_cutover_evidence_review_packet_contract.json",
    "packet_receipt": "b04_r6_post_cutover_evidence_review_packet_receipt.json",
    "packet_report": "b04_r6_post_cutover_evidence_review_packet_report.md",
    "evidence_inventory": "b04_r6_post_cutover_evidence_inventory.json",
    "evidence_scorecard": "b04_r6_post_cutover_evidence_scorecard.json",
    "decision_matrix": "b04_r6_post_cutover_decision_matrix.json",
    "r6_opening_readiness_matrix": "b04_r6_r6_opening_readiness_matrix.json",
    "rollback_continuation_matrix": "b04_r6_post_cutover_rollback_continuation_matrix.json",
    "package_promotion_blocker_matrix": "b04_r6_post_cutover_package_promotion_blocker_matrix.json",
    "external_audit_delta_readiness": "b04_r6_post_cutover_external_audit_delta_readiness.json",
    "public_verifier_readiness": "b04_r6_post_cutover_public_verifier_readiness.json",
    "commercial_claim_ceiling_update": "b04_r6_post_cutover_commercial_claim_ceiling_update.json",
    "route_distribution_review": "b04_r6_post_cutover_route_distribution_review_contract.json",
    "fallback_behavior_review": "b04_r6_post_cutover_fallback_behavior_review_contract.json",
    "operator_override_review": "b04_r6_post_cutover_operator_override_review_contract.json",
    "kill_switch_review": "b04_r6_post_cutover_kill_switch_review_contract.json",
    "rollback_review": "b04_r6_post_cutover_rollback_review_contract.json",
    "drift_monitoring_review": "b04_r6_post_cutover_drift_monitoring_review_contract.json",
    "incident_freeze_review": "b04_r6_post_cutover_incident_freeze_review_contract.json",
    "trace_completeness_review": "b04_r6_post_cutover_trace_completeness_review_contract.json",
    "replay_readiness_review": "b04_r6_post_cutover_replay_readiness_review_contract.json",
    "external_verifier_review": "b04_r6_post_cutover_external_verifier_readiness_review_contract.json",
    "commercial_claim_boundary_review": "b04_r6_post_cutover_commercial_claim_boundary_review_contract.json",
    "no_authorization_drift_receipt": "b04_r6_post_cutover_no_authorization_drift_receipt.json",
    "validation_plan": "b04_r6_post_cutover_evidence_review_validation_plan.json",
    "validation_reason_codes": "b04_r6_post_cutover_evidence_review_validation_reason_codes.json",
    "r6_opening_review_packet_prep_only_draft": "b04_r6_r6_opening_review_packet_prep_only_draft.json",
    "limited_continuation_packet_prep_only_draft": "b04_r6_limited_continuation_packet_prep_only_draft.json",
    "rollback_closeout_packet_prep_only_draft": "b04_r6_rollback_closeout_packet_prep_only_draft.json",
    "external_audit_delta_packet_prep_only_draft": "b04_r6_external_audit_delta_packet_prep_only_draft.json",
    "package_promotion_review_preconditions_prep_only_draft": (
        "b04_r6_package_promotion_review_preconditions_prep_only_draft.json"
    ),
    "pipeline_board": "b04_r6_pipeline_board.json",
    "campaign_board": "kt_e2e_closure_campaign_board.json",
    "future_blocker_register": "kt_future_blocker_register.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}


class LaneFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise LaneFailure(code, detail)


def _walk(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_B04R6_POST_CUTOVER_REVIEW_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_POST_CUTOVER_REVIEW_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _runtime_json_inputs_for_branch(branch: str) -> Dict[str, str]:
    if branch == AUTHORITY_BRANCH:
        return dict(RUNTIME_JSON_INPUTS)
    return {role: raw for role, raw in RUNTIME_JSON_INPUTS.items() if role not in RUNTIME_REPLAY_OVERWRITTEN_INPUT_ROLES}


def _all_json_inputs(branch: str) -> Dict[str, str]:
    return {f"runtime_{role}": raw for role, raw in _runtime_json_inputs_for_branch(branch).items()}


ALL_JSON_INPUTS = _all_json_inputs(AUTHORITY_BRANCH)
ALL_TEXT_INPUTS = {f"runtime_{role}": raw for role, raw in RUNTIME_TEXT_INPUTS.items()}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_POST_CUTOVER_REVIEW_RUNTIME_EVIDENCE_MISSING", f"{label} must be a JSON object")
    return payload


def _payloads(root: Path, branch: str) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in _all_json_inputs(branch).items()}
    texts = {role: common.read_text_required(root, raw, label=role) for role, raw in ALL_TEXT_INPUTS.items()}
    return payloads, texts


def _ensure_runtime_boundaries(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role, payload in payloads.items():
        for key, value in _walk(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{role}.{key} drifted to {value!r}")
        if payload.get("runtime_cutover_executed") is not True:
            _fail("RC_B04R6_POST_CUTOVER_REVIEW_RUNTIME_EVIDENCE_MISSING", f"{role} missing cutover execution truth")
        if payload.get("package_promotion") not in (None, "DEFERRED"):
            _fail("RC_B04R6_POST_CUTOVER_REVIEW_PACKAGE_PROMOTION_DRIFT", f"{role}.package_promotion drifted")


def _validate_runtime_handoff(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    contract = payloads["runtime_execution_contract"]
    receipt = payloads["runtime_execution_receipt"]
    result = payloads["runtime_result"]
    for label, payload in (("contract", contract), ("receipt", receipt), ("result", result)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_POST_CUTOVER_REVIEW_RUNTIME_EVIDENCE_MISSING", f"{label} lane drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_POST_CUTOVER_REVIEW_RUNTIME_OUTCOME_DRIFT", f"{label} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_POST_CUTOVER_REVIEW_NEXT_MOVE_DRIFT", f"{label} next move drift")
    next_move = payloads.get("runtime_next_lawful_move")
    if next_move is not None and next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_POST_CUTOVER_REVIEW_NEXT_MOVE_DRIFT", "runtime next move drift")
    if not contract.get("input_bindings"):
        _fail("RC_B04R6_POST_CUTOVER_REVIEW_INPUT_BINDINGS_EMPTY", "runtime input bindings empty")
    scorecard = result.get("result", {})
    required_true = (
        "sample_limit_respected",
        "static_fallback_preserved",
        "abstention_fallback_preserved",
        "null_route_preserved",
        "operator_override_ready",
        "kill_switch_ready",
        "rollback_ready",
        "external_verifier_ready",
        "commercial_claim_boundary_preserved",
    )
    for key in required_true:
        if scorecard.get(key) is not True:
            _fail("RC_B04R6_POST_CUTOVER_REVIEW_SCORECARD_INCOMPLETE", f"scorecard.{key} not true")
    for key in ("route_distribution_health", "drift_status", "replay_status"):
        if scorecard.get(key) != "PASS":
            _fail("RC_B04R6_POST_CUTOVER_REVIEW_SCORECARD_INCOMPLETE", f"scorecard.{key} not PASS")
    report = texts.get("runtime_report", "").lower()
    for phrase in ("does not open r6", "does not promote package", "post-cutover evidence review is next"):
        if phrase not in report:
            _fail("RC_B04R6_POST_CUTOVER_REVIEW_RUNTIME_EVIDENCE_MISSING", f"runtime report missing {phrase!r}")


def _validate_inputs(root: Path, branch: str, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _ensure_runtime_boundaries(payloads)
    _validate_runtime_handoff(payloads, texts)
    for role, raw in {**_runtime_json_inputs_for_branch(branch), **RUNTIME_TEXT_INPUTS}.items():
        file_sha256(common.resolve_path(root, raw))


def _input_bindings(root: Path, branch: str) -> list[Dict[str, Any]]:
    output_paths = {f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values()}
    rows = []
    for role, raw in sorted({**_all_json_inputs(branch), **ALL_TEXT_INPUTS}.items()):
        overwritten = raw in output_paths
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": (
                    "pre_overwrite_file_sha256_at_post_cutover_review_authoring"
                    if overwritten
                    else "file_sha256_at_post_cutover_review_authoring"
                ),
                "overwritten_by_post_cutover_review_output": overwritten,
            }
        )
    return rows


def _binding_hashes(input_bindings: list[Dict[str, Any]]) -> Dict[str, str]:
    return {f"{row['role']}_hash": row["sha256"] for row in input_bindings}


def _inventory(payloads: Dict[str, Dict[str, Any]], input_bindings: list[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "inventory_id": "B04_R6_POST_CUTOVER_EVIDENCE_INVENTORY_V1",
        "runtime_cutover_result": runtime.SELECTED_OUTCOME,
        "bound_artifact_count": len(input_bindings),
        "runtime_receipts": sorted(role for role in payloads if role.endswith("_receipt")),
        "input_bindings": input_bindings,
    }


def _scorecard(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    result = payloads["runtime_result"].get("result", {})
    return {
        "scorecard_id": "B04_R6_POST_CUTOVER_EVIDENCE_SCORECARD_V1",
        "runtime_cutover_result": "PASSED",
        "overall_grade": "A_READY_FOR_R6_OPENING_REVIEW",
        "sample_limit_respected": result.get("sample_limit_respected") is True,
        "route_distribution_health": result.get("route_distribution_health"),
        "fallback_behavior": "PASS" if result.get("fallback_failures") == 0 else "FAIL",
        "static_fallback_preserved": result.get("static_fallback_preserved") is True,
        "abstention_fallback_preserved": result.get("abstention_fallback_preserved") is True,
        "null_route_preserved": result.get("null_route_preserved") is True,
        "operator_override_ready": result.get("operator_override_ready") is True,
        "kill_switch_ready": result.get("kill_switch_ready") is True,
        "rollback_ready": result.get("rollback_ready") is True,
        "drift_status": result.get("drift_status"),
        "incident_freeze_clean": result.get("incident_freeze_triggers") == [],
        "trace_completeness": "PASS" if result.get("trace_complete_cases") == result.get("total_cases") else "FAIL",
        "replay_status": result.get("replay_status"),
        "external_verifier_ready": result.get("external_verifier_ready") is True,
        "commercial_claim_boundary_preserved": result.get("commercial_claim_boundary_preserved") is True,
        "package_promotion_ready": False,
        "r6_opening_review_ready": True,
    }


def _decision_matrix(scorecard: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "decision_matrix_id": "B04_R6_POST_CUTOVER_DECISION_MATRIX_V1",
        "runtime_cutover_result": "PASSED",
        "overall_grade": scorecard["overall_grade"],
        "r6_opening_review_ready": True,
        "limited_continuation_ready": True,
        "rollback_closeout_ready": False,
        "external_audit_delta_ready": "READY_FOR_PACKET",
        "package_promotion_ready": False,
        "commercial_claim_status": "BOUNDARY_ONLY",
        "recommended_next_path": RECOMMENDED_VALIDATED_PATH,
        "recommendation_is_authority": False,
        "blocking_reasons": [
            "r6_opening_requires_post_cutover_evidence_review_validation",
            "package_promotion_requires_r6_opening_review_and_external_audit_delta",
            "commercial_activation_claims_remain_forbidden",
        ],
        "supporting_evidence": [
            "runtime_cutover_passed",
            "fallbacks_preserved",
            "operator_controls_preserved",
            "drift_and_incident_receipts_passed",
            "replay_and_external_verifier_receipts_passed",
        ],
    }


def _authority_state() -> Dict[str, Any]:
    return {
        "runtime_cutover_executed": True,
        "post_cutover_evidence_review_packet_authored": True,
        "post_cutover_evidence_review_validated": False,
        "r6_opening_review_authorized": False,
        "r6_open": False,
        "global_runtime_surface_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "metric_contract_mutated": False,
        "static_comparator_weakened": False,
        "cutover_result_treated_as_r6_opening": False,
        "cutover_result_treated_as_package_promotion": False,
    }


def _base(
    *,
    generated_utc: str,
    branch: str,
    head: str,
    current_main_head: str,
    input_bindings: list[Dict[str, Any]],
    trust_zone_validation: Dict[str, Any],
    inventory: Dict[str, Any],
    scorecard: Dict[str, Any],
    decision_matrix: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_version": "v1",
        "generated_utc": generated_utc,
        "current_branch": branch,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "validation_success_outcome": VALIDATION_SUCCESS_OUTCOME,
        "validation_success_next_move": VALIDATION_SUCCESS_NEXT_MOVE,
        "recommended_validated_path": RECOMMENDED_VALIDATED_PATH,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "overwritten_input_roles": [
            row["role"] for row in input_bindings if row.get("overwritten_by_post_cutover_review_output")
        ],
        "replay_overwritten_runtime_input_roles": sorted(RUNTIME_REPLAY_OVERWRITTEN_INPUT_ROLES),
        "binding_hashes": _binding_hashes(input_bindings),
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        "evidence_inventory": inventory,
        "evidence_scorecard": scorecard,
        "decision_matrix": decision_matrix,
        "recommendation_is_authority": False,
        "no_authorization_drift": True,
        **_authority_state(),
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _prep_only(base: Dict[str, Any], *, role: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.post_cutover_evidence_review.{role}.prep_only.v1",
        artifact_id=f"B04_R6_POST_CUTOVER_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        prep_only=True,
        can_authorize=False,
        cannot_open_r6=True,
        cannot_authorize_lobe_escalation=True,
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _review(base: Dict[str, Any], *, role: str, status: str = "PASS", **extra: Any) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.post_cutover_evidence_review.{role}.v1",
        artifact_id=f"B04_R6_POST_CUTOVER_{role.upper()}",
        review_role=role,
        review_status=status,
        **extra,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    scorecard = base["evidence_scorecard"]
    decision = base["decision_matrix"]
    payloads: Dict[str, Any] = {
        "packet_contract": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.packet_contract.v1", artifact_id="B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET_CONTRACT"),
        "packet_receipt": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.packet_receipt.v1", artifact_id="B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET_RECEIPT", verdict="BOUND_FOR_VALIDATION"),
        "evidence_inventory": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.inventory.v1", artifact_id="B04_R6_POST_CUTOVER_EVIDENCE_INVENTORY", inventory=base["evidence_inventory"]),
        "evidence_scorecard": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.scorecard.v1", artifact_id="B04_R6_POST_CUTOVER_EVIDENCE_SCORECARD", scorecard=scorecard),
        "decision_matrix": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.decision_matrix.v1", artifact_id="B04_R6_POST_CUTOVER_DECISION_MATRIX", decision_matrix=decision),
        "r6_opening_readiness_matrix": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.r6_opening_readiness.v1", artifact_id="B04_R6_R6_OPENING_READINESS_MATRIX", readiness="READY_FOR_REVIEW_PACKET", r6_opening_review_ready=True, r6_opening_authorized=False),
        "rollback_continuation_matrix": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.rollback_continuation.v1", artifact_id="B04_R6_POST_CUTOVER_ROLLBACK_CONTINUATION_MATRIX", limited_continuation_ready=True, rollback_closeout_required=False),
        "package_promotion_blocker_matrix": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.package_promotion_blockers.v1", artifact_id="B04_R6_POST_CUTOVER_PACKAGE_PROMOTION_BLOCKER_MATRIX", package_promotion_ready=False, blockers=decision["blocking_reasons"]),
        "external_audit_delta_readiness": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.external_audit_delta_readiness.v1", artifact_id="B04_R6_POST_CUTOVER_EXTERNAL_AUDIT_DELTA_READINESS", external_audit_delta_ready="READY_FOR_PACKET"),
        "public_verifier_readiness": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.public_verifier_readiness.v1", artifact_id="B04_R6_POST_CUTOVER_PUBLIC_VERIFIER_READINESS", public_verifier_ready=True),
        "commercial_claim_ceiling_update": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.commercial_claim_ceiling.v1", artifact_id="B04_R6_POST_CUTOVER_COMMERCIAL_CLAIM_CEILING_UPDATE", allowed_claims=["B04 R6 runtime cutover passed under bounded packet law"], forbidden_claims=["R6 is open", "package promotion is authorized", "commercial activation is authorized"]),
        "route_distribution_review": _review(base, role="route_distribution_review", route_distribution_health=scorecard["route_distribution_health"]),
        "fallback_behavior_review": _review(base, role="fallback_behavior_review", fallback_behavior=scorecard["fallback_behavior"]),
        "operator_override_review": _review(base, role="operator_override_review", operator_override_ready=scorecard["operator_override_ready"]),
        "kill_switch_review": _review(base, role="kill_switch_review", kill_switch_ready=scorecard["kill_switch_ready"]),
        "rollback_review": _review(base, role="rollback_review", rollback_ready=scorecard["rollback_ready"]),
        "drift_monitoring_review": _review(base, role="drift_monitoring_review", drift_status=scorecard["drift_status"]),
        "incident_freeze_review": _review(base, role="incident_freeze_review", incident_freeze_clean=scorecard["incident_freeze_clean"]),
        "trace_completeness_review": _review(base, role="trace_completeness_review", trace_completeness=scorecard["trace_completeness"]),
        "replay_readiness_review": _review(base, role="replay_readiness_review", replay_status=scorecard["replay_status"]),
        "external_verifier_review": _review(base, role="external_verifier_review", external_verifier_ready=scorecard["external_verifier_ready"]),
        "commercial_claim_boundary_review": _review(base, role="commercial_claim_boundary_review", commercial_claim_status="BOUNDARY_ONLY"),
        "no_authorization_drift_receipt": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.no_authorization_drift.v1", artifact_id="B04_R6_POST_CUTOVER_NO_AUTHORIZATION_DRIFT_RECEIPT", validation_status="PASS", no_downstream_authorization_drift=True),
        "validation_plan": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.validation_plan.v1", artifact_id="B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_VALIDATION_PLAN", validation_success_outcome=VALIDATION_SUCCESS_OUTCOME),
        "validation_reason_codes": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.validation_reason_codes.v1", artifact_id="B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_VALIDATION_REASON_CODES", reason_codes=list(REASON_CODES)),
        "pipeline_board": _artifact(base, schema_id="kt.b04_r6.pipeline_board.v25", artifact_id="B04_R6_PIPELINE_BOARD", lanes=[
            {"lane": "RUN_B04_R6_RUNTIME_CUTOVER", "status": "PASSED", "authoritative": False},
            {"lane": "AUTHOR_B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET", "status": "CURRENT_BOUND", "authoritative": True},
            {"lane": "VALIDATE_B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET", "status": "NEXT", "authoritative": True},
            {"lane": "R6_OPENING_REVIEW", "status": "RECOMMENDED_NOT_AUTHORIZED", "authoritative": False},
        ]),
        "campaign_board": _artifact(base, schema_id="kt.e2e_closure.campaign_board.v4", artifact_id="KT_E2E_CLOSURE_CAMPAIGN_BOARD", corridors=[
            {"corridor": "R6_RUNTIME_CUTOVER", "status": "PASSED_REVIEW_PACKET_BOUND"},
            {"corridor": "R6_OPENING", "status": "RECOMMENDED_PENDING_VALIDATION"},
            {"corridor": "PACKAGE_PROMOTION", "status": "BLOCKED"},
            {"corridor": "COMMERCIAL_TRUTH_PLANE", "status": "BOUNDARY_ONLY"},
        ]),
        "future_blocker_register": _artifact(base, schema_id="kt.future_blocker_register.v7", artifact_id="KT_FUTURE_BLOCKER_REGISTER", blockers=[
            {"blocker_id": "B04R6-POST-CUTOVER-001", "category": "r6_opening", "status": "OPEN", "required_next_artifact": OUTPUTS["validation_plan"]},
            {"blocker_id": "B04R6-POST-CUTOVER-002", "category": "package_promotion", "status": "BLOCKING", "required_next_artifact": OUTPUTS["package_promotion_review_preconditions_prep_only_draft"]},
            {"blocker_id": "B04R6-POST-CUTOVER-003", "category": "commercial_claims", "status": "BLOCKING", "required_next_artifact": OUTPUTS["commercial_claim_ceiling_update"]},
        ]),
        "next_lawful_move": _artifact(base, schema_id="kt.b04_r6.post_cutover_evidence_review.next_lawful_move.v1", artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT", verdict="NEXT_LAWFUL_MOVE_SET"),
    }
    payloads.update({role: _prep_only(base, role=role) for role in PREP_ONLY_ROLES})
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Post-Cutover Evidence Review Packet\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        f"Recommended validated path: {contract['recommended_validated_path']}.\n\n"
        "The packet binds the passed runtime cutover evidence, emits inventory, scorecard, decision matrix, R6 opening "
        "readiness, rollback/continuation posture, package blockers, external audit readiness, public verifier readiness, "
        "and commercial claim ceiling. The recommendation is not authority.\n\n"
        "This packet does not open R6, authorize lobe escalation, promote package, authorize commercial activation claims, "
        "or mutate truth/trust law. Validation is next.\n"
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 post-cutover evidence review packet")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root, branch)
    _validate_inputs(root, branch, payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_POST_CUTOVER_REVIEW_TRUST_ZONE_FAILED", "fresh trust-zone validation must pass")
    input_bindings = _input_bindings(root, branch)
    inventory = _inventory(payloads, input_bindings)
    scorecard = _scorecard(payloads)
    decision_matrix = _decision_matrix(scorecard)
    base = _base(
        generated_utc=utc_now_iso_z(),
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        input_bindings=input_bindings,
        trust_zone_validation=trust_zone_validation,
        inventory=inventory,
        scorecard=scorecard,
        decision_matrix=decision_matrix,
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


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=AUTHORITATIVE_LANE)
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
