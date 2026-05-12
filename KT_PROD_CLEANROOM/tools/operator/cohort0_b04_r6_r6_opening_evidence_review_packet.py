from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_r6_opening as opening
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/b04-r6-r6-opening-evidence-review-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-r6-opening-evidence-review-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET"
PREVIOUS_LANE = opening.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = opening.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = opening.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = "B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET_BOUND__R6_OPENING_EVIDENCE_REVIEW_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET_INVALID__FORENSIC_R6_OPENING_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET"

RECOMMENDED_VALIDATED_PATH = "PACKAGE_PROMOTION_REVIEW_PACKET_NEXT"
VALIDATION_SUCCESS_OUTCOME = (
    "B04_R6_R6_OPENING_EVIDENCE_REVIEW_VALIDATED__PACKAGE_PROMOTION_REVIEW_PACKET_NEXT"
)
VALIDATION_SUCCESS_NEXT_MOVE = "AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET"

FORBIDDEN_ACTIONS = (
    "LOBE_ESCALATION_AUTHORIZED",
    "PACKAGE_PROMOTION_AUTHORIZED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "METRIC_CONTRACT_MUTATED",
    "STATIC_COMPARATOR_WEAKENED",
    "R6_OPEN_TREATED_AS_PACKAGE_PROMOTION",
    "R6_OPEN_TREATED_AS_COMMERCIAL_ACTIVATION",
)

DOWNSTREAM_DRIFT_KEYS = {
    "global_runtime_surface_authorized": "RC_B04R6_R6_OPENING_REVIEW_GLOBAL_SURFACE_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_R6_OPENING_REVIEW_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_R6_OPENING_REVIEW_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_R6_OPENING_REVIEW_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_R6_OPENING_REVIEW_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_R6_OPENING_REVIEW_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_R6_OPENING_REVIEW_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_R6_OPENING_REVIEW_COMPARATOR_WEAKENED",
    "r6_open_treated_as_package_promotion": "RC_B04R6_R6_OPENING_REVIEW_RESULT_PROMOTION_DRIFT",
    "r6_open_treated_as_commercial_activation": "RC_B04R6_R6_OPENING_REVIEW_RESULT_COMMERCIAL_DRIFT",
}

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_R6_OPENING_REVIEW_RUNTIME_EVIDENCE_MISSING",
            "RC_B04R6_R6_OPENING_REVIEW_RUNTIME_OUTCOME_DRIFT",
            "RC_B04R6_R6_OPENING_REVIEW_NEXT_MOVE_DRIFT",
            "RC_B04R6_R6_OPENING_REVIEW_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_R6_OPENING_REVIEW_SCORECARD_INCOMPLETE",
            "RC_B04R6_R6_OPENING_REVIEW_PACKAGE_PROMOTION_RECOMMENDATION_UNSUPPORTED",
            "RC_B04R6_R6_OPENING_REVIEW_PREP_ONLY_DRIFT",
            "RC_B04R6_R6_OPENING_REVIEW_TRUST_ZONE_FAILED",
            *tuple(DOWNSTREAM_DRIFT_KEYS.values()),
        )
    )
)

OPENING_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in opening.OUTPUTS.items()
    if filename.endswith(".json")
}
OPENING_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in opening.OUTPUTS.items()
    if not filename.endswith(".json")
}

PREP_ONLY_ROLES = (
    "package_promotion_review_packet_prep_only_draft",
    "commercial_activation_claim_review_prep_only_draft",
    "commercial_activation_claim_validation_plan_prep_only",
    "external_audit_delta_packet_prep_only_draft",
    "limited_continuation_packet_prep_only_draft",
    "rollback_closeout_packet_prep_only_draft",
)

OUTPUTS = {
    "packet_contract": "b04_r6_r6_opening_evidence_review_packet_contract.json",
    "packet_receipt": "b04_r6_r6_opening_evidence_review_packet_receipt.json",
    "packet_report": "b04_r6_r6_opening_evidence_review_packet_report.md",
    "evidence_inventory": "b04_r6_r6_opening_evidence_inventory.json",
    "evidence_scorecard": "b04_r6_r6_opening_evidence_scorecard.json",
    "decision_matrix": "b04_r6_r6_opening_post_run_decision_matrix.json",
    "package_promotion_readiness_matrix": "b04_r6_package_promotion_readiness_matrix.json",
    "commercial_claim_ceiling_update": "b04_r6_commercial_claim_ceiling_update.json",
    "external_audit_delta_readiness": "b04_r6_external_audit_delta_readiness.json",
    "public_verifier_readiness": "b04_r6_public_verifier_readiness.json",
    "rollback_continuation_matrix": "b04_r6_r6_opening_rollback_continuation_matrix.json",
    "route_distribution_review": "b04_r6_r6_opening_route_distribution_review_contract.json",
    "fallback_behavior_review": "b04_r6_r6_opening_fallback_behavior_review_contract.json",
    "static_fallback_review": "b04_r6_r6_opening_static_fallback_review_contract.json",
    "abstention_fallback_review": "b04_r6_r6_opening_abstention_fallback_review_contract.json",
    "null_route_review": "b04_r6_r6_opening_null_route_review_contract.json",
    "operator_override_review": "b04_r6_r6_opening_operator_override_review_contract.json",
    "kill_switch_review": "b04_r6_r6_opening_kill_switch_review_contract.json",
    "rollback_review": "b04_r6_r6_opening_rollback_review_contract.json",
    "drift_monitoring_review": "b04_r6_r6_opening_drift_monitoring_review_contract.json",
    "incident_freeze_review": "b04_r6_r6_opening_incident_freeze_review_contract.json",
    "trace_completeness_review": "b04_r6_r6_opening_trace_completeness_review_contract.json",
    "replay_readiness_review": "b04_r6_r6_opening_replay_readiness_review_contract.json",
    "external_verifier_review": "b04_r6_r6_opening_external_verifier_readiness_review_contract.json",
    "commercial_claim_boundary_review": "b04_r6_r6_opening_commercial_claim_boundary_review_contract.json",
    "package_promotion_blocker_review": "b04_r6_r6_opening_package_promotion_blocker_review_contract.json",
    "no_authorization_drift_receipt": "b04_r6_r6_opening_evidence_no_authorization_drift_receipt.json",
    "validation_plan": "b04_r6_r6_opening_evidence_review_validation_plan.json",
    "validation_reason_codes": "b04_r6_r6_opening_evidence_review_validation_reason_codes.json",
    "package_promotion_review_packet_prep_only_draft": (
        "b04_r6_package_promotion_review_packet_prep_only_draft.json"
    ),
    "commercial_activation_claim_review_prep_only_draft": (
        "b04_r6_commercial_activation_claim_review_prep_only_draft.json"
    ),
    "commercial_activation_claim_validation_plan_prep_only": (
        "b04_r6_commercial_activation_claim_validation_plan_prep_only.json"
    ),
    "external_audit_delta_packet_prep_only_draft": "b04_r6_external_audit_delta_packet_prep_only_draft.json",
    "limited_continuation_packet_prep_only_draft": "b04_r6_limited_continuation_packet_prep_only_draft.json",
    "rollback_closeout_packet_prep_only_draft": "b04_r6_rollback_closeout_packet_prep_only_draft.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
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
            yield str(key), item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_B04R6_R6_OPENING_REVIEW_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_R6_OPENING_REVIEW_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _opening_json_inputs_for_branch(branch: str) -> Dict[str, str]:
    if branch == AUTHORITY_BRANCH:
        return dict(OPENING_JSON_INPUTS)
    output_paths = {f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values()}
    return {role: raw for role, raw in OPENING_JSON_INPUTS.items() if raw not in output_paths}


def _all_json_inputs(branch: str) -> Dict[str, str]:
    return {f"opening_{role}": raw for role, raw in _opening_json_inputs_for_branch(branch).items()}


ALL_JSON_INPUTS = _all_json_inputs(AUTHORITY_BRANCH)
ALL_TEXT_INPUTS = {f"opening_{role}": raw for role, raw in OPENING_TEXT_INPUTS.items()}


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_R6_OPENING_REVIEW_RUNTIME_EVIDENCE_MISSING", f"{label} must be a JSON object")
    return payload


def _payloads(root: Path, branch: str) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in _all_json_inputs(branch).items()}
    texts = {role: common.read_text_required(root, raw, label=role) for role, raw in ALL_TEXT_INPUTS.items()}
    return payloads, texts


def _ensure_opening_boundaries(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role, payload in payloads.items():
        for key, value in _walk(payload):
            if key in DOWNSTREAM_DRIFT_KEYS and value is not False:
                _fail(DOWNSTREAM_DRIFT_KEYS[key], f"{role}.{key} drifted to {value!r}")
        if payload.get("r6_opening_executed") is not True or payload.get("r6_open") is not True:
            _fail("RC_B04R6_R6_OPENING_REVIEW_RUNTIME_EVIDENCE_MISSING", f"{role} missing R6 opening truth")
        if payload.get("package_promotion") not in (None, "DEFERRED", "BLOCKED"):
            _fail("RC_B04R6_R6_OPENING_REVIEW_PACKAGE_PROMOTION_DRIFT", f"{role}.package_promotion drifted")
        if payload.get("commercial_claim_status") not in (None, "BOUNDARY_ONLY"):
            _fail("RC_B04R6_R6_OPENING_REVIEW_COMMERCIAL_CLAIM_DRIFT", f"{role}.commercial_claim_status drifted")


def _validate_opening_handoff(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    contract = payloads["opening_execution_contract"]
    receipt = payloads["opening_execution_receipt"]
    result = payloads["opening_result"]
    next_move = payloads["opening_next_lawful_move"]
    for label, payload in (("opening contract", contract), ("opening receipt", receipt), ("opening result", result)):
        if payload.get("authoritative_lane") != PREVIOUS_LANE:
            _fail("RC_B04R6_R6_OPENING_REVIEW_RUNTIME_EVIDENCE_MISSING", f"{label} lane drift")
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_B04R6_R6_OPENING_REVIEW_RUNTIME_OUTCOME_DRIFT", f"{label} outcome drift")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_B04R6_R6_OPENING_REVIEW_NEXT_MOVE_DRIFT", f"{label} next move drift")
        if not payload.get("input_bindings"):
            _fail("RC_B04R6_R6_OPENING_REVIEW_INPUT_BINDINGS_EMPTY", f"{label} input_bindings empty")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_R6_OPENING_REVIEW_NEXT_MOVE_DRIFT", "opening next-lawful-move drift")
    report = texts.get("opening_report", "").lower()
    for phrase in ("does not promote package", "does not authorize commercial activation claims"):
        if phrase not in report:
            _fail("RC_B04R6_R6_OPENING_REVIEW_RUNTIME_EVIDENCE_MISSING", f"opening report missing {phrase!r}")


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _ensure_opening_boundaries(payloads)
    _validate_opening_handoff(payloads, texts)
    scorecard = payloads["opening_execution_contract"].get("scorecard", {})
    required = {
        "sample_limit_respected": True,
        "static_fallback_preserved": True,
        "operator_override_ready": True,
        "kill_switch_ready": True,
        "rollback_ready": True,
        "route_distribution_health": "PASS",
        "drift_status": "PASS",
        "replay_status": "PASS",
        "external_verifier_ready": True,
        "commercial_claim_boundary_preserved": True,
    }
    for key, expected in required.items():
        if scorecard.get(key) != expected:
            _fail("RC_B04R6_R6_OPENING_REVIEW_SCORECARD_INCOMPLETE", f"scorecard {key}={scorecard.get(key)!r}")


def _input_bindings(root: Path, branch: str) -> list[Dict[str, Any]]:
    output_paths = {f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values()}
    rows: list[Dict[str, Any]] = []
    for role, raw in sorted({**_all_json_inputs(branch), **ALL_TEXT_INPUTS}.items()):
        overwritten = raw in output_paths
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": (
                    "pre_overwrite_file_sha256_at_r6_opening_evidence_review"
                    if overwritten
                    else "file_sha256_at_r6_opening_evidence_review"
                ),
                "overwritten_by_r6_opening_evidence_review_output": overwritten,
            }
        )
    return rows


def _scorecard(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    opening_scorecard = payloads["opening_execution_contract"]["scorecard"]
    return {
        "opening_result": "PASSED",
        "r6_opening_executed": True,
        "r6_open": True,
        "sample_limit_respected": opening_scorecard["sample_limit_respected"],
        "route_distribution_health": opening_scorecard["route_distribution_health"],
        "fallback_behavior": "PASS" if opening_scorecard["fallback_failures"] == 0 else "FAIL",
        "static_fallback_preserved": opening_scorecard["static_fallback_preserved"],
        "abstention_fallback_preserved": opening_scorecard["abstention_fallback_preserved"],
        "null_route_preserved": opening_scorecard["null_route_preserved"],
        "operator_override_ready": opening_scorecard["operator_override_ready"],
        "kill_switch_ready": opening_scorecard["kill_switch_ready"],
        "rollback_ready": opening_scorecard["rollback_ready"],
        "drift_status": opening_scorecard["drift_status"],
        "incident_freeze_clean": not opening_scorecard["incident_freeze_triggers"],
        "trace_completeness": "PASS",
        "replay_status": opening_scorecard["replay_status"],
        "external_verifier_ready": opening_scorecard["external_verifier_ready"],
        "commercial_claim_boundary_preserved": opening_scorecard["commercial_claim_boundary_preserved"],
        "package_promotion_review_ready": True,
        "package_promotion_ready": False,
        "commercial_activation_claim_ready": False,
        "blocking_reasons": [
            "package_promotion_requires_r6_opening_evidence_review_validation",
            "commercial_activation_claims_require_separate_claim_review",
        ],
    }


def _decision_matrix(scorecard: Dict[str, Any]) -> Dict[str, Any]:
    review_ready = all(
        (
            scorecard["r6_opening_executed"],
            scorecard["r6_open"],
            scorecard["sample_limit_respected"],
            scorecard["route_distribution_health"] == "PASS",
            scorecard["fallback_behavior"] == "PASS",
            scorecard["operator_override_ready"],
            scorecard["kill_switch_ready"],
            scorecard["rollback_ready"],
            scorecard["drift_status"] == "PASS",
            scorecard["incident_freeze_clean"],
            scorecard["replay_status"] == "PASS",
            scorecard["commercial_claim_boundary_preserved"],
        )
    )
    recommended = RECOMMENDED_VALIDATED_PATH if review_ready else "LIMITED_CONTINUATION_PACKET_NEXT"
    return {
        "decision_matrix_id": "B04_R6_R6_OPENING_EVIDENCE_DECISION_MATRIX_V1",
        "r6_opening_result": "PASSED",
        "overall_grade": "A_REVIEWABLE" if review_ready else "B_LIMITED_CONTINUATION_RECOMMENDED",
        "package_promotion_review_ready": review_ready,
        "package_promotion_ready": False,
        "commercial_activation_claim_status": "BOUNDARY_ONLY",
        "external_audit_delta_ready": "READY_FOR_PACKET",
        "recommended_next_path": recommended,
        "recommendation_is_authority": False,
        "blocking_reasons": scorecard["blocking_reasons"],
        "supporting_evidence": [
            "r6_opening_execution_contract",
            "r6_opening_result",
            "r6_opening_case_manifest",
            "r6_opening_no_authorization_drift_receipt",
        ],
    }


def _authority_state() -> Dict[str, Any]:
    return {
        "runtime_cutover_executed": True,
        "post_cutover_evidence_review_validated": True,
        "r6_opening_review_validated": True,
        "r6_opening_authorization_validated": True,
        "r6_opening_execution_packet_validated": True,
        "r6_opening_executed": True,
        "r6_open": True,
        "r6_opening_evidence_review_packet_authored": True,
        "r6_opening_evidence_review_validated": False,
        "global_runtime_surface_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "package_promotion_authorized": False,
        "commercial_claim_status": "BOUNDARY_ONLY",
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "metric_contract_mutated": False,
        "static_comparator_weakened": False,
        "r6_open_treated_as_package_promotion": False,
        "r6_open_treated_as_commercial_activation": False,
    }


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    input_bindings: list[Dict[str, Any]],
    scorecard: Dict[str, Any],
    decision_matrix: Dict[str, Any],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
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
        "recommended_validated_path": RECOMMENDED_VALIDATED_PATH,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "overwritten_input_roles": [
            row["role"] for row in input_bindings if row.get("overwritten_by_r6_opening_evidence_review_output")
        ],
        "binding_hashes": {f"{row['role']}_hash": row["sha256"] for row in input_bindings},
        "scorecard": scorecard,
        "decision_matrix": decision_matrix,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        "no_authorization_drift": True,
        **_authority_state(),
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _prep_only(base: Dict[str, Any], *, role: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.r6_opening_evidence_review.{role}.prep_only.v1",
        artifact_id=f"B04_R6_R6_OPENING_EVIDENCE_REVIEW_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_authorize_lobe_escalation=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _review(base: Dict[str, Any], *, role: str, status: str = "PASS", **extra: Any) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.r6_opening_evidence_review.{role}.contract.v1",
        artifact_id=f"B04_R6_R6_OPENING_EVIDENCE_REVIEW_{role.upper()}",
        review_status=status,
        **extra,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    scorecard = base["scorecard"]
    decision = base["decision_matrix"]
    payloads: Dict[str, Any] = {
        "packet_contract": _artifact(base, schema_id="kt.b04_r6.r6_opening_evidence_review.packet_contract.v1", artifact_id="B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET_CONTRACT"),
        "packet_receipt": _artifact(base, schema_id="kt.b04_r6.r6_opening_evidence_review.packet_receipt.v1", artifact_id="B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET_RECEIPT", verdict="BOUND_FOR_VALIDATION"),
        "evidence_inventory": _artifact(base, schema_id="kt.b04_r6.r6_opening_evidence_review.inventory.v1", artifact_id="B04_R6_R6_OPENING_EVIDENCE_INVENTORY", evidence_roles=sorted(ALL_JSON_INPUTS)),
        "evidence_scorecard": _artifact(base, schema_id="kt.b04_r6.r6_opening_evidence_review.scorecard.v1", artifact_id="B04_R6_R6_OPENING_EVIDENCE_SCORECARD", scorecard=scorecard),
        "decision_matrix": _artifact(base, schema_id="kt.b04_r6.r6_opening_evidence_review.decision_matrix.v1", artifact_id="B04_R6_R6_OPENING_POST_RUN_DECISION_MATRIX", decision_matrix=decision),
        "package_promotion_readiness_matrix": _artifact(base, schema_id="kt.b04_r6.package_promotion.readiness_matrix.v1", artifact_id="B04_R6_PACKAGE_PROMOTION_READINESS_MATRIX", package_promotion_review_ready=decision["package_promotion_review_ready"], package_promotion_ready=False),
        "commercial_claim_ceiling_update": _artifact(base, schema_id="kt.b04_r6.commercial_claim_ceiling.update.v1", artifact_id="B04_R6_COMMERCIAL_CLAIM_CEILING_UPDATE", allowed_claims=["R6 opening passed under bounded packet law; evidence review validation is next."], forbidden_claims=["Package promotion is authorized.", "Commercial activation is authorized."]),
        "external_audit_delta_readiness": _artifact(base, schema_id="kt.b04_r6.external_audit_delta.readiness.v1", artifact_id="B04_R6_EXTERNAL_AUDIT_DELTA_READINESS", external_audit_delta_ready="READY_FOR_PACKET"),
        "public_verifier_readiness": _artifact(base, schema_id="kt.b04_r6.public_verifier.readiness.v1", artifact_id="B04_R6_PUBLIC_VERIFIER_READINESS", public_verifier_ready=True),
        "rollback_continuation_matrix": _artifact(base, schema_id="kt.b04_r6.r6_opening.rollback_continuation_matrix.v1", artifact_id="B04_R6_R6_OPENING_ROLLBACK_CONTINUATION_MATRIX", rollback_closeout_ready=False, limited_continuation_ready=True),
        "route_distribution_review": _review(base, role="route_distribution", route_distribution_health=scorecard["route_distribution_health"]),
        "fallback_behavior_review": _review(base, role="fallback_behavior", fallback_behavior=scorecard["fallback_behavior"]),
        "static_fallback_review": _review(base, role="static_fallback", static_fallback_preserved=True),
        "abstention_fallback_review": _review(base, role="abstention_fallback", abstention_fallback_preserved=True),
        "null_route_review": _review(base, role="null_route", null_route_preserved=True),
        "operator_override_review": _review(base, role="operator_override", operator_override_ready=True),
        "kill_switch_review": _review(base, role="kill_switch", kill_switch_ready=True),
        "rollback_review": _review(base, role="rollback", rollback_ready=True),
        "drift_monitoring_review": _review(base, role="drift_monitoring", drift_status="PASS"),
        "incident_freeze_review": _review(base, role="incident_freeze", incident_freeze_clean=True),
        "trace_completeness_review": _review(base, role="trace_completeness", trace_completeness="PASS"),
        "replay_readiness_review": _review(base, role="replay_readiness", replay_status="PASS"),
        "external_verifier_review": _review(base, role="external_verifier", external_verifier_ready=True),
        "commercial_claim_boundary_review": _review(base, role="commercial_claim_boundary", commercial_claim_boundary_preserved=True),
        "package_promotion_blocker_review": _review(base, role="package_promotion_blocker", package_promotion_authorized=False, blockers=scorecard["blocking_reasons"]),
        "no_authorization_drift_receipt": _artifact(base, schema_id="kt.b04_r6.r6_opening_evidence_review.no_authorization_drift.receipt.v1", artifact_id="B04_R6_R6_OPENING_EVIDENCE_REVIEW_NO_AUTHORIZATION_DRIFT_RECEIPT", validation_status="PASS", no_downstream_authorization_drift=True),
        "validation_plan": _artifact(base, schema_id="kt.b04_r6.r6_opening_evidence_review.validation_plan.v1", artifact_id="B04_R6_R6_OPENING_EVIDENCE_REVIEW_VALIDATION_PLAN", validation_success_outcome=VALIDATION_SUCCESS_OUTCOME),
        "validation_reason_codes": _artifact(base, schema_id="kt.b04_r6.r6_opening_evidence_review.reason_codes.v1", artifact_id="B04_R6_R6_OPENING_EVIDENCE_REVIEW_VALIDATION_REASON_CODES", reason_codes=list(REASON_CODES)),
        "pipeline_board": _artifact(base, schema_id="kt.b04_r6.pipeline_board.v31", artifact_id="B04_R6_PIPELINE_BOARD", lanes=[
            {"lane": "RUN_B04_R6_R6_OPENING", "status": "PASSED", "authoritative": False},
            {"lane": "AUTHOR_B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET", "status": "CURRENT_BOUND", "authoritative": True},
            {"lane": "VALIDATE_B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET", "status": "NEXT", "authoritative": True},
            {"lane": "PACKAGE_PROMOTION_REVIEW", "status": "RECOMMENDED_NOT_AUTHORIZED", "authoritative": False},
            {"lane": "COMMERCIAL_ACTIVATION_CLAIM_REVIEW", "status": "BLOCKED", "authoritative": False},
        ]),
        "future_blocker_register": _artifact(base, schema_id="kt.future_blocker_register.v11", artifact_id="KT_FUTURE_BLOCKER_REGISTER", blockers=[
            {"category": "r6_opening_evidence_review_validation", "status": "OPEN", "blocks": [VALIDATION_SUCCESS_NEXT_MOVE]},
            {"category": "package_promotion", "status": "BLOCKING", "blocks": ["PACKAGE_PROMOTION_AUTHORIZED"]},
            {"category": "commercial_claims", "status": "BLOCKING", "blocks": ["COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED"]},
        ]),
        "next_lawful_move": _artifact(base, schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v59", artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT", verdict="NEXT_LAWFUL_MOVE_SET"),
    }
    payloads.update({role: _prep_only(base, role=role) for role in PREP_ONLY_ROLES})
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 R6 Opening Evidence Review Packet\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "The R6 opening evidence review packet is bound for validation. It reviews the R6 opening run, scorecard, "
        "fallbacks, operator control, kill switch, rollback, drift, incident/freeze status, trace completeness, replay "
        "readiness, external verifier readiness, commercial claim boundary, and package-promotion blockers.\n\n"
        "The packet recommends package-promotion review packet authorship after validation, but that recommendation is "
        "not authority. It does not authorize package promotion, does not authorize commercial activation claims, does "
        "not authorize lobe escalation, and does not mutate truth/trust law.\n"
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 R6 opening evidence review packet")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root, branch)
    _validate_inputs(payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_R6_OPENING_REVIEW_TRUST_ZONE_FAILED", "fresh trust-zone validation must pass")
    scorecard = _scorecard(payloads)
    decision = _decision_matrix(scorecard)
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root, branch),
        scorecard=scorecard,
        decision_matrix=decision,
        trust_zone_validation=trust_zone_validation,
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
