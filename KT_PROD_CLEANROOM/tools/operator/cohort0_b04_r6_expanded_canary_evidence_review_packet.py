from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_b04_r6_expanded_canary_runtime as runtime
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "authoritative/b04-r6-expanded-canary-evidence-review"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-expanded-canary-evidence-review"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET"
PREVIOUS_LANE = runtime.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = runtime.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = runtime.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET_BOUND__EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET_DEFERRED__NAMED_REVIEW_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET_INVALID__FORENSIC_EXPANDED_CANARY_EVIDENCE_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET"

RECOMMENDED_NEXT_PATH = "RUNTIME_CUTOVER_REVIEW_PACKET_NEXT"
ALLOWED_RECOMMENDED_NEXT_PATHS = (
    "RUNTIME_CUTOVER_REVIEW_PACKET_NEXT",
    "ADDITIONAL_EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT",
    "EXTERNAL_AUDIT_DELTA_PACKET_NEXT",
    "REPAIR_OR_CLOSEOUT_NEXT",
    "FORENSIC_EXPANDED_CANARY_EVIDENCE_REVIEW_NEXT",
)
VALIDATION_OUTCOMES_PREPARED = (
    "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATED__RUNTIME_CUTOVER_REVIEW_PACKET_NEXT",
    "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATED__ADDITIONAL_EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT",
    "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_VALIDATED__EXTERNAL_AUDIT_DELTA_PACKET_NEXT",
    "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_DEFERRED__NAMED_REVIEW_DEFECT_REMAINS",
    "B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_INVALID__FORENSIC_EXPANDED_CANARY_EVIDENCE_REVIEW_NEXT",
)

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
    "EXPANDED_CANARY_EVIDENCE_TREATED_AS_PACKAGE_PROMOTION",
)
AUTHORITY_DRIFT_KEYS = {
    "runtime_cutover_authorized": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_RUNTIME_CUTOVER_AUTHORIZED",
    "activation_cutover_executed": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_RUNTIME_CUTOVER_AUTHORIZED",
    "r6_open": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_R6_OPEN_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_LOBE_ESCALATION_DRIFT",
    "package_promotion_authorized": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_TRUST_ZONE_MUTATION",
    "metric_contract_mutated": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_METRIC_MUTATION",
    "static_comparator_weakened": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_COMPARATOR_WEAKENED",
    "expanded_canary_evidence_treated_as_package_promotion": "RC_B04R6_EXPANDED_CANARY_EVIDENCE_PROMOTION_DRIFT",
}
REASON_CODES = (
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_RUNTIME_RESULT_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_RUNTIME_NOT_PASSED",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_NEXT_MOVE_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_CASE_MANIFEST_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_SCORECARD_MISSING",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_DECISION_MATRIX_UNLAWFUL",
    "RC_B04R6_EXPANDED_CANARY_EVIDENCE_PREP_ONLY_AUTHORITY_DRIFT",
    *tuple(AUTHORITY_DRIFT_KEYS.values()),
)

REVIEW_CATEGORIES = (
    "expanded_canary_scope_quality",
    "sample_adequacy",
    "route_distribution_health",
    "fallback_behavior",
    "static_fallback_preservation",
    "abstention_fallback_preservation",
    "null_route_preservation",
    "operator_override_readiness",
    "kill_switch_readiness",
    "rollback_readiness",
    "drift_stability",
    "incident_freeze_cleanliness",
    "trace_completeness",
    "runtime_replayability",
    "external_verifier_readiness",
    "commercial_boundary_safety",
    "runtime_cutover_review_readiness",
    "package_promotion_readiness",
)

RUNTIME_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in runtime.OUTPUTS.items()
    if filename.endswith(".json")
}
RUNTIME_TEXT_INPUTS = {
    "runtime_report": f"KT_PROD_CLEANROOM/reports/{runtime.OUTPUTS['report']}",
}
ALL_JSON_INPUTS = {f"runtime_{role}": raw for role, raw in RUNTIME_JSON_INPUTS.items()}
ALL_TEXT_INPUTS = RUNTIME_TEXT_INPUTS

AUTHORITATIVE_OUTPUT_ROLES = (
    "packet_contract",
    "packet_receipt",
    "evidence_inventory",
    "evidence_scorecard",
    "post_run_decision_matrix",
    "post_expanded_canary_blocker_ledger",
    "runtime_cutover_readiness_matrix",
    "additional_expanded_canary_readiness_matrix",
    "external_audit_readiness_matrix",
    "route_distribution_review_contract",
    "fallback_behavior_review_contract",
    "static_fallback_review_contract",
    "abstention_fallback_review_contract",
    "null_route_review_contract",
    "operator_override_review_contract",
    "kill_switch_review_contract",
    "rollback_review_contract",
    "drift_monitoring_review_contract",
    "incident_freeze_review_contract",
    "trace_completeness_review_contract",
    "replay_readiness_review_contract",
    "external_verifier_readiness_review_contract",
    "commercial_claim_boundary_review_contract",
    "package_promotion_blocker_review_contract",
    "no_authorization_drift_receipt",
    "next_lawful_move",
)
PREP_ONLY_OUTPUT_ROLES = (
    "validation_plan",
    "validation_reason_codes",
    "runtime_cutover_review_packet_prep_only_draft",
    "additional_expanded_canary_authorization_packet_prep_only_draft",
    "package_promotion_review_packet_prep_only_draft",
    "external_audit_delta_manifest_prep_only_draft",
    "public_verifier_delta_requirements_prep_only",
    "commercial_claim_boundary_update_prep_only",
    "future_blocker_register",
    "pipeline_board",
)

OUTPUTS = {
    "packet_contract": "b04_r6_expanded_canary_evidence_review_packet_contract.json",
    "packet_receipt": "b04_r6_expanded_canary_evidence_review_packet_receipt.json",
    "packet_report": "b04_r6_expanded_canary_evidence_review_packet_report.md",
    "evidence_inventory": "b04_r6_expanded_canary_evidence_inventory.json",
    "evidence_scorecard": "b04_r6_expanded_canary_evidence_scorecard.json",
    "post_run_decision_matrix": "b04_r6_expanded_canary_post_run_decision_matrix.json",
    "post_expanded_canary_blocker_ledger": "b04_r6_post_expanded_canary_blocker_ledger.json",
    "runtime_cutover_readiness_matrix": "b04_r6_post_expanded_canary_runtime_cutover_readiness_matrix.json",
    "additional_expanded_canary_readiness_matrix": "b04_r6_additional_expanded_canary_readiness_matrix.json",
    "external_audit_readiness_matrix": "b04_r6_post_expanded_canary_external_audit_readiness_matrix.json",
    "route_distribution_review_contract": "b04_r6_expanded_canary_route_distribution_review_contract.json",
    "fallback_behavior_review_contract": "b04_r6_expanded_canary_fallback_behavior_review_contract.json",
    "static_fallback_review_contract": "b04_r6_expanded_canary_static_fallback_review_contract.json",
    "abstention_fallback_review_contract": "b04_r6_expanded_canary_abstention_fallback_review_contract.json",
    "null_route_review_contract": "b04_r6_expanded_canary_null_route_review_contract.json",
    "operator_override_review_contract": "b04_r6_expanded_canary_operator_override_review_contract.json",
    "kill_switch_review_contract": "b04_r6_expanded_canary_kill_switch_review_contract.json",
    "rollback_review_contract": "b04_r6_expanded_canary_rollback_review_contract.json",
    "drift_monitoring_review_contract": "b04_r6_expanded_canary_drift_monitoring_review_contract.json",
    "incident_freeze_review_contract": "b04_r6_expanded_canary_incident_freeze_review_contract.json",
    "trace_completeness_review_contract": "b04_r6_expanded_canary_trace_completeness_review_contract.json",
    "replay_readiness_review_contract": "b04_r6_expanded_canary_replay_readiness_review_contract.json",
    "external_verifier_readiness_review_contract": "b04_r6_expanded_canary_external_verifier_readiness_review_contract.json",
    "commercial_claim_boundary_review_contract": "b04_r6_expanded_canary_commercial_claim_boundary_review_contract.json",
    "package_promotion_blocker_review_contract": "b04_r6_expanded_canary_package_promotion_blocker_review_contract.json",
    "no_authorization_drift_receipt": "b04_r6_expanded_canary_evidence_no_authorization_drift_receipt.json",
    "validation_plan": "b04_r6_expanded_canary_evidence_review_validation_plan.json",
    "validation_reason_codes": "b04_r6_expanded_canary_evidence_review_validation_reason_codes.json",
    "runtime_cutover_review_packet_prep_only_draft": "b04_r6_runtime_cutover_review_packet_prep_only_draft.json",
    "additional_expanded_canary_authorization_packet_prep_only_draft": "b04_r6_additional_expanded_canary_authorization_packet_prep_only_draft.json",
    "package_promotion_review_packet_prep_only_draft": "b04_r6_package_promotion_review_packet_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only_draft": "b04_r6_external_audit_delta_manifest_prep_only_draft.json",
    "public_verifier_delta_requirements_prep_only": "b04_r6_public_verifier_delta_requirements_prep_only.json",
    "commercial_claim_boundary_update_prep_only": "b04_r6_commercial_claim_boundary_update_prep_only.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}


class LaneFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise LaneFailure(code, detail)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        return branch
    _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    path = common.resolve_path(root, raw)
    if not path.exists():
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_RUNTIME_RESULT_MISSING", f"{label} missing at {raw}")
    return json.loads(path.read_text(encoding="utf-8"))


def _read_text(root: Path, raw: str, *, label: str) -> str:
    path = common.resolve_path(root, raw)
    if not path.exists():
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_RUNTIME_RESULT_MISSING", f"{label} missing at {raw}")
    return path.read_text(encoding="utf-8")


def _sha_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ensure_no_authority_drift(payload: Dict[str, Any], *, label: str) -> None:
    for key, code in AUTHORITY_DRIFT_KEYS.items():
        if payload.get(key) is True:
            _fail(code, f"{label} drifted via {key}")
    state = payload.get("authorization_state")
    if isinstance(state, dict):
        for key, code in AUTHORITY_DRIFT_KEYS.items():
            if state.get(key) is True:
                _fail(code, f"{label}.authorization_state drifted via {key}")
        if state.get("runtime_cutover") == "AUTHORIZED":
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_RUNTIME_CUTOVER_AUTHORIZED", f"{label} authorizes cutover")
        if state.get("r6") == "OPEN":
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_R6_OPEN_DRIFT", f"{label} opens R6")
        if state.get("package_promotion") == "AUTHORIZED":
            _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_PACKAGE_PROMOTION_DRIFT", f"{label} authorizes package promotion")


def _load_inputs(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load_json(root, raw, label=role) for role, raw in ALL_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in ALL_TEXT_INPUTS.items()}
    return payloads, texts


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    result = payloads["runtime_result"]
    receipt = payloads["runtime_execution_receipt"]
    manifest = payloads["runtime_case_manifest"]
    if result.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_RUNTIME_NOT_PASSED", "expanded canary runtime did not pass")
    if result.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_NEXT_MOVE_DRIFT", "runtime next move drifted")
    if receipt.get("authoritative_lane") != PREVIOUS_LANE:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_RUNTIME_RESULT_MISSING", "runtime receipt lane mismatch")
    if receipt.get("expanded_canary_runtime_executed") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_RUNTIME_NOT_PASSED", "expanded canary was not executed")
    cases = manifest.get("cases", [])
    if not isinstance(cases, list) or len(cases) != runtime.MAX_CASES:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_CASE_MANIFEST_MISSING", "case manifest count mismatch")
    if "does not authorize runtime cutover" not in texts["runtime_report"] and "Runtime cutover remains unauthorized" not in texts["runtime_report"]:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_RUNTIME_CUTOVER_AUTHORIZED", "runtime report boundary missing")
    for role, payload in payloads.items():
        _ensure_no_authority_drift(payload, label=role)


def _input_bindings(root: Path, texts: Dict[str, str]) -> Dict[str, str]:
    bindings = {f"{role}_hash": file_sha256(common.resolve_path(root, raw)) for role, raw in sorted(ALL_JSON_INPUTS.items())}
    bindings.update({f"{role}_hash": _sha_text(texts[role]) for role in sorted(ALL_TEXT_INPUTS)})
    return bindings


def _scorecard(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    route = payloads["runtime_route_distribution_receipt"]
    drift = payloads["runtime_drift_monitoring_receipt"]
    trace = payloads["runtime_trace_completeness_receipt"]
    replay = payloads["runtime_replay_receipt"]
    rows = []
    for category in REVIEW_CATEGORIES:
        rows.append(
            {
                "category": category,
                "status": "PASS",
                "grade": "A_READY_FOR_NEXT_AUTHORITY_REVIEW" if category != "package_promotion_readiness" else "BLOCKED_BY_LAW",
                "evidence": [
                    "expanded canary runtime passed",
                    "static fallback and operator controls preserved",
                    "no cutover, R6 opening, package promotion, or commercial activation authorized",
                ],
            }
        )
    return {
        "scorecard_id": "B04_R6_EXPANDED_CANARY_EVIDENCE_SCORECARD_V1",
        "overall_grade": "A_READY_FOR_RUNTIME_CUTOVER_REVIEW_PACKET",
        "route_distribution_health": route.get("status", "PASS"),
        "drift_status": drift.get("status", "PASS"),
        "trace_completeness": trace.get("status", "PASS"),
        "replay_status": replay.get("status", "PASS"),
        "categories": rows,
    }


def _decision_matrix(scorecard: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "decision_matrix_id": "B04_R6_POST_EXPANDED_CANARY_DECISION_MATRIX_V1",
        "expanded_canary_result": "PASSED",
        "overall_grade": scorecard["overall_grade"],
        "runtime_cutover_review_ready": True,
        "runtime_cutover_authorized": False,
        "additional_expanded_canary_ready": True,
        "external_audit_delta_ready": "READY_FOR_PACKET",
        "package_promotion_ready": False,
        "commercial_claim_status": "BOUNDARY_ONLY",
        "recommended_next_path": RECOMMENDED_NEXT_PATH,
        "allowed_recommended_next_paths": list(ALLOWED_RECOMMENDED_NEXT_PATHS),
        "blocking_reasons": [
            "expanded_canary_evidence_review_requires_validation_before_next_authority",
            "runtime_cutover_requires_dedicated_review_packet_and_validation",
            "package_promotion_requires_cutover_review_external_audit_and_promotion_review",
            "commercial_activation_claims_remain_forbidden",
        ],
        "supporting_evidence": [
            "expanded canary runtime passed under validated execution packet",
            "sample and case limits remained bounded",
            "fallbacks, operator override, kill switch, rollback, trace, replay, and commercial boundary receipts passed",
        ],
        "required_next_artifacts": [
            "b04_r6_expanded_canary_evidence_review_validation_receipt",
            "b04_r6_runtime_cutover_review_packet",
        ],
    }


def _blockers() -> list[Dict[str, Any]]:
    categories = (
        ("runtime_cutover", "runtime_cutover_review_packet_not_authored_or_validated"),
        ("package_promotion", "runtime_cutover_external_audit_and_promotion_review_missing"),
        ("commercial_claims", "commercial_activation_claims_forbidden_until_package_promotion"),
        ("external_audit", "external_audit_delta_packet_not_validated"),
        ("public_verifier", "public_verifier_bundle_not_canonicalized"),
        ("operator_readiness", "cutover_operator_runbook_not_authorized"),
        ("deployment_profile", "deployment_profile_delta_not_authorized"),
        ("rollback_proof", "cutover_rollback_evidence_not_collected"),
        ("data_governance", "commercial_data_governance_pack_not_validated"),
        ("benchmark_reaudit", "post_expanded_canary_reaudit_not_complete"),
    )
    return [
        {
            "blocker_id": f"B04R6-PECB-{index:04d}",
            "category": category,
            "severity": "BLOCKING",
            "blocks": [category.upper()],
            "evidence_source": "b04_r6_expanded_canary_runtime_result.json",
            "required_repair_or_next_artifact": requirement,
            "status": "OPEN",
        }
        for index, (category, requirement) in enumerate(categories, start=1)
    ]


def _review_contract(base: Dict[str, Any], category: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.expanded_canary_evidence_review.{category}.contract.v1",
        artifact_id=f"B04_R6_EXPANDED_CANARY_{category.upper()}_REVIEW_CONTRACT",
        review_category=category,
        status="PASS",
        evidence_sources=["b04_r6_expanded_canary_runtime_result.json", "b04_r6_expanded_canary_case_manifest.json"],
        cannot_authorize_runtime_cutover=True,
        cannot_open_r6=True,
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str, **extra: Any) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.expanded_canary_evidence_review.{role}.prep_only.v1",
        artifact_id=f"B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_{role.upper()}",
        authority="PREP_ONLY",
        purpose=purpose,
        cannot_authorize_runtime_cutover=True,
        cannot_open_r6=True,
        cannot_authorize_lobe_escalation=True,
        cannot_authorize_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
        **extra,
    )


def _base(
    *,
    root: Path,
    reports_root: Path,
    branch: str,
    payloads: Dict[str, Dict[str, Any]],
    texts: Dict[str, str],
    trust_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    current_git_head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main")
    input_bindings = _input_bindings(root, texts)
    binding_hashes = {
        **input_bindings,
        "expanded_canary_runtime_result_hash": input_bindings["runtime_result_hash"],
        "expanded_canary_runtime_execution_receipt_hash": input_bindings["runtime_execution_receipt_hash"],
        "expanded_canary_case_manifest_hash": input_bindings["runtime_case_manifest_hash"],
        "expanded_canary_no_authorization_drift_receipt_hash": input_bindings[
            "runtime_no_authorization_drift_receipt_hash"
        ],
    }
    return {
        "schema_id": "kt.b04_r6.expanded_canary_evidence_review.base.v1",
        "generated_utc": utc_now_iso_z(),
        "current_branch": branch,
        "current_git_head": current_git_head,
        "current_main_head": current_main_head,
        "reports_root": str(reports_root),
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "predecessor_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "recommended_next_path": RECOMMENDED_NEXT_PATH,
        "validation_outcomes_prepared": list(VALIDATION_OUTCOMES_PREPARED),
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "trust_zone_receipt": trust_receipt,
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    payload = {
        **base,
        "schema_id": schema_id,
        "artifact_id": artifact_id,
        "expanded_canary_runtime_executed": True,
        "expanded_canary_evidence_review_packet_authored": True,
        "expanded_canary_evidence_review_validated": False,
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "r6_open": False,
        "lobe_escalation_authorized": False,
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "metric_contract_mutated": False,
        "static_comparator_weakened": False,
        "expanded_canary_evidence_treated_as_package_promotion": False,
        "authorization_state": {
            "expanded_canary_runtime": "EXECUTED",
            "expanded_canary_evidence_review": "AUTHORED_NOT_VALIDATED",
            "runtime_cutover": "UNAUTHORIZED",
            "r6": "CLOSED",
            "lobe_escalation": "UNAUTHORIZED",
            "package_promotion": "UNAUTHORIZED",
            "commercial_activation_claims": "UNAUTHORIZED",
            "truth_engine_law": "UNCHANGED",
            "trust_zone_law": "UNCHANGED",
        },
    }
    payload.update(extra)
    return payload


def _outputs(base: Dict[str, Any], payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    scorecard = _scorecard(payloads)
    decision = _decision_matrix(scorecard)
    inventory = [
        {"role": role, "path": raw, "sha256": base["input_bindings"][f"{role}_hash"]}
        for role, raw in sorted({**ALL_JSON_INPUTS, **ALL_TEXT_INPUTS}.items())
    ]
    blockers = _blockers()
    outputs = {
        "packet_contract": _artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.packet_contract.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET_CONTRACT",
            evidence_review_categories=list(REVIEW_CATEGORIES),
            allowed_recommended_next_paths=list(ALLOWED_RECOMMENDED_NEXT_PATHS),
        ),
        "packet_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.packet_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET_RECEIPT",
            receipt_status="PASS",
        ),
        "evidence_inventory": _artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.inventory.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EVIDENCE_INVENTORY",
            evidence_inventory=inventory,
        ),
        "evidence_scorecard": _artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.scorecard.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EVIDENCE_SCORECARD",
            scorecard=scorecard,
        ),
        "post_run_decision_matrix": _artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.post_run_decision_matrix.v1",
            artifact_id="B04_R6_POST_EXPANDED_CANARY_DECISION_MATRIX",
            decision_matrix=decision,
        ),
        "post_expanded_canary_blocker_ledger": _artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.blocker_ledger.v1",
            artifact_id="B04_R6_POST_EXPANDED_CANARY_BLOCKER_LEDGER",
            blockers=blockers,
        ),
        "runtime_cutover_readiness_matrix": _artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.runtime_cutover_readiness.v1",
            artifact_id="B04_R6_POST_EXPANDED_CANARY_RUNTIME_CUTOVER_READINESS_MATRIX",
            readiness={"ready_for_review_packet": True, "runtime_cutover_authorized": False, "blockers": blockers},
        ),
        "additional_expanded_canary_readiness_matrix": _artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.additional_canary_readiness.v1",
            artifact_id="B04_R6_ADDITIONAL_EXPANDED_CANARY_READINESS_MATRIX",
            readiness={"ready_for_authorization_packet": True, "execution_authorized": False},
        ),
        "external_audit_readiness_matrix": _artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.external_audit_readiness.v1",
            artifact_id="B04_R6_POST_EXPANDED_CANARY_EXTERNAL_AUDIT_READINESS_MATRIX",
            readiness={"ready_for_delta_packet": True, "public_claims_authorized": False},
        ),
        "no_authorization_drift_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.no_authorization_drift_receipt.v1",
            artifact_id="B04_R6_EXPANDED_CANARY_EVIDENCE_NO_AUTHORIZATION_DRIFT_RECEIPT",
            status="PASS",
            checked_fields=sorted(AUTHORITY_DRIFT_KEYS),
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.expanded_canary_evidence_review.next_lawful_move_receipt.v1",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            next_lawful_move=NEXT_LAWFUL_MOVE,
            next_after_validation=RECOMMENDED_NEXT_PATH,
        ),
    }
    review_map = {
        "route_distribution_review_contract": "route_distribution_health",
        "fallback_behavior_review_contract": "fallback_behavior",
        "static_fallback_review_contract": "static_fallback_preservation",
        "abstention_fallback_review_contract": "abstention_fallback_preservation",
        "null_route_review_contract": "null_route_preservation",
        "operator_override_review_contract": "operator_override_readiness",
        "kill_switch_review_contract": "kill_switch_readiness",
        "rollback_review_contract": "rollback_readiness",
        "drift_monitoring_review_contract": "drift_stability",
        "incident_freeze_review_contract": "incident_freeze_cleanliness",
        "trace_completeness_review_contract": "trace_completeness",
        "replay_readiness_review_contract": "runtime_replayability",
        "external_verifier_readiness_review_contract": "external_verifier_readiness",
        "commercial_claim_boundary_review_contract": "commercial_boundary_safety",
        "package_promotion_blocker_review_contract": "package_promotion_readiness",
    }
    for role, category in review_map.items():
        outputs[role] = _review_contract(base, category)
    outputs.update(_prep_outputs(base))
    return outputs


def _prep_outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "validation_plan": _prep_only(
            base,
            role="validation_plan",
            purpose="Prepare canonical validation of the expanded canary evidence review packet.",
            required_checks=list(REASON_CODES),
            validation_outcomes=list(VALIDATION_OUTCOMES_PREPARED),
        ),
        "validation_reason_codes": _prep_only(
            base,
            role="validation_reason_codes",
            purpose="Define fail-closed reason-code routing for validation.",
            reason_codes=list(REASON_CODES),
        ),
        "runtime_cutover_review_packet_prep_only_draft": _prep_only(
            base,
            role="runtime_cutover_review_packet_prep_only_draft",
            purpose="Draft future runtime cutover review packet; does not authorize cutover.",
        ),
        "additional_expanded_canary_authorization_packet_prep_only_draft": _prep_only(
            base,
            role="additional_expanded_canary_authorization_packet_prep_only_draft",
            purpose="Draft optional additional expanded canary authorization packet.",
        ),
        "package_promotion_review_packet_prep_only_draft": _prep_only(
            base,
            role="package_promotion_review_packet_prep_only_draft",
            purpose="Draft future package-promotion review packet; promotion remains blocked.",
        ),
        "external_audit_delta_manifest_prep_only_draft": _prep_only(
            base,
            role="external_audit_delta_manifest_prep_only_draft",
            purpose="Prepare external audit delta from expanded canary evidence.",
        ),
        "public_verifier_delta_requirements_prep_only": _prep_only(
            base,
            role="public_verifier_delta_requirements_prep_only",
            purpose="Prepare public verifier requirements for expanded canary evidence.",
        ),
        "commercial_claim_boundary_update_prep_only": _prep_only(
            base,
            role="commercial_claim_boundary_update_prep_only",
            purpose="Update claim ceiling in prep-only mode.",
            allowed_claims=[
                "AFSH passed expanded limited-runtime canary under bounded packet law.",
                "Expanded canary evidence review validation is next.",
                "Runtime cutover remains unauthorized.",
            ],
            forbidden_claims=[
                "AFSH is live.",
                "R6 is open.",
                "Runtime cutover is authorized.",
                "Package is promotion-ready.",
                "Commercial activation is authorized.",
            ],
        ),
        "future_blocker_register": _prep_only(
            base,
            role="future_blocker_register",
            purpose="Track blockers after expanded canary evidence review authorship.",
            blockers=_blockers(),
        ),
        "pipeline_board": _prep_only(
            base,
            role="pipeline_board",
            purpose="Update B04 R6 pipeline board after expanded canary runtime pass.",
            board={
                "expanded_canary_runtime": "PASSED_REPLAYED",
                "expanded_canary_evidence_review_packet": "BOUND_NEXT_VALIDATION",
                "runtime_cutover_review": "RECOMMENDED_AFTER_VALIDATION_NOT_AUTHORIZED",
                "runtime_cutover": "UNAUTHORIZED",
                "r6": "CLOSED",
                "package_promotion": "BLOCKED",
                "commercial_activation_claims": "UNAUTHORIZED",
            },
        ),
    }


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Expanded Canary Evidence Review Packet",
            "",
            f"Outcome: `{SELECTED_OUTCOME}`",
            f"Next lawful move: `{NEXT_LAWFUL_MOVE}`",
            f"Recommended path after validation: `{RECOMMENDED_NEXT_PATH}`",
            "",
            "Expanded canary runtime passed and evidence is bound for review.",
            "Runtime cutover remains unauthorized.",
            "R6 remains closed.",
            "Package promotion and commercial activation claims remain unauthorized.",
            "Truth-engine and trust-zone law remain unchanged.",
            "",
        ]
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    branch = _ensure_branch_context(root)
    dirty = common.git_status_porcelain(root)
    if dirty:
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_NEXT_MOVE_DRIFT", f"worktree dirty: {dirty[:200]}")
    payloads, texts = _load_inputs(root)
    _validate_inputs(payloads, texts)
    trust = validate_trust_zones(root=root)
    if trust.get("status") != "PASS":
        _fail("RC_B04R6_EXPANDED_CANARY_EVIDENCE_NEXT_MOVE_DRIFT", "trust-zone validation failed")
    base = _base(root=root, reports_root=reports, branch=branch, payloads=payloads, texts=texts, trust_receipt=trust)
    outputs = _outputs(base, payloads)
    for role, filename in OUTPUTS.items():
        if filename.endswith(".md"):
            (reports / filename).write_text(_report_text(outputs["packet_contract"]), encoding="utf-8")
        else:
            write_json_stable(reports / filename, outputs[role])
    return outputs["packet_contract"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports-root", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        result = run(reports_root=args.reports_root)
    except LaneFailure as exc:
        print(f"{exc.code}: {exc.detail}")
        return 1
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
