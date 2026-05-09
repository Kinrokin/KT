from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable


AUTHORITY_BRANCH = "authoritative/b04-r6-expanded-canary-authorization-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-expanded-canary-authorization-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET"
PREDECESSOR_OUTCOME = "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATED__EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT"
PREDECESSOR_NEXT_MOVE = "AUTHOR_B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET"
SELECTED_OUTCOME = (
    "B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET_BOUND__"
    "EXPANDED_CANARY_AUTHORIZATION_VALIDATION_NEXT"
)
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET"

VALIDATION_SUCCESS_OUTCOME = (
    "B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET_VALIDATED__"
    "EXPANDED_CANARY_EXECUTION_PACKET_NEXT"
)
VALIDATION_SUCCESS_NEXT_MOVE = "AUTHOR_B04_R6_EXPANDED_CANARY_EXECUTION_PACKET"

FORBIDDEN_ACTIONS = (
    "EXPANDED_CANARY_RUNTIME_EXECUTED",
    "EXPANDED_CANARY_RUNTIME_AUTHORIZED",
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
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_VALIDATED_EVIDENCE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_DECISION_MATRIX_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_READINESS_MATRIX_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_SCOPE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_SAMPLE_LIMIT_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_ALLOWED_CASE_CLASSES_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_EXCLUDED_CASE_CLASSES_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_FALLBACK_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_OPERATOR_CONTROL_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_KILL_SWITCH_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_ROLLBACK_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_DRIFT_THRESHOLD_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_INCIDENT_FREEZE_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_RECEIPT_SCHEMA_MISSING",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_PREP_ONLY_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_RUNTIME_AUTHORIZED",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_RUNTIME_CUTOVER_AUTHORIZED",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_R6_OPEN_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_PACKAGE_PROMOTION_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_NEXT_MOVE_DRIFT",
)

INPUTS = {
    "canary_evidence_review_validation_receipt": "b04_r6_canary_evidence_review_validation_receipt.json",
    "canary_evidence_scorecard": "b04_r6_canary_evidence_scorecard.json",
    "post_canary_decision_matrix": "b04_r6_canary_post_run_decision_matrix.json",
    "post_canary_blocker_ledger": "b04_r6_post_canary_blocker_ledger.json",
    "expanded_canary_readiness_matrix": "b04_r6_expanded_canary_readiness_matrix.json",
    "canary_result": "b04_r6_limited_runtime_canary_result.json",
    "canary_case_manifest": "b04_r6_canary_case_manifest.json",
    "canary_route_distribution_receipt": "b04_r6_canary_route_distribution_receipt.json",
    "canary_fallback_behavior_receipt": "b04_r6_canary_fallback_behavior_receipt.json",
    "canary_trace_completeness_receipt": "b04_r6_canary_trace_completeness_receipt.json",
    "campaign_order_validation_receipt": "kt_e2e_closure_campaign_order_validation_receipt.json",
    "current_next_lawful_move": "kt_next_lawful_move_receipt.json",
}

OUTPUTS = {
    "packet_contract": "b04_r6_expanded_canary_authorization_packet_contract.json",
    "packet_receipt": "b04_r6_expanded_canary_authorization_packet_receipt.json",
    "packet_report": "b04_r6_expanded_canary_authorization_packet_report.md",
    "scope_manifest": "b04_r6_expanded_canary_scope_manifest.json",
    "allowed_case_class_contract": "b04_r6_expanded_canary_allowed_case_class_contract.json",
    "excluded_case_class_contract": "b04_r6_expanded_canary_excluded_case_class_contract.json",
    "sample_limit_contract": "b04_r6_expanded_canary_sample_limit_contract.json",
    "static_fallback_contract": "b04_r6_expanded_canary_static_fallback_contract.json",
    "abstention_fallback_contract": "b04_r6_expanded_canary_abstention_fallback_contract.json",
    "null_route_preservation_contract": "b04_r6_expanded_canary_null_route_preservation_contract.json",
    "operator_override_contract": "b04_r6_expanded_canary_operator_override_contract.json",
    "kill_switch_contract": "b04_r6_expanded_canary_kill_switch_contract.json",
    "rollback_contract": "b04_r6_expanded_canary_rollback_contract.json",
    "route_distribution_health_thresholds": "b04_r6_expanded_canary_route_distribution_health_thresholds.json",
    "drift_thresholds": "b04_r6_expanded_canary_drift_thresholds.json",
    "incident_freeze_contract": "b04_r6_expanded_canary_incident_freeze_contract.json",
    "runtime_receipt_schema": "b04_r6_expanded_canary_runtime_receipt_schema.json",
    "external_verifier_requirements": "b04_r6_expanded_canary_external_verifier_requirements.json",
    "commercial_claim_boundary": "b04_r6_expanded_canary_commercial_claim_boundary.json",
    "package_promotion_prohibition_receipt": "b04_r6_expanded_canary_package_promotion_prohibition_receipt.json",
    "no_authorization_drift_receipt": "b04_r6_expanded_canary_no_authorization_drift_receipt.json",
    "validation_plan": "b04_r6_expanded_canary_authorization_validation_plan.json",
    "validation_reason_codes": "b04_r6_expanded_canary_authorization_validation_reason_codes.json",
    "execution_packet_prep_only_draft": "b04_r6_expanded_canary_execution_packet_prep_only_draft.json",
    "execution_validation_plan_prep_only": "b04_r6_expanded_canary_execution_validation_plan_prep_only.json",
    "evidence_review_packet_prep_only_draft": "b04_r6_expanded_canary_evidence_review_packet_prep_only_draft.json",
    "external_audit_delta_manifest_prep_only": "b04_r6_external_audit_delta_manifest_prep_only_draft.json",
    "package_promotion_review_preconditions_prep_only": "b04_r6_package_promotion_review_preconditions_prep_only_draft.json",
    "future_blocker_register": "b04_r6_future_blocker_register.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "next_lawful_move": "b04_r6_next_lawful_move_receipt.json",
}

PREP_ONLY_ROLES = (
    "execution_packet_prep_only_draft",
    "execution_validation_plan_prep_only",
    "evidence_review_packet_prep_only_draft",
    "external_audit_delta_manifest_prep_only",
    "package_promotion_review_preconditions_prep_only",
)

CONTRACT_ROLES = (
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


def _fail(code: str, detail: str) -> None:
    raise RuntimeError(f"FAIL_CLOSED: {code}: {detail}")


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch not in ALLOWED_BRANCHES and not branch.startswith(REPLAY_BRANCH_PREFIX):
        allowed = ", ".join(sorted([*ALLOWED_BRANCHES, f"{REPLAY_BRANCH_PREFIX}*"]))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}; got: {branch}")
    if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
        raise RuntimeError("FAIL_CLOSED: main replay requires local main to equal origin/main")
    return branch


def _load_inputs(reports_root: Path) -> Dict[str, Dict[str, Any]]:
    payloads: Dict[str, Dict[str, Any]] = {}
    for role, filename in INPUTS.items():
        path = reports_root / filename
        if not path.exists():
            _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_VALIDATED_EVIDENCE_MISSING", f"missing {filename}")
        payload = common.load_json_required(reports_root.parent.parent, f"KT_PROD_CLEANROOM/reports/{filename}", label=role)
        if not isinstance(payload, dict):
            _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_VALIDATED_EVIDENCE_MISSING", f"{filename} must be object")
        payloads[role] = payload
    return payloads


def _walk_dicts(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


def _validate_inputs(payloads: Dict[str, Dict[str, Any]]) -> None:
    validation = payloads["canary_evidence_review_validation_receipt"]
    if validation.get("selected_outcome") != PREDECESSOR_OUTCOME:
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_VALIDATED_EVIDENCE_MISSING", "canary evidence validation outcome drifted")
    if validation.get("next_lawful_move") != PREDECESSOR_NEXT_MOVE:
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_NEXT_MOVE_DRIFT", "canary evidence validation next move drifted")

    current_next = payloads["current_next_lawful_move"]
    if current_next.get("selected_outcome") != (
        "KT_E2E_CLOSURE_ADAPTIVE_RATIFICATION_AND_7B_AMPLIFICATION_BENCHMARK_ORDER_VALIDATED__"
        "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT"
    ):
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_NEXT_MOVE_DRIFT", "campaign validation outcome not current")
    if current_next.get("next_lawful_move") != PREDECESSOR_NEXT_MOVE:
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_NEXT_MOVE_DRIFT", "current next lawful move is not this authoring lane")

    decision_payload = payloads["post_canary_decision_matrix"]
    decision = decision_payload.get("decision_matrix", decision_payload)
    if decision.get("recommended_next_path") != "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT":
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_DECISION_MATRIX_DRIFT", "decision matrix did not select expanded canary")
    if decision.get("runtime_cutover_review_ready") is not False or decision.get("package_promotion_ready") is not False:
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_DECISION_MATRIX_DRIFT", "decision matrix widened authority")

    readiness = payloads["expanded_canary_readiness_matrix"]
    if readiness.get("decision_matrix", {}).get("expanded_canary_ready") is not True:
        _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_READINESS_MATRIX_DRIFT", "expanded canary readiness is not true")

    for role, payload in payloads.items():
        for nested in _walk_dicts(payload):
            if nested.get("runtime_cutover_authorized") is True:
                _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_RUNTIME_CUTOVER_AUTHORIZED", f"{role} authorizes cutover")
            if nested.get("r6_open") is True:
                _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_R6_OPEN_DRIFT", f"{role} opens R6")
            if nested.get("package_promotion_authorized") is True:
                _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_PACKAGE_PROMOTION_DRIFT", f"{role} promotes package")
            if nested.get("commercial_activation_claim_authorized") is True:
                _fail("RC_B04R6_EXPANDED_CANARY_AUTH_PACKET_COMMERCIAL_CLAIM_DRIFT", f"{role} authorizes commercial claim")


def _binding_hashes(reports_root: Path) -> Dict[str, str]:
    return {f"{role}_hash": file_sha256(reports_root / filename) for role, filename in INPUTS.items()}


def _guard() -> Dict[str, Any]:
    return {
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
        "expanded_canary_runtime_authorized": False,
        "expanded_canary_runtime_executed": False,
        "expanded_canary_execution_packet_authored": False,
        "expanded_canary_execution_packet_validated": False,
    }


def _prep_guard() -> Dict[str, Any]:
    return {
        "authority": "PREP_ONLY",
        "cannot_authorize_runtime_cutover": True,
        "cannot_open_r6": True,
        "cannot_authorize_lobe_escalation": True,
        "cannot_authorize_package_promotion": True,
        "cannot_authorize_commercial_activation_claims": True,
        "cannot_mutate_truth_engine_law": True,
        "cannot_mutate_trust_zone_law": True,
        "cannot_authorize_expanded_canary_execution": True,
    }


def _base(
    *,
    artifact_id: str,
    branch: str,
    head: str,
    current_main_head: str,
    generated_utc: str,
    bindings: Dict[str, str],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.b04_r6.expanded_canary_authorization_packet.v1",
        "artifact_id": artifact_id,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": "B04_R6_CANARY_EVIDENCE_REVIEW_PACKET_VALIDATION",
        "predecessor_outcome": PREDECESSOR_OUTCOME,
        "previous_next_lawful_move": PREDECESSOR_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "current_branch": branch,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "generated_utc": generated_utc,
        "binding_hashes": bindings,
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "expanded_canary_authorization_packet_authored": True,
        "expanded_canary_authorization_packet_validated": False,
        **_guard(),
    }


def _contract_detail(role: str) -> Dict[str, Any]:
    details: Dict[str, Any] = {
        "scope_manifest": {
            "scope_status": "EXPANDED_CANARY_SCOPE_DEFINED_NOT_EXECUTING",
            "global_r6_scope_allowed": False,
            "runtime_cutover_allowed": False,
            "max_case_count_per_window": 36,
            "max_window_minutes": 120,
            "operator_observed": True,
        },
        "allowed_case_class_contract": {
            "allowed_case_classes": [
                "ROUTE_ELIGIBLE_LOW_RISK_CANARY_CONFIRMED",
                "STATIC_FALLBACK_AVAILABLE_EXPANDED_ROUTE_CHECK",
                "NON_COMMERCIAL_OPERATOR_OBSERVED_EXPANDED_SAMPLE",
                "PRIOR_CANARY_COVERED_CASE_CLASS_EXTENSION",
            ],
        },
        "excluded_case_class_contract": {
            "excluded_case_classes": [
                "GLOBAL_R6_TRAFFIC",
                "RUNTIME_CUTOVER_SURFACE",
                "NULL_ROUTE_CONTROL",
                "COMMERCIAL_ACTIVATION_SURFACE",
                "PACKAGE_PROMOTION_SURFACE",
            ],
        },
        "sample_limit_contract": {
            "sample_limit_defined": True,
            "max_cases": 36,
            "max_route_observations": 24,
            "requires_operator_observation": True,
            "may_not_expand_without_validation": True,
        },
        "static_fallback_contract": {"static_fallback_required": True, "static_remains_fallback_authority": True},
        "abstention_fallback_contract": {"abstention_fallback_required": True},
        "null_route_preservation_contract": {"null_route_controls_excluded": True, "null_route_preservation_required": True},
        "operator_override_contract": {"operator_override_required": True, "operator_override_may_freeze_run": True},
        "kill_switch_contract": {"kill_switch_required": True, "kill_switch_invocation_freezes_expanded_canary": True},
        "rollback_contract": {"rollback_required": True, "rollback_to_prior_static_authority": True},
        "route_distribution_health_thresholds": {
            "route_distribution_thresholds_defined": True,
            "max_unknown_route_rate": 0.0,
            "max_static_fallback_rate": 0.6,
        },
        "drift_thresholds": {"drift_thresholds_defined": True, "max_drift_signal_count": 0},
        "incident_freeze_contract": {
            "incident_freeze_conditions_defined": True,
            "freeze_on_any_user_facing_authority_drift": True,
            "freeze_on_any_commercial_claim_drift": True,
        },
        "runtime_receipt_schema": {
            "runtime_receipt_schema_defined": True,
            "required_receipts": [
                "case_manifest",
                "route_distribution",
                "fallback_behavior",
                "operator_control",
                "kill_switch",
                "rollback",
                "drift_monitoring",
                "incident_freeze",
                "trace_completeness",
                "replay",
                "no_authorization_drift",
            ],
        },
        "external_verifier_requirements": {"external_verifier_required": True, "replay_bundle_required": True},
        "commercial_claim_boundary": {
            "commercial_claim_status": "BOUNDARY_ONLY",
            "allowed_claim": "B04 R6 completed bounded canary evidence review and may author expanded canary authorization.",
            "forbidden_claims": [
                "AFSH is live",
                "R6 is open",
                "runtime cutover is authorized",
                "package promotion is authorized",
                "commercial activation is authorized",
            ],
        },
        "package_promotion_prohibition_receipt": {
            "package_promotion_authorized": False,
            "package_promotion_requires_future_review": True,
        },
    }
    return details[role]


def _write_report(path: Path, *, current_main_head: str) -> None:
    path.write_text(
        "\n".join(
            [
                "# B04 R6 Expanded Canary Authorization Packet",
                "",
                f"Outcome: {SELECTED_OUTCOME}",
                "",
                f"Current main: {current_main_head}",
                "",
                f"Next lawful move: {NEXT_LAWFUL_MOVE}",
                "",
                "This packet authors expanded-canary authorization terms only. It does not execute expanded canary, authorize runtime cutover, open R6, promote package, authorize commercial activation claims, activate lobes, authorize GPU training, or mutate truth/trust law.",
                "",
            ]
        ),
        encoding="utf-8",
        newline="\n",
    )


def _write_outputs(
    reports_root: Path,
    *,
    branch: str,
    head: str,
    current_main_head: str,
    generated_utc: str,
    payloads: Dict[str, Dict[str, Any]],
    bindings: Dict[str, str],
) -> None:
    scorecard_payload = payloads["canary_evidence_scorecard"]
    scorecard = scorecard_payload.get("scorecard", scorecard_payload)
    decision_payload = payloads["post_canary_decision_matrix"]
    decision = decision_payload.get("decision_matrix", decision_payload)
    readiness = payloads["expanded_canary_readiness_matrix"]
    common_base = _base(
        artifact_id="B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET",
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        generated_utc=generated_utc,
        bindings=bindings,
    )
    packet = {
        **common_base,
        "may_authorize": ["EXPANDED_CANARY_AUTHORIZATION_PACKET_AUTHORED"],
        "recommended_next_path_validated": "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT",
        "canary_evidence_overall_grade": scorecard.get("overall_grade"),
        "decision_matrix": decision,
        "expanded_canary_readiness": readiness.get("decision_matrix", {}),
        "validation_success_outcome": VALIDATION_SUCCESS_OUTCOME,
        "validation_success_next_lawful_move": VALIDATION_SUCCESS_NEXT_MOVE,
    }
    write_json_stable(reports_root / OUTPUTS["packet_contract"], packet)
    write_json_stable(
        reports_root / OUTPUTS["packet_receipt"],
        {
            **packet,
            "artifact_id": "B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET_RECEIPT",
            "receipt_role": "packet_authored",
        },
    )

    for role in CONTRACT_ROLES:
        write_json_stable(
            reports_root / OUTPUTS[role],
            {
                **common_base,
                "artifact_id": role.upper(),
                "contract_status": "BOUND_NON_EXECUTING",
                "details": _contract_detail(role),
            },
        )

    write_json_stable(
        reports_root / OUTPUTS["no_authorization_drift_receipt"],
        {
            **common_base,
            "artifact_id": "B04_R6_EXPANDED_CANARY_NO_AUTHORIZATION_DRIFT_RECEIPT",
            "no_authorization_drift": True,
        },
    )
    write_json_stable(
        reports_root / OUTPUTS["validation_plan"],
        {
            **common_base,
            "artifact_id": "B04_R6_EXPANDED_CANARY_AUTHORIZATION_VALIDATION_PLAN",
            "validation_lane": NEXT_LAWFUL_MOVE,
            "expected_success_outcome": VALIDATION_SUCCESS_OUTCOME,
            "expected_success_next_lawful_move": VALIDATION_SUCCESS_NEXT_MOVE,
            "checks": list(REASON_CODES),
        },
    )
    write_json_stable(
        reports_root / OUTPUTS["validation_reason_codes"],
        {
            **common_base,
            "artifact_id": "B04_R6_EXPANDED_CANARY_AUTHORIZATION_VALIDATION_REASON_CODES",
            "reason_codes": list(REASON_CODES),
        },
    )
    for role in PREP_ONLY_ROLES:
        write_json_stable(
            reports_root / OUTPUTS[role],
            {
                **_prep_guard(),
                "schema_id": "kt.b04_r6.expanded_canary_authorization.prep_only.v1",
                "artifact_id": role.upper(),
                "predecessor_outcome": SELECTED_OUTCOME,
                "next_lawful_move": NEXT_LAWFUL_MOVE,
                "purpose": f"Prep-only scaffold for {role}.",
                **_guard(),
            },
        )
    write_json_stable(
        reports_root / OUTPUTS["future_blocker_register"],
        {
            **common_base,
            "artifact_id": "B04_R6_FUTURE_BLOCKER_REGISTER",
            "blockers": [
                {
                    "blocker_id": "B04R6-EXP-CANARY-AUTH-001",
                    "category": "expanded_canary_execution",
                    "status": "OPEN",
                    "blocks": ["EXPANDED_CANARY_EXECUTION_PACKET"],
                    "required_next_artifact": "VALIDATE_B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET",
                },
                {
                    "blocker_id": "B04R6-EXP-CANARY-AUTH-002",
                    "category": "runtime_cutover",
                    "status": "OPEN",
                    "blocks": ["RUNTIME_CUTOVER_REVIEW_PACKET"],
                    "required_next_artifact": "expanded canary execution and evidence review remain incomplete",
                },
            ],
        },
    )
    write_json_stable(
        reports_root / OUTPUTS["pipeline_board"],
        {
            **common_base,
            "artifact_id": "B04_R6_PIPELINE_BOARD",
            "pipeline_state": {
                "canary_evidence_review": "VALIDATED",
                "expanded_canary_authorization_packet": "BOUND",
                "expanded_canary_authorization_validation": "NEXT",
                "expanded_canary_execution": "BLOCKED",
                "runtime_cutover": "BLOCKED",
                "r6_open": "BLOCKED",
                "package_promotion": "BLOCKED",
                "commercial_activation_claims": "BLOCKED",
            },
        },
    )
    write_json_stable(
        reports_root / OUTPUTS["next_lawful_move"],
        {
            **common_base,
            "artifact_id": "B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            "receipt_type": "NEXT_LAWFUL_MOVE",
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
    )
    _write_report(reports_root / OUTPUTS["packet_report"], current_main_head=current_main_head)


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    branch = _ensure_branch_context(root)
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads = _load_inputs(reports_root)
    _validate_inputs(payloads)
    bindings = _binding_hashes(reports_root)
    generated_utc = utc_now_iso_z()
    _write_outputs(
        reports_root,
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        generated_utc=generated_utc,
        payloads=payloads,
        bindings=bindings,
    )
    return common.load_json_required(
        root,
        f"KT_PROD_CLEANROOM/reports/{OUTPUTS['packet_receipt']}",
        label="expanded_canary_authorization_packet_receipt",
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Author the B04 R6 expanded-canary authorization packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
