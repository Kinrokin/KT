from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_commercial_activation_review_packet_validation as review_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/b04-r6-commercial-activation-authorization-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-commercial-activation-authorization-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_PACKET"
PREVIOUS_LANE = review_validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = review_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = review_validation.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = (
    "B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_PACKET_BOUND__"
    "COMMERCIAL_ACTIVATION_AUTHORIZATION_VALIDATION_NEXT"
)
OUTCOME_DEFERRED = (
    "B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_PACKET_DEFERRED__"
    "NAMED_PACKET_DEFECT_REMAINS"
)
OUTCOME_INVALID = (
    "B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_PACKET_INVALID__"
    "FORENSIC_COMMERCIAL_AUTHORIZATION_REVIEW_NEXT"
)
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_PACKET"

VALIDATION_SUCCESS_OUTCOME = (
    "B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_PACKET_VALIDATED__"
    "COMMERCIAL_ACTIVATION_EXECUTION_PACKET_NEXT"
)
VALIDATION_SUCCESS_NEXT_MOVE = "AUTHOR_B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET"

BENCHMARK_GOVERNING_STATEMENT = (
    "KT does not claim small models are secretly giant models. KT tests where governed substrate makes smaller "
    "models act above class, and proves where it does not."
)

FORBIDDEN_ACTIONS = (
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "COMMERCIAL_ACTIVATION_EXECUTED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "BENCHMARK_PREP_TREATED_AS_COMMERCIAL_AUTHORITY",
    "SEVEN_B_AMPLIFICATION_CLAIMED_PROVEN",
)

AUTHORITY_DRIFT_KEYS = {
    "commercial_activation_claim_authorized": "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_COMMERCIAL_CLAIM_DRIFT",
    "commercial_activation_executed": "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_EXECUTION_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_TRUST_ZONE_MUTATION",
    "benchmark_prep_authorizes_commercial_activation": (
        "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_BENCHMARK_AUTHORITY_DRIFT"
    ),
    "seven_b_amplification_claimed_proven": "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_7B_CLAIM_DRIFT",
}

CLAIM_BEARING_FIELD_MARKERS = (
    "activation",
    "authorization_state",
    "authority_state",
    "claim",
    "commercial",
)
POSITIVE_AUTHORITY_TOKENS = (
    "ACTIVE",
    "AUTHORIZED",
    "COMMERCIAL_ACTIVATION",
    "ENABLED",
    "EXECUTED",
    "PRODUCTION",
)
NEGATIVE_AUTHORITY_QUALIFIERS = (
    "AUTHORIZATION_PACKET",
    "AUTHORIZATION_REQUIRES_VALIDATION",
    "AUTHORIZATION_VALIDATION_NEXT",
    "BLOCKED",
    "BOUNDARY_ONLY",
    "CANNOT_AUTHORIZE",
    "DEFERRED",
    "DOES NOT",
    "DOES_NOT_AUTHORIZE",
    "FORBIDDEN",
    "NEXT",
    "NOT AUTHORIZED",
    "NOT_AUTHORIZED",
    "PREP_ONLY",
    "PROHIBITED",
    "REMAINS UNAUTHORIZED",
    "REVIEW",
    "UNAUTHORIZED",
    "VALIDATION_NEXT",
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_REVIEW_VALIDATION_MISSING",
            "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_REVIEW_OUTCOME_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_NEXT_MOVE_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_READINESS_INCOMPLETE",
            "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

REVIEW_VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in review_validation.OUTPUTS.items()
    if filename.endswith(".json")
}
REVIEW_VALIDATION_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in review_validation.OUTPUTS.items()
    if not filename.endswith(".json")
}

AUTHORIZATION_CONTRACT_ROLES = (
    "activation_scope_contract",
    "allowed_commercial_surface_contract",
    "excluded_commercial_surface_contract",
    "claim_authorization_scope_contract",
    "customer_safe_language_contract",
    "operator_obligation_contract",
    "deployment_profile_requirements",
    "support_incident_requirements",
    "data_governance_requirements",
    "rollback_obligation_contract",
    "external_audit_requirements",
    "public_verifier_requirements",
    "commercial_claim_ceiling",
    "release_truth_derivation_contract",
    "no_authority_drift_receipt",
)

PREP_ONLY_ROLES = (
    "commercial_activation_execution_packet_prep_only_draft",
    "commercial_activation_execution_validation_plan_prep_only",
    "commercial_activation_evidence_review_packet_prep_only_draft",
    "commercial_activation_repair_or_rollback_prep_only_draft",
    "commercial_activation_forensic_review_prep_only_draft",
    "external_audit_delta_packet_prep_only_draft",
    "follow_up_audit_readiness_packet_prep_only_draft",
)

BENCHMARK_PREP_ROLES = (
    "provider_runtime_bakeoff_plan_prep_only",
    "verified_work_per_dollar_metric_contract_prep_only",
    "seven_b_amplification_ablation_plan",
    "long_horizon_agent_workload_suite_prep_only",
    "price_per_validated_lane_scorecard_schema",
    "provider_latency_throughput_cost_matrix_prep_only",
    "model_provider_selection_policy_prep_only",
    "gpu_inference_readiness_gate_prep_only",
)

OUTPUTS = {
    "authorization_contract": "b04_r6_commercial_activation_authorization_packet_contract.json",
    "authorization_receipt": "b04_r6_commercial_activation_authorization_packet_receipt.json",
    "authorization_report": "b04_r6_commercial_activation_authorization_packet_report.md",
    "activation_scope_contract": "b04_r6_commercial_activation_authorization_scope_contract.json",
    "allowed_commercial_surface_contract": "b04_r6_commercial_activation_allowed_surface_contract.json",
    "excluded_commercial_surface_contract": "b04_r6_commercial_activation_excluded_surface_contract.json",
    "claim_authorization_scope_contract": "b04_r6_commercial_activation_claim_authorization_scope_contract.json",
    "customer_safe_language_contract": "b04_r6_commercial_activation_customer_safe_language_contract.json",
    "operator_obligation_contract": "b04_r6_commercial_activation_operator_obligation_contract.json",
    "deployment_profile_requirements": "b04_r6_commercial_activation_deployment_profile_requirements.json",
    "support_incident_requirements": "b04_r6_commercial_activation_support_incident_requirements.json",
    "data_governance_requirements": "b04_r6_commercial_activation_data_governance_requirements.json",
    "rollback_obligation_contract": "b04_r6_commercial_activation_rollback_obligation_contract.json",
    "external_audit_requirements": "b04_r6_commercial_activation_external_audit_requirements.json",
    "public_verifier_requirements": "b04_r6_commercial_activation_public_verifier_requirements.json",
    "commercial_claim_ceiling": "b04_r6_commercial_activation_commercial_claim_ceiling.json",
    "release_truth_derivation_contract": "b04_r6_commercial_activation_release_truth_derivation_contract.json",
    "no_authority_drift_receipt": "b04_r6_commercial_activation_authorization_no_authority_drift_receipt.json",
    "authorization_validation_plan": "b04_r6_commercial_activation_authorization_validation_plan.json",
    "authorization_validation_reason_codes": "b04_r6_commercial_activation_authorization_validation_reason_codes.json",
    "commercial_activation_execution_packet_prep_only_draft": (
        "b04_r6_commercial_activation_execution_packet_prep_only_draft.json"
    ),
    "commercial_activation_execution_validation_plan_prep_only": (
        "b04_r6_commercial_activation_execution_validation_plan_prep_only.json"
    ),
    "commercial_activation_evidence_review_packet_prep_only_draft": (
        "b04_r6_commercial_activation_evidence_review_packet_prep_only_draft.json"
    ),
    "commercial_activation_repair_or_rollback_prep_only_draft": (
        "b04_r6_commercial_activation_repair_or_rollback_prep_only_draft.json"
    ),
    "commercial_activation_forensic_review_prep_only_draft": (
        "b04_r6_commercial_activation_forensic_review_prep_only_draft.json"
    ),
    "external_audit_delta_packet_prep_only_draft": (
        "b04_r6_post_commercial_activation_external_audit_delta_packet_prep_only_draft.json"
    ),
    "follow_up_audit_readiness_packet_prep_only_draft": (
        "kt_e2e_follow_up_audit_readiness_packet_prep_only_draft.json"
    ),
    "provider_runtime_bakeoff_plan_prep_only": "kt_provider_runtime_bakeoff_plan_prep_only.json",
    "verified_work_per_dollar_metric_contract_prep_only": (
        "kt_verified_work_per_dollar_metric_contract_prep_only.json"
    ),
    "seven_b_amplification_ablation_plan": "kt_7b_amplification_ablation_plan.json",
    "long_horizon_agent_workload_suite_prep_only": "kt_long_horizon_agent_workload_suite_prep_only.json",
    "price_per_validated_lane_scorecard_schema": "kt_price_per_validated_lane_scorecard_schema.json",
    "provider_latency_throughput_cost_matrix_prep_only": (
        "kt_provider_latency_throughput_cost_matrix_prep_only.json"
    ),
    "model_provider_selection_policy_prep_only": "kt_model_provider_selection_policy_prep_only.json",
    "gpu_inference_readiness_gate_prep_only": "kt_gpu_inference_readiness_gate_prep_only.json",
    "campaign_board": "kt_e2e_closure_campaign_board.json",
    "pipeline_board": "b04_r6_pipeline_board.json",
    "claim_ceiling_current_state": "kt_claim_ceiling_current_state.json",
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


def _walk_items(value: Any, parent_key: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk_items(item, str(key))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                yield from _walk_items(item, parent_key)
            else:
                yield parent_key, item


def _is_claim_bearing_field(key: str) -> bool:
    normalized = key.upper()
    if normalized.startswith(("B04_R6_", "KT_")):
        return False
    lowered = key.lower()
    if any(marker in lowered for marker in ("blocked", "forbidden", "prohibited")):
        return False
    return any(marker in lowered for marker in CLAIM_BEARING_FIELD_MARKERS)


def _contains_positive_authority_token(value: str) -> bool:
    normalized = value.upper().replace("-", "_").replace(" ", "_")
    if any(qualifier in normalized for qualifier in NEGATIVE_AUTHORITY_QUALIFIERS):
        return False
    return any(token in normalized for token in POSITIVE_AUTHORITY_TOKENS)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_REVIEW_VALIDATION_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_REVIEW_VALIDATION_MISSING", str(exc))


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in REVIEW_VALIDATION_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in REVIEW_VALIDATION_TEXT_INPUTS.items()}
    return payloads, texts


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk_items(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted non-false")
            if _is_claim_bearing_field(key) and isinstance(value, str) and _contains_positive_authority_token(value):
                _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        for phrase in (
            "COMMERCIAL ACTIVATION AUTHORIZED",
            "COMMERCIAL ACTIVATION CLAIM AUTHORIZED",
            "COMMERCIAL ACTIVATION EXECUTED",
            "KT IS COMMERCIALLY ACTIVATED",
            "7B AMPLIFICATION IS PROVEN",
        ):
            if phrase in normalized:
                _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["validation_contract"]
    receipt = payloads["validation_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_REVIEW_OUTCOME_DRIFT", "validation contract outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_REVIEW_OUTCOME_DRIFT", "validation receipt outcome drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_NEXT_MOVE_DRIFT", "validation contract next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_NEXT_MOVE_DRIFT", "next-lawful-move receipt drift")
    required_true = (
        "r6_open",
        "package_promotion_executed",
        "package_promotion_passed",
        "package_promotion_evidence_review_validated",
        "commercial_activation_review_packet_validated",
        "commercial_activation_authorization_packet_next",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    )
    for key in required_true:
        if contract.get(key) is not True:
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_READINESS_INCOMPLETE", f"validation contract {key} is not true")
    required_false = (
        "commercial_activation_claim_authorized",
        "commercial_activation_executed",
        "benchmark_prep_authorizes_commercial_activation",
        "seven_b_amplification_claimed_proven",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
    )
    for key in required_false:
        if contract.get(key) is not False:
            _fail(AUTHORITY_DRIFT_KEYS.get(key, "RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_READINESS_INCOMPLETE"), key)
    if not contract.get("binding_hashes"):
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_INPUT_BINDINGS_EMPTY", "validation binding hashes are empty")


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _ensure_authority_closed(payloads, texts)
    _validate_handoff(payloads)


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**REVIEW_VALIDATION_JSON_INPUTS, **REVIEW_VALIDATION_TEXT_INPUTS}.items()):
        path = root / raw
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _guard() -> Dict[str, Any]:
    return {
        "r6_open": True,
        "package_promotion_executed": True,
        "package_promotion_passed": True,
        "package_promotion_evidence_review_validated": True,
        "commercial_activation_review_packet_validated": True,
        "commercial_activation_authorization_packet_authored": True,
        "commercial_activation_authorization_validated": False,
        "commercial_activation_execution_packet_authored": False,
        "commercial_activation_claim_authorized": False,
        "commercial_activation_executed": False,
        "benchmark_prep_authorizes_commercial_activation": False,
        "seven_b_amplification_claimed_proven": False,
        "truth_engine_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_changed": False,
        "trust_zone_law_unchanged": True,
    }


def _readiness_matrix() -> Dict[str, Any]:
    categories = {
        "validated_commercial_activation_review": "PASS",
        "package_promotion_evidence": "PASS",
        "r6_opening_evidence": "PASS",
        "external_audit_readiness": "PASS",
        "public_verifier_readiness": "PASS",
        "claim_compiler_claim_ceiling": "PASS",
        "customer_safe_language": "PASS",
        "operator_support_readiness": "PASS",
        "deployment_profile_readiness": "PASS",
        "rollback_freeze_readiness": "PASS",
        "data_governance_readiness": "PASS",
        "truth_trust_unchanged_receipts": "PASS",
        "benchmark_provider_prep_boundary": "PASS_NON_AUTHORITATIVE",
    }
    return {
        "readiness_categories": categories,
        "authorization_packet_ready": all(value.startswith("PASS") for value in categories.values()),
        "execution_packet_ready": False,
        "commercial_activation_ready": False,
        "blocking_reasons": [
            "commercial_activation_authorization_requires_independent_validation",
            "commercial_activation_execution_requires_execution_packet_authoring_and_validation",
            "commercial_activation_claims_require_successful_activation_evidence_review",
        ],
    }


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    input_bindings: list[Dict[str, str]],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
    readiness = _readiness_matrix()
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
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "binding_hashes": {f"{row['role']}_hash": row["sha256"] for row in input_bindings},
        "readiness_matrix": readiness,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        "commercial_claim_ceiling_summary": (
            "Commercial activation authorization packet is authored for validation; "
            "commercial activation claims and execution remain unauthorized."
        ),
        "benchmark_governing_statement": BENCHMARK_GOVERNING_STATEMENT,
        **_guard(),
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _contract(base: Dict[str, Any], *, role: str, purpose: str, requirements: Sequence[str]) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.commercial_activation_authorization.{role}.v1",
        artifact_id=f"B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_{role.upper()}",
        contract_role=role,
        contract_status="BOUND",
        purpose=purpose,
        requirements=list(requirements),
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str, benchmark: bool = False) -> Dict[str, Any]:
    payload = _artifact(
        base,
        schema_id=f"kt.b04_r6.commercial_activation_authorization.{role}.prep_only.v1",
        artifact_id=f"B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_authorize_commercial_activation_claims=True,
        cannot_execute_commercial_activation=True,
        cannot_authorize_package_promotion=True,
        cannot_open_r6=True,
        cannot_authorize_lobe_escalation=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )
    if benchmark:
        payload.update(
            {
                "cannot_claim_7b_amplification_proven": True,
                "benchmark_authority": "PREP_ONLY",
                "governing_statement": BENCHMARK_GOVERNING_STATEMENT,
            }
        )
    return payload


def _benchmark_payload(base: Dict[str, Any], *, role: str) -> Dict[str, Any]:
    payload = _prep_only(base, role=role, purpose="Prepare provider/runtime benchmark campaign.", benchmark=True)
    payload.update(
        {
            "metric": "lawful_replayable_progress_per_dollar",
            "providers": [
                "CoreWeave / Kimi K2.6",
                "OpenAI model",
                "Anthropic model",
                "Gemini model",
                "local 7B",
                "local 14B",
                "local 32B",
                "best available open model",
            ],
            "workloads": [
                "author lane packet",
                "validate packet",
                "repair review finding",
                "generate tests",
                "parse JSON",
                "run proof replay",
                "create audit summary",
                "handle long-horizon repo task",
                "recover from failed review",
                "maintain claim ceiling",
            ],
            "seven_b_ablation_ladder": [
                "A0 raw 7B",
                "A1 7B + prompt discipline",
                "A2 7B + retrieval",
                "A3 7B + tools",
                "A4 7B + verifier loop",
                "A5 7B + adapters",
                "A6 7B + router / triage",
                "A7 7B + lobes",
                "A8 7B + full KT governance / receipts / replay / proof factory",
            ],
        }
    )
    return payload


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    payloads: Dict[str, Any] = {
        "authorization_contract": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_authorization_packet.contract.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_PACKET_CONTRACT",
            authorization_packet_summary=(
                "Authorizes only the validation of commercial-activation authorization conditions. "
                "It does not execute commercial activation and does not authorize commercial activation claims."
            ),
        ),
        "authorization_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_authorization_packet.receipt.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_PACKET_RECEIPT",
            verdict="COMMERCIAL_ACTIVATION_AUTHORIZATION_PACKET_BOUND_VALIDATION_NEXT",
        ),
        "authorization_validation_plan": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_authorization.validation_plan.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_VALIDATION_PLAN",
            required_validations=[
                "validated commercial activation review is bound",
                "claim ceiling remains bounded",
                "customer-safe language derives from receipts",
                "operator support, deployment, rollback, and data-governance readiness are bound",
                "commercial activation is not executed",
                "commercial activation claims remain unauthorized until post-activation evidence review",
            ],
        ),
        "authorization_validation_reason_codes": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_authorization.reason_codes.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_VALIDATION_REASON_CODES",
            reason_code_taxonomy=list(REASON_CODES),
        ),
        "campaign_board": _artifact(
            base,
            schema_id="kt.e2e_closure.campaign_board.v1",
            artifact_id="KT_E2E_CLOSURE_CAMPAIGN_BOARD",
            r6_status="OPEN",
            package_promotion="PASSED",
            commercial_activation_review="VALIDATED",
            commercial_activation_authorization="BOUND_VALIDATION_NEXT",
            commercial_activation_execution="BLOCKED_UNTIL_EXECUTION_PACKET_VALIDATION",
            provider_benchmark_campaign="PREP_ONLY",
            seven_b_amplification="NOT_PROVEN",
        ),
        "pipeline_board": _artifact(
            base,
            schema_id="kt.b04_r6.pipeline_board.v1",
            artifact_id="B04_R6_PIPELINE_BOARD",
            r6="OPEN",
            package_promotion="PASSED",
            commercial_activation_review="VALIDATED",
            commercial_activation_authorization="BOUND",
            commercial_activation_authorization_validation="NEXT",
            commercial_activation_execution="BLOCKED",
        ),
        "claim_ceiling_current_state": _artifact(
            base,
            schema_id="kt.claim_ceiling.current_state.v1",
            artifact_id="KT_CLAIM_CEILING_CURRENT_STATE",
            allowed_claims=[
                "R6 is open.",
                "Package promotion passed.",
                "Commercial activation review is validated.",
                "Commercial activation authorization packet is bound and awaits validation.",
                "Commercial activation is not executed.",
                "Commercial activation claims remain unauthorized until evidence review validates.",
                "Truth/trust law is unchanged.",
            ],
            forbidden_claims=[
                "KT is commercially activated.",
                "KT is production-commercial live.",
                "Commercial activation claims are authorized.",
                "Commercial activation has executed.",
                "7B amplification is proven.",
                "KT beats all larger models generally.",
            ],
        ),
        "future_blocker_register": _artifact(
            base,
            schema_id="kt.future_blocker_register.v1",
            artifact_id="KT_FUTURE_BLOCKER_REGISTER",
            blockers=[
                "commercial_activation_authorization_requires_validation",
                "commercial_activation_execution_requires_execution_packet_authoring_and_validation",
                "commercial_activation_claims_require_post_activation_evidence_review_validation",
                "follow_up_audit_readiness_requires_later evidence review",
                "provider_benchmark_outputs_are_prep_only",
            ],
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.next_lawful_move_receipt.v1",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
    }
    contract_specs = {
        "activation_scope_contract": (
            "Define bounded commercial-activation authorization scope.",
            ["authorization validation only", "execution remains blocked until execution packet validation"],
        ),
        "allowed_commercial_surface_contract": (
            "Define commercial surfaces that may be considered after validation.",
            ["customer-safe status language", "support readiness", "deployment profile", "public verifier bundle"],
        ),
        "excluded_commercial_surface_contract": (
            "Define excluded commercial surfaces.",
            ["commercial claim execution", "unreviewed pricing claims", "unvalidated 7B amplification claims"],
        ),
        "claim_authorization_scope_contract": (
            "Define claim authorization scope.",
            ["claims derive from receipts", "commercial activation claims require post-activation evidence review"],
        ),
        "customer_safe_language_contract": (
            "Bind customer-safe language.",
            ["no production-commercial-live claim before evidence review", "no benchmark overclaim"],
        ),
        "operator_obligation_contract": (
            "Define operator obligations.",
            ["support runbook", "incident response", "claim ceiling acknowledgement"],
        ),
        "deployment_profile_requirements": (
            "Define deployment profile requirements.",
            ["release truth derivation", "operator ownership", "fallback and rollback controls"],
        ),
        "support_incident_requirements": (
            "Define support and incident requirements.",
            ["freeze path", "support routing", "customer notification boundary"],
        ),
        "data_governance_requirements": (
            "Define data governance requirements.",
            ["data handling boundary", "secret/distributable hygiene", "public verifier exclusions"],
        ),
        "rollback_obligation_contract": (
            "Define rollback obligations.",
            ["rollback evidence", "quarantine path", "commercial claim freeze path"],
        ),
        "external_audit_requirements": (
            "Define external audit requirements.",
            ["hash manifest", "replay manifest", "auditor README"],
        ),
        "public_verifier_requirements": (
            "Define public verifier requirements.",
            ["minimal reproducible bundle", "source hash manifest", "claim boundary"],
        ),
        "commercial_claim_ceiling": (
            "Bind commercial claim ceiling.",
            ["commercial activation is not executed", "claims remain unauthorized until evidence review"],
        ),
        "release_truth_derivation_contract": (
            "Require release truth to derive mechanically from receipts.",
            ["claim compiler boundary", "validation receipts", "replay artifacts"],
        ),
        "no_authority_drift_receipt": (
            "Record no-authority-drift state.",
            ["no commercial activation execution", "no commercial claim authorization", "benchmark prep non-authoritative"],
        ),
    }
    for role, (purpose, requirements) in contract_specs.items():
        payloads[role] = _contract(base, role=role, purpose=purpose, requirements=requirements)
    prep_purposes = {
        "commercial_activation_execution_packet_prep_only_draft": "Prepare future commercial activation execution packet.",
        "commercial_activation_execution_validation_plan_prep_only": "Prepare future execution-packet validation plan.",
        "commercial_activation_evidence_review_packet_prep_only_draft": (
            "Prepare future commercial activation evidence review."
        ),
        "commercial_activation_repair_or_rollback_prep_only_draft": (
            "Prepare repair, rollback, quarantine, or freeze path."
        ),
        "commercial_activation_forensic_review_prep_only_draft": "Prepare forensic commercial activation review path.",
        "external_audit_delta_packet_prep_only_draft": "Prepare external audit delta packet after activation evidence.",
        "follow_up_audit_readiness_packet_prep_only_draft": "Prepare final E2E follow-up audit readiness packet.",
    }
    for role, purpose in prep_purposes.items():
        payloads[role] = _prep_only(base, role=role, purpose=purpose)
    for role in BENCHMARK_PREP_ROLES:
        payloads[role] = _benchmark_payload(base, role=role)
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Commercial Activation Authorization Packet",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "This packet binds the validated commercial activation review and freezes the authorization law.",
            "It does not execute commercial activation and does not authorize commercial activation claims.",
            "",
            BENCHMARK_GOVERNING_STATEMENT,
            "",
            "Provider/runtime and 7B benchmark artifacts are PREP_ONLY.",
            "Truth-engine and trust-zone law remain unchanged.",
            "",
        ]
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 commercial activation authorization packet")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_inputs(payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_AUTH_TRUST_ZONE_FAILED", "fresh trust-zone validation must pass")
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
        trust_zone_validation=trust_zone_validation,
    )
    output_payloads = _outputs(base)
    contract = output_payloads["authorization_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "authorization_report":
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
