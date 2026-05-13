from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_commercial_activation_authorization_packet_validation as auth_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/b04-r6-commercial-activation-execution-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-commercial-activation-execution-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET"
PREVIOUS_LANE = auth_validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = auth_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = auth_validation.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = (
    "B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET_BOUND__"
    "COMMERCIAL_ACTIVATION_EXECUTION_VALIDATION_NEXT"
)
OUTCOME_DEFERRED = (
    "B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET_DEFERRED__"
    "NAMED_PACKET_DEFECT_REMAINS"
)
OUTCOME_INVALID = (
    "B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET_INVALID__"
    "FORENSIC_COMMERCIAL_ACTIVATION_EXECUTION_REVIEW_NEXT"
)
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET"

VALIDATION_SUCCESS_OUTCOME = (
    "B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET_VALIDATED__"
    "COMMERCIAL_ACTIVATION_NEXT"
)
VALIDATION_SUCCESS_NEXT_MOVE = "RUN_B04_R6_COMMERCIAL_ACTIVATION"

BENCHMARK_GOVERNING_STATEMENT = (
    "KT does not claim small models are secretly giant models. KT tests where governed substrate makes smaller "
    "models act above class, and proves where it does not."
)

FORBIDDEN_ACTIONS = (
    "COMMERCIAL_ACTIVATION_EXECUTED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "BENCHMARK_PREP_TREATED_AS_COMMERCIAL_AUTHORITY",
    "SEVEN_B_AMPLIFICATION_CLAIMED_PROVEN",
)

AUTHORITY_DRIFT_KEYS = {
    "commercial_activation_executed": "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_EXECUTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_TRUST_ZONE_MUTATION",
    "benchmark_prep_authorizes_commercial_activation": (
        "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_BENCHMARK_AUTHORITY_DRIFT"
    ),
    "seven_b_amplification_claimed_proven": "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_7B_CLAIM_DRIFT",
}

CLAIM_BEARING_FIELD_MARKERS = (
    "activation",
    "authorization_state",
    "authority_state",
    "claim",
    "commercial",
    "execution_state",
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
    "AUTHORIZATION_VALIDATION",
    "BLOCKED",
    "BOUNDARY_ONLY",
    "CANNOT_AUTHORIZE",
    "DEFERRED",
    "DOES_NOT_AUTHORIZE",
    "DOES_NOT_EXECUTE",
    "EXECUTION_PACKET",
    "FORBIDDEN",
    "NEXT",
    "NOT_AUTHORIZED",
    "NOT_EXECUTED",
    "PREP_ONLY",
    "PROHIBITED",
    "REMAINS_UNAUTHORIZED",
    "REVIEW_PACKET",
    "STILL_BLOCKED",
    "UNAUTHORIZED",
    "VALIDATION_NEXT",
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_AUTH_VALIDATION_MISSING",
            "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_OUTCOME_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_NEXT_MOVE_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_CONTRACT_INCOMPLETE",
            "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_PREP_ONLY_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

AUTH_VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in auth_validation.OUTPUTS.items()
    if filename.endswith(".json")
}
AUTH_VALIDATION_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in auth_validation.OUTPUTS.items()
    if not filename.endswith(".json")
}

EXECUTION_CONTRACT_ROLES = (
    "activation_execution_mode_contract",
    "commercial_activation_scope_contract",
    "allowed_commercial_surface_contract",
    "excluded_commercial_surface_contract",
    "claim_ceiling_contract",
    "customer_safe_language_execution_contract",
    "operator_obligation_execution_contract",
    "deployment_profile_execution_contract",
    "support_incident_execution_contract",
    "data_governance_execution_contract",
    "release_truth_execution_contract",
    "external_verifier_bundle_contract",
    "public_verifier_bundle_contract",
    "audit_bundle_contract",
    "rollback_execution_contract",
    "quarantine_freeze_contract",
    "expected_activation_artifact_manifest",
    "result_interpretation_contract",
    "no_authority_drift_receipt",
)

PREP_ONLY_ROLES = (
    "commercial_activation_run_result_schema_prep_only",
    "commercial_activation_evidence_review_packet_prep_only_draft",
    "commercial_activation_repair_or_rollback_prep_only_draft",
    "commercial_activation_forensic_review_prep_only_draft",
    "follow_up_audit_readiness_packet_prep_only_draft",
    "post_activation_external_audit_delta_packet_prep_only_draft",
)

OUTPUTS = {
    "execution_contract": "b04_r6_commercial_activation_execution_packet_contract.json",
    "execution_receipt": "b04_r6_commercial_activation_execution_packet_receipt.json",
    "execution_report": "b04_r6_commercial_activation_execution_packet_report.md",
    "activation_execution_mode_contract": "b04_r6_commercial_activation_execution_mode_contract.json",
    "commercial_activation_scope_contract": "b04_r6_commercial_activation_execution_scope_contract.json",
    "allowed_commercial_surface_contract": "b04_r6_commercial_activation_execution_allowed_surface_contract.json",
    "excluded_commercial_surface_contract": "b04_r6_commercial_activation_execution_excluded_surface_contract.json",
    "claim_ceiling_contract": "b04_r6_commercial_activation_execution_claim_ceiling_contract.json",
    "customer_safe_language_execution_contract": (
        "b04_r6_commercial_activation_execution_customer_safe_language_contract.json"
    ),
    "operator_obligation_execution_contract": (
        "b04_r6_commercial_activation_execution_operator_obligation_contract.json"
    ),
    "deployment_profile_execution_contract": (
        "b04_r6_commercial_activation_execution_deployment_profile_contract.json"
    ),
    "support_incident_execution_contract": "b04_r6_commercial_activation_execution_support_incident_contract.json",
    "data_governance_execution_contract": "b04_r6_commercial_activation_execution_data_governance_contract.json",
    "release_truth_execution_contract": "b04_r6_commercial_activation_execution_release_truth_contract.json",
    "external_verifier_bundle_contract": "b04_r6_commercial_activation_execution_external_verifier_bundle.json",
    "public_verifier_bundle_contract": "b04_r6_commercial_activation_execution_public_verifier_bundle.json",
    "audit_bundle_contract": "b04_r6_commercial_activation_execution_audit_bundle_contract.json",
    "rollback_execution_contract": "b04_r6_commercial_activation_execution_rollback_contract.json",
    "quarantine_freeze_contract": "b04_r6_commercial_activation_execution_quarantine_freeze_contract.json",
    "expected_activation_artifact_manifest": "b04_r6_commercial_activation_execution_expected_artifact_manifest.json",
    "result_interpretation_contract": "b04_r6_commercial_activation_execution_result_interpretation_contract.json",
    "no_authority_drift_receipt": "b04_r6_commercial_activation_execution_no_authority_drift_receipt.json",
    "execution_validation_plan": "b04_r6_commercial_activation_execution_validation_plan.json",
    "execution_validation_reason_codes": "b04_r6_commercial_activation_execution_validation_reason_codes.json",
    "commercial_activation_run_result_schema_prep_only": (
        "b04_r6_commercial_activation_run_result_schema_prep_only.json"
    ),
    "commercial_activation_evidence_review_packet_prep_only_draft": (
        "b04_r6_commercial_activation_execution_evidence_review_packet_prep_only_draft.json"
    ),
    "commercial_activation_repair_or_rollback_prep_only_draft": (
        "b04_r6_commercial_activation_repair_or_rollback_prep_only_draft.json"
    ),
    "commercial_activation_forensic_review_prep_only_draft": (
        "b04_r6_commercial_activation_forensic_review_prep_only_draft.json"
    ),
    "follow_up_audit_readiness_packet_prep_only_draft": (
        "kt_e2e_follow_up_audit_readiness_packet_prep_only_draft.json"
    ),
    "post_activation_external_audit_delta_packet_prep_only_draft": (
        "b04_r6_post_commercial_activation_external_audit_delta_packet_prep_only_draft.json"
    ),
    "pipeline_board": "b04_r6_pipeline_board.json",
    "campaign_board": "kt_e2e_closure_campaign_board.json",
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


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk_items(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_items(item)


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
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_AUTH_VALIDATION_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_AUTH_VALIDATION_MISSING", str(exc))


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in AUTH_VALIDATION_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in AUTH_VALIDATION_TEXT_INPUTS.items()}
    return payloads, texts


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk_items(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted non-false")
            if _is_claim_bearing_field(key) and isinstance(value, str) and _contains_positive_authority_token(value):
                _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        for phrase in (
            "COMMERCIAL ACTIVATION EXECUTED",
            "COMMERCIAL ACTIVATION AUTHORIZED",
            "COMMERCIAL ACTIVATION CLAIM AUTHORIZED",
            "COMMERCIAL ACTIVATION CLAIMS AUTHORIZED",
            "7B AMPLIFICATION IS PROVEN",
        ):
            if phrase in normalized:
                _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["validation_contract"]
    receipt = payloads["validation_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_OUTCOME_DRIFT", "authorization validation outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_OUTCOME_DRIFT", "authorization validation receipt drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_NEXT_MOVE_DRIFT", "authorization validation next drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_NEXT_MOVE_DRIFT", "next-lawful-move receipt drift")
    for key in (
        "r6_open",
        "package_promotion_passed",
        "commercial_activation_review_packet_validated",
        "commercial_activation_authorization_packet_authored",
        "commercial_activation_authorization_validated",
        "commercial_activation_execution_packet_next",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    ):
        if contract.get(key) is not True:
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_CONTRACT_INCOMPLETE", f"{key} is not true")
    for key in (
        "commercial_activation_execution_packet_authored",
        "commercial_activation_claim_authorized",
        "commercial_activation_executed",
        "benchmark_prep_authorizes_commercial_activation",
        "seven_b_amplification_claimed_proven",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
    ):
        if contract.get(key) is not False:
            _fail(AUTHORITY_DRIFT_KEYS.get(key, "RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_CONTRACT_INCOMPLETE"), key)
    if not contract.get("binding_hashes"):
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_INPUT_BINDINGS_EMPTY", "authorization validation bindings empty")


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _ensure_authority_closed(payloads, texts)
    _validate_handoff(payloads)


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**AUTH_VALIDATION_JSON_INPUTS, **AUTH_VALIDATION_TEXT_INPUTS}.items()):
        rows.append({"role": role, "path": raw, "sha256": file_sha256(root / raw)})
    return rows


def _guard() -> Dict[str, Any]:
    return {
        "r6_open": True,
        "package_promotion_passed": True,
        "commercial_activation_authorization_validated": True,
        "commercial_activation_execution_packet_authored": True,
        "commercial_activation_execution_packet_validated": False,
        "commercial_activation_executed": False,
        "commercial_activation_claim_authorized": False,
        "benchmark_prep_authorizes_commercial_activation": False,
        "seven_b_amplification_claimed_proven": False,
        "truth_engine_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_changed": False,
        "trust_zone_law_unchanged": True,
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
    return {
        "schema_version": "v1",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "current_branch_head": head,
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
        "benchmark_governing_statement": BENCHMARK_GOVERNING_STATEMENT,
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "binding_hashes": {f"{row['role']}_hash": row["sha256"] for row in input_bindings},
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        **_guard(),
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _contract(base: Dict[str, Any], *, role: str, requirements: Sequence[str]) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.commercial_activation_execution_packet.{role}.v1",
        artifact_id=f"B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET_{role.upper()}",
        contract_role=role,
        contract_status="BOUND",
        requirements=list(requirements),
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.commercial_activation_execution_packet.{role}.prep_only.v1",
        artifact_id=f"B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_execute_commercial_activation=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_claim_7b_amplification_proven=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    payloads: Dict[str, Any] = {
        "execution_contract": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_execution_packet.contract.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET_CONTRACT",
            execution_packet_summary=(
                "Defines how commercial activation may run after independent execution-packet validation. "
                "It does not execute commercial activation or authorize claims."
            ),
        ),
        "execution_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_execution_packet.receipt.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET_RECEIPT",
            verdict="COMMERCIAL_ACTIVATION_EXECUTION_PACKET_BOUND_VALIDATION_NEXT",
        ),
        "execution_validation_plan": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_execution_packet.validation_plan.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET_VALIDATION_PLAN",
            required_validations=[
                "validated commercial activation authorization is bound",
                "activation execution mode and surface are bounded",
                "claim ceiling and customer-safe language are preserved",
                "rollback/quarantine/freeze paths are present",
                "commercial activation has not executed inside this packet",
            ],
        ),
        "execution_validation_reason_codes": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_execution_packet.reason_codes.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_PACKET_VALIDATION_REASON_CODES",
            reason_code_taxonomy=list(REASON_CODES),
        ),
        "pipeline_board": _artifact(
            base,
            schema_id="kt.b04_r6.pipeline_board.v1",
            artifact_id="B04_R6_PIPELINE_BOARD",
            r6="OPEN",
            package_promotion="PASSED",
            commercial_activation_authorization="VALIDATED",
            commercial_activation_execution_packet="BOUND",
            commercial_activation_execution_validation="NEXT",
            commercial_activation_execution="BLOCKED",
            commercial_activation_claims="BLOCKED",
        ),
        "campaign_board": _artifact(
            base,
            schema_id="kt.e2e_closure_campaign_board.v1",
            artifact_id="KT_E2E_CLOSURE_CAMPAIGN_BOARD",
            commercial_activation_corridor="EXECUTION_PACKET_BOUND__VALIDATION_NEXT",
            provider_benchmark_corridor="PREP_ONLY",
            follow_up_audit_corridor="PREP_ONLY",
        ),
        "claim_ceiling_current_state": _artifact(
            base,
            schema_id="kt.claim_ceiling_current_state.v1",
            artifact_id="KT_CLAIM_CEILING_CURRENT_STATE",
            allowed_claims=[
                "R6 is open.",
                "Package promotion has passed.",
                "Commercial activation authorization is validated.",
                "Commercial activation execution packet is authored for validation.",
            ],
            forbidden_claims=[
                "Commercial activation has executed.",
                "Commercial activation claims are authorized.",
                "7B amplification is proven.",
            ],
        ),
        "future_blocker_register": _artifact(
            base,
            schema_id="kt.future_blocker_register.v1",
            artifact_id="KT_FUTURE_BLOCKER_REGISTER",
            blockers=[
                "commercial_activation_execution_packet_requires_validation",
                "commercial_activation_not_executed",
                "commercial_activation_claims_require_evidence_review_validation",
                "follow_up_audit_readiness_requires_post_activation_evidence_review",
            ],
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.next_lawful_move_receipt.v1",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
    }
    contract_requirements = {
        "activation_execution_mode_contract": ["operator-observed activation execution", "receipt-heavy execution"],
        "commercial_activation_scope_contract": ["bounded commercial surface", "no benchmark/provider authority"],
        "allowed_commercial_surface_contract": ["customer-safe status surface", "approved package surface"],
        "excluded_commercial_surface_contract": ["unvalidated claims", "benchmark superiority claims", "archive residue"],
        "claim_ceiling_contract": ["activation run is not final claim authorization"],
        "customer_safe_language_execution_contract": ["derive language from receipts", "no free-form authority claims"],
        "operator_obligation_execution_contract": ["runbook acknowledgement", "incident ownership"],
        "deployment_profile_execution_contract": ["approved deployment profile", "rollback path"],
        "support_incident_execution_contract": ["support contacts", "freeze path"],
        "data_governance_execution_contract": ["data boundary", "secret/distributable hygiene"],
        "release_truth_execution_contract": ["derive activation truth from receipts"],
        "external_verifier_bundle_contract": ["external hash manifest", "auditor README"],
        "public_verifier_bundle_contract": ["public verifier manifest", "claim ceiling"],
        "audit_bundle_contract": ["activation evidence inventory", "negative-result ledger"],
        "rollback_execution_contract": ["rollback command path", "commercial freeze path"],
        "quarantine_freeze_contract": ["freeze on claim drift", "freeze on audit defect"],
        "expected_activation_artifact_manifest": ["activation receipt", "activation report", "evidence review prep"],
        "result_interpretation_contract": ["pass requires later evidence review before claims"],
        "no_authority_drift_receipt": ["no execution", "no claim authorization", "truth/trust unchanged"],
    }
    for role, requirements in contract_requirements.items():
        payloads[role] = _contract(base, role=role, requirements=requirements)
    prep_purposes = {
        "commercial_activation_run_result_schema_prep_only": "Prepare future commercial activation run result schema.",
        "commercial_activation_evidence_review_packet_prep_only_draft": "Prepare post-activation evidence review.",
        "commercial_activation_repair_or_rollback_prep_only_draft": "Prepare repair or rollback path.",
        "commercial_activation_forensic_review_prep_only_draft": "Prepare forensic commercial activation review.",
        "follow_up_audit_readiness_packet_prep_only_draft": "Prepare final follow-up audit readiness packet.",
        "post_activation_external_audit_delta_packet_prep_only_draft": "Prepare post-activation external audit delta.",
    }
    for role, purpose in prep_purposes.items():
        payloads[role] = _prep_only(base, role=role, purpose=purpose)
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Commercial Activation Execution Packet",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "This packet defines commercial activation execution law but does not run commercial activation.",
            "Commercial activation claims remain unauthorized until post-activation evidence review validates.",
            "Truth/trust law remains unchanged.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 commercial activation execution packet")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_inputs(payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_EXEC_PACKET_TRUST_ZONE_FAILED", "fresh trust-zone validation must pass")
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
        trust_zone_validation=trust_zone_validation,
    )
    output_payloads = _outputs(base)
    contract = output_payloads["execution_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "execution_report":
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
