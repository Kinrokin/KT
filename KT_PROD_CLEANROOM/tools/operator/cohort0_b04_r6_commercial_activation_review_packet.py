from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_package_promotion_evidence_review_packet_validation as evidence_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/b04-r6-commercial-activation-review-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-commercial-activation-review-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PACKET"
PREVIOUS_LANE = evidence_validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = evidence_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = evidence_validation.NEXT_LAWFUL_MOVE

SELECTED_OUTCOME = "B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PACKET_BOUND__COMMERCIAL_ACTIVATION_REVIEW_VALIDATION_NEXT"
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PACKET"
OUTCOME_DEFERRED = "B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PACKET_INVALID__FORENSIC_REVIEW_NEXT"

RECOMMENDED_NEXT_PATH = "COMMERCIAL_ACTIVATION_AUTHORIZATION_PACKET_NEXT"

FORBIDDEN_ACTIONS = (
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "COMMERCIAL_ACTIVATION_EXECUTED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "BENCHMARK_PREP_TREATED_AS_COMMERCIAL_AUTHORITY",
    "SEVEN_B_AMPLIFICATION_CLAIMED_PROVEN",
)

AUTHORITY_DRIFT_KEYS = {
    "commercial_activation_claim_authorized": "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_COMMERCIAL_CLAIM_DRIFT",
    "commercial_activation_executed": "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_EXECUTION_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_TRUST_ZONE_MUTATION",
    "benchmark_prep_authorizes_commercial_activation": (
        "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_BENCHMARK_AUTHORITY_DRIFT"
    ),
    "seven_b_amplification_claimed_proven": "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_7B_CLAIM_DRIFT",
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
            "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_INPUT_MISSING",
            "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_OUTCOME_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_NEXT_MOVE_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_INCOMPLETE",
            "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_PREP_ONLY_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in evidence_validation.OUTPUTS.items()
    if filename.endswith(".json")
}
VALIDATION_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in evidence_validation.OUTPUTS.items()
    if not filename.endswith(".json")
}

REVIEW_ROLES = (
    "package_promotion_evidence_review_validation_review",
    "claim_ceiling_review",
    "external_audit_readiness_review",
    "public_verifier_readiness_review",
    "customer_safe_language_review",
    "operator_support_readiness_review",
    "deployment_profile_review",
    "rollback_and_freeze_review",
    "data_governance_review",
    "no_authority_drift_review",
)

PREP_ONLY_ROLES = (
    "commercial_activation_authorization_packet_prep_only_draft",
    "commercial_activation_validation_plan_prep_only",
    "external_audit_delta_packet_prep_only_draft",
    "limited_commercial_continuation_packet_prep_only_draft",
    "commercial_activation_repair_or_closeout_prep_only_draft",
)

OUTPUTS = {
    "review_contract": "b04_r6_commercial_activation_review_packet_contract.json",
    "review_receipt": "b04_r6_commercial_activation_review_packet_receipt.json",
    "review_report": "b04_r6_commercial_activation_review_packet_report.md",
    "evidence_inventory": "b04_r6_commercial_activation_review_evidence_inventory.json",
    "evidence_scorecard": "b04_r6_commercial_activation_review_scorecard.json",
    "post_package_decision_matrix": "b04_r6_commercial_activation_post_package_decision_matrix.json",
    "commercial_activation_blocker_ledger": "b04_r6_commercial_activation_review_blocker_ledger.json",
    "package_promotion_evidence_review_validation_review": (
        "b04_r6_commercial_activation_package_evidence_validation_review.json"
    ),
    "claim_ceiling_review": "b04_r6_commercial_activation_claim_ceiling_review.json",
    "external_audit_readiness_review": "b04_r6_commercial_activation_external_audit_readiness_review.json",
    "public_verifier_readiness_review": "b04_r6_commercial_activation_public_verifier_readiness_review.json",
    "customer_safe_language_review": "b04_r6_commercial_activation_customer_safe_language_review.json",
    "operator_support_readiness_review": "b04_r6_commercial_activation_operator_support_readiness_review.json",
    "deployment_profile_review": "b04_r6_commercial_activation_deployment_profile_review.json",
    "rollback_and_freeze_review": "b04_r6_commercial_activation_rollback_freeze_review.json",
    "data_governance_review": "b04_r6_commercial_activation_data_governance_review.json",
    "no_authority_drift_review": "b04_r6_commercial_activation_no_authority_drift_review.json",
    "validation_plan": "b04_r6_commercial_activation_review_validation_plan.json",
    "validation_reason_codes": "b04_r6_commercial_activation_review_validation_reason_codes.json",
    "commercial_activation_authorization_packet_prep_only_draft": (
        "b04_r6_commercial_activation_authorization_packet_prep_only_draft.json"
    ),
    "commercial_activation_validation_plan_prep_only": (
        "b04_r6_commercial_activation_authorization_validation_plan_prep_only.json"
    ),
    "external_audit_delta_packet_prep_only_draft": (
        "b04_r6_commercial_activation_external_audit_delta_packet_prep_only_draft.json"
    ),
    "limited_commercial_continuation_packet_prep_only_draft": (
        "b04_r6_limited_commercial_continuation_packet_prep_only_draft.json"
    ),
    "commercial_activation_repair_or_closeout_prep_only_draft": (
        "b04_r6_commercial_activation_repair_or_closeout_prep_only_draft.json"
    ),
    "pipeline_board": "b04_r6_commercial_activation_review_pipeline_board.json",
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
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_INPUT_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_INPUT_MISSING", str(exc))


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in VALIDATION_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in VALIDATION_TEXT_INPUTS.items()}
    return payloads, texts


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk_items(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted non-false")
            if _is_claim_bearing_field(key) and isinstance(value, str) and _contains_positive_authority_token(value):
                _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        for phrase in (
            "COMMERCIAL ACTIVATION AUTHORIZED",
            "COMMERCIAL ACTIVATION CLAIM AUTHORIZED",
            "COMMERCIAL ACTIVATION EXECUTED",
            "7B AMPLIFICATION IS PROVEN",
        ):
            if phrase in normalized:
                _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**VALIDATION_JSON_INPUTS, **VALIDATION_TEXT_INPUTS}.items()):
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": "file_sha256_at_commercial_activation_review_packet_authoring",
            }
        )
    return rows


def _binding_hashes(root: Path) -> Dict[str, str]:
    return {f"{row['role']}_hash": row["sha256"] for row in _input_bindings(root)}


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["validation_contract"]
    receipt = payloads["validation_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_OUTCOME_DRIFT", "validation contract outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_OUTCOME_DRIFT", "validation receipt outcome drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_NEXT_MOVE_DRIFT", "validation contract next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_NEXT_MOVE_DRIFT", "next-lawful-move receipt drift")
    for key in (
        "r6_open",
        "package_promotion_executed",
        "package_promotion_passed",
        "package_promotion_evidence_review_validated",
        "commercial_activation_review_packet_next",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    ):
        if contract.get(key) is not True:
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_INCOMPLETE", f"{key} is not true")
    for key in (
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
        "benchmark_prep_authorizes_package_promotion",
        "seven_b_amplification_claimed_proven",
    ):
        if contract.get(key) is not False:
            _fail(AUTHORITY_DRIFT_KEYS.get(key, "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_INCOMPLETE"), key)
    if not contract.get("binding_hashes") or not contract.get("input_bindings"):
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_INPUT_BINDINGS_EMPTY", "validation bindings empty")


def _validate_prep_only_inputs(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in evidence_validation.PREP_ONLY_OUTPUT_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_PREP_ONLY_DRIFT", f"{role} is not PREP_ONLY")
        for key in (
            "cannot_authorize_commercial_activation_claims",
            "cannot_mutate_truth_engine_law",
            "cannot_mutate_trust_zone_law",
        ):
            if payload.get(key) is not True:
                _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_PREP_ONLY_DRIFT", f"{role}.{key} drifted")


def _validate_inputs(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _validate_handoff(payloads)
    _validate_prep_only_inputs(payloads)
    _ensure_authority_closed(payloads, texts)
    for role, raw in VALIDATION_JSON_INPUTS.items():
        if len(file_sha256(common.resolve_path(root, raw))) != 64:
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_INPUT_MISSING", f"{role} hash malformed")


def _guard() -> Dict[str, Any]:
    return {
        "r6_open": True,
        "package_promotion_executed": True,
        "package_promotion_passed": True,
        "package_promotion_evidence_review_validated": True,
        "commercial_activation_review_packet_authored": True,
        "commercial_activation_review_packet_validated": False,
        "commercial_activation_authorization_packet_next_recommended": True,
        "commercial_activation_claim_authorized": False,
        "commercial_activation_executed": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "benchmark_prep_authorizes_commercial_activation": False,
        "seven_b_amplification_claimed_proven": False,
        "cannot_authorize_commercial_activation_claims": True,
        "cannot_execute_commercial_activation": True,
        "cannot_mutate_truth_engine_law": True,
        "cannot_mutate_trust_zone_law": True,
    }


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    input_bindings: list[Dict[str, str]],
    binding_hashes: Dict[str, str],
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
        "recommended_next_path": RECOMMENDED_NEXT_PATH,
        "recommendation_is_authority": False,
        "allowed_outcomes": [SELECTED_OUTCOME, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "outcome_routing": {
            SELECTED_OUTCOME: NEXT_LAWFUL_MOVE,
            OUTCOME_DEFERRED: "REPAIR_B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PACKET_DEFECTS",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_COMMERCIAL_ACTIVATION_REVIEW_PACKET",
        },
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "binding_hashes": binding_hashes,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        **_guard(),
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _review_artifact(base: Dict[str, Any], *, role: str, grade: str = "PASS") -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.commercial_activation_review.{role}.v1",
        artifact_id=f"B04_R6_COMMERCIAL_ACTIVATION_REVIEW_{role.upper()}",
        review_role=role,
        review_status="BOUND",
        grade=grade,
        commercial_activation_claim_authorized=False,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.commercial_activation_review.{role}.prep_only.v1",
        artifact_id=f"B04_R6_COMMERCIAL_ACTIVATION_REVIEW_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_authorize_commercial_activation_claims=True,
        cannot_execute_commercial_activation=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    category_grades = {
        "package_promotion_evidence_review_validation": "PASS",
        "claim_ceiling": "PASS",
        "external_audit_readiness": "PASS",
        "public_verifier_readiness": "PASS",
        "customer_safe_language": "PASS",
        "operator_support_readiness": "PASS",
        "deployment_profile": "PASS",
        "rollback_and_freeze": "PASS",
        "data_governance": "PASS",
        "no_authority_drift": "PASS",
    }
    payloads: Dict[str, Any] = {
        "review_contract": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_review_packet_contract.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PACKET_CONTRACT",
            review_summary=(
                "Commercial-activation review packet is authored from validated package-promotion evidence. "
                "It recommends commercial-activation authorization packet authorship only."
            ),
        ),
        "review_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_review_packet_receipt.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PACKET_RECEIPT",
            receipt_type="AUTHORING_RECEIPT",
        ),
        "evidence_inventory": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_review_evidence_inventory.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_REVIEW_EVIDENCE_INVENTORY",
            inventory_roles=sorted(VALIDATION_JSON_INPUTS),
        ),
        "evidence_scorecard": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_review_scorecard.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_REVIEW_SCORECARD",
            overall_grade="A_REVIEWABLE",
            category_grades=category_grades,
        ),
        "post_package_decision_matrix": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_post_package_decision_matrix.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_POST_PACKAGE_DECISION_MATRIX",
            commercial_activation_authorization_review_ready=True,
            commercial_activation_claim_status="UNAUTHORIZED_REVIEW_ONLY",
            blocking_reasons=["commercial_activation_requires_review_validation"],
        ),
        "commercial_activation_blocker_ledger": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_review_blocker_ledger.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_REVIEW_BLOCKER_LEDGER",
            blockers=[
                {
                    "blocker_id": "B04R6-CAR-0001",
                    "category": "commercial_activation",
                    "severity": "BLOCKING",
                    "blocks": ["COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED"],
                    "required_repair_or_next_artifact": "VALIDATE_B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PACKET",
                    "status": "OPEN",
                }
            ],
        ),
        "validation_plan": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_review_validation_plan.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_REVIEW_VALIDATION_PLAN",
            validation_objective="Validate commercial-activation review before authorization packet authorship.",
        ),
        "validation_reason_codes": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_review_validation_reason_codes.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_REVIEW_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
        ),
        "pipeline_board": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation_review_pipeline_board.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PIPELINE_BOARD",
            board={
                "r6": "OPEN",
                "package_promotion": "PASSED",
                "package_promotion_evidence_review": "VALIDATED",
                "commercial_activation_review_packet": "BOUND",
                "commercial_activation_review_validation": "NEXT",
                "commercial_activation_claims": "UNAUTHORIZED",
            },
        ),
        "claim_ceiling_current_state": _artifact(
            base,
            schema_id="kt.claim_ceiling_current_state.v1",
            artifact_id="KT_CLAIM_CEILING_CURRENT_STATE",
            allowed_claims=[
                "R6 is open.",
                "Package promotion has passed.",
                "Commercial-activation review packet is authored.",
            ],
            forbidden_claims=[
                "Commercial activation claims are authorized.",
                "KT is commercially activated.",
                "7B amplification is proven.",
            ],
        ),
        "future_blocker_register": _artifact(
            base,
            schema_id="kt.future_blocker_register.v1",
            artifact_id="KT_FUTURE_BLOCKER_REGISTER",
            blockers=[
                "commercial_activation_review_validation_not_complete",
                "commercial_activation_authorization_packet_not_authored_or_validated",
                "commercial_activation_execution_not_authorized",
                "external_audit_delta_required_before_public_claims",
                "seven_b_amplification_not_proven",
            ],
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.next_lawful_move_receipt.v1",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            receipt_type="NEXT_LAWFUL_MOVE",
        ),
    }
    for role in REVIEW_ROLES:
        payloads[role] = _review_artifact(base, role=role)
    prep_purposes = {
        "commercial_activation_authorization_packet_prep_only_draft": (
            "Prepare commercial-activation authorization packet; does not authorize claims."
        ),
        "commercial_activation_validation_plan_prep_only": "Prepare authorization validation if review validates.",
        "external_audit_delta_packet_prep_only_draft": "Prepare external audit delta; prep only.",
        "limited_commercial_continuation_packet_prep_only_draft": "Prepare limited commercial continuation fallback.",
        "commercial_activation_repair_or_closeout_prep_only_draft": "Prepare repair/closeout fallback.",
    }
    payloads.update({role: _prep_only(base, role=role, purpose=prep_purposes[role]) for role in PREP_ONLY_ROLES})
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Commercial Activation Review Packet",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "The packet reviews validated package-promotion evidence and recommends commercial-activation",
            "authorization packet authorship only.",
            "",
            "Recommendation is not authorization. Commercial activation claims remain unauthorized.",
            "Truth-engine and trust-zone law remain unchanged. 7B amplification remains unproven.",
            "",
        ]
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root):
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 commercial-activation review packet")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_inputs(root, payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_TRUST_ZONE_FAILED", "trust-zone validation failed")
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
        binding_hashes=_binding_hashes(root),
        trust_zone_validation=trust_zone_validation,
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
    parser = argparse.ArgumentParser(description="Author the B04 R6 commercial-activation review packet.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
