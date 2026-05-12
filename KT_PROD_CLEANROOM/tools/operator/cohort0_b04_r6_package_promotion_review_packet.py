from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_r6_opening_evidence_review_packet_validation as opening_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/b04-r6-package-promotion-review-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-package-promotion-review-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET"
PREVIOUS_LANE = opening_validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = opening_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = opening_validation.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = "B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET_BOUND__PACKAGE_PROMOTION_REVIEW_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET_INVALID__FORENSIC_PACKAGE_PROMOTION_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET"

RECOMMENDED_VALIDATED_PATH = "PACKAGE_PROMOTION_AUTHORIZATION_PACKET_NEXT"
VALIDATION_SUCCESS_OUTCOME = (
    "B04_R6_PACKAGE_PROMOTION_REVIEW_VALIDATED__PACKAGE_PROMOTION_AUTHORIZATION_PACKET_NEXT"
)
VALIDATION_SUCCESS_NEXT_MOVE = "AUTHOR_B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_PACKET"

FORBIDDEN_ACTIONS = (
    "PACKAGE_PROMOTION_AUTHORIZED",
    "PACKAGE_PROMOTION_EXECUTED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "LOBE_ESCALATION_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "R6_OPEN_TREATED_AS_PACKAGE_PROMOTION",
    "PACKAGE_PROMOTION_TREATED_AS_COMMERCIAL_ACTIVATION",
)

AUTHORITY_DRIFT_KEYS = {
    "package_promotion_authorized": "RC_B04R6_PACKAGE_PROMOTION_REVIEW_PACKAGE_PROMOTION_DRIFT",
    "package_promotion_executed": "RC_B04R6_PACKAGE_PROMOTION_REVIEW_PACKAGE_PROMOTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_PACKAGE_PROMOTION_REVIEW_COMMERCIAL_CLAIM_DRIFT",
    "lobe_escalation_authorized": "RC_B04R6_PACKAGE_PROMOTION_REVIEW_LOBE_ESCALATION_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_PACKAGE_PROMOTION_REVIEW_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_PACKAGE_PROMOTION_REVIEW_TRUST_ZONE_MUTATION",
    "r6_open_treated_as_package_promotion": "RC_B04R6_PACKAGE_PROMOTION_REVIEW_RESULT_PROMOTION_DRIFT",
    "package_promotion_treated_as_commercial_activation": (
        "RC_B04R6_PACKAGE_PROMOTION_REVIEW_COMMERCIAL_CLAIM_DRIFT"
    ),
}

CLAIM_BEARING_FIELD_MARKERS = (
    "authorization_state",
    "authority_state",
    "claim",
    "commercial",
    "package_promotion",
    "promotion",
)
POSITIVE_AUTHORITY_TOKENS = (
    "AUTHORIZED",
    "ACTIVE",
    "ENABLED",
    "PROMOTED",
    "PRODUCTION",
    "COMMERCIAL_ACTIVATION",
    "PACKAGE_PROMOTION",
)
NEGATIVE_AUTHORITY_QUALIFIERS = (
    "BLOCKED",
    "BOUNDARY_ONLY",
    "CANNOT_AUTHORIZE",
    "DEFERRED",
    "DOES NOT",
    "DOES_NOT_AUTHORIZE",
    "FORBIDDEN",
    "NO_COMMERCIAL",
    "NO_PACKAGE_PROMOTION",
    "NO_PROMOTION",
    "NOT AUTHORIZED",
    "NOT_AUTHORIZED",
    "PREP_ONLY",
    "PROHIBITED",
    "REMAINS UNAUTHORIZED",
    "REVIEW_PACKET",
    "STILL_BLOCKED",
    "UNAUTHORIZED",
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_PACKAGE_PROMOTION_REVIEW_VALIDATION_MISSING",
            "RC_B04R6_PACKAGE_PROMOTION_REVIEW_VALIDATION_OUTCOME_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_REVIEW_NEXT_MOVE_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_REVIEW_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_PACKAGE_PROMOTION_REVIEW_READINESS_INCOMPLETE",
            "RC_B04R6_PACKAGE_PROMOTION_REVIEW_DECISION_UNSUPPORTED",
            "RC_B04R6_PACKAGE_PROMOTION_REVIEW_PREP_ONLY_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_REVIEW_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_REVIEW_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in opening_validation.OUTPUTS.items()
    if filename.endswith(".json")
}
VALIDATION_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in opening_validation.OUTPUTS.items()
    if not filename.endswith(".json")
}

PREP_ONLY_ROLES = (
    "package_promotion_review_validation_plan",
    "package_promotion_review_validation_reason_codes",
    "package_promotion_authorization_packet_prep_only_draft",
    "package_promotion_execution_packet_prep_only_draft",
    "package_promotion_evidence_review_packet_prep_only_draft",
    "external_audit_delta_packet_prep_only_draft",
    "commercial_activation_claim_review_prep_only_draft",
)

OUTPUTS = {
    "packet_contract": "b04_r6_package_promotion_review_packet_contract.json",
    "packet_receipt": "b04_r6_package_promotion_review_packet_receipt.json",
    "packet_report": "b04_r6_package_promotion_review_packet_report.md",
    "evidence_inventory": "b04_r6_package_promotion_evidence_inventory.json",
    "evidence_scorecard": "b04_r6_package_promotion_evidence_scorecard.json",
    "decision_matrix": "b04_r6_package_promotion_decision_matrix.json",
    "blocker_ledger": "b04_r6_package_promotion_blocker_ledger.json",
    "release_truth_derivation_review": "b04_r6_release_truth_derivation_review_contract.json",
    "external_audit_delta_readiness_review": "b04_r6_package_promotion_external_audit_delta_readiness_review.json",
    "public_verifier_readiness_review": "b04_r6_package_promotion_public_verifier_readiness_review.json",
    "commercial_claim_boundary_review": "b04_r6_package_promotion_commercial_claim_boundary_review.json",
    "no_authorization_drift_receipt": "b04_r6_package_promotion_no_authorization_drift_receipt.json",
    "package_promotion_review_validation_plan": "b04_r6_package_promotion_review_validation_plan.json",
    "package_promotion_review_validation_reason_codes": "b04_r6_package_promotion_review_validation_reason_codes.json",
    "package_promotion_authorization_packet_prep_only_draft": (
        "b04_r6_package_promotion_authorization_packet_prep_only_draft.json"
    ),
    "package_promotion_execution_packet_prep_only_draft": (
        "b04_r6_package_promotion_execution_packet_prep_only_draft.json"
    ),
    "package_promotion_evidence_review_packet_prep_only_draft": (
        "b04_r6_package_promotion_evidence_review_packet_prep_only_draft.json"
    ),
    "external_audit_delta_packet_prep_only_draft": "b04_r6_external_audit_delta_packet_prep_only_draft.json",
    "commercial_activation_claim_review_prep_only_draft": (
        "b04_r6_commercial_activation_claim_review_prep_only_draft.json"
    ),
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


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk_items(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_items(item)


def _is_claim_bearing_field(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in CLAIM_BEARING_FIELD_MARKERS)


def _contains_positive_authority_token(value: str) -> bool:
    normalized = value.upper().replace("-", "_")
    if any(qualifier in normalized for qualifier in NEGATIVE_AUTHORITY_QUALIFIERS):
        return False
    return any(token in normalized for token in POSITIVE_AUTHORITY_TOKENS)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_VALIDATION_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_VALIDATION_MISSING", str(exc))


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
                _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        for phrase in (
            "PACKAGE PROMOTION AUTHORIZED",
            "PACKAGE IS PROMOTED",
            "COMMERCIAL ACTIVATION AUTHORIZED",
            "COMMERCIAL ACTIVATION CLAIM AUTHORIZED",
        ):
            if phrase in normalized:
                _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["validation_contract"]
    receipt = payloads["validation_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_VALIDATION_OUTCOME_DRIFT", "validation contract outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_VALIDATION_OUTCOME_DRIFT", "validation receipt outcome drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_NEXT_MOVE_DRIFT", "validation contract next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_NEXT_MOVE_DRIFT", "next-lawful-move receipt drift")
    if contract.get("r6_open") is not True or contract.get("package_promotion_review_packet_next") is not True:
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_VALIDATION_OUTCOME_DRIFT", "package review handoff truth missing")
    if contract.get("r6_opening_evidence_review_validated") is not True:
        _fail(
            "RC_B04R6_PACKAGE_PROMOTION_REVIEW_VALIDATION_OUTCOME_DRIFT",
            "R6 opening evidence review validation truth missing",
        )


def _validate_readiness(payloads: Dict[str, Dict[str, Any]]) -> None:
    readiness = payloads["package_promotion_readiness_validation"]
    decision = payloads["decision_matrix_validation"]
    no_authorization_drift = payloads["no_authorization_drift_validation"]
    if readiness.get("validation_status") != "PASS":
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_READINESS_INCOMPLETE", "package readiness validation did not pass")
    if decision.get("validation_status") != "PASS":
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_DECISION_UNSUPPORTED", "decision validation did not pass")
    if no_authorization_drift.get("no_authorization_drift") is not True:
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_READINESS_INCOMPLETE", "no-authorization-drift validation failed")
    if payloads["validation_contract"].get("recommended_validated_path") != "PACKAGE_PROMOTION_REVIEW_PACKET_NEXT":
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_DECISION_UNSUPPORTED", "prior recommendation drift")


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _validate_handoff(payloads)
    _validate_readiness(payloads)
    _ensure_authority_closed(payloads, texts)


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**VALIDATION_JSON_INPUTS, **VALIDATION_TEXT_INPUTS}.items()):
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": "file_sha256_at_package_promotion_review_packet",
            }
        )
    if not rows:
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_INPUT_BINDINGS_EMPTY", "no package review input bindings")
    return rows


def _scorecard(payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "r6_open": True,
        "r6_opening_evidence_review_validated": True,
        "package_promotion_review_packet_next": True,
        "package_promotion_review_ready": True,
        "package_promotion_authorization_ready": True,
        "package_promotion_ready": False,
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "external_audit_delta_ready": (
            payloads["external_audit_delta_readiness_validation"].get("validation_status") == "PASS"
        ),
        "public_verifier_ready": (
            payloads["public_verifier_readiness_validation"].get("validation_status") == "PASS"
        ),
        "release_truth_derivation_ready": True,
        "commercial_claim_boundary_preserved": (
            payloads["commercial_claim_boundary_validation"].get("validation_status") == "PASS"
        ),
        "no_authorization_drift": payloads["no_authorization_drift_validation"].get("no_authorization_drift") is True,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "blocking_reasons": [
            "package_promotion_requires_package_promotion_review_validation",
            "package_promotion_authorization_requires_separate_authorization_packet",
            "commercial_activation_claims_require_separate_claim_review",
        ],
    }


def _decision_matrix(scorecard: Dict[str, Any]) -> Dict[str, Any]:
    authorization_review_ready = all(
        (
            scorecard["r6_open"],
            scorecard["r6_opening_evidence_review_validated"],
            scorecard["package_promotion_review_packet_next"],
            scorecard["external_audit_delta_ready"],
            scorecard["public_verifier_ready"],
            scorecard["commercial_claim_boundary_preserved"],
            scorecard["no_authorization_drift"],
        )
    )
    recommended = RECOMMENDED_VALIDATED_PATH if authorization_review_ready else "EXTERNAL_AUDIT_DELTA_PACKET_NEXT"
    return {
        "decision_matrix_id": "B04_R6_PACKAGE_PROMOTION_REVIEW_DECISION_MATRIX_V1",
        "overall_grade": "A_REVIEWABLE" if authorization_review_ready else "B_EXTERNAL_AUDIT_DELTA_FIRST",
        "package_promotion_authorization_packet_ready": authorization_review_ready,
        "package_promotion_ready": False,
        "package_promotion_authorized": False,
        "commercial_activation_claim_status": "BOUNDARY_ONLY",
        "recommendation_is_authority": False,
        "recommended_next_path": recommended,
        "blocking_reasons": scorecard["blocking_reasons"],
        "supporting_evidence": [
            "r6_opening_evidence_review_validation_contract",
            "package_promotion_readiness_validation",
            "commercial_claim_boundary_validation",
            "external_audit_delta_readiness_validation",
            "public_verifier_readiness_validation",
            "no_authorization_drift_validation",
        ],
    }


def _authority_state() -> Dict[str, Any]:
    return {
        "runtime_cutover_executed": True,
        "r6_opening_executed": True,
        "r6_open": True,
        "r6_opening_evidence_review_validated": True,
        "package_promotion_review_packet_authored": True,
        "package_promotion_review_validated": False,
        "package_promotion_authorization_packet_authored": False,
        "package_promotion_authorized": False,
        "package_promotion_executed": False,
        "package_promotion": "UNAUTHORIZED",
        "commercial_claim_status": "BOUNDARY_ONLY",
        "commercial_activation_claim_authorized": False,
        "lobe_escalation_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "r6_open_treated_as_package_promotion": False,
        "package_promotion_treated_as_commercial_activation": False,
    }


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    input_bindings: list[Dict[str, str]],
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
        "binding_hashes": {f"{row['role']}_hash": row["sha256"] for row in input_bindings},
        "scorecard": scorecard,
        "decision_matrix": decision_matrix,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        "no_authorization_drift": scorecard["no_authorization_drift"],
        **_authority_state(),
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    role_upper = role.upper()
    prefix = "PACKAGE_PROMOTION_REVIEW_"
    artifact_suffix = role_upper[len(prefix) :] if role_upper.startswith(prefix) else role_upper
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.package_promotion_review.{role}.prep_only.v1",
        artifact_id=f"B04_R6_PACKAGE_PROMOTION_REVIEW_{artifact_suffix}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_authorize_package_promotion=True,
        cannot_execute_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_authorize_lobe_escalation=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _review(base: Dict[str, Any], *, role: str, status: str = "PASS", **extra: Any) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.package_promotion_review.{role}.contract.v1",
        artifact_id=f"B04_R6_PACKAGE_PROMOTION_REVIEW_{role.upper()}",
        review_status=status,
        **extra,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    scorecard = base["scorecard"]
    decision = base["decision_matrix"]
    blocker_rows = [
        {
            "blocker_id": "B04R6-PPR-0001",
            "category": "package_promotion",
            "severity": "BLOCKING",
            "blocks": ["PACKAGE_PROMOTION_AUTHORIZED", "PACKAGE_PROMOTION_EXECUTED"],
            "evidence_source": "b04_r6_package_promotion_review_packet_contract.json",
            "required_repair_or_next_artifact": "VALIDATE_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET",
            "status": "OPEN",
        },
        {
            "blocker_id": "B04R6-PPR-0002",
            "category": "commercial_activation_claims",
            "severity": "BLOCKING",
            "blocks": ["COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED"],
            "evidence_source": "b04_r6_package_promotion_commercial_claim_boundary_review.json",
            "required_repair_or_next_artifact": "AUTHOR_B04_R6_COMMERCIAL_ACTIVATION_CLAIM_REVIEW_PACKET",
            "status": "OPEN",
        },
    ]
    payloads: Dict[str, Any] = {
        "packet_contract": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_review.packet_contract.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET_CONTRACT",
        ),
        "packet_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_review.packet_receipt.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET_RECEIPT",
            verdict="BOUND_FOR_VALIDATION",
        ),
        "evidence_inventory": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_review.inventory.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_REVIEW_EVIDENCE_INVENTORY",
            evidence_roles=sorted(VALIDATION_JSON_INPUTS),
        ),
        "evidence_scorecard": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_review.scorecard.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_REVIEW_EVIDENCE_SCORECARD",
            scorecard=scorecard,
        ),
        "decision_matrix": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_review.decision_matrix.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_REVIEW_DECISION_MATRIX",
            decision_matrix=decision,
        ),
        "blocker_ledger": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_review.blocker_ledger.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_REVIEW_BLOCKER_LEDGER",
            blockers=blocker_rows,
        ),
        "release_truth_derivation_review": _review(
            base,
            role="release_truth_derivation",
            release_truth_derivation_ready=scorecard["release_truth_derivation_ready"],
            derived_from_receipts=True,
        ),
        "external_audit_delta_readiness_review": _review(
            base,
            role="external_audit_delta_readiness",
            external_audit_delta_ready=scorecard["external_audit_delta_ready"],
        ),
        "public_verifier_readiness_review": _review(
            base,
            role="public_verifier_readiness",
            public_verifier_ready=scorecard["public_verifier_ready"],
        ),
        "commercial_claim_boundary_review": _review(
            base,
            role="commercial_claim_boundary",
            commercial_claim_boundary_preserved=scorecard["commercial_claim_boundary_preserved"],
            allowed_claims=[
                "R6 is open under bounded packet law.",
                "Package-promotion review packet is bound for validation.",
            ],
            forbidden_claims=[
                "Package promotion is authorized.",
                "Commercial activation claims are authorized.",
            ],
        ),
        "no_authorization_drift_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_review.no_authorization_drift.receipt.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_REVIEW_NO_AUTHORIZATION_DRIFT_RECEIPT",
            validation_status="PASS",
            no_downstream_authorization_drift=True,
        ),
        "pipeline_board": _artifact(
            base,
            schema_id="kt.b04_r6.pipeline_board.v60",
            artifact_id="B04_R6_PIPELINE_BOARD",
            lanes=[
                {"lane": "RUN_B04_R6_R6_OPENING", "status": "PASSED", "authoritative": False},
                {"lane": "VALIDATE_B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET", "status": "VALIDATED", "authoritative": False},
                {"lane": "AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET", "status": "CURRENT_BOUND", "authoritative": True},
                {"lane": "VALIDATE_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET", "status": "NEXT", "authoritative": True},
                {"lane": "PACKAGE_PROMOTION_AUTHORIZATION", "status": "RECOMMENDED_NOT_AUTHORIZED", "authoritative": False},
                {"lane": "PACKAGE_PROMOTION_EXECUTION", "status": "BLOCKED", "authoritative": False},
                {"lane": "COMMERCIAL_ACTIVATION_CLAIM_REVIEW", "status": "BLOCKED", "authoritative": False},
            ],
        ),
        "future_blocker_register": _artifact(
            base,
            schema_id="kt.future_blocker_register.v12",
            artifact_id="KT_FUTURE_BLOCKER_REGISTER",
            blockers=blocker_rows,
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.operator.b04_r6_next_lawful_move_receipt.v60",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            verdict="NEXT_LAWFUL_MOVE_SET",
        ),
    }
    prep_purposes = {
        "package_promotion_review_validation_plan": "Prepare validation law for this package-promotion review packet.",
        "package_promotion_review_validation_reason_codes": "Enumerate package-promotion review validation fail-closed codes.",
        "package_promotion_authorization_packet_prep_only_draft": (
            "Prepare the possible next authorization packet; this draft does not authorize promotion."
        ),
        "package_promotion_execution_packet_prep_only_draft": (
            "Prepare possible future execution law; this draft does not execute promotion."
        ),
        "package_promotion_evidence_review_packet_prep_only_draft": (
            "Prepare possible future promotion evidence review after separate execution."
        ),
        "external_audit_delta_packet_prep_only_draft": "Prepare external audit delta packet if routed later.",
        "commercial_activation_claim_review_prep_only_draft": (
            "Prepare commercial claim review preconditions; activation claims remain forbidden."
        ),
    }
    payloads.update({role: _prep_only(base, role=role, purpose=prep_purposes[role]) for role in PREP_ONLY_ROLES})
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return (
        "# B04 R6 Package-Promotion Review Packet\n\n"
        f"Outcome: {contract['selected_outcome']}\n\n"
        f"Next lawful move: {contract['next_lawful_move']}\n\n"
        "The package-promotion review packet is bound for validation after the R6 opening evidence review "
        "validated on canonical main. It reviews release truth derivation, external audit readiness, public verifier "
        "readiness, commercial claim boundary, blocker state, and no-authorization-drift posture.\n\n"
        "This packet may recommend package-promotion authorization packet authorship after validation, but that "
        "recommendation is not authority. It does not authorize package promotion, does not execute package "
        "promotion, does not authorize commercial activation claims, and does not mutate truth/trust law.\n"
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")
    branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 package-promotion review packet")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_inputs(payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_PACKAGE_PROMOTION_REVIEW_TRUST_ZONE_FAILED", "fresh trust-zone validation must pass")
    scorecard = _scorecard(payloads)
    decision = _decision_matrix(scorecard)
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
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
