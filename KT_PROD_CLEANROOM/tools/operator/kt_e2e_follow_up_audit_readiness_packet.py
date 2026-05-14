from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_commercial_activation_evidence_review_packet_validation as evidence_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/kt-e2e-follow-up-audit-readiness-packet"
REPLAY_BRANCH_PREFIX = "replay/kt-e2e-follow-up-audit-readiness-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_PACKET"
PREVIOUS_LANE = evidence_validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = evidence_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = evidence_validation.NEXT_LAWFUL_MOVE

SELECTED_OUTCOME = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_PACKET_BOUND__AUDIT_READINESS_VALIDATION_NEXT"
NEXT_LAWFUL_MOVE = "VALIDATE_KT_E2E_FOLLOW_UP_AUDIT_READINESS_PACKET"
OUTCOME_DEFERRED = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_PACKET_INVALID__FORENSIC_AUDIT_READINESS_REVIEW_NEXT"

VALIDATED_SUCCESS_OUTCOME = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATED__READY_FOR_REAUDIT_OR_EXTERNAL_REVIEW"

FORBIDDEN_ACTIONS = (
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "FOLLOW_UP_AUDIT_READINESS_VALIDATED",
    "PUBLIC_COMMERCIAL_CLAIMS_UNBOUNDED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "SEVEN_B_AMPLIFICATION_CLAIMED_PROVEN",
)

AUTHORITY_DRIFT_KEYS = {
    "commercial_activation_claim_authorized": "RC_KT_E2E_AUDIT_READY_PACKET_CLAIM_DRIFT",
    "follow_up_audit_readiness_validated": "RC_KT_E2E_AUDIT_READY_PACKET_PREMATURE_VALIDATION",
    "truth_engine_law_changed": "RC_KT_E2E_AUDIT_READY_PACKET_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_KT_E2E_AUDIT_READY_PACKET_TRUST_ZONE_MUTATION",
    "seven_b_amplification_claimed_proven": "RC_KT_E2E_AUDIT_READY_PACKET_7B_CLAIM_DRIFT",
}

CLAIM_DRIFT_PHRASES = (
    "COMMERCIAL ACTIVATION CLAIMS AUTHORIZED",
    "KT IS PRODUCTION-COMMERCIAL LIVE",
    "FOLLOW-UP AUDIT READINESS VALIDATED",
    "READY FOR REAUDIT",
    "7B AMPLIFICATION IS PROVEN",
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_E2E_AUDIT_READY_PACKET_INPUT_MISSING",
            "RC_KT_E2E_AUDIT_READY_PACKET_OUTCOME_DRIFT",
            "RC_KT_E2E_AUDIT_READY_PACKET_NEXT_MOVE_DRIFT",
            "RC_KT_E2E_AUDIT_READY_PACKET_INPUT_HASH_MISMATCH",
            "RC_KT_E2E_AUDIT_READY_PACKET_EVIDENCE_INCOMPLETE",
            "RC_KT_E2E_AUDIT_READY_PACKET_CLAIM_TOKEN_DRIFT",
            "RC_KT_E2E_AUDIT_READY_PACKET_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

INPUTS = {
    "commercial_activation_evidence_review_validation_contract": (
        "KT_PROD_CLEANROOM/reports/b04_r6_commercial_activation_evidence_review_validation_contract.json"
    ),
    "commercial_activation_evidence_review_validation_receipt": (
        "KT_PROD_CLEANROOM/reports/b04_r6_commercial_activation_evidence_review_validation_receipt.json"
    ),
    "commercial_activation_evidence_review_validation_next_lawful_move": (
        "KT_PROD_CLEANROOM/reports/b04_r6_commercial_activation_evidence_review_validation_next_lawful_move_receipt.json"
    ),
    "commercial_activation_evidence_inventory": (
        "KT_PROD_CLEANROOM/reports/b04_r6_commercial_activation_evidence_inventory.json"
    ),
    "commercial_activation_evidence_scorecard": (
        "KT_PROD_CLEANROOM/reports/b04_r6_commercial_activation_evidence_scorecard.json"
    ),
    "claim_ceiling_current_state": "KT_PROD_CLEANROOM/reports/kt_claim_ceiling_current_state.json",
    "package_promotion_evidence_review": (
        "KT_PROD_CLEANROOM/reports/b04_r6_commercial_activation_package_promotion_evidence_review.json"
    ),
    "r6_opening_evidence_review": (
        "KT_PROD_CLEANROOM/reports/b04_r6_commercial_activation_r6_opening_evidence_review.json"
    ),
    "runtime_cutover_evidence_review": (
        "KT_PROD_CLEANROOM/reports/b04_r6_commercial_activation_runtime_cutover_evidence_review.json"
    ),
    "external_verifier_readiness_review": (
        "KT_PROD_CLEANROOM/reports/b04_r6_commercial_activation_external_verifier_readiness_review.json"
    ),
    "public_verifier_readiness_matrix": (
        "KT_PROD_CLEANROOM/reports/b04_r6_commercial_activation_public_verifier_readiness_matrix.json"
    ),
    "operator_commercial_readiness_review": "KT_PROD_CLEANROOM/reports/b04_r6_operator_commercial_readiness_review.json",
    "follow_up_audit_blocker_ledger": "KT_PROD_CLEANROOM/reports/kt_e2e_follow_up_audit_blocker_ledger.json",
    "defect_prevention_matrix": "KT_PROD_CLEANROOM/reports/kt_defect_prevention_matrix.json",
}

OUTPUTS = {
    "packet_contract": "kt_e2e_follow_up_audit_readiness_packet_contract.json",
    "packet_receipt": "kt_e2e_follow_up_audit_readiness_packet_receipt.json",
    "packet_report": "kt_e2e_follow_up_audit_readiness_packet_report.md",
    "canonical_state_board": "kt_e2e_follow_up_audit_canonical_state_board.json",
    "allowed_claims_current_state": "kt_e2e_follow_up_audit_allowed_claims_current_state.json",
    "forbidden_claims_current_state": "kt_e2e_follow_up_audit_forbidden_claims_current_state.json",
    "proof_replay_bundle_manifest": "kt_e2e_follow_up_audit_proof_replay_bundle_manifest.json",
    "external_verifier_manifest": "kt_e2e_follow_up_audit_external_verifier_manifest.json",
    "commercial_activation_evidence_review": "kt_e2e_follow_up_audit_commercial_activation_evidence_review.json",
    "package_promotion_evidence_summary": "kt_e2e_follow_up_audit_package_promotion_evidence_summary.json",
    "r6_opening_evidence_summary": "kt_e2e_follow_up_audit_r6_opening_evidence_summary.json",
    "truth_trust_unchanged_receipt": "kt_e2e_follow_up_audit_truth_trust_unchanged_receipt.json",
    "boundary_state_receipt": "kt_e2e_follow_up_audit_boundary_state_receipt.json",
    "known_limitations_ledger": "kt_e2e_follow_up_audit_known_limitations_ledger.json",
    "open_blocker_ledger": "kt_e2e_follow_up_audit_open_blocker_ledger.json",
    "validation_plan": "kt_e2e_follow_up_audit_readiness_validation_plan.json",
    "validation_reason_codes": "kt_e2e_follow_up_audit_readiness_validation_reason_codes.json",
    "external_audit_delta_prep_only": "kt_e2e_external_audit_delta_packet_prep_only_draft.json",
    "commercial_claim_authorization_prep_only": "kt_e2e_commercial_claim_authorization_packet_prep_only_draft.json",
    "public_reaudit_packet_prep_only": "kt_e2e_public_reaudit_packet_prep_only_draft.json",
    "next_lawful_move": "kt_e2e_follow_up_audit_readiness_next_lawful_move_receipt.json",
}

PREP_ONLY_ROLES = (
    "external_audit_delta_prep_only",
    "commercial_claim_authorization_prep_only",
    "public_reaudit_packet_prep_only",
)


class LaneFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise LaneFailure(code, detail)


def _walk(value: Any, parent_key: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk(item, str(key))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                yield from _walk(item, parent_key)
            else:
                yield parent_key, item


def _is_negative_field(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in ("forbidden", "blocked", "prohibited", "cannot", "disallowed"))


def _contains_forbidden_claim(value: str) -> bool:
    normalized = value.upper()
    return any(phrase in normalized for phrase in CLAIM_DRIFT_PHRASES)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_KT_E2E_AUDIT_READY_PACKET_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_KT_E2E_AUDIT_READY_PACKET_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_KT_E2E_AUDIT_READY_PACKET_INPUT_MISSING", f"{label} must be a JSON object")
    return payload


def _payloads(root: Path) -> Dict[str, Dict[str, Any]]:
    return {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted")
            if isinstance(value, str) and not _is_negative_field(key) and _contains_forbidden_claim(value):
                _fail("RC_KT_E2E_AUDIT_READY_PACKET_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["commercial_activation_evidence_review_validation_contract"]
    receipt = payloads["commercial_activation_evidence_review_validation_receipt"]
    next_move = payloads["commercial_activation_evidence_review_validation_next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_KT_E2E_AUDIT_READY_PACKET_OUTCOME_DRIFT", "validation contract outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_KT_E2E_AUDIT_READY_PACKET_OUTCOME_DRIFT", "validation receipt outcome drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_KT_E2E_AUDIT_READY_PACKET_NEXT_MOVE_DRIFT", "next lawful move drift")
    for key in (
        "commercial_activation_evidence_review_validated",
        "commercial_activation_executed",
        "commercial_activation_passed",
        "package_promotion_passed",
        "r6_open",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    ):
        if contract.get(key) is not True:
            _fail("RC_KT_E2E_AUDIT_READY_PACKET_EVIDENCE_INCOMPLETE", f"{key} is not true")
    for key in (
        "commercial_activation_claim_authorized",
        "follow_up_audit_readiness_validated",
        "seven_b_amplification_claimed_proven",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
    ):
        if contract.get(key) is not False:
            _fail(AUTHORITY_DRIFT_KEYS.get(key, "RC_KT_E2E_AUDIT_READY_PACKET_EVIDENCE_INCOMPLETE"), key)


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows = []
    for role, raw in sorted(INPUTS.items()):
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_E2E_AUDIT_READY_PACKET_INPUT_MISSING", raw)
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    trust_zone_validation: Dict[str, Any],
    input_bindings: list[Dict[str, str]],
) -> Dict[str, Any]:
    return {
        "schema_version": "v1",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_branch_head": head,
        "current_main_head": current_main_head,
        "current_branch": branch,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "validated_success_outcome": VALIDATED_SUCCESS_OUTCOME,
        "allowed_outcomes": [SELECTED_OUTCOME, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "binding_hashes": {f"{row['role']}_hash": row["sha256"] for row in input_bindings},
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        "r6_open": True,
        "package_promotion_passed": True,
        "commercial_activation_executed": True,
        "commercial_activation_passed": True,
        "commercial_activation_evidence_review_validated": True,
        "follow_up_audit_readiness_packet_authored": True,
        "follow_up_audit_readiness_validated": False,
        "commercial_activation_claim_authorized": False,
        "seven_b_amplification_claimed_proven": False,
        "truth_engine_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_changed": False,
        "trust_zone_law_unchanged": True,
        "cannot_authorize_commercial_activation_claims": True,
        "cannot_claim_follow_up_audit_readiness_validated": True,
        "cannot_claim_7b_amplification_proven": True,
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.e2e.follow_up_audit_readiness.{role}.prep_only.v1",
        artifact_id=f"KT_E2E_FOLLOW_UP_AUDIT_READINESS_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_authorize_commercial_activation_claims=True,
        cannot_claim_follow_up_audit_readiness_validated=True,
        cannot_claim_7b_amplification_proven=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    payloads: Dict[str, Any] = {
        "packet_contract": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.packet_contract.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_READINESS_PACKET_CONTRACT",
            packet_summary="Follow-up audit readiness packet is authored and awaits validation.",
        ),
        "packet_receipt": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.packet_receipt.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_READINESS_PACKET_RECEIPT",
            verdict="FOLLOW_UP_AUDIT_READINESS_PACKET_BOUND_VALIDATION_NEXT",
        ),
        "canonical_state_board": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.canonical_state_board.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_CANONICAL_STATE_BOARD",
            state={
                "r6": "OPEN",
                "package_promotion": "PASSED",
                "commercial_activation": "PASSED",
                "commercial_activation_evidence_review": "VALIDATED",
                "follow_up_audit_readiness": "PACKET_AUTHORED_VALIDATION_NEXT",
                "commercial_activation_claims": "UNAUTHORIZED",
                "seven_b_amplification": "NOT_PROVEN",
            },
        ),
        "allowed_claims_current_state": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.allowed_claims.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_ALLOWED_CLAIMS_CURRENT_STATE",
            allowed_claims=[
                "R6 is open.",
                "Package promotion passed.",
                "Commercial activation ran and passed under packet law.",
                "Commercial activation evidence review is validated.",
                "Follow-up audit readiness packet is authored and awaiting validation.",
            ],
        ),
        "forbidden_claims_current_state": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.forbidden_claims.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_FORBIDDEN_CLAIMS_CURRENT_STATE",
            forbidden_claims=[
                "Commercial activation claims are authorized.",
                "Follow-up audit readiness is validated.",
                "KT is production-commercial live.",
                "7B amplification is proven.",
            ],
        ),
        "proof_replay_bundle_manifest": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.proof_replay_bundle_manifest.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_PROOF_REPLAY_BUNDLE_MANIFEST",
            replay_bundle_roles=list(INPUTS),
        ),
        "external_verifier_manifest": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.external_verifier_manifest.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_EXTERNAL_VERIFIER_MANIFEST",
            verifier_status="READY_FOR_VALIDATION_REVIEW",
            external_review_required=True,
        ),
        "commercial_activation_evidence_review": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.commercial_activation_evidence_review.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_COMMERCIAL_ACTIVATION_EVIDENCE_REVIEW",
            review_status="BOUND",
            grade="PASS",
        ),
        "package_promotion_evidence_summary": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.package_promotion_evidence_summary.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_PACKAGE_PROMOTION_EVIDENCE_SUMMARY",
            review_status="BOUND",
            package_promotion_passed=True,
        ),
        "r6_opening_evidence_summary": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.r6_opening_evidence_summary.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_R6_OPENING_EVIDENCE_SUMMARY",
            review_status="BOUND",
            r6_open=True,
        ),
        "truth_trust_unchanged_receipt": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.truth_trust_unchanged_receipt.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_TRUTH_TRUST_UNCHANGED_RECEIPT",
            truth_engine_law_unchanged=True,
            trust_zone_law_unchanged=True,
        ),
        "boundary_state_receipt": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.boundary_state_receipt.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_BOUNDARY_STATE_RECEIPT",
            canonical_lab_archive_commercial_boundary_preserved=True,
        ),
        "known_limitations_ledger": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.known_limitations_ledger.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_KNOWN_LIMITATIONS_LEDGER",
            limitations=[
                "commercial activation claims require separate claim authority",
                "external audit/re-audit has not yet run",
                "7B amplification remains unproven benchmark prep",
            ],
        ),
        "open_blocker_ledger": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.open_blocker_ledger.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_OPEN_BLOCKER_LEDGER",
            blockers=[
                "follow_up_audit_readiness_packet_not_validated",
                "external_reaudit_not_complete",
                "commercial_claim_authorization_not_validated",
            ],
        ),
        "validation_plan": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.validation_plan.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATION_PLAN",
            required_validations=[
                "canonical state board is bound",
                "proof/replay bundle is complete",
                "allowed and forbidden claims remain mechanically derived",
                "truth/trust law unchanged",
            ],
        ),
        "validation_reason_codes": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.validation_reason_codes.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATION_REASON_CODES",
            reason_code_taxonomy=list(REASON_CODES),
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.next_lawful_move_receipt.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_READINESS_NEXT_LAWFUL_MOVE_RECEIPT",
            receipt_type="NEXT_LAWFUL_MOVE",
        ),
    }
    payloads["external_audit_delta_prep_only"] = _prep_only(
        base, role="external_audit_delta_prep_only", purpose="Prepare external audit delta packet after validation."
    )
    payloads["commercial_claim_authorization_prep_only"] = _prep_only(
        base,
        role="commercial_claim_authorization_prep_only",
        purpose="Prepare bounded commercial claim authorization path after validation.",
    )
    payloads["public_reaudit_packet_prep_only"] = _prep_only(
        base, role="public_reaudit_packet_prep_only", purpose="Prepare public re-audit packet after validation."
    )
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# KT E2E Follow-Up Audit Readiness Packet",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "The packet organizes KT's follow-up audit readiness evidence and routes to validation.",
            "Commercial activation claims remain unauthorized. Follow-up audit readiness is not validated yet.",
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
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before KT E2E follow-up audit readiness packet")
    payloads = _payloads(root)
    _validate_handoff(payloads)
    _ensure_authority_closed(payloads)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_E2E_AUDIT_READY_PACKET_TRUST_ZONE_FAILED", "trust-zone validation failed")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        trust_zone_validation=trust_zone_validation,
        input_bindings=_input_bindings(root),
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
