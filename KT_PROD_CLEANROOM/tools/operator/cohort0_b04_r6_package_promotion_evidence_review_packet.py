from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_package_promotion as promotion
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/b04-r6-package-promotion-evidence-review-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-package-promotion-evidence-review-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_PACKET"
PREVIOUS_LANE = promotion.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = promotion.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = promotion.NEXT_LAWFUL_MOVE

SELECTED_OUTCOME = (
    "B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_PACKET_BOUND__"
    "PACKAGE_PROMOTION_EVIDENCE_REVIEW_VALIDATION_NEXT"
)
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_PACKET"
OUTCOME_DEFERRED = "B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_PACKET_INVALID__FORENSIC_REVIEW_NEXT"

RECOMMENDED_NEXT_PATH = "COMMERCIAL_ACTIVATION_REVIEW_PACKET_NEXT"
VALIDATION_SUCCESS_OUTCOMES = (
    "B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_VALIDATED__COMMERCIAL_ACTIVATION_REVIEW_PACKET_NEXT",
    "B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_VALIDATED__EXTERNAL_AUDIT_DELTA_PACKET_NEXT",
    "B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_VALIDATED__LIMITED_PACKAGE_CONTINUATION_NEXT",
    "B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_VALIDATED__PACKAGE_ROLLBACK_OR_REPAIR_NEXT",
)

FORBIDDEN_ACTIONS = (
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "BENCHMARK_PREP_TREATED_AS_PACKAGE_AUTHORITY",
    "SEVEN_B_AMPLIFICATION_CLAIMED_PROVEN",
)

AUTHORITY_DRIFT_KEYS = {
    "commercial_activation_claim_authorized": "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_TRUST_ZONE_MUTATION",
    "benchmark_prep_authorizes_package_promotion": "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_BENCHMARK_AUTHORITY_DRIFT",
    "seven_b_amplification_claimed_proven": "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_7B_CLAIM_DRIFT",
}

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_PROMOTION_MISSING",
            "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_OUTCOME_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_NEXT_MOVE_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_INCOMPLETE",
            "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_PREP_ONLY_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

PROMOTION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in promotion.OUTPUTS.items()
    if filename.endswith(".json")
}
PROMOTION_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in promotion.OUTPUTS.items()
    if not filename.endswith(".json")
}

REVIEW_CONTRACT_ROLES = (
    "release_truth_review",
    "external_verifier_readiness_review",
    "commercial_claim_ceiling_review",
    "operator_runbook_review",
    "deployment_profile_review",
    "rollback_review",
    "incident_freeze_review",
    "data_governance_review",
    "public_verifier_bundle_review",
    "clean_distributable_review",
)

PREP_ONLY_ROLES = (
    "commercial_activation_review_packet_prep_only_draft",
    "external_audit_delta_packet_prep_only_draft",
    "limited_package_continuation_packet_prep_only_draft",
    "package_rollback_or_repair_packet_prep_only_draft",
)

OUTPUTS = {
    "review_contract": "b04_r6_package_promotion_evidence_review_packet_contract.json",
    "review_receipt": "b04_r6_package_promotion_evidence_review_packet_receipt.json",
    "review_report": "b04_r6_package_promotion_evidence_review_packet_report.md",
    "evidence_inventory": "b04_r6_package_promotion_evidence_inventory.json",
    "evidence_scorecard": "b04_r6_package_promotion_evidence_scorecard.json",
    "post_promotion_decision_matrix": "b04_r6_package_promotion_post_run_decision_matrix.json",
    "commercial_activation_blocker_ledger": "b04_r6_commercial_activation_blocker_ledger.json",
    "release_truth_review": "b04_r6_package_promotion_release_truth_review.json",
    "external_verifier_readiness_review": "b04_r6_package_promotion_external_verifier_readiness_review.json",
    "commercial_claim_ceiling_review": "b04_r6_package_promotion_commercial_claim_ceiling_review.json",
    "operator_runbook_review": "b04_r6_package_promotion_operator_runbook_review.json",
    "deployment_profile_review": "b04_r6_package_promotion_deployment_profile_review.json",
    "rollback_review": "b04_r6_package_promotion_rollback_review.json",
    "incident_freeze_review": "b04_r6_package_promotion_incident_freeze_review.json",
    "data_governance_review": "b04_r6_package_promotion_data_governance_review.json",
    "public_verifier_bundle_review": "b04_r6_package_promotion_public_verifier_bundle_review.json",
    "clean_distributable_review": "b04_r6_package_promotion_clean_distributable_review.json",
    "no_authority_drift_receipt": "b04_r6_package_promotion_evidence_review_no_authority_drift_receipt.json",
    "validation_plan": "b04_r6_package_promotion_evidence_review_validation_plan.json",
    "validation_reason_codes": "b04_r6_package_promotion_evidence_review_validation_reason_codes.json",
    "commercial_activation_review_packet_prep_only_draft": (
        "b04_r6_commercial_activation_review_packet_prep_only_draft.json"
    ),
    "external_audit_delta_packet_prep_only_draft": "b04_r6_external_audit_delta_packet_prep_only_draft.json",
    "limited_package_continuation_packet_prep_only_draft": (
        "b04_r6_limited_package_continuation_packet_prep_only_draft.json"
    ),
    "package_rollback_or_repair_packet_prep_only_draft": (
        "b04_r6_package_rollback_or_repair_packet_prep_only_draft.json"
    ),
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


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk_items(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_items(item)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_PROMOTION_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_PROMOTION_MISSING", str(exc))


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in PROMOTION_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in PROMOTION_TEXT_INPUTS.items()}
    return payloads, texts


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk_items(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted non-false")
            if isinstance(value, str) and "7B AMPLIFICATION IS PROVEN" in value.upper():
                _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        for phrase in ("COMMERCIAL ACTIVATION AUTHORIZED", "7B AMPLIFICATION IS PROVEN"):
            if phrase in normalized:
                _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["promotion_contract"]
    receipt = payloads["promotion_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_OUTCOME_DRIFT", "promotion outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_OUTCOME_DRIFT", "promotion receipt drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_NEXT_MOVE_DRIFT", "promotion next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_NEXT_MOVE_DRIFT", "next-lawful-move receipt drift")
    for key in (
        "r6_open",
        "package_promotion_execution_packet_validated",
        "package_promotion_executed",
        "package_promotion_passed",
        "package_promotion_evidence_review_packet_next",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    ):
        if contract.get(key) is not True:
            _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_INCOMPLETE", f"{key} is not true")
    for key in (
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
        "benchmark_prep_authorizes_package_promotion",
        "seven_b_amplification_claimed_proven",
    ):
        if contract.get(key) is not False:
            _fail(AUTHORITY_DRIFT_KEYS.get(key, "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_INCOMPLETE"), key)
    if not contract.get("binding_hashes"):
        _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_INPUT_BINDINGS_EMPTY", "promotion bindings empty")


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _ensure_authority_closed(payloads, texts)
    _validate_handoff(payloads)
    for role in promotion.PREP_ONLY_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY":
            _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_PREP_ONLY_DRIFT", f"{role} prep boundary drift")


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**PROMOTION_JSON_INPUTS, **PROMOTION_TEXT_INPUTS}.items()):
        rows.append({"role": role, "path": raw, "sha256": file_sha256(root / raw)})
    return rows


def _guard() -> Dict[str, Any]:
    return {
        "r6_open": True,
        "package_promotion_executed": True,
        "package_promotion_passed": True,
        "package_promotion_evidence_review_packet_authored": True,
        "package_promotion_evidence_review_validated": False,
        "commercial_activation_review_packet_next_recommended": True,
        "commercial_activation_claim_authorized": False,
        "benchmark_prep_authorizes_package_promotion": False,
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
        "current_branch": branch,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "allowed_outcomes": [SELECTED_OUTCOME, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "validation_success_outcomes": list(VALIDATION_SUCCESS_OUTCOMES),
        "recommended_next_path": RECOMMENDED_NEXT_PATH,
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "reason_codes": list(REASON_CODES),
        "input_bindings": input_bindings,
        "binding_hashes": {f"{row['role']}_hash": row["sha256"] for row in input_bindings},
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        **_guard(),
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _review(base: Dict[str, Any], *, role: str, grade: str, evidence_role: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.package_promotion_evidence_review.{role}.v1",
        artifact_id=f"B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_{role.upper()}",
        review_role=role,
        review_status="BOUND",
        grade=grade,
        evidence_role=evidence_role,
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.package_promotion_evidence_review.{role}.prep_only.v1",
        artifact_id=f"B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_authorize_commercial_activation_claims=True,
        cannot_claim_7b_amplification_proven=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    payloads: Dict[str, Any] = {
        "review_contract": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_evidence_review.contract.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_PACKET_CONTRACT",
            review_summary="Package-promotion evidence is organized for validation; commercial activation is not authorized.",
        ),
        "review_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_evidence_review.receipt.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_PACKET_RECEIPT",
            verdict="PACKAGE_PROMOTION_EVIDENCE_REVIEW_BOUND_VALIDATION_NEXT",
        ),
        "evidence_inventory": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_evidence_review.inventory.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EVIDENCE_INVENTORY",
            evidence_roles=list(promotion.PROMOTION_RECEIPT_ROLES),
            evidence_hashes={role: base["binding_hashes"].get(f"{role}_hash") for role in promotion.PROMOTION_RECEIPT_ROLES},
        ),
        "evidence_scorecard": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_evidence_review.scorecard.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EVIDENCE_SCORECARD",
            overall_grade="A_REVIEWABLE",
            category_grades={role: "PASS" for role in promotion.PROMOTION_RECEIPT_ROLES},
        ),
        "post_promotion_decision_matrix": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_evidence_review.decision_matrix.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_POST_RUN_DECISION_MATRIX",
            package_promotion_result="PASSED",
            recommended_next_path=RECOMMENDED_NEXT_PATH,
            commercial_activation_review_ready=True,
            commercial_activation_claim_status="UNAUTHORIZED_REVIEW_ONLY",
            blocking_reasons=["commercial_activation_requires_evidence_review_validation"],
        ),
        "commercial_activation_blocker_ledger": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_evidence_review.commercial_activation_blockers.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_BLOCKER_LEDGER",
            blockers=[
                "package_promotion_evidence_review_not_validated",
                "commercial_activation_review_packet_not_authored",
                "commercial_activation_claim_validation_not_complete",
            ],
        ),
        "no_authority_drift_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_evidence_review.no_authority_drift.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_NO_AUTHORITY_DRIFT_RECEIPT",
            drift_detected=False,
        ),
        "validation_plan": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_evidence_review.validation_plan.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_VALIDATION_PLAN",
            required_validations=[
                "promotion evidence is bound",
                "decision matrix is justified",
                "commercial activation remains unauthorized",
                "truth/trust law unchanged",
            ],
        ),
        "validation_reason_codes": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_evidence_review.reason_codes.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_REASON_CODES",
            reason_code_taxonomy=list(REASON_CODES),
        ),
        "pipeline_board": _artifact(
            base,
            schema_id="kt.b04_r6.pipeline_board.v1",
            artifact_id="B04_R6_PIPELINE_BOARD",
            r6="OPEN",
            package_promotion="PASSED",
            package_promotion_evidence_review="BOUND_VALIDATION_NEXT",
            commercial_activation="BLOCKED",
        ),
        "claim_ceiling_current_state": _artifact(
            base,
            schema_id="kt.claim_ceiling.current_state.v1",
            artifact_id="KT_CLAIM_CEILING_CURRENT_STATE",
            allowed_claims=[
                "R6 is open.",
                "Package promotion passed under the validated execution packet.",
                "Package promotion evidence review packet is authored and awaits validation.",
                "Commercial activation is not authorized.",
            ],
            forbidden_claims=[
                "Commercial activation is authorized.",
                "KT is production-commercial live.",
                "7B amplification is proven.",
            ],
        ),
        "future_blocker_register": _artifact(
            base,
            schema_id="kt.future_blocker_register.v1",
            artifact_id="KT_FUTURE_BLOCKER_REGISTER",
            blockers=[
                "package_promotion_evidence_review_not_validated",
                "commercial_activation_review_packet_not_authored",
                "external_audit_delta_not_validated",
            ],
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.next_lawful_move_receipt.v1",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
    }
    review_sources = {
        "release_truth_review": "release_truth_receipt",
        "external_verifier_readiness_review": "external_verifier_readiness_receipt",
        "commercial_claim_ceiling_review": "commercial_claim_boundary_receipt",
        "operator_runbook_review": "operator_runbook_receipt",
        "deployment_profile_review": "deployment_profile_receipt",
        "rollback_review": "rollback_receipt",
        "incident_freeze_review": "incident_freeze_receipt",
        "data_governance_review": "data_governance_receipt",
        "public_verifier_bundle_review": "public_verifier_bundle_receipt",
        "clean_distributable_review": "clean_distributable_receipt",
    }
    for role, evidence_role in review_sources.items():
        payloads[role] = _review(base, role=role, grade="PASS", evidence_role=evidence_role)
    prep_purposes = {
        "commercial_activation_review_packet_prep_only_draft": "Prepare commercial activation review packet.",
        "external_audit_delta_packet_prep_only_draft": "Prepare external audit delta packet.",
        "limited_package_continuation_packet_prep_only_draft": "Prepare limited package continuation path.",
        "package_rollback_or_repair_packet_prep_only_draft": "Prepare package rollback or repair path.",
    }
    for role, purpose in prep_purposes.items():
        payloads[role] = _prep_only(base, role=role, purpose=purpose)
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Package Promotion Evidence Review Packet",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "The packet binds package-promotion evidence and recommends commercial-activation review packet authorship.",
            "Recommendation is not authorization. Commercial activation claims remain unauthorized.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 package-promotion evidence review")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_inputs(payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_TRUST_ZONE_FAILED", "fresh trust-zone validation must pass")
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
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
    parser = argparse.ArgumentParser(description=AUTHORITATIVE_LANE)
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
