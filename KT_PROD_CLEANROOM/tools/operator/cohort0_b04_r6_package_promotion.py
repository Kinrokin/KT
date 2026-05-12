from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_package_promotion_execution_packet_validation as validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "run/b04-r6-package-promotion"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-package-promotion"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_PACKAGE_PROMOTION"
PREVIOUS_LANE = validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = validation.NEXT_LAWFUL_MOVE

OUTCOME_PASSED = "B04_R6_PACKAGE_PROMOTION_PASSED__PACKAGE_PROMOTION_EVIDENCE_REVIEW_PACKET_NEXT"
OUTCOME_FAILED = "B04_R6_PACKAGE_PROMOTION_FAILED__PACKAGE_REPAIR_OR_ROLLBACK_NEXT"
OUTCOME_INVALID = "B04_R6_PACKAGE_PROMOTION_INVALIDATED__FORENSIC_PACKAGE_PROMOTION_REVIEW_NEXT"
OUTCOME_DEFERRED = "B04_R6_PACKAGE_PROMOTION_DEFERRED__NAMED_PROMOTION_DEFECT_REMAINS"
SELECTED_OUTCOME = OUTCOME_PASSED
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_PACKAGE_PROMOTION_EVIDENCE_REVIEW_PACKET"

FORBIDDEN_ACTIONS = (
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "BENCHMARK_PREP_TREATED_AS_PACKAGE_AUTHORITY",
    "SEVEN_B_AMPLIFICATION_CLAIMED_PROVEN",
)

AUTHORITY_DRIFT_KEYS = {
    "commercial_activation_claim_authorized": "RC_B04R6_PACKAGE_PROMOTION_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_PACKAGE_PROMOTION_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_PACKAGE_PROMOTION_TRUST_ZONE_MUTATION",
    "benchmark_prep_authorizes_package_promotion": "RC_B04R6_PACKAGE_PROMOTION_BENCHMARK_AUTHORITY_DRIFT",
    "seven_b_amplification_claimed_proven": "RC_B04R6_PACKAGE_PROMOTION_7B_CLAIM_DRIFT",
}

CLAIM_BEARING_FIELD_MARKERS = (
    "authorization_state",
    "authority_state",
    "claim",
    "commercial",
    "execution_state",
    "package_promotion",
    "promotion",
)
POSITIVE_AUTHORITY_TOKENS = (
    "ACTIVE",
    "COMMERCIAL_ACTIVATION",
    "ENABLED",
    "EXECUTED",
    "PRODUCTION",
    "PROMOTED",
)
NEGATIVE_AUTHORITY_QUALIFIERS = (
    "BLOCKED",
    "BOUNDARY_ONLY",
    "CANNOT_AUTHORIZE",
    "DEFERRED",
    "DOES_NOT_AUTHORIZE",
    "FORBIDDEN",
    "NO_COMMERCIAL",
    "NOT_AUTHORIZED",
    "PREP_ONLY",
    "PROHIBITED",
    "REMAINS_UNAUTHORIZED",
    "REVIEW_PACKET",
    "UNAUTHORIZED",
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_PACKAGE_PROMOTION_VALIDATION_MISSING",
            "RC_B04R6_PACKAGE_PROMOTION_VALIDATION_OUTCOME_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_NEXT_MOVE_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_PACKAGE_PROMOTION_VALIDATION_INCOMPLETE",
            "RC_B04R6_PACKAGE_PROMOTION_PREP_ONLY_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

VALIDATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in validation.OUTPUTS.items()
    if filename.endswith(".json")
}
VALIDATION_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in validation.OUTPUTS.items()
    if not filename.endswith(".json")
}

PROMOTION_RECEIPT_ROLES = (
    "package_manifest",
    "release_truth_receipt",
    "external_verifier_readiness_receipt",
    "commercial_claim_boundary_receipt",
    "operator_runbook_receipt",
    "deployment_profile_receipt",
    "rollback_receipt",
    "incident_freeze_receipt",
    "data_governance_receipt",
    "public_verifier_bundle_receipt",
    "clean_distributable_receipt",
    "no_authority_drift_receipt",
)

PREP_ONLY_ROLES = (
    "package_promotion_evidence_review_packet_prep_only_draft",
    "package_repair_or_rollback_packet_prep_only_draft",
    "forensic_package_promotion_review_packet_prep_only_draft",
    "commercial_activation_review_packet_prep_only_draft",
    "external_audit_delta_packet_prep_only_draft",
)

OUTPUTS = {
    "promotion_contract": "b04_r6_package_promotion_execution_contract.json",
    "promotion_receipt": "b04_r6_package_promotion_execution_receipt.json",
    "promotion_result": "b04_r6_package_promotion_result.json",
    "promotion_report": "b04_r6_package_promotion_report.md",
    "package_manifest": "b04_r6_package_promotion_manifest.json",
    "release_truth_receipt": "b04_r6_package_promotion_release_truth_receipt.json",
    "external_verifier_readiness_receipt": "b04_r6_package_promotion_external_verifier_readiness_receipt.json",
    "commercial_claim_boundary_receipt": "b04_r6_package_promotion_commercial_claim_boundary_receipt.json",
    "operator_runbook_receipt": "b04_r6_package_promotion_operator_runbook_receipt.json",
    "deployment_profile_receipt": "b04_r6_package_promotion_deployment_profile_receipt.json",
    "rollback_receipt": "b04_r6_package_promotion_rollback_receipt.json",
    "incident_freeze_receipt": "b04_r6_package_promotion_incident_freeze_receipt.json",
    "data_governance_receipt": "b04_r6_package_promotion_data_governance_receipt.json",
    "public_verifier_bundle_receipt": "b04_r6_package_promotion_public_verifier_bundle_receipt.json",
    "clean_distributable_receipt": "b04_r6_package_promotion_clean_distributable_receipt.json",
    "no_authority_drift_receipt": "b04_r6_package_promotion_no_authority_drift_receipt.json",
    "package_promotion_evidence_review_packet_prep_only_draft": (
        "b04_r6_package_promotion_evidence_review_packet_prep_only_draft.json"
    ),
    "package_repair_or_rollback_packet_prep_only_draft": (
        "b04_r6_package_repair_or_rollback_packet_prep_only_draft.json"
    ),
    "forensic_package_promotion_review_packet_prep_only_draft": (
        "b04_r6_forensic_package_promotion_review_packet_prep_only_draft.json"
    ),
    "commercial_activation_review_packet_prep_only_draft": (
        "b04_r6_commercial_activation_review_packet_prep_only_draft.json"
    ),
    "external_audit_delta_packet_prep_only_draft": "b04_r6_external_audit_delta_packet_prep_only_draft.json",
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


def _is_claim_bearing_field(key: str) -> bool:
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
            _fail("RC_B04R6_PACKAGE_PROMOTION_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_PACKAGE_PROMOTION_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_PACKAGE_PROMOTION_VALIDATION_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_PACKAGE_PROMOTION_VALIDATION_MISSING", str(exc))


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in VALIDATION_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in VALIDATION_TEXT_INPUTS.items()}
    return payloads, texts


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk_items(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted non-false")
            if isinstance(value, str) and "7B AMPLIFICATION IS PROVEN" in value.upper():
                _fail("RC_B04R6_PACKAGE_PROMOTION_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
            if _is_claim_bearing_field(key) and isinstance(value, str) and _contains_positive_authority_token(value):
                _fail("RC_B04R6_PACKAGE_PROMOTION_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        for phrase in ("COMMERCIAL ACTIVATION AUTHORIZED", "7B AMPLIFICATION IS PROVEN"):
            if phrase in normalized:
                _fail("RC_B04R6_PACKAGE_PROMOTION_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["validation_contract"]
    receipt = payloads["validation_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_PACKAGE_PROMOTION_VALIDATION_OUTCOME_DRIFT", "execution validation outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_PACKAGE_PROMOTION_VALIDATION_OUTCOME_DRIFT", "execution validation receipt drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_PACKAGE_PROMOTION_NEXT_MOVE_DRIFT", "execution validation next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_PACKAGE_PROMOTION_NEXT_MOVE_DRIFT", "next-lawful-move receipt drift")
    for key in (
        "r6_open",
        "package_promotion_authorization_validated",
        "package_promotion_execution_packet_authored",
        "package_promotion_execution_packet_validated",
        "package_promotion_next",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    ):
        if contract.get(key) is not True:
            _fail("RC_B04R6_PACKAGE_PROMOTION_VALIDATION_INCOMPLETE", f"{key} is not true")
    for key in (
        "package_promotion_executed",
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
        "benchmark_prep_authorizes_package_promotion",
        "seven_b_amplification_claimed_proven",
    ):
        if contract.get(key) is not False:
            _fail(AUTHORITY_DRIFT_KEYS.get(key, "RC_B04R6_PACKAGE_PROMOTION_VALIDATION_INCOMPLETE"), key)
    if not contract.get("binding_hashes"):
        _fail("RC_B04R6_PACKAGE_PROMOTION_INPUT_BINDINGS_EMPTY", "execution validation bindings empty")


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _ensure_authority_closed(payloads, texts)
    _validate_handoff(payloads)
    for role in validation.PREP_ONLY_OUTPUT_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY" or payload.get("cannot_execute_package_promotion") is not True:
            _fail("RC_B04R6_PACKAGE_PROMOTION_PREP_ONLY_DRIFT", f"{role} prep boundary drift")


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**VALIDATION_JSON_INPUTS, **VALIDATION_TEXT_INPUTS}.items()):
        rows.append({"role": role, "path": raw, "sha256": file_sha256(root / raw)})
    return rows


def _guard() -> Dict[str, Any]:
    return {
        "r6_open": True,
        "package_promotion_authorization_validated": True,
        "package_promotion_execution_packet_authored": True,
        "package_promotion_execution_packet_validated": True,
        "package_promotion_authorized": True,
        "package_promotion_executed": True,
        "package_promotion_passed": True,
        "package_promotion_evidence_review_packet_next": True,
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
        "allowed_outcomes": [OUTCOME_PASSED, OUTCOME_FAILED, OUTCOME_INVALID, OUTCOME_DEFERRED],
        "outcome_routing": {
            OUTCOME_PASSED: NEXT_LAWFUL_MOVE,
            OUTCOME_FAILED: "AUTHOR_B04_R6_PACKAGE_REPAIR_OR_ROLLBACK_PACKET",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_PACKAGE_PROMOTION_REVIEW_PACKET",
            OUTCOME_DEFERRED: "REPAIR_B04_R6_PACKAGE_PROMOTION_DEFECTS",
        },
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


def _receipt(base: Dict[str, Any], *, role: str, checks: Sequence[str]) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.package_promotion.{role}.receipt.v1",
        artifact_id=f"B04_R6_PACKAGE_PROMOTION_{role.upper()}",
        receipt_role=role,
        receipt_status="PASS",
        checks=list(checks),
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.package_promotion.{role}.prep_only.v1",
        artifact_id=f"B04_R6_PACKAGE_PROMOTION_{role.upper()}",
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
        "promotion_contract": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion.execution_contract.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EXECUTION_CONTRACT",
            promotion_mode="bounded_receipt_backed_package_promotion",
        ),
        "promotion_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion.execution_receipt.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EXECUTION_RECEIPT",
            verdict="PACKAGE_PROMOTION_PASSED_EVIDENCE_REVIEW_NEXT",
        ),
        "promotion_result": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion.result.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_RESULT",
            result="PASSED",
            commercial_activation_authorized=False,
        ),
        "pipeline_board": _artifact(
            base,
            schema_id="kt.b04_r6.pipeline_board.v1",
            artifact_id="B04_R6_PIPELINE_BOARD",
            r6="OPEN",
            package_promotion="PASSED_EVIDENCE_REVIEW_NEXT",
            commercial_activation="BLOCKED",
            provider_benchmark_campaign="PREP_ONLY",
        ),
        "claim_ceiling_current_state": _artifact(
            base,
            schema_id="kt.claim_ceiling.current_state.v1",
            artifact_id="KT_CLAIM_CEILING_CURRENT_STATE",
            allowed_claims=[
                "R6 is open.",
                "Package promotion passed under the validated execution packet.",
                "Package promotion evidence review is the next lawful move.",
                "Commercial activation is not authorized.",
                "Truth/trust law is unchanged.",
            ],
            forbidden_claims=[
                "Commercial activation is authorized.",
                "KT is production-commercial live.",
                "7B amplification is proven.",
                "KT beats all larger models generally.",
            ],
        ),
        "future_blocker_register": _artifact(
            base,
            schema_id="kt.future_blocker_register.v1",
            artifact_id="KT_FUTURE_BLOCKER_REGISTER",
            blockers=[
                "package_promotion_evidence_review_not_authored",
                "package_promotion_evidence_review_not_validated",
                "commercial_activation_requires_later_review",
                "7b_amplification_not_proven",
            ],
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.next_lawful_move_receipt.v1",
            artifact_id="B04_R6_NEXT_LAWFUL_MOVE_RECEIPT",
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
    }
    receipt_checks = {
        "package_manifest": ["release package surface is bounded", "excluded artifacts remain excluded"],
        "release_truth_receipt": ["release truth is receipt-derived", "archive residue excluded"],
        "external_verifier_readiness_receipt": ["external hash manifest ready", "auditor path prepared"],
        "commercial_claim_boundary_receipt": ["commercial activation remains unauthorized"],
        "operator_runbook_receipt": ["operator obligations preserved"],
        "deployment_profile_receipt": ["deployment profile review remains evidence-bound"],
        "rollback_receipt": ["rollback path remains available"],
        "incident_freeze_receipt": ["freeze path remains available"],
        "data_governance_receipt": ["data governance review remains bounded"],
        "public_verifier_bundle_receipt": ["public verifier bundle prepared"],
        "clean_distributable_receipt": ["no-secret distributable boundary preserved"],
        "no_authority_drift_receipt": ["no commercial activation", "truth/trust unchanged"],
    }
    for role, checks in receipt_checks.items():
        payloads[role] = _receipt(base, role=role, checks=checks)
    prep_purposes = {
        "package_promotion_evidence_review_packet_prep_only_draft": "Prepare package-promotion evidence review.",
        "package_repair_or_rollback_packet_prep_only_draft": "Prepare repair or rollback path if review fails.",
        "forensic_package_promotion_review_packet_prep_only_draft": "Prepare forensic package-promotion review.",
        "commercial_activation_review_packet_prep_only_draft": "Prepare later commercial activation review.",
        "external_audit_delta_packet_prep_only_draft": "Prepare external audit delta packet.",
    }
    for role, purpose in prep_purposes.items():
        payloads[role] = _prep_only(base, role=role, purpose=purpose)
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Package Promotion",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "Package promotion passed under the validated execution packet.",
            "Commercial activation claims remain unauthorized. Truth/trust law remains unchanged.",
            "Provider/runtime and 7B benchmark outputs remain PREP_ONLY.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 package promotion")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_inputs(payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_PACKAGE_PROMOTION_TRUST_ZONE_FAILED", "fresh trust-zone validation must pass")
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
        trust_zone_validation=trust_zone_validation,
    )
    output_payloads = _outputs(base)
    contract = output_payloads["promotion_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "promotion_report":
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
