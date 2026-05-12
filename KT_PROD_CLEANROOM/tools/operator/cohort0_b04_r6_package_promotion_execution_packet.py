from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_package_promotion_authorization_packet_validation as auth_validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/b04-r6-package-promotion-execution-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-package-promotion-execution-packet"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET"
PREVIOUS_LANE = auth_validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = auth_validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = auth_validation.NEXT_LAWFUL_MOVE

OUTCOME_BOUND = "B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET_BOUND__PACKAGE_PROMOTION_EXECUTION_VALIDATION_NEXT"
OUTCOME_DEFERRED = "B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET_INVALID__FORENSIC_PACKAGE_PROMOTION_EXECUTION_REVIEW_NEXT"
SELECTED_OUTCOME = OUTCOME_BOUND
NEXT_LAWFUL_MOVE = "VALIDATE_B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET"

VALIDATION_SUCCESS_OUTCOME = "B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET_VALIDATED__PACKAGE_PROMOTION_NEXT"
VALIDATION_SUCCESS_NEXT_MOVE = "RUN_B04_R6_PACKAGE_PROMOTION"

FORBIDDEN_ACTIONS = (
    "PACKAGE_PROMOTION_EXECUTED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "BENCHMARK_PREP_TREATED_AS_PACKAGE_AUTHORITY",
    "SEVEN_B_AMPLIFICATION_CLAIMED_PROVEN",
)

AUTHORITY_DRIFT_KEYS = {
    "package_promotion_executed": "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_EXECUTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_TRUST_ZONE_MUTATION",
    "benchmark_prep_authorizes_package_promotion": "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_BENCHMARK_AUTHORITY_DRIFT",
    "seven_b_amplification_claimed_proven": "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_7B_CLAIM_DRIFT",
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
    "PACKAGE_PROMOTION",
    "PRODUCTION",
    "PROMOTED",
)
NEGATIVE_AUTHORITY_QUALIFIERS = (
    "AUTHORIZATION_PACKET",
    "BLOCKED",
    "BOUNDARY_ONLY",
    "CANNOT_AUTHORIZE",
    "DEFERRED",
    "DOES_NOT_AUTHORIZE",
    "EXECUTION_PACKET",
    "FORBIDDEN",
    "NO_COMMERCIAL",
    "NO_PACKAGE_PROMOTION",
    "NO_PROMOTION",
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
            "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_AUTH_VALIDATION_MISSING",
            "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_OUTCOME_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_NEXT_MOVE_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_CONTRACT_INCOMPLETE",
            "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_PREP_ONLY_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_TRUST_ZONE_FAILED",
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
    "promotion_execution_mode_contract",
    "package_scope_contract",
    "release_surface_contract",
    "included_artifact_manifest",
    "excluded_artifact_manifest",
    "claim_ceiling_contract",
    "operator_obligation_contract",
    "rollback_execution_contract",
    "quarantine_freeze_contract",
    "release_truth_derivation_contract",
    "external_verifier_bundle_contract",
    "audit_bundle_contract",
    "clean_distributable_no_secret_contract",
    "expected_promotion_artifact_manifest",
    "result_interpretation_contract",
    "no_authority_drift_receipt",
)

PREP_ONLY_ROLES = (
    "package_promotion_run_result_schema_prep_only",
    "package_promotion_evidence_review_packet_prep_only_draft",
    "package_promotion_failure_closeout_prep_only_draft",
    "forensic_package_promotion_review_prep_only_draft",
    "commercial_activation_review_packet_prep_only_draft",
    "external_audit_delta_packet_prep_only_draft",
)

OUTPUTS = {
    "execution_contract": "b04_r6_package_promotion_execution_packet_contract.json",
    "execution_receipt": "b04_r6_package_promotion_execution_packet_receipt.json",
    "execution_report": "b04_r6_package_promotion_execution_packet_report.md",
    "promotion_execution_mode_contract": "b04_r6_package_promotion_execution_mode_contract.json",
    "package_scope_contract": "b04_r6_package_promotion_execution_package_scope_contract.json",
    "release_surface_contract": "b04_r6_package_promotion_execution_release_surface_contract.json",
    "included_artifact_manifest": "b04_r6_package_promotion_execution_included_artifact_manifest.json",
    "excluded_artifact_manifest": "b04_r6_package_promotion_execution_excluded_artifact_manifest.json",
    "claim_ceiling_contract": "b04_r6_package_promotion_execution_claim_ceiling_contract.json",
    "operator_obligation_contract": "b04_r6_package_promotion_execution_operator_obligation_contract.json",
    "rollback_execution_contract": "b04_r6_package_promotion_execution_rollback_contract.json",
    "quarantine_freeze_contract": "b04_r6_package_promotion_execution_quarantine_freeze_contract.json",
    "release_truth_derivation_contract": "b04_r6_package_promotion_execution_release_truth_derivation_contract.json",
    "external_verifier_bundle_contract": "b04_r6_package_promotion_execution_external_verifier_bundle_contract.json",
    "audit_bundle_contract": "b04_r6_package_promotion_execution_audit_bundle_contract.json",
    "clean_distributable_no_secret_contract": "b04_r6_package_promotion_execution_clean_distributable_no_secret_contract.json",
    "expected_promotion_artifact_manifest": "b04_r6_package_promotion_execution_expected_artifact_manifest.json",
    "result_interpretation_contract": "b04_r6_package_promotion_execution_result_interpretation_contract.json",
    "no_authority_drift_receipt": "b04_r6_package_promotion_execution_no_authority_drift_receipt.json",
    "execution_validation_plan": "b04_r6_package_promotion_execution_validation_plan.json",
    "execution_validation_reason_codes": "b04_r6_package_promotion_execution_validation_reason_codes.json",
    "package_promotion_run_result_schema_prep_only": "b04_r6_package_promotion_run_result_schema_prep_only.json",
    "package_promotion_evidence_review_packet_prep_only_draft": (
        "b04_r6_package_promotion_execution_evidence_review_packet_prep_only_draft.json"
    ),
    "package_promotion_failure_closeout_prep_only_draft": (
        "b04_r6_package_promotion_failure_closeout_prep_only_draft.json"
    ),
    "forensic_package_promotion_review_prep_only_draft": (
        "b04_r6_forensic_package_promotion_review_prep_only_draft.json"
    ),
    "commercial_activation_review_packet_prep_only_draft": (
        "b04_r6_package_promotion_execution_commercial_activation_review_packet_prep_only_draft.json"
    ),
    "external_audit_delta_packet_prep_only_draft": (
        "b04_r6_package_promotion_execution_external_audit_delta_packet_prep_only_draft.json"
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
            _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_AUTH_VALIDATION_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_AUTH_VALIDATION_MISSING", str(exc))


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
                _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        for phrase in (
            "PACKAGE PROMOTION EXECUTED",
            "PACKAGE IS PROMOTED",
            "COMMERCIAL ACTIVATION AUTHORIZED",
            "7B AMPLIFICATION IS PROVEN",
        ):
            if phrase in normalized:
                _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["validation_contract"]
    receipt = payloads["validation_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_OUTCOME_DRIFT", "authorization validation outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_OUTCOME_DRIFT", "authorization validation receipt drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_NEXT_MOVE_DRIFT", "authorization validation next drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_NEXT_MOVE_DRIFT", "next-lawful-move receipt drift")
    for key in (
        "r6_open",
        "package_promotion_authorization_validated",
        "package_promotion_execution_packet_next",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    ):
        if contract.get(key) is not True:
            _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_CONTRACT_INCOMPLETE", f"{key} is not true")
    for key in (
        "package_promotion_execution_packet_authored",
        "package_promotion_authorized",
        "package_promotion_executed",
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
        "benchmark_prep_authorizes_package_promotion",
        "seven_b_amplification_claimed_proven",
    ):
        if contract.get(key) is not False:
            _fail(AUTHORITY_DRIFT_KEYS.get(key, "RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_CONTRACT_INCOMPLETE"), key)
    if not contract.get("binding_hashes"):
        _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_INPUT_BINDINGS_EMPTY", "authorization validation bindings empty")


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
        "package_promotion_authorization_validated": True,
        "package_promotion_execution_packet_authored": True,
        "package_promotion_execution_packet_validated": False,
        "package_promotion_authorized": False,
        "package_promotion_executed": False,
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
        "validation_success_outcome": VALIDATION_SUCCESS_OUTCOME,
        "validation_success_next_move": VALIDATION_SUCCESS_NEXT_MOVE,
        "allowed_outcomes": [OUTCOME_BOUND, OUTCOME_DEFERRED, OUTCOME_INVALID],
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


def _contract(base: Dict[str, Any], *, role: str, requirements: Sequence[str]) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.package_promotion_execution_packet.{role}.v1",
        artifact_id=f"B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET_{role.upper()}",
        contract_role=role,
        contract_status="BOUND",
        requirements=list(requirements),
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.package_promotion_execution_packet.{role}.prep_only.v1",
        artifact_id=f"B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_execute_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_claim_7b_amplification_proven=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    payloads: Dict[str, Any] = {
        "execution_contract": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_execution_packet.contract.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET_CONTRACT",
            execution_packet_summary=(
                "Defines how package promotion may run after independent execution-packet validation. "
                "It does not execute package promotion."
            ),
        ),
        "execution_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_execution_packet.receipt.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET_RECEIPT",
            verdict="PACKAGE_PROMOTION_EXECUTION_PACKET_BOUND_VALIDATION_NEXT",
        ),
        "execution_validation_plan": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_execution_packet.validation_plan.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET_VALIDATION_PLAN",
            required_validations=[
                "validated package promotion authorization is bound",
                "execution mode and package scope are bounded",
                "release truth and claim ceiling are preserved",
                "rollback/quarantine/freeze paths are present",
                "commercial activation remains unauthorized",
            ],
        ),
        "execution_validation_reason_codes": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_execution_packet.reason_codes.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET_VALIDATION_REASON_CODES",
            reason_code_taxonomy=list(REASON_CODES),
        ),
        "pipeline_board": _artifact(
            base,
            schema_id="kt.b04_r6.pipeline_board.v1",
            artifact_id="B04_R6_PIPELINE_BOARD",
            r6="OPEN",
            package_promotion_authorization="VALIDATED",
            package_promotion_execution_packet="BOUND",
            package_promotion_execution_validation="NEXT",
            package_promotion_execution="BLOCKED",
            commercial_activation="BLOCKED",
        ),
        "future_blocker_register": _artifact(
            base,
            schema_id="kt.future_blocker_register.v1",
            artifact_id="KT_FUTURE_BLOCKER_REGISTER",
            blockers=[
                "package_promotion_execution_packet_requires_validation",
                "package_promotion_run_not_executed",
                "commercial_activation_requires_later_review",
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
        "promotion_execution_mode_contract": ["operator-observed promotion execution", "rollback-ready"],
        "package_scope_contract": ["bounded package scope", "no commercial activation surface"],
        "release_surface_contract": ["release truth bundle", "public verifier bundle", "operator runbook"],
        "included_artifact_manifest": ["validated receipts", "hash manifest", "claim ceiling"],
        "excluded_artifact_manifest": ["secrets", "archive residue", "unvalidated benchmark claims"],
        "claim_ceiling_contract": ["package promotion is not commercial activation"],
        "operator_obligation_contract": ["runbook acknowledgement", "incident ownership"],
        "rollback_execution_contract": ["rollback command path", "quarantine path"],
        "quarantine_freeze_contract": ["freeze on claim drift", "freeze on secret scan failure"],
        "release_truth_derivation_contract": ["derive release truth from receipts"],
        "external_verifier_bundle_contract": ["external hash manifest", "auditor README"],
        "audit_bundle_contract": ["audit evidence inventory", "negative-result ledger"],
        "clean_distributable_no_secret_contract": ["secret scan", "distributable hygiene"],
        "expected_promotion_artifact_manifest": ["promotion receipt", "promotion report", "evidence review prep"],
        "result_interpretation_contract": ["pass does not authorize commercial activation"],
        "no_authority_drift_receipt": ["no execution", "no commercial activation", "truth/trust unchanged"],
    }
    for role, requirements in contract_requirements.items():
        payloads[role] = _contract(base, role=role, requirements=requirements)
    prep_purposes = {
        "package_promotion_run_result_schema_prep_only": "Prepare future package-promotion run result schema.",
        "package_promotion_evidence_review_packet_prep_only_draft": "Prepare post-promotion evidence review.",
        "package_promotion_failure_closeout_prep_only_draft": "Prepare failed-promotion closeout.",
        "forensic_package_promotion_review_prep_only_draft": "Prepare forensic package-promotion review.",
        "commercial_activation_review_packet_prep_only_draft": "Prepare later commercial activation review.",
        "external_audit_delta_packet_prep_only_draft": "Prepare external audit delta packet.",
    }
    for role, purpose in prep_purposes.items():
        payloads[role] = _prep_only(base, role=role, purpose=purpose)
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Package Promotion Execution Packet",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "This packet defines promotion execution law but does not run package promotion.",
            "Commercial activation claims remain unauthorized. Truth/trust law remains unchanged.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 package-promotion execution packet")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_inputs(payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_PACKAGE_PROMOTION_EXEC_PACKET_TRUST_ZONE_FAILED", "fresh trust-zone validation must pass")
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
