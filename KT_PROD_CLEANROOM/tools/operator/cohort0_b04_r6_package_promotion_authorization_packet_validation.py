from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_package_promotion_authorization_packet as authorization
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/b04-r6-package-promotion-authorization-packet"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-package-promotion-authorization-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_PACKET_VALIDATION"
PREVIOUS_LANE = authorization.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = authorization.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = authorization.NEXT_LAWFUL_MOVE

SELECTED_OUTCOME = (
    "B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_PACKET_VALIDATED__PACKAGE_PROMOTION_EXECUTION_PACKET_NEXT"
)
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_PACKAGE_PROMOTION_EXECUTION_PACKET"
OUTCOME_DEFERRED = "B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_VALIDATION_DEFERRED__NAMED_DEFECT_REMAINS"
OUTCOME_INVALID = "B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_VALIDATION_INVALID__FORENSIC_REVIEW_NEXT"

FORBIDDEN_ACTIONS = (
    "PACKAGE_PROMOTION_EXECUTED",
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "BENCHMARK_PREP_TREATED_AS_PACKAGE_AUTHORITY",
    "SEVEN_B_AMPLIFICATION_CLAIMED_PROVEN",
)

AUTHORITY_DRIFT_KEYS = {
    "package_promotion_executed": "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_PACKAGE_EXECUTION_DRIFT",
    "commercial_activation_claim_authorized": "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_COMMERCIAL_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_TRUST_ZONE_MUTATION",
    "benchmark_prep_authorizes_package_promotion": "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_BENCHMARK_AUTHORITY_DRIFT",
    "seven_b_amplification_claimed_proven": "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_7B_CLAIM_DRIFT",
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
            "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_PACKET_MISSING",
            "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_PACKET_OUTCOME_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_NEXT_MOVE_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_CONTRACT_INCOMPLETE",
            "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_PREP_ONLY_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

AUTHORIZATION_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in authorization.OUTPUTS.items()
    if filename.endswith(".json")
}
AUTHORIZATION_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in authorization.OUTPUTS.items()
    if not filename.endswith(".json")
}

VALIDATION_RECEIPT_ROLES = (
    "packet_binding_validation",
    "scope_validation",
    "surface_validation",
    "release_truth_validation",
    "operator_obligation_validation",
    "rollback_obligation_validation",
    "external_audit_validation",
    "public_verifier_validation",
    "deployment_profile_validation",
    "data_governance_validation",
    "claim_ceiling_validation",
    "prep_only_boundary_validation",
    "benchmark_prep_boundary_validation",
    "no_authority_drift_validation",
)

PREP_ONLY_OUTPUT_ROLES = (
    "package_promotion_execution_packet_prep_only_draft",
    "package_promotion_execution_validation_plan_prep_only",
    "package_promotion_run_result_schema_prep_only",
    "package_promotion_evidence_review_packet_prep_only_draft",
    "commercial_activation_review_preconditions_prep_only",
    "external_audit_delta_validation_plan_prep_only",
)

OUTPUTS = {
    "validation_contract": "b04_r6_package_promotion_authorization_validation_contract.json",
    "validation_receipt": "b04_r6_package_promotion_authorization_validation_receipt.json",
    "validation_report": "b04_r6_package_promotion_authorization_validation_report.md",
    "packet_binding_validation": "b04_r6_package_promotion_authorization_validation_packet_binding_receipt.json",
    "scope_validation": "b04_r6_package_promotion_authorization_validation_scope_receipt.json",
    "surface_validation": "b04_r6_package_promotion_authorization_validation_surface_receipt.json",
    "release_truth_validation": "b04_r6_package_promotion_authorization_validation_release_truth_receipt.json",
    "operator_obligation_validation": "b04_r6_package_promotion_authorization_validation_operator_receipt.json",
    "rollback_obligation_validation": "b04_r6_package_promotion_authorization_validation_rollback_receipt.json",
    "external_audit_validation": "b04_r6_package_promotion_authorization_validation_external_audit_receipt.json",
    "public_verifier_validation": "b04_r6_package_promotion_authorization_validation_public_verifier_receipt.json",
    "deployment_profile_validation": "b04_r6_package_promotion_authorization_validation_deployment_profile_receipt.json",
    "data_governance_validation": "b04_r6_package_promotion_authorization_validation_data_governance_receipt.json",
    "claim_ceiling_validation": "b04_r6_package_promotion_authorization_validation_claim_ceiling_receipt.json",
    "prep_only_boundary_validation": "b04_r6_package_promotion_authorization_validation_prep_only_boundary_receipt.json",
    "benchmark_prep_boundary_validation": (
        "b04_r6_package_promotion_authorization_validation_benchmark_prep_boundary_receipt.json"
    ),
    "no_authority_drift_validation": "b04_r6_package_promotion_authorization_validation_no_authority_drift_receipt.json",
    "package_promotion_execution_packet_prep_only_draft": (
        "b04_r6_package_promotion_authorization_validation_execution_packet_prep_only_draft.json"
    ),
    "package_promotion_execution_validation_plan_prep_only": (
        "b04_r6_package_promotion_authorization_validation_execution_validation_plan_prep_only.json"
    ),
    "package_promotion_run_result_schema_prep_only": (
        "b04_r6_package_promotion_authorization_validation_run_result_schema_prep_only.json"
    ),
    "package_promotion_evidence_review_packet_prep_only_draft": (
        "b04_r6_package_promotion_authorization_validation_evidence_review_packet_prep_only_draft.json"
    ),
    "commercial_activation_review_preconditions_prep_only": (
        "b04_r6_package_promotion_authorization_validation_commercial_activation_preconditions_prep_only.json"
    ),
    "external_audit_delta_validation_plan_prep_only": (
        "b04_r6_package_promotion_authorization_validation_external_audit_delta_plan_prep_only.json"
    ),
    "pipeline_board": "b04_r6_package_promotion_authorization_validation_pipeline_board.json",
    "future_blocker_register": "b04_r6_package_promotion_authorization_validation_future_blocker_register.json",
    "next_lawful_move": "b04_r6_package_promotion_authorization_validation_next_lawful_move_receipt.json",
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
            _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_PACKET_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_PACKET_MISSING", str(exc))


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in AUTHORIZATION_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in AUTHORIZATION_TEXT_INPUTS.items()}
    return payloads, texts


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk_items(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted non-false")
            if _is_claim_bearing_field(key) and isinstance(value, str) and _contains_positive_authority_token(value):
                _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        for phrase in (
            "PACKAGE PROMOTION EXECUTED",
            "PACKAGE IS PROMOTED",
            "COMMERCIAL ACTIVATION AUTHORIZED",
            "7B AMPLIFICATION IS PROVEN",
        ):
            if phrase in normalized:
                _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["authorization_contract"]
    receipt = payloads["authorization_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_PACKET_OUTCOME_DRIFT", "authorization contract outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_PACKET_OUTCOME_DRIFT", "authorization receipt outcome drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_NEXT_MOVE_DRIFT", "authorization contract next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_NEXT_MOVE_DRIFT", "next-lawful-move receipt drift")
    for key in (
        "r6_open",
        "package_promotion_review_validated",
        "package_promotion_authorization_packet_authored",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    ):
        if contract.get(key) is not True:
            _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_CONTRACT_INCOMPLETE", f"{key} is not true")
    for key in (
        "package_promotion_authorization_validated",
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
            _fail(AUTHORITY_DRIFT_KEYS.get(key, "RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_CONTRACT_INCOMPLETE"), key)
    if not contract.get("binding_hashes"):
        _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_INPUT_BINDINGS_EMPTY", "authorization binding hashes are empty")


def _validate_contract_roles(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in authorization.AUTHORIZATION_CONTRACT_ROLES:
        payload = payloads[role]
        if payload.get("contract_status") != "BOUND" or not payload.get("requirements"):
            _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_CONTRACT_INCOMPLETE", f"{role} incomplete")
    for role in authorization.PREP_ONLY_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY" or payload.get("cannot_execute_package_promotion") is not True:
            _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_PREP_ONLY_DRIFT", f"{role} prep boundary drift")
    for role in authorization.BENCHMARK_PREP_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY" or payload.get("cannot_claim_7b_amplification_proven") is not True:
            _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_BENCHMARK_AUTHORITY_DRIFT", f"{role} benchmark drift")


def _validate_inputs(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _ensure_authority_closed(payloads, texts)
    _validate_handoff(payloads)
    _validate_contract_roles(payloads)


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**AUTHORIZATION_JSON_INPUTS, **AUTHORIZATION_TEXT_INPUTS}.items()):
        path = root / raw
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _guard() -> Dict[str, Any]:
    return {
        "r6_open": True,
        "package_promotion_review_validated": True,
        "package_promotion_authorization_packet_authored": True,
        "package_promotion_authorization_validated": True,
        "package_promotion_execution_packet_next": True,
        "package_promotion_execution_packet_authored": False,
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
        "allowed_outcomes": [SELECTED_OUTCOME, OUTCOME_DEFERRED, OUTCOME_INVALID],
        "outcome_routing": {
            SELECTED_OUTCOME: NEXT_LAWFUL_MOVE,
            OUTCOME_DEFERRED: "REPAIR_B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_VALIDATION_DEFECTS",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_PACKAGE_PROMOTION_AUTHORIZATION_REVIEW_PACKET",
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


def _validation_receipt(base: Dict[str, Any], *, role: str, source_roles: Sequence[str]) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.package_promotion_authorization.validation.{role}.v1",
        artifact_id=f"B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_{role.upper()}_RECEIPT",
        validation_role=role,
        validation_status="PASS",
        source_roles=list(source_roles),
        validated_hashes={f"{source}_hash": base["binding_hashes"].get(f"{source}_hash") for source in source_roles},
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.package_promotion_authorization.validation.{role}.prep_only.v1",
        artifact_id=f"B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_VALIDATION_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_authorize_package_promotion=True,
        cannot_execute_package_promotion=True,
        cannot_authorize_commercial_activation_claims=True,
        cannot_claim_7b_amplification_proven=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    payloads: Dict[str, Any] = {
        "validation_contract": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_authorization_validation.contract.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_VALIDATION_CONTRACT",
            validation_summary=(
                "Package-promotion authorization packet validates and supports only package-promotion "
                "execution packet authorship."
            ),
        ),
        "validation_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_authorization_validation.receipt.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_VALIDATION_RECEIPT",
            verdict="PACKAGE_PROMOTION_AUTHORIZATION_VALIDATED_EXECUTION_PACKET_NEXT",
        ),
        "pipeline_board": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_authorization_validation.pipeline_board.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_VALIDATION_PIPELINE_BOARD",
            r6="OPEN",
            package_promotion_review="VALIDATED",
            package_promotion_authorization="VALIDATED",
            package_promotion_execution_packet="NEXT",
            package_promotion_execution="BLOCKED",
            commercial_activation="BLOCKED",
            provider_benchmark_campaign="PREP_ONLY",
        ),
        "future_blocker_register": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_authorization_validation.future_blocker_register.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_VALIDATION_FUTURE_BLOCKER_REGISTER",
            blockers=[
                "package_promotion_execution_packet_not_authored",
                "package_promotion_execution_packet_not_validated",
                "package_promotion_not_executed",
                "commercial_activation_review_not_authorized",
            ],
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.b04_r6.package_promotion_authorization_validation.next_lawful_move_receipt.v1",
            artifact_id="B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT",
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
    }
    receipt_sources = {
        "packet_binding_validation": ["authorization_contract", "authorization_receipt"],
        "scope_validation": ["promotion_scope_contract"],
        "surface_validation": ["allowed_package_surface_contract", "excluded_package_surface_contract"],
        "release_truth_validation": ["release_truth_derivation_contract"],
        "operator_obligation_validation": ["operator_obligation_contract"],
        "rollback_obligation_validation": ["rollback_obligation_contract"],
        "external_audit_validation": ["external_audit_requirements"],
        "public_verifier_validation": ["public_verifier_requirements"],
        "deployment_profile_validation": ["deployment_profile_requirements"],
        "data_governance_validation": ["data_governance_requirements"],
        "claim_ceiling_validation": ["commercial_claim_ceiling", "claim_ceiling_current_state"],
        "prep_only_boundary_validation": list(authorization.PREP_ONLY_ROLES),
        "benchmark_prep_boundary_validation": list(authorization.BENCHMARK_PREP_ROLES),
        "no_authority_drift_validation": ["no_authority_drift_receipt"],
    }
    for role, sources in receipt_sources.items():
        payloads[role] = _validation_receipt(base, role=role, source_roles=sources)
    prep_purposes = {
        "package_promotion_execution_packet_prep_only_draft": "Prepare execution-packet authoring lane.",
        "package_promotion_execution_validation_plan_prep_only": "Prepare execution-packet validation lane.",
        "package_promotion_run_result_schema_prep_only": "Prepare package-promotion run result schema.",
        "package_promotion_evidence_review_packet_prep_only_draft": "Prepare post-promotion evidence review.",
        "commercial_activation_review_preconditions_prep_only": "Prepare later commercial activation review gates.",
        "external_audit_delta_validation_plan_prep_only": "Prepare external audit delta validation gates.",
    }
    for role, purpose in prep_purposes.items():
        payloads[role] = _prep_only(base, role=role, purpose=purpose)
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Package Promotion Authorization Validation",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "The authorization packet validates and routes only to package-promotion execution packet authorship.",
            "Package promotion is not executed. Commercial activation claims remain unauthorized.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 package-promotion authorization validation")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_inputs(payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_PACKAGE_PROMOTION_AUTH_VAL_TRUST_ZONE_FAILED", "fresh trust-zone validation must pass")
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
        trust_zone_validation=trust_zone_validation,
    )
    output_payloads = _outputs(base)
    contract = output_payloads["validation_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "validation_report":
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
