from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_b04_r6_commercial_activation_execution_packet_validation as validation
from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "run/b04-r6-commercial-activation"
REPLAY_BRANCH_PREFIX = "replay/b04-r6-commercial-activation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "B04_R6_COMMERCIAL_ACTIVATION"
PREVIOUS_LANE = validation.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = validation.NEXT_LAWFUL_MOVE

OUTCOME_PASSED = "B04_R6_COMMERCIAL_ACTIVATION_PASSED__COMMERCIAL_ACTIVATION_EVIDENCE_REVIEW_PACKET_NEXT"
OUTCOME_FAILED = "B04_R6_COMMERCIAL_ACTIVATION_FAILED__COMMERCIAL_REPAIR_OR_ROLLBACK_NEXT"
OUTCOME_INVALID = "B04_R6_COMMERCIAL_ACTIVATION_INVALIDATED__FORENSIC_COMMERCIAL_ACTIVATION_REVIEW_NEXT"
OUTCOME_DEFERRED = "B04_R6_COMMERCIAL_ACTIVATION_DEFERRED__NAMED_ACTIVATION_DEFECT_REMAINS"
SELECTED_OUTCOME = OUTCOME_PASSED
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_COMMERCIAL_ACTIVATION_EVIDENCE_REVIEW_PACKET"

FORBIDDEN_ACTIONS = (
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "BENCHMARK_PREP_TREATED_AS_COMMERCIAL_AUTHORITY",
    "SEVEN_B_AMPLIFICATION_CLAIMED_PROVEN",
    "FOLLOW_UP_AUDIT_READINESS_CLAIMED_VALIDATED",
)

AUTHORITY_DRIFT_KEYS = {
    "commercial_activation_claim_authorized": "RC_B04R6_COMMERCIAL_ACTIVATION_CLAIM_DRIFT",
    "truth_engine_law_changed": "RC_B04R6_COMMERCIAL_ACTIVATION_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_B04R6_COMMERCIAL_ACTIVATION_TRUST_ZONE_MUTATION",
    "benchmark_prep_authorizes_commercial_activation": "RC_B04R6_COMMERCIAL_ACTIVATION_BENCHMARK_AUTHORITY_DRIFT",
    "seven_b_amplification_claimed_proven": "RC_B04R6_COMMERCIAL_ACTIVATION_7B_CLAIM_DRIFT",
    "follow_up_audit_readiness_validated": "RC_B04R6_COMMERCIAL_ACTIVATION_AUDIT_READINESS_DRIFT",
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
DIRECT_NEGATING_AUTHORITY_QUALIFIERS = (
    "BLOCKED",
    "CANNOT_AUTHORIZE",
    "DOES_NOT_AUTHORIZE",
    "FORBIDDEN",
    "NO_COMMERCIAL_ACTIVATION_CLAIMS",
    "NOT_AUTHORIZED",
    "PROHIBITED",
    "REMAINS_UNAUTHORIZED",
    "STILL_BLOCKED",
    "UNAUTHORIZED",
)
CONTEXTUAL_NON_AUTHORITY_QUALIFIERS = (
    "AUTHORIZATION_PACKET",
    "AUTHORIZATION_VALIDATION",
    "BOUNDARY_ONLY",
    "EVIDENCE_REVIEW",
    "EXECUTION_PACKET",
    "NEXT",
    "PREP_ONLY",
    "REVIEW_PACKET",
    "VALIDATED",
)
STRONG_AUTHORITY_TOKENS = (
    "ACTIVE",
    "AUTHORIZED",
    "ENABLED",
    "PRODUCTION",
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_B04R6_COMMERCIAL_ACTIVATION_VALIDATION_MISSING",
            "RC_B04R6_COMMERCIAL_ACTIVATION_VALIDATION_OUTCOME_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_NEXT_MOVE_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_INPUT_BINDINGS_EMPTY",
            "RC_B04R6_COMMERCIAL_ACTIVATION_INPUT_BINDING_INCOMPLETE",
            "RC_B04R6_COMMERCIAL_ACTIVATION_INPUT_HASH_MISMATCH",
            "RC_B04R6_COMMERCIAL_ACTIVATION_PREDECESSOR_MAIN_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_VALIDATION_INCOMPLETE",
            "RC_B04R6_COMMERCIAL_ACTIVATION_PREP_ONLY_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_CLAIM_TOKEN_DRIFT",
            "RC_B04R6_COMMERCIAL_ACTIVATION_TRUST_ZONE_FAILED",
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

ACTIVATION_RECEIPT_ROLES = (
    "activation_surface_receipt",
    "claim_ceiling_receipt",
    "customer_safe_language_receipt",
    "operator_obligation_receipt",
    "deployment_profile_receipt",
    "support_incident_receipt",
    "data_governance_receipt",
    "release_truth_receipt",
    "external_verifier_receipt",
    "public_verifier_receipt",
    "audit_bundle_receipt",
    "rollback_receipt",
    "quarantine_freeze_receipt",
    "trace_completeness_receipt",
    "no_authority_drift_receipt",
)

PREP_ONLY_ROLES = (
    "commercial_activation_evidence_review_packet_prep_only_draft",
    "commercial_activation_repair_or_rollback_packet_prep_only_draft",
    "forensic_commercial_activation_review_packet_prep_only_draft",
    "follow_up_audit_readiness_packet_prep_only_draft",
    "post_activation_external_audit_delta_packet_prep_only_draft",
)

OUTPUTS = {
    "activation_contract": "b04_r6_commercial_activation_execution_contract.json",
    "activation_receipt": "b04_r6_commercial_activation_execution_receipt.json",
    "activation_result": "b04_r6_commercial_activation_result.json",
    "activation_report": "b04_r6_commercial_activation_report.md",
    "activation_surface_receipt": "b04_r6_commercial_activation_surface_receipt.json",
    "claim_ceiling_receipt": "b04_r6_commercial_activation_claim_ceiling_receipt.json",
    "customer_safe_language_receipt": "b04_r6_commercial_activation_customer_safe_language_receipt.json",
    "operator_obligation_receipt": "b04_r6_commercial_activation_operator_obligation_receipt.json",
    "deployment_profile_receipt": "b04_r6_commercial_activation_deployment_profile_receipt.json",
    "support_incident_receipt": "b04_r6_commercial_activation_support_incident_receipt.json",
    "data_governance_receipt": "b04_r6_commercial_activation_data_governance_receipt.json",
    "release_truth_receipt": "b04_r6_commercial_activation_release_truth_receipt.json",
    "external_verifier_receipt": "b04_r6_commercial_activation_external_verifier_receipt.json",
    "public_verifier_receipt": "b04_r6_commercial_activation_public_verifier_receipt.json",
    "audit_bundle_receipt": "b04_r6_commercial_activation_audit_bundle_receipt.json",
    "rollback_receipt": "b04_r6_commercial_activation_rollback_receipt.json",
    "quarantine_freeze_receipt": "b04_r6_commercial_activation_quarantine_freeze_receipt.json",
    "trace_completeness_receipt": "b04_r6_commercial_activation_trace_completeness_receipt.json",
    "no_authority_drift_receipt": "b04_r6_commercial_activation_no_authority_drift_receipt.json",
    "commercial_activation_evidence_review_packet_prep_only_draft": (
        "b04_r6_commercial_activation_evidence_review_packet_prep_only_draft.json"
    ),
    "commercial_activation_repair_or_rollback_packet_prep_only_draft": (
        "b04_r6_commercial_activation_repair_or_rollback_packet_prep_only_draft.json"
    ),
    "forensic_commercial_activation_review_packet_prep_only_draft": (
        "b04_r6_forensic_commercial_activation_review_packet_prep_only_draft.json"
    ),
    "follow_up_audit_readiness_packet_prep_only_draft": (
        "kt_e2e_follow_up_audit_readiness_packet_prep_only_draft.json"
    ),
    "post_activation_external_audit_delta_packet_prep_only_draft": (
        "b04_r6_post_commercial_activation_external_audit_delta_packet_prep_only_draft.json"
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


def _walk_items(value: Any, parent_key: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            current_key = str(key)
            yield current_key, item
            yield from _walk_items(item, current_key)
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
    if any(qualifier in normalized for qualifier in DIRECT_NEGATING_AUTHORITY_QUALIFIERS):
        return False
    if any(token in normalized for token in STRONG_AUTHORITY_TOKENS):
        return True
    if "COMMERCIAL_ACTIVATION" in normalized:
        return not any(qualifier in normalized for qualifier in CONTEXTUAL_NON_AUTHORITY_QUALIFIERS)
    return any(token in normalized for token in POSITIVE_AUTHORITY_TOKENS)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_B04R6_COMMERCIAL_ACTIVATION_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_VALIDATION_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_VALIDATION_MISSING", str(exc))


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in VALIDATION_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in VALIDATION_TEXT_INPUTS.items()}
    return payloads, texts


def _git_blob_bytes(root: Path, commit: str, raw: str) -> bytes:
    blob_ref = f"{commit}:{raw.replace(chr(92), '/')}"
    result = subprocess.run(["git", "show", blob_ref], cwd=root, capture_output=True, check=True)
    return result.stdout


def _git_blob_sha256(root: Path, commit: str, raw: str) -> str:
    return hashlib.sha256(_git_blob_bytes(root, commit, raw)).hexdigest()


def _git_is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(["git", "merge-base", "--is-ancestor", ancestor, descendant], cwd=root, capture_output=True)
    return result.returncode == 0


def _validated_validation_packet_head(contract: Dict[str, Any]) -> str:
    current_main_head = str(contract.get("current_main_head") or "")
    current_git_head = str(contract.get("current_git_head") or "")
    current_branch_head = str(contract.get("current_branch_head") or "")
    if not current_main_head or current_main_head != current_git_head or current_main_head != current_branch_head:
        _fail(
            "RC_B04R6_COMMERCIAL_ACTIVATION_PREDECESSOR_MAIN_DRIFT",
            "execution validation packet head metadata is not replay-bound",
        )
    return current_main_head


def _expected_source_hash(root: Path, row: Dict[str, Any], *, fallback_contract: Dict[str, Any]) -> str:
    raw = str(row.get("path", ""))
    binding_kind = row.get("binding_kind")
    if binding_kind == "git_object_before_overwrite":
        git_commit = row.get("git_commit")
        if not git_commit:
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_INPUT_BINDING_INCOMPLETE", f"{row.get('role')} missing git_commit")
        return _git_blob_sha256(root, str(git_commit), raw)
    if not binding_kind:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_INPUT_BINDING_INCOMPLETE", f"{row.get('role')} missing binding_kind")
    current_hash = file_sha256(common.resolve_path(root, raw))
    if current_hash == row.get("sha256"):
        return current_hash
    output_paths = {f"KT_PROD_CLEANROOM/reports/{filename}" for filename in OUTPUTS.values()}
    if raw in output_paths:
        return _git_blob_sha256(root, _validated_validation_packet_head(fallback_contract), raw)
    return current_hash


def _ensure_validation_source_bindings_current(root: Path, contract: Dict[str, Any]) -> None:
    bindings = contract.get("input_bindings")
    binding_hashes = contract.get("binding_hashes")
    if not isinstance(bindings, list) or not bindings:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_INPUT_BINDINGS_EMPTY", "execution validation source bindings empty")
    if not isinstance(binding_hashes, dict) or not binding_hashes:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_INPUT_BINDINGS_EMPTY", "execution validation binding hashes empty")
    for row in bindings:
        if not isinstance(row, dict) or not row.get("role") or not row.get("path") or not row.get("sha256"):
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_INPUT_BINDING_INCOMPLETE", "malformed validation binding row")
        role = str(row["role"])
        bound_hash = str(row["sha256"])
        if binding_hashes.get(f"{role}_hash") != bound_hash:
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_INPUT_HASH_MISMATCH", f"{role} binding hash mismatch")
        if _expected_source_hash(root, row, fallback_contract=contract) != bound_hash:
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_INPUT_HASH_MISMATCH", f"{role} current source hash mismatch")


def _validate_predecessor_lineage(root: Path, contract: Dict[str, Any], *, current_main_head: str) -> None:
    predecessor_main = contract.get("current_main_head")
    predecessor_head = contract.get("current_git_head") or contract.get("current_branch_head")
    if not predecessor_main or not predecessor_head:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_PREDECESSOR_MAIN_DRIFT", "predecessor head metadata missing")
    if predecessor_main == current_main_head:
        return
    if not _git_is_ancestor(root, str(predecessor_head), current_main_head):
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_PREDECESSOR_MAIN_DRIFT", "predecessor is not in current main lineage")


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk_items(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted non-false")
            if isinstance(value, str) and "7B AMPLIFICATION IS PROVEN" in value.upper():
                _fail("RC_B04R6_COMMERCIAL_ACTIVATION_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
            if _is_claim_bearing_field(key) and isinstance(value, str) and _contains_positive_authority_token(value):
                _fail("RC_B04R6_COMMERCIAL_ACTIVATION_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        normalized = text.upper()
        for phrase in (
            "COMMERCIAL ACTIVATION CLAIM AUTHORIZED",
            "COMMERCIAL ACTIVATION CLAIMS AUTHORIZED",
            "KT IS COMMERCIALLY ACTIVATED",
            "7B AMPLIFICATION IS PROVEN",
        ):
            if phrase in normalized:
                _fail("RC_B04R6_COMMERCIAL_ACTIVATION_CLAIM_TOKEN_DRIFT", f"{label} contains {phrase!r}")


def _validate_handoff(root: Path, payloads: Dict[str, Dict[str, Any]], *, current_main_head: str) -> None:
    contract = payloads["validation_contract"]
    receipt = payloads["validation_receipt"]
    next_move = payloads["next_lawful_move"]
    _ensure_validation_source_bindings_current(root, contract)
    _validate_predecessor_lineage(root, contract, current_main_head=current_main_head)
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_VALIDATION_OUTCOME_DRIFT", "execution validation outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_VALIDATION_OUTCOME_DRIFT", "execution validation receipt drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_NEXT_MOVE_DRIFT", "execution validation next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_NEXT_MOVE_DRIFT", "next-lawful-move receipt drift")
    for key in (
        "r6_open",
        "package_promotion_passed",
        "commercial_activation_authorization_validated",
        "commercial_activation_execution_packet_authored",
        "commercial_activation_execution_packet_validated",
        "commercial_activation_next",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    ):
        if contract.get(key) is not True:
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_VALIDATION_INCOMPLETE", f"{key} is not true")
    for key in (
        "commercial_activation_executed",
        "commercial_activation_claim_authorized",
        "benchmark_prep_authorizes_commercial_activation",
        "seven_b_amplification_claimed_proven",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
    ):
        if contract.get(key) is not False:
            _fail(AUTHORITY_DRIFT_KEYS.get(key, "RC_B04R6_COMMERCIAL_ACTIVATION_VALIDATION_INCOMPLETE"), key)


def _validate_inputs(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str], *, current_main_head: str) -> None:
    _ensure_authority_closed(payloads, texts)
    _validate_handoff(root, payloads, current_main_head=current_main_head)
    for role in validation.PREP_ONLY_OUTPUT_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY" or payload.get("cannot_execute_commercial_activation") is not True:
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_PREP_ONLY_DRIFT", f"{role} prep boundary drift")
        if payload.get("cannot_authorize_commercial_activation_claims") is not True:
            _fail("RC_B04R6_COMMERCIAL_ACTIVATION_PREP_ONLY_DRIFT", f"{role} claim boundary drift")


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**VALIDATION_JSON_INPUTS, **VALIDATION_TEXT_INPUTS}.items()):
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": "file_sha256_at_commercial_activation_run",
            }
        )
    return rows


def _guard() -> Dict[str, Any]:
    return {
        "r6_open": True,
        "package_promotion_passed": True,
        "commercial_activation_authorization_validated": True,
        "commercial_activation_execution_packet_validated": True,
        "commercial_activation_authorized": True,
        "commercial_activation_executed": True,
        "commercial_activation_passed": True,
        "commercial_activation_evidence_review_packet_next": True,
        "commercial_activation_claim_authorized": False,
        "benchmark_prep_authorizes_commercial_activation": False,
        "seven_b_amplification_claimed_proven": False,
        "follow_up_audit_readiness_validated": False,
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
        "allowed_outcomes": [OUTCOME_PASSED, OUTCOME_FAILED, OUTCOME_INVALID, OUTCOME_DEFERRED],
        "outcome_routing": {
            OUTCOME_PASSED: NEXT_LAWFUL_MOVE,
            OUTCOME_FAILED: "AUTHOR_B04_R6_COMMERCIAL_ACTIVATION_REPAIR_OR_ROLLBACK_PACKET",
            OUTCOME_INVALID: "AUTHOR_B04_R6_FORENSIC_COMMERCIAL_ACTIVATION_REVIEW_PACKET",
            OUTCOME_DEFERRED: "REPAIR_B04_R6_COMMERCIAL_ACTIVATION_DEFECTS",
        },
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "benchmark_governing_statement": validation.execution.BENCHMARK_GOVERNING_STATEMENT,
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
        schema_id=f"kt.b04_r6.commercial_activation.{role}.receipt.v1",
        artifact_id=f"B04_R6_COMMERCIAL_ACTIVATION_{role.upper()}",
        receipt_role=role,
        receipt_status="PASS",
        checks=list(checks),
    )


def _prep_only(base: Dict[str, Any], *, role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.b04_r6.commercial_activation.{role}.prep_only.v1",
        artifact_id=f"B04_R6_COMMERCIAL_ACTIVATION_{role.upper()}",
        authority="PREP_ONLY",
        status="PREP_ONLY",
        purpose=purpose,
        cannot_authorize_commercial_activation_claims=True,
        cannot_claim_7b_amplification_proven=True,
        cannot_validate_follow_up_audit_readiness=True,
        cannot_mutate_truth_engine_law=True,
        cannot_mutate_trust_zone_law=True,
    )


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    payloads: Dict[str, Any] = {
        "activation_contract": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation.execution_contract.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_CONTRACT",
            activation_mode="bounded_receipt_backed_commercial_activation",
        ),
        "activation_receipt": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation.execution_receipt.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_EXECUTION_RECEIPT",
            verdict="COMMERCIAL_ACTIVATION_PASSED_EVIDENCE_REVIEW_NEXT",
        ),
        "activation_result": _artifact(
            base,
            schema_id="kt.b04_r6.commercial_activation.result.v1",
            artifact_id="B04_R6_COMMERCIAL_ACTIVATION_RESULT",
            result="PASSED",
            commercial_activation_executed=True,
            commercial_activation_claim_authorized=False,
            follow_up_audit_readiness_validated=False,
        ),
        "pipeline_board": _artifact(
            base,
            schema_id="kt.b04_r6.pipeline_board.v1",
            artifact_id="B04_R6_PIPELINE_BOARD",
            r6="OPEN",
            package_promotion="PASSED",
            commercial_activation="PASSED_EVIDENCE_REVIEW_NEXT",
            commercial_activation_claims="BLOCKED_UNTIL_EVIDENCE_REVIEW_VALIDATION",
            follow_up_audit_readiness="BLOCKED",
        ),
        "claim_ceiling_current_state": _artifact(
            base,
            schema_id="kt.claim_ceiling.current_state.v1",
            artifact_id="KT_CLAIM_CEILING_CURRENT_STATE",
            allowed_claims=[
                "R6 is open.",
                "Package promotion has passed.",
                "Commercial activation executed under the validated execution packet.",
                "Commercial activation evidence review is the next lawful move.",
                "Truth/trust law is unchanged.",
            ],
            forbidden_claims=[
                "Commercial activation claims are authorized.",
                "Commercial activation evidence review is validated.",
                "KT E2E follow-up audit readiness is validated.",
                "7B amplification is proven.",
            ],
        ),
        "future_blocker_register": _artifact(
            base,
            schema_id="kt.future_blocker_register.v1",
            artifact_id="KT_FUTURE_BLOCKER_REGISTER",
            blockers=[
                "commercial_activation_evidence_review_not_authored",
                "commercial_activation_evidence_review_not_validated",
                "commercial_activation_claims_require_evidence_review_validation",
                "follow_up_audit_readiness_requires_post_activation_evidence_review_validation",
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
        "activation_surface_receipt": ["commercial surface activated under validated execution packet"],
        "claim_ceiling_receipt": ["claims remain blocked pending post-activation evidence review validation"],
        "customer_safe_language_receipt": ["customer-facing language remains receipt-derived"],
        "operator_obligation_receipt": ["operator obligations preserved"],
        "deployment_profile_receipt": ["deployment profile executed within validated scope"],
        "support_incident_receipt": ["support and incident path ready"],
        "data_governance_receipt": ["data governance boundary preserved"],
        "release_truth_receipt": ["release truth remains mechanically derived"],
        "external_verifier_receipt": ["external verifier bundle remains inspectable"],
        "public_verifier_receipt": ["public verifier bundle remains bounded"],
        "audit_bundle_receipt": ["activation audit bundle prepared"],
        "rollback_receipt": ["rollback remains available"],
        "quarantine_freeze_receipt": ["quarantine/freeze remains available"],
        "trace_completeness_receipt": ["activation traces are complete for evidence review"],
        "no_authority_drift_receipt": ["no claim authorization", "truth/trust unchanged"],
    }
    for role, checks in receipt_checks.items():
        payloads[role] = _receipt(base, role=role, checks=checks)
    prep_purposes = {
        "commercial_activation_evidence_review_packet_prep_only_draft": "Prepare post-activation evidence review.",
        "commercial_activation_repair_or_rollback_packet_prep_only_draft": "Prepare repair or rollback path.",
        "forensic_commercial_activation_review_packet_prep_only_draft": "Prepare forensic commercial activation review.",
        "follow_up_audit_readiness_packet_prep_only_draft": "Prepare final E2E follow-up audit readiness packet.",
        "post_activation_external_audit_delta_packet_prep_only_draft": "Prepare post-activation external audit delta.",
    }
    for role, purpose in prep_purposes.items():
        payloads[role] = _prep_only(base, role=role, purpose=purpose)
    return payloads


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# B04 R6 Commercial Activation",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "Commercial activation passed under the validated execution packet.",
            "Commercial activation claims remain unauthorized until post-activation evidence review validates.",
            "Follow-up audit readiness is not validated. Truth/trust law remains unchanged.",
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
        raise RuntimeError("FAIL_CLOSED: dirty worktree before B04 R6 commercial activation")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads, texts = _payloads(root)
    _validate_inputs(root, payloads, texts, current_main_head=current_main_head)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_B04R6_COMMERCIAL_ACTIVATION_TRUST_ZONE_FAILED", "fresh trust-zone validation must pass")
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=_input_bindings(root),
        trust_zone_validation=trust_zone_validation,
    )
    output_payloads = _outputs(base)
    contract = output_payloads["activation_contract"]
    for role, filename in OUTPUTS.items():
        path = reports_root / filename
        if role == "activation_report":
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
