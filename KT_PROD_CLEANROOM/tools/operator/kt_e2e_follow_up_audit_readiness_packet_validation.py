from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_e2e_follow_up_audit_readiness_packet as packet
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/kt-e2e-follow-up-audit-readiness-packet"
REPLAY_BRANCH_PREFIX = "replay/kt-e2e-follow-up-audit-readiness-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_PACKET_VALIDATION"
PREVIOUS_LANE = packet.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = packet.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = packet.NEXT_LAWFUL_MOVE

SELECTED_OUTCOME = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATED__READY_FOR_REAUDIT_OR_EXTERNAL_REVIEW"
NEXT_LAWFUL_MOVE = "READY_FOR_REAUDIT_OR_EXTERNAL_REVIEW"
OUTCOME_EXTERNAL_AUDIT = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATED__EXTERNAL_AUDIT_DELTA_PACKET_NEXT"
OUTCOME_COMMERCIAL_CLAIM = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATED__COMMERCIAL_CLAIM_AUTHORIZATION_PACKET_NEXT"
OUTCOME_DEFERRED = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_DEFERRED__NAMED_AUDIT_READINESS_DEFECT_REMAINS"
OUTCOME_INVALID = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_INVALID__FORENSIC_AUDIT_READINESS_REVIEW_NEXT"

FORBIDDEN_ACTIONS = (
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
    "BENCHMARK_PREP_TREATED_AS_COMMERCIAL_AUTHORITY",
    "SEVEN_B_AMPLIFICATION_CLAIMED_PROVEN",
)

AUTHORITY_DRIFT_KEYS = {
    "commercial_activation_claim_authorized": "RC_KT_E2E_AUDIT_READY_VAL_CLAIM_DRIFT",
    "benchmark_prep_authorizes_commercial_activation": "RC_KT_E2E_AUDIT_READY_VAL_BENCHMARK_AUTHORITY_DRIFT",
    "truth_engine_law_changed": "RC_KT_E2E_AUDIT_READY_VAL_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_KT_E2E_AUDIT_READY_VAL_TRUST_ZONE_MUTATION",
    "seven_b_amplification_claimed_proven": "RC_KT_E2E_AUDIT_READY_VAL_7B_CLAIM_DRIFT",
}

CLAIM_DRIFT_PHRASES = (
    "COMMERCIAL ACTIVATION CLAIMS AUTHORIZED",
    "COMMERCIAL ACTIVATION CLAIM AUTHORIZED",
    "KT IS PRODUCTION-COMMERCIAL LIVE",
    "7B AMPLIFICATION IS PROVEN",
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_E2E_AUDIT_READY_VAL_PACKET_MISSING",
            "RC_KT_E2E_AUDIT_READY_VAL_PACKET_OUTCOME_DRIFT",
            "RC_KT_E2E_AUDIT_READY_VAL_NEXT_MOVE_DRIFT",
            "RC_KT_E2E_AUDIT_READY_VAL_INPUT_HASH_MISSING",
            "RC_KT_E2E_AUDIT_READY_VAL_INPUT_HASH_MALFORMED",
            "RC_KT_E2E_AUDIT_READY_VAL_INPUT_HASH_MISMATCH",
            "RC_KT_E2E_AUDIT_READY_VAL_CLAIM_TOKEN_DRIFT",
            "RC_KT_E2E_AUDIT_READY_VAL_AUDIT_EVIDENCE_INCOMPLETE",
            "RC_KT_E2E_AUDIT_READY_VAL_BOUNDARY_DRIFT",
            "RC_KT_E2E_AUDIT_READY_VAL_PREP_ONLY_DRIFT",
            "RC_KT_E2E_AUDIT_READY_VAL_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

PACKET_JSON_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in packet.OUTPUTS.items()
    if filename.endswith(".json")
}
PACKET_TEXT_INPUTS = {
    role: f"KT_PROD_CLEANROOM/reports/{filename}"
    for role, filename in packet.OUTPUTS.items()
    if not filename.endswith(".json")
}

VALIDATION_MAP = {
    "canonical_state_board_validation": ("canonical_state_board",),
    "allowed_claims_validation": ("allowed_claims_current_state",),
    "forbidden_claims_validation": ("forbidden_claims_current_state",),
    "proof_replay_bundle_validation": ("proof_replay_bundle_manifest",),
    "external_verifier_manifest_validation": ("external_verifier_manifest",),
    "commercial_activation_evidence_validation": ("commercial_activation_evidence_review",),
    "package_promotion_evidence_validation": ("package_promotion_evidence_summary",),
    "r6_opening_evidence_validation": ("r6_opening_evidence_summary",),
    "truth_trust_validation": ("truth_trust_unchanged_receipt",),
    "boundary_state_validation": ("boundary_state_receipt",),
    "limitations_validation": ("known_limitations_ledger",),
    "open_blocker_validation": ("open_blocker_ledger",),
}

PREP_ONLY_OUTPUT_ROLES = (
    "external_audit_delta_packet_prep_only",
    "commercial_claim_authorization_packet_prep_only",
    "public_reaudit_packet_prep_only",
)

OUTPUTS = {
    "validation_contract": "kt_e2e_follow_up_audit_readiness_validation_contract.json",
    "validation_receipt": "kt_e2e_follow_up_audit_readiness_validation_receipt.json",
    "validation_report": "kt_e2e_follow_up_audit_readiness_validation_report.md",
    "canonical_state_board_validation": "kt_e2e_follow_up_audit_readiness_validation_canonical_state_board_receipt.json",
    "allowed_claims_validation": "kt_e2e_follow_up_audit_readiness_validation_allowed_claims_receipt.json",
    "forbidden_claims_validation": "kt_e2e_follow_up_audit_readiness_validation_forbidden_claims_receipt.json",
    "proof_replay_bundle_validation": "kt_e2e_follow_up_audit_readiness_validation_proof_replay_bundle_receipt.json",
    "external_verifier_manifest_validation": "kt_e2e_follow_up_audit_readiness_validation_external_verifier_receipt.json",
    "commercial_activation_evidence_validation": (
        "kt_e2e_follow_up_audit_readiness_validation_commercial_activation_evidence_receipt.json"
    ),
    "package_promotion_evidence_validation": (
        "kt_e2e_follow_up_audit_readiness_validation_package_promotion_evidence_receipt.json"
    ),
    "r6_opening_evidence_validation": "kt_e2e_follow_up_audit_readiness_validation_r6_opening_evidence_receipt.json",
    "truth_trust_validation": "kt_e2e_follow_up_audit_readiness_validation_truth_trust_receipt.json",
    "boundary_state_validation": "kt_e2e_follow_up_audit_readiness_validation_boundary_state_receipt.json",
    "limitations_validation": "kt_e2e_follow_up_audit_readiness_validation_limitations_receipt.json",
    "open_blocker_validation": "kt_e2e_follow_up_audit_readiness_validation_open_blocker_receipt.json",
    "prep_only_boundary_validation": "kt_e2e_follow_up_audit_readiness_validation_prep_only_boundary_receipt.json",
    "no_authority_drift_validation": "kt_e2e_follow_up_audit_readiness_validation_no_authority_drift_receipt.json",
    "claim_boundary_validation": "kt_e2e_follow_up_audit_readiness_validation_claim_boundary_receipt.json",
    "external_audit_delta_packet_prep_only": "kt_e2e_follow_up_audit_external_audit_delta_next_prep_only.json",
    "commercial_claim_authorization_packet_prep_only": (
        "kt_e2e_follow_up_audit_commercial_claim_authorization_next_prep_only.json"
    ),
    "public_reaudit_packet_prep_only": "kt_e2e_follow_up_audit_public_reaudit_next_prep_only.json",
    "next_lawful_move": "kt_e2e_follow_up_audit_readiness_validation_next_lawful_move_receipt.json",
}


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


def _is_explicit_negative_claim_field(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in ("forbidden", "blocked", "prohibited", "cannot", "disallowed"))


def _contains_forbidden_claim(value: str) -> bool:
    normalized = value.upper()
    return any(phrase in normalized for phrase in CLAIM_DRIFT_PHRASES)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_KT_E2E_AUDIT_READY_VAL_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_KT_E2E_AUDIT_READY_VAL_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_KT_E2E_AUDIT_READY_VAL_PACKET_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_KT_E2E_AUDIT_READY_VAL_PACKET_MISSING", str(exc))


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in PACKET_JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in PACKET_TEXT_INPUTS.items()}
    return payloads, texts


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _git_blob_hash(root: Path, commit: str, raw_path: str) -> Optional[str]:
    result = subprocess.run(["git", "show", f"{commit}:{raw_path}"], cwd=root, capture_output=True)
    if result.returncode != 0:
        return None
    return hashlib.sha256(result.stdout).hexdigest()


def _packet_is_replay_bound(contract: Dict[str, Any]) -> bool:
    main_head = contract.get("current_main_head")
    return (
        isinstance(main_head, str)
        and len(main_head) == 40
        and contract.get("current_git_head") == main_head
        and contract.get("current_branch_head") == main_head
    )


def _ensure_source_hash_matches(root: Path, contract: Dict[str, Any], row: Dict[str, Any]) -> None:
    raw_path = str(row.get("path", ""))
    expected = row.get("sha256")
    if not _is_sha256(expected):
        _fail("RC_KT_E2E_AUDIT_READY_VAL_INPUT_HASH_MALFORMED", f"malformed source hash for {row!r}")
    path = common.resolve_path(root, raw_path)
    if path.is_file() and file_sha256(path) == expected:
        return
    if _packet_is_replay_bound(contract):
        fallback_hash = _git_blob_hash(root, str(contract["current_main_head"]), raw_path)
        if fallback_hash == expected:
            return
    _fail("RC_KT_E2E_AUDIT_READY_VAL_INPUT_HASH_MISMATCH", f"source hash mismatch for {raw_path}")


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted non-false")
            if isinstance(value, str) and not _is_explicit_negative_claim_field(key) and _contains_forbidden_claim(value):
                _fail("RC_KT_E2E_AUDIT_READY_VAL_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        if _contains_forbidden_claim(text):
            _fail("RC_KT_E2E_AUDIT_READY_VAL_CLAIM_TOKEN_DRIFT", f"{label} contains forbidden claim")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["packet_contract"]
    receipt = payloads["packet_receipt"]
    next_move = payloads["next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_KT_E2E_AUDIT_READY_VAL_PACKET_OUTCOME_DRIFT", "packet contract outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_KT_E2E_AUDIT_READY_VAL_PACKET_OUTCOME_DRIFT", "packet receipt outcome drift")
    if contract.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_KT_E2E_AUDIT_READY_VAL_NEXT_MOVE_DRIFT", "packet contract next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_KT_E2E_AUDIT_READY_VAL_NEXT_MOVE_DRIFT", "packet next-lawful-move receipt drift")
    for key in (
        "r6_open",
        "package_promotion_passed",
        "commercial_activation_executed",
        "commercial_activation_passed",
        "commercial_activation_evidence_review_validated",
        "follow_up_audit_readiness_packet_authored",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    ):
        if contract.get(key) is not True:
            _fail("RC_KT_E2E_AUDIT_READY_VAL_AUDIT_EVIDENCE_INCOMPLETE", f"{key} is not true")
    for key in (
        "follow_up_audit_readiness_validated",
        "commercial_activation_claim_authorized",
        "benchmark_prep_authorizes_commercial_activation",
        "seven_b_amplification_claimed_proven",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
    ):
        if contract.get(key) is not False:
            _fail(AUTHORITY_DRIFT_KEYS.get(key, "RC_KT_E2E_AUDIT_READY_VAL_AUDIT_EVIDENCE_INCOMPLETE"), key)


def _validate_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["packet_contract"]
    binding_hashes = contract.get("binding_hashes", {})
    input_bindings = contract.get("input_bindings")
    if not isinstance(binding_hashes, dict):
        _fail("RC_KT_E2E_AUDIT_READY_VAL_INPUT_HASH_MISSING", "packet missing binding_hashes")
    if not isinstance(input_bindings, list) or not input_bindings:
        _fail("RC_KT_E2E_AUDIT_READY_VAL_INPUT_HASH_MISSING", "packet missing input_bindings")
    for row in input_bindings:
        if not isinstance(row, dict):
            _fail("RC_KT_E2E_AUDIT_READY_VAL_INPUT_HASH_MALFORMED", "malformed packet binding row")
        role = str(row.get("role", "")).strip()
        if binding_hashes.get(f"{role}_hash") != row.get("sha256"):
            _fail("RC_KT_E2E_AUDIT_READY_VAL_INPUT_HASH_MISSING", f"binding hash mismatch for {role}")
        _ensure_source_hash_matches(root, contract, row)


def _validate_claims(payloads: Dict[str, Dict[str, Any]]) -> None:
    allowed = payloads["allowed_claims_current_state"].get("allowed_claims", [])
    forbidden = payloads["forbidden_claims_current_state"].get("forbidden_claims", [])
    if "Commercial activation evidence review is validated." not in allowed:
        _fail("RC_KT_E2E_AUDIT_READY_VAL_AUDIT_EVIDENCE_INCOMPLETE", "missing validated evidence claim")
    if "Follow-up audit readiness packet is authored and awaiting validation." not in allowed:
        _fail("RC_KT_E2E_AUDIT_READY_VAL_AUDIT_EVIDENCE_INCOMPLETE", "missing authored packet claim")
    for phrase in (
        "Commercial activation claims are authorized.",
        "Follow-up audit readiness is validated.",
        "7B amplification is proven.",
    ):
        if phrase not in forbidden:
            _fail("RC_KT_E2E_AUDIT_READY_VAL_BOUNDARY_DRIFT", f"forbidden claim missing: {phrase}")


def _validate_audit_artifacts(payloads: Dict[str, Dict[str, Any]]) -> None:
    board = payloads["canonical_state_board"].get("state", {})
    expected_board = {
        "r6": "OPEN",
        "package_promotion": "PASSED",
        "commercial_activation": "PASSED",
        "commercial_activation_evidence_review": "VALIDATED",
        "follow_up_audit_readiness": "PACKET_AUTHORED_VALIDATION_NEXT",
        "commercial_activation_claims": "UNAUTHORIZED",
        "seven_b_amplification": "NOT_PROVEN",
    }
    if board != expected_board:
        _fail("RC_KT_E2E_AUDIT_READY_VAL_BOUNDARY_DRIFT", "canonical state board drift")
    truth_trust_receipt = payloads["truth_trust_unchanged_receipt"]
    if (
        truth_trust_receipt.get("truth_engine_law_unchanged") is not True
        or truth_trust_receipt.get("trust_zone_law_unchanged") is not True
    ):
        _fail("RC_KT_E2E_AUDIT_READY_VAL_BOUNDARY_DRIFT", "truth/trust receipt drift")
    if payloads["boundary_state_receipt"].get("canonical_lab_archive_commercial_boundary_preserved") is not True:
        _fail("RC_KT_E2E_AUDIT_READY_VAL_BOUNDARY_DRIFT", "boundary receipt drift")
    if "commercial_activation_evidence_review_validation_contract" not in payloads[
        "proof_replay_bundle_manifest"
    ].get("replay_bundle_roles", []):
        _fail("RC_KT_E2E_AUDIT_READY_VAL_AUDIT_EVIDENCE_INCOMPLETE", "proof bundle missing validation role")
    if "follow_up_audit_readiness_packet_not_validated" not in payloads["open_blocker_ledger"].get("blockers", []):
        _fail("RC_KT_E2E_AUDIT_READY_VAL_AUDIT_EVIDENCE_INCOMPLETE", "open blocker ledger drift")
    if "external audit/re-audit has not yet run" not in payloads["known_limitations_ledger"].get("limitations", []):
        _fail("RC_KT_E2E_AUDIT_READY_VAL_AUDIT_EVIDENCE_INCOMPLETE", "known limitations drift")


def _validate_prep_only(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in packet.PREP_ONLY_ROLES:
        payload = payloads[role]
        if payload.get("authority") != "PREP_ONLY" or payload.get("status") != "PREP_ONLY":
            _fail("RC_KT_E2E_AUDIT_READY_VAL_PREP_ONLY_DRIFT", f"{role} is not PREP_ONLY")
        for key in (
            "cannot_authorize_commercial_activation_claims",
            "cannot_claim_follow_up_audit_readiness_validated",
            "cannot_claim_7b_amplification_proven",
            "cannot_mutate_truth_engine_law",
            "cannot_mutate_trust_zone_law",
        ):
            if payload.get(key) is not True:
                _fail("RC_KT_E2E_AUDIT_READY_VAL_PREP_ONLY_DRIFT", f"{role}.{key} drifted")


def _validate_report(text: str) -> None:
    lowered = text.lower()
    for phrase in ("follow-up audit readiness packet", "commercial activation claims remain unauthorized"):
        if phrase not in lowered:
            _fail("RC_KT_E2E_AUDIT_READY_VAL_AUDIT_EVIDENCE_INCOMPLETE", f"report missing {phrase}")


def _validate_packet_payloads(root: Path, payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    _validate_handoff(payloads)
    _validate_hashes(root, payloads)
    _validate_claims(payloads)
    _validate_audit_artifacts(payloads)
    _validate_prep_only(payloads)
    _validate_report(texts["packet_report"])
    _ensure_authority_closed(payloads, texts)


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in sorted({**PACKET_JSON_INPUTS, **PACKET_TEXT_INPUTS}.items()):
        rows.append(
            {
                "role": role,
                "path": raw,
                "sha256": file_sha256(common.resolve_path(root, raw)),
                "binding_kind": "file_sha256_at_follow_up_audit_readiness_validation",
            }
        )
    return rows


def _guard() -> Dict[str, Any]:
    return {
        "r6_open": True,
        "package_promotion_passed": True,
        "commercial_activation_executed": True,
        "commercial_activation_passed": True,
        "commercial_activation_evidence_review_validated": True,
        "follow_up_audit_readiness_packet_authored": True,
        "follow_up_audit_readiness_validated": True,
        "ready_for_reaudit_or_external_review": True,
        "commercial_activation_claim_authorized": False,
        "benchmark_prep_authorizes_commercial_activation": False,
        "seven_b_amplification_claimed_proven": False,
        "truth_engine_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_changed": False,
        "trust_zone_law_unchanged": True,
        "cannot_authorize_commercial_activation_claims": True,
        "cannot_claim_7b_amplification_proven": True,
        "cannot_mutate_truth_engine_law": True,
        "cannot_mutate_trust_zone_law": True,
    }


def _base(
    *,
    generated_utc: str,
    head: str,
    branch_head: str,
    current_main_head: str,
    branch: str,
    input_bindings: list[Dict[str, str]],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_version": "v1",
        "generated_utc": generated_utc,
        "current_git_head": head,
        "current_branch_head": branch_head,
        "current_main_head": current_main_head,
        "current_branch": branch,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "allowed_outcomes": [
            SELECTED_OUTCOME,
            OUTCOME_EXTERNAL_AUDIT,
            OUTCOME_COMMERCIAL_CLAIM,
            OUTCOME_DEFERRED,
            OUTCOME_INVALID,
        ],
        "outcome_routing": {
            SELECTED_OUTCOME: NEXT_LAWFUL_MOVE,
            OUTCOME_EXTERNAL_AUDIT: "AUTHOR_KT_E2E_EXTERNAL_AUDIT_DELTA_PACKET",
            OUTCOME_COMMERCIAL_CLAIM: "AUTHOR_KT_E2E_COMMERCIAL_CLAIM_AUTHORIZATION_PACKET",
            OUTCOME_DEFERRED: "REPAIR_KT_E2E_FOLLOW_UP_AUDIT_READINESS_DEFECTS",
            OUTCOME_INVALID: "AUTHOR_KT_E2E_FORENSIC_AUDIT_READINESS_REVIEW_PACKET",
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


def _prep_only(base: Dict[str, Any], role: str, purpose: str) -> Dict[str, Any]:
    return _artifact(
        base,
        schema_id=f"kt.e2e.follow_up_audit_readiness.validation.{role}.prep_only.v1",
        artifact_id=f"KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATION_{role.upper()}",
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
        "validation_contract": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.validation_contract.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATION_CONTRACT",
            validation_summary="Follow-up audit readiness validates for re-audit or external review.",
        ),
        "validation_receipt": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.validation_receipt.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATION_RECEIPT",
            verdict="READY_FOR_REAUDIT_OR_EXTERNAL_REVIEW",
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.validation_next_lawful_move.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATION_NEXT_LAWFUL_MOVE",
            final_target=SELECTED_OUTCOME,
        ),
        "prep_only_boundary_validation": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.validation_prep_only_boundary.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATION_PREP_ONLY_BOUNDARY",
            validation_status="PASS",
        ),
        "no_authority_drift_validation": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.validation_no_authority_drift.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATION_NO_AUTHORITY_DRIFT",
            validation_status="PASS",
        ),
        "claim_boundary_validation": _artifact(
            base,
            schema_id="kt.e2e.follow_up_audit_readiness.validation_claim_boundary.v1",
            artifact_id="KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATION_CLAIM_BOUNDARY",
            validation_status="PASS",
            commercial_activation_claims_remain_unauthorized=True,
        ),
    }
    for role, inputs in VALIDATION_MAP.items():
        payloads[role] = _artifact(
            base,
            schema_id=f"kt.e2e.follow_up_audit_readiness.validation.{role}.v1",
            artifact_id=f"KT_E2E_FOLLOW_UP_AUDIT_READINESS_{role.upper()}",
            validation_status="PASS",
            validated_inputs=list(inputs),
        )
    payloads["external_audit_delta_packet_prep_only"] = _prep_only(
        base, "external_audit_delta_packet", "Prepare a future external audit delta packet after readiness validation."
    )
    payloads["commercial_claim_authorization_packet_prep_only"] = _prep_only(
        base,
        "commercial_claim_authorization_packet",
        "Prepare future commercial claim authorization without granting claim authority.",
    )
    payloads["public_reaudit_packet_prep_only"] = _prep_only(
        base, "public_reaudit_packet", "Prepare a public re-audit packet after validation."
    )
    return payloads


def _write_report(root: Path, base: Dict[str, Any]) -> None:
    path = common.resolve_path(root, f"KT_PROD_CLEANROOM/reports/{OUTPUTS['validation_report']}")
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(
        [
            "# KT E2E Follow-Up Audit Readiness Validation",
            "",
            f"Outcome: `{base['selected_outcome']}`",
            f"Next lawful move: `{base['next_lawful_move']}`",
            "",
            "Follow-up audit readiness is validated for re-audit or external review.",
            "Commercial activation claims remain unauthorized until a separate claim authority validates.",
            "Truth/trust law remains unchanged.",
            "Benchmark/provider/7B prep remains non-authoritative; 7B amplification is not proven.",
            "",
        ]
    )
    path.write_text(text, encoding="utf-8")


def run(*, reports_root: Path) -> Dict[str, str]:
    root = repo_root()
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before KT E2E follow-up audit readiness validation")
    branch = _ensure_branch_context(root)
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main")
    branch_head = current_main_head if branch == "main" else head
    payloads, texts = _payloads(root)
    _validate_packet_payloads(root, payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS":
        _fail("RC_KT_E2E_AUDIT_READY_VAL_TRUST_ZONE_FAILED", "trust-zone validation failed")
    input_bindings = _input_bindings(root)
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        branch_head=branch_head,
        current_main_head=current_main_head,
        branch=branch,
        input_bindings=input_bindings,
        trust_zone_validation=trust_zone_validation,
    )
    outputs = _outputs(base)
    reports_root.mkdir(parents=True, exist_ok=True)
    written: Dict[str, str] = {}
    for role, payload in outputs.items():
        filename = OUTPUTS[role]
        write_json_stable(reports_root / filename, payload)
        written[role] = filename
    _write_report(root, base)
    written["validation_report"] = OUTPUTS["validation_report"]
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    result = run(reports_root=(repo_root() / args.reports_root).resolve())
    contract = common.load_json_required(repo_root(), f"KT_PROD_CLEANROOM/reports/{result['validation_contract']}")
    print(contract["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
