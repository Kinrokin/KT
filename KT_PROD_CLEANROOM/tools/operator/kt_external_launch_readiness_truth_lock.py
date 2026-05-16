from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/kt-external-launch-readiness-truth-lock"
REPLAY_BRANCH_PREFIX = "replay/kt-external-launch-readiness-truth-lock"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_SUPERLANE_V1"
PREVIOUS_LANE = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_PACKET_VALIDATION"
EXPECTED_PREVIOUS_OUTCOME = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATED__READY_FOR_REAUDIT_OR_EXTERNAL_REVIEW"
EXPECTED_PREVIOUS_NEXT_MOVE = "READY_FOR_REAUDIT_OR_EXTERNAL_REVIEW"

SELECTED_OUTCOME = "KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_BOUND__TRUTH_LOCK_VALIDATION_NEXT"
NEXT_LAWFUL_MOVE = "VALIDATE_KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_SUPERLANE_V1"
VALIDATED_SUCCESS_OUTCOME = "KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_VALIDATED__DETACHED_VERIFIER_KIT_NEXT"
VALIDATED_NEXT_LAWFUL_MOVE = "AUTHOR_KT_DETACHED_VERIFIER_KIT_SUPERLANE_V1"

FORBIDDEN_ACTIONS = (
    "COMMERCIAL_ACTIVATION_CLAIM_AUTHORIZED",
    "EXTERNAL_AUDIT_COMPLETED",
    "SEVEN_B_AMPLIFICATION_CLAIMED_PROVEN",
    "BEYOND_SOTA_CLAIM_AUTHORIZED",
    "FULL_CIVILIZATION_STACK_PRODUCTION_READY",
    "TRUTH_ENGINE_LAW_MUTATED",
    "TRUST_ZONE_LAW_MUTATED",
)

AUTHORITY_DRIFT_KEYS = {
    "commercial_activation_claim_authorized": "RC_KT_TRUTH_LOCK_COMMERCIAL_CLAIM_DRIFT",
    "external_audit_completed": "RC_KT_TRUTH_LOCK_EXTERNAL_AUDIT_DRIFT",
    "seven_b_amplification_claimed_proven": "RC_KT_TRUTH_LOCK_7B_DRIFT",
    "beyond_sota_claim_authorized": "RC_KT_TRUTH_LOCK_SOTA_DRIFT",
    "full_civilization_stack_production_ready": "RC_KT_TRUTH_LOCK_CIV_STACK_DRIFT",
    "truth_engine_law_changed": "RC_KT_TRUTH_LOCK_TRUTH_ENGINE_MUTATION",
    "trust_zone_law_changed": "RC_KT_TRUTH_LOCK_TRUST_ZONE_MUTATION",
}

CLAIM_DRIFT_PHRASES = (
    "COMMERCIAL ACTIVATION CLAIMS ARE AUTHORIZED",
    "COMMERCIAL ACTIVATION CLAIM AUTHORIZED",
    "KT IS PRODUCTION-COMMERCIAL LIVE",
    "EXTERNAL AUDIT IS COMPLETE",
    "EXTERNAL REAUDIT IS COMPLETE",
    "7B AMPLIFICATION IS PROVEN",
    "BEYOND-SOTA",
    "BEYOND SOTA",
    "FULL CIVILIZATION STACK IS PRODUCTION READY",
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_TRUTH_LOCK_INPUT_MISSING",
            "RC_KT_TRUTH_LOCK_PREVIOUS_OUTCOME_DRIFT",
            "RC_KT_TRUTH_LOCK_NEXT_MOVE_DRIFT",
            "RC_KT_TRUTH_LOCK_INPUT_HASH_MISMATCH",
            "RC_KT_TRUTH_LOCK_CLAIM_TOKEN_DRIFT",
            "RC_KT_TRUTH_LOCK_TRUST_ZONE_FAILED",
            *tuple(AUTHORITY_DRIFT_KEYS.values()),
        )
    )
)

INPUTS = {
    "follow_up_audit_validation_contract": (
        "KT_PROD_CLEANROOM/reports/kt_e2e_follow_up_audit_readiness_validation_contract.json"
    ),
    "follow_up_audit_validation_receipt": (
        "KT_PROD_CLEANROOM/reports/kt_e2e_follow_up_audit_readiness_validation_receipt.json"
    ),
    "follow_up_audit_validation_next_lawful_move": (
        "KT_PROD_CLEANROOM/reports/kt_e2e_follow_up_audit_readiness_validation_next_lawful_move_receipt.json"
    ),
    "allowed_claims_current_state": "KT_PROD_CLEANROOM/reports/kt_e2e_follow_up_audit_allowed_claims_current_state.json",
    "forbidden_claims_current_state": "KT_PROD_CLEANROOM/reports/kt_e2e_follow_up_audit_forbidden_claims_current_state.json",
    "canonical_state_board": "KT_PROD_CLEANROOM/reports/kt_e2e_follow_up_audit_canonical_state_board.json",
    "proof_replay_bundle_manifest": "KT_PROD_CLEANROOM/reports/kt_e2e_follow_up_audit_proof_replay_bundle_manifest.json",
    "external_verifier_manifest": "KT_PROD_CLEANROOM/reports/kt_e2e_follow_up_audit_external_verifier_manifest.json",
    "known_limitations_ledger": "KT_PROD_CLEANROOM/reports/kt_e2e_follow_up_audit_known_limitations_ledger.json",
    "open_blocker_ledger": "KT_PROD_CLEANROOM/reports/kt_e2e_follow_up_audit_open_blocker_ledger.json",
    "truth_trust_receipt": "KT_PROD_CLEANROOM/reports/kt_e2e_follow_up_audit_truth_trust_unchanged_receipt.json",
}

JSON_OUTPUTS = {
    "current_truth_head": "governance/current_truth_head.json",
    "current_truth_head_receipt": "governance/current_truth_head_receipt.json",
    "canonical_scope_manifest": "governance/canonical_scope_manifest.json",
    "supersession_ledger": "governance/supersession_ledger.json",
    "stale_receipt_quarantine_receipt": "governance/stale_receipt_quarantine_receipt.json",
    "artifact_authority_classification": "governance/artifact_authority_classification.json",
    "truth_lock_validation_plan": "governance/truth_lock_validation_plan.json",
    "truth_lock_validation_reason_codes": "governance/truth_lock_validation_reason_codes.json",
    "truth_lock_next_lawful_move_receipt": "governance/truth_lock_next_lawful_move_receipt.json",
    "external_launch_readiness_board": "governance/external_launch_readiness_board.json",
}

TEXT_OUTPUTS = {
    "claim_authority_matrix": "governance/claim_authority_matrix.yaml",
    "hard_refusal_tokens": "governance/hard_refusal_tokens.yaml",
    "reviewer_readme": "external/reviewer_readme.md",
    "known_limitations": "external/known_limitations.md",
    "audit_scope": "external/audit_scope.md",
    "kt_current_state_one_page": "external/kt_current_state_one_page.md",
}

OUTPUTS = {**JSON_OUTPUTS, **TEXT_OUTPUTS}


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
    return any(marker in lowered for marker in ("forbidden", "blocked", "prohibited", "cannot", "disallowed", "refusal"))


def _contains_forbidden_claim(value: str) -> bool:
    normalized = value.upper()
    return any(phrase in normalized for phrase in CLAIM_DRIFT_PHRASES)


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_KT_TRUTH_LOCK_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_KT_TRUTH_LOCK_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_KT_TRUTH_LOCK_INPUT_MISSING", f"{label} must be a JSON object")
    return payload


def _payloads(root: Path) -> Dict[str, Dict[str, Any]]:
    return {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}


def _ensure_authority_closed(payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail(AUTHORITY_DRIFT_KEYS[key], f"{label}.{key} drifted non-false")
            if isinstance(value, str) and not _is_negative_field(key) and _contains_forbidden_claim(value):
                _fail("RC_KT_TRUTH_LOCK_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")


def _validate_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["follow_up_audit_validation_contract"]
    receipt = payloads["follow_up_audit_validation_receipt"]
    next_move = payloads["follow_up_audit_validation_next_lawful_move"]
    if contract.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_KT_TRUTH_LOCK_PREVIOUS_OUTCOME_DRIFT", "follow-up audit validation contract outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_KT_TRUTH_LOCK_PREVIOUS_OUTCOME_DRIFT", "follow-up audit validation receipt outcome drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_KT_TRUTH_LOCK_NEXT_MOVE_DRIFT", "follow-up audit next lawful move drift")
    required_flags = {
        "ready_for_reaudit_or_external_review": True,
        "follow_up_audit_readiness_validated": True,
        "commercial_activation_claim_authorized": False,
        "benchmark_prep_authorizes_commercial_activation": False,
        "seven_b_amplification_claimed_proven": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }
    for key, expected in required_flags.items():
        if contract.get(key) is not expected:
            _fail("RC_KT_TRUTH_LOCK_PREVIOUS_OUTCOME_DRIFT", f"follow-up audit validation {key} drifted")


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows = []
    for role, raw in INPUTS.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_TRUTH_LOCK_INPUT_MISSING", f"{role} missing at {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _binding_hashes(rows: Iterable[Dict[str, str]]) -> Dict[str, str]:
    return {f"{row['role']}_hash": row["sha256"] for row in rows}


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
        "allowed_outcomes": [
            SELECTED_OUTCOME,
            "KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_DEFERRED__NAMED_TRUTH_LOCK_DEFECT_REMAINS",
            "KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_INVALID__FORENSIC_TRUTH_LOCK_REVIEW_NEXT",
        ],
        "authoritative_lane": AUTHORITATIVE_LANE,
        "binding_hashes": _binding_hashes(input_bindings),
        "cannot_authorize_commercial_activation_claims": True,
        "cannot_claim_7b_amplification_proven": True,
        "cannot_claim_beyond_sota": True,
        "cannot_claim_external_audit_complete": True,
        "cannot_claim_full_civilization_stack_ready": True,
        "cannot_mutate_truth_engine_law": True,
        "cannot_mutate_trust_zone_law": True,
        "commercial_activation_claim_authorized": False,
        "commercial_activation_executed": True,
        "commercial_activation_passed": True,
        "current_branch": branch,
        "current_branch_head": head,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "external_audit_completed": False,
        "follow_up_audit_readiness_validated": True,
        "forbidden_actions": list(FORBIDDEN_ACTIONS),
        "generated_utc": generated_utc,
        "input_bindings": input_bindings,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "package_promotion_passed": True,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "r6_open": True,
        "ready_for_reaudit_or_external_review": True,
        "selected_outcome": SELECTED_OUTCOME,
        "seven_b_amplification_claimed_proven": False,
        "truth_engine_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_changed": False,
        "trust_zone_law_unchanged": True,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _json_outputs(base: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    allowed_claims = [
        "KT is ready for re-audit or external review.",
        "Follow-up audit readiness is validated.",
        "Commercial activation ran and passed under packet law.",
        "Commercial activation evidence review is validated.",
        "R6 is open.",
        "Package promotion passed.",
    ]
    forbidden_claims = [
        "Commercial activation claims are authorized.",
        "External audit is complete.",
        "KT is production-commercial live.",
        "7B amplification is proven.",
        "KT has a beyond-SOTA claim.",
        "The full civilization stack is production ready.",
    ]
    current_truth = {
        "status": "READY_FOR_REAUDIT_OR_EXTERNAL_REVIEW",
        "allowed_claims": allowed_claims,
        "forbidden_claims": forbidden_claims,
        "commercial_activation_claims": "UNAUTHORIZED",
        "external_audit": "NOT_COMPLETED",
        "seven_b_amplification": "NOT_PROVEN",
        "benchmark_provider_prep": "NON_AUTHORITATIVE",
        "truth_trust_law": "UNCHANGED",
    }
    return {
        "current_truth_head": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.current_truth_head.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_CURRENT_TRUTH_HEAD",
            current_truth=current_truth,
            launch_positioning="KT Verifier / KT Evidence Pack / KT Claim Compiler",
        ),
        "current_truth_head_receipt": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.current_truth_head_receipt.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_CURRENT_TRUTH_HEAD_RECEIPT",
            receipt_type="TRUTH_LOCK_AUTHORING_RECEIPT",
            truth_locked_for_external_consumption=False,
            validation_required=True,
        ),
        "canonical_scope_manifest": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.canonical_scope_manifest.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_CANONICAL_SCOPE_MANIFEST",
            canonical_scope=[
                "governance/current_truth_head.json",
                "governance/claim_authority_matrix.yaml",
                "governance/hard_refusal_tokens.yaml",
                "external/reviewer_readme.md",
                "external/audit_scope.md",
                "external/kt_current_state_one_page.md",
            ],
            lab_archive_commercial_boundary="canonical truth controls external posture; lab/archive material is non-authoritative unless indexed here",
        ),
        "supersession_ledger": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.supersession_ledger.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_SUPERSESSION_LEDGER",
            supersedes=[
                "pre-follow-up-audit-readiness claim ceilings",
                "branch-only commercial activation status summaries",
                "archive or generated reports not listed in current_truth_head bindings",
            ],
            supersession_policy="Current truth head wins over stale reports, branch artifacts, generated summaries, and archive material.",
        ),
        "stale_receipt_quarantine_receipt": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.stale_receipt_quarantine_receipt.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_STALE_RECEIPT_QUARANTINE_RECEIPT",
            quarantine_policy="Stale or historical proof is demoted, hashed, archived, and indexed rather than deleted.",
            deletion_authorized=False,
        ),
        "artifact_authority_classification": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.artifact_authority_classification.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_ARTIFACT_AUTHORITY_CLASSIFICATION",
            classifications={
                "governance/current_truth_head.json": "CURRENT_AUTHORITY_AFTER_VALIDATION",
                "external/current docs": "EXTERNAL_REVIEWER_SURFACE_AFTER_VALIDATION",
                "KT_PROD_CLEANROOM/reports": "SOURCE_EVIDENCE_AND_HISTORICAL_PROOF",
                "repo cleanup archive manifests": "NON_DESTRUCTIVE_INDEX",
                "benchmark/provider/7B prep": "PREP_ONLY",
            },
        ),
        "truth_lock_validation_plan": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.validation_plan.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_VALIDATION_PLAN",
            required_validations=[
                "current truth head binds follow-up audit readiness validation",
                "claim authority matrix forbids claim expansion",
                "hard refusal tokens cover commercial, audit, 7B, SOTA, and civilization-stack overclaims",
                "external docs match current truth",
                "stale proof is quarantined/indexed without deletion",
            ],
        ),
        "truth_lock_validation_reason_codes": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.validation_reason_codes.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_VALIDATION_REASON_CODES",
            reason_code_taxonomy=list(REASON_CODES),
        ),
        "truth_lock_next_lawful_move_receipt": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.next_lawful_move_receipt.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_NEXT_LAWFUL_MOVE_RECEIPT",
            receipt_type="NEXT_LAWFUL_MOVE",
        ),
        "external_launch_readiness_board": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.board.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_BOARD",
            board={
                "truth_lock": "PACKET_AUTHORED_VALIDATION_NEXT",
                "detached_verifier": "BLOCKED_UNTIL_TRUTH_LOCK_VALIDATES",
                "commercial_activation_claims": "UNAUTHORIZED",
                "external_audit": "NOT_COMPLETED",
                "seven_b_amplification": "NOT_PROVEN",
                "repo_cleanup": "NON_DESTRUCTIVE_PARALLEL_INDEXING",
            },
        ),
    }


def _yaml_claim_authority() -> str:
    return "\n".join(
        [
            "schema_id: kt.external_launch_readiness.truth_lock.claim_authority_matrix.v1",
            "artifact_id: KT_EXTERNAL_LAUNCH_READINESS_CLAIM_AUTHORITY_MATRIX",
            "authority: AUTHORING_PACKET_VALIDATION_REQUIRED",
            "claim_classes:",
            "  ready_for_reaudit_or_external_review: ALLOWED_AFTER_TRUTH_LOCK_VALIDATION",
            "  commercial_activation_ran: ALLOWED_WITH_PACKET_LAW_BOUNDARY",
            "  commercial_activation_claims_authorized: FORBIDDEN_REQUIRES_SEPARATE_CLAIM_AUTHORITY",
            "  external_audit_complete: FORBIDDEN_NOT_YET_RUN",
            "  seven_b_amplification_proven: FORBIDDEN_NOT_PROVEN",
            "  beyond_sota: FORBIDDEN_NOT_EARNED",
            "  full_civilization_stack_ready: FORBIDDEN_NOT_RATIFIED",
            "  truth_engine_law_mutation: FORBIDDEN",
            "  trust_zone_law_mutation: FORBIDDEN",
            "",
        ]
    )


def _yaml_refusal_tokens() -> str:
    return "\n".join(
        [
            "schema_id: kt.external_launch_readiness.truth_lock.hard_refusal_tokens.v1",
            "artifact_id: KT_EXTERNAL_LAUNCH_READINESS_HARD_REFUSAL_TOKENS",
            "blocked_claim_tokens:",
            "  - commercial activation claims authorized",
            "  - production-commercial live",
            "  - external audit complete",
            "  - external reaudit complete",
            "  - 7B amplification proven",
            "  - beyond-SOTA",
            "  - full civilization stack production ready",
            "allowed_negative_contexts:",
            "  - forbidden",
            "  - blocked",
            "  - prohibited",
            "  - unauthorized",
            "  - not proven",
            "  - not complete",
            "  - cannot claim",
            "",
        ]
    )


def _reviewer_readme() -> str:
    return "\n".join(
        [
            "# KT External Reviewer Readme",
            "",
            "KT is ready for re-audit or external review.",
            "Use `governance/current_truth_head.json` as the current external-facing truth source after Truth Lock validation.",
            "Commercial activation ran and passed under packet law, but commercial activation claims remain unauthorized.",
            "Benchmark/provider/7B prep is non-authoritative, and 7B amplification remains unproven.",
            "Truth-engine and trust-zone law remain unchanged.",
            "",
        ]
    )


def _known_limitations() -> str:
    return "\n".join(
        [
            "# KT Known Limitations",
            "",
            "- External audit or re-audit has not been completed.",
            "- Commercial activation claims require a separate validated claim-authority lane.",
            "- 7B amplification remains unproven until benchmark ablation evidence validates.",
            "- Adaptive/civilization-stack production readiness remains outside current authority.",
            "- Historical proof remains available as archived/indexed evidence, not current truth.",
            "",
        ]
    )


def _audit_scope() -> str:
    return "\n".join(
        [
            "# KT Audit Scope",
            "",
            "In scope: current truth head, claim authority matrix, proof/replay bundle, external verifier manifest, R6/package/commercial activation evidence, and truth/trust unchanged receipts.",
            "Out of scope: unrestricted commercial claims, external audit completion claims, beyond-SOTA claims, 7B amplification proof claims, and production-ready civilization-stack claims.",
            "",
        ]
    )


def _one_page() -> str:
    return "\n".join(
        [
            "# KT Current State One Page",
            "",
            "KT is ready for re-audit or external review.",
            "R6 is open. Package promotion passed. Commercial activation ran and passed under packet law.",
            "Commercial activation claims are not authorized.",
            "External audit is not complete. 7B amplification is not proven.",
            "The buyer-safe positioning is KT Verifier / KT Evidence Pack / KT Claim Compiler.",
            "",
        ]
    )


def _text_outputs() -> Dict[str, str]:
    return {
        "claim_authority_matrix": _yaml_claim_authority(),
        "hard_refusal_tokens": _yaml_refusal_tokens(),
        "reviewer_readme": _reviewer_readme(),
        "known_limitations": _known_limitations(),
        "audit_scope": _audit_scope(),
        "kt_current_state_one_page": _one_page(),
    }


def run(*, output_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    output_root = output_root or root
    if output_root.resolve() != root.resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical repository root only")
    branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before KT external launch readiness Truth Lock")
    payloads = _payloads(root)
    _ensure_authority_closed(payloads)
    _validate_handoff(payloads)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_TRUTH_LOCK_TRUST_ZONE_FAILED", "trust-zone validation failed")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    input_bindings = _input_bindings(root)
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        trust_zone_validation=trust_zone_validation,
        input_bindings=input_bindings,
    )
    json_outputs = _json_outputs(base)
    text_outputs = _text_outputs()
    for role, raw in JSON_OUTPUTS.items():
        write_json_stable(output_root / raw, json_outputs[role])
    for role, raw in TEXT_OUTPUTS.items():
        path = output_root / raw
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text_outputs[role], encoding="utf-8", newline="\n")
    return json_outputs["current_truth_head"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=AUTHORITATIVE_LANE)
    parser.add_argument("--output-root", default=".")
    args = parser.parse_args(argv)
    result = run(output_root=(repo_root() / args.output_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
