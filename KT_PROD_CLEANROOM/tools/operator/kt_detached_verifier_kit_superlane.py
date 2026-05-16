from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "author/kt-detached-verifier-kit-superlane-v1"
REPLAY_BRANCH_PREFIX = "replay/kt-detached-verifier-kit-superlane-v1"
VALIDATION_BRANCH = "validate/kt-detached-verifier-kit-superlane-v1"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, VALIDATION_BRANCH, "main"})

AUTHORITATIVE_LANE = "KT_DETACHED_VERIFIER_KIT_SUPERLANE_V1"
EXPECTED_PREVIOUS_OUTCOME = "KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_VALIDATED__DETACHED_VERIFIER_KIT_NEXT"
EXPECTED_PREVIOUS_NEXT_MOVE = "AUTHOR_KT_DETACHED_VERIFIER_KIT_SUPERLANE_V1"
SELECTED_OUTCOME = (
    "KT_DETACHED_VERIFIER_KIT_SUPERLANE_V1_AUTHORED__"
    "HIGHWAY_SHADOW_AND_FP0_OVERLAY_ELIGIBLE_NON_CLAIM_EXPANSION"
)
NEXT_LAWFUL_MOVE = "VALIDATE_KT_DETACHED_VERIFIER_KIT_SUPERLANE_V1"

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_DETACHED_VERIFIER_PREDECESSOR_MISSING",
            "RC_KT_DETACHED_VERIFIER_PREDECESSOR_OUTCOME_DRIFT",
            "RC_KT_DETACHED_VERIFIER_PREDECESSOR_NEXT_MOVE_DRIFT",
            "RC_KT_DETACHED_VERIFIER_PREDECESSOR_HASH_MISMATCH",
            "RC_KT_DETACHED_VERIFIER_BOUNDARY_DRIFT",
            "RC_KT_DETACHED_VERIFIER_CLAIM_TOKEN_DRIFT",
            "RC_KT_DETACHED_VERIFIER_BRANCH_DRIFT",
            "RC_KT_DETACHED_VERIFIER_TRUST_ZONE_FAILED",
        )
    )
)

INPUTS = {
    "truth_lock_validation_contract": "governance/truth_lock_validation_contract.json",
    "truth_lock_validation_receipt": "governance/truth_lock_validation_receipt.json",
    "truth_lock_validation_next_lawful_move_receipt": "governance/truth_lock_validation_next_lawful_move_receipt.json",
    "detached_verifier_kit_next_prep_only": "governance/detached_verifier_kit_next_prep_only.json",
    "current_truth_head": "governance/current_truth_head.json",
    "artifact_authority_classification": "governance/artifact_authority_classification.json",
}

OPTIONAL_INPUTS = {
    "public_verifier_manifest": "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
    "public_verifier_kit": "KT_PROD_CLEANROOM/reports/public_verifier_kit.json",
    "public_verifier_detached_receipt": "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
    "external_audit_packet_manifest": "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json",
}

OUTPUTS = {
    "constitution": "governance/detached_verifier_kit_constitution_v1.json",
    "manifest": "governance/detached_verifier_kit_manifest_v1.json",
    "evidence_bundle": "governance/detached_verifier_evidence_bundle_v1.json",
    "replay_protocol": "governance/detached_verifier_replay_protocol_v1.json",
    "audit_safe_proof_contract": "governance/detached_verifier_audit_safe_proof_contract_v1.json",
    "claim_limiter": "governance/detached_verifier_claim_limiter_v1.json",
    "negative_test_matrix": "governance/detached_verifier_negative_test_matrix_v1.json",
    "ci_matrix": "governance/detached_verifier_ci_matrix_v1.json",
    "parallel_lane_eligibility": "governance/detached_verifier_parallel_lane_eligibility_receipt.json",
    "next_lawful_move": "governance/detached_verifier_next_lawful_move_receipt.json",
    "receipt": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_kit_superlane_receipt.json",
    "report": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_kit_superlane_report.md",
}

WORKSTREAM_FILES_TOUCHED = sorted(
    set(
        [
            "KT_PROD_CLEANROOM/tools/operator/kt_detached_verifier_kit_superlane.py",
            "KT_PROD_CLEANROOM/tests/operator/test_kt_detached_verifier_kit_superlane.py",
            *OUTPUTS.values(),
        ]
    )
)

AUTHORITY_DRIFT_KEYS = {
    "commercial_activation_claim_authorized",
    "external_audit_completed",
    "seven_b_amplification_claimed_proven",
    "detached_verifier_clean_room_replay_run",
    "detached_verifier_external_audit_completed",
    "highway_shadow_promoted_to_authority",
    "fp0_overlay_promoted_to_authority",
}

CLAIM_DRIFT_PHRASES = (
    "COMMERCIAL ACTIVATION CLAIMS ARE AUTHORIZED",
    "COMMERCIAL ACTIVATION IS AUTHORIZED",
    "EXTERNAL AUDIT IS COMPLETE",
    "EXTERNAL AUDIT COMPLETED",
    "7B AMPLIFICATION IS PROVEN",
    "SEVEN B AMPLIFICATION IS PROVEN",
    "BEYOND-SOTA",
    "BEYOND SOTA",
    "DETACHED VERIFIER CLEAN ROOM REPLAY HAS RUN",
    "DETACHED VERIFIER KIT IS EXTERNALLY VALIDATED",
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
    return any(marker in lowered for marker in ("forbidden", "blocked", "prohibited", "cannot", "disallowed", "refusal"))


def _is_machine_routing_field(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in ("outcome", "next_lawful_move", "allowed_outcomes", "lane_id", "artifact_id", "schema_id"))


def _is_negative_text_context(value: str) -> bool:
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in (
            "not authorized",
            "not proven",
            "not complete",
            "not completed",
            "forbidden",
            "blocked",
            "prohibited",
            "out of scope",
            "cannot claim",
            "does not claim",
            "does not authorize",
            "requires a separate",
            "requires separate",
            "must not claim",
            "remains unauthorized",
        )
    )


def _contains_forbidden_claim(value: str) -> bool:
    normalized = value.upper()
    return any(phrase in normalized for phrase in CLAIM_DRIFT_PHRASES)


def _status_relpaths(status: str) -> list[str]:
    rows: list[str] = []
    for line in status.splitlines():
        if not line.strip():
            continue
        rel = line[3:].strip().replace("\\", "/")
        if rel:
            rows.append(rel)
    return rows


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_KT_DETACHED_VERIFIER_BRANCH_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_KT_DETACHED_VERIFIER_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_DETACHED_VERIFIER_BRANCH_DRIFT", "dirty worktree outside Detached Verifier kit scope: " + ", ".join(out_of_scope))


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_KT_DETACHED_VERIFIER_PREDECESSOR_MISSING", f"{label} must be a JSON object")
    return payload


def _load_inputs(root: Path) -> Dict[str, Dict[str, Any]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in INPUTS.items()}
    for role, raw in OPTIONAL_INPUTS.items():
        path = common.resolve_path(root, raw)
        if path.is_file():
            payloads[role] = _load(root, raw, label=role)
    return payloads


def _ensure_claim_boundary(payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail("RC_KT_DETACHED_VERIFIER_BOUNDARY_DRIFT", f"{label}.{key} drifted non-false")
            if isinstance(value, str) and not _is_negative_field(key) and not _is_machine_routing_field(key):
                if _contains_forbidden_claim(value) and not _is_negative_text_context(value):
                    _fail("RC_KT_DETACHED_VERIFIER_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")


def _ensure_predecessor(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in (
        "truth_lock_validation_contract",
        "truth_lock_validation_receipt",
        "truth_lock_validation_next_lawful_move_receipt",
        "detached_verifier_kit_next_prep_only",
    ):
        payload = payloads[role]
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_DETACHED_VERIFIER_PREDECESSOR_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_DETACHED_VERIFIER_PREDECESSOR_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        required = {
            "truth_lock_validated": True,
            "commercial_activation_claim_authorized": False,
            "external_audit_completed": False,
            "seven_b_amplification_claimed_proven": False,
            "truth_engine_law_unchanged": True,
            "trust_zone_law_unchanged": True,
        }
        for key, expected in required.items():
            if payload.get(key) is not expected:
                _fail("RC_KT_DETACHED_VERIFIER_BOUNDARY_DRIFT", f"{role}.{key} drifted")


def _binding_rows(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in {**INPUTS, **OPTIONAL_INPUTS}.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            if role in OPTIONAL_INPUTS:
                continue
            _fail("RC_KT_DETACHED_VERIFIER_PREDECESSOR_MISSING", f"missing {role}: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _ensure_validation_bindings_recompute(root: Path, payloads: Dict[str, Dict[str, Any]]) -> None:
    contract = payloads["truth_lock_validation_contract"]
    rows = contract.get("artifact_bindings")
    if not isinstance(rows, list) or not rows:
        _fail("RC_KT_DETACHED_VERIFIER_PREDECESSOR_HASH_MISMATCH", "Truth Lock validation artifact_bindings missing")
    for row in rows:
        if not isinstance(row, dict):
            _fail("RC_KT_DETACHED_VERIFIER_PREDECESSOR_HASH_MISMATCH", "Truth Lock validation binding row malformed")
        raw = str(row.get("path", "")).strip()
        expected = str(row.get("sha256", "")).strip()
        if not raw or len(expected) != 64:
            _fail("RC_KT_DETACHED_VERIFIER_PREDECESSOR_HASH_MISMATCH", "Truth Lock validation binding incomplete")
        path = common.resolve_path(root, raw)
        if not path.is_file() or file_sha256(path) != expected:
            _fail("RC_KT_DETACHED_VERIFIER_PREDECESSOR_HASH_MISMATCH", f"source hash mismatch for {raw}")


def _base(
    *,
    branch: str,
    head: str,
    current_main_head: str,
    generated_utc: str,
    input_bindings: list[Dict[str, str]],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "allowed_outcomes": [
            SELECTED_OUTCOME,
            "KT_DETACHED_VERIFIER_KIT_SUPERLANE_V1_DEFERRED__NAMED_AUTHORING_DEFECT_REMAINS",
            "KT_DETACHED_VERIFIER_KIT_SUPERLANE_V1_INVALID__FORENSIC_TRUTH_LOCK_REVIEW_NEXT",
        ],
        "authoritative_lane": AUTHORITATIVE_LANE,
        "authority": "AUTHORING_ONLY",
        "binding_hashes": {f"{row['role']}_hash": row["sha256"] for row in input_bindings},
        "cannot_authorize_commercial_activation_claims": True,
        "cannot_claim_7b_amplification_proven": True,
        "cannot_claim_beyond_sota": True,
        "cannot_claim_external_audit_complete": True,
        "cannot_mutate_truth_engine_law": True,
        "cannot_mutate_trust_zone_law": True,
        "commercial_activation_claim_authorized": False,
        "current_branch": branch,
        "current_branch_head": head,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "detached_verifier_clean_room_replay_run": False,
        "detached_verifier_external_audit_completed": False,
        "external_audit_completed": False,
        "fp0_overlay_eligible_non_claim_expansion": True,
        "fp0_overlay_promoted_to_authority": False,
        "generated_utc": generated_utc,
        "highway_shadow_eligible_non_claim_expansion": True,
        "highway_shadow_promoted_to_authority": False,
        "input_bindings": input_bindings,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "predecessor_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "selected_outcome": SELECTED_OUTCOME,
        "seven_b_amplification_claimed_proven": False,
        "truth_engine_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        "trust_zone_law_changed": False,
        "trust_zone_law_unchanged": True,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "truth_lock_validated": True,
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _outputs(base: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    validation_commands = [
        "python -m tools.operator.kt_detached_verifier_kit_superlane",
        "python -m pytest --no-cov -q KT_PROD_CLEANROOM/tests/operator/test_kt_detached_verifier_kit_superlane.py",
        "python -m tools.operator.trust_zone_validate",
        "git diff --check",
    ]
    detached_inputs = [
        "Truth Lock validation contract and receipt",
        "current truth head and artifact authority classification",
        "public verifier manifest where present",
        "detached verifier receipt where present",
        "external audit packet manifest where present",
    ]
    return {
        "constitution": _artifact(
            base,
            schema_id="kt.detached_verifier.kit.constitution.v1",
            artifact_id="KT_DETACHED_VERIFIER_KIT_CONSTITUTION_V1",
            purpose="Define the detached verifier kit lane after canonical Truth Lock validation.",
            scope=[
                "package verifier inputs for clean-room replay",
                "define deterministic replay protocol",
                "define audit-safe proof contract",
                "bind claim limiter and negative tests",
            ],
            forbidden=[
                "commercial activation claims",
                "external audit completion claims",
                "7B amplification proof claims",
                "truth/trust law mutation",
                "Highway or FP0 authority promotion",
            ],
        ),
        "manifest": _artifact(
            base,
            schema_id="kt.detached_verifier.kit.manifest.v1",
            artifact_id="KT_DETACHED_VERIFIER_KIT_MANIFEST_V1",
            kit_components=[
                OUTPUTS["constitution"],
                OUTPUTS["evidence_bundle"],
                OUTPUTS["replay_protocol"],
                OUTPUTS["audit_safe_proof_contract"],
                OUTPUTS["claim_limiter"],
                OUTPUTS["negative_test_matrix"],
                OUTPUTS["ci_matrix"],
            ],
            detached_inputs=detached_inputs,
            launch_chain_status="TRUTH_LOCK_VALIDATED__DETACHED_VERIFIER_KIT_AUTHORED",
        ),
        "evidence_bundle": _artifact(
            base,
            schema_id="kt.detached_verifier.evidence_bundle.v1",
            artifact_id="KT_DETACHED_VERIFIER_EVIDENCE_BUNDLE_V1",
            evidence_classes=[
                "canonical truth bindings",
                "claim boundary bindings",
                "public verifier package inputs",
                "detached replay inputs",
                "trust-zone validation receipt",
                "negative test matrix",
                "CI matrix",
            ],
            clean_room_replay_required=True,
            clean_room_replay_completed=False,
        ),
        "replay_protocol": _artifact(
            base,
            schema_id="kt.detached_verifier.replay_protocol.v1",
            artifact_id="KT_DETACHED_VERIFIER_REPLAY_PROTOCOL_V1",
            replay_steps=[
                "checkout verifier kit bundle without relying on local repo state",
                "load canonical JSON receipts as source of truth",
                "verify all bound hashes before execution",
                "run detached verifier in clean environment",
                "compare detached conclusions to canonical claim ceiling",
                "emit detached verifier evidence review packet",
            ],
            deterministic_replay_required=True,
            network_required=False,
        ),
        "audit_safe_proof_contract": _artifact(
            base,
            schema_id="kt.detached_verifier.audit_safe_proof_contract.v1",
            artifact_id="KT_DETACHED_VERIFIER_AUDIT_SAFE_PROOF_CONTRACT_V1",
            audit_posture="READY_FOR_DETACHED_VERIFIER_AUTHORING_ONLY",
            external_audit_claim="External audit is not complete.",
            verifier_claim="Detached Verifier Kit is authored, not yet validated or externally replayed.",
            required_future_gates=[
                "VALIDATE_KT_DETACHED_VERIFIER_KIT_SUPERLANE_V1",
                "RUN_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY",
                "AUTHOR_KT_DETACHED_VERIFIER_EVIDENCE_REVIEW_PACKET",
                "VALIDATE_KT_DETACHED_VERIFIER_EVIDENCE_REVIEW_PACKET",
            ],
        ),
        "claim_limiter": _artifact(
            base,
            schema_id="kt.detached_verifier.claim_limiter.v1",
            artifact_id="KT_DETACHED_VERIFIER_CLAIM_LIMITER_V1",
            allowed_claims=[
                "Truth Lock is validated.",
                "The next lawful trunk is Detached Verifier Kit validation.",
                "The Detached Verifier Kit has been authored as an internal proof packet.",
                "Highway shadow and FP0 overlay lanes are eligible only as non-claim-expansion companions.",
            ],
            forbidden_claims=[
                "Commercial activation claims are authorized.",
                "External audit is complete.",
                "7B amplification is proven.",
                "Detached verifier clean-room replay has run.",
                "Highway or FP0 has canonical authority.",
            ],
        ),
        "negative_test_matrix": _artifact(
            base,
            schema_id="kt.detached_verifier.negative_test_matrix.v1",
            artifact_id="KT_DETACHED_VERIFIER_NEGATIVE_TEST_MATRIX_V1",
            required_negative_tests=[
                "predecessor outcome drift fails closed",
                "predecessor next lawful move drift fails closed",
                "predecessor source hash drift fails closed",
                "commercial activation overclaim fails closed",
                "external audit completion overclaim fails closed",
                "7B proof overclaim fails closed",
                "Highway/FP0 authority promotion drift fails closed",
            ],
        ),
        "ci_matrix": _artifact(
            base,
            schema_id="kt.detached_verifier.ci_matrix.v1",
            artifact_id="KT_DETACHED_VERIFIER_CI_MATRIX_V1",
            validation_commands=validation_commands,
            hidden_ruleset_contexts=[
                "p0-program-catalog",
                "ws0-delivery-parity",
                "ws1-mai-conformance",
                "ws2-replay-bindingloop",
                "ws3-constitution",
            ],
        ),
        "parallel_lane_eligibility": _artifact(
            base,
            schema_id="kt.detached_verifier.parallel_lane_eligibility_receipt.v1",
            artifact_id="KT_DETACHED_VERIFIER_PARALLEL_LANE_ELIGIBILITY_RECEIPT",
            highway_shadow_promotion_status="ELIGIBLE_NON_CLAIM_EXPANSION_ONLY",
            fp0_overlay_promotion_status="ELIGIBLE_NON_CLAIM_EXPANSION_ONLY",
            commercial_claim_expansion_allowed=False,
            canonical_authority_promotion_allowed=False,
        ),
        "next_lawful_move": _artifact(
            base,
            schema_id="kt.detached_verifier.next_lawful_move_receipt.v1",
            artifact_id="KT_DETACHED_VERIFIER_NEXT_LAWFUL_MOVE_RECEIPT",
            receipt_type="NEXT_LAWFUL_MOVE",
        ),
        "receipt": _artifact(
            base,
            schema_id="kt.detached_verifier.kit.superlane_receipt.v1",
            artifact_id="KT_DETACHED_VERIFIER_KIT_SUPERLANE_RECEIPT",
            verdict="DETACHED_VERIFIER_KIT_AUTHORED_VALIDATION_NEXT",
            outputs=list(OUTPUTS.values()),
        ),
    }


def _report_text(receipt: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# KT Detached Verifier Kit Superlane V1",
            "",
            f"Outcome: {receipt['selected_outcome']}",
            f"Next lawful move: {receipt['next_lawful_move']}",
            "",
            "Truth Lock is validated and the Detached Verifier Kit is authored for validation.",
            "This lane does not run clean-room replay and does not complete external audit.",
            "Commercial activation claims remain unauthorized. 7B amplification remains unproven.",
            "Highway shadow and FP0 overlay lanes are eligible only as non-claim-expansion companions.",
            "Truth-engine and trust-zone law remain unchanged.",
            "",
        ]
    )


def run(*, output_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    output_root = output_root or root
    if output_root.resolve() != root.resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical repository root only")
    branch = _ensure_branch_context(root)
    _ensure_workspace_scope(root)
    payloads = _load_inputs(root)
    _ensure_predecessor(payloads)
    _ensure_claim_boundary(payloads)
    _ensure_validation_bindings_recompute(root, payloads)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_DETACHED_VERIFIER_TRUST_ZONE_FAILED", "trust-zone validation failed")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    base = _base(
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        generated_utc=utc_now_iso_z(),
        input_bindings=_binding_rows(root),
        trust_zone_validation=trust_zone_validation,
    )
    outputs = _outputs(base)
    for role, raw in OUTPUTS.items():
        path = output_root / raw
        if role == "report":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_report_text(outputs["receipt"]), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, outputs[role])
    return outputs["receipt"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=AUTHORITATIVE_LANE)
    parser.add_argument("--output-root", default=".")
    args = parser.parse_args(argv)
    result = run(output_root=(repo_root() / args.output_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
