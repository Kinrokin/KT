from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import canonical_file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REQUIRED_BRANCH = "authoritative/post-boundary-canonical-regrade-audit"
EXECUTION_STATUS = "PASS__POST_BOUNDARY_CANONICAL_REGRADE_AUDIT_BOUND"
OUTCOME = "POST_BOUNDARY_CANONICAL_REGRADE_AUDIT_COMPLETE"
NEXT_MOVE = "AUTHOR_UPPER_STACK_RATIFICATION_READINESS_AUTHORITY_PACKET"

POST_MERGE_CLOSEOUT = "post_merge_trust_zone_boundary_closeout_receipt.json"
TRUTH_ENGINE_HANDOFF = "cohort0_post_f_truth_engine_post_pr_canonical_handoff_receipt.json"
TRUTH_ENGINE_CONTRADICTION_LEDGER = "cohort0_post_f_truth_engine_contradiction_ledger.json"
TRACK_01_FINAL = "cohort0_post_f_track_01_final_summary_receipt.json"
TRACK_02_FINAL = "cohort0_post_f_track_02_final_summary_receipt.json"
TRACK_03_FINAL = "cohort0_post_f_track_03_final_summary_receipt.json"
TRACK_03_POST_MERGE = "cohort0_post_f_track_03_post_merge_closeout_receipt.json"
PR15_FL3_CLOSEOUT = "cohort0_post_f_pr15_fl3_full_red_to_green_receipt.json"
UNKNOWN_QUEUE = "unknown_zone_resolution_queue.json"
REMAINING_UNKNOWN_LEDGER = "remaining_unknown_zone_blocker_ledger.json"
PRODUCT_PROOF_REVIEW = "product_proof_boundary_review_receipt.json"
TRUST_ZONE_VALIDATION_MATRIX = "trust_zone_validation_matrix.json"

OUTPUT_PACKET = "post_boundary_canonical_regrade_audit_packet.json"
OUTPUT_RECEIPT = "post_boundary_canonical_regrade_audit_receipt.json"
WEAKNESS_LEDGER = "weakness_closure_delta_ledger.json"
A_PLUS_GAP_LEDGER = "remaining_a_plus_gap_ledger.json"
NEXT_LANE_RECOMMENDATION = "next_authoritative_lane_recommendation.json"
OUTPUT_REPORT = "POST_BOUNDARY_CANONICAL_REGRADE_AUDIT_REPORT.md"


def _ensure_pass(payload: Dict[str, Any], *, label: str) -> None:
    common.ensure_pass(payload, label=label)


def _ensure_true(payload: Dict[str, Any], key: str, *, label: str) -> None:
    if not bool(payload.get(key, False)):
        raise RuntimeError(f"FAIL_CLOSED: {label} must set {key}=true")


def _ensure_int(payload: Dict[str, Any], key: str, expected: int, *, label: str) -> None:
    try:
        value = int(payload[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"FAIL_CLOSED: {label} must declare integer {key}") from exc
    if value != expected:
        raise RuntimeError(f"FAIL_CLOSED: {label} expected {key}={expected}, got {value}")


def _load_receipt(root: Path, reports_root: Path, filename: str, *, label: str) -> Dict[str, Any]:
    return common.load_json_required(root, reports_root / filename, label=label)


def _hash_ref(path: Path) -> Dict[str, str]:
    return {"path": path.as_posix(), "sha256": canonical_file_sha256(path)}


def _evidence_refs(root: Path, reports_root: Path, governance_root: Path) -> Dict[str, Dict[str, str]]:
    refs = {
        "canonical_scope_manifest": governance_root / "canonical_scope_manifest.json",
        "trust_zone_registry": governance_root / "trust_zone_registry.json",
        "post_merge_closeout": reports_root / POST_MERGE_CLOSEOUT,
        "truth_engine_handoff": reports_root / TRUTH_ENGINE_HANDOFF,
        "truth_engine_contradiction_ledger": reports_root / TRUTH_ENGINE_CONTRADICTION_LEDGER,
        "track_01_final": reports_root / TRACK_01_FINAL,
        "track_02_final": reports_root / TRACK_02_FINAL,
        "track_03_final": reports_root / TRACK_03_FINAL,
        "track_03_post_merge": reports_root / TRACK_03_POST_MERGE,
        "pr15_fl3_closeout": reports_root / PR15_FL3_CLOSEOUT,
        "unknown_queue": reports_root / UNKNOWN_QUEUE,
        "remaining_unknown_ledger": reports_root / REMAINING_UNKNOWN_LEDGER,
        "product_proof_review": reports_root / PRODUCT_PROOF_REVIEW,
        "trust_zone_validation_matrix": reports_root / TRUST_ZONE_VALIDATION_MATRIX,
    }
    return {key: _hash_ref(path.resolve().relative_to(root)) for key, path in refs.items()}


def validate_inputs(*, payloads: Dict[str, Dict[str, Any]], live_validation: Dict[str, Any]) -> None:
    for key, payload in payloads.items():
        _ensure_pass(payload, label=key)

    closeout = payloads["post_merge_closeout"]
    if str(closeout.get("next_lawful_move", "")).strip() != "RUN_POST_BOUNDARY_CANONICAL_REGRADE_AUDIT":
        raise RuntimeError("FAIL_CLOSED: post-merge closeout must authorize post-boundary regrade audit")
    _ensure_int(closeout, "unknown_zone_queue_count", 0, label="post-merge closeout")
    _ensure_int(closeout, "live_blocker_count", 0, label="post-merge closeout")
    _ensure_true(closeout, "package_promotion_remains_deferred", label="post-merge closeout")
    _ensure_true(closeout, "truth_engine_derivation_law_unchanged", label="post-merge closeout")

    _ensure_int(payloads["truth_engine_contradiction_ledger"], "blocking_contradiction_count", 0, label="truth-engine contradiction ledger")
    _ensure_int(payloads["truth_engine_contradiction_ledger"], "advisory_contradiction_count", 0, label="truth-engine contradiction ledger")
    _ensure_int(payloads["truth_engine_handoff"], "blocking_contradiction_count", 0, label="truth-engine canonical handoff")

    _ensure_int(payloads["unknown_queue"], "queue_count", 0, label="unknown-zone queue")
    _ensure_int(payloads["unknown_queue"], "live_blocker_count", 0, label="unknown-zone queue")
    _ensure_int(payloads["remaining_unknown_ledger"], "remaining_unknown_count", 0, label="remaining unknown-zone blocker ledger")
    _ensure_int(payloads["remaining_unknown_ledger"], "live_blocker_count", 0, label="remaining unknown-zone blocker ledger")

    product = payloads["product_proof_review"]
    _ensure_int(product, "finding_count", 6, label="product/proof boundary review")
    _ensure_int(product, "resolved_count", 2, label="product/proof boundary review")
    _ensure_int(product, "deferred_count", 4, label="product/proof boundary review")
    _ensure_int(product, "live_blocker_count", 0, label="product/proof boundary review")
    for row in product.get("decisions", []):
        if isinstance(row, dict) and bool(row.get("may_drive_product_truth", True)):
            raise RuntimeError("FAIL_CLOSED: product/proof review decision may not drive product truth")

    matrix = payloads["trust_zone_validation_matrix"]
    if str(matrix.get("validation_status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: trust-zone validation matrix must be PASS")
    _ensure_int(matrix, "check_count", 24, label="trust-zone validation matrix")
    _ensure_int(matrix, "failure_count", 0, label="trust-zone validation matrix")

    if str(live_validation.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: live trust-zone validation must pass")
    if len(live_validation.get("checks", [])) != 24:
        raise RuntimeError("FAIL_CLOSED: live trust-zone validation must report 24 checks")
    if len(live_validation.get("failures", [])) != 0:
        raise RuntimeError("FAIL_CLOSED: live trust-zone validation must report 0 failures")

    for key in [
        "post_merge_closeout",
        "unknown_queue",
        "remaining_unknown_ledger",
        "product_proof_review",
        "trust_zone_validation_matrix",
    ]:
        _ensure_true(payloads[key], "package_promotion_remains_deferred", label=key)
        _ensure_true(payloads[key], "truth_engine_derivation_law_unchanged", label=key)


def build_outputs(
    *,
    root: Path,
    reports_root: Path,
    governance_root: Path,
    branch_head: str,
    payloads: Dict[str, Dict[str, Any]],
    live_validation: Dict[str, Any],
) -> Dict[str, Any]:
    generated_utc = utc_now_iso_z()
    common_header = {
        "status": "PASS",
        "generated_utc": generated_utc,
        "execution_status": EXECUTION_STATUS,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
    }
    evidence = _evidence_refs(root, reports_root, governance_root)

    audit_findings = [
        {
            "finding_id": "PBR-001",
            "question": "Did truth-engine plus trust-zone work fix stale/mixed-boundary weakness?",
            "verdict": "PASS__STRONGLY_CONTAINED",
            "evidence": ["truth_engine_contradiction_ledger", "post_merge_closeout", "trust_zone_validation_matrix"],
        },
        {
            "finding_id": "PBR-002",
            "question": "Are Track 01, Track 02, Track 03, PR remediation, truth-engine, and trust-zone surfaces aligned on main?",
            "verdict": "PASS__ALIGNED_ON_CANONICAL_MAIN",
            "evidence": ["track_01_final", "track_02_final", "track_03_post_merge", "pr15_fl3_closeout", "truth_engine_handoff", "post_merge_closeout"],
        },
        {
            "finding_id": "PBR-003",
            "question": "Does canonical scope prevent archive/lab/commercial residue from driving live truth?",
            "verdict": "PASS__BOUNDARY_ENFORCED_WITH_ZERO_UNKNOWN_ZONE_QUEUE",
            "evidence": ["canonical_scope_manifest", "trust_zone_registry", "unknown_queue", "remaining_unknown_ledger"],
        },
        {
            "finding_id": "PBR-004",
            "question": "Are product/proof boundary findings closed or safely deferred?",
            "verdict": "PASS__TWO_RESOLVED_FOUR_NON_AUTHORITATIVE_DEFERRED",
            "evidence": ["product_proof_review"],
        },
        {
            "finding_id": "PBR-005",
            "question": "Does package promotion remain correctly deferred?",
            "verdict": "PASS__PACKAGE_PROMOTION_DEFERRED",
            "evidence": ["post_merge_closeout", "product_proof_review"],
        },
    ]

    weakness_entries = [
        {
            "weakness_id": "W-TRUTH-001",
            "weakness": "stale/live posture confusion",
            "pre_boundary_status": "MATERIAL_SYSTEM_RISK",
            "post_boundary_status": "CLOSED_FOR_CURRENT_CANONICAL_MAIN",
            "evidence": ["truth_engine_contradiction_ledger", "truth_engine_handoff"],
            "residual_risk": "recompute required after every future authority-changing event",
        },
        {
            "weakness_id": "W-BOUNDARY-001",
            "weakness": "canonical truth drowned by archive/lab/commercial residue",
            "pre_boundary_status": "MATERIAL_SYSTEM_RISK",
            "post_boundary_status": "STRONGLY_CONTAINED",
            "evidence": ["trust_zone_registry", "canonical_scope_manifest", "unknown_queue"],
            "residual_risk": "new files can reintroduce unknown zones unless validation remains required",
        },
        {
            "weakness_id": "W-PRODUCT-001",
            "weakness": "product/proof claim conflation",
            "pre_boundary_status": "ACTIVE_BOUNDARY_RISK",
            "post_boundary_status": "CONTAINED_WITH_DEFERRED_WORDING_CLEANUP",
            "evidence": ["product_proof_review"],
            "residual_risk": "four generated-doctrine frontier terms must not be buyer-facing before promotion court",
        },
        {
            "weakness_id": "W-PACKAGE-001",
            "weakness": "package-vs-repo authority confusion",
            "pre_boundary_status": "MATERIAL_GOVERNANCE_RISK",
            "post_boundary_status": "CLOSED_FOR_CURRENT_CAMPAIGN",
            "evidence": ["post_merge_closeout", "track_03_post_merge"],
            "residual_risk": "package promotion remains a separate future court",
        },
        {
            "weakness_id": "W-FL3-001",
            "weakness": "PR15 FL3 remediation instability",
            "pre_boundary_status": "MERGE_BLOCKING_SUBSTRATE_DEBT",
            "post_boundary_status": "CLOSED_GREEN",
            "evidence": ["pr15_fl3_closeout"],
            "residual_risk": "future FL3 law-bundle changes need same receipt discipline",
        },
    ]

    gap_entries = [
        {
            "gap_id": "A-GAP-001",
            "layer": "upper_stack_ratification",
            "current_grade": "B_MINUS_TO_B_RANGE",
            "target_grade": "A_PLUS",
            "status": "OPEN",
            "reason": "crucibles, Policy C, adapters, tournaments, router/lobes still need ordered ratification against the cleaned boundary universe",
            "recommended_lane": "upper_stack_ratification_readiness",
        },
        {
            "gap_id": "A-GAP-002",
            "layer": "external_verifiability",
            "current_grade": "B_RANGE",
            "target_grade": "A_PLUS",
            "status": "OPEN",
            "reason": "canonical self-verification is stronger, but broader third-party/public verification remains incomplete",
            "recommended_lane": "external_assurance_after_upper_stack_readiness",
        },
        {
            "gap_id": "A-GAP-003",
            "layer": "comparative_proof_breadth",
            "current_grade": "B_RANGE",
            "target_grade": "A_PLUS",
            "status": "OPEN",
            "reason": "Track 01 proves a bounded wedge, not broad comparative superiority",
            "recommended_lane": "broader_comparative_proof_after_ratification_readiness",
        },
        {
            "gap_id": "A-GAP-004",
            "layer": "commercial_product_maturity",
            "current_grade": "C_TO_B_MINUS_RANGE",
            "target_grade": "A_PLUS",
            "status": "OPEN",
            "reason": "buyer-safe language is bounded and package promotion is deferred; product maturity still trails governance maturity",
            "recommended_lane": "commercial_truth_plane_after_claim_boundary_cleanup",
        },
        {
            "gap_id": "A-GAP-005",
            "layer": "standards_alignment",
            "current_grade": "B_MINUS_RANGE",
            "target_grade": "A_PLUS",
            "status": "OPEN",
            "reason": "SLSA/in-toto/Sigstore/NIST mappings exist as direction, but formal compliance/admissibility remains a later standards court",
            "recommended_lane": "standards_alignment_after_external_assurance",
        },
    ]

    recommendation = {
        **common_header,
        "schema_id": "kt.operator.next_authoritative_lane_recommendation.v1",
        "outcome": "UPPER_STACK_RATIFICATION_READINESS_RECOMMENDED",
        "recommended_next_authoritative_lane": "upper_stack_ratification_readiness",
        "recommended_next_move": NEXT_MOVE,
        "why_now": [
            "truth-engine contradiction handling is canonical and clean",
            "trust-zone boundary inventory is reduced to zero unknowns",
            "product/proof boundary findings are resolved or non-authoritatively deferred",
            "the largest remaining A+ gap is upper-stack ratification, not more boundary cleanup",
        ],
        "initial_scope": [
            "crucible / Policy C registry and pressure taxonomy",
            "adapter lifecycle and promotion law",
            "tournament / promotion / merge law",
            "router / lobe ratification order",
        ],
        "forbidden_scope": [
            "package promotion",
            "broad model superiority claims",
            "commercial claim widening",
            "router/lobe superiority claims before ratification",
        ],
        "next_lawful_move": NEXT_MOVE,
    }

    packet = {
        **common_header,
        "schema_id": "kt.operator.post_boundary_canonical_regrade_audit_packet.v1",
        "outcome": OUTCOME,
        "authoritative_lane": REQUIRED_BRANCH,
        "branch_head": branch_head,
        "audit_scope": "focused post-boundary canonical regrade",
        "evidence_refs": evidence,
        "audit_questions": audit_findings,
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        **common_header,
        "schema_id": "kt.operator.post_boundary_canonical_regrade_audit_receipt.v1",
        "outcome": OUTCOME,
        "branch_head": branch_head,
        "truth_engine_blocking_contradictions": 0,
        "truth_engine_advisory_contradictions": 0,
        "unknown_zone_queue_count": 0,
        "live_blocker_count": 0,
        "trust_zone_validation_status": "PASS",
        "trust_zone_validation_check_count": 24,
        "trust_zone_validation_failure_count": 0,
        "product_proof_findings": 6,
        "product_proof_resolved": 2,
        "product_proof_deferred_non_authoritative": 4,
        "weakness_closure_count": len(weakness_entries),
        "remaining_a_plus_gap_count": len(gap_entries),
        "recommended_next_authoritative_lane": "upper_stack_ratification_readiness",
        "next_lawful_move": NEXT_MOVE,
    }
    weakness_ledger = {
        **common_header,
        "schema_id": "kt.operator.weakness_closure_delta_ledger.v1",
        "outcome": "POST_BOUNDARY_WEAKNESS_CLOSURE_DELTAS_BOUND",
        "closed_or_strongly_contained_count": len(weakness_entries),
        "entries": weakness_entries,
        "next_lawful_move": NEXT_MOVE,
    }
    gap_ledger = {
        **common_header,
        "schema_id": "kt.operator.remaining_a_plus_gap_ledger.v1",
        "outcome": "REMAINING_A_PLUS_GAPS_BOUND",
        "open_gap_count": len(gap_entries),
        "entries": gap_entries,
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Post-Boundary Canonical Regrade Audit Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            "- Truth-engine contradictions: `0 blocking`, `0 advisory`",
            "- Unknown-zone queue: `0`",
            "- Trust-zone validation: `PASS`, `24` checks, `0` failures",
            "- Product/proof findings: `6`; resolved `2`; deferred non-authoritative `4`",
            "- Package promotion: `deferred`",
            "- Truth-engine law: `unchanged`",
            "- Regrade verdict: truth/boundary/governance weakness class is strongly contained on canonical `main`",
            "- Remaining major A+ gap: upper-stack ratification readiness",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {
        "packet": packet,
        "receipt": receipt,
        "weakness_ledger": weakness_ledger,
        "gap_ledger": gap_ledger,
        "recommendation": recommendation,
        "report": report,
    }


def run(
    *,
    reports_root: Path,
    governance_root: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = common.git_current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: post-boundary regrade must run on {REQUIRED_BRANCH}, got {branch_name}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: post-boundary regrade requires a clean worktree")
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: post-boundary regrade must write canonical reports root only")
    if governance_root.resolve() != (root / "KT_PROD_CLEANROOM/governance").resolve():
        raise RuntimeError("FAIL_CLOSED: post-boundary regrade must read canonical governance root only")

    payloads = {
        "post_merge_closeout": _load_receipt(root, reports_root, POST_MERGE_CLOSEOUT, label="post-merge trust-zone closeout"),
        "truth_engine_handoff": _load_receipt(root, reports_root, TRUTH_ENGINE_HANDOFF, label="truth-engine canonical handoff"),
        "truth_engine_contradiction_ledger": _load_receipt(root, reports_root, TRUTH_ENGINE_CONTRADICTION_LEDGER, label="truth-engine contradiction ledger"),
        "track_01_final": _load_receipt(root, reports_root, TRACK_01_FINAL, label="Track 01 final summary"),
        "track_02_final": _load_receipt(root, reports_root, TRACK_02_FINAL, label="Track 02 final summary"),
        "track_03_final": _load_receipt(root, reports_root, TRACK_03_FINAL, label="Track 03 final summary"),
        "track_03_post_merge": _load_receipt(root, reports_root, TRACK_03_POST_MERGE, label="Track 03 post-merge closeout"),
        "pr15_fl3_closeout": _load_receipt(root, reports_root, PR15_FL3_CLOSEOUT, label="PR15 FL3 closeout"),
        "unknown_queue": _load_receipt(root, reports_root, UNKNOWN_QUEUE, label="unknown-zone queue"),
        "remaining_unknown_ledger": _load_receipt(root, reports_root, REMAINING_UNKNOWN_LEDGER, label="remaining unknown-zone blocker ledger"),
        "product_proof_review": _load_receipt(root, reports_root, PRODUCT_PROOF_REVIEW, label="product/proof review"),
        "trust_zone_validation_matrix": _load_receipt(root, reports_root, TRUST_ZONE_VALIDATION_MATRIX, label="trust-zone validation matrix"),
    }
    live_validation = validate_trust_zones(root=root)
    validate_inputs(payloads=payloads, live_validation=live_validation)

    outputs = build_outputs(
        root=root,
        reports_root=reports_root.resolve(),
        governance_root=governance_root.resolve(),
        branch_head=common.git_rev_parse(root, "HEAD"),
        payloads=payloads,
        live_validation=live_validation,
    )
    for filename, key in [
        (OUTPUT_PACKET, "packet"),
        (OUTPUT_RECEIPT, "receipt"),
        (WEAKNESS_LEDGER, "weakness_ledger"),
        (A_PLUS_GAP_LEDGER, "gap_ledger"),
        (NEXT_LANE_RECOMMENDATION, "recommendation"),
    ]:
        write_json_stable((reports_root / filename).resolve(), outputs[key])
    common.write_text((reports_root / OUTPUT_REPORT).resolve(), str(outputs["report"]))
    return {"outcome": OUTCOME, "next_lawful_move": NEXT_MOVE}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Run the focused post-boundary canonical regrade audit.")
    parser.add_argument("--governance-root", default="KT_PROD_CLEANROOM/governance")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        governance_root=common.resolve_path(root, args.governance_root),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
