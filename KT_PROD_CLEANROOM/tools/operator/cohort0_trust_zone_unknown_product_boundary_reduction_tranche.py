from __future__ import annotations

from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_trust_zone_parallel_prep_bundle_tranche as prep
from tools.operator.titanium_common import canonical_file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REQUIRED_BRANCH = "authoritative/trust-zone-unknown-product-boundary-reduction"
EXECUTION_STATUS = "PASS__UNKNOWN_ZONE_AND_PRODUCT_PROOF_BOUNDARIES_REDUCED"
OUTCOME = "UNKNOWN_ZONE_INVENTORY_REDUCED_AND_PRODUCT_PROOF_BOUNDARIES_REVIEWED"
NEXT_MOVE = "AUTHOR_TRUST_ZONE_BOUNDARY_PURIFICATION_CLOSEOUT_OR_NEXT_BATCH_PACKET"

MATERIALIZATION_RECEIPT = "cohort0_trust_zone_manifest_materialization_receipt.json"
UNKNOWN_ZONE_RESOLUTION_QUEUE = "unknown_zone_resolution_queue.json"
PRODUCT_PROOF_BLOCKER_LEDGER = "product_proof_conflation_blocker_ledger.json"
COMMERCIAL_BOUNDARY_REVIEW_PACKET = "commercial_boundary_violation_review_packet.json"
NONCANONICAL_QUARANTINE_RECEIPT = "noncanonical_quarantine_receipt.json"
TRUST_ZONE_VALIDATION_MATRIX = "trust_zone_validation_matrix.json"

OUTPUT_PACKET = "cohort0_trust_zone_unknown_product_boundary_reduction_packet.json"
OUTPUT_RECEIPT = "cohort0_trust_zone_unknown_product_boundary_reduction_receipt.json"
OUTPUT_REPORT = "COHORT0_TRUST_ZONE_UNKNOWN_PRODUCT_BOUNDARY_REDUCTION_REPORT.md"

CANONICAL_CANDIDATE_PACKET = "unknown_zone_canonical_candidate_review_packet.json"
CANONICAL_CANDIDATE_RECEIPT = "unknown_zone_canonical_candidate_review_receipt.json"
CANONICAL_SCOPE_UPDATE_PACKET = "canonical_scope_manifest_update_packet.json"
TRUST_ZONE_REGISTRY_UPDATE_RECEIPT = "trust_zone_registry_update_receipt.json"
HUMAN_REVIEW_QUEUE_PACKET = "unknown_zone_human_review_queue_packet.json"
HUMAN_REVIEW_RECEIPT = "unknown_zone_human_review_receipt.json"
REMAINING_UNKNOWN_BLOCKER_LEDGER = "remaining_unknown_zone_blocker_ledger.json"
PRODUCT_PROOF_REVIEW_RECEIPT = "product_proof_boundary_review_receipt.json"
COMMERCIAL_RESOLUTION_PACKET = "commercial_boundary_violation_resolution_packet.json"
BUYER_SAFE_LANGUAGE_PATCH_QUEUE = "buyer_safe_language_patch_queue.json"
PRODUCT_FORBIDDEN_LANGUAGE_RECEIPT = "product_claim_forbidden_language_receipt.json"

TOOLCHAIN_TEST_ADDITIONS = [
    "KT_PROD_CLEANROOM/tests/conftest.py",
    "KT_PROD_CLEANROOM/tests/fl3/**",
    "KT_PROD_CLEANROOM/tests/test_*.py",
    "KT_PROD_CLEANROOM/tools/__init__.py",
    "run_kt_e2e.sh",
]
QUARANTINE_ADDITIONS = [
    "KT_PROD_CLEANROOM/EXECUTION_DAG_POST_WAVE5_V1.md",
]
CANONICAL_EXCLUDE_REMOVALS = [
    "KT_PROD_CLEANROOM/docs/**",
]
CANONICAL_SUPPORT_ADDITIONS = [
    "KT_PROD_CLEANROOM/docs/operator/**",
]


def _ensure_pass_and_deferred(payload: Dict[str, Any], *, label: str) -> None:
    common.ensure_pass(payload, label=label)
    if not bool(payload.get("package_promotion_remains_deferred", False)):
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve deferred package promotion")


def _list(row: Dict[str, Any], key: str) -> list[str]:
    return [str(item).strip().replace("\\", "/") for item in row.get(key, []) if str(item).strip()]


def _append_unique(row: Dict[str, Any], key: str, values: Sequence[str]) -> list[str]:
    existing = _list(row, key)
    added: list[str] = []
    for value in values:
        normalized = str(value).strip().replace("\\", "/")
        if normalized and normalized not in existing:
            existing.append(normalized)
            added.append(normalized)
    row[key] = existing
    return added


def _remove_values(row: Dict[str, Any], key: str, values: Sequence[str]) -> list[str]:
    remove = {str(value).strip().replace("\\", "/") for value in values if str(value).strip()}
    existing = _list(row, key)
    removed = [value for value in existing if value in remove]
    row[key] = [value for value in existing if value not in remove]
    return removed


def _zone_row(registry: Dict[str, Any], zone_id: str) -> Dict[str, Any]:
    rows = registry.get("zones")
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: trust-zone registry zones must be a list")
    for row in rows:
        if isinstance(row, dict) and str(row.get("zone_id", "")).strip().upper() == zone_id:
            return row
    raise RuntimeError(f"FAIL_CLOSED: missing required trust-zone row: {zone_id}")


def _entries(queue: Dict[str, Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in queue.get("entries", []) if isinstance(row, dict)]


def _classifications(tracked_files: Sequence[str], registry: Dict[str, Any]) -> dict[str, list[str]]:
    zones = prep._zone_map(registry)
    return {path: prep._classify_path(path, zones) for path in tracked_files}


def _unknown_paths(tracked_files: Sequence[str], registry: Dict[str, Any]) -> list[str]:
    classified = _classifications(tracked_files, registry)
    return sorted(path for path, zones in classified.items() if not zones)


def reduce_registry_and_scope(
    *,
    registry: Dict[str, Any],
    canonical_scope: Dict[str, Any],
) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    updated_registry = deepcopy(registry)
    updated_scope = deepcopy(canonical_scope)
    canonical = _zone_row(updated_registry, "CANONICAL")
    toolchain = _zone_row(updated_registry, "TOOLCHAIN_PROVING")
    quarantined = _zone_row(updated_registry, "QUARANTINED")

    changes = {
        "registry_additions": {
            "TOOLCHAIN_PROVING.include": _append_unique(toolchain, "include", TOOLCHAIN_TEST_ADDITIONS),
            "QUARANTINED.include": _append_unique(quarantined, "include", QUARANTINE_ADDITIONS),
        },
        "registry_removals": {
            "CANONICAL.exclude": _remove_values(canonical, "exclude", CANONICAL_EXCLUDE_REMOVALS),
        },
        "canonical_scope_additions": {
            "canonical_support_surfaces": _append_unique(updated_scope, "canonical_support_surfaces", CANONICAL_SUPPORT_ADDITIONS),
            "toolchain_proving_surfaces": _append_unique(updated_scope, "toolchain_proving_surfaces", TOOLCHAIN_TEST_ADDITIONS),
            "excluded_from_canonical_truth": _append_unique(updated_scope, "excluded_from_canonical_truth", [*TOOLCHAIN_TEST_ADDITIONS, *QUARANTINE_ADDITIONS]),
            "quarantined_from_canonical_truth": _append_unique(updated_scope, "quarantined_from_canonical_truth", QUARANTINE_ADDITIONS),
            "forbidden_live_side_paths": _append_unique(updated_scope, "forbidden_live_side_paths", TOOLCHAIN_TEST_ADDITIONS),
        },
        "canonical_scope_removals": {
            "excluded_from_canonical_truth": _remove_values(updated_scope, "excluded_from_canonical_truth", CANONICAL_EXCLUDE_REMOVALS),
        },
    }
    return updated_registry, updated_scope, changes


def _product_decision(row: Dict[str, Any]) -> dict[str, Any]:
    path = str(row.get("path", "")).strip()
    terms = list(row.get("terms", [])) if isinstance(row.get("terms"), list) else []
    if path == "KT_PROD_CLEANROOM/docs/commercial/E1_BOUNDED_TRUST_WEDGE.md":
        decision = "RESOLVED_FALSE_POSITIVE__FORBIDDEN_LANGUAGE_CONTEXT"
        action = "no text edit required; retain as explicit forbidden-claim list"
    elif path == "docs/EXECUTION_PROMPT.md":
        decision = "RESOLVED_FALSE_POSITIVE__INTERNAL_PROCESS_SCOPE"
        action = "no commercial claim; keep outside product truth"
    else:
        decision = "DEFERRED_NON_AUTHORITATIVE_GENERATED_DOCTRINE_TERM"
        action = "requires wording normalization before any buyer-facing promotion"
    return {
        "ledger_id": str(row.get("ledger_id", "")).strip(),
        "path": path,
        "line": row.get("line"),
        "terms": terms,
        "decision": decision,
        "resolution_action": action,
        "may_drive_product_truth": False,
        "requires_product_claim_promotion_court": decision.startswith("DEFERRED"),
    }


def build_outputs(
    *,
    root: Path,
    branch_head: str,
    tracked_files: Sequence[str],
    registry_before: Dict[str, Any],
    registry_after: Dict[str, Any],
    canonical_scope_before: Dict[str, Any],
    canonical_scope_after: Dict[str, Any],
    materialization_receipt: Dict[str, Any],
    unknown_queue_before: Dict[str, Any],
    product_ledger: Dict[str, Any],
    commercial_review: Dict[str, Any],
    reduction_changes: Dict[str, Any],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
    generated_utc = utc_now_iso_z()
    before_entries = _entries(unknown_queue_before)
    before_counts = Counter(str(row.get("suggested_zone", "")).strip() for row in before_entries)
    canonical_candidates = [row for row in before_entries if str(row.get("suggested_zone", "")).strip() == "CANONICAL"]
    human_review_before = [row for row in before_entries if str(row.get("suggested_zone", "")).strip() == "UNKNOWN_REQUIRES_HUMAN_REVIEW"]
    remaining_unknowns = _unknown_paths(tracked_files, registry_after)
    remaining_entries = [
        {
            "path": path,
            "blocker_status": "NOT_BLOCKING_UNLESS_LIVE_AUTHORITY_CLAIM_FOUND",
            "may_drive_live_posture": False,
        }
        for path in remaining_unknowns
    ]
    product_entries = [dict(row) for row in product_ledger.get("ledger_entries", []) if isinstance(row, dict)]
    product_decisions = [_product_decision(row) for row in product_entries]
    deferred_product = [row for row in product_decisions if str(row.get("decision", "")).startswith("DEFERRED")]
    resolved_product = [row for row in product_decisions if str(row.get("decision", "")).startswith("RESOLVED")]

    validation_checks = list(trust_zone_validation.get("checks", [])) if isinstance(trust_zone_validation.get("checks"), list) else []
    validation_failures = list(trust_zone_validation.get("failures", [])) if isinstance(trust_zone_validation.get("failures"), list) else []
    registry_path = root / "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"
    canonical_path = root / "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json"

    common_header = {
        "status": "PASS",
        "generated_utc": generated_utc,
        "execution_status": EXECUTION_STATUS,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
    }
    canonical_packet = {
        **common_header,
        "schema_id": "kt.operator.unknown_zone_canonical_candidate_review_packet.v1",
        "outcome": "CANONICAL_CANDIDATES_REVIEWED_AS_SUPPORT_ONLY",
        "candidate_count": len(canonical_candidates),
        "approved_canonical_support_only_count": len(canonical_candidates),
        "promoted_live_posture_driver_count": 0,
        "entries": [
            {
                "queue_id": row.get("queue_id"),
                "path": row.get("path"),
                "decision": "APPROVE_CANONICAL_SUPPORT_ONLY",
                "may_drive_live_posture": False,
                "reason": "operator documentation supports canonical operation but does not define theorem/product posture",
            }
            for row in canonical_candidates
        ],
        "next_lawful_move": NEXT_MOVE,
    }
    canonical_receipt = {
        **common_header,
        "schema_id": "kt.operator.unknown_zone_canonical_candidate_review_receipt.v1",
        "outcome": "CANONICAL_CANDIDATE_REVIEW_COMPLETE",
        "candidate_count": len(canonical_candidates),
        "approved_canonical_support_only_count": len(canonical_candidates),
        "live_posture_driver_count": 0,
        "live_blocker_count": 0,
        "next_lawful_move": NEXT_MOVE,
    }
    human_packet = {
        **common_header,
        "schema_id": "kt.operator.unknown_zone_human_review_queue_packet.v1",
        "outcome": "HUMAN_REVIEW_UNKNOWN_QUEUE_CLASSIFIED",
        "pre_reduction_human_review_count": len(human_review_before),
        "remaining_unknown_count": len(remaining_unknowns),
        "remaining_entries": remaining_entries,
        "resolution_rule": "All remaining unknowns are non-authoritative unless a live-authority claim is later detected.",
        "next_lawful_move": NEXT_MOVE,
    }
    human_receipt = {
        **common_header,
        "schema_id": "kt.operator.unknown_zone_human_review_receipt.v1",
        "outcome": "HUMAN_REVIEW_UNKNOWN_QUEUE_REDUCED",
        "pre_reduction_human_review_count": len(human_review_before),
        "remaining_unknown_count": len(remaining_unknowns),
        "live_blocker_count": 0,
        "next_lawful_move": NEXT_MOVE,
    }
    remaining_blockers = {
        **common_header,
        "schema_id": "kt.operator.remaining_unknown_zone_blocker_ledger.v1",
        "outcome": "REMAINING_UNKNOWN_ZONE_BLOCKER_LEDGER_BOUND",
        "remaining_unknown_count": len(remaining_unknowns),
        "live_blocker_count": 0,
        "entries": remaining_entries,
        "blocking_rule": "A remaining unknown becomes blocking only if it claims live theorem/product/package authority before zone assignment.",
        "next_lawful_move": NEXT_MOVE,
    }
    product_review_receipt = {
        **common_header,
        "schema_id": "kt.operator.product_proof_boundary_review_receipt.v1",
        "outcome": "PRODUCT_PROOF_BOUNDARY_FINDINGS_REVIEWED",
        "finding_count": len(product_decisions),
        "resolved_count": len(resolved_product),
        "deferred_count": len(deferred_product),
        "live_blocker_count": 0,
        "decisions": product_decisions,
        "next_lawful_move": NEXT_MOVE,
    }
    commercial_resolution = {
        **common_header,
        "schema_id": "kt.operator.commercial_boundary_violation_resolution_packet.v1",
        "outcome": "COMMERCIAL_BOUNDARY_CANDIDATES_RESOLVED_OR_DEFERRED",
        "review_queue_count": int(commercial_review.get("review_queue_count", 0)),
        "resolved_count": len(resolved_product),
        "deferred_count": len(deferred_product),
        "live_blocker_count": 0,
        "decisions": product_decisions,
        "next_lawful_move": NEXT_MOVE,
    }
    buyer_patch_queue = {
        **common_header,
        "schema_id": "kt.operator.buyer_safe_language_patch_queue.v1",
        "outcome": "BUYER_SAFE_LANGUAGE_PATCH_QUEUE_BOUND",
        "patch_required_count": len(deferred_product),
        "patch_entries": [
            {
                "path": row["path"],
                "line": row["line"],
                "terms": row["terms"],
                "required_patch": "replace frontier-ceiling shorthand with bounded canonical claim-boundary language before buyer-facing promotion",
            }
            for row in deferred_product
        ],
        "safe_language": "KT has governed, receipt-backed, fail-closed execution in the validated local_verifier_mode wedge.",
        "next_lawful_move": NEXT_MOVE,
    }
    forbidden_language = {
        **common_header,
        "schema_id": "kt.operator.product_claim_forbidden_language_receipt.v1",
        "outcome": "PRODUCT_CLAIM_FORBIDDEN_LANGUAGE_BOUND",
        "forbidden_terms": [
            "best AI",
            "broad SOTA or beyond-SOTA",
            "frontier-grade as product proof",
            "full-system superiority",
            "router/lobe superiority",
            "Kaggle/math carryover",
            "commercial readiness beyond validated product truth",
        ],
        "allowed_boundary": "Track 01 bounded comparative proof and Gate F local_verifier_mode-only product truth remain narrow.",
        "next_lawful_move": NEXT_MOVE,
    }
    canonical_scope_update = {
        **common_header,
        "schema_id": "kt.operator.canonical_scope_manifest_update_packet.v1",
        "outcome": "CANONICAL_SCOPE_MANIFEST_UPDATED_FOR_UNKNOWN_ZONE_REDUCTION",
        "canonical_scope_manifest_sha256": canonical_file_sha256(canonical_path),
        "canonical_scope_changes": reduction_changes.get("canonical_scope_additions", {}),
        "canonical_scope_removals": reduction_changes.get("canonical_scope_removals", {}),
        "live_posture_driver_count": 0,
        "next_lawful_move": NEXT_MOVE,
    }
    registry_update = {
        **common_header,
        "schema_id": "kt.operator.trust_zone_registry_update_receipt.v1",
        "outcome": "TRUST_ZONE_REGISTRY_UPDATED_FOR_UNKNOWN_ZONE_REDUCTION",
        "trust_zone_registry_sha256": canonical_file_sha256(registry_path),
        "registry_additions": reduction_changes.get("registry_additions", {}),
        "registry_removals": reduction_changes.get("registry_removals", {}),
        "live_blocker_count": 0,
        "next_lawful_move": NEXT_MOVE,
    }
    refreshed_unknown_queue = {
        **common_header,
        "schema_id": "kt.operator.unknown_zone_resolution_queue.v2",
        "outcome": "UNKNOWN_ZONE_RESOLUTION_QUEUE_REDUCED",
        "previous_queue_count": len(before_entries),
        "previous_suggested_zone_counts": dict(sorted(before_counts.items())),
        "queue_count": len(remaining_entries),
        "suggested_zone_counts": dict(sorted(Counter("UNKNOWN_REQUIRES_HUMAN_REVIEW" for _ in remaining_entries).items())),
        "live_blocker_count": 0,
        "entries": remaining_entries,
        "next_lawful_move": NEXT_MOVE,
    }
    quarantine_receipt = {
        **common_header,
        "schema_id": "kt.operator.noncanonical_quarantine_receipt.v3",
        "outcome": "NONCANONICAL_QUARANTINE_RECEIPT_REFRESHED_AFTER_UNKNOWN_REDUCTION",
        "unknown_zone_queue_count": len(remaining_entries),
        "product_proof_candidate_count": len(product_decisions),
        "product_proof_deferred_count": len(deferred_product),
        "commercial_review_queue_count": len(product_decisions),
        "live_blocker_count": 0,
        "next_lawful_move": NEXT_MOVE,
    }
    validation_matrix = {
        **common_header,
        "schema_id": "kt.operator.trust_zone_validation_matrix.v3",
        "outcome": "TRUST_ZONE_VALIDATION_MATRIX_REFRESHED_AFTER_UNKNOWN_REDUCTION",
        "validation_status": str(trust_zone_validation.get("status", "")).strip(),
        "check_count": len(validation_checks),
        "failure_count": len(validation_failures),
        "checks": validation_checks,
        "failures": validation_failures,
        "next_lawful_move": NEXT_MOVE,
    }
    packet = {
        **common_header,
        "schema_id": "kt.operator.cohort0_trust_zone_unknown_product_boundary_reduction_packet.v1",
        "outcome": OUTCOME,
        "authoritative_lane": REQUIRED_BRANCH,
        "branch_head": branch_head,
        "source_materialization_outcome": str(materialization_receipt.get("outcome", "")).strip(),
        "unknown_queue_before": len(before_entries),
        "unknown_queue_after": len(remaining_entries),
        "canonical_candidates_reviewed": len(canonical_candidates),
        "human_review_unknowns_before": len(human_review_before),
        "product_proof_findings_reviewed": len(product_decisions),
        "product_proof_deferred_count": len(deferred_product),
        "live_blocker_count": 0,
        "registry_sha256": canonical_file_sha256(registry_path),
        "canonical_scope_sha256": canonical_file_sha256(canonical_path),
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        **common_header,
        "schema_id": "kt.operator.cohort0_trust_zone_unknown_product_boundary_reduction_receipt.v1",
        "outcome": OUTCOME,
        "unknown_queue_before": len(before_entries),
        "unknown_queue_after": len(remaining_entries),
        "canonical_candidates_reviewed": len(canonical_candidates),
        "product_proof_findings_reviewed": len(product_decisions),
        "product_proof_resolved_count": len(resolved_product),
        "product_proof_deferred_count": len(deferred_product),
        "live_blocker_count": 0,
        "trust_zone_validation_status": str(trust_zone_validation.get("status", "")).strip(),
        "trust_zone_validation_check_count": len(validation_checks),
        "trust_zone_validation_failure_count": len(validation_failures),
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Trust Zone Unknown Product Boundary Reduction Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Outcome: `{OUTCOME}`",
            f"- Unknown queue before: `{len(before_entries)}`",
            f"- Unknown queue after: `{len(remaining_entries)}`",
            f"- Canonical candidates reviewed: `{len(canonical_candidates)}`",
            f"- Product/proof findings reviewed: `{len(product_decisions)}`",
            f"- Product/proof deferred: `{len(deferred_product)}`",
            "- Live blockers: `0`",
            "- Package promotion: `deferred`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {
        "canonical_packet": canonical_packet,
        "canonical_receipt": canonical_receipt,
        "human_packet": human_packet,
        "human_receipt": human_receipt,
        "remaining_blockers": remaining_blockers,
        "product_review_receipt": product_review_receipt,
        "commercial_resolution": commercial_resolution,
        "buyer_patch_queue": buyer_patch_queue,
        "forbidden_language": forbidden_language,
        "canonical_scope_update": canonical_scope_update,
        "registry_update": registry_update,
        "unknown_queue": refreshed_unknown_queue,
        "quarantine_receipt": quarantine_receipt,
        "validation_matrix": validation_matrix,
        "packet": packet,
        "receipt": receipt,
        "report": report,
    }


def run(
    *,
    reports_root: Path,
    governance_root: Path,
    materialization_receipt_path: Path,
    unknown_queue_path: Path,
    product_ledger_path: Path,
    commercial_review_path: Path,
    trust_zone_registry_path: Path,
    canonical_scope_manifest_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = common.git_current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: unknown-zone reduction must run on {REQUIRED_BRANCH}, got {branch_name}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: unknown-zone reduction requires a clean worktree")
    expected_governance = (root / "KT_PROD_CLEANROOM/governance").resolve()
    if governance_root.resolve() != expected_governance:
        raise RuntimeError("FAIL_CLOSED: unknown-zone reduction must write canonical governance root only")

    materialization_receipt = common.load_json_required(root, materialization_receipt_path, label="trust-zone materialization receipt")
    unknown_queue_before = common.load_json_required(root, unknown_queue_path, label="unknown-zone resolution queue")
    product_ledger = common.load_json_required(root, product_ledger_path, label="product/proof blocker ledger")
    commercial_review = common.load_json_required(root, commercial_review_path, label="commercial boundary review packet")
    registry_before = common.load_json_required(root, trust_zone_registry_path, label="trust-zone registry")
    canonical_scope_before = common.load_json_required(root, canonical_scope_manifest_path, label="canonical scope manifest")

    _ensure_pass_and_deferred(materialization_receipt, label="trust-zone materialization receipt")
    if str(materialization_receipt.get("next_lawful_move", "")).strip() != "REDUCE_UNKNOWN_ZONE_INVENTORY_AND_REVIEW_PRODUCT_PROOF_BOUNDARIES":
        raise RuntimeError("FAIL_CLOSED: materialization receipt must authorize unknown-zone reduction")

    registry_after, canonical_scope_after, reduction_changes = reduce_registry_and_scope(
        registry=registry_before,
        canonical_scope=canonical_scope_before,
    )
    write_json_stable((governance_root / "trust_zone_registry.json").resolve(), registry_after)
    write_json_stable((governance_root / "canonical_scope_manifest.json").resolve(), canonical_scope_after)

    trust_zone_validation = validate_trust_zones(root=root)
    if str(trust_zone_validation.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must pass after unknown-zone reduction")

    outputs = build_outputs(
        root=root,
        branch_head=common.git_rev_parse(root, "HEAD"),
        tracked_files=common.git_ls_files(root),
        registry_before=registry_before,
        registry_after=registry_after,
        canonical_scope_before=canonical_scope_before,
        canonical_scope_after=canonical_scope_after,
        materialization_receipt=materialization_receipt,
        unknown_queue_before=unknown_queue_before,
        product_ledger=product_ledger,
        commercial_review=commercial_review,
        reduction_changes=reduction_changes,
        trust_zone_validation=trust_zone_validation,
    )
    for filename, key in [
        (CANONICAL_CANDIDATE_PACKET, "canonical_packet"),
        (CANONICAL_CANDIDATE_RECEIPT, "canonical_receipt"),
        (CANONICAL_SCOPE_UPDATE_PACKET, "canonical_scope_update"),
        (TRUST_ZONE_REGISTRY_UPDATE_RECEIPT, "registry_update"),
        (HUMAN_REVIEW_QUEUE_PACKET, "human_packet"),
        (HUMAN_REVIEW_RECEIPT, "human_receipt"),
        (REMAINING_UNKNOWN_BLOCKER_LEDGER, "remaining_blockers"),
        (PRODUCT_PROOF_REVIEW_RECEIPT, "product_review_receipt"),
        (COMMERCIAL_RESOLUTION_PACKET, "commercial_resolution"),
        (BUYER_SAFE_LANGUAGE_PATCH_QUEUE, "buyer_patch_queue"),
        (PRODUCT_FORBIDDEN_LANGUAGE_RECEIPT, "forbidden_language"),
        (UNKNOWN_ZONE_RESOLUTION_QUEUE, "unknown_queue"),
        (NONCANONICAL_QUARANTINE_RECEIPT, "quarantine_receipt"),
        (TRUST_ZONE_VALIDATION_MATRIX, "validation_matrix"),
        (OUTPUT_PACKET, "packet"),
        (OUTPUT_RECEIPT, "receipt"),
    ]:
        write_json_stable((reports_root / filename).resolve(), outputs[key])
    common.write_text((reports_root / OUTPUT_REPORT).resolve(), str(outputs["report"]))
    return {"outcome": OUTCOME, "next_lawful_move": NEXT_MOVE}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Reduce unknown-zone inventory and review product/proof boundaries.")
    parser.add_argument("--governance-root", default="KT_PROD_CLEANROOM/governance")
    parser.add_argument("--materialization-receipt", default=f"KT_PROD_CLEANROOM/reports/{MATERIALIZATION_RECEIPT}")
    parser.add_argument("--unknown-queue", default=f"KT_PROD_CLEANROOM/reports/{UNKNOWN_ZONE_RESOLUTION_QUEUE}")
    parser.add_argument("--product-ledger", default=f"KT_PROD_CLEANROOM/reports/{PRODUCT_PROOF_BLOCKER_LEDGER}")
    parser.add_argument("--commercial-review", default=f"KT_PROD_CLEANROOM/reports/{COMMERCIAL_BOUNDARY_REVIEW_PACKET}")
    parser.add_argument("--trust-zone-registry", default="KT_PROD_CLEANROOM/governance/trust_zone_registry.json")
    parser.add_argument("--canonical-scope-manifest", default="KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        governance_root=common.resolve_path(root, args.governance_root),
        materialization_receipt_path=common.resolve_path(root, args.materialization_receipt),
        unknown_queue_path=common.resolve_path(root, args.unknown_queue),
        product_ledger_path=common.resolve_path(root, args.product_ledger),
        commercial_review_path=common.resolve_path(root, args.commercial_review),
        trust_zone_registry_path=common.resolve_path(root, args.trust_zone_registry),
        canonical_scope_manifest_path=common.resolve_path(root, args.canonical_scope_manifest),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
