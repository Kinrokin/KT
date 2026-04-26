from __future__ import annotations

from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_trust_zone_parallel_prep_bundle_tranche as prep
from tools.operator.titanium_common import canonical_file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REQUIRED_BRANCH = "authoritative/trust-zone-manifests-quarantine-materialization"
EXECUTION_STATUS = "PASS__TRUST_ZONE_MANIFESTS_AND_QUARANTINE_RECEIPT_MATERIALIZED"
OUTCOME = "TRUST_ZONE_REGISTRY_SCOPE_MANIFESTS_AND_QUARANTINE_RECEIPT_MATERIALIZED"
NEXT_MOVE = "REDUCE_UNKNOWN_ZONE_INVENTORY_AND_REVIEW_PRODUCT_PROOF_BOUNDARIES"

OUTPUT_PACKET = "cohort0_trust_zone_manifest_materialization_packet.json"
OUTPUT_RECEIPT = "cohort0_trust_zone_manifest_materialization_receipt.json"
OUTPUT_REPORT = "COHORT0_TRUST_ZONE_MANIFEST_MATERIALIZATION_REPORT.md"
UNKNOWN_ZONE_RESOLUTION_QUEUE = "unknown_zone_resolution_queue.json"
PRODUCT_PROOF_BLOCKER_LEDGER = "product_proof_conflation_blocker_ledger.json"
COMMERCIAL_BOUNDARY_REVIEW_PACKET = "commercial_boundary_violation_review_packet.json"
NONCANONICAL_QUARANTINE_RECEIPT = "noncanonical_quarantine_receipt.json"
TRUST_ZONE_VALIDATION_MATRIX = "trust_zone_validation_matrix.json"

PREP_RECEIPT = "cohort0_trust_zone_parallel_prep_bundle_receipt.json"
CONTRACT_RECEIPT = "cohort0_trust_zone_registry_scope_contract_receipt.json"

TOOLCHAIN_PROVING_ADDITIONS = [
    "KT_PROD_CLEANROOM/tests/operator/**",
    "KT_PROD_CLEANROOM/pyproject.toml",
    "KT_PROD_CLEANROOM/pytest.ini",
    "KT_PROD_CLEANROOM/requirements-*.in",
    "KT_PROD_CLEANROOM/requirements-*.lock.txt",
    "KT_PROD_CLEANROOM/sitecustomize.py",
    "KT_PROD_CLEANROOM/run_policy_c_smoke_train.py",
]
COMMERCIAL_INCLUDE_ADDITIONS = [
    "KT_PROD_CLEANROOM/product/**",
    "KT_PROD_CLEANROOM/docs/**",
]
COMMERCIAL_EXCLUDE_ADDITIONS = [
    "KT_PROD_CLEANROOM/docs/operator/**",
]
GENERATED_RUNTIME_TRUTH_ADDITIONS = [
    "KT_PROD_CLEANROOM/exports/law/**",
]
QUARANTINE_INCLUDE_ADDITIONS = [
    "KT_PROD_CLEANROOM/runs/**",
    "KT_PROD_CLEANROOM/*PROMPT*.md",
    "KT_PROD_CLEANROOM/*WORK_ORDER*.json",
    "KT_PROD_CLEANROOM/kt.*.json",
    "KT_PROD_CLEANROOM/W4_PHASE_GATES.md",
    "KT_PROD_CLEANROOM/decision_log.md",
]
CANONICAL_EXCLUDE_ADDITIONS = [
    *TOOLCHAIN_PROVING_ADDITIONS,
    *COMMERCIAL_INCLUDE_ADDITIONS,
    *GENERATED_RUNTIME_TRUTH_ADDITIONS,
    *QUARANTINE_INCLUDE_ADDITIONS,
]


def _ensure_pass_and_deferred(payload: Dict[str, Any], *, label: str) -> None:
    common.ensure_pass(payload, label=label)
    if not bool(payload.get("package_promotion_remains_deferred", False)):
        raise RuntimeError(f"FAIL_CLOSED: {label} must preserve deferred package promotion")


def _suggest_zone(path: str) -> tuple[str, str]:
    lowered = path.lower()
    if path.startswith("KT_PROD_CLEANROOM/product/") or path.startswith("KT_PROD_CLEANROOM/docs/commercial/"):
        return "COMMERCIAL", "product_or_buyer_surface"
    if path.startswith("KT_PROD_CLEANROOM/tests/operator/"):
        return "TOOLCHAIN_PROVING", "operator_test_proving_surface"
    if path.startswith("KT_PROD_CLEANROOM/runs/post_f_track_03/"):
        return "QUARANTINED", "deferred_track03_package_or_staging_surface"
    if path.startswith("KT_PROD_CLEANROOM/runs/"):
        return "QUARANTINED", "run_output_or_staging_surface"
    if path.startswith("KT_PROD_CLEANROOM/exports/"):
        return "GENERATED_RUNTIME_TRUTH", "generated_export_surface"
    if path.startswith("KT_PROD_CLEANROOM/docs/") or path.startswith("docs/"):
        return "COMMERCIAL", "documentary_surface"
    if lowered.endswith((".toml", ".ini", ".lock.txt", "requirements-wave0.in")):
        return "TOOLCHAIN_PROVING", "toolchain_configuration_surface"
    if path.startswith("KT_PROD_CLEANROOM/kt.") or path.startswith("KT_PROD_CLEANROOM/CODEX_") or path.startswith("KT_PROD_CLEANROOM/FINAL_"):
        return "QUARANTINED", "work_order_or_prompt_lineage_surface"
    return "UNKNOWN_REQUIRES_HUMAN_REVIEW", "no_safe_rule_yet"


def _append_unique(row: Dict[str, Any], key: str, values: Sequence[str]) -> list[str]:
    existing = [str(item).strip().replace("\\", "/") for item in row.get(key, []) if str(item).strip()]
    added: list[str] = []
    for value in values:
        normalized = str(value).strip().replace("\\", "/")
        if normalized and normalized not in existing:
            existing.append(normalized)
            added.append(normalized)
    row[key] = existing
    return added


def _zone_row(registry: Dict[str, Any], zone_id: str) -> Dict[str, Any]:
    rows = registry.get("zones")
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: trust-zone registry zones must be a list")
    for row in rows:
        if isinstance(row, dict) and str(row.get("zone_id", "")).strip().upper() == zone_id:
            return row
    raise RuntimeError(f"FAIL_CLOSED: missing required trust-zone row: {zone_id}")


def materialize_scope_manifests(
    *,
    registry: Dict[str, Any],
    canonical_scope: Dict[str, Any],
    readiness_scope: Dict[str, Any],
) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    updated_registry = deepcopy(registry)
    updated_canonical = deepcopy(canonical_scope)
    updated_readiness = deepcopy(readiness_scope)
    changes: dict[str, Any] = {
        "registry_additions": {},
        "canonical_scope_additions": {},
        "readiness_scope_changed": False,
    }

    canonical_row = _zone_row(updated_registry, "CANONICAL")
    toolchain_row = _zone_row(updated_registry, "TOOLCHAIN_PROVING")
    commercial_row = _zone_row(updated_registry, "COMMERCIAL")
    generated_row = _zone_row(updated_registry, "GENERATED_RUNTIME_TRUTH")
    quarantine_row = _zone_row(updated_registry, "QUARANTINED")

    changes["registry_additions"]["CANONICAL.exclude"] = _append_unique(canonical_row, "exclude", CANONICAL_EXCLUDE_ADDITIONS)
    changes["registry_additions"]["TOOLCHAIN_PROVING.include"] = _append_unique(toolchain_row, "include", TOOLCHAIN_PROVING_ADDITIONS)
    changes["registry_additions"]["COMMERCIAL.include"] = _append_unique(commercial_row, "include", COMMERCIAL_INCLUDE_ADDITIONS)
    changes["registry_additions"]["COMMERCIAL.exclude"] = _append_unique(commercial_row, "exclude", COMMERCIAL_EXCLUDE_ADDITIONS)
    changes["registry_additions"]["GENERATED_RUNTIME_TRUTH.include"] = _append_unique(generated_row, "include", GENERATED_RUNTIME_TRUTH_ADDITIONS)
    changes["registry_additions"]["QUARANTINED.include"] = _append_unique(quarantine_row, "include", QUARANTINE_INCLUDE_ADDITIONS)

    changes["canonical_scope_additions"]["toolchain_proving_surfaces"] = _append_unique(
        updated_canonical,
        "toolchain_proving_surfaces",
        TOOLCHAIN_PROVING_ADDITIONS,
    )
    changes["canonical_scope_additions"]["documentary_only_surfaces"] = _append_unique(
        updated_canonical,
        "documentary_only_surfaces",
        COMMERCIAL_INCLUDE_ADDITIONS,
    )
    changes["canonical_scope_additions"]["generated_truth_surfaces"] = _append_unique(
        updated_canonical,
        "generated_truth_surfaces",
        GENERATED_RUNTIME_TRUTH_ADDITIONS,
    )
    changes["canonical_scope_additions"]["excluded_from_canonical_truth"] = _append_unique(
        updated_canonical,
        "excluded_from_canonical_truth",
        CANONICAL_EXCLUDE_ADDITIONS,
    )
    changes["canonical_scope_additions"]["quarantined_from_canonical_truth"] = _append_unique(
        updated_canonical,
        "quarantined_from_canonical_truth",
        QUARANTINE_INCLUDE_ADDITIONS,
    )
    changes["canonical_scope_additions"]["forbidden_live_side_paths"] = _append_unique(
        updated_canonical,
        "forbidden_live_side_paths",
        TOOLCHAIN_PROVING_ADDITIONS,
    )
    return updated_registry, updated_canonical, updated_readiness, changes


def _build_unknown_queue(*, tracked_files: Sequence[str], registry: Dict[str, Any]) -> Dict[str, Any]:
    zones = prep._zone_map(registry)
    unknown_paths = sorted(path for path in tracked_files if not prep._classify_path(path, zones))
    entries: list[dict[str, Any]] = []
    for idx, path in enumerate(unknown_paths, start=1):
        suggested_zone, reason = _suggest_zone(path)
        entries.append(
            {
                "queue_id": f"UZQ-{idx:04d}",
                "path": path,
                "suggested_zone": suggested_zone,
                "suggestion_reason": reason,
                "initial_review_status": "QUEUED_NOT_BLOCKING",
                "may_drive_live_posture": False,
                "blocking_if": "path claims live theorem/product/package/promotion authority before zone assignment",
            }
        )
    counts = Counter(str(row["suggested_zone"]) for row in entries)
    return {
        "schema_id": "kt.operator.unknown_zone_resolution_queue.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": "UNKNOWN_ZONE_RESOLUTION_QUEUE_MATERIALIZED",
        "queue_count": len(entries),
        "suggested_zone_counts": dict(sorted(counts.items())),
        "live_blocker_count": 0,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "entries": entries,
        "next_lawful_move": NEXT_MOVE,
    }


def _build_product_blocker_ledger(product_scan: Dict[str, Any], commercial_violations: Dict[str, Any]) -> Dict[str, Any]:
    findings = [row for row in product_scan.get("findings", []) if isinstance(row, dict)]
    violations = [row for row in commercial_violations.get("candidate_violations", []) if isinstance(row, dict)]
    rows: list[dict[str, Any]] = []
    for idx, row in enumerate(violations, start=1):
        rows.append(
            {
                "ledger_id": f"PPB-{idx:03d}",
                "path": str(row.get("path", "")).strip(),
                "line": row.get("line"),
                "terms": list(row.get("terms", [])) if isinstance(row.get("terms"), list) else [],
                "candidate_violation_class": str(row.get("candidate_violation_class", "risky_claim_boundary_review")).strip(),
                "blocker_status": "NOT_BLOCKING_UNLESS_PROMOTED_AS_PRODUCT_TRUTH",
                "required_resolution": "review language against canonical product truth before any commercial promotion",
            }
        )
    return {
        "schema_id": "kt.operator.product_proof_conflation_blocker_ledger.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": "PRODUCT_PROOF_CONFLATION_BLOCKER_LEDGER_MATERIALIZED",
        "candidate_finding_count": len(findings),
        "candidate_violation_count": len(violations),
        "live_blocker_count": 0,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "rule": "Candidate findings remain review items unless promoted copy claims proof or product truth beyond canonical boundaries.",
        "ledger_entries": rows,
        "next_lawful_move": NEXT_MOVE,
    }


def _build_commercial_review_packet(product_ledger: Dict[str, Any]) -> Dict[str, Any]:
    entries = [row for row in product_ledger.get("ledger_entries", []) if isinstance(row, dict)]
    return {
        "schema_id": "kt.operator.commercial_boundary_violation_review_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": "COMMERCIAL_BOUNDARY_VIOLATION_REVIEW_PACKET_MATERIALIZED",
        "review_queue_count": len(entries),
        "live_blocker_count": 0,
        "package_promotion_remains_deferred": True,
        "allowed_language": [
            "governed, receipt-backed, fail-closed execution",
            "validated local_verifier_mode wedge",
            "bounded Track 01 comparative proof only",
        ],
        "forbidden_interpretations": [
            "best AI",
            "broad SOTA or beyond-SOTA claim",
            "full-system superiority",
            "router/lobe superiority",
            "Kaggle/math carryover",
            "commercial readiness beyond validated product truth",
        ],
        "review_entries": entries,
        "next_lawful_move": NEXT_MOVE,
    }


def build_outputs(
    *,
    root: Path,
    branch_name: str,
    branch_head: str,
    materialization_changes: Dict[str, Any],
    tracked_files: Sequence[str],
    registry: Dict[str, Any],
    canonical_scope: Dict[str, Any],
    readiness_scope: Dict[str, Any],
    contract_receipt: Dict[str, Any],
    prep_receipt: Dict[str, Any],
    product_scan: Dict[str, Any],
    commercial_violations: Dict[str, Any],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
    generated_utc = utc_now_iso_z()
    registry_path = root / "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"
    canonical_path = root / "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json"
    readiness_path = root / "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json"
    unknown_queue = _build_unknown_queue(tracked_files=tracked_files, registry=registry)
    product_ledger = _build_product_blocker_ledger(product_scan, commercial_violations)
    commercial_review = _build_commercial_review_packet(product_ledger)
    validation_checks = list(trust_zone_validation.get("checks", [])) if isinstance(trust_zone_validation.get("checks"), list) else []
    validation_failures = list(trust_zone_validation.get("failures", [])) if isinstance(trust_zone_validation.get("failures"), list) else []

    manifest_binding = {
        "trust_zone_registry": {
            "path": "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
            "schema_id": str(registry.get("schema_id", "")).strip(),
            "registry_id": str(registry.get("registry_id", "")).strip(),
            "zone_count": len(registry.get("zones", [])) if isinstance(registry.get("zones"), list) else 0,
            "canonical_json_sha256": canonical_file_sha256(registry_path),
        },
        "canonical_scope_manifest": {
            "path": "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
            "schema_id": str(canonical_scope.get("schema_id", "")).strip(),
            "manifest_id": str(canonical_scope.get("manifest_id", "")).strip(),
            "canonical_json_sha256": canonical_file_sha256(canonical_path),
        },
        "readiness_scope_manifest": {
            "path": "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json",
            "schema_id": str(readiness_scope.get("schema_id", "")).strip(),
            "manifest_id": str(readiness_scope.get("manifest_id", "")).strip(),
            "canonical_json_sha256": canonical_file_sha256(readiness_path),
        },
    }
    quarantine_receipt = {
        "schema_id": "kt.operator.noncanonical_quarantine_receipt.v2",
        "status": "PASS",
        "generated_utc": generated_utc,
        "execution_status": EXECUTION_STATUS,
        "outcome": "NONCANONICAL_QUARANTINE_RECEIPT_MATERIALIZED__NO_LIVE_MUTATION",
        "live_blocker_count": 0,
        "unknown_zone_queue_count": unknown_queue["queue_count"],
        "product_proof_candidate_count": product_ledger["candidate_violation_count"],
        "commercial_review_queue_count": commercial_review["review_queue_count"],
        "quarantine_scope": [
            "LAB",
            "ARCHIVE",
            "COMMERCIAL",
            "GENERATED_RUNTIME_TRUTH",
            "QUARANTINED",
            "TOOLCHAIN_PROVING",
            "LOCAL_ONLY_IGNORED",
            "EXTERNAL_ADVISORY_QUARANTINED",
        ],
        "deferred_package_scope": [
            "KT_PROD_CLEANROOM/runs/post_f_track_03/**",
            "stage_and_promote package-internal promotion remains deferred",
        ],
        "rule": "This receipt materializes quarantine accounting only; it does not move files or promote any noncanonical surface.",
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "next_lawful_move": NEXT_MOVE,
    }
    validation_matrix = {
        "schema_id": "kt.operator.trust_zone_validation_matrix.v2",
        "status": "PASS",
        "generated_utc": generated_utc,
        "execution_status": EXECUTION_STATUS,
        "outcome": "TRUST_ZONE_VALIDATION_MATRIX_REFRESHED_FOR_MATERIALIZATION",
        "validation_status": str(trust_zone_validation.get("status", "")).strip(),
        "check_count": len(validation_checks),
        "failure_count": len(validation_failures),
        "checks": validation_checks,
        "failures": validation_failures,
        "next_lawful_move": NEXT_MOVE,
    }
    packet = {
        "schema_id": "kt.operator.cohort0_trust_zone_manifest_materialization_packet.v1",
        "status": "PASS",
        "generated_utc": generated_utc,
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "authoritative_lane": REQUIRED_BRANCH,
        "branch_name": branch_name,
        "branch_head": branch_head,
        "claim_boundary": (
            "This packet materializes registry/scope/quarantine operating surfaces only. It does not promote packages, "
            "change truth-engine law, widen Gate F, or ratify upper-stack/lab claims."
        ),
        "source_receipts": {
            "contract_receipt_next_move": str(contract_receipt.get("next_lawful_move", "")).strip(),
            "prep_receipt_next_move": str(prep_receipt.get("next_lawful_move", "")).strip(),
            "prep_unknown_zone_path_count": prep_receipt.get("unknown_zone_path_count"),
            "prep_candidate_commercial_violation_count": prep_receipt.get("candidate_commercial_violation_count"),
        },
        "manifest_binding": manifest_binding,
        "materialization_changes": materialization_changes,
        "materialized_outputs": [
            "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
            "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
            "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json",
            "KT_PROD_CLEANROOM/reports/noncanonical_quarantine_receipt.json",
            "KT_PROD_CLEANROOM/reports/unknown_zone_resolution_queue.json",
            "KT_PROD_CLEANROOM/reports/product_proof_conflation_blocker_ledger.json",
            "KT_PROD_CLEANROOM/reports/commercial_boundary_violation_review_packet.json",
        ],
        "unknown_zone_queue_count": unknown_queue["queue_count"],
        "product_proof_candidate_count": product_ledger["candidate_violation_count"],
        "commercial_review_queue_count": commercial_review["review_queue_count"],
        "live_blocker_count": 0,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_trust_zone_manifest_materialization_receipt.v1",
        "status": "PASS",
        "generated_utc": generated_utc,
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "manifest_binding_count": len(manifest_binding),
        "materialized_output_count": len(packet["materialized_outputs"]),
        "unknown_zone_queue_count": unknown_queue["queue_count"],
        "product_proof_candidate_count": product_ledger["candidate_violation_count"],
        "commercial_review_queue_count": commercial_review["review_queue_count"],
        "live_blocker_count": 0,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Trust Zone Manifest Materialization Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Outcome: `{OUTCOME}`",
            f"- Authoritative lane: `{REQUIRED_BRANCH}`",
            f"- Registry/scope manifests bound: `{len(manifest_binding)}`",
            f"- Unknown-zone queue count: `{unknown_queue['queue_count']}`",
            f"- Product/proof candidate count: `{product_ledger['candidate_violation_count']}`",
            f"- Commercial review queue count: `{commercial_review['review_queue_count']}`",
            "- Live blockers: `0`",
            "- Package promotion: `deferred`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {
        "packet": packet,
        "receipt": receipt,
        "report": report,
        "unknown_queue": unknown_queue,
        "product_ledger": product_ledger,
        "commercial_review": commercial_review,
        "quarantine_receipt": quarantine_receipt,
        "validation_matrix": validation_matrix,
    }


def run(
    *,
    reports_root: Path,
    governance_root: Path,
    contract_receipt_path: Path,
    prep_receipt_path: Path,
    trust_zone_registry_path: Path,
    canonical_scope_manifest_path: Path,
    readiness_scope_manifest_path: Path,
    product_scan_path: Path,
    commercial_violations_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = common.git_current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: trust-zone materialization must run on {REQUIRED_BRANCH}, got {branch_name}")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: trust-zone materialization requires a clean worktree")

    contract_receipt = common.load_json_required(root, contract_receipt_path, label="trust-zone contract receipt")
    prep_receipt = common.load_json_required(root, prep_receipt_path, label="trust-zone parallel prep receipt")
    registry = common.load_json_required(root, trust_zone_registry_path, label="trust-zone registry")
    canonical_scope = common.load_json_required(root, canonical_scope_manifest_path, label="canonical scope manifest")
    readiness_scope = common.load_json_required(root, readiness_scope_manifest_path, label="readiness scope manifest")
    product_scan = common.load_json_required(root, product_scan_path, label="product/proof conflation scan")
    commercial_violations = common.load_json_required(root, commercial_violations_path, label="commercial claim boundary violations")

    _ensure_pass_and_deferred(contract_receipt, label="trust-zone contract receipt")
    _ensure_pass_and_deferred(prep_receipt, label="trust-zone parallel prep receipt")
    if str(prep_receipt.get("next_lawful_move", "")).strip() != "MATERIALIZE_TRUST_ZONE_REGISTRY_SCOPE_MANIFESTS_AND_QUARANTINE_RECEIPT":
        raise RuntimeError("FAIL_CLOSED: prep receipt must authorize trust-zone manifest materialization")

    registry, canonical_scope, readiness_scope, materialization_changes = materialize_scope_manifests(
        registry=registry,
        canonical_scope=canonical_scope,
        readiness_scope=readiness_scope,
    )
    write_json_stable((governance_root / "trust_zone_registry.json").resolve(), registry)
    write_json_stable((governance_root / "canonical_scope_manifest.json").resolve(), canonical_scope)
    write_json_stable((governance_root / "readiness_scope_manifest.json").resolve(), readiness_scope)

    trust_zone_validation = validate_trust_zones(root=root)
    if str(trust_zone_validation.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must pass before manifest materialization")

    outputs = build_outputs(
        root=root,
        branch_name=branch_name,
        branch_head=common.git_rev_parse(root, "HEAD"),
        materialization_changes=materialization_changes,
        tracked_files=common.git_ls_files(root),
        registry=registry,
        canonical_scope=canonical_scope,
        readiness_scope=readiness_scope,
        contract_receipt=contract_receipt,
        prep_receipt=prep_receipt,
        product_scan=product_scan,
        commercial_violations=commercial_violations,
        trust_zone_validation=trust_zone_validation,
    )

    write_json_stable((reports_root / UNKNOWN_ZONE_RESOLUTION_QUEUE).resolve(), outputs["unknown_queue"])
    write_json_stable((reports_root / PRODUCT_PROOF_BLOCKER_LEDGER).resolve(), outputs["product_ledger"])
    write_json_stable((reports_root / COMMERCIAL_BOUNDARY_REVIEW_PACKET).resolve(), outputs["commercial_review"])
    write_json_stable((reports_root / NONCANONICAL_QUARANTINE_RECEIPT).resolve(), outputs["quarantine_receipt"])
    write_json_stable((reports_root / TRUST_ZONE_VALIDATION_MATRIX).resolve(), outputs["validation_matrix"])
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {"outcome": OUTCOME, "next_lawful_move": NEXT_MOVE}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Materialize trust-zone registry/scope manifests and quarantine receipts.")
    parser.add_argument("--governance-root", default="KT_PROD_CLEANROOM/governance")
    parser.add_argument("--contract-receipt", default=f"KT_PROD_CLEANROOM/reports/{CONTRACT_RECEIPT}")
    parser.add_argument("--prep-receipt", default=f"KT_PROD_CLEANROOM/reports/{PREP_RECEIPT}")
    parser.add_argument("--trust-zone-registry", default="KT_PROD_CLEANROOM/governance/trust_zone_registry.json")
    parser.add_argument("--canonical-scope-manifest", default="KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json")
    parser.add_argument("--readiness-scope-manifest", default="KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json")
    parser.add_argument("--product-scan", default="KT_PROD_CLEANROOM/reports/product_proof_conflation_scan.json")
    parser.add_argument("--commercial-violations", default="KT_PROD_CLEANROOM/reports/commercial_claim_boundary_violations.json")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        governance_root=common.resolve_path(root, args.governance_root),
        contract_receipt_path=common.resolve_path(root, args.contract_receipt),
        prep_receipt_path=common.resolve_path(root, args.prep_receipt),
        trust_zone_registry_path=common.resolve_path(root, args.trust_zone_registry),
        canonical_scope_manifest_path=common.resolve_path(root, args.canonical_scope_manifest),
        readiness_scope_manifest_path=common.resolve_path(root, args.readiness_scope_manifest),
        product_scan_path=common.resolve_path(root, args.product_scan),
        commercial_violations_path=common.resolve_path(root, args.commercial_violations),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
