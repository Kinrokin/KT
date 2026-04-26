from __future__ import annotations

import fnmatch
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


REQUIRED_BRANCH = "authoritative/trust-zone-registry-scope-contract"
EXECUTION_STATUS = "PASS__TRUST_ZONE_PARALLEL_PREP_BUNDLE_BOUND"
OUTCOME = "TRUST_ZONE_PARALLEL_PREP_LANES_EMITTED__NON_AUTHORITATIVE"
NEXT_MOVE = "MATERIALIZE_TRUST_ZONE_REGISTRY_SCOPE_MANIFESTS_AND_QUARANTINE_RECEIPT"

OUTPUT_RECEIPT = "cohort0_trust_zone_parallel_prep_bundle_receipt.json"
OUTPUT_REPORT = "COHORT0_TRUST_ZONE_PARALLEL_PREP_BUNDLE_REPORT.md"

OUTPUTS = {
    "candidate_inventory": "trust_zone_candidate_inventory.json",
    "unknown_blockers": "unknown_zone_blocker_ledger.json",
    "zone_diff_report": "zone_assignment_diff_report.md",
    "product_proof_scan": "product_proof_conflation_scan.json",
    "commercial_claim_violations": "commercial_claim_boundary_violations.json",
    "buyer_language_patch": "buyer_safe_language_candidate_patch.md",
    "lab_promotion_contract": "lab_to_canonical_promotion_contract_draft.json",
    "promotion_required_matrix": "promotion_required_receipts_matrix.json",
    "rollback_required_matrix": "rollback_required_receipts_matrix.json",
    "archive_supersession_map": "archive_supersession_map.json",
    "archive_citation_rules": "historical_receipt_citation_rules.md",
    "stale_receipt_ledger": "stale_receipt_override_blocker_ledger.json",
    "external_intake_contract": "external_advisory_bundle_intake_contract.json",
    "advisory_hash_schema": "advisory_bundle_hash_manifest_schema.json",
    "adopt_reject_schema": "adopt_reject_supersede_matrix_schema.json",
    "standards_gap_matrix": "standards_alignment_gap_matrix_draft.json",
    "standards_forbidden_language": "standards_claim_forbidden_language.md",
    "upper_stack_inventory": "upper_stack_ratification_readiness_inventory.json",
    "router_lobe_gap_matrix": "router_lobe_gap_matrix.json",
    "adapter_gap_matrix": "adapter_civilization_gap_matrix.json",
    "clean_state_watchdog": "clean_state_watchdog_receipt.json",
    "untracked_quarantine_receipt": "untracked_residue_quarantine_receipt.json",
    "branch_authority_receipt": "branch_authority_status_receipt.json",
}

CLAIM_TERMS = (
    "best ai",
    "beyond-sota",
    "sota",
    "frontier-grade",
    "frontier grade",
    "frontier",
    "full-system",
    "full system",
    "kaggle",
    "router/lobe",
    "router and lobe",
    "commercially ready",
)


def _current_branch_name(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip() or "UNKNOWN_BRANCH"


def _git_status_porcelain(root: Path) -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout


def _git_rev_parse(root: Path, ref: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", ref],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


def _git_ls_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return sorted(line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip())


def _patterns(row: Dict[str, Any], key: str) -> list[str]:
    return [str(item).strip().replace("\\", "/") for item in row.get(key, []) if str(item).strip()]


def _matches(path: str, pattern: str) -> bool:
    norm_path = path.replace("\\", "/")
    norm_pattern = pattern.replace("\\", "/")
    if fnmatch.fnmatch(norm_path, norm_pattern):
        return True
    if norm_pattern.endswith("/**"):
        return norm_path.startswith(norm_pattern[:-3])
    return False


def _matches_any(path: str, patterns: Iterable[str]) -> bool:
    return any(_matches(path, pattern) for pattern in patterns)


def _zone_map(registry: Dict[str, Any]) -> dict[str, Dict[str, Any]]:
    rows = registry.get("zones", [])
    out: dict[str, Dict[str, Any]] = {}
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                zone_id = str(row.get("zone_id", "")).strip().upper()
                if zone_id:
                    out[zone_id] = row
    return out


def _classify_path(path: str, zones: dict[str, Dict[str, Any]]) -> list[str]:
    matches: list[str] = []
    for zone_id, row in zones.items():
        includes = _patterns(row, "include")
        excludes = _patterns(row, "exclude")
        if includes and _matches_any(path, includes) and not _matches_any(path, excludes):
            matches.append(zone_id)
    return sorted(matches)


def _tracked_text(path: Path, *, max_bytes: int = 250_000) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _claim_scan(root: Path, tracked_files: Sequence[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    scan_roots = ("README", "docs/", "KT-Codex/", "KT_PROD_CLEANROOM/docs/commercial/", "KT_PROD_CLEANROOM/product/")
    findings: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    for rel in tracked_files:
        if not rel.startswith(scan_roots):
            continue
        if not rel.lower().endswith((".md", ".txt", ".json", ".yaml", ".yml")):
            continue
        text = _tracked_text(root / rel)
        if not text:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            lowered = line.lower()
            terms = [term for term in CLAIM_TERMS if term in lowered]
            if not terms:
                continue
            row = {"path": rel, "line": line_no, "terms": terms, "snippet": line.strip()[:240]}
            findings.append(row)
            if any(term in terms for term in ("best ai", "beyond-sota", "sota", "full-system", "full system", "commercially ready")):
                violations.append({**row, "candidate_violation_class": "broad_or_commercial_claim_boundary_review"})
    return findings[:200], violations[:200]


def _upper_stack_counts(tracked_files: Sequence[str]) -> dict[str, dict[str, Any]]:
    taxonomy = {
        "crucibles_policy_c": ("crucible", "policy_c", "pressure"),
        "adapters": ("adapter",),
        "tournaments_promotion_merge": ("tournament", "promotion", "merge"),
        "router_lobes": ("router", "lobe"),
        "forge_training": ("forge", "training", "curriculum"),
    }
    out: dict[str, dict[str, Any]] = {}
    for class_id, terms in taxonomy.items():
        rows = [path for path in tracked_files if any(term in path.lower() for term in terms)]
        out[class_id] = {
            "tracked_path_count": len(rows),
            "sample_paths": rows[:40],
            "prep_classification": "needs_ordered_ratification_before_broad_claims",
        }
    return out


def _write_json_output(reports_root: Path, name: str, payload: Dict[str, Any]) -> str:
    path = (reports_root / name).resolve()
    write_json_stable(path, payload)
    return path.as_posix()


def _write_text_output(reports_root: Path, name: str, text: str) -> str:
    path = (reports_root / name).resolve()
    common.write_text(path, text)
    return path.as_posix()


def build_outputs(
    *,
    root: Path,
    branch_name: str,
    branch_head: str,
    status_before: str,
    tracked_files: Sequence[str],
    registry: Dict[str, Any],
    contract_receipt: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    generated_utc = utc_now_iso_z()
    zones = _zone_map(registry)
    classifications = {path: _classify_path(path, zones) for path in tracked_files}
    zone_counter = Counter(zone for zone_list in classifications.values() for zone in zone_list)
    unknown_paths = sorted(path for path, zone_list in classifications.items() if not zone_list)
    multi_zone_paths = sorted(path for path, zone_list in classifications.items() if len(zone_list) > 1)
    claim_findings, claim_violations = _claim_scan(root, tracked_files)
    archive_paths = [path for path in tracked_files if path.startswith("KT_ARCHIVE/") or "archive" in path.lower()]
    supersession_receipts = [path for path in tracked_files if "supersession" in path.lower()]
    upper_stack = _upper_stack_counts(tracked_files)
    common_header = {
        "status": "PASS",
        "generated_utc": generated_utc,
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "authoritative_lane": REQUIRED_BRANCH,
        "prep_only": True,
        "may_drive_live_posture": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
    }

    return {
        "candidate_inventory": {
            **common_header,
            "schema_id": "kt.operator.trust_zone_candidate_inventory.v1",
            "tracked_file_count": len(tracked_files),
            "zone_counts": dict(sorted(zone_counter.items())),
            "unknown_zone_path_count": len(unknown_paths),
            "multi_zone_path_count": len(multi_zone_paths),
            "unknown_zone_path_samples": unknown_paths[:100],
            "multi_zone_path_samples": [{"path": path, "zones": classifications[path]} for path in multi_zone_paths[:100]],
        },
        "unknown_blockers": {
            **common_header,
            "schema_id": "kt.operator.unknown_zone_blocker_ledger.v1",
            "live_blocker_count": 0,
            "prep_finding_count": len(unknown_paths),
            "rule": "Unknown paths are prep findings unless they claim live theorem/product/package authority.",
            "unknown_zone_path_samples": unknown_paths[:100],
        },
        "zone_diff_report": common.report_lines(
            "Trust Zone Assignment Diff Report",
            [
                f"- Tracked files scanned: `{len(tracked_files)}`",
                f"- Known zone assignments: `{sum(zone_counter.values())}`",
                f"- Unknown-zone path count: `{len(unknown_paths)}`",
                f"- Multi-zone path count: `{len(multi_zone_paths)}`",
                "- Status: `prep-only; not live authority`",
            ],
        ),
        "product_proof_scan": {
            **common_header,
            "schema_id": "kt.operator.product_proof_conflation_scan.v1",
            "finding_count": len(claim_findings),
            "findings": claim_findings,
            "rule": "Findings are candidates for buyer-language review and cannot widen product truth.",
        },
        "commercial_claim_violations": {
            **common_header,
            "schema_id": "kt.operator.commercial_claim_boundary_violations.v1",
            "candidate_violation_count": len(claim_violations),
            "candidate_violations": claim_violations,
            "live_blocker_count": 0,
            "rule": "Candidate violations become blockers only if promoted commercial copy claims live posture beyond canonical truth.",
        },
        "buyer_language_patch": common.report_lines(
            "Buyer Safe Language Candidate Patch",
            [
                "- Use: `KT provides governed, receipt-backed, fail-closed execution in the validated local_verifier_mode wedge.`",
                "- Avoid: `best AI`, `beyond-SOTA`, `full-system superiority`, `Kaggle proof`, or broad router/lobe claims.",
                "- Require: every commercial proof statement cites a canonical receipt and preserves Gate F narrow-wedge limits.",
            ],
        ),
        "lab_promotion_contract": {
            **common_header,
            "schema_id": "kt.operator.lab_to_canonical_promotion_contract_draft.v1",
            "promotion_steps": [
                "bind lab artifact manifest and hashes",
                "bind validation matrix and replay receipt",
                "bind claim boundary and forbidden interpretations",
                "run truth-engine recompute after proposed promotion",
                "merge through protected PR only",
            ],
            "forbidden_shortcuts": ["proximity promotion", "commercial-language promotion", "archive resurrection", "untracked authority"],
        },
        "promotion_required_matrix": {
            **common_header,
            "schema_id": "kt.operator.promotion_required_receipts_matrix.v1",
            "required_receipts": [
                "source_manifest_receipt",
                "content_hash_manifest_receipt",
                "validation_matrix_receipt",
                "claim_boundary_receipt",
                "truth_engine_recompute_receipt",
                "protected_merge_receipt",
            ],
        },
        "rollback_required_matrix": {
            **common_header,
            "schema_id": "kt.operator.rollback_required_receipts_matrix.v1",
            "required_receipts": [
                "rollback_decision_receipt",
                "supersession_or_reversion_receipt",
                "stale_source_quarantine_receipt",
                "truth_engine_recompute_receipt",
            ],
        },
        "archive_supersession_map": {
            **common_header,
            "schema_id": "kt.operator.archive_supersession_map.v1",
            "archive_path_count": len(archive_paths),
            "supersession_receipt_count": len(supersession_receipts),
            "archive_path_samples": archive_paths[:100],
            "supersession_receipt_samples": supersession_receipts[:100],
            "rule": "Archive may explain lineage only; live posture requires current canonical receipt.",
        },
        "archive_citation_rules": common.report_lines(
            "Historical Receipt Citation Rules",
            [
                "- Historical receipts may be cited only as lineage.",
                "- Every historical citation must name the superseding canonical surface when one exists.",
                "- Historical receipts may never satisfy current-head proof, package promotion, or product-truth claims.",
            ],
        ),
        "stale_receipt_ledger": {
            **common_header,
            "schema_id": "kt.operator.stale_receipt_override_blocker_ledger.v1",
            "live_blocker_count": 0,
            "candidate_stale_surface_count": len(archive_paths),
            "rule": "A stale surface becomes blocking only when it attempts to drive live truth.",
        },
        "external_intake_contract": {
            **common_header,
            "schema_id": "kt.operator.external_advisory_bundle_intake_contract.v1",
            "intake_steps": [
                "record absolute path and operator-provided source context",
                "compute SHA256 before use",
                "extract into tracked staging or quarantine, never canonical overwrite",
                "emit adopt/reject/supersede matrix",
                "fail closed on hash mismatch or hidden authority claim",
            ],
        },
        "advisory_hash_schema": {
            **common_header,
            "schema_id": "kt.operator.advisory_bundle_hash_manifest_schema.v1",
            "required_fields": ["artifact_id", "source_path", "sha256", "size_bytes", "intake_utc", "authority_status"],
            "authority_status_values": ["EXTERNAL_ADVISORY_ONLY", "REJECTED", "ADOPTED_BY_LATER_COURT", "SUPERSEDED"],
        },
        "adopt_reject_schema": {
            **common_header,
            "schema_id": "kt.operator.adopt_reject_supersede_matrix_schema.v1",
            "row_fields": ["artifact_id", "decision", "reason", "target_zone", "required_followup_receipt"],
            "decision_values": ["ADOPT", "REJECT", "SUPERSEDE", "QUARANTINE", "DEFER"],
        },
        "standards_gap_matrix": {
            **common_header,
            "schema_id": "kt.operator.standards_alignment_gap_matrix_draft.v1",
            "claim_status": "ADVISORY_GAP_MAP_ONLY__NO_COMPLIANCE_CLAIM",
            "standards": [
                {"standard": "SLSA", "current_claim": "not_claimed", "next_gap_to_assess": "build provenance and builder identity"},
                {"standard": "in-toto", "current_claim": "not_claimed", "next_gap_to_assess": "layout, link metadata, threshold signing"},
                {"standard": "Sigstore/Rekor", "current_claim": "mock_only_or_bounded", "next_gap_to_assess": "public transparency log and key policy"},
                {"standard": "TUF", "current_claim": "not_claimed", "next_gap_to_assess": "role separation and metadata expiry"},
                {"standard": "NIST SSDF/SP 800-218", "current_claim": "not_claimed", "next_gap_to_assess": "secure development practice mapping"},
                {"standard": "NIST AI RMF", "current_claim": "not_claimed", "next_gap_to_assess": "risk governance and measurement mapping"},
                {"standard": "ISO/IEC 42001-style governance", "current_claim": "not_claimed", "next_gap_to_assess": "AI management-system control mapping"},
            ],
        },
        "standards_forbidden_language": common.report_lines(
            "Standards Claim Forbidden Language",
            [
                "- Do not claim SLSA, in-toto, Sigstore/Rekor, TUF, NIST SSDF, NIST AI RMF, or ISO/IEC 42001 compliance from this prep lane.",
                "- Allowed language: `draft gap map`, `advisory pre-map`, `not a compliance claim`.",
            ],
        ),
        "upper_stack_inventory": {
            **common_header,
            "schema_id": "kt.operator.upper_stack_ratification_readiness_inventory.v1",
            "maturity_rule": "All upper-stack surfaces are inventory-only until later ordered ratification.",
            "classes": upper_stack,
        },
        "router_lobe_gap_matrix": {
            **common_header,
            "schema_id": "kt.operator.router_lobe_gap_matrix.v1",
            "gap_status": "PREP_ONLY__NO_ROUTER_OR_LOBE_SUPERIORITY_CLAIM",
            "known_gaps": [
                "router/lobe claims require ordered ratification receipts",
                "Track 01 bounded wedge result cannot be generalized to router/lobe superiority",
                "lab or scaffold surfaces require promotion law before live posture use",
            ],
        },
        "adapter_gap_matrix": {
            **common_header,
            "schema_id": "kt.operator.adapter_civilization_gap_matrix.v1",
            "gap_status": "PREP_ONLY__NO_ADAPTER_CIVILIZATION_CLAIM",
            "known_gaps": [
                "adapter lifecycle law must be bound before broad adapter claims",
                "tournament/promotion law must govern any adapter result promotion",
                "comparative results require category-fair scorecards before external claims",
            ],
        },
        "clean_state_watchdog": {
            **common_header,
            "schema_id": "kt.operator.clean_state_watchdog_receipt.v1",
            "status_before_output_write": "CLEAN" if not status_before.strip() else "DIRTY",
            "porcelain_before_output_write": status_before.splitlines(),
            "branch": branch_name,
            "branch_head": branch_head,
        },
        "untracked_quarantine_receipt": {
            **common_header,
            "schema_id": "kt.operator.untracked_residue_quarantine_receipt.v1",
            "status_before_output_write": "CLEAN" if not status_before.strip() else "DIRTY",
            "quarantine_action": "none_required" if not status_before.strip() else "defer_to_operator_quarantine_before_authority_use",
            "rule": "Untracked residue cannot become authority by proximity.",
        },
        "branch_authority_receipt": {
            **common_header,
            "schema_id": "kt.operator.branch_authority_status_receipt.v1",
            "branch": branch_name,
            "branch_head": branch_head,
            "authoritative_lane": REQUIRED_BRANCH,
            "contract_receipt_outcome": str(contract_receipt.get("outcome", "")).strip(),
            "next_lawful_move": NEXT_MOVE,
        },
        "bundle_receipt": {
            **common_header,
            "schema_id": "kt.operator.cohort0_trust_zone_parallel_prep_bundle_receipt.v1",
            "output_count": len(OUTPUTS),
            "unknown_zone_path_count": len(unknown_paths),
            "candidate_claim_finding_count": len(claim_findings),
            "candidate_commercial_violation_count": len(claim_violations),
            "upper_stack_class_count": len(upper_stack),
            "next_lawful_move": NEXT_MOVE,
        },
        "bundle_report": common.report_lines(
            "Cohort0 Trust Zone Parallel Prep Bundle Report",
            [
                f"- Execution status: `{EXECUTION_STATUS}`",
                f"- Outcome: `{OUTCOME}`",
                f"- Output surfaces: `{len(OUTPUTS)}`",
                f"- Unknown-zone path findings: `{len(unknown_paths)}`",
                f"- Product/proof claim findings: `{len(claim_findings)}`",
                "- Authority posture: `prep-only; may not drive live truth`",
                f"- Next lawful move: `{NEXT_MOVE}`",
            ],
        ),
    }


def run(*, reports_root: Path, contract_receipt_path: Path, trust_zone_registry_path: Path) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: parallel prep bundle must run on {REQUIRED_BRANCH}, got {branch_name}")
    status_before = _git_status_porcelain(root)
    if status_before.strip():
        raise RuntimeError("FAIL_CLOSED: parallel prep bundle requires a clean worktree")

    contract_receipt = common.load_json_required(root, contract_receipt_path, label="trust-zone registry/scope contract receipt")
    registry = common.load_json_required(root, trust_zone_registry_path, label="trust-zone registry")
    common.ensure_pass(contract_receipt, label="trust-zone registry/scope contract receipt")
    if str(contract_receipt.get("next_lawful_move", "")).strip() != "EXECUTE_TRUST_ZONE_BOUNDARY_PURIFICATION_PARALLEL_PREP_BUNDLE":
        raise RuntimeError("FAIL_CLOSED: contract receipt must authorize the parallel prep bundle")

    outputs = build_outputs(
        root=root,
        branch_name=branch_name,
        branch_head=_git_rev_parse(root, "HEAD"),
        status_before=status_before,
        tracked_files=_git_ls_files(root),
        registry=registry,
        contract_receipt=contract_receipt,
    )
    for key, filename in OUTPUTS.items():
        payload = outputs[key]
        if isinstance(payload, dict):
            _write_json_output(reports_root, filename, payload)
        else:
            _write_text_output(reports_root, filename, str(payload))
    _write_json_output(reports_root, OUTPUT_RECEIPT, outputs["bundle_receipt"])
    _write_text_output(reports_root, OUTPUT_REPORT, str(outputs["bundle_report"]))
    return {"outcome": OUTCOME, "next_lawful_move": NEXT_MOVE, "output_count": len(OUTPUTS)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Emit non-authoritative trust-zone parallel prep lane outputs.")
    parser.add_argument("--contract-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_trust_zone_registry_scope_contract_receipt.json")
    parser.add_argument("--trust-zone-registry", default="KT_PROD_CLEANROOM/governance/trust_zone_registry.json")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        contract_receipt_path=common.resolve_path(root, args.contract_receipt),
        trust_zone_registry_path=common.resolve_path(root, args.trust_zone_registry),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
