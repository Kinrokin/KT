from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.trust_zone_validate import validate_trust_zones
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


OUTPUT_PACKET = "cohort0_trust_zone_registry_scope_contract_packet.json"
OUTPUT_RECEIPT = "cohort0_trust_zone_registry_scope_contract_receipt.json"
OUTPUT_REPORT = "COHORT0_TRUST_ZONE_REGISTRY_SCOPE_CONTRACT_REPORT.md"
GOVERNANCE_CONTRACT = "trust_zone_boundary_purification_scope_contract.json"

REQUIRED_BRANCH = "authoritative/trust-zone-registry-scope-contract"
EXECUTION_STATUS = "PASS__TRUST_ZONE_REGISTRY_SCOPE_CONTRACT_BOUND"
OUTCOME = "TRUST_ZONE_BOUNDARY_PURIFICATION_REGISTRY_AND_SCOPE_CONTRACT_DEFINED"
NEXT_MOVE = "EXECUTE_TRUST_ZONE_BOUNDARY_PURIFICATION_PARALLEL_PREP_BUNDLE"


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


def _zone_contract() -> list[dict[str, Any]]:
    return [
        {
            "zone_id": "CANONICAL",
            "drives_live_posture": True,
            "scope_rule": "Only promoted canonical repo authority and approved generated-truth surfaces may drive live theorem/product posture.",
            "compatible_existing_zones": ["CANONICAL", "GENERATED_RUNTIME_TRUTH"],
        },
        {
            "zone_id": "LAB",
            "drives_live_posture": False,
            "scope_rule": "Experimental, ratification, benchmark, adapter, router, lobe, and upper-stack work remains non-authoritative until promoted by law.",
            "compatible_existing_zones": ["LAB"],
        },
        {
            "zone_id": "ARCHIVE",
            "drives_live_posture": False,
            "scope_rule": "Historical lineage may be cited only with supersession context and may never override current canonical truth.",
            "compatible_existing_zones": ["ARCHIVE", "QUARANTINED"],
        },
        {
            "zone_id": "COMMERCIAL",
            "drives_live_posture": False,
            "scope_rule": "Buyer/product language may reference canonical truth but may not become proof or widen validated claims.",
            "compatible_existing_zones": ["COMMERCIAL"],
        },
        {
            "zone_id": "LOCAL_ONLY_IGNORED",
            "drives_live_posture": False,
            "scope_rule": "Ignored, untracked, local freeze, _tmp, and operator scratch artifacts are preservation-or-ignore only.",
            "compatible_existing_zones": [],
        },
        {
            "zone_id": "EXTERNAL_ADVISORY_QUARANTINED",
            "drives_live_posture": False,
            "scope_rule": "External bundles, other-chat outputs, Drive exports, and outside audits require hash-bound intake and adopt/reject/supersede decisions.",
            "compatible_existing_zones": ["QUARANTINED"],
        },
        {
            "zone_id": "TOOLCHAIN_PROVING",
            "drives_live_posture": False,
            "scope_rule": "Tools, tests, CI, validators, and operator scripts may prove or package truth but may not inherit runtime authority.",
            "compatible_existing_zones": ["TOOLCHAIN_PROVING"],
        },
    ]


def _violation_classes() -> list[dict[str, Any]]:
    return [
        {
            "class_id": "stale_artifact_override",
            "severity": "BLOCKING",
            "trigger": "A superseded or stale artifact attempts to define current live posture.",
            "resolution": "Bind supersession, quarantine the stale driver, and rerun truth-engine recompute.",
        },
        {
            "class_id": "archive_to_canonical_bleed",
            "severity": "BLOCKING",
            "trigger": "Archive or historical lineage material is treated as canonical active truth.",
            "resolution": "Move to archive citation rules or quarantine, then regenerate canonical scope manifest.",
        },
        {
            "class_id": "product_proof_conflation",
            "severity": "BLOCKING",
            "trigger": "Commercial or buyer-facing language turns product copy into proof, or proof receipts into broad product claims.",
            "resolution": "Reduce language to canonical product truth or require a product-claim promotion court.",
        },
        {
            "class_id": "lab_result_overclaim",
            "severity": "BLOCKING",
            "trigger": "A lab or benchmark result claims live canonical, router/lobe, Kaggle, or broad superiority posture before promotion.",
            "resolution": "Return the result to lab scope and open lab-to-canonical promotion only if required receipts exist.",
        },
        {
            "class_id": "deferred_package_artifact_misuse",
            "severity": "BLOCKING",
            "trigger": "Track 03 package artifacts or stage-and-promote outputs drive repo authority before package promotion is separately authorized.",
            "resolution": "Preserve package promotion deferral and emit a package-boundary blocker ledger.",
        },
        {
            "class_id": "external_advisory_bundle_treated_as_authority",
            "severity": "BLOCKING",
            "trigger": "A downloaded zip, prompt, Drive export, outside audit, or other-chat file is consumed as authority without hash-bound intake.",
            "resolution": "Run external advisory bundle intake with hash manifest and adopt/reject/supersede matrix.",
        },
        {
            "class_id": "unknown_zone_live_claim",
            "severity": "BLOCKING",
            "trigger": "A path with no zone assignment claims live theorem, product, package, or promotion truth.",
            "resolution": "Assign a zone or quarantine before it can be used by any live posture engine.",
        },
    ]


def build_outputs(
    *,
    branch_head: str,
    authority_receipt: Dict[str, Any],
    post_merge_audit_receipt: Dict[str, Any],
    current_registry: Dict[str, Any],
    canonical_scope_manifest: Dict[str, Any],
    readiness_scope_manifest: Dict[str, Any],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    root = repo_root()
    zones = _zone_contract()
    violations = _violation_classes()
    contract = {
        "schema_id": "kt.governance.trust_zone_boundary_purification_scope_contract.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "authoritative_lane": REQUIRED_BRANCH,
        "branch_head": branch_head,
        "claim_boundary": (
            "This contract defines trust-zone and boundary-purification law only. It does not promote packages, "
            "widen Gate F, change truth-engine derivation law, or ratify upper-stack/lab claims."
        ),
        "source_authority": {
            "authority_receipt_outcome": str(authority_receipt.get("outcome", "")).strip(),
            "post_merge_audit_outcome": str(post_merge_audit_receipt.get("outcome", "")).strip(),
            "package_promotion_remains_deferred": bool(post_merge_audit_receipt.get("package_promotion_remains_deferred", False)),
            "trust_zone_validation_status": str(trust_zone_validation.get("status", "")).strip(),
        },
        "zone_registry_contract": zones,
        "scope_rules": {
            "can_drive_live_posture": ["CANONICAL"],
            "can_support_historical_lineage_only": ["ARCHIVE", "EXTERNAL_ADVISORY_QUARANTINED"],
            "can_inform_product_or_commercial_language": ["CANONICAL", "COMMERCIAL"],
            "excluded_from_authority_entirely": ["LOCAL_ONLY_IGNORED"],
            "toolchain_may_prove_but_not_own_runtime_truth": ["TOOLCHAIN_PROVING"],
        },
        "promotion_rules": {
            "lab_to_canonical": [
                "requires explicit promotion packet",
                "requires source manifest and content hashes",
                "requires validation matrix PASS",
                "requires truth-engine recompute after promotion",
            ],
            "archive_citation": [
                "must cite superseding live surface when one exists",
                "must never drive current posture",
                "must enter stale-source quarantine ledger if ambiguous",
            ],
            "commercial_reference_to_canonical": [
                "may quote bounded canonical product truth only",
                "may not convert Track 01/02/03 proof into broad superiority",
                "must preserve Gate F local_verifier_mode-only boundary",
            ],
            "local_only_residue": [
                "must stay ignored, quarantined, or externally preserved",
                "must not satisfy current-head proof requirements",
            ],
        },
        "violation_classes": violations,
        "required_outputs": [
            "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
            "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json",
            "KT_PROD_CLEANROOM/reports/noncanonical_quarantine_receipt.json",
            "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
            "KT_PROD_CLEANROOM/reports/trust_zone_validation_matrix.json",
        ],
        "failure_law": {
            "blocking": [
                "any file claiming live authority from the wrong zone",
                "any product claim using unpromoted lab evidence",
                "any stale historical receipt driving live posture",
                "any deferred package artifact driving repo truth",
                "any external advisory artifact treated as authority without hash-bound intake",
            ],
            "warn_only": [
                "historical artifact is stale but explicitly non-driving",
                "commercial copy references canonical truth without overclaim",
                "unknown path exists without live-authority language",
            ],
            "new_court_required": [
                "package promotion boundary change",
                "truth-engine derivation-law change",
                "Gate F product posture broadening",
                "upper-stack/lab result promotion to canonical truth",
            ],
        },
        "current_registry_seed": {
            "schema_id": str(current_registry.get("schema_id", "")).strip(),
            "registry_id": str(current_registry.get("registry_id", "")).strip(),
            "zone_count": len(current_registry.get("zones", [])) if isinstance(current_registry.get("zones"), list) else 0,
        },
        "current_scope_seed": {
            "canonical_scope_manifest_id": str(canonical_scope_manifest.get("manifest_id", "")).strip(),
            "readiness_scope_manifest_id": str(readiness_scope_manifest.get("manifest_id", "")).strip(),
        },
        "next_lawful_move": NEXT_MOVE,
    }
    packet = {
        "schema_id": "kt.operator.cohort0_trust_zone_registry_scope_contract_packet.v1",
        "status": "PASS",
        "generated_utc": contract["generated_utc"],
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "contract_ref": common.resolve_path(
            root,
            f"KT_PROD_CLEANROOM/governance/{GOVERNANCE_CONTRACT}",
        ).as_posix(),
        "zone_count": len(zones),
        "violation_class_count": len(violations),
        "required_output_count": len(contract["required_outputs"]),
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "source_refs": common.output_ref_dict(
            authority_receipt=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_trust_zone_boundary_purification_authority_receipt.json"),
            post_merge_audit_receipt=common.resolve_path(root, "KT_PROD_CLEANROOM/reports/cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json"),
            trust_zone_registry=common.resolve_path(root, "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"),
            canonical_scope_manifest=common.resolve_path(root, "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json"),
            readiness_scope_manifest=common.resolve_path(root, "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json"),
        ),
        "contract": contract,
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_trust_zone_registry_scope_contract_receipt.v1",
        "status": "PASS",
        "generated_utc": contract["generated_utc"],
        "execution_status": EXECUTION_STATUS,
        "outcome": OUTCOME,
        "zone_count": len(zones),
        "violation_class_count": len(violations),
        "required_output_count": len(contract["required_outputs"]),
        "package_promotion_remains_deferred": True,
        "trust_zone_validation_status": str(trust_zone_validation.get("status", "")).strip(),
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Trust Zone Registry Scope Contract Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Outcome: `{OUTCOME}`",
            f"- Authoritative lane: `{REQUIRED_BRANCH}`",
            f"- Zones bound: `{len(zones)}`",
            f"- Violation classes bound: `{len(violations)}`",
            "- Package promotion: `deferred`",
            "- Truth-engine derivation law: `unchanged`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"contract": contract, "packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    governance_root: Path,
    authority_receipt_path: Path,
    post_merge_audit_receipt_path: Path,
    trust_zone_registry_path: Path,
    canonical_scope_manifest_path: Path,
    readiness_scope_manifest_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: trust-zone scope contract must run on {REQUIRED_BRANCH}, got {branch_name}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: trust-zone scope contract requires a clean worktree")

    authority_receipt = common.load_json_required(root, authority_receipt_path, label="trust-zone authority receipt")
    post_merge_audit_receipt = common.load_json_required(root, post_merge_audit_receipt_path, label="post-merge boundary readiness audit receipt")
    current_registry = common.load_json_required(root, trust_zone_registry_path, label="trust-zone registry")
    canonical_scope_manifest = common.load_json_required(root, canonical_scope_manifest_path, label="canonical scope manifest")
    readiness_scope_manifest = common.load_json_required(root, readiness_scope_manifest_path, label="readiness scope manifest")

    common.ensure_pass(authority_receipt, label="trust-zone authority receipt")
    common.ensure_pass(post_merge_audit_receipt, label="post-merge boundary readiness audit receipt")
    if str(authority_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_TRUST_ZONE_BOUNDARY_PURIFICATION_REGISTRY_AND_SCOPE_CONTRACT":
        raise RuntimeError("FAIL_CLOSED: trust-zone authority receipt must authorize registry/scope contract authoring")
    if str(post_merge_audit_receipt.get("next_lawful_move", "")).strip() != "PROMOTE_TRUST_ZONE_BOUNDARY_PURIFICATION_AS_NEXT_AUTHORITATIVE_LANE":
        raise RuntimeError("FAIL_CLOSED: post-merge audit must preserve trust-zone promotion next move")
    if not bool(post_merge_audit_receipt.get("package_promotion_remains_deferred", False)):
        raise RuntimeError("FAIL_CLOSED: package promotion must remain deferred")

    trust_zone_validation = validate_trust_zones(root=root)
    if str(trust_zone_validation.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: trust-zone validation must pass before scope contract binding")

    outputs = build_outputs(
        branch_head=_git_rev_parse(root, "HEAD"),
        authority_receipt=authority_receipt,
        post_merge_audit_receipt=post_merge_audit_receipt,
        current_registry=current_registry,
        canonical_scope_manifest=canonical_scope_manifest,
        readiness_scope_manifest=readiness_scope_manifest,
        trust_zone_validation=trust_zone_validation,
    )

    write_json_stable((governance_root / GOVERNANCE_CONTRACT).resolve(), outputs["contract"])
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
    parser = common.main_parser("Bind the trust-zone boundary-purification registry/scope contract.")
    parser.add_argument("--governance-root", default="KT_PROD_CLEANROOM/governance")
    parser.add_argument("--authority-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_trust_zone_boundary_purification_authority_receipt.json")
    parser.add_argument("--post-merge-audit-receipt", default="KT_PROD_CLEANROOM/reports/cohort0_post_merge_canonical_truth_boundary_readiness_audit_receipt.json")
    parser.add_argument("--trust-zone-registry", default="KT_PROD_CLEANROOM/governance/trust_zone_registry.json")
    parser.add_argument("--canonical-scope-manifest", default="KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json")
    parser.add_argument("--readiness-scope-manifest", default="KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json")
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        governance_root=common.resolve_path(root, args.governance_root),
        authority_receipt_path=common.resolve_path(root, args.authority_receipt),
        post_merge_audit_receipt_path=common.resolve_path(root, args.post_merge_audit_receipt),
        trust_zone_registry_path=common.resolve_path(root, args.trust_zone_registry),
        canonical_scope_manifest_path=common.resolve_path(root, args.canonical_scope_manifest),
        readiness_scope_manifest_path=common.resolve_path(root, args.readiness_scope_manifest),
    )
    print(result["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
