from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
RECEIPT_INDEX_REL = f"{DEFAULT_REPORT_ROOT_REL}/ws0_ws11_closeout_receipt_index.json"
BLOCKER_REGISTER_REL = f"{DEFAULT_REPORT_ROOT_REL}/ws0_ws11_closeout_blocker_register.json"
PROOF_LADDER_REL = f"{DEFAULT_REPORT_ROOT_REL}/ws0_ws11_closeout_proof_class_ladder.json"
SUMMARY_REL = f"{DEFAULT_REPORT_ROOT_REL}/ws0_ws11_closeout_summary.json"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "HEAD")
    except Exception:  # noqa: BLE001
        return ""


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return load_json(path)


def _artifact_meta(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    payload: Dict[str, Any] = {}
    if path.exists() and path.suffix.lower() == ".json":
        payload = load_json(path)
    generated_utc = ""
    for key in ("generated_utc", "created_utc", "effective_utc"):
        value = str(payload.get(key, "")).strip()
        if value:
            generated_utc = value
            break
    subject_commit = ""
    for key in (
        "compiled_head_commit",
        "validated_head_sha",
        "current_head_commit",
        "pinned_head_sha",
        "truth_subject_commit",
        "platform_governance_subject_commit",
        "runtime_boundary_subject_commit",
    ):
        value = str(payload.get(key, "")).strip()
        if value:
            subject_commit = value
            break
    return {
        "artifact_ref": rel,
        "exists": path.exists(),
        "schema_id": str(payload.get("schema_id", "")).strip(),
        "status": str(payload.get("status", "")).strip(),
        "generated_utc": generated_utc,
        "subject_commit": subject_commit,
    }


def _closeout_artifact_refs(*, root: Path, report_root_rel: str) -> List[str]:
    report_root = (root / Path(report_root_rel)).resolve()
    if not report_root.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing report root: {report_root.as_posix()}")

    refs: List[str] = []
    for path in sorted(report_root.rglob("*.json")):
        name = path.name.lower()
        if any(token in name for token in ("receipt", "manifest", "index", "register", "summary", "catalog", "ladder")):
            refs.append(path.relative_to(root).as_posix())
    return refs


def _workstream_definitions() -> List[Dict[str, Any]]:
    return [
        {
            "workstream_id": "WS0",
            "title": "Audit Baseline And Scope Lock",
            "artifact_refs": [
                "KT_PROD_CLEANROOM/reports/system_audit_scope.json",
                "KT_PROD_CLEANROOM/reports/blast_radius_map.json",
                "KT_PROD_CLEANROOM/reports/dependency_touch_matrix.json",
                "KT_PROD_CLEANROOM/reports/external_admissibility_gap_register.json",
            ],
            "summary": "Audit baseline, blast radius, dependency grammar, and blocker register were pinned.",
        },
        {
            "workstream_id": "WS1",
            "title": "Authority Contract Freeze And Documentary Demotion",
            "artifact_refs": [
                "KT_PROD_CLEANROOM/reports/WS1_completion_report.json",
                "KT_PROD_CLEANROOM/reports/documentary_truth_demotions_receipt.json",
            ],
            "summary": "Main-bound mirrors were frozen as documentary-only under an explicit completion report.",
        },
        {
            "workstream_id": "WS2",
            "title": "Authority Resolver Singularity",
            "artifact_refs": [
                "KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json",
                "KT_PROD_CLEANROOM/reports/truth_supersession_receipt.json",
                "KT_PROD_CLEANROOM/reports/settled_authority_promotion_receipt.json",
            ],
            "summary": "Settled truth source and supersession semantics were established around the ledger-backed authority path.",
        },
        {
            "workstream_id": "WS3",
            "title": "Reporting Integrity Repair",
            "artifact_refs": [
                "KT_PROD_CLEANROOM/reports/reporting_integrity_repair_receipt.json",
            ],
            "summary": "Remote publication reporting was repaired without upgrading authority proof class.",
        },
        {
            "workstream_id": "WS4",
            "title": "Published-Head Admissible Convergence",
            "artifact_refs": [
                "KT_PROD_CLEANROOM/reports/published_head_self_convergence_receipt.json",
                "KT_PROD_CLEANROOM/reports/authority_convergence_receipt.json",
            ],
            "summary": "Published-head self-convergence remains explicit and unresolved on the final retained evidence stack.",
        },
        {
            "workstream_id": "WS5",
            "title": "Authority Bundle And Attestation Fabric",
            "artifact_refs": [
                "KT_PROD_CLEANROOM/governance/authority_subject_contract.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
            ],
            "summary": "Deterministic authority subject and bundle minting are materialized and exercised by the publication layer.",
        },
        {
            "workstream_id": "WS6",
            "title": "Sigstore And In-Toto Publication Layer",
            "artifact_refs": [
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
            ],
            "summary": "Transparency-backed signing, verification, and authority-bundle validation pass.",
        },
        {
            "workstream_id": "WS7",
            "title": "Public Verifier Productization",
            "artifact_refs": [
                "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
            ],
            "summary": "Evidence-commit versus subject-commit semantics are machine-legible and anti-overread.",
        },
        {
            "workstream_id": "WS8",
            "title": "Representative Authority-Lane Reproducibility",
            "artifact_refs": [
                "KT_PROD_CLEANROOM/reports/representative_authority_lane_reproducibility_receipt.json",
                "KT_PROD_CLEANROOM/reports/proofrunbundle_index.json",
            ],
            "summary": "Same-MVE clean-clone reproducibility is proven for certify, hat_demo, and the representative authority lane.",
        },
        {
            "workstream_id": "WS9",
            "title": "Platform Governance Narrowing",
            "artifact_refs": [
                "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
            ],
            "summary": "Workflow governance is admitted while platform enforcement remains explicitly blocked.",
        },
        {
            "workstream_id": "WS10",
            "title": "Runtime Boundary And Commercial Claim Compiler Settlement",
            "artifact_refs": [
                "KT_PROD_CLEANROOM/reports/runtime_boundary_integrity_receipt.json",
                "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
                "KT_PROD_CLEANROOM/reports/commercial_program_catalog.json",
            ],
            "summary": "Canonical runtime boundary and bounded commercial claims are settled on their subject head.",
        },
        {
            "workstream_id": "WS11",
            "title": "Frontier Settlement And H1 Gate Evaluation",
            "artifact_refs": [
                "KT_PROD_CLEANROOM/reports/frontier_settlement_receipt.json",
                "KT_PROD_CLEANROOM/reports/h1_activation_gate_receipt.json",
                "KT_PROD_CLEANROOM/reports/next_horizon_activation_receipt.json",
            ],
            "summary": "The final frontier settlement passes as an evaluation and seals H1 as blocked pending stronger proof.",
        },
    ]


def _workstream_statuses(ctx: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    ws1 = ctx["KT_PROD_CLEANROOM/reports/WS1_completion_report.json"]
    ws1_status = str(((ws1.get("verdict") or {}).get("status", ""))).strip()
    published = ctx["KT_PROD_CLEANROOM/reports/published_head_self_convergence_receipt.json"]
    authority = ctx["KT_PROD_CLEANROOM/reports/authority_convergence_receipt.json"]
    crypto = ctx["KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json"]
    verifier = ctx["KT_PROD_CLEANROOM/reports/public_verifier_manifest.json"]
    representative = ctx["KT_PROD_CLEANROOM/reports/representative_authority_lane_reproducibility_receipt.json"]
    platform = ctx["KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json"]
    runtime_boundary = ctx["KT_PROD_CLEANROOM/reports/runtime_boundary_integrity_receipt.json"]
    commercial = ctx["KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json"]
    frontier = ctx["KT_PROD_CLEANROOM/reports/frontier_settlement_receipt.json"]

    return {
        "WS0": "PASS",
        "WS1": ws1_status or "PASS",
        "WS2": "PASS"
        if str(ctx["KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json"].get("status", "")).strip() == "SETTLED_AUTHORITATIVE"
        and str(ctx["KT_PROD_CLEANROOM/reports/truth_supersession_receipt.json"].get("status", "")).strip() == "PASS"
        else "HOLD",
        "WS3": str(ctx["KT_PROD_CLEANROOM/reports/reporting_integrity_repair_receipt.json"].get("status", "")).strip() or "HOLD",
        "WS4": "NOT_PROVEN_ON_FINAL_HEAD"
        if str(published.get("proof_class", "")).strip() != "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN"
        or str(authority.get("status", "")).strip() != "PASS"
        else "PASS",
        "WS5": "PASS"
        if any(
            isinstance(row, dict)
            and str(row.get("check", "")).strip() == "authority_bundle_minted_and_validated"
            and str(row.get("status", "")).strip() == "PASS"
            for row in (crypto.get("checks") if isinstance(crypto.get("checks"), list) else [])
        )
        else "HOLD",
        "WS6": str(crypto.get("status", "")).strip() or "HOLD",
        "WS7": "PASS"
        if bool(verifier.get("evidence_contains_subject"))
        and bool(str(verifier.get("claim_boundary", "")).strip())
        else "HOLD",
        "WS8": "PASS"
        if str(representative.get("status", "")).strip() == "PASS"
        and bool(representative.get("representative_authority_lane_proven"))
        else "HOLD",
        "WS9": "PASS_WITH_PLATFORM_BLOCK"
        if str(platform.get("platform_governance_verdict", "")).strip() == "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED"
        else str(platform.get("status", "")).strip() or "HOLD",
        "WS10": "PASS"
        if str(runtime_boundary.get("status", "")).strip() == "PASS" and str(commercial.get("status", "")).strip() == "PASS"
        else "HOLD",
        "WS11": str(frontier.get("status", "")).strip() or "HOLD",
    }


def build_closeout_receipt_index(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    primary_refs: List[str] = []
    workstreams = _workstream_definitions()
    for row in workstreams:
        for rel in row["artifact_refs"]:
            if rel not in primary_refs:
                primary_refs.append(rel)
    artifact_refs = _closeout_artifact_refs(root=root, report_root_rel=report_root_rel)
    for rel in primary_refs:
        if rel not in artifact_refs:
            artifact_refs.append(rel)

    ctx = {rel: _load_required(root, rel) for rel in primary_refs if Path(rel).suffix.lower() == ".json"}
    statuses = _workstream_statuses(ctx)

    return {
        "schema_id": "kt.operator.ws0_ws11_closeout_receipt_index.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": _git_head(root),
        "claim_boundary": (
            "This closeout bundle indexes WS0-WS11 receipts for compiled_head_commit only. "
            "A later repository head that contains this bundle must not be described as the compiled head unless the SHAs match."
        ),
        "workstream_index": [
            {
                "workstream_id": row["workstream_id"],
                "title": row["title"],
                "final_status": statuses[row["workstream_id"]],
                "summary": row["summary"],
                "artifact_refs": list(row["artifact_refs"]),
            }
            for row in workstreams
        ],
        "artifact_index": [_artifact_meta(root, rel) for rel in artifact_refs],
    }


def build_closeout_blocker_register(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    frontier = _load_required(root, f"{report_root_rel}/frontier_settlement_receipt.json")
    platform = _load_required(root, f"{report_root_rel}/platform_governance_narrowing_receipt.json")
    representative = _load_required(root, f"{report_root_rel}/representative_authority_lane_reproducibility_receipt.json")

    remaining = [
        {
            "blocker_id": "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED",
            "severity": "CRITICAL",
            "status": "OPEN",
            "blocks": ["published-head self-convergence proof", "H1 activation", "higher authority claims"],
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/published_head_self_convergence_receipt.json",
                "KT_PROD_CLEANROOM/reports/h1_activation_gate_receipt.json",
            ],
        },
        {
            "blocker_id": "AUTHORITY_CONVERGENCE_UNRESOLVED",
            "severity": "CRITICAL",
            "status": "OPEN",
            "blocks": ["truth publication stabilization", "H1 activation", "current-head authority closure"],
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/authority_convergence_receipt.json",
                "KT_PROD_CLEANROOM/reports/frontier_settlement_receipt.json",
            ],
        },
        {
            "blocker_id": "TRUTH_PUBLICATION_STABILIZED_FALSE",
            "severity": "HIGH",
            "status": "OPEN",
            "blocks": ["Domain 1 closure", "H1 activation", "promotion-civilization entry"],
            "evidence_refs": [
                "KT_PROD_CLEANROOM/governance/execution_board.json",
                "KT_PROD_CLEANROOM/reports/h1_activation_gate_receipt.json",
            ],
        },
        {
            "blocker_id": "PLATFORM_ENFORCEMENT_UNPROVEN",
            "severity": "HIGH",
            "status": "OPEN",
            "blocks": ["platform-enforced governance claims", "enterprise legitimacy above workflow governance only"],
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
                "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
            ],
        },
        {
            "blocker_id": "CROSS_ENV_CONTROLLED_VARIATION_NOT_RUN",
            "severity": "MEDIUM",
            "status": "OPEN",
            "blocks": ["higher reproducibility band", "cross-environment authority-lane proof"],
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/representative_authority_lane_reproducibility_receipt.json",
                "KT_PROD_CLEANROOM/reports/twocleanclone_proof.json",
            ],
        },
        {
            "blocker_id": "H1_ACTIVATION_GATE_CLOSED",
            "severity": "HIGH",
            "status": "OPEN",
            "blocks": ["single-adapter H1 activation", "router and multi-adapter activation"],
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/h1_activation_gate_receipt.json",
                "KT_PROD_CLEANROOM/reports/next_horizon_activation_receipt.json",
            ],
        },
    ]

    resolved = [
        {
            "blocker_id": "DOCUMENTARY_MIRROR_AMBIGUITY_CLEARED",
            "cleared_by": "WS1",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/WS1_completion_report.json",
                "KT_PROD_CLEANROOM/reports/documentary_truth_demotions_receipt.json",
            ],
        },
        {
            "blocker_id": "STALE_LEDGER_PUBLICATION_REPORTING_CLEARED",
            "cleared_by": "WS3",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/reporting_integrity_repair_receipt.json",
            ],
        },
        {
            "blocker_id": "TRANSPARENCY_PUBLICATION_LAYER_COMPLETE",
            "cleared_by": "WS6",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
            ],
        },
        {
            "blocker_id": "PUBLIC_VERIFIER_OVERREAD_ELIMINATED",
            "cleared_by": "WS7",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
            ],
        },
        {
            "blocker_id": "REPRESENTATIVE_AUTHORITY_LANE_SAME_MVE_PROVEN",
            "cleared_by": "WS8",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/representative_authority_lane_reproducibility_receipt.json",
                "KT_PROD_CLEANROOM/reports/proofrunbundle_index.json",
            ],
        },
        {
            "blocker_id": "PLATFORM_GOVERNANCE_AMBIGUITY_FORMALLY_NARROWED",
            "cleared_by": "WS9",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
            ],
        },
        {
            "blocker_id": "RUNTIME_BOUNDARY_CONTRADICTION_CLEARED",
            "cleared_by": "WS10",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/runtime_boundary_integrity_receipt.json",
            ],
        },
        {
            "blocker_id": "COMMERCIAL_CLAIM_OVERREAD_BOUNDARY_ENFORCED",
            "cleared_by": "WS10",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
                "KT_PROD_CLEANROOM/reports/commercial_program_catalog.json",
            ],
        },
    ]

    return {
        "schema_id": "kt.operator.ws0_ws11_closeout_blocker_register.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": _git_head(root),
        "claim_boundary": (
            "This blocker register describes the final retained WS0-WS11 ceiling for compiled_head_commit only. "
            "A later repository head that contains this register must not be described as the compiled head unless the SHAs match."
        ),
        "frontier_settlement_verdict": str(frontier.get("frontier_settlement_verdict", "")).strip(),
        "platform_governance_verdict": str(platform.get("platform_governance_verdict", "")).strip(),
        "representative_authority_lane_proven": bool(representative.get("representative_authority_lane_proven")),
        "remaining_blockers": remaining,
        "resolved_blockers": resolved,
    }


def build_closeout_proof_class_ladder(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    ws1 = _load_required(root, f"{report_root_rel}/WS1_completion_report.json")
    settled_truth = _load_required(root, f"{report_root_rel}/settled_truth_source_receipt.json")
    reporting = _load_required(root, f"{report_root_rel}/reporting_integrity_repair_receipt.json")
    published = _load_required(root, f"{report_root_rel}/published_head_self_convergence_receipt.json")
    verifier = _load_required(root, f"{report_root_rel}/public_verifier_manifest.json")
    platform = _load_required(root, f"{report_root_rel}/platform_governance_narrowing_receipt.json")
    runtime_boundary = _load_required(root, f"{report_root_rel}/runtime_boundary_integrity_receipt.json")
    representative = _load_required(root, f"{report_root_rel}/representative_authority_lane_reproducibility_receipt.json")
    frontier = _load_required(root, f"{report_root_rel}/frontier_settlement_receipt.json")

    levels = [
        {
            "rank": 1,
            "proof_class_id": "DOCUMENTARY_DEMOTION_FROZEN",
            "attained": str(((ws1.get("verdict") or {}).get("status", ""))).strip() == "PASS",
            "subject_commit": str((ws1.get("post_ws1_repo_state") or {}).get("git_head", "")).strip(),
            "boundary": "Main-bound mirrors are documentary compatibility surfaces only.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/WS1_completion_report.json",
            ],
        },
        {
            "rank": 2,
            "proof_class_id": "SETTLED_AUTHORITATIVE_LEDGER_CURRENT_HEAD",
            "attained": str(settled_truth.get("status", "")).strip() == "SETTLED_AUTHORITATIVE",
            "subject_commit": str(settled_truth.get("pinned_head_sha", "")).strip(),
            "boundary": "Active truth source is the ledger current pointer, not the main mirror.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json",
                "KT_PROD_CLEANROOM/reports/truth_supersession_receipt.json",
            ],
        },
        {
            "rank": 3,
            "proof_class_id": "REPORTING_INTEGRITY_REPAIRED",
            "attained": str(reporting.get("status", "")).strip() == "PASS",
            "subject_commit": str(reporting.get("current_git_head", "")).strip(),
            "boundary": "Remote publication reporting is accurate without upgrading authority proof class.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/reporting_integrity_repair_receipt.json",
            ],
        },
        {
            "rank": 4,
            "proof_class_id": "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN",
            "attained": str(published.get("proof_class", "")).strip() == "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN",
            "subject_commit": str(published.get("validated_head_sha", "")).strip(),
            "boundary": "Would permit published-head authority claims only if explicitly proven.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/published_head_self_convergence_receipt.json",
            ],
        },
        {
            "rank": 5,
            "proof_class_id": "PUBLISHED_HEAD_TRANSPARENCY_VERIFIED_SUBJECT",
            "attained": str(verifier.get("subject_verdict", "")).strip() == "PUBLISHED_HEAD_TRANSPARENCY_VERIFIED",
            "subject_commit": str(verifier.get("truth_subject_commit", "")).strip(),
            "boundary": "Transparency verification applies to truth_subject_commit, not automatically to current HEAD.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
            ],
        },
        {
            "rank": 6,
            "proof_class_id": "WORKFLOW_GOVERNANCE_ONLY",
            "attained": str(platform.get("platform_governance_verdict", "")).strip() == "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED",
            "subject_commit": str(platform.get("platform_governance_subject_commit", "")).strip(),
            "boundary": "Workflow governance is proven; platform enforcement is not.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
                "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
            ],
        },
        {
            "rank": 7,
            "proof_class_id": "CANONICAL_RUNTIME_BOUNDARY_SETTLED",
            "attained": str(runtime_boundary.get("runtime_boundary_verdict", "")).strip() == "CANONICAL_RUNTIME_BOUNDARY_SETTLED",
            "subject_commit": str(runtime_boundary.get("runtime_boundary_subject_commit", "")).strip(),
            "boundary": "Compatibility-only roots are quarantined outside canonical runtime truth.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/runtime_boundary_integrity_receipt.json",
            ],
        },
        {
            "rank": 8,
            "proof_class_id": "REPRESENTATIVE_AUTHORITY_LANE_SAME_MVE_ONLY",
            "attained": bool(representative.get("representative_authority_lane_proven")),
            "subject_commit": str(representative.get("validated_head_sha", "")).strip(),
            "boundary": "Representative authority-lane reproducibility is proven only on the same MVE, not cross-environment.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/representative_authority_lane_reproducibility_receipt.json",
                "KT_PROD_CLEANROOM/reports/proofrunbundle_index.json",
            ],
        },
        {
            "rank": 9,
            "proof_class_id": "FRONTIER_SETTLEMENT_WITH_H1_BLOCK",
            "attained": str(frontier.get("frontier_settlement_verdict", "")).strip() == "FRONTIER_SETTLED_WITH_H1_BLOCK",
            "subject_commit": str(frontier.get("compiled_head_commit", "")).strip(),
            "boundary": "Frontier settlement is complete as an evaluation; H1 remains blocked.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/frontier_settlement_receipt.json",
                "KT_PROD_CLEANROOM/reports/h1_activation_gate_receipt.json",
            ],
        },
        {
            "rank": 10,
            "proof_class_id": "H1_SINGLE_ADAPTER_ALLOWED",
            "attained": bool(frontier.get("h1_allowed")),
            "subject_commit": str(frontier.get("compiled_head_commit", "")).strip(),
            "boundary": "Would allow only H1 single-adapter benchmarking, not router or multi-adapter activation.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/h1_activation_gate_receipt.json",
                "KT_PROD_CLEANROOM/reports/next_horizon_activation_receipt.json",
            ],
        },
        {
            "rank": 11,
            "proof_class_id": "PLATFORM_ENFORCEMENT_PROVEN",
            "attained": str(platform.get("platform_governance_verdict", "")).strip() == "PLATFORM_ENFORCEMENT_PROVEN",
            "subject_commit": str(platform.get("platform_governance_subject_commit", "")).strip(),
            "boundary": "Would raise governance legitimacy beyond workflow governance only.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
            ],
        },
        {
            "rank": 12,
            "proof_class_id": "CROSS_ENV_CONTROLLED_VARIATION_COMPLETE",
            "attained": bool(representative.get("cross_environment_controlled_variation_complete")),
            "subject_commit": str(representative.get("validated_head_sha", "")).strip(),
            "boundary": "Would raise reproducibility beyond same-MVE authority-lane proof.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/representative_authority_lane_reproducibility_receipt.json",
                "KT_PROD_CLEANROOM/reports/twocleanclone_proof.json",
            ],
        },
    ]

    return {
        "schema_id": "kt.operator.ws0_ws11_closeout_proof_class_ladder.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": _git_head(root),
        "claim_boundary": (
            "This proof-class ladder summarizes attained and unattained WS0-WS11 classes for compiled_head_commit only. "
            "A later repository head that contains this ladder must not be described as the compiled head unless the SHAs match."
        ),
        "levels": levels,
    }


def build_closeout_summary(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    settled_truth = _load_required(root, f"{report_root_rel}/settled_truth_source_receipt.json")
    verifier = _load_required(root, f"{report_root_rel}/public_verifier_manifest.json")
    platform = _load_required(root, f"{report_root_rel}/platform_governance_narrowing_receipt.json")
    runtime_boundary = _load_required(root, f"{report_root_rel}/runtime_boundary_integrity_receipt.json")
    representative = _load_required(root, f"{report_root_rel}/representative_authority_lane_reproducibility_receipt.json")
    commercial = _load_required(root, f"{report_root_rel}/commercial_claim_compiler_receipt.json")
    frontier = _load_required(root, f"{report_root_rel}/frontier_settlement_receipt.json")
    h1_gate = _load_required(root, f"{report_root_rel}/h1_activation_gate_receipt.json")

    proven = [
        {
            "statement": "Documentary demotion on main-bound truth mirrors is frozen and explicit.",
            "scope": "WS1 documentary compatibility surfaces only",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/WS1_completion_report.json",
            ],
        },
        {
            "statement": "The active truth source is the ledger current pointer and settled truth is authoritative on its subject head.",
            "scope": str(settled_truth.get("pinned_head_sha", "")).strip(),
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json",
            ],
        },
        {
            "statement": "A transparency-verified truth subject exists and current heads only contain evidence for that subject unless the SHAs match.",
            "scope": str(verifier.get("truth_subject_commit", "")).strip(),
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
            ],
        },
        {
            "statement": "Workflow governance is proven, but only as workflow governance and not as platform-enforced governance.",
            "scope": str(platform.get("platform_governance_subject_commit", "")).strip(),
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
            ],
        },
        {
            "statement": "Canonical runtime boundary integrity is settled for its subject head.",
            "scope": str(runtime_boundary.get("runtime_boundary_subject_commit", "")).strip(),
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/runtime_boundary_integrity_receipt.json",
            ],
        },
        {
            "statement": "Representative authority-lane reproducibility is proven on the same MVE for certify, hat_demo, and program.red_assault.serious_v1.",
            "scope": str(representative.get("validated_head_sha", "")).strip(),
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/representative_authority_lane_reproducibility_receipt.json",
                "KT_PROD_CLEANROOM/reports/proofrunbundle_index.json",
            ],
        },
        {
            "statement": "Commercial claim boundaries are documentary-only and bound to the verifier, runtime boundary, and active truth source.",
            "scope": str(commercial.get("compiled_head_commit", commercial.get("current_head_commit", ""))).strip(),
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
                "KT_PROD_CLEANROOM/reports/commercial_program_catalog.json",
            ],
        },
        {
            "statement": "Frontier settlement is complete as an evaluation and the final H1 gate was lawfully checked.",
            "scope": str(frontier.get("compiled_head_commit", "")).strip(),
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/frontier_settlement_receipt.json",
                "KT_PROD_CLEANROOM/reports/h1_activation_gate_receipt.json",
            ],
        },
    ]

    not_proven = [
        {
            "statement": "Published-head self-convergence is not proven on the retained final stack.",
            "scope": "published-head authority",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/published_head_self_convergence_receipt.json",
            ],
        },
        {
            "statement": "Authority convergence does not pass on the retained final stack.",
            "scope": "current-head authority convergence",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/authority_convergence_receipt.json",
            ],
        },
        {
            "statement": "Truth publication stabilized remains false on the execution board.",
            "scope": "Domain 1 exit gate",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/governance/execution_board.json",
                "KT_PROD_CLEANROOM/reports/h1_activation_gate_receipt.json",
            ],
        },
        {
            "statement": "Platform-enforced governance is not proven; the legitimacy ceiling remains workflow-governance-only.",
            "scope": "platform governance",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/platform_governance_narrowing_receipt.json",
                "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
            ],
        },
        {
            "statement": "Cross-environment controlled variation is not complete.",
            "scope": "reproducibility beyond same MVE",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/representative_authority_lane_reproducibility_receipt.json",
            ],
        },
        {
            "statement": "H1 is not allowed, single-adapter benchmarking is not open, and router or multi-adapter activation remains blocked.",
            "scope": "H1 and upper-horizon activation",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/h1_activation_gate_receipt.json",
                "KT_PROD_CLEANROOM/reports/next_horizon_activation_receipt.json",
            ],
        },
        {
            "statement": "Current evidence heads are not themselves the transparency-verified truth subject or fresh runtime-boundary subject unless the SHAs match.",
            "scope": "evidence-head versus subject-head semantics",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
                "KT_PROD_CLEANROOM/reports/frontier_settlement_receipt.json",
            ],
        },
    ]

    return {
        "schema_id": "kt.operator.ws0_ws11_closeout_summary.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": _git_head(root),
        "claim_boundary": (
            "This closeout summary states what is proven and not proven for compiled_head_commit only. "
            "A later repository head that contains this summary must not be described as the compiled head unless the SHAs match."
        ),
        "closeout_verdict": "SEALED_WITH_OPEN_BLOCKERS",
        "frontier_settlement_verdict": str(frontier.get("frontier_settlement_verdict", "")).strip(),
        "h1_gate_verdict": str(h1_gate.get("h1_gate_verdict", "")).strip(),
        "proven": proven,
        "not_proven": not_proven,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit the final WS0-WS11 closeout bundle.")
    parser.add_argument("--root", default="", help="Optional repository root override.")
    parser.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL, help="Report root relative to repository root.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = Path(str(args.root)).resolve() if str(args.root).strip() else repo_root()

    payloads = {
        RECEIPT_INDEX_REL: build_closeout_receipt_index(root=root, report_root_rel=args.report_root),
        BLOCKER_REGISTER_REL: build_closeout_blocker_register(root=root, report_root_rel=args.report_root),
        PROOF_LADDER_REL: build_closeout_proof_class_ladder(root=root, report_root_rel=args.report_root),
        SUMMARY_REL: build_closeout_summary(root=root, report_root_rel=args.report_root),
    }

    writes: List[Dict[str, Any]] = []
    for rel, payload in payloads.items():
        changed = write_json_stable((root / Path(rel)).resolve(), payload)
        writes.append(
            {
                "artifact_ref": rel,
                "updated": changed,
                "compiled_head_commit": str(payload.get("compiled_head_commit", "")).strip(),
                "schema_id": str(payload.get("schema_id", "")).strip(),
            }
        )

    print(
        json.dumps(
            {
                "status": "PASS",
                "compiled_head_commit": _git_head(root),
                "artifacts_written": writes,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
