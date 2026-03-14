from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
WORK_ORDER_REL = "KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V2/WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION.v2.json"
STEP7_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_judgment_plane_computation_receipt.json"
STATE_VECTOR_REL = f"{REPORT_ROOT_REL}/kt_state_vector.json"
TAG_CATALOG_REL = f"{REPORT_ROOT_REL}/kt_tag_catalog.json"
CONTRACT_INDEX_REL = f"{REPORT_ROOT_REL}/kt_contract_index.json"
TRUTH_SURFACE_MAP_REL = f"{REPORT_ROOT_REL}/kt_truth_surface_map.json"
HISTORICAL_CLAIMS_REL = f"{REPORT_ROOT_REL}/kt_historical_claims.json"
REOPENED_DEFECTS_REL = f"{REPORT_ROOT_REL}/kt_reopened_defect_register.json"
ORGAN_ONTOLOGY_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_organ_ontology.json"
ORGAN_DEP_MATRIX_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_organ_dependency_matrix.json"
QUALITY_POLICY_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_quality_policy.json"
READINESS_LATTICE_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_readiness_lattice.json"
RELEASE_LAW_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_release_law.json"
TRUST_ZONE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"
PUBLIC_VERIFIER_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
RUNTIME_BOUNDARY_REL = f"{REPORT_ROOT_REL}/runtime_boundary_integrity_receipt.json"
COMMERCIAL_COMPILER_REL = f"{REPORT_ROOT_REL}/commercial_claim_compiler_receipt.json"
REPRODUCIBILITY_REL = f"{REPORT_ROOT_REL}/representative_authority_lane_reproducibility_receipt.json"
FRONTIER_SETTLEMENT_REL = f"{REPORT_ROOT_REL}/frontier_settlement_receipt.json"
H1_GATE_REL = f"{REPORT_ROOT_REL}/h1_activation_gate_receipt.json"
README_REL = "README.md"
REPO_CANON_REL = "REPO_CANON.md"
DOCS_ARCHITECTURE_REL = "docs/KT_ARCHITECTURE.md"
DOCS_RUNBOOK_REL = "docs/RUNBOOK.md"
DOCS_OVERVIEW_REL = "docs/KT_OVERVIEW.md"

CANON_PROPOSAL_REL = f"{REPORT_ROOT_REL}/kt_canon_proposal.json"
CANON_RATIFICATION_LOG_REL = f"{REPORT_ROOT_REL}/kt_canon_ratification_log.json"
NORMALIZATION_WORK_ORDER_REL = f"{REPORT_ROOT_REL}/kt_normalization_work_order.json"
PATH_UNIFICATION_PLAN_REL = f"{REPORT_ROOT_REL}/kt_path_unification_plan.json"
SCHEMA_UNIFICATION_PLAN_REL = f"{REPORT_ROOT_REL}/kt_schema_unification_plan.json"
GENERATED_ARTIFACT_POLICY_REL = f"{REPORT_ROOT_REL}/kt_generated_artifact_policy.json"
DEPRECATION_PLAN_REL = f"{REPORT_ROOT_REL}/kt_deprecation_plan.json"
REPO_PROFESSIONALIZATION_PLAN_REL = f"{REPORT_ROOT_REL}/kt_repo_professionalization_plan.json"
REPO_STYLE_GUIDE_REL = f"{REPORT_ROOT_REL}/kt_repo_style_guide.json"
DOCS_TOPOLOGY_REL = f"{REPORT_ROOT_REL}/kt_docs_topology.json"
RELEASE_PROFILE_REL = f"{REPORT_ROOT_REL}/kt_release_profile.json"
SUBMISSION_PROFILE_REL = f"{REPORT_ROOT_REL}/kt_submission_profile.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_normalization_and_professionalization_planning_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/canon_normalization_plan_compile.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_canon_normalization_plan_compile.py"

DELIVERABLE_REFS = [
    CANON_PROPOSAL_REL,
    CANON_RATIFICATION_LOG_REL,
    NORMALIZATION_WORK_ORDER_REL,
    PATH_UNIFICATION_PLAN_REL,
    SCHEMA_UNIFICATION_PLAN_REL,
    GENERATED_ARTIFACT_POLICY_REL,
    DEPRECATION_PLAN_REL,
    REPO_PROFESSIONALIZATION_PLAN_REL,
    REPO_STYLE_GUIDE_REL,
    DOCS_TOPOLOGY_REL,
    RELEASE_PROFILE_REL,
    SUBMISSION_PROFILE_REL,
]
SUBJECT_ARTIFACT_REFS = DELIVERABLE_REFS + [TOOL_REL, TEST_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

WORK_ORDER_ID = "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION"
WORK_ORDER_SCHEMA_ID = "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2"

PROTECTED_PREFIXES = (
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "kt_truth_ledger:",
    ".github/workflows/",
)

ROOT_ALLOWED_KEEP = {
    ".devcontainer",
    ".gitattributes",
    ".github",
    ".gitignore",
    ".vscode",
    "LICENSE",
    "README.md",
    "REPO_CANON.md",
    "KT-Codex",
    "KT_PROD_CLEANROOM",
    "docs",
    "run_kt_e2e.sh",
}
ROOT_IGNORE = {".git"}

MAJOR_FUNCTION_IDS = [
    "control_packets",
    "foundation_pack",
    "constitutional_spine",
    "governance_law",
    "runtime_kernel",
    "generated_reports_and_receipts",
    "operator_compilers",
    "verification_delivery_security",
    "growth_and_crucible_memory",
    "lab_adaptation_and_training",
    "public_docs",
    "commercial_docs",
    "archive_memory",
    "codex_lineage",
    "release_and_submission_profiles",
]

WORK_PACKAGE_IDS = [
    "WP_STEP8_ROOT_AND_ARCHIVE_BOUNDARY",
    "WP_STEP8_DOCS_TOPOLOGY_RATIONALIZATION",
    "WP_STEP8_SCHEMA_HOUSING_AND_NAMING",
    "WP_STEP8_GENERATED_ARTIFACT_BOUNDARY",
    "WP_STEP8_RELEASE_AND_SUBMISSION_LAYOUT",
    "WP_STEP8_CODEX_AND_LINEAGE_BOUNDARY",
]

DOC_LAYER_IDS = [
    "root_orientation",
    "public_manual_docs",
    "operator_internal_docs",
    "commercial_docs",
    "generated_doctrine_target",
    "audit_archive_target",
    "codex_lineage_docs",
]

RELEASE_PROFILE_IDS = [
    "internal_operator_audit_release",
    "external_specialist_demo_release",
    "governed_partner_review_release",
    "competition_release",
    "publication_release",
]

SUBMISSION_PROFILE_IDS = [
    "auditor_packet",
    "specialist_demo_packet",
    "partner_review_packet",
    "competition_bundle",
    "publication_peer_review_bundle",
]


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_parent(root: Path, commit: str) -> str:
    if not str(commit).strip():
        return ""
    try:
        return _git(root, "rev-parse", f"{commit}^")
    except Exception:  # noqa: BLE001
        return ""


def _git_diff_files(root: Path, older: str, newer: str, paths: Sequence[str]) -> List[str]:
    if not older or not newer:
        return []
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "diff", "--name-only", older, newer, "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _git_last_commit_for_paths(root: Path, paths: Sequence[str]) -> str:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return ""
    try:
        return _git(root, "log", "-1", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return ""


def _normalize_ref(ref: str) -> str:
    return str(ref).replace("\\", "/").strip()


def _is_protected(path: str) -> bool:
    normalized = _normalize_ref(path)
    return any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _existing_root_entries(root: Path) -> List[str]:
    entries = []
    for path in sorted(root.iterdir(), key=lambda item: item.name.lower()):
        if path.name in ROOT_IGNORE:
            continue
        entries.append(path.name)
    return entries


def _root_noise(entries: Sequence[str]) -> List[str]:
    return [entry for entry in entries if entry not in ROOT_ALLOWED_KEEP]


def _trust_zone_counts(ctx: Dict[str, Any]) -> Dict[str, int]:
    facet_counts = ctx["tag_catalog"].get("facet_counts", {})
    return {
        "ARCHIVE": int(facet_counts.get("trust_zone:ARCHIVE", 0)),
        "CANONICAL": int(facet_counts.get("trust_zone:CANONICAL", 0)),
        "COMMERCIAL": int(facet_counts.get("trust_zone:COMMERCIAL", 0)),
        "GENERATED_RUNTIME_TRUTH": int(facet_counts.get("trust_zone:GENERATED_RUNTIME_TRUTH", 0)),
        "LAB": int(facet_counts.get("trust_zone:LAB", 0)),
        "QUARANTINED": int(facet_counts.get("trust_zone:QUARANTINED", 0)),
    }


def _quality_levels(ctx: Dict[str, Any]) -> Dict[str, str]:
    return {row["organ_id"]: row["quality_level"] for row in ctx["state_vector"].get("organ_readiness", []) if isinstance(row, dict)}


def _step_context(root: Path) -> Dict[str, Any]:
    step7 = _load_required(root, STEP7_RECEIPT_REL)
    if str(step7.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 8 is blocked until the Step 7 judgment-plane receipt is PASS.")

    return {
        "work_order": _load_required(root, WORK_ORDER_REL),
        "step7_receipt": step7,
        "state_vector": _load_required(root, STATE_VECTOR_REL),
        "tag_catalog": _load_required(root, TAG_CATALOG_REL),
        "contract_index": _load_required(root, CONTRACT_INDEX_REL),
        "truth_surface_map": _load_required(root, TRUTH_SURFACE_MAP_REL),
        "historical_claims": _load_required(root, HISTORICAL_CLAIMS_REL),
        "reopened_defects": _load_required(root, REOPENED_DEFECTS_REL),
        "organ_ontology": _load_required(root, ORGAN_ONTOLOGY_REL),
        "organ_dependency_matrix": _load_required(root, ORGAN_DEP_MATRIX_REL),
        "quality_policy": _load_required(root, QUALITY_POLICY_REL),
        "readiness_lattice": _load_required(root, READINESS_LATTICE_REL),
        "release_law": _load_required(root, RELEASE_LAW_REL),
        "trust_zone_registry": _load_required(root, TRUST_ZONE_REGISTRY_REL),
        "public_verifier": _load_required(root, PUBLIC_VERIFIER_REL),
        "runtime_boundary": _load_required(root, RUNTIME_BOUNDARY_REL),
        "commercial_compiler": _load_required(root, COMMERCIAL_COMPILER_REL),
        "reproducibility": _load_required(root, REPRODUCIBILITY_REL),
        "frontier_settlement": _load_required(root, FRONTIER_SETTLEMENT_REL),
        "h1_gate": _load_required(root, H1_GATE_REL),
        "root_entries": _existing_root_entries(root),
        "step7_evidence_commit": _git_last_commit_for_paths(root, [STEP7_RECEIPT_REL]),
    }


def _function_row(
    *,
    major_function_id: str,
    label: str,
    canonical_root: str,
    current_status: str,
    supporting_roots: Sequence[str],
    competing_roots: Sequence[str],
    proposed_actions: Sequence[str],
    evidence_refs: Sequence[str],
) -> Dict[str, Any]:
    return {
        "major_function_id": major_function_id,
        "label": label,
        "canonical_root": canonical_root,
        "current_status": current_status,
        "supporting_roots": list(supporting_roots),
        "competing_or_adjacent_roots": list(competing_roots),
        "proposed_actions": list(proposed_actions),
        "ratification_required": True,
        "evidence_refs": list(evidence_refs),
    }


def _build_canon_proposal(ctx: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    state_vector = ctx["state_vector"]
    root_entries = ctx["root_entries"]
    rows = [
        _function_row(
            major_function_id="control_packets",
            label="Control Packets",
            canonical_root="KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/",
            current_status="ALREADY_EFFECTIVE_KEEP",
            supporting_roots=["KT_PROD_CLEANROOM/AUDITS/"],
            competing_roots=["work_order.json"],
            proposed_actions=["keep_canonical_packet_root", "demote_root_work_orders_to_archive"],
            evidence_refs=[WORK_ORDER_REL, STEP7_RECEIPT_REL],
        ),
        _function_row(
            major_function_id="foundation_pack",
            label="Foundation Pack",
            canonical_root="KT_PROD_CLEANROOM/governance/foundation_pack/",
            current_status="ALREADY_EFFECTIVE_KEEP",
            supporting_roots=["KT_PROD_CLEANROOM/governance/"],
            competing_roots=[],
            proposed_actions=["keep_ratified_foundation_root", "forbid_duplicate_foundation_schemas_elsewhere"],
            evidence_refs=[ORGAN_ONTOLOGY_REL, RELEASE_LAW_REL],
        ),
        _function_row(
            major_function_id="constitutional_spine",
            label="Constitutional Spine",
            canonical_root="KT_PROD_CLEANROOM/governance/constitutional_spine/",
            current_status="ALREADY_EFFECTIVE_KEEP",
            supporting_roots=["KT_PROD_CLEANROOM/governance/"],
            competing_roots=[],
            proposed_actions=["keep_meta_governance_under_constitutional_spine", "treat_generated_doctrine_as_derivative_not_law"],
            evidence_refs=[ORGAN_DEP_MATRIX_REL, QUALITY_POLICY_REL],
        ),
        _function_row(
            major_function_id="governance_law",
            label="Governance Law",
            canonical_root="KT_PROD_CLEANROOM/governance/",
            current_status="ALREADY_EFFECTIVE_KEEP_WITH_SCOPE_BOUNDARY",
            supporting_roots=["KT_PROD_CLEANROOM/governance/platform/", "KT_PROD_CLEANROOM/governance/signers/"],
            competing_roots=["docs/audit/**", "KT-Codex/**"],
            proposed_actions=["keep_live_law_in_governance_root", "demote_historical_and_codex_lawlike_surfaces_to_lineage_only"],
            evidence_refs=[TRUST_ZONE_REGISTRY_REL, CONTRACT_INDEX_REL],
        ),
        _function_row(
            major_function_id="runtime_kernel",
            label="Runtime Kernel",
            canonical_root="KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
            current_status="ALREADY_EFFECTIVE_KEEP_SEALED",
            supporting_roots=["KT_PROD_CLEANROOM/05_QUARANTINE/"],
            competing_roots=["KT_TEMPLE_ROOT/"],
            proposed_actions=["keep_single_runtime_root", "archive_legacy_runtime_strata_outside_kernel"],
            evidence_refs=[RUNTIME_BOUNDARY_REL, DOCS_ARCHITECTURE_REL],
        ),
        _function_row(
            major_function_id="generated_reports_and_receipts",
            label="Generated Reports and Receipts",
            canonical_root="KT_PROD_CLEANROOM/reports/",
            current_status="ALREADY_EFFECTIVE_KEEP_WITH_SCHEMA_HOUSING_GAP",
            supporting_roots=["KT_PROD_CLEANROOM/exports/_truth/current/"],
            competing_roots=["KT_PROD_CLEANROOM/exports/_runs/", "tmp/"],
            proposed_actions=["keep_committed_governed_reports_in_reports_root", "separate_report_schemas_into_dedicated_subroot"],
            evidence_refs=[TRUTH_SURFACE_MAP_REL, CONTRACT_INDEX_REL, PUBLIC_VERIFIER_REL],
        ),
        _function_row(
            major_function_id="operator_compilers",
            label="Operator Compilers",
            canonical_root="KT_PROD_CLEANROOM/tools/operator/",
            current_status="ALREADY_EFFECTIVE_KEEP",
            supporting_roots=["KT_PROD_CLEANROOM/tests/operator/"],
            competing_roots=[],
            proposed_actions=["keep_operator_compilers_under_single_root", "bind_every_operator_compiler_to_receipt_and_test"],
            evidence_refs=[STEP7_RECEIPT_REL, STATE_VECTOR_REL],
        ),
        _function_row(
            major_function_id="verification_delivery_security",
            label="Verification Delivery Security",
            canonical_root="KT_PROD_CLEANROOM/tools/verification/",
            current_status="ALREADY_EFFECTIVE_KEEP_WITH_SUBROOT_SPLIT",
            supporting_roots=["KT_PROD_CLEANROOM/tools/delivery/", "KT_PROD_CLEANROOM/tools/security/"],
            competing_roots=[],
            proposed_actions=["keep_integrity_tooling_outside_runtime_root", "preserve_cross_surface_attestation_boundary"],
            evidence_refs=[CONTRACT_INDEX_REL, PUBLIC_VERIFIER_REL],
        ),
        _function_row(
            major_function_id="growth_and_crucible_memory",
            label="Growth and Crucible Memory",
            canonical_root="KT_PROD_CLEANROOM/tools/growth/",
            current_status="ALREADY_EFFECTIVE_KEEP_WITH_LINEAGE_FORMALIZATION_PENDING",
            supporting_roots=["KT_PROD_CLEANROOM/governance/"],
            competing_roots=["KAGGLE_MRT1_E2E_FINAL.sh", "run_epoch_escalation.py"],
            proposed_actions=["keep_growth_memory_under_tools_growth", "absorb_root_growth_scripts_into_archive_or_runbooks"],
            evidence_refs=[HISTORICAL_CLAIMS_REL, REPRODUCIBILITY_REL],
        ),
        _function_row(
            major_function_id="lab_adaptation_and_training",
            label="Lab Adaptation and Training",
            canonical_root="KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/",
            current_status="ALREADY_EFFECTIVE_KEEP_WITH_PROMOTION_BOUNDARY",
            supporting_roots=["KT_PROD_CLEANROOM/tools/training/", "KT_PROD_CLEANROOM/tools/router/"],
            competing_roots=["KT_LANE_LORA_PHASE_B/"],
            proposed_actions=["keep_lab_adaptation_separate_from_canonical_runtime", "archive_legacy_lab_roots_and_leave_promotion_law_explicit"],
            evidence_refs=[ORGAN_ONTOLOGY_REL, STATE_VECTOR_REL],
        ),
        _function_row(
            major_function_id="public_docs",
            label="Public Docs",
            canonical_root="docs/",
            current_status="ALREADY_EFFECTIVE_KEEP_WITH_ARCHIVE_SPLIT_PENDING",
            supporting_roots=["README.md", "REPO_CANON.md"],
            competing_roots=["docs/audit/**", "RUN_REPORT.md", "runbook.txt"],
            proposed_actions=["keep_human_public_docs_under_docs_root", "reduce_root_docs_to_orientation_only", "move_audit_history_under_archive_root"],
            evidence_refs=[README_REL, REPO_CANON_REL, DOCS_OVERVIEW_REL, DOCS_RUNBOOK_REL],
        ),
        _function_row(
            major_function_id="commercial_docs",
            label="Commercial Docs",
            canonical_root="KT_PROD_CLEANROOM/docs/commercial/",
            current_status="ALREADY_EFFECTIVE_KEEP_FROZEN_BY_CLAIM_COMPILER",
            supporting_roots=["docs/"],
            competing_roots=["KT-Codex/Volume-II-Business/"],
            proposed_actions=["keep_commercial_surfaces_bound_to_claim_compiler", "demote_business_drafts_to_codex_lineage"],
            evidence_refs=[COMMERCIAL_COMPILER_REL, STATE_VECTOR_REL],
        ),
        _function_row(
            major_function_id="archive_memory",
            label="Archive Memory",
            canonical_root="KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/",
            current_status="TARGET_ROOT_EFFECTIVE_BUT_UNDERUSED",
            supporting_roots=["docs/audit/"],
            competing_roots=["KT_TEMPLE_ROOT/", "KT_LANE_LORA_PHASE_B/", "EPOCH_GOV.json", "EPOCH_CROSS.json", "EPOCH_PARADOX.json"],
            proposed_actions=["consolidate_legacy_material_into_archive_vault", "treat_root_archive_sprawl_as_migration_target_not_live_surface"],
            evidence_refs=[REOPENED_DEFECTS_REL, HISTORICAL_CLAIMS_REL],
        ),
        _function_row(
            major_function_id="codex_lineage",
            label="Codex Lineage",
            canonical_root="KT-Codex/",
            current_status="KEEP_AS_LINEAGE_ONLY_NOT_ACTIVE_LAW",
            supporting_roots=[],
            competing_roots=["docs/", "KT_PROD_CLEANROOM/governance/"],
            proposed_actions=["keep_codex_as_draft_lineage_root", "forbid_codex_from_silently_becoming_canon_without_ratification"],
            evidence_refs=[HISTORICAL_CLAIMS_REL, TAG_CATALOG_REL],
        ),
        _function_row(
            major_function_id="release_and_submission_profiles",
            label="Release and Submission Profiles",
            canonical_root="docs/generated/profiles/",
            current_status="TARGET_ROOT_NOT_YET_CREATED",
            supporting_roots=["KT_PROD_CLEANROOM/reports/", "docs/"],
            competing_roots=["README.md", "KT-Codex/"],
            proposed_actions=["create_machine_state_derived_profile_root", "keep_release_and_submission_packets_out_of_root_clutter"],
            evidence_refs=[STATE_VECTOR_REL, RELEASE_LAW_REL, QUALITY_POLICY_REL],
        ),
    ]
    ids = [row["major_function_id"] for row in rows]
    if ids != MAJOR_FUNCTION_IDS:
        raise RuntimeError("FAIL_CLOSED: major function proposal set drifted.")
    return {
        "schema_id": "kt.operator.canon_proposal.v1",
        "generated_utc": generated_utc,
        "proposal_status": "PROPOSED_UNRATIFIED",
        "proposal_only": True,
        "source_step7_compiled_head_commit": str(ctx["step7_receipt"].get("compiled_head_commit", "")).strip(),
        "source_step7_evidence_commit": str(ctx["step7_evidence_commit"]).strip(),
        "claim_ceiling_status": dict(state_vector.get("claim_ceiling_status", {})),
        "open_blockers": list(state_vector.get("open_blockers", [])),
        "repo_topology_observations": {
            "root_entry_count": len(root_entries),
            "root_noise_count": len(_root_noise(root_entries)),
            "root_noise_entries": _root_noise(root_entries),
            "trust_zone_counts": _trust_zone_counts(ctx),
            "contract_count": int(((ctx["contract_index"].get("summary") or {}).get("contract_count", 0))),
            "truth_surface_count": int(((ctx["truth_surface_map"].get("summary") or {}).get("surface_count", 0))),
            "historical_source_family_count": len(ctx["historical_claims"].get("source_families", [])),
        },
        "major_function_proposals": rows,
        "claim_boundary": (
            "This Step 8 canon proposal is proposal-only. It identifies target canonical roots and migration directions, "
            "but it does not ratify canon and does not authorize structural mutation of the repository."
        ),
    }


def _build_canon_ratification_log(canon_proposal: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    entries = []
    for row in canon_proposal.get("major_function_proposals", []):
        entries.append(
            {
                "major_function_id": row["major_function_id"],
                "canonical_root": row["canonical_root"],
                "proposal_status": "PENDING_RATIFICATION",
                "current_effect": "NONE_PROPOSAL_ONLY",
                "ratification_required": True,
                "ratification_gate": "EXPLICIT_POST_STEP8_APPROVAL_AND_FUTURE_EXECUTION_WORK_ORDER",
                "notes": "Step 8 may propose canon. It may not ratify canon.",
            }
        )
    return {
        "schema_id": "kt.operator.canon_ratification_log.v1",
        "generated_utc": generated_utc,
        "proposal_ref": CANON_PROPOSAL_REL,
        "ratification_status": "UNRATIFIED_PROPOSAL_ONLY",
        "entries": entries,
        "claim_boundary": "This log records pending canon proposals only. No entry in this file changes active canon until explicitly ratified later.",
    }


def _work_package(
    *,
    package_id: str,
    title: str,
    objective: str,
    target_paths: Sequence[str],
    migration_tests: Sequence[str],
    rollback_plan: Sequence[str],
    blocked_by: Sequence[str],
    evidence_refs: Sequence[str],
) -> Dict[str, Any]:
    return {
        "package_id": package_id,
        "title": title,
        "objective": objective,
        "target_paths": list(target_paths),
        "migration_tests": list(migration_tests),
        "rollback_plan": list(rollback_plan),
        "blocked_by": list(blocked_by),
        "evidence_refs": list(evidence_refs),
    }


def _build_normalization_work_order(ctx: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    root_noise = _root_noise(ctx["root_entries"])
    packages = [
        _work_package(
            package_id="WP_STEP8_ROOT_AND_ARCHIVE_BOUNDARY",
            title="Root and Archive Boundary",
            objective="Move legacy root clutter and historical audit material into the archive vault while preserving lineage references.",
            target_paths=["docs/audit/**", "KT_TEMPLE_ROOT/**", "KT_LANE_LORA_PHASE_B/**", "EPOCH_*.json", "OPERATION_A_*", "RUN_REPORT.md", "runbook.txt", "work_order.json"],
            migration_tests=[
                "verify every migrated path resolves from an archive index or redirect manifest",
                "verify no runtime, governance, or public claim surface path changes without explicit path-map receipts",
                "verify root noise count strictly decreases and allowed root keep set remains intact",
            ],
            rollback_plan=[
                "restore the original root paths from the migration manifest",
                "revert archive-vault additions and redirect files in one atomic rollback commit",
            ],
            blocked_by=["ROOT_ARCHIVE_CONTAMINATION"],
            evidence_refs=[REOPENED_DEFECTS_REL, HISTORICAL_CLAIMS_REL],
        ),
        _work_package(
            package_id="WP_STEP8_DOCS_TOPOLOGY_RATIONALIZATION",
            title="Docs Topology Rationalization",
            objective="Separate public manuals, operator docs, commercial docs, generated doctrine, and archived audits into stable lanes.",
            target_paths=["README.md", "docs/**", "KT_PROD_CLEANROOM/docs/**", "KT-Codex/**"],
            migration_tests=[
                "verify root README stays orientation-only and points into canonical docs lanes",
                "verify every moved doc retains explicit audience and claim-boundary markers",
                "verify docs link graph resolves without depending on deprecated root files",
            ],
            rollback_plan=[
                "restore prior docs paths from the docs topology manifest",
                "remove generated redirects and restore previous cross-links",
            ],
            blocked_by=[],
            evidence_refs=[README_REL, DOCS_TOPOLOGY_REL, REPO_CANON_REL],
        ),
        _work_package(
            package_id="WP_STEP8_SCHEMA_HOUSING_AND_NAMING",
            title="Schema Housing and Naming",
            objective="Unify schema homes so runtime, foundation, report, codex, and archive schemas stop competing for the same semantic role.",
            target_paths=[
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/**",
                "KT_PROD_CLEANROOM/governance/foundation_pack/**",
                "KT_PROD_CLEANROOM/reports/*.schema.json",
                "KT-Codex/schemas/**",
                "run_manifest.schema.json",
            ],
            migration_tests=[
                "verify every schema has exactly one declared canonical home and versioned filename",
                "verify report schemas are physically separated from live report instances",
                "verify no schema move changes a schema_id without an explicit supersession note",
            ],
            rollback_plan=[
                "restore original schema locations from the schema move ledger",
                "repoint schema indexes to their pre-migration paths and rerun validators",
            ],
            blocked_by=[],
            evidence_refs=[CONTRACT_INDEX_REL, SCHEMA_UNIFICATION_PLAN_REL],
        ),
        _work_package(
            package_id="WP_STEP8_GENERATED_ARTIFACT_BOUNDARY",
            title="Generated Artifact Boundary",
            objective="Clarify what may be committed, what is documentary-only, what is lineage-only, and what must remain local or ephemeral.",
            target_paths=["KT_PROD_CLEANROOM/reports/**", "KT_PROD_CLEANROOM/exports/**", "KT_PROD_CLEANROOM/tools/growth/ledgers/**", "tmp/**", ".env.secret"],
            migration_tests=[
                "verify committed generated artifacts all carry schema_id, generated_utc, and evidence refs",
                "verify documentary mirrors remain non-authoritative after any rehouse",
                "verify local secret-like residue is removed from canonical root scope",
            ],
            rollback_plan=[
                "restore prior artifact roots and reapply the previous gitignore/local-only rules",
                "revert any artifact-class registry updates in one rollback commit",
            ],
            blocked_by=["LOCAL_RESIDUE_PRESENT"],
            evidence_refs=[TRUTH_SURFACE_MAP_REL, REOPENED_DEFECTS_REL],
        ),
        _work_package(
            package_id="WP_STEP8_RELEASE_AND_SUBMISSION_LAYOUT",
            title="Release and Submission Layout",
            objective="Create profile-specific release and submission bundle layouts that cannot overread current proof ceilings.",
            target_paths=["docs/generated/profiles/**", "KT_PROD_CLEANROOM/reports/**", "docs/**"],
            migration_tests=[
                "verify every bundle profile lists allowed and forbidden claims",
                "verify no release bundle claims H1, platform enforcement, or fresh HEAD truth verification while blockers remain open",
                "verify included artifacts are limited to each profile's declared scope",
            ],
            rollback_plan=[
                "remove generated profile roots and restore previous release notes or bundle manifests",
                "revert profile index changes and re-run profile validators",
            ],
            blocked_by=["H1_ACTIVATION_GATE_CLOSED", "PLATFORM_ENFORCEMENT_UNPROVEN"],
            evidence_refs=[RELEASE_PROFILE_REL, SUBMISSION_PROFILE_REL, STATE_VECTOR_REL],
        ),
        _work_package(
            package_id="WP_STEP8_CODEX_AND_LINEAGE_BOUNDARY",
            title="Codex and Lineage Boundary",
            objective="Keep KT-Codex available as historical/draft lineage without letting it silently compete with ratified law or public manuals.",
            target_paths=["KT-Codex/**", "docs/**", "KT_PROD_CLEANROOM/governance/**"],
            migration_tests=[
                "verify codex surfaces are labeled lineage-only in all indexes",
                "verify no public or governance index points to codex as current law",
                "verify codex cross-links into public docs are explicitly marked draft lineage",
            ],
            rollback_plan=[
                "restore prior codex references and labels from the codex boundary manifest",
                "revert docs/governance cross-reference updates in one rollback commit",
            ],
            blocked_by=[],
            evidence_refs=[HISTORICAL_CLAIMS_REL, TAG_CATALOG_REL],
        ),
    ]
    if [row["package_id"] for row in packages] != WORK_PACKAGE_IDS:
        raise RuntimeError("FAIL_CLOSED: Step 8 work-package set drifted.")
    return {
        "schema_id": "kt.operator.normalization_work_order.v1",
        "generated_utc": generated_utc,
        "work_order_status": "PROPOSED_UNRATIFIED",
        "proposal_only": True,
        "root_noise_entries": root_noise,
        "work_packages": packages,
        "claim_boundary": (
            "This work order schedules future normalization only. It does not authorize execution until a later explicit approval and "
            "must remain reversible with migration tests and rollback plans for every package."
        ),
    }


def _build_path_unification_plan(ctx: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    groups = [
        {
            "group_id": "root_orientation_keep",
            "current_surfaces": ["README.md", "LICENSE", "REPO_CANON.md", "run_kt_e2e.sh", ".github/**", ".devcontainer/**"],
            "canonical_target_root": "ROOT_KEEP_SET",
            "disposition": "KEEP_MINIMAL_ROOT_ORIENTATION",
            "evidence_refs": [README_REL, REPO_CANON_REL],
        },
        {
            "group_id": "audit_archive_migration",
            "current_surfaces": ["docs/audit/**"],
            "canonical_target_root": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/docs_audit/",
            "disposition": "MIGRATE_TO_ARCHIVE_ROOT",
            "evidence_refs": [REOPENED_DEFECTS_REL, HISTORICAL_CLAIMS_REL],
        },
        {
            "group_id": "legacy_runtime_archive_migration",
            "current_surfaces": ["KT_TEMPLE_ROOT/**", "KT_LANE_LORA_PHASE_B/**"],
            "canonical_target_root": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/legacy_runtime/",
            "disposition": "MIGRATE_TO_ARCHIVE_ROOT",
            "evidence_refs": [REOPENED_DEFECTS_REL],
        },
        {
            "group_id": "root_legacy_operations_archive",
            "current_surfaces": ["EPOCH_CROSS.json", "EPOCH_GOV.json", "EPOCH_PARADOX.json", "OPERATION_A_*", "RUN_REPORT.md", "acceptance_checklist.txt", "runbook.txt", "work_order.json"],
            "canonical_target_root": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/root_legacy/",
            "disposition": "MIGRATE_TO_ARCHIVE_ROOT",
            "evidence_refs": [REOPENED_DEFECTS_REL, HISTORICAL_CLAIMS_REL],
        },
        {
            "group_id": "generated_truth_keep",
            "current_surfaces": ["KT_PROD_CLEANROOM/reports/**", "KT_PROD_CLEANROOM/exports/_truth/current/**"],
            "canonical_target_root": "KT_PROD_CLEANROOM/reports/",
            "disposition": "KEEP_GENERATED_REPORTS_WITH_DOCUMENTARY_MIRRORS_SEPARATE",
            "evidence_refs": [TRUTH_SURFACE_MAP_REL, PUBLIC_VERIFIER_REL],
        },
        {
            "group_id": "local_secret_ejection",
            "current_surfaces": [".env.secret"],
            "canonical_target_root": "LOCAL_UNTRACKED_SECRET_STORE",
            "disposition": "EJECT_FROM_REPO_SURFACE",
            "evidence_refs": [REOPENED_DEFECTS_REL],
        },
        {
            "group_id": "future_profiles_root",
            "current_surfaces": ["docs/**", "KT_PROD_CLEANROOM/reports/**"],
            "canonical_target_root": "docs/generated/profiles/",
            "disposition": "CREATE_FUTURE_MACHINE_DERIVED_PROFILE_ROOT",
            "evidence_refs": [STATE_VECTOR_REL, RELEASE_LAW_REL],
        },
    ]
    return {
        "schema_id": "kt.operator.path_unification_plan.v1",
        "generated_utc": generated_utc,
        "proposal_status": "PROPOSED_UNRATIFIED",
        "root_keep_set": sorted(ROOT_ALLOWED_KEEP),
        "current_root_entries": list(ctx["root_entries"]),
        "current_root_noise_entries": _root_noise(ctx["root_entries"]),
        "path_groups": groups,
        "claim_boundary": "This plan proposes future path moves only. No path listed here changes active canon until a later migration work order is executed and ratified.",
    }


def _build_schema_unification_plan(ctx: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    schema_families = [
        {
            "family_id": "runtime_execution_schemas",
            "canonical_root": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/",
            "status": "KEEP_CURRENT_CANONICAL_HOME",
            "scope": "runtime contracts and execution schemas",
            "evidence_refs": [CONTRACT_INDEX_REL, RUNTIME_BOUNDARY_REL],
        },
        {
            "family_id": "foundation_and_meta_schemas",
            "canonical_root": "KT_PROD_CLEANROOM/governance/foundation_pack/",
            "status": "KEEP_CURRENT_CANONICAL_HOME",
            "scope": "foundation pack schemas and cross-step compiler base schemas",
            "evidence_refs": [ORGAN_ONTOLOGY_REL, RELEASE_LAW_REL],
        },
        {
            "family_id": "generated_report_schemas",
            "canonical_root": "KT_PROD_CLEANROOM/reports/schemas/",
            "status": "TARGET_HOME_NOT_YET_CREATED",
            "scope": "schemas that currently sit beside live generated reports",
            "evidence_refs": [CONTRACT_INDEX_REL],
        },
        {
            "family_id": "codex_lineage_schemas",
            "canonical_root": "KT-Codex/schemas/",
            "status": "KEEP_AS_LINEAGE_ONLY",
            "scope": "codex-side lineage or external-draft schemas",
            "evidence_refs": [HISTORICAL_CLAIMS_REL, TAG_CATALOG_REL],
        },
        {
            "family_id": "archive_legacy_schemas",
            "canonical_root": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/schemas/",
            "status": "TARGET_HOME_NOT_YET_CREATED",
            "scope": "root-level or deprecated legacy schemas retained only for lineage",
            "evidence_refs": [REOPENED_DEFECTS_REL, CONTRACT_INDEX_REL],
        },
    ]
    return {
        "schema_id": "kt.operator.schema_unification_plan.v1",
        "generated_utc": generated_utc,
        "proposal_status": "PROPOSED_UNRATIFIED",
        "current_contract_summary": dict(ctx["contract_index"].get("summary", {})),
        "schema_families": schema_families,
        "normalization_rules": [
            "one canonical home per schema family",
            "schema and instance surfaces must remain physically separable where feasible",
            "generated report schemas must not remain co-mingled with live reports once migrated",
            "root-level active schemas are forbidden after normalization; remaining root schemas become archive lineage only",
            "schema_id version bumps require explicit temporal supersession notes",
        ],
        "concrete_migration_candidates": [
            {
                "current_path": "KT_PROD_CLEANROOM/reports/WS1_completion_report.schema.json",
                "proposed_path": "KT_PROD_CLEANROOM/reports/schemas/WS1_completion_report.schema.json",
            },
            {
                "current_path": "KT_PROD_CLEANROOM/reports/supporting_law_touch_exception_receipt.schema.json",
                "proposed_path": "KT_PROD_CLEANROOM/reports/schemas/supporting_law_touch_exception_receipt.schema.json",
            },
            {
                "current_path": "run_manifest.schema.json",
                "proposed_path": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/schemas/run_manifest.schema.json",
            },
        ],
        "claim_boundary": "This schema plan proposes housing and naming rules only. It does not move any schema surface yet.",
    }


def _build_generated_artifact_policy(*, generated_utc: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.generated_artifact_policy.v1",
        "generated_utc": generated_utc,
        "policy_status": "PROPOSED_UNRATIFIED",
        "artifact_classes": [
            {
                "artifact_class_id": "ratified_authored_law",
                "canonical_roots": ["KT_PROD_CLEANROOM/governance/", "KT_PROD_CLEANROOM/governance/foundation_pack/", "KT_PROD_CLEANROOM/governance/constitutional_spine/"],
                "law_effect": "ACTIVE_WHEN_RATIFIED",
                "commit_policy": "COMMITTED_AUTHORED",
            },
            {
                "artifact_class_id": "governed_generated_reports",
                "canonical_roots": ["KT_PROD_CLEANROOM/reports/"],
                "law_effect": "EVIDENCE_ONLY_UNLESS_RATIFIED_ELSEWHERE",
                "commit_policy": "COMMITTED_IF_DETERMINISTIC_AND_SCHEMA_BOUND",
            },
            {
                "artifact_class_id": "documentary_mirrors",
                "canonical_roots": ["KT_PROD_CLEANROOM/exports/_truth/current/"],
                "law_effect": "DOCUMENTARY_ONLY_NON_AUTHORITATIVE",
                "commit_policy": "COMMITTED_ONLY_FOR_DECLARED_MIRRORS",
            },
            {
                "artifact_class_id": "committed_lineage_ledgers",
                "canonical_roots": ["KT_PROD_CLEANROOM/tools/growth/ledgers/"],
                "law_effect": "LINEAGE_ONLY_UNLESS_PROMOTED_BY_GOVERNED_RULES",
                "commit_policy": "COMMITTED_ONLY_WHEN_REFERENCED_BY_REGISTRY_OR_RECEIPT",
            },
            {
                "artifact_class_id": "ephemeral_operator_runs",
                "canonical_roots": ["KT_PROD_CLEANROOM/exports/_runs/", "tmp/", ".pytest_cache/", "__pycache__/"],
                "law_effect": "NONE",
                "commit_policy": "LOCAL_OR_EPHEMERAL_ONLY",
            },
            {
                "artifact_class_id": "generated_doctrine_and_profiles",
                "canonical_roots": ["docs/generated/"],
                "law_effect": "PUBLIC_DERIVATIVE_ONLY_UNTIL_RATIFIED",
                "commit_policy": "COMMITTED_ONLY_AFTER_MACHINE_STATE_GENERATION_AND_RATIFICATION_LOG",
            },
            {
                "artifact_class_id": "local_secret_residue",
                "canonical_roots": [".env.secret"],
                "law_effect": "FORBIDDEN",
                "commit_policy": "MUST_NOT_EXIST_IN_REPO_ROOT",
            },
        ],
        "forbidden_outcomes": [
            "generated doctrine becoming law without ratification",
            "documentary mirrors treated as active authority",
            "ephemeral operator runs committed as canonical evidence without schema-bound receipts",
            "secret-like residue remaining at repo root",
        ],
        "claim_boundary": "Generated artifacts may support evidence chains, but they do not become law or fresh authority claims by being generated alone.",
    }


def _build_deprecation_plan(ctx: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    defects = {row["defect_id"]: row for row in ctx["reopened_defects"].get("defects", []) if isinstance(row, dict) and row.get("defect_id")}
    return {
        "schema_id": "kt.operator.deprecation_plan.v1",
        "generated_utc": generated_utc,
        "proposal_status": "PROPOSED_UNRATIFIED",
        "deprecations": [
            {
                "surface_id": "root_docs_audit_tree",
                "current_surface": "docs/audit/**",
                "future_status": "ARCHIVE_ONLY",
                "target_root": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/docs_audit/",
                "trigger": "archive migration package execution",
                "evidence_refs": list(defects.get("ROOT_ARCHIVE_CONTAMINATION", {}).get("current_evidence_refs", [])),
            },
            {
                "surface_id": "legacy_root_runtime_roots",
                "current_surface": "KT_TEMPLE_ROOT/** and KT_LANE_LORA_PHASE_B/**",
                "future_status": "ARCHIVE_ONLY",
                "target_root": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/legacy_runtime/",
                "trigger": "root and archive boundary execution",
                "evidence_refs": list(defects.get("ROOT_ARCHIVE_CONTAMINATION", {}).get("current_evidence_refs", [])),
            },
            {
                "surface_id": "root_epoch_and_operation_files",
                "current_surface": "EPOCH_*.json, OPERATION_A_*, RUN_REPORT.md, runbook.txt, work_order.json",
                "future_status": "ARCHIVE_ONLY",
                "target_root": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/root_legacy/",
                "trigger": "root and archive boundary execution",
                "evidence_refs": list(defects.get("ROOT_ARCHIVE_CONTAMINATION", {}).get("current_evidence_refs", [])),
            },
            {
                "surface_id": "root_secret_residue",
                "current_surface": ".env.secret",
                "future_status": "REMOVED_FROM_REPO_SURFACE",
                "target_root": "LOCAL_SECRET_MANAGER_OR_UNTRACKED_ENV",
                "trigger": "generated artifact boundary execution",
                "evidence_refs": list(defects.get("LOCAL_RESIDUE_PRESENT", {}).get("current_evidence_refs", [])),
            },
            {
                "surface_id": "root_run_manifest_schema",
                "current_surface": "run_manifest.schema.json",
                "future_status": "ARCHIVE_SCHEMA_ONLY",
                "target_root": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/schemas/",
                "trigger": "schema housing execution",
                "evidence_refs": [CONTRACT_INDEX_REL],
            },
            {
                "surface_id": "manual_repo_canon_inventory",
                "current_surface": "REPO_CANON.md",
                "future_status": "RETAIN_AS_TRANSITIONAL_POINTER_UNTIL_GENERATED_DOCTRINE_EXISTS",
                "target_root": "docs/generated/",
                "trigger": "step11_doctrine_generation",
                "evidence_refs": [REPO_CANON_REL, README_REL],
            },
        ],
        "claim_boundary": "Deprecation entries are future migration intents only. No listed surface loses validity until its replacement and migration receipt both exist.",
    }


def _build_repo_professionalization_plan(ctx: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    root_entries = ctx["root_entries"]
    root_noise = _root_noise(root_entries)
    return {
        "schema_id": "kt.operator.repo_professionalization_plan.v1",
        "generated_utc": generated_utc,
        "proposal_status": "PROPOSED_UNRATIFIED",
        "current_root_entry_count": len(root_entries),
        "current_root_noise_count": len(root_noise),
        "current_root_noise_entries": root_noise,
        "target_top_level_layout": {
            "minimal_root_keep": sorted(ROOT_ALLOWED_KEEP),
            "archive_root": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/",
            "public_docs_root": "docs/",
            "commercial_docs_root": "KT_PROD_CLEANROOM/docs/commercial/",
            "generated_profiles_root": "docs/generated/profiles/",
        },
        "coverage_axes": {
            "repo_shape": ["WP_STEP8_ROOT_AND_ARCHIVE_BOUNDARY"],
            "docs": ["WP_STEP8_DOCS_TOPOLOGY_RATIONALIZATION"],
            "schemas": ["WP_STEP8_SCHEMA_HOUSING_AND_NAMING"],
            "release_layout": ["WP_STEP8_RELEASE_AND_SUBMISSION_LAYOUT"],
            "submission_layout": ["WP_STEP8_RELEASE_AND_SUBMISSION_LAYOUT"],
        },
        "linked_work_packages": WORK_PACKAGE_IDS,
        "quality_alignment": {
            "runtime_quality": "retain QL3 runtime root isolation while cleaning surrounding repo shape",
            "governance_quality": "keep workflow-governance-only ceiling explicit during any normalization",
            "operability_quality": "reduce outsider confusion by making docs, profiles, and bundles discoverable",
        },
        "claim_boundary": "Professionalization here means a reversible plan for repo shape and outward legibility. It is not a statement that the repo is already fully normalized or fully green.",
    }


def _build_repo_style_guide(*, generated_utc: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.repo_style_guide.v1",
        "generated_utc": generated_utc,
        "style_status": "PROPOSED_UNRATIFIED",
        "path_conventions": [
            "live governed law stays under KT_PROD_CLEANROOM/governance/",
            "runtime code and schemas stay under KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
            "committed generated evidence stays under KT_PROD_CLEANROOM/reports/",
            "root stays orientation/legal/launcher only",
            "historical and legacy material should converge into KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/",
        ],
        "json_conventions": [
            "ASCII, LF, stable key ordering",
            "schema_id required on structured governed artifacts",
            "generated_utc required on emitted artifacts",
            "claim-bearing artifacts require explicit evidence refs or boundary text",
        ],
        "python_conventions": [
            "one governed compiler per file with deterministic CLI",
            "focused test alongside each new compiler",
            "proposal-only steps must not mutate live canon while planning future work",
        ],
        "naming_conventions": [
            "receipts end with _receipt.json",
            "schemas end with .schema.json",
            "work orders use WORK_ORDER_* for controlling packets and kt_*_work_order.json for generated plans",
            "generated machine-state artifacts use lowercase kt_* names",
        ],
        "docs_conventions": [
            "root README is orientation-only",
            "public docs define audience and claim boundary",
            "commercial docs remain claim-compiler bound",
            "codex docs remain lineage-only unless later ratified",
        ],
        "claim_boundary": "This style guide is a proposal for future normalization work. It does not retroactively make all existing surfaces compliant.",
    }


def _build_docs_topology(*, generated_utc: str) -> Dict[str, Any]:
    layers = [
        {
            "layer_id": "root_orientation",
            "canonical_root": "ROOT",
            "audience": "all entrants",
            "status": "ACTIVE_MINIMAL_KEEP",
            "included_surfaces": ["README.md", "LICENSE", "REPO_CANON.md", "run_kt_e2e.sh"],
            "claim_boundary": "orientation only; no canon ratification by root summaries",
        },
        {
            "layer_id": "public_manual_docs",
            "canonical_root": "docs/",
            "audience": "public specialist readers",
            "status": "ACTIVE_MANUAL_DOCS",
            "included_surfaces": ["docs/KT_OVERVIEW.md", "docs/KT_ARCHITECTURE.md", "docs/KT_THREAT_MODEL.md", "docs/RUNBOOK.md"],
            "claim_boundary": "must not outrun machine-state claim ceilings",
        },
        {
            "layer_id": "operator_internal_docs",
            "canonical_root": "KT_PROD_CLEANROOM/docs/operator/",
            "audience": "operators and maintainers",
            "status": "ACTIVE_INTERNAL_DOCS",
            "included_surfaces": ["KT_PROD_CLEANROOM/docs/operator/**"],
            "claim_boundary": "internal doctrine and runbooks remain subordinate to governance law and receipts",
        },
        {
            "layer_id": "commercial_docs",
            "canonical_root": "KT_PROD_CLEANROOM/docs/commercial/",
            "audience": "commercial and external evaluation readers",
            "status": "ACTIVE_BOUND_BY_CLAIM_COMPILER",
            "included_surfaces": ["KT_PROD_CLEANROOM/docs/commercial/**"],
            "claim_boundary": "documentary only; compiler-bounded claims only",
        },
        {
            "layer_id": "generated_doctrine_target",
            "canonical_root": "docs/generated/",
            "audience": "future external/public doctrine consumers",
            "status": "TARGET_NOT_YET_CREATED",
            "included_surfaces": ["KT_Whitepaper_vN.md", "KT_Governance_Spine_vN.md", "kt_*_profile artifacts"],
            "claim_boundary": "machine-state derived only after Step 11",
        },
        {
            "layer_id": "audit_archive_target",
            "canonical_root": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/docs_audit/",
            "audience": "historians and auditors",
            "status": "TARGET_FOR_ROOT_ARCHIVE_MIGRATION",
            "included_surfaces": ["docs/audit/**"],
            "claim_boundary": "lineage memory only, not current law",
        },
        {
            "layer_id": "codex_lineage_docs",
            "canonical_root": "KT-Codex/",
            "audience": "draft doctrine and external packet readers",
            "status": "ACTIVE_LINEAGE_ONLY",
            "included_surfaces": ["KT-Codex/**"],
            "claim_boundary": "draft lineage, not active canon",
        },
    ]
    if [row["layer_id"] for row in layers] != DOC_LAYER_IDS:
        raise RuntimeError("FAIL_CLOSED: docs topology layer set drifted.")
    return {
        "schema_id": "kt.operator.docs_topology.v1",
        "generated_utc": generated_utc,
        "proposal_status": "PROPOSED_UNRATIFIED",
        "layers": layers,
        "migration_targets": [
            {"from": "docs/audit/**", "to": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/docs_audit/"},
            {"from": "KT-Codex/**", "to": "KT-Codex/**", "note": "keep in place but label lineage-only"},
            {"from": "future generated doctrine artifacts", "to": "docs/generated/"},
        ],
        "claim_boundary": "Docs topology defines future housing and audience lanes only. It does not itself publish new doctrine.",
    }


def _build_release_profile(ctx: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    quality_levels = _quality_levels(ctx)
    profiles = [
        {
            "profile_id": "internal_operator_audit_release",
            "current_status": "ADMISSIBLE_WITH_BOUNDARIES",
            "target_quality": {"governance_quality": "QL2", "runtime_quality": "QL3", "proof_quality": "QL2", "operability_quality": "QL1"},
            "required_evidence_refs": [STEP7_RECEIPT_REL, PUBLIC_VERIFIER_REL, RUNTIME_BOUNDARY_REL],
            "blocked_by": [],
            "forbidden_claims": ["HEAD_IS_VERIFIED_SUBJECT", "H1_ALLOWED", "PLATFORM_ENFORCED_GOVERNANCE_PROVEN"],
        },
        {
            "profile_id": "external_specialist_demo_release",
            "current_status": "ADMISSIBLE_WITH_BOUNDARIES",
            "target_quality": {"governance_quality": "QL2", "runtime_quality": "QL3", "proof_quality": "QL2", "operability_quality": "QL2"},
            "required_evidence_refs": [PUBLIC_VERIFIER_REL, RUNTIME_BOUNDARY_REL, COMMERCIAL_COMPILER_REL],
            "blocked_by": [],
            "forbidden_claims": ["H1_ALLOWED", "PLATFORM_ENFORCED_GOVERNANCE_PROVEN", "CROSS_ENV_REPRODUCIBILITY_COMPLETE"],
        },
        {
            "profile_id": "governed_partner_review_release",
            "current_status": "HOLD_PENDING_PLATFORM_AND_PROFILE_WORK",
            "target_quality": {"governance_quality": "QL3", "runtime_quality": "QL3", "proof_quality": "QL2", "operability_quality": "QL2"},
            "required_evidence_refs": [PUBLIC_VERIFIER_REL, COMMERCIAL_COMPILER_REL, STATE_VECTOR_REL],
            "blocked_by": ["PLATFORM_ENFORCEMENT_UNPROVEN"],
            "forbidden_claims": ["PLATFORM_ENFORCED_GOVERNANCE_PROVEN", "H1_ALLOWED"],
        },
        {
            "profile_id": "competition_release",
            "current_status": "BLOCKED",
            "target_quality": {"governance_quality": "QL3", "runtime_quality": "QL3", "proof_quality": "QL3", "operability_quality": "QL3", "competition_quality": "QL3"},
            "required_evidence_refs": [REPRODUCIBILITY_REL, STATE_VECTOR_REL],
            "blocked_by": ["CROSS_ENV_CONTROLLED_VARIATION_NOT_RUN", "DELTA_LINEAGE_MISSING", "QUALITY_LEVEL_BELOW_TARGET"],
            "forbidden_claims": ["COMPETITION_READY", "H1_ALLOWED"],
        },
        {
            "profile_id": "publication_release",
            "current_status": "BLOCKED",
            "target_quality": {"governance_quality": "QL3", "runtime_quality": "QL3", "proof_quality": "QL3", "operability_quality": "QL3", "publication_quality": "QL3"},
            "required_evidence_refs": [PUBLIC_VERIFIER_REL, FRONTIER_SETTLEMENT_REL, STATE_VECTOR_REL],
            "blocked_by": ["PARADOX_PROGRAM_UNBOUNDED", "PLATFORM_ENFORCEMENT_UNPROVEN", "DOCTRINE_AND_PROFILES_GENERATED_PENDING"],
            "forbidden_claims": ["PUBLICATION_READY", "H1_ALLOWED", "HEAD_IS_VERIFIED_SUBJECT"],
        },
    ]
    if [row["profile_id"] for row in profiles] != RELEASE_PROFILE_IDS:
        raise RuntimeError("FAIL_CLOSED: release profile set drifted.")
    return {
        "schema_id": "kt.operator.release_profile.v1",
        "generated_utc": generated_utc,
        "profile_status": "PROPOSED_FROM_CURRENT_CEILING",
        "current_ceiling": dict(ctx["state_vector"].get("claim_ceiling_status", {})),
        "quality_snapshot": quality_levels,
        "h1_allowed": bool(ctx["h1_gate"].get("h1_allowed", False)),
        "profiles": profiles,
        "claim_boundary": "Release profile proposals are bounded by the current Step 7 state vector and may not overread blocked horizons as released capability.",
    }


def _build_submission_profile(ctx: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    profiles = [
        {
            "profile_id": "auditor_packet",
            "current_status": "ADMISSIBLE_WITH_BOUNDARIES",
            "included_surfaces": [PUBLIC_VERIFIER_REL, RUNTIME_BOUNDARY_REL, STEP7_RECEIPT_REL, STATE_VECTOR_REL],
            "blocked_by": [],
            "forbidden_claims": ["HEAD_IS_VERIFIED_SUBJECT", "H1_ALLOWED"],
        },
        {
            "profile_id": "specialist_demo_packet",
            "current_status": "ADMISSIBLE_WITH_BOUNDARIES",
            "included_surfaces": [PUBLIC_VERIFIER_REL, COMMERCIAL_COMPILER_REL, RELEASE_PROFILE_REL],
            "blocked_by": [],
            "forbidden_claims": ["PLATFORM_ENFORCED_GOVERNANCE_PROVEN", "H1_ALLOWED"],
        },
        {
            "profile_id": "partner_review_packet",
            "current_status": "HOLD_PENDING_PLATFORM_AND_PROFILE_WORK",
            "included_surfaces": [PUBLIC_VERIFIER_REL, COMMERCIAL_COMPILER_REL, RELEASE_PROFILE_REL],
            "blocked_by": ["PLATFORM_ENFORCEMENT_UNPROVEN"],
            "forbidden_claims": ["PLATFORM_ENFORCED_GOVERNANCE_PROVEN", "H1_ALLOWED"],
        },
        {
            "profile_id": "competition_bundle",
            "current_status": "BLOCKED",
            "included_surfaces": [REPRODUCIBILITY_REL, RELEASE_PROFILE_REL],
            "blocked_by": ["CROSS_ENV_CONTROLLED_VARIATION_NOT_RUN", "DELTA_LINEAGE_MISSING"],
            "forbidden_claims": ["COMPETITION_READY", "H1_ALLOWED"],
        },
        {
            "profile_id": "publication_peer_review_bundle",
            "current_status": "BLOCKED",
            "included_surfaces": [PUBLIC_VERIFIER_REL, FRONTIER_SETTLEMENT_REL, RELEASE_PROFILE_REL],
            "blocked_by": ["PARADOX_PROGRAM_UNBOUNDED", "DOCTRINE_AND_PROFILES_GENERATED_PENDING", "PLATFORM_ENFORCEMENT_UNPROVEN"],
            "forbidden_claims": ["PUBLICATION_READY", "HEAD_IS_VERIFIED_SUBJECT", "H1_ALLOWED"],
        },
    ]
    if [row["profile_id"] for row in profiles] != SUBMISSION_PROFILE_IDS:
        raise RuntimeError("FAIL_CLOSED: submission profile set drifted.")
    return {
        "schema_id": "kt.operator.submission_profile.v1",
        "generated_utc": generated_utc,
        "profile_status": "PROPOSED_FROM_CURRENT_CEILING",
        "h1_allowed": bool(ctx["h1_gate"].get("h1_allowed", False)),
        "profiles": profiles,
        "claim_boundary": "Submission bundles are proposed artifact selections only. They must inherit the same claim ceiling and blockers as the current state vector.",
    }


def build_step8_outputs(root: Path, generated_utc: Optional[str] = None) -> Dict[str, Any]:
    generated = generated_utc or utc_now_iso_z()
    ctx = _step_context(root)
    canon = _build_canon_proposal(ctx, generated_utc=generated)
    outputs = {
        "kt_canon_proposal": canon,
        "kt_canon_ratification_log": _build_canon_ratification_log(canon, generated_utc=generated),
        "kt_normalization_work_order": _build_normalization_work_order(ctx, generated_utc=generated),
        "kt_path_unification_plan": _build_path_unification_plan(ctx, generated_utc=generated),
        "kt_schema_unification_plan": _build_schema_unification_plan(ctx, generated_utc=generated),
        "kt_generated_artifact_policy": _build_generated_artifact_policy(generated_utc=generated),
        "kt_deprecation_plan": _build_deprecation_plan(ctx, generated_utc=generated),
        "kt_repo_professionalization_plan": _build_repo_professionalization_plan(ctx, generated_utc=generated),
        "kt_repo_style_guide": _build_repo_style_guide(generated_utc=generated),
        "kt_docs_topology": _build_docs_topology(generated_utc=generated),
        "kt_release_profile": _build_release_profile(ctx, generated_utc=generated),
        "kt_submission_profile": _build_submission_profile(ctx, generated_utc=generated),
    }

    canon_ids = [row["major_function_id"] for row in outputs["kt_canon_proposal"]["major_function_proposals"]]
    if canon_ids != MAJOR_FUNCTION_IDS:
        raise RuntimeError("FAIL_CLOSED: Step 8 canon proposal missing major function coverage.")

    for row in outputs["kt_normalization_work_order"]["work_packages"]:
        if not row.get("migration_tests") or not row.get("rollback_plan"):
            raise RuntimeError(f"FAIL_CLOSED: Step 8 work package missing migration tests or rollback plan: {row.get('package_id')}")

    if outputs["kt_canon_ratification_log"]["ratification_status"] != "UNRATIFIED_PROPOSAL_ONLY":
        raise RuntimeError("FAIL_CLOSED: Step 8 canon ratification log must remain unratified.")

    return outputs


def build_step8_receipt(root: Path) -> Dict[str, Any]:
    ctx = _step_context(root)
    generated_utc = utc_now_iso_z()
    first = build_step8_outputs(root, generated_utc=generated_utc)
    second = build_step8_outputs(root, generated_utc=generated_utc)
    for key in first:
        if not semantically_equal_json(first[key], second[key]):
            raise RuntimeError(f"FAIL_CLOSED: nondeterministic Step 8 output detected: {key}")

    compiled_head = _git_head(root)
    parent = _git_parent(root, compiled_head)
    actual_touched = sorted(set(_git_diff_files(root, parent, compiled_head, SUBJECT_ARTIFACT_REFS) + [RECEIPT_REL]))
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = [path for path in actual_touched if _is_protected(path)]

    professionalization = first["kt_repo_professionalization_plan"]
    coverage_axes = set((professionalization.get("coverage_axes") or {}).keys())
    required_axes = {"repo_shape", "docs", "schemas", "release_layout", "submission_layout"}

    return {
        "schema_id": "kt.operator.normalization_and_professionalization_planning_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "pass_verdict": "NORMALIZATION_AND_PROFESSIONALIZATION_PLANNED",
        "compiled_head_commit": compiled_head,
        "current_head_commit": compiled_head,
        "controlling_work_order": {
            "schema_id": WORK_ORDER_SCHEMA_ID,
            "work_order_id": WORK_ORDER_ID,
            "step_id": 8,
            "step_name": "CANON_PROPOSAL_NORMALIZATION_PLAN_AND_REPO_PROFESSIONALIZATION_PLAN",
        },
        "step7_gate_subject_commit": str(ctx["step7_receipt"].get("compiled_head_commit", "")).strip(),
        "step7_gate_evidence_commit": str(ctx["step7_evidence_commit"]).strip(),
        "claim_boundary": (
            "This receipt validates Step 8 planning artifacts for compiled_head_commit only. "
            "The outputs are proposal-only and do not ratify canon or authorize repository mutations beyond the planning artifacts themselves."
        ),
        "summary": {
            "major_function_count": len(first["kt_canon_proposal"].get("major_function_proposals", [])),
            "work_package_count": len(first["kt_normalization_work_order"].get("work_packages", [])),
            "deprecation_count": len(first["kt_deprecation_plan"].get("deprecations", [])),
            "release_profile_count": len(first["kt_release_profile"].get("profiles", [])),
            "submission_profile_count": len(first["kt_submission_profile"].get("profiles", [])),
        },
        "checks": [
            {
                "check": "step7_gate_passed",
                "detail": "Step 8 requires the Step 7 judgment-plane receipt to be PASS.",
                "refs": [STEP7_RECEIPT_REL],
                "status": "PASS",
            },
            {
                "check": "one_canonical_path_proposal_per_major_function",
                "detail": "Canon proposal covers every Step 8 major function with an explicit canonical root proposal.",
                "refs": [CANON_PROPOSAL_REL, ORGAN_ONTOLOGY_REL],
                "status": "PASS" if len(first["kt_canon_proposal"].get("major_function_proposals", [])) == len(MAJOR_FUNCTION_IDS) else "FAIL",
            },
            {
                "check": "generated_and_deprecated_artifact_policies_exist",
                "detail": "Generated artifact policy and deprecation plan are both present and proposal-only.",
                "refs": [GENERATED_ARTIFACT_POLICY_REL, DEPRECATION_PLAN_REL],
                "status": "PASS"
                if first["kt_generated_artifact_policy"].get("policy_status") == "PROPOSED_UNRATIFIED"
                and first["kt_deprecation_plan"].get("proposal_status") == "PROPOSED_UNRATIFIED"
                else "FAIL",
            },
            {
                "check": "professionalization_plan_covers_required_axes",
                "detail": "Repo professionalization plan must cover repo shape, docs, schemas, release layout, and submission layout.",
                "refs": [REPO_PROFESSIONALIZATION_PLAN_REL],
                "status": "PASS" if required_axes.issubset(coverage_axes) else "FAIL",
            },
            {
                "check": "all_work_packages_have_migration_tests_and_rollback",
                "detail": "Every planned normalization package must carry migration tests and rollback plan arrays.",
                "refs": [NORMALIZATION_WORK_ORDER_REL],
                "status": "PASS"
                if all(row.get("migration_tests") and row.get("rollback_plan") for row in first["kt_normalization_work_order"].get("work_packages", []))
                else "FAIL",
            },
            {
                "check": "proposal_only_and_no_claim_upgrade",
                "detail": "Canon ratification log must remain unratified and release/submission profiles must preserve the current blocked horizons.",
                "refs": [CANON_RATIFICATION_LOG_REL, RELEASE_PROFILE_REL, SUBMISSION_PROFILE_REL, STATE_VECTOR_REL],
                "status": "PASS"
                if first["kt_canon_ratification_log"].get("ratification_status") == "UNRATIFIED_PROPOSAL_ONLY"
                and not bool(first["kt_release_profile"].get("h1_allowed"))
                and not bool(first["kt_submission_profile"].get("h1_allowed"))
                else "FAIL",
            },
            {
                "check": "post_touch_accounting_clean",
                "detail": "Actual touched set must match the lawful Step 8 subject files plus the planning receipt.",
                "refs": SUBJECT_ARTIFACT_REFS + [RECEIPT_REL],
                "status": "PASS" if not unexpected_touches and not protected_touch_violations else "FAIL",
            },
        ],
        "planned_mutates": PLANNED_MUTATES,
        "actual_touched": actual_touched,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "next_lawful_step": {
            "step_id": 9,
            "step_name": "RUNTIME_EXPERIMENT_CRUCIBLE_AND_DELTA_REGISTRY",
            "status_after_step_8": "UNLOCKED" if not unexpected_touches and not protected_touch_violations else "BLOCKED",
        },
    }


def write_step8_outputs(root: Path) -> Dict[str, Any]:
    outputs = build_step8_outputs(root)
    artifact_map = {
        CANON_PROPOSAL_REL: outputs["kt_canon_proposal"],
        CANON_RATIFICATION_LOG_REL: outputs["kt_canon_ratification_log"],
        NORMALIZATION_WORK_ORDER_REL: outputs["kt_normalization_work_order"],
        PATH_UNIFICATION_PLAN_REL: outputs["kt_path_unification_plan"],
        SCHEMA_UNIFICATION_PLAN_REL: outputs["kt_schema_unification_plan"],
        GENERATED_ARTIFACT_POLICY_REL: outputs["kt_generated_artifact_policy"],
        DEPRECATION_PLAN_REL: outputs["kt_deprecation_plan"],
        REPO_PROFESSIONALIZATION_PLAN_REL: outputs["kt_repo_professionalization_plan"],
        REPO_STYLE_GUIDE_REL: outputs["kt_repo_style_guide"],
        DOCS_TOPOLOGY_REL: outputs["kt_docs_topology"],
        RELEASE_PROFILE_REL: outputs["kt_release_profile"],
        SUBMISSION_PROFILE_REL: outputs["kt_submission_profile"],
    }
    writes = []
    for rel, payload in artifact_map.items():
        changed = write_json_stable(root / Path(rel), payload)
        writes.append({"artifact_ref": rel, "updated": bool(changed), "schema_id": str(payload.get("schema_id", "")).strip()})
    return {"status": "PASS", "artifacts_written": writes}


def emit_step8_receipt(root: Path) -> Dict[str, Any]:
    receipt = build_step8_receipt(root)
    write_json_stable(root / Path(RECEIPT_REL), receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile Step 8 canon, normalization, and repo professionalization planning artifacts.")
    parser.add_argument("--emit-receipt", action="store_true", help="Emit the Step 8 planning receipt instead of only the subject artifacts.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    result = emit_step8_receipt(root) if args.emit_receipt else write_step8_outputs(root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
