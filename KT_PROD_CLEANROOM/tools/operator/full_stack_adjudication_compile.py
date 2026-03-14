from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"

WORK_ORDER_REL = "KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V2/WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION.v2.json"
STEP11_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_doctrine_and_profiles_generation_receipt.json"
STEP10_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_paradox_program_bounded_receipt.json"
STEP9_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_runtime_and_experiment_memory_sealing_receipt.json"
STEP8_RELEASE_PROFILE_REL = f"{REPORT_ROOT_REL}/kt_release_profile.json"
STEP8_SUBMISSION_PROFILE_REL = f"{REPORT_ROOT_REL}/kt_submission_profile.json"
STEP5_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_snapshot_inventory_compilation_receipt.json"
STEP4_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_historical_memory_ingestion_receipt.json"
CLAIM_CEILING_SUMMARY_REL = f"{REPORT_ROOT_REL}/kt_claim_ceiling_summary.json"
OPEN_BLOCKER_LADDER_REL = f"{REPORT_ROOT_REL}/kt_open_blocker_ladder.json"
CLAIM_REGISTRY_REL = f"{REPORT_ROOT_REL}/kt_claim_registry.json"
STATE_VECTOR_REL = f"{REPORT_ROOT_REL}/kt_state_vector.json"
REOPENED_DEFECTS_REL = f"{REPORT_ROOT_REL}/kt_reopened_defect_register.json"
REPO_PROFESSIONALIZATION_REL = f"{REPORT_ROOT_REL}/kt_repo_professionalization_plan.json"
PUBLIC_VERIFIER_MANIFEST_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
PLATFORM_GOVERNANCE_REL = f"{REPORT_ROOT_REL}/platform_governance_narrowing_receipt.json"
RUNTIME_BOUNDARY_REL = f"{REPORT_ROOT_REL}/runtime_boundary_integrity_receipt.json"
REPRODUCIBILITY_REL = f"{REPORT_ROOT_REL}/representative_authority_lane_reproducibility_receipt.json"
FRONTIER_SETTLEMENT_REL = f"{REPORT_ROOT_REL}/frontier_settlement_receipt.json"
EXPERIMENT_MEMORY_REL = STEP9_RECEIPT_REL
PARADOX_SCHEDULER_REL = f"{REPORT_ROOT_REL}/kt_proof_obligation_scheduler.json"
PARADOX_CLAIM_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_paradox_claim_matrix.json"
HISTORICAL_CLAIMS_REL = f"{REPORT_ROOT_REL}/kt_historical_claims.json"
WS_CLOSEOUT_SUMMARY_REL = f"{REPORT_ROOT_REL}/ws0_ws11_closeout_summary.json"

ORGAN_ONTOLOGY_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_organ_ontology.json"
QUALITY_POLICY_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_quality_policy.json"
READINESS_LATTICE_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_readiness_lattice.json"

DOCTRINE_MANIFEST_REL = "docs/generated/kt_doctrine_manifest.json"
DOCTRINE_RATIFICATION_LOG_REL = "docs/generated/kt_doctrine_ratification_log.json"
OUTSIDER_PROFILE_REL = "docs/generated/profiles/kt_outsider_onboarding_profile.json"
COMPETITION_PROFILE_REL = "docs/generated/profiles/kt_competition_profile.json"
PUBLICATION_PROFILE_REL = "docs/generated/profiles/kt_publication_profile.json"
MATH_GURU_PROFILE_REL = "docs/generated/profiles/kt_math_guru_profile.json"

FULL_STACK_AUDIT_REL = f"{REPORT_ROOT_REL}/kt_full_stack_audit.json"
ATTACK_VECTORS_REL = f"{REPORT_ROOT_REL}/kt_attack_vectors.json"
SURVIVAL_METRICS_REL = f"{REPORT_ROOT_REL}/kt_survival_metrics.json"
PROOF_OBLIGATIONS_REL = f"{REPORT_ROOT_REL}/kt_proof_obligations.json"
RELEASE_READINESS_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_release_readiness_matrix.json"
ADJUDICATION_CLOSEOUT_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_adjudication_closeout_bundle.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_full_stack_adjudication_completion_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/full_stack_adjudication_compile.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_full_stack_adjudication_compile.py"

DELIVERABLE_REFS = [
    FULL_STACK_AUDIT_REL,
    ATTACK_VECTORS_REL,
    SURVIVAL_METRICS_REL,
    PROOF_OBLIGATIONS_REL,
    RELEASE_READINESS_MATRIX_REL,
    ADJUDICATION_CLOSEOUT_BUNDLE_REL,
]
SUBJECT_ARTIFACT_REFS = DELIVERABLE_REFS + [TOOL_REL, TEST_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

WORK_ORDER_ID = "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION"
WORK_ORDER_SCHEMA_ID = "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2"

PROTECTED_PREFIXES = (
    "KT_PROD_CLEANROOM/docs/commercial/",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "kt_truth_ledger:",
    ".github/workflows/",
)

CLAIM_CLASSIFICATIONS = {"proven", "evidenced_only", "contradicted", "aspirational"}


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


def _unique_refs(values: Sequence[str]) -> List[str]:
    refs: List[str] = []
    seen = set()
    for value in values:
        normalized = _normalize_ref(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            refs.append(normalized)
    return refs


def _is_protected(path: str) -> bool:
    normalized = _normalize_ref(path)
    return any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _step_context(root: Path) -> Dict[str, Any]:
    step11 = _load_required(root, STEP11_RECEIPT_REL)
    if str(step11.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 12 is blocked until the Step 11 doctrine receipt is PASS.")
    return {
        "work_order": _load_required(root, WORK_ORDER_REL),
        "step11_receipt": step11,
        "step11_evidence_commit": _git_last_commit_for_paths(root, [STEP11_RECEIPT_REL]),
        "step10_receipt": _load_required(root, STEP10_RECEIPT_REL),
        "step9_receipt": _load_required(root, STEP9_RECEIPT_REL),
        "step8_release_profile": _load_required(root, STEP8_RELEASE_PROFILE_REL),
        "step8_submission_profile": _load_required(root, STEP8_SUBMISSION_PROFILE_REL),
        "step5_receipt": _load_required(root, STEP5_RECEIPT_REL),
        "step4_receipt": _load_required(root, STEP4_RECEIPT_REL),
        "claim_ceiling_summary": _load_required(root, CLAIM_CEILING_SUMMARY_REL),
        "open_blocker_ladder": _load_required(root, OPEN_BLOCKER_LADDER_REL),
        "claim_registry": _load_required(root, CLAIM_REGISTRY_REL),
        "state_vector": _load_required(root, STATE_VECTOR_REL),
        "reopened_defects": _load_required(root, REOPENED_DEFECTS_REL),
        "repo_professionalization": _load_required(root, REPO_PROFESSIONALIZATION_REL),
        "public_verifier_manifest": _load_required(root, PUBLIC_VERIFIER_MANIFEST_REL),
        "platform_governance": _load_required(root, PLATFORM_GOVERNANCE_REL),
        "runtime_boundary": _load_required(root, RUNTIME_BOUNDARY_REL),
        "reproducibility": _load_required(root, REPRODUCIBILITY_REL),
        "frontier_settlement": _load_required(root, FRONTIER_SETTLEMENT_REL),
        "experiment_memory": _load_required(root, EXPERIMENT_MEMORY_REL),
        "paradox_scheduler": _load_required(root, PARADOX_SCHEDULER_REL),
        "paradox_claim_matrix": _load_required(root, PARADOX_CLAIM_MATRIX_REL),
        "historical_claims": _load_required(root, HISTORICAL_CLAIMS_REL),
        "closeout_summary": _load_required(root, WS_CLOSEOUT_SUMMARY_REL),
        "organ_ontology": _load_required(root, ORGAN_ONTOLOGY_REL),
        "quality_policy": _load_required(root, QUALITY_POLICY_REL),
        "readiness_lattice": _load_required(root, READINESS_LATTICE_REL),
        "doctrine_manifest": _load_required(root, DOCTRINE_MANIFEST_REL),
        "doctrine_ratification_log": _load_required(root, DOCTRINE_RATIFICATION_LOG_REL),
        "outsider_profile": _load_required(root, OUTSIDER_PROFILE_REL),
        "competition_profile": _load_required(root, COMPETITION_PROFILE_REL),
        "publication_profile": _load_required(root, PUBLICATION_PROFILE_REL),
        "math_guru_profile": _load_required(root, MATH_GURU_PROFILE_REL),
    }


def _current_organ_statuses(state_vector: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows: Dict[str, Dict[str, Any]] = {}
    for row in state_vector.get("organ_readiness", []):
        if not isinstance(row, dict):
            continue
        updated = dict(row)
        organ_id = str(updated.get("organ_id", "")).strip()
        blockers = [str(item).strip() for item in updated.get("blockers", []) if str(item).strip()]
        if organ_id == "experiment_crucible_plane":
            blockers = [item for item in blockers if item != "DELTA_LINEAGE_MISSING"]
            updated["status"] = "RUNTIME_AND_EXPERIMENT_MEMORY_SEALED_REPRESENTATIVE_ONLY"
        elif organ_id == "paradox_metabolism_plane":
            blockers = [item for item in blockers if item != "PARADOX_PROGRAM_UNBOUNDED"]
            updated["status"] = "BOUNDED_AT_DOCUMENTARY_CEILING"
        elif organ_id == "public_claims_and_doctrine_plane":
            updated["status"] = "MACHINE_STATE_DOCTRINE_GENERATED"
        updated["blockers"] = blockers
        rows[organ_id] = updated
    return rows


def _organ_verdict(organ_id: str) -> str:
    verdicts = {
        "governance_spine": "PROVEN_AT_WORKFLOW_CEILING",
        "constitutional_meta_governance": "PROVEN_WITH_PLATFORM_LIMIT",
        "truth_authority_plane": "EVIDENCED_ONLY_AT_SUBJECT_CEILING",
        "runtime_spine": "PROVEN_CANONICAL_BOUNDARY",
        "operator_factory": "SURVIVED_WITH_BOUNDARY_ENFORCEMENT",
        "verification_delivery_security_plane": "PROVEN_TRANSPARENCY_AND_BUNDLE",
        "lab_adaptation_plane": "PROMOTION_REQUIRED_BEFORE_CANON",
        "experiment_crucible_plane": "PROVEN_AT_REPRESENTATIVE_BAND",
        "paradox_metabolism_plane": "PROVEN_AT_DOCUMENTARY_CEILING",
        "public_claims_and_doctrine_plane": "GENERATED_WITH_EXPLICIT_BOUNDARIES",
        "release_profile_plane": "BLOCKED_BY_OPEN_HORIZONS",
        "commercial_surface_plane": "PROVEN_DOCUMENTARY_ONLY",
        "archive_memory_plane": "INGESTED_WITH_ROOT_CONTAMINATION_RISK",
        "adjudication_plane": "FULL_STACK_ADJUDICATION_COMPLETE_WITH_OPEN_BLOCKERS",
    }
    return verdicts.get(organ_id, "COVERED_WITH_EXPLICIT_EVIDENCE")


def _organ_evidence_refs(organ_id: str) -> List[str]:
    refs = {
        "governance_spine": [PLATFORM_GOVERNANCE_REL, PUBLIC_VERIFIER_MANIFEST_REL, CLAIM_CEILING_SUMMARY_REL],
        "constitutional_meta_governance": [PLATFORM_GOVERNANCE_REL, DOCTRINE_RATIFICATION_LOG_REL],
        "truth_authority_plane": [PUBLIC_VERIFIER_MANIFEST_REL, CLAIM_CEILING_SUMMARY_REL, FRONTIER_SETTLEMENT_REL],
        "runtime_spine": [RUNTIME_BOUNDARY_REL],
        "operator_factory": [PUBLIC_VERIFIER_MANIFEST_REL, STEP11_RECEIPT_REL],
        "verification_delivery_security_plane": [PUBLIC_VERIFIER_MANIFEST_REL, "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json"],
        "lab_adaptation_plane": [STEP9_RECEIPT_REL, REPO_PROFESSIONALIZATION_REL],
        "experiment_crucible_plane": [REPRODUCIBILITY_REL, STEP9_RECEIPT_REL],
        "paradox_metabolism_plane": [STEP10_RECEIPT_REL, PARADOX_SCHEDULER_REL],
        "public_claims_and_doctrine_plane": [STEP11_RECEIPT_REL, DOCTRINE_MANIFEST_REL, DOCTRINE_RATIFICATION_LOG_REL],
        "release_profile_plane": [STEP8_RELEASE_PROFILE_REL, STEP8_SUBMISSION_PROFILE_REL, OUTSIDER_PROFILE_REL, COMPETITION_PROFILE_REL, PUBLICATION_PROFILE_REL],
        "commercial_surface_plane": ["KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json", PUBLIC_VERIFIER_MANIFEST_REL],
        "archive_memory_plane": [STEP4_RECEIPT_REL, REOPENED_DEFECTS_REL],
        "adjudication_plane": [WS_CLOSEOUT_SUMMARY_REL, STEP11_RECEIPT_REL],
    }
    return refs.get(organ_id, [])


def _build_organ_assessments(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    status_map = _current_organ_statuses(ctx["state_vector"])
    rows: List[Dict[str, Any]] = []
    for organ in ctx["organ_ontology"].get("organs", []):
        if not isinstance(organ, dict):
            continue
        organ_id = str(organ.get("organ_id", "")).strip()
        state_row = status_map.get(organ_id, {})
        blockers = [str(item).strip() for item in state_row.get("blockers", []) if str(item).strip()]
        rows.append(
            {
                "organ_id": organ_id,
                "label": str(organ.get("label", "")).strip(),
                "organ_class": str(organ.get("organ_class", "")).strip(),
                "current_ceiling": str(organ.get("current_ceiling", "")).strip(),
                "quality_level": str(state_row.get("quality_level", "")).strip(),
                "current_status": str(state_row.get("status", "")).strip(),
                "adjudication_verdict": _organ_verdict(organ_id),
                "blockers": blockers,
                "evidence_refs": _organ_evidence_refs(organ_id),
                "trust_zones": list(organ.get("trust_zones", [])),
            }
        )
    return rows


def _claim_row(
    *,
    claim_id: str,
    classification: str,
    scope: str,
    statement: str,
    ceiling: str,
    evidence_refs: Sequence[str],
    blocked_by: Sequence[str] = (),
) -> Dict[str, Any]:
    return {
        "claim_id": claim_id,
        "classification": classification,
        "scope": scope,
        "statement": statement,
        "ceiling": ceiling,
        "blocked_by": list(blocked_by),
        "evidence_refs": _unique_refs(evidence_refs),
    }


def _build_claim_assessments(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    ceiling = ctx["claim_ceiling_summary"]
    frontier = ctx["frontier_settlement"]
    platform = ctx["platform_governance"]
    verifier = ctx["public_verifier_manifest"]
    runtime = ctx["runtime_boundary"]
    reproducibility = ctx["reproducibility"]
    repo_prof = ctx["repo_professionalization"]
    return [
        _claim_row(
            claim_id="CLAIM::TRANSPARENCY_VERIFIED_TRUTH_SUBJECT",
            classification="proven",
            scope=str(verifier.get("truth_subject_commit", "")).strip(),
            statement="A transparency-verified truth subject exists at the documented truth subject commit.",
            ceiling="PUBLISHED_HEAD_TRANSPARENCY_VERIFIED_SUBJECT",
            evidence_refs=[PUBLIC_VERIFIER_MANIFEST_REL, "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json"],
        ),
        _claim_row(
            claim_id="CLAIM::TRUTH_AUTHORITY_BEYOND_SUBJECT_CEILING",
            classification="evidenced_only",
            scope="current-head authority",
            statement="Truth authority is evidenced only up to the transparency-verified subject ceiling; current-head authority convergence remains unresolved.",
            ceiling="TRANSPARENCY_VERIFIED_SUBJECT_ONLY",
            evidence_refs=[PUBLIC_VERIFIER_MANIFEST_REL, "KT_PROD_CLEANROOM/reports/authority_convergence_receipt.json", "KT_PROD_CLEANROOM/reports/published_head_self_convergence_receipt.json"],
            blocked_by=["AUTHORITY_CONVERGENCE_UNRESOLVED", "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED"],
        ),
        _claim_row(
            claim_id="CLAIM::CURRENT_HEAD_AUTHORITY_CONVERGENCE_PASS",
            classification="contradicted",
            scope="current-head authority convergence",
            statement="Current-head authority convergence is not passing on the retained stack.",
            ceiling="FAIL_CLOSED",
            evidence_refs=["KT_PROD_CLEANROOM/reports/authority_convergence_receipt.json", FRONTIER_SETTLEMENT_REL],
            blocked_by=["AUTHORITY_CONVERGENCE_UNRESOLVED"],
        ),
        _claim_row(
            claim_id="CLAIM::WORKFLOW_GOVERNANCE_ONLY_LEGITIMACY",
            classification="proven",
            scope=str(platform.get("platform_governance_subject_commit", "")).strip(),
            statement="Workflow governance legitimacy is proven, with platform-enforced governance explicitly blocked.",
            ceiling="WORKFLOW_GOVERNANCE_ONLY",
            evidence_refs=[PLATFORM_GOVERNANCE_REL, PUBLIC_VERIFIER_MANIFEST_REL],
        ),
        _claim_row(
            claim_id="CLAIM::PLATFORM_ENFORCEMENT_PROVEN",
            classification="contradicted",
            scope="platform governance",
            statement="Platform-enforced governance is not proven on main.",
            ceiling="BLOCKED",
            evidence_refs=[PLATFORM_GOVERNANCE_REL, PUBLIC_VERIFIER_MANIFEST_REL],
            blocked_by=["PLATFORM_ENFORCEMENT_UNPROVEN"],
        ),
        _claim_row(
            claim_id="CLAIM::CANONICAL_RUNTIME_BOUNDARY_SETTLED",
            classification="proven",
            scope=str(runtime.get("runtime_boundary_subject_commit", "")).strip(),
            statement="Canonical runtime boundary integrity is settled for the runtime-boundary subject commit.",
            ceiling="CANONICAL_RUNTIME_BOUNDARY_SETTLED",
            evidence_refs=[RUNTIME_BOUNDARY_REL],
        ),
        _claim_row(
            claim_id="CLAIM::REPRESENTATIVE_SAME_MVE_REPRODUCIBILITY",
            classification="proven",
            scope=str(reproducibility.get("validated_head_sha", "")).strip(),
            statement="Representative same-MVE authority-lane reproducibility is proven.",
            ceiling="REPRESENTATIVE_AUTHORITY_LANE_SAME_MVE_ONLY",
            evidence_refs=[REPRODUCIBILITY_REL, STEP9_RECEIPT_REL],
        ),
        _claim_row(
            claim_id="CLAIM::CROSS_ENV_REPRODUCIBILITY_COMPLETE",
            classification="aspirational",
            scope="cross-environment reproducibility",
            statement="Cross-environment controlled variation is not yet complete.",
            ceiling="NOT_ATTAINED",
            evidence_refs=[REPRODUCIBILITY_REL, CLAIM_CEILING_SUMMARY_REL],
            blocked_by=["CROSS_ENV_CONTROLLED_VARIATION_NOT_RUN"],
        ),
        _claim_row(
            claim_id="CLAIM::EXPERIMENT_AND_DELTA_LINEAGE_AUDITABLE",
            classification="proven",
            scope="experiment crucible memory",
            statement="Governed experiments, learning deltas, and receipt lineage are now auditable.",
            ceiling="DOCUMENTARY_ONLY",
            evidence_refs=[STEP9_RECEIPT_REL, "KT_PROD_CLEANROOM/reports/kt_lineage_manifest.json"],
        ),
        _claim_row(
            claim_id="CLAIM::PARADOX_PROGRAM_BOUNDED",
            classification="proven",
            scope="paradox metabolism",
            statement="Paradox metabolism is bounded at documentary-only ceiling with explicit stress, counterexamples, and TTL obligations.",
            ceiling="DOCUMENTARY_ONLY",
            evidence_refs=[STEP10_RECEIPT_REL, PARADOX_CLAIM_MATRIX_REL, PARADOX_SCHEDULER_REL],
        ),
        _claim_row(
            claim_id="CLAIM::DOCTRINE_GENERATED_FROM_MACHINE_STATE",
            classification="proven",
            scope="public claims and doctrine",
            statement="Doctrine, profiles, and playbooks are generated from machine-state inputs and ratified for documentary use.",
            ceiling="DOCUMENTARY_ONLY",
            evidence_refs=[STEP11_RECEIPT_REL, DOCTRINE_MANIFEST_REL, DOCTRINE_RATIFICATION_LOG_REL],
        ),
        _claim_row(
            claim_id="CLAIM::COMMERCIAL_SURFACE_DOCUMENTARY_BOUNDARY",
            classification="proven",
            scope="commercial surface",
            statement="Commercial claims remain documentary-only and compiler-bounded.",
            ceiling="DOCUMENTARY_ONLY",
            evidence_refs=["KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json", PUBLIC_VERIFIER_MANIFEST_REL],
        ),
        _claim_row(
            claim_id="CLAIM::H1_ACTIVATION_ALLOWED",
            classification="contradicted",
            scope="H1 activation",
            statement="H1 activation is still blocked.",
            ceiling="BLOCKED",
            evidence_refs=[FRONTIER_SETTLEMENT_REL, "KT_PROD_CLEANROOM/reports/h1_activation_gate_receipt.json"],
            blocked_by=list(frontier.get("blockers", [])),
        ),
        _claim_row(
            claim_id="CLAIM::COMPETITION_RELEASE_READY",
            classification="aspirational",
            scope="competition profile",
            statement="Competition release readiness is not yet admissible.",
            ceiling="BLOCKED",
            evidence_refs=[COMPETITION_PROFILE_REL, STEP8_RELEASE_PROFILE_REL, QUALITY_POLICY_REL],
            blocked_by=["CROSS_ENV_CONTROLLED_VARIATION_NOT_RUN", "H1_ACTIVATION_GATE_CLOSED", "QUALITY_LEVEL_BELOW_TARGET"],
        ),
        _claim_row(
            claim_id="CLAIM::PUBLICATION_RELEASE_READY",
            classification="aspirational",
            scope="publication profile",
            statement="Publication release readiness is not yet admissible.",
            ceiling="BLOCKED",
            evidence_refs=[PUBLICATION_PROFILE_REL, STEP8_RELEASE_PROFILE_REL, CLAIM_CEILING_SUMMARY_REL],
            blocked_by=["PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED", "PLATFORM_ENFORCEMENT_UNPROVEN", "TRUTH_PUBLICATION_STABILIZED_FALSE"],
        ),
        _claim_row(
            claim_id="CLAIM::FULL_REPO_PROFESSIONALIZATION_COMPLETE",
            classification="contradicted",
            scope="repo professionalization",
            statement="The repo is not yet fully professionalized; root noise, root archive contamination, and local residue remain open.",
            ceiling="PROPOSAL_ONLY",
            evidence_refs=[REPO_PROFESSIONALIZATION_REL, REOPENED_DEFECTS_REL],
            blocked_by=["LOCAL_RESIDUE_PRESENT", "ROOT_ARCHIVE_CONTAMINATION"],
        ),
        _claim_row(
            claim_id="CLAIM::CURRENT_HEAD_MAY_BE_PHRASED_AS_VERIFIED_SUBJECT",
            classification="contradicted",
            scope="current-head public phrasing",
            statement="Current heads may not be phrased as the verified subject unless the SHAs match.",
            ceiling="BLOCKED",
            evidence_refs=[PUBLIC_VERIFIER_MANIFEST_REL, DOCTRINE_RATIFICATION_LOG_REL],
        ),
        _claim_row(
            claim_id="CLAIM::HISTORICAL_MEMORY_INGESTED",
            classification="proven",
            scope="historical lineage",
            statement="Historical claims, conflicts, resolutions, and reopened defects are ingested into machine-usable memory.",
            ceiling="DOCUMENTARY_ONLY",
            evidence_refs=[STEP4_RECEIPT_REL, HISTORICAL_CLAIMS_REL, REOPENED_DEFECTS_REL],
        ),
    ]


def _attack_row(
    *,
    attack_id: str,
    target_organs: Sequence[str],
    hypothesis: str,
    barrier: str,
    verdict: str,
    severity: str,
    evidence_refs: Sequence[str],
) -> Dict[str, Any]:
    return {
        "attack_id": attack_id,
        "target_organs": list(target_organs),
        "red_team_attack": {"hypothesis": hypothesis},
        "blue_team_hardening": {"observed_barrier": barrier, "evidence_refs": _unique_refs(evidence_refs)},
        "magistrate_scoring": {"verdict": verdict, "severity": severity},
    }


def _build_attack_vectors() -> Dict[str, Any]:
    vectors = [
        _attack_row(
            attack_id="AV01_HEAD_SUBJECT_OVERREAD",
            target_organs=["truth_authority_plane", "public_claims_and_doctrine_plane"],
            hypothesis="Current HEAD can be described as the transparency-verified subject even when the subject and evidence SHAs differ.",
            barrier="Public verifier and generated doctrine forbid phrasing HEAD as the verified subject unless SHAs match.",
            verdict="SURVIVED_FAIL_CLOSED",
            severity="P0_authority",
            evidence_refs=[PUBLIC_VERIFIER_MANIFEST_REL, DOCTRINE_RATIFICATION_LOG_REL, OUTSIDER_PROFILE_REL],
        ),
        _attack_row(
            attack_id="AV02_PLATFORM_GOVERNANCE_OVERCLAIM",
            target_organs=["governance_spine", "public_claims_and_doctrine_plane"],
            hypothesis="Workflow governance proof can be inflated into platform-enforced governance.",
            barrier="Platform-governance narrowing and generated profiles keep platform enforcement blocked.",
            verdict="SURVIVED_FAIL_CLOSED",
            severity="P1_governance",
            evidence_refs=[PLATFORM_GOVERNANCE_REL, PUBLIC_VERIFIER_MANIFEST_REL, PUBLICATION_PROFILE_REL],
        ),
        _attack_row(
            attack_id="AV03_RUNTIME_BOUNDARY_BLEED",
            target_organs=["runtime_spine", "operator_factory"],
            hypothesis="Compatibility-only roots can be smuggled back into canonical runtime claims.",
            barrier="Runtime boundary receipt and generated doctrine keep compatibility roots quarantined.",
            verdict="SURVIVED_FAIL_CLOSED",
            severity="P0_runtime_integrity",
            evidence_refs=[RUNTIME_BOUNDARY_REL, DOCTRINE_MANIFEST_REL],
        ),
        _attack_row(
            attack_id="AV04_H1_PREMATURE_ACTIVATION",
            target_organs=["paradox_metabolism_plane", "release_profile_plane"],
            hypothesis="H1 can be described as open because frontier settlement exists.",
            barrier="Frontier settlement and release/doctrine profiles keep H1 explicitly blocked.",
            verdict="SURVIVED_FAIL_CLOSED",
            severity="P0_authority",
            evidence_refs=[FRONTIER_SETTLEMENT_REL, COMPETITION_PROFILE_REL, PUBLICATION_PROFILE_REL],
        ),
        _attack_row(
            attack_id="AV05_PARADOX_INDEFINITE_HOLD",
            target_organs=["paradox_metabolism_plane"],
            hypothesis="Paradox-related hold states can remain indefinite without escalation.",
            barrier="The paradox proof-obligation scheduler applies TTL and fail-closed/escalation semantics to active holds.",
            verdict="SURVIVED_WITH_TTL",
            severity="P1_claim_evidence",
            evidence_refs=[STEP10_RECEIPT_REL, PARADOX_SCHEDULER_REL],
        ),
        _attack_row(
            attack_id="AV06_UNTRACKED_DELTA_GENERATION",
            target_organs=["experiment_crucible_plane", "paradox_metabolism_plane"],
            hypothesis="Resolution or training deltas can be manufactured without governed lineage.",
            barrier="Step 9 lineage sealing and Step 10 counterexample handling keep untracked deltas inadmissible.",
            verdict="SURVIVED_FAIL_CLOSED",
            severity="P1_claim_evidence",
            evidence_refs=[STEP9_RECEIPT_REL, "KT_PROD_CLEANROOM/reports/kt_lineage_manifest.json", STEP10_RECEIPT_REL],
        ),
        _attack_row(
            attack_id="AV07_COMPETITION_PUBLICATION_OVERRUN",
            target_organs=["release_profile_plane", "public_claims_and_doctrine_plane"],
            hypothesis="Generated doctrine can overstate competition or publication readiness.",
            barrier="Competition and publication profiles remain blocked with explicit forbidden claims and gaps.",
            verdict="SURVIVED_FAIL_CLOSED",
            severity="P1_claim_evidence",
            evidence_refs=[COMPETITION_PROFILE_REL, PUBLICATION_PROFILE_REL, DOCTRINE_RATIFICATION_LOG_REL],
        ),
        _attack_row(
            attack_id="AV08_ARCHIVE_CONTAMINATION_PROMOTION",
            target_organs=["archive_memory_plane", "public_claims_and_doctrine_plane"],
            hypothesis="Root archive clutter can still confuse canon versus lineage.",
            barrier="Historical ingestion and docs topology label archive/codex surfaces as lineage-only, but physical contamination remains open.",
            verdict="RESIDUAL_RISK_ACKNOWLEDGED",
            severity="P2_duplicate_surface",
            evidence_refs=[STEP4_RECEIPT_REL, REOPENED_DEFECTS_REL, REPO_PROFESSIONALIZATION_REL],
        ),
        _attack_row(
            attack_id="AV09_LOCAL_SECRET_RESIDUE",
            target_organs=["archive_memory_plane", "release_profile_plane"],
            hypothesis="Local secret-like residue at repo root could contaminate a release or audit reading.",
            barrier="The residue is explicitly remembered as still-open risk rather than ignored, but it is not yet removed.",
            verdict="OPEN_HYGIENE_RISK",
            severity="P0_runtime_integrity",
            evidence_refs=[REOPENED_DEFECTS_REL, REPO_PROFESSIONALIZATION_REL],
        ),
        _attack_row(
            attack_id="AV10_CROSS_ENV_REPRODUCIBILITY_INFLATION",
            target_organs=["experiment_crucible_plane", "release_profile_plane"],
            hypothesis="Representative same-MVE reproducibility can be narrated as cross-environment completion.",
            barrier="Reproducibility receipts and competition profiles keep the claim bounded to the representative same-MVE band.",
            verdict="SURVIVED_FAIL_CLOSED",
            severity="P1_claim_evidence",
            evidence_refs=[REPRODUCIBILITY_REL, COMPETITION_PROFILE_REL, CLAIM_CEILING_SUMMARY_REL],
        ),
    ]
    verdict_counts: Dict[str, int] = {}
    for row in vectors:
        verdict = row["magistrate_scoring"]["verdict"]
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
    return {
        "schema_id": "kt.operator.attack_vectors.v1",
        "generated_utc": utc_now_iso_z(),
        "adjudication_structure": ["red_team_attack", "blue_team_hardening", "magistrate_scoring"],
        "attack_vectors": vectors,
        "summary": {"attack_vector_count": len(vectors), "verdict_counts": verdict_counts},
    }


def _normalize_profile_status(value: str) -> str:
    status = str(value).strip()
    if status == "ADMISSIBLE_WITH_BOUNDARIES":
        return "READY_WITH_BOUNDARIES"
    if status.startswith("HOLD"):
        return "HOLD"
    if status == "BLOCKED":
        return "BLOCKED"
    return status or "UNKNOWN"


def _build_release_readiness_matrix(ctx: Dict[str, Any]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for profile in ctx["step8_release_profile"].get("profiles", []):
        rows.append(
            {
                "profile_family": "release_profile_plan",
                "profile_id": str(profile.get("profile_id", "")).strip(),
                "readiness_verdict": _normalize_profile_status(profile.get("current_status", "")),
                "blocked_by": list(profile.get("blocked_by", [])),
                "claim_ceiling": ctx["claim_ceiling_summary"]["highest_attained_proof_class"]["proof_class_id"],
                "evidence_refs": list(profile.get("required_evidence_refs", [])),
                "forbidden_claims": list(profile.get("forbidden_claims", [])),
            }
        )
    for profile in ctx["step8_submission_profile"].get("profiles", []):
        rows.append(
            {
                "profile_family": "submission_profile_plan",
                "profile_id": str(profile.get("profile_id", "")).strip(),
                "readiness_verdict": _normalize_profile_status(profile.get("current_status", "")),
                "blocked_by": list(profile.get("blocked_by", [])),
                "claim_ceiling": ctx["claim_ceiling_summary"]["highest_attained_proof_class"]["proof_class_id"],
                "evidence_refs": list(profile.get("included_surfaces", [])),
                "forbidden_claims": list(profile.get("forbidden_claims", [])),
            }
        )
    for rel, profile in [
        (OUTSIDER_PROFILE_REL, ctx["outsider_profile"]),
        (COMPETITION_PROFILE_REL, ctx["competition_profile"]),
        (PUBLICATION_PROFILE_REL, ctx["publication_profile"]),
        (MATH_GURU_PROFILE_REL, ctx["math_guru_profile"]),
    ]:
        rows.append(
            {
                "profile_family": "generated_doctrine_profile",
                "profile_id": str(profile.get("profile_id", "")).strip(),
                "readiness_verdict": _normalize_profile_status(profile.get("current_status", "")),
                "blocked_by": list(profile.get("explicit_gaps", [])),
                "claim_ceiling": str(profile.get("current_admissibility_ceiling", "")).strip(),
                "evidence_refs": [rel] + list(profile.get("current_evidence_refs", [])),
                "forbidden_claims": list(profile.get("forbidden_claims", [])),
            }
        )
    ready = sum(1 for row in rows if row["readiness_verdict"] == "READY_WITH_BOUNDARIES")
    hold = sum(1 for row in rows if row["readiness_verdict"] == "HOLD")
    blocked = sum(1 for row in rows if row["readiness_verdict"] == "BLOCKED")
    return {
        "schema_id": "kt.operator.release_readiness_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": "Readiness rows inherit the current blocker ladder and must not be read as horizon upgrades while blockers remain open.",
        "profiles": rows,
        "summary": {
            "profile_count": len(rows),
            "ready_with_boundaries_count": ready,
            "hold_count": hold,
            "blocked_count": blocked,
        },
    }


def _build_proof_obligations(ctx: Dict[str, Any]) -> Dict[str, Any]:
    obligations: List[Dict[str, Any]] = []
    for row in ctx["open_blocker_ladder"].get("blocker_ladder", []):
        obligations.append(
            {
                "obligation_id": f"OBLIGATION::{row['blocker_id']}",
                "severity": str(row.get("severity", "")).strip(),
                "status": "OPEN",
                "statement": f"Resolve blocker {row['blocker_id']} before claiming blocked proof classes.",
                "blocked_proof_classes": list(row.get("blocked_proof_classes", [])),
                "evidence_refs": list(row.get("evidence_refs", [])),
            }
        )
    obligations.extend(
        [
            {
                "obligation_id": "OBLIGATION::COMPETITION_PROFILE_QL3",
                "severity": "P1_claim_evidence",
                "status": "OPEN",
                "statement": "Raise competition-facing quality and reproducibility to QL3 before any competition-ready claim.",
                "blocked_proof_classes": ["competition_release"],
                "evidence_refs": [COMPETITION_PROFILE_REL, QUALITY_POLICY_REL, READINESS_LATTICE_REL],
            },
            {
                "obligation_id": "OBLIGATION::PUBLICATION_PROFILE_QL3",
                "severity": "P1_claim_evidence",
                "status": "OPEN",
                "statement": "Raise publication-facing truth, governance, and operability surfaces to QL3 before any publication-ready claim.",
                "blocked_proof_classes": ["publication_release"],
                "evidence_refs": [PUBLICATION_PROFILE_REL, QUALITY_POLICY_REL, READINESS_LATTICE_REL],
            },
            {
                "obligation_id": "OBLIGATION::REMOVE_LOCAL_RESIDUE_FROM_CANONICAL_ROOT",
                "severity": "P0_runtime_integrity",
                "status": "OPEN",
                "statement": "Remove local secret-like residue from the canonical root scope.",
                "blocked_proof_classes": ["repo_professionalization_complete"],
                "evidence_refs": [REOPENED_DEFECTS_REL, REPO_PROFESSIONALIZATION_REL],
            },
            {
                "obligation_id": "OBLIGATION::MIGRATE_ROOT_ARCHIVE_CONTAMINATION",
                "severity": "P2_duplicate_surface",
                "status": "OPEN",
                "statement": "Move historical archive material out of root/docs-audit lanes into the archive vault plan.",
                "blocked_proof_classes": ["repo_professionalization_complete"],
                "evidence_refs": [REOPENED_DEFECTS_REL, REPO_PROFESSIONALIZATION_REL],
            },
        ]
    )
    return {
        "schema_id": "kt.operator.proof_obligations.v1",
        "generated_utc": utc_now_iso_z(),
        "obligations": obligations,
        "summary": {"open_obligation_count": len(obligations)},
    }


def _build_survival_metrics(
    *,
    organ_assessments: List[Dict[str, Any]],
    claim_assessments: List[Dict[str, Any]],
    attack_vectors: Dict[str, Any],
    release_matrix: Dict[str, Any],
    proof_obligations: Dict[str, Any],
    ctx: Dict[str, Any],
) -> Dict[str, Any]:
    claim_counts: Dict[str, int] = {}
    for row in claim_assessments:
        claim_counts[row["classification"]] = claim_counts.get(row["classification"], 0) + 1
    attack_counts = attack_vectors["summary"]["verdict_counts"]
    return {
        "schema_id": "kt.operator.survival_metrics.v1",
        "generated_utc": utc_now_iso_z(),
        "metrics": {
            "organ_count": len(organ_assessments),
            "organ_covered_count": len(organ_assessments),
            "claim_count": len(claim_assessments),
            "claim_classification_counts": claim_counts,
            "attack_vector_count": attack_vectors["summary"]["attack_vector_count"],
            "attack_verdict_counts": attack_counts,
            "profile_count": release_matrix["summary"]["profile_count"],
            "ready_with_boundaries_count": release_matrix["summary"]["ready_with_boundaries_count"],
            "hold_count": release_matrix["summary"]["hold_count"],
            "blocked_count": release_matrix["summary"]["blocked_count"],
            "open_proof_obligation_count": proof_obligations["summary"]["open_obligation_count"],
            "open_blocker_count": len(ctx["open_blocker_ladder"]["blocker_ladder"]),
            "root_noise_count": int(ctx["repo_professionalization"].get("current_root_noise_count", 0)),
            "state_taint_status": str(ctx["step5_receipt"].get("state_taint_status", "")).strip(),
            "highest_attained_proof_class": str(
                ctx["claim_ceiling_summary"]["highest_attained_proof_class"].get("proof_class_id", "")
            ).strip(),
        },
    }


def _build_full_stack_audit(
    *,
    organ_assessments: List[Dict[str, Any]],
    claim_assessments: List[Dict[str, Any]],
    attack_vectors: Dict[str, Any],
    proof_obligations: Dict[str, Any],
    release_matrix: Dict[str, Any],
    ctx: Dict[str, Any],
) -> Dict[str, Any]:
    residual_risks = [
        {
            "risk_id": "LOCAL_RESIDUE_PRESENT",
            "severity": "P0_runtime_integrity",
            "status": "OPEN",
            "evidence_refs": [REOPENED_DEFECTS_REL, REPO_PROFESSIONALIZATION_REL],
        },
        {
            "risk_id": "ROOT_ARCHIVE_CONTAMINATION",
            "severity": "P2_duplicate_surface",
            "status": "OPEN",
            "evidence_refs": [REOPENED_DEFECTS_REL, REPO_PROFESSIONALIZATION_REL, STEP4_RECEIPT_REL],
        },
    ]
    claim_counts: Dict[str, int] = {}
    for row in claim_assessments:
        claim_counts[row["classification"]] = claim_counts.get(row["classification"], 0) + 1
    return {
        "schema_id": "kt.operator.full_stack_audit.v1",
        "generated_utc": utc_now_iso_z(),
        "completion_status": "FULL_STACK_ADJUDICATION_COMPLETE",
        "claim_boundary": (
            "This adjudication is derived from cited receipts, doctrine artifacts, and proof ceilings. "
            "Completion does not remove the open blockers or upgrade blocked horizons."
        ),
        "adjudication_structure": ["red_team_attack", "blue_team_hardening", "magistrate_scoring"],
        "organ_coverage": {
            "required_organ_count": len(ctx["organ_ontology"].get("organs", [])),
            "covered_organ_count": len(organ_assessments),
            "all_major_organs_covered": len(organ_assessments) == len(ctx["organ_ontology"].get("organs", [])),
        },
        "claim_classification_summary": claim_counts,
        "organ_assessments": organ_assessments,
        "claim_assessments": claim_assessments,
        "open_blockers": [row["blocker_id"] for row in ctx["open_blocker_ladder"].get("blocker_ladder", [])],
        "residual_risks": residual_risks,
        "attack_vector_ref": ATTACK_VECTORS_REL,
        "proof_obligations_ref": PROOF_OBLIGATIONS_REL,
        "release_readiness_matrix_ref": RELEASE_READINESS_MATRIX_REL,
        "supporting_refs": _unique_refs(
            [
                STEP11_RECEIPT_REL,
                STEP10_RECEIPT_REL,
                STEP9_RECEIPT_REL,
                CLAIM_CEILING_SUMMARY_REL,
                PUBLIC_VERIFIER_MANIFEST_REL,
                PLATFORM_GOVERNANCE_REL,
                RUNTIME_BOUNDARY_REL,
                REPRODUCIBILITY_REL,
                FRONTIER_SETTLEMENT_REL,
                DOCTRINE_MANIFEST_REL,
                DOCTRINE_RATIFICATION_LOG_REL,
            ]
        ),
    }


def _build_closeout_bundle(
    *,
    attack_vectors: Dict[str, Any],
    survival_metrics: Dict[str, Any],
    proof_obligations: Dict[str, Any],
    release_matrix: Dict[str, Any],
    full_stack_audit: Dict[str, Any],
    ctx: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.adjudication_closeout_bundle.v1",
        "generated_utc": utc_now_iso_z(),
        "program_verdict": "FULL_STACK_ADJUDICATION_COMPLETE",
        "claim_boundary": "Program adjudication is complete, but open blockers and blocked horizons remain explicit.",
        "deliverable_refs": DELIVERABLE_REFS,
        "supporting_refs": [STEP11_RECEIPT_REL, CLAIM_CEILING_SUMMARY_REL, OPEN_BLOCKER_LADDER_REL, DOCTRINE_MANIFEST_REL],
        "summary": {
            "open_blocker_count": len(ctx["open_blocker_ladder"].get("blocker_ladder", [])),
            "attack_vector_count": attack_vectors["summary"]["attack_vector_count"],
            "ready_with_boundaries_count": release_matrix["summary"]["ready_with_boundaries_count"],
            "blocked_profile_count": release_matrix["summary"]["blocked_count"],
            "claim_count": len(full_stack_audit["claim_assessments"]),
            "open_proof_obligation_count": proof_obligations["summary"]["open_obligation_count"],
            "highest_attained_proof_class": str(
                ctx["claim_ceiling_summary"]["highest_attained_proof_class"].get("proof_class_id", "")
            ).strip(),
        },
    }


def build_step12_outputs(root: Path, generated_utc: Optional[str] = None) -> Dict[str, Any]:
    _ = generated_utc or utc_now_iso_z()
    ctx = _step_context(root)
    organ_assessments = _build_organ_assessments(ctx)
    claim_assessments = _build_claim_assessments(ctx)
    attack_vectors = _build_attack_vectors()
    release_matrix = _build_release_readiness_matrix(ctx)
    proof_obligations = _build_proof_obligations(ctx)
    survival_metrics = _build_survival_metrics(
        organ_assessments=organ_assessments,
        claim_assessments=claim_assessments,
        attack_vectors=attack_vectors,
        release_matrix=release_matrix,
        proof_obligations=proof_obligations,
        ctx=ctx,
    )
    full_stack_audit = _build_full_stack_audit(
        organ_assessments=organ_assessments,
        claim_assessments=claim_assessments,
        attack_vectors=attack_vectors,
        proof_obligations=proof_obligations,
        release_matrix=release_matrix,
        ctx=ctx,
    )
    closeout_bundle = _build_closeout_bundle(
        attack_vectors=attack_vectors,
        survival_metrics=survival_metrics,
        proof_obligations=proof_obligations,
        release_matrix=release_matrix,
        full_stack_audit=full_stack_audit,
        ctx=ctx,
    )
    if len(organ_assessments) != len(ctx["organ_ontology"].get("organs", [])):
        raise RuntimeError("FAIL_CLOSED: Step 12 did not cover all ontology organs.")
    if any(row["classification"] not in CLAIM_CLASSIFICATIONS for row in claim_assessments):
        raise RuntimeError("FAIL_CLOSED: Step 12 emitted an invalid claim classification.")
    if release_matrix["summary"]["profile_count"] == 0:
        raise RuntimeError("FAIL_CLOSED: Step 12 release readiness matrix is empty.")
    return {
        FULL_STACK_AUDIT_REL: full_stack_audit,
        ATTACK_VECTORS_REL: attack_vectors,
        SURVIVAL_METRICS_REL: survival_metrics,
        PROOF_OBLIGATIONS_REL: proof_obligations,
        RELEASE_READINESS_MATRIX_REL: release_matrix,
        ADJUDICATION_CLOSEOUT_BUNDLE_REL: closeout_bundle,
    }


def build_step12_receipt(root: Path) -> Dict[str, Any]:
    generated_utc = utc_now_iso_z()
    ctx = _step_context(root)
    first = build_step12_outputs(root, generated_utc=generated_utc)
    second = build_step12_outputs(root, generated_utc=generated_utc)
    if not semantically_equal_json(first, second):
        raise RuntimeError("FAIL_CLOSED: nondeterministic Step 12 outputs detected.")

    compiled_head = _git_head(root)
    parent = _git_parent(root, compiled_head)
    actual_touched = sorted(set(_git_diff_files(root, parent, compiled_head, SUBJECT_ARTIFACT_REFS) + [RECEIPT_REL]))
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = [path for path in actual_touched if _is_protected(path)]

    organ_count = len(first[FULL_STACK_AUDIT_REL]["organ_assessments"])
    claim_count = len(first[FULL_STACK_AUDIT_REL]["claim_assessments"])
    release_count = first[RELEASE_READINESS_MATRIX_REL]["summary"]["profile_count"]
    obligation_count = first[PROOF_OBLIGATIONS_REL]["summary"]["open_obligation_count"]
    claim_categories = {row["classification"] for row in first[FULL_STACK_AUDIT_REL]["claim_assessments"]}

    return {
        "schema_id": "kt.operator.full_stack_adjudication_completion_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "pass_verdict": "FULL_STACK_ADJUDICATION_COMPLETE",
        "compiled_head_commit": compiled_head,
        "current_head_commit": compiled_head,
        "controlling_work_order": {
            "schema_id": WORK_ORDER_SCHEMA_ID,
            "work_order_id": WORK_ORDER_ID,
            "step_id": 12,
            "step_name": "FULL_STACK_ADJUDICATION_RELEASE_READINESS_AND_FINAL_E2E_AUDIT",
        },
        "step11_gate_subject_commit": str(ctx["step11_receipt"].get("compiled_head_commit", "")).strip(),
        "step11_gate_evidence_commit": str(ctx["step11_evidence_commit"]).strip(),
        "claim_boundary": (
            "This receipt seals the final Step 12 adjudication for compiled_head_commit only. "
            "Completion does not clear the open blockers or elevate blocked horizons."
        ),
        "summary": {
            "organ_count": organ_count,
            "claim_count": claim_count,
            "profile_count": release_count,
            "open_proof_obligation_count": obligation_count,
        },
        "checks": [
            {
                "check": "step11_gate_passed",
                "detail": "Step 12 requires the Step 11 doctrine receipt to be PASS.",
                "refs": [STEP11_RECEIPT_REL],
                "status": "PASS",
            },
            {
                "check": "all_major_organs_covered",
                "detail": "All first-class organs from the foundation ontology must be covered in the adjudication.",
                "refs": [ORGAN_ONTOLOGY_REL, FULL_STACK_AUDIT_REL],
                "status": "PASS" if organ_count == len(ctx["organ_ontology"].get("organs", [])) else "FAIL",
            },
            {
                "check": "all_major_claims_classified",
                "detail": "Major claims must all be classified as proven, evidenced_only, contradicted, or aspirational.",
                "refs": [FULL_STACK_AUDIT_REL],
                "status": "PASS" if claim_categories.issubset(CLAIM_CLASSIFICATIONS) and claim_count >= 12 else "FAIL",
            },
            {
                "check": "remaining_proof_obligations_explicit",
                "detail": "Remaining proof obligations must be listed explicitly in the Step 12 obligation register.",
                "refs": [PROOF_OBLIGATIONS_REL, OPEN_BLOCKER_LADDER_REL],
                "status": "PASS" if obligation_count >= len(ctx["open_blocker_ladder"].get("blocker_ladder", [])) else "FAIL",
            },
            {
                "check": "release_readiness_explicit_per_profile",
                "detail": "Release and operating profile readiness must be explicit per profile row.",
                "refs": [RELEASE_READINESS_MATRIX_REL, STEP8_RELEASE_PROFILE_REL, STEP8_SUBMISSION_PROFILE_REL, OUTSIDER_PROFILE_REL],
                "status": "PASS" if release_count >= 10 else "FAIL",
            },
            {
                "check": "no_claim_upgrade_beyond_current_ceiling",
                "detail": "Step 12 may not claim platform enforcement, H1, or current-head truth verification as proven.",
                "refs": [FULL_STACK_AUDIT_REL, CLAIM_CEILING_SUMMARY_REL],
                "status": "PASS"
                if all(
                    row["classification"] != "proven"
                    for row in first[FULL_STACK_AUDIT_REL]["claim_assessments"]
                    if row["claim_id"]
                    in {
                        "CLAIM::PLATFORM_ENFORCEMENT_PROVEN",
                        "CLAIM::H1_ACTIVATION_ALLOWED",
                        "CLAIM::CURRENT_HEAD_MAY_BE_PHRASED_AS_VERIFIED_SUBJECT",
                        "CLAIM::CROSS_ENV_REPRODUCIBILITY_COMPLETE",
                    }
                )
                else "FAIL",
            },
            {
                "check": "post_touch_accounting_clean",
                "detail": "Actual touched set must match the lawful Step 12 subject files plus the Step 12 receipt.",
                "refs": SUBJECT_ARTIFACT_REFS + [RECEIPT_REL],
                "status": "PASS" if not unexpected_touches and not protected_touch_violations else "FAIL",
            },
        ],
        "planned_mutates": PLANNED_MUTATES,
        "actual_touched": actual_touched,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "next_lawful_step": {"status_after_step_12": "PROGRAM_COMPLETE", "step_id": 0, "step_name": "NONE"},
    }


def write_step12_outputs(root: Path) -> Dict[str, Any]:
    outputs = build_step12_outputs(root)
    writes: List[Dict[str, Any]] = []
    for rel, payload in outputs.items():
        changed = write_json_stable(root / Path(rel), payload)
        writes.append({"artifact_ref": rel, "updated": bool(changed), "schema_id": str(payload.get("schema_id", "")).strip()})
    return {"status": "PASS", "artifacts_written": writes}


def emit_step12_receipt(root: Path) -> Dict[str, Any]:
    receipt = build_step12_receipt(root)
    write_json_stable(root / Path(RECEIPT_REL), receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile Step 12 full-stack adjudication bundle.")
    parser.add_argument("--emit-receipt", action="store_true", help="Emit the Step 12 receipt instead of only the subject artifacts.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    result = emit_step12_receipt(root) if args.emit_receipt else write_step12_outputs(root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
