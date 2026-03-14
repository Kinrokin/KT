from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Optional, Sequence, Tuple

import jsonschema

from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
WORK_ORDER_REL = "KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V2/WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION.v2.json"
STEP6_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_graph_and_catalog_compilation_receipt.json"
CLAIM_TAXONOMY_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_claim_taxonomy.json"
STATE_VECTOR_SCHEMA_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_state_vector.schema.json"
ORGAN_ONTOLOGY_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_organ_ontology.json"
CONSTITUTION_MANIFEST_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_constitution_manifest.json"
SELF_DESCRIPTION_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_self_description.json"
QUALITY_POLICY_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_quality_policy.json"
READINESS_LATTICE_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_readiness_lattice.json"

GOVERNANCE_BASELINE_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_governance_baseline_ingestion_receipt.json"
HISTORICAL_MEMORY_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_historical_memory_ingestion_receipt.json"
CLAIM_CEILING_SUMMARY_REL = f"{REPORT_ROOT_REL}/kt_claim_ceiling_summary.json"
OPEN_BLOCKER_LADDER_REL = f"{REPORT_ROOT_REL}/kt_open_blocker_ladder.json"
WS0_WS11_SUMMARY_REL = f"{REPORT_ROOT_REL}/ws0_ws11_closeout_summary.json"
PUBLIC_VERIFIER_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
PLATFORM_GOVERNANCE_REL = f"{REPORT_ROOT_REL}/platform_governance_narrowing_receipt.json"
RUNTIME_BOUNDARY_REL = f"{REPORT_ROOT_REL}/runtime_boundary_integrity_receipt.json"
REPRODUCIBILITY_REL = f"{REPORT_ROOT_REL}/representative_authority_lane_reproducibility_receipt.json"
FRONTIER_SETTLEMENT_REL = f"{REPORT_ROOT_REL}/frontier_settlement_receipt.json"
H1_GATE_REL = f"{REPORT_ROOT_REL}/h1_activation_gate_receipt.json"
COMMERCIAL_COMPILER_REL = f"{REPORT_ROOT_REL}/commercial_claim_compiler_receipt.json"
CRYPTO_PUBLICATION_REL = f"{REPORT_ROOT_REL}/cryptographic_publication_receipt.json"
SETTLED_TRUTH_SOURCE_REL = f"{REPORT_ROOT_REL}/settled_truth_source_receipt.json"
AUTHORITY_CONVERGENCE_REL = f"{REPORT_ROOT_REL}/authority_convergence_receipt.json"
PUBLISHED_HEAD_SELF_CONVERGENCE_REL = f"{REPORT_ROOT_REL}/published_head_self_convergence_receipt.json"
HISTORICAL_CLAIMS_REL = f"{REPORT_ROOT_REL}/kt_historical_claims.json"
HISTORICAL_CONFLICTS_REL = f"{REPORT_ROOT_REL}/kt_historical_conflicts.json"
HISTORICAL_RESOLUTIONS_REL = f"{REPORT_ROOT_REL}/kt_historical_resolutions.json"
REOPENED_DEFECT_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_reopened_defect_register.json"
DATA_LINEAGE_REL = f"{REPORT_ROOT_REL}/kt_data_lineage.json"
ADAPTER_REGISTRY_REL = f"{REPORT_ROOT_REL}/kt_adapter_registry.json"
MODEL_REGISTRY_REL = f"{REPORT_ROOT_REL}/kt_model_registry.json"
SECTOR_REGISTRY_REL = f"{REPORT_ROOT_REL}/kt_sector_harness_registry.json"

CLAIMS_RAW_REL = f"{REPORT_ROOT_REL}/kt_claims_raw.json"
CLAIM_REGISTRY_REL = f"{REPORT_ROOT_REL}/kt_claim_registry.json"
RULE_RESULTS_REL = f"{REPORT_ROOT_REL}/kt_rule_results.json"
CONFLICT_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_conflict_register.json"
COUNTEREXAMPLE_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_counterexample_register.json"
CLAIM_EVIDENCE_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_claim_evidence_matrix.json"
STATE_VECTOR_REL = f"{REPORT_ROOT_REL}/kt_state_vector.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_judgment_plane_computation_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/claim_judgment_compile.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_claim_judgment_compile.py"

DELIVERABLE_REFS = [
    CLAIMS_RAW_REL,
    CLAIM_REGISTRY_REL,
    RULE_RESULTS_REL,
    CONFLICT_REGISTER_REL,
    COUNTEREXAMPLE_REGISTER_REL,
    CLAIM_EVIDENCE_MATRIX_REL,
    STATE_VECTOR_REL,
]
SUBJECT_ARTIFACT_REFS = DELIVERABLE_REFS + [TOOL_REL, TEST_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

WORK_ORDER_ID = "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION"
WORK_ORDER_SCHEMA_ID = "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2"

PROTECTED_PREFIXES = (
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "kt_truth_ledger:",
    ".github/workflows/",
    "KT_PROD_CLEANROOM/docs/commercial/",
)

CONFLICT_SEVERITY_ORDER = {
    "P0_authority": 1,
    "P0_runtime_integrity": 2,
    "P1_governance": 3,
    "P1_claim_evidence": 4,
    "P2_schema_drift": 5,
    "P2_duplicate_surface": 6,
    "P3_doc_staleness": 7,
}

ORGAN_STATUS_MAP = {
    "governance_spine": ("QL2", "WORKFLOW_GOVERNANCE_ONLY_EVIDENCED", ["PLATFORM_ENFORCEMENT_UNPROVEN"]),
    "constitutional_meta_governance": ("QL2", "RATIFIED_PLATFORM_LIMITED", ["PLATFORM_ENFORCEMENT_UNPROVEN"]),
    "truth_authority_plane": (
        "QL2",
        "SUBJECT_ONLY_EVIDENCED_CURRENT_HEAD_UNSETTLED",
        [
            "AUTHORITY_CONVERGENCE_UNRESOLVED",
            "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED",
            "TRUTH_PUBLICATION_STABILIZED_FALSE",
        ],
    ),
    "runtime_spine": ("QL3", "CANONICAL_BOUNDARY_SETTLED", []),
    "operator_factory": (
        "QL2",
        "BOUNDARY_ENFORCING_OUTPUTS_ACTIVE",
        ["AUTHORITY_CONVERGENCE_UNRESOLVED", "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED"],
    ),
    "verification_delivery_security_plane": ("QL2", "TRANSPARENCY_SUBJECT_PUBLISHED", []),
    "lab_adaptation_plane": ("QL1", "PROMOTION_REQUIRED_BEFORE_CANON", []),
    "experiment_crucible_plane": (
        "QL2",
        "REPRESENTATIVE_ONLY_PROVEN",
        ["CROSS_ENV_CONTROLLED_VARIATION_NOT_RUN", "DELTA_LINEAGE_MISSING"],
    ),
    "paradox_metabolism_plane": ("QL1", "FRONTIER_EVALUATED_FORMAL_BOUND_PENDING", ["PARADOX_PROGRAM_UNBOUNDED"]),
    "public_claims_and_doctrine_plane": ("QL2", "CLAIM_BOUNDARY_ENFORCED", []),
    "commercial_surface_plane": ("QL2", "DOCUMENTARY_BOUNDARY_ENFORCED", []),
    "archive_memory_plane": ("QL1", "LINEAGE_MEMORY_INGESTED", ["ROOT_ARCHIVE_CONTAMINATION"]),
    "release_profile_plane": ("QL1", "BOUNDED_RELEASE_PROFILES_ONLY", ["H1_ACTIVATION_GATE_CLOSED"]),
    "adjudication_plane": (
        "QL2",
        "SEALED_BASELINE_PRE_FINAL_ADJUDICATION",
        [
            "AUTHORITY_CONVERGENCE_UNRESOLVED",
            "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED",
            "H1_ACTIVATION_GATE_CLOSED",
        ],
    ),
}

FUTURE_STEP_ARTIFACTS = {
    "experiment_lineage": [
        "KT_PROD_CLEANROOM/reports/kt_experiment_registry.json",
        "KT_PROD_CLEANROOM/reports/kt_learning_delta_register.json",
        "KT_PROD_CLEANROOM/reports/kt_receipt_lineage_register.json",
    ],
    "paradox_program": [
        "KT_PROD_CLEANROOM/reports/kt_paradox_models.tla",
        "KT_PROD_CLEANROOM/reports/kt_paradox_stress_results.json",
        "KT_PROD_CLEANROOM/reports/kt_paradox_counterexamples.json",
    ],
    "doctrine_generation": [
        "KT_PROD_CLEANROOM/reports/kt_doctrine_manifest.json",
        "KT_PROD_CLEANROOM/reports/kt_doctrine_ratification_log.json",
        "KT_PROD_CLEANROOM/reports/kt_doctrine_compiler_spec.json",
    ],
    "canon_normalization": [
        "KT_PROD_CLEANROOM/reports/kt_canon_proposal.json",
        "KT_PROD_CLEANROOM/reports/kt_normalization_work_order.json",
        "KT_PROD_CLEANROOM/reports/kt_repo_professionalization_plan.json",
    ],
    "full_stack_adjudication": [
        "KT_PROD_CLEANROOM/reports/kt_full_stack_audit.json",
        "KT_PROD_CLEANROOM/reports/kt_release_readiness_matrix.json",
        "KT_PROD_CLEANROOM/reports/kt_adjudication_closeout_bundle.json",
    ],
}


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


def _missing_artifact_refs(root: Path, refs: Sequence[str]) -> List[str]:
    return [ref for ref in refs if not (root / Path(ref)).exists()]


def _step_context(root: Path) -> Dict[str, Any]:
    step6 = _load_required(root, STEP6_RECEIPT_REL)
    if str(step6.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 7 is blocked until Step 6 graph and catalog compilation is PASS.")

    return {
        "step6_receipt": step6,
        "work_order": _load_required(root, WORK_ORDER_REL),
        "claim_taxonomy": _load_required(root, CLAIM_TAXONOMY_REL),
        "state_vector_schema": _load_required(root, STATE_VECTOR_SCHEMA_REL),
        "organ_ontology": _load_required(root, ORGAN_ONTOLOGY_REL),
        "constitution_manifest": _load_required(root, CONSTITUTION_MANIFEST_REL),
        "self_description": _load_required(root, SELF_DESCRIPTION_REL),
        "quality_policy": _load_required(root, QUALITY_POLICY_REL),
        "readiness_lattice": _load_required(root, READINESS_LATTICE_REL),
        "governance_baseline_receipt": _load_required(root, GOVERNANCE_BASELINE_RECEIPT_REL),
        "historical_memory_receipt": _load_required(root, HISTORICAL_MEMORY_RECEIPT_REL),
        "claim_ceiling_summary": _load_required(root, CLAIM_CEILING_SUMMARY_REL),
        "open_blocker_ladder": _load_required(root, OPEN_BLOCKER_LADDER_REL),
        "ws0_ws11_summary": _load_required(root, WS0_WS11_SUMMARY_REL),
        "public_verifier": _load_required(root, PUBLIC_VERIFIER_REL),
        "platform_governance": _load_required(root, PLATFORM_GOVERNANCE_REL),
        "runtime_boundary": _load_required(root, RUNTIME_BOUNDARY_REL),
        "reproducibility": _load_required(root, REPRODUCIBILITY_REL),
        "frontier_settlement": _load_required(root, FRONTIER_SETTLEMENT_REL),
        "h1_gate": _load_required(root, H1_GATE_REL),
        "commercial_compiler": _load_required(root, COMMERCIAL_COMPILER_REL),
        "cryptographic_publication": _load_required(root, CRYPTO_PUBLICATION_REL),
        "settled_truth_source": _load_required(root, SETTLED_TRUTH_SOURCE_REL),
        "authority_convergence": _load_required(root, AUTHORITY_CONVERGENCE_REL),
        "published_head_self_convergence": _load_required(root, PUBLISHED_HEAD_SELF_CONVERGENCE_REL),
        "historical_claims": _load_required(root, HISTORICAL_CLAIMS_REL),
        "historical_conflicts": _load_required(root, HISTORICAL_CONFLICTS_REL),
        "historical_resolutions": _load_required(root, HISTORICAL_RESOLUTIONS_REL),
        "reopened_defects": _load_required(root, REOPENED_DEFECT_REGISTER_REL),
        "data_lineage": _load_required(root, DATA_LINEAGE_REL),
        "adapter_registry": _load_required(root, ADAPTER_REGISTRY_REL),
        "model_registry": _load_required(root, MODEL_REGISTRY_REL),
        "sector_registry": _load_required(root, SECTOR_REGISTRY_REL),
    }


def _slug(value: str) -> str:
    out = "".join(ch.lower() if ch.isalnum() else "_" for ch in value)
    while "__" in out:
        out = out.replace("__", "_")
    return out.strip("_") or "claim"


def _claim_class_for_summary(statement: str, evidence_refs: Sequence[str], scope: str) -> str:
    joined = " ".join([statement, scope, " ".join(evidence_refs)]).lower()
    if "runtime boundary" in joined or "canonical runtime" in joined:
        return "runtime_boundary_claim"
    if "workflow governance" in joined or "platform governance" in joined or "legitimacy" in joined:
        return "governance_legitimacy_claim"
    if "commercial" in joined:
        return "commercial_surface_claim"
    if "reproducibility" in joined or "same mve" in joined or "authority-lane" in joined:
        return "reproducibility_claim"
    if "frontier settlement" in joined or "h1" in joined or "activation" in joined:
        return "release_readiness_claim"
    if "transparency-verified" in joined or "cryptographic publication" in joined:
        return "transparency_publication_claim"
    return "truth_authority_claim"


def _append_raw_claim(
    raw_claims: List[Dict[str, Any]],
    counts: Counter[str],
    *,
    claim_id: str,
    claim_class_id: str,
    source_ref: str,
    plane: str,
    claim_text: str,
    surface_status: str,
    evidence_refs: Sequence[str],
    source_epoch: str,
    extracted_from: str,
) -> None:
    source = _normalize_ref(source_ref)
    refs = sorted({_normalize_ref(ref) for ref in evidence_refs if _normalize_ref(ref)})
    raw_claims.append(
        {
            "claim_id": claim_id,
            "claim_class_id": claim_class_id,
            "source_ref": source,
            "plane": plane,
            "claim_text": claim_text,
            "surface_status": surface_status,
            "evidence_refs": refs,
            "source_epoch": source_epoch,
            "extracted_from": extracted_from,
        }
    )
    counts[source] += 1


def _build_raw_claims(ctx: Dict[str, Any], root: Path, *, generated_utc: str) -> Dict[str, Any]:
    raw_claims: List[Dict[str, Any]] = []
    source_counts: Counter[str] = Counter()
    summary = ctx["ws0_ws11_summary"]

    for section_name in ("proven", "not_proven"):
        for index, row in enumerate(summary.get(section_name, []), start=1):
            if not isinstance(row, dict):
                continue
            statement = str(row.get("statement", "")).strip()
            scope = str(row.get("scope", "")).strip()
            evidence_refs = [str(ref) for ref in row.get("evidence_refs", []) if str(ref).strip()]
            claim_class_id = _claim_class_for_summary(statement, evidence_refs, scope)
            _append_raw_claim(
                raw_claims,
                source_counts,
                claim_id=f"STEP7_CLOSEOUT_{section_name.upper()}_{index:02d}",
                claim_class_id=claim_class_id,
                source_ref=WS0_WS11_SUMMARY_REL,
                plane="judgment_plane",
                claim_text=statement,
                surface_status=section_name,
                evidence_refs=[WS0_WS11_SUMMARY_REL, *evidence_refs],
                source_epoch="ws0_ws11_closeout",
                extracted_from="ws0_ws11_closeout_summary",
            )

    for domain_id, row in sorted((ctx["claim_ceiling_summary"].get("current_ceiling_by_domain") or {}).items()):
        if not isinstance(row, dict):
            continue
        _append_raw_claim(
            raw_claims,
            source_counts,
            claim_id=f"STEP7_CEILING_{_slug(domain_id).upper()}",
            claim_class_id={
                "truth_subject": "truth_authority_claim",
                "governance": "governance_legitimacy_claim",
                "runtime_boundary": "runtime_boundary_claim",
                "reproducibility": "reproducibility_claim",
                "activation": "release_readiness_claim",
            }.get(domain_id, "truth_authority_claim"),
            source_ref=CLAIM_CEILING_SUMMARY_REL,
            plane="judgment_plane",
            claim_text=f"Current admissibility ceiling for {domain_id} is {row.get('ceiling_id', '')}.",
            surface_status="current_ceiling",
            evidence_refs=[CLAIM_CEILING_SUMMARY_REL, str(row.get("evidence_commit", "")).strip()],
            source_epoch="step1_governance_baseline",
            extracted_from="claim_ceiling_summary",
        )

    for index, row in enumerate(ctx["claim_ceiling_summary"].get("unattained_proof_classes", []), start=1):
        if not isinstance(row, dict):
            continue
        _append_raw_claim(
            raw_claims,
            source_counts,
            claim_id=f"STEP7_UNATTAINED_PROOF_{index:02d}",
            claim_class_id={
                "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN": "truth_authority_claim",
                "PLATFORM_ENFORCEMENT_PROVEN": "governance_legitimacy_claim",
                "CROSS_ENV_CONTROLLED_VARIATION_COMPLETE": "reproducibility_claim",
                "H1_SINGLE_ADAPTER_ALLOWED": "release_readiness_claim",
            }.get(str(row.get("proof_class_id", "")).strip(), "truth_authority_claim"),
            source_ref=CLAIM_CEILING_SUMMARY_REL,
            plane="proof_plane",
            claim_text=f"Proof class {row.get('proof_class_id', '')} is not yet attained.",
            surface_status="unattained",
            evidence_refs=[CLAIM_CEILING_SUMMARY_REL],
            source_epoch="step1_governance_baseline",
            extracted_from="claim_ceiling_summary",
        )

    manifest = ctx["public_verifier"]
    _append_raw_claim(
        raw_claims,
        source_counts,
        claim_id="STEP7_TRUTH_SUBJECT_TRANSPARENCY_VERIFIED",
        claim_class_id="transparency_publication_claim",
        source_ref=PUBLIC_VERIFIER_REL,
        plane="proof_plane",
        claim_text=f"Truth subject commit {manifest.get('truth_subject_commit', '')} is transparency-verified while evidence commit remains separate.",
        surface_status=str(manifest.get("subject_verdict", "")).strip() or "observed",
        evidence_refs=[PUBLIC_VERIFIER_REL, CRYPTO_PUBLICATION_REL],
        source_epoch="ws6_ws7",
        extracted_from="public_verifier_manifest",
    )
    _append_raw_claim(
        raw_claims,
        source_counts,
        claim_id="STEP7_HEAD_SUBJECT_LAG_IS_TYPED",
        claim_class_id="truth_authority_claim",
        source_ref=PUBLIC_VERIFIER_REL,
        plane="judgment_plane",
        claim_text="Current HEAD contains evidence for the truth subject commit but is not itself the truth subject unless SHAs match.",
        surface_status="bounded",
        evidence_refs=[PUBLIC_VERIFIER_REL],
        source_epoch="ws7",
        extracted_from="public_verifier_manifest",
    )
    _append_raw_claim(
        raw_claims,
        source_counts,
        claim_id="STEP7_PLATFORM_GOVERNANCE_WORKFLOW_ONLY",
        claim_class_id="governance_legitimacy_claim",
        source_ref=PLATFORM_GOVERNANCE_REL,
        plane="judgment_plane",
        claim_text="Workflow governance is evidenced, but platform-enforced governance remains unproven.",
        surface_status=str(ctx["platform_governance"].get("workflow_governance_status", "")).strip() or "observed",
        evidence_refs=[PLATFORM_GOVERNANCE_REL, PUBLIC_VERIFIER_REL],
        source_epoch="ws9",
        extracted_from="platform_governance_narrowing_receipt",
    )
    _append_raw_claim(
        raw_claims,
        source_counts,
        claim_id="STEP7_RUNTIME_BOUNDARY_SETTLED",
        claim_class_id="runtime_boundary_claim",
        source_ref=RUNTIME_BOUNDARY_REL,
        plane="proof_plane",
        claim_text="Canonical runtime roots are settled and compatibility-only roots remain quarantined.",
        surface_status=str(ctx["runtime_boundary"].get("status", "")).strip() or "observed",
        evidence_refs=[RUNTIME_BOUNDARY_REL],
        source_epoch="ws10",
        extracted_from="runtime_boundary_integrity_receipt",
    )
    _append_raw_claim(
        raw_claims,
        source_counts,
        claim_id="STEP7_REPRODUCIBILITY_REPRESENTATIVE_ONLY",
        claim_class_id="reproducibility_claim",
        source_ref=REPRODUCIBILITY_REL,
        plane="proof_plane",
        claim_text="Representative authority-lane reproducibility is proven on the same MVE, but cross-environment controlled variation is not complete.",
        surface_status=str(ctx["reproducibility"].get("status", "")).strip() or "observed",
        evidence_refs=[REPRODUCIBILITY_REL],
        source_epoch="ws8",
        extracted_from="representative_authority_lane_reproducibility_receipt",
    )
    _append_raw_claim(
        raw_claims,
        source_counts,
        claim_id="STEP7_COMMERCIAL_SURFACE_DOCUMENTARY_ONLY",
        claim_class_id="commercial_surface_claim",
        source_ref=COMMERCIAL_COMPILER_REL,
        plane="operability_plane",
        claim_text="Commercial surfaces are documentary-only and bound to machine evidence receipts.",
        surface_status=str(ctx["commercial_compiler"].get("status", "")).strip() or "observed",
        evidence_refs=[COMMERCIAL_COMPILER_REL, PUBLIC_VERIFIER_REL, RUNTIME_BOUNDARY_REL],
        source_epoch="ws10",
        extracted_from="commercial_claim_compiler_receipt",
    )
    _append_raw_claim(
        raw_claims,
        source_counts,
        claim_id="STEP7_FRONTIER_SETTLED_H1_BLOCKED",
        claim_class_id="release_readiness_claim",
        source_ref=FRONTIER_SETTLEMENT_REL,
        plane="proof_plane",
        claim_text="Frontier settlement completed as evaluation, but H1 remains blocked.",
        surface_status=str(ctx["frontier_settlement"].get("status", "")).strip() or "observed",
        evidence_refs=[FRONTIER_SETTLEMENT_REL, H1_GATE_REL],
        source_epoch="ws11",
        extracted_from="frontier_settlement_receipt",
    )
    _append_raw_claim(
        raw_claims,
        source_counts,
        claim_id="STEP7_PARADOX_BOUNDING_STILL_FUTURE",
        claim_class_id="paradox_bound_claim",
        source_ref=WORK_ORDER_REL,
        plane="proof_plane",
        claim_text="Paradox metabolism verification remains a future bounded-program obligation and is not yet sealed by dedicated paradox artifacts.",
        surface_status="planned",
        evidence_refs=[WORK_ORDER_REL, FRONTIER_SETTLEMENT_REL],
        source_epoch="work_order_step_10",
        extracted_from="work_order",
    )
    _append_raw_claim(
        raw_claims,
        source_counts,
        claim_id="STEP7_EXPERIMENT_LINEAGE_REGISTRY_STILL_FUTURE",
        claim_class_id="experiment_lineage_claim",
        source_ref=WORK_ORDER_REL,
        plane="lineage_plane",
        claim_text="Experiment and learning-delta lineage sealing remains a future registry compilation obligation.",
        surface_status="planned",
        evidence_refs=[WORK_ORDER_REL, DATA_LINEAGE_REL, HISTORICAL_CLAIMS_REL],
        source_epoch="work_order_step_9",
        extracted_from="work_order",
    )
    _append_raw_claim(
        raw_claims,
        source_counts,
        claim_id="STEP7_DOCTRINE_COMPILER_STILL_FUTURE",
        claim_class_id="doctrine_generation_claim",
        source_ref=WORK_ORDER_REL,
        plane="operability_plane",
        claim_text="Doctrine, profiles, and external professionalization remain future machine-state generation work.",
        surface_status="planned",
        evidence_refs=[WORK_ORDER_REL, SELF_DESCRIPTION_REL, CONSTITUTION_MANIFEST_REL],
        source_epoch="work_order_step_11",
        extracted_from="work_order",
    )

    for row in ctx["historical_claims"].get("claims", []):
        if not isinstance(row, dict):
            continue
        claim_id = str(row.get("claim_id", "")).strip()
        _append_raw_claim(
            raw_claims,
            source_counts,
            claim_id=f"STEP7_{claim_id}",
            claim_class_id="historical_lineage_claim",
            source_ref=HISTORICAL_CLAIMS_REL,
            plane=str(row.get("plane", "temporal_plane")).strip() or "temporal_plane",
            claim_text=str(row.get("claim_text", "")).strip(),
            surface_status=str(row.get("claim_status", "unclear")).strip(),
            evidence_refs=[HISTORICAL_CLAIMS_REL, *[str(ref) for ref in row.get("evidence_refs", []) if str(ref).strip()]],
            source_epoch=str(row.get("source_epoch", "historical")).strip() or "historical",
            extracted_from="historical_claims",
        )

    return {
        "schema_id": "kt.operator.claims_raw.v1",
        "generated_utc": generated_utc,
        "source_surfaces": [
            {"surface_ref": surface_ref, "extracted_claim_count": int(count)}
            for surface_ref, count in sorted(source_counts.items())
        ],
        "claims": sorted(raw_claims, key=lambda row: row["claim_id"]),
    }


def _raw_claim_ids_by_class(raw_claims: Sequence[Dict[str, Any]]) -> DefaultDict[str, List[str]]:
    out: DefaultDict[str, List[str]] = defaultdict(list)
    for row in raw_claims:
        out[str(row.get("claim_class_id", "")).strip()].append(str(row.get("claim_id", "")).strip())
    return out


def _open_blockers(ctx: Dict[str, Any]) -> List[str]:
    return [
        str(row.get("blocker_id", "")).strip()
        for row in ctx["open_blocker_ladder"].get("blocker_ladder", [])
        if isinstance(row, dict) and str(row.get("blocker_id", "")).strip()
    ]


def _claim_evaluation_templates(ctx: Dict[str, Any], root: Path) -> Dict[str, Dict[str, Any]]:
    open_blockers = set(_open_blockers(ctx))
    taxonomy_rows = {row["claim_class_id"]: row for row in ctx["claim_taxonomy"].get("claim_classes", []) if isinstance(row, dict)}

    experiment_missing = _missing_artifact_refs(root, FUTURE_STEP_ARTIFACTS["experiment_lineage"])
    paradox_missing = _missing_artifact_refs(root, FUTURE_STEP_ARTIFACTS["paradox_program"])
    doctrine_missing = _missing_artifact_refs(root, FUTURE_STEP_ARTIFACTS["doctrine_generation"])

    return {
        "truth_authority_claim": {
            "status": "partially_evidenced",
            "current_admissibility_ceiling": "TRANSPARENCY_VERIFIED_SUBJECT_ONLY",
            "judgment_summary": (
                "Settled truth source and transparency-verified truth subject are evidenced, but current-head authority convergence and "
                "published-head self-convergence remain unresolved."
            ),
            "evidence_refs": [
                SETTLED_TRUTH_SOURCE_REL,
                PUBLIC_VERIFIER_REL,
                AUTHORITY_CONVERGENCE_REL,
                PUBLISHED_HEAD_SELF_CONVERGENCE_REL,
                CLAIM_CEILING_SUMMARY_REL,
                OPEN_BLOCKER_LADDER_REL,
            ],
            "blockers": [blocker for blocker in taxonomy_rows["truth_authority_claim"].get("blocked_by", []) if blocker in open_blockers],
        },
        "transparency_publication_claim": {
            "status": "evidenced",
            "current_admissibility_ceiling": "TRANSPARENCY_VERIFIED_SUBJECT_ONLY",
            "judgment_summary": "Cryptographic publication and transparency verification are evidenced for the truth subject commit, with explicit subject/evidence lag handling.",
            "evidence_refs": [CRYPTO_PUBLICATION_REL, PUBLIC_VERIFIER_REL],
            "blockers": [],
        },
        "governance_legitimacy_claim": {
            "status": "evidenced",
            "current_admissibility_ceiling": "WORKFLOW_GOVERNANCE_ONLY",
            "judgment_summary": "Workflow governance is evidenced and platform-governance overread is mechanically blocked while platform enforcement remains unproven.",
            "evidence_refs": [PLATFORM_GOVERNANCE_REL, PUBLIC_VERIFIER_REL, CLAIM_CEILING_SUMMARY_REL],
            "blockers": [blocker for blocker in taxonomy_rows["governance_legitimacy_claim"].get("blocked_by", []) if blocker in open_blockers],
        },
        "runtime_boundary_claim": {
            "status": "evidenced",
            "current_admissibility_ceiling": "CANONICAL_RUNTIME_BOUNDARY_SUBJECT_ONLY",
            "judgment_summary": "Canonical runtime roots are settled for the runtime-boundary subject and compatibility-only roots remain quarantined.",
            "evidence_refs": [RUNTIME_BOUNDARY_REL, CLAIM_CEILING_SUMMARY_REL],
            "blockers": [],
        },
        "reproducibility_claim": {
            "status": "evidenced",
            "current_admissibility_ceiling": "REPRESENTATIVE_SAME_MVE_ONLY",
            "judgment_summary": "Representative authority-lane reproducibility is proven on the same MVE, but cross-environment variation remains open.",
            "evidence_refs": [REPRODUCIBILITY_REL, CLAIM_CEILING_SUMMARY_REL],
            "blockers": [blocker for blocker in taxonomy_rows["reproducibility_claim"].get("blocked_by", []) if blocker in open_blockers],
        },
        "experiment_lineage_claim": {
            "status": "partially_evidenced",
            "current_admissibility_ceiling": "DOCUMENTARY_ONLY",
            "judgment_summary": "Historical crucible lineage and current adapter/model/sector lineage are present, but the dedicated experiment and learning-delta registries are still missing.",
            "evidence_refs": [HISTORICAL_CLAIMS_REL, DATA_LINEAGE_REL, WORK_ORDER_REL],
            "blockers": taxonomy_rows["experiment_lineage_claim"].get("blocked_by", []) if experiment_missing else [],
        },
        "paradox_bound_claim": {
            "status": "partially_evidenced",
            "current_admissibility_ceiling": "DOCUMENTARY_ONLY",
            "judgment_summary": "Frontier settlement gives bounded paradox-adjacent evidence, but the dedicated paradox verification program artifacts are not yet present.",
            "evidence_refs": [FRONTIER_SETTLEMENT_REL, WORK_ORDER_REL],
            "blockers": taxonomy_rows["paradox_bound_claim"].get("blocked_by", []) if paradox_missing else [],
        },
        "doctrine_generation_claim": {
            "status": "partially_evidenced",
            "current_admissibility_ceiling": "DOCUMENTARY_ONLY",
            "judgment_summary": "Public claim boundaries are machine-enforced, but the dedicated doctrine compiler, profiles, and ratification outputs are still pending.",
            "evidence_refs": [PUBLIC_VERIFIER_REL, COMMERCIAL_COMPILER_REL, SELF_DESCRIPTION_REL, WORK_ORDER_REL],
            "blockers": ["DOCTRINE_GENERATION_PENDING"] if doctrine_missing else [],
        },
        "commercial_surface_claim": {
            "status": "evidenced",
            "current_admissibility_ceiling": "DOCUMENTARY_ONLY",
            "judgment_summary": "Commercial surfaces are bounded to documentary-only claims and tied back to verifier and runtime-boundary receipts.",
            "evidence_refs": [COMMERCIAL_COMPILER_REL, PUBLIC_VERIFIER_REL, RUNTIME_BOUNDARY_REL],
            "blockers": [],
        },
        "release_readiness_claim": {
            "status": "partially_evidenced",
            "current_admissibility_ceiling": "COMPETITION_AND_PUBLICATION_GRADE",
            "judgment_summary": "Bounded external and publication-facing surfaces exist, but H1 remains blocked and no final release-readiness matrix exists yet.",
            "evidence_refs": [READINESS_LATTICE_REL, QUALITY_POLICY_REL, FRONTIER_SETTLEMENT_REL, H1_GATE_REL],
            "blockers": [blocker for blocker in taxonomy_rows["release_readiness_claim"].get("blocked_by", []) if blocker in {"QUALITY_LEVEL_BELOW_TARGET", "H1_ACTIVATION_GATE_CLOSED"} or blocker in open_blockers],
        },
        "historical_lineage_claim": {
            "status": "evidenced",
            "current_admissibility_ceiling": "DOCUMENTARY_ONLY",
            "judgment_summary": "Historical audits, conflicts, resolutions, codex lineage, and reopened defects are ingested as machine-usable memory.",
            "evidence_refs": [HISTORICAL_CLAIMS_REL, HISTORICAL_CONFLICTS_REL, HISTORICAL_RESOLUTIONS_REL, REOPENED_DEFECT_REGISTER_REL],
            "blockers": [],
        },
    }


def _build_claim_registry(ctx: Dict[str, Any], root: Path, raw_claims: Sequence[Dict[str, Any]], *, generated_utc: str) -> Dict[str, Any]:
    taxonomy_rows = [row for row in ctx["claim_taxonomy"].get("claim_classes", []) if isinstance(row, dict)]
    raw_ids_by_class = _raw_claim_ids_by_class(raw_claims)
    templates = _claim_evaluation_templates(ctx, root)
    registry_rows: List[Dict[str, Any]] = []

    for row in taxonomy_rows:
        claim_class_id = str(row.get("claim_class_id", "")).strip()
        template = templates[claim_class_id]
        registry_rows.append(
            {
                "claim_class_id": claim_class_id,
                "label": str(row.get("label", "")).strip(),
                "status": template["status"],
                "max_admissibility_ceiling": str(row.get("max_admissibility_ceiling", "")).strip(),
                "current_admissibility_ceiling": template["current_admissibility_ceiling"],
                "judgment_summary": template["judgment_summary"],
                "applicable_organs": list(row.get("applicable_organs", [])),
                "required_evidence_classes": list(row.get("required_evidence_classes", [])),
                "evidence_refs": sorted({_normalize_ref(ref) for ref in template["evidence_refs"] if _normalize_ref(ref)}),
                "raw_claim_ids": sorted(set(raw_ids_by_class.get(claim_class_id, []))),
                "blockers": sorted(set(template["blockers"])),
                "evidence_chain_complete": bool(template["evidence_refs"]) and bool(raw_ids_by_class.get(claim_class_id)),
            }
        )

    return {
        "schema_id": "kt.operator.claim_registry.v1",
        "generated_utc": generated_utc,
        "claim_classes": sorted(registry_rows, key=lambda item: item["claim_class_id"]),
    }


def _build_rule_results(ctx: Dict[str, Any], claim_registry: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    claim_rows = {
        str(row.get("claim_class_id", "")).strip(): row
        for row in claim_registry.get("claim_classes", [])
        if isinstance(row, dict)
    }
    class_rules: List[Dict[str, Any]] = []
    for claim_class_id, row in sorted(claim_rows.items()):
        status = str(row.get("status", "")).strip()
        rule_status = "PASS" if status == "evidenced" else "HOLD" if status == "partially_evidenced" else "FAIL"
        class_rules.append(
            {
                "rule_id": f"RULE::{claim_class_id}",
                "target_id": claim_class_id,
                "status": rule_status,
                "derived_status": status,
                "detail": str(row.get("judgment_summary", "")).strip(),
                "evidence_refs": list(row.get("evidence_refs", [])),
            }
        )

    profile_results: List[Dict[str, Any]] = []
    profile_rows = [row for row in ctx["readiness_lattice"].get("nodes", []) if isinstance(row, dict)]
    profile_status_map = {
        "internal_only": ("PASS", "State taint is clear and no internal-only blocker is active."),
        "external_demo_or_specialist_use": (
            "PASS",
            "Truth-authority is bounded rather than contradicted, runtime boundary is evidenced, and documentary/commercial boundaries are present.",
        ),
        "competition_and_publication_grade": (
            "HOLD",
            "Competition/publication surfaces stay bounded, but release readiness is not fully evidenced and H1 remains blocked.",
        ),
        "commercial_documentary_only": (
            "PASS",
            "Commercial documentary-only boundaries and required markers are evidenced.",
        ),
        "h1_activation": (
            "BLOCKED",
            "Published-head self-convergence, authority convergence, truth-publication stabilization, and H1 activation remain blocked.",
        ),
    }
    for row in profile_rows:
        profile_id = str(row.get("profile_id", "")).strip()
        status, detail = profile_status_map.get(profile_id, ("HOLD", "No explicit rule result defined."))
        profile_results.append(
            {
                "rule_id": f"PROFILE::{profile_id}",
                "target_id": profile_id,
                "status": status,
                "detail": detail,
                "required_claim_classes": list(row.get("required_claim_classes", [])),
                "blocking_conditions": list(row.get("blocking_conditions", [])),
                "evidence_refs": [READINESS_LATTICE_REL, QUALITY_POLICY_REL, CLAIM_REGISTRY_REL],
            }
        )

    experiment_missing = _missing_artifact_refs(repo_root(), FUTURE_STEP_ARTIFACTS["experiment_lineage"])
    paradox_missing = _missing_artifact_refs(repo_root(), FUTURE_STEP_ARTIFACTS["paradox_program"])
    doctrine_missing = _missing_artifact_refs(repo_root(), FUTURE_STEP_ARTIFACTS["doctrine_generation"])
    canon_missing = _missing_artifact_refs(repo_root(), FUTURE_STEP_ARTIFACTS["canon_normalization"])
    adjudication_missing = _missing_artifact_refs(repo_root(), FUTURE_STEP_ARTIFACTS["full_stack_adjudication"])

    derived_results = [
        {
            "rule_id": "DERIVED::lineage_domains_present",
            "target_id": "lineage_completeness",
            "status": "PASS" if not experiment_missing else "HOLD",
            "detail": "Adapter/model/sector/historical/governance lineage exists, but experiment and delta lineage sealing remains incomplete."
            if experiment_missing
            else "All tracked lineage domains are present.",
            "evidence_refs": [DATA_LINEAGE_REL, HISTORICAL_CLAIMS_REL, GOVERNANCE_BASELINE_RECEIPT_REL],
        },
        {
            "rule_id": "DERIVED::canon_normalization_pending",
            "target_id": "normalization_status",
            "status": "HOLD" if canon_missing else "PASS",
            "detail": "Canon and normalization planning artifacts are not yet present." if canon_missing else "Canon and normalization planning artifacts exist.",
            "evidence_refs": [WORK_ORDER_REL, STEP6_RECEIPT_REL],
        },
        {
            "rule_id": "DERIVED::paradox_program_pending",
            "target_id": "paradox_program",
            "status": "HOLD" if paradox_missing else "PASS",
            "detail": "Dedicated paradox verification artifacts are still missing." if paradox_missing else "Dedicated paradox verification artifacts exist.",
            "evidence_refs": [WORK_ORDER_REL, FRONTIER_SETTLEMENT_REL],
        },
        {
            "rule_id": "DERIVED::doctrine_generation_pending",
            "target_id": "doctrine_version",
            "status": "HOLD" if doctrine_missing else "PASS",
            "detail": "Doctrine compiler and profile outputs are still missing." if doctrine_missing else "Doctrine compiler and profile outputs exist.",
            "evidence_refs": [WORK_ORDER_REL, SELF_DESCRIPTION_REL, CONSTITUTION_MANIFEST_REL],
        },
        {
            "rule_id": "DERIVED::full_stack_adjudication_pending",
            "target_id": "adjudication_status",
            "status": "HOLD" if adjudication_missing else "PASS",
            "detail": "Full-stack adjudication artifacts are still missing." if adjudication_missing else "Full-stack adjudication artifacts exist.",
            "evidence_refs": [WORK_ORDER_REL, CLAIM_REGISTRY_REL],
        },
    ]

    return {
        "schema_id": "kt.operator.rule_results.v1",
        "generated_utc": generated_utc,
        "class_rule_results": class_rules,
        "readiness_profile_results": profile_results,
        "derived_rule_results": derived_results,
    }


def _build_counterexample_register(ctx: Dict[str, Any], root: Path, *, generated_utc: str) -> Dict[str, Any]:
    authority = ctx["authority_convergence"]
    verifier = ctx["public_verifier"]
    reproducibility = ctx["reproducibility"]
    h1_gate = ctx["h1_gate"]
    reopened = {row["defect_id"]: row for row in ctx["reopened_defects"].get("defects", []) if isinstance(row, dict) and row.get("defect_id")}
    paradox_missing = _missing_artifact_refs(root, FUTURE_STEP_ARTIFACTS["paradox_program"])
    experiment_missing = _missing_artifact_refs(root, FUTURE_STEP_ARTIFACTS["experiment_lineage"])

    rows = [
        {
            "counterexample_id": "COUNTEREXAMPLE::CURRENT_HEAD_AUTHORITY_DIVERGENCE",
            "claim_class_id": "truth_authority_claim",
            "severity": "P0_authority",
            "description": "Main-bound pointer, current-state, and runtime-closure surfaces do not converge on the current authority head.",
            "observed": {
                "board_head": authority.get("observed", {}).get("board_head"),
                "pointer_head": authority.get("observed", {}).get("pointer_head"),
                "current_state_head": authority.get("observed", {}).get("current_state_head"),
                "runtime_audit_head": authority.get("observed", {}).get("runtime_audit_head"),
            },
            "expected": {"all_heads_equal": True},
            "evidence_refs": [AUTHORITY_CONVERGENCE_REL, OPEN_BLOCKER_LADDER_REL],
        },
        {
            "counterexample_id": "COUNTEREXAMPLE::HEAD_NOT_EQUAL_TRUTH_SUBJECT",
            "claim_class_id": "truth_authority_claim",
            "severity": "P0_authority",
            "description": "The current evidence commit is not the same SHA as the transparency-verified truth subject commit.",
            "observed": {
                "evidence_commit": verifier.get("evidence_commit"),
                "truth_subject_commit": verifier.get("truth_subject_commit"),
                "evidence_equals_subject": verifier.get("evidence_equals_subject"),
            },
            "expected": {"evidence_equals_subject": True},
            "evidence_refs": [PUBLIC_VERIFIER_REL, CLAIM_CEILING_SUMMARY_REL],
        },
        {
            "counterexample_id": "COUNTEREXAMPLE::PLATFORM_ENFORCEMENT_BLOCKED",
            "claim_class_id": "governance_legitimacy_claim",
            "severity": "P1_governance",
            "description": "Platform branch-protection enforcement is blocked and cannot support a platform-enforced governance claim.",
            "observed": {
                "branch_protection_status": ctx["platform_governance"].get("branch_protection_status"),
                "platform_block": ctx["platform_governance"].get("platform_block"),
            },
            "expected": {"branch_protection_status": "PASS"},
            "evidence_refs": [PLATFORM_GOVERNANCE_REL, PUBLIC_VERIFIER_REL],
        },
        {
            "counterexample_id": "COUNTEREXAMPLE::CROSS_ENV_VARIATION_NOT_RUN",
            "claim_class_id": "reproducibility_claim",
            "severity": "P1_claim_evidence",
            "description": "Representative reproducibility is same-MVE only; cross-environment controlled variation is still not run.",
            "observed": {
                "cross_environment_controlled_variation_complete": reproducibility.get("cross_environment_controlled_variation_complete"),
                "reproducibility_band": reproducibility.get("reproducibility_band"),
            },
            "expected": {"cross_environment_controlled_variation_complete": True},
            "evidence_refs": [REPRODUCIBILITY_REL, OPEN_BLOCKER_LADDER_REL],
        },
        {
            "counterexample_id": "COUNTEREXAMPLE::H1_GATE_CLOSED",
            "claim_class_id": "release_readiness_claim",
            "severity": "P1_governance",
            "description": "H1 remains blocked and no single-adapter benchmarking or router activation is admissible.",
            "observed": {
                "h1_allowed": h1_gate.get("h1_allowed"),
                "next_allowed_transition": h1_gate.get("next_allowed_transition"),
            },
            "expected": {"h1_allowed": True},
            "evidence_refs": [H1_GATE_REL, FRONTIER_SETTLEMENT_REL],
        },
        {
            "counterexample_id": "COUNTEREXAMPLE::LOCAL_SECRET_RESIDUE_PRESENT",
            "claim_class_id": "release_readiness_claim",
            "severity": "P0_runtime_integrity",
            "description": "A local secret-like residue file remains at repo root.",
            "observed": reopened.get("LOCAL_RESIDUE_PRESENT", {}).get("current_values", {}),
            "expected": {"env_secret_exists": False},
            "evidence_refs": list(reopened.get("LOCAL_RESIDUE_PRESENT", {}).get("current_evidence_refs", [])),
        },
        {
            "counterexample_id": "COUNTEREXAMPLE::ROOT_ARCHIVE_CONTAMINATION_PRESENT",
            "claim_class_id": "historical_lineage_claim",
            "severity": "P2_duplicate_surface",
            "description": "Historical archive surfaces remain physically co-located with active repo-control surfaces.",
            "observed": reopened.get("ROOT_ARCHIVE_CONTAMINATION", {}).get("current_values", {}),
            "expected": {
                "docs_audit_exists": False,
                "kt_temple_root_exists": False,
                "kt_lane_lora_phase_b_exists": False,
            },
            "evidence_refs": list(reopened.get("ROOT_ARCHIVE_CONTAMINATION", {}).get("current_evidence_refs", [])),
        },
        {
            "counterexample_id": "COUNTEREXAMPLE::EXPERIMENT_DELTA_LINEAGE_ARTIFACTS_MISSING",
            "claim_class_id": "experiment_lineage_claim",
            "severity": "P1_claim_evidence",
            "description": "Dedicated experiment and learning-delta lineage outputs are not yet present.",
            "observed": {"missing_artifacts": experiment_missing},
            "expected": {"missing_artifacts": []},
            "evidence_refs": [WORK_ORDER_REL, DATA_LINEAGE_REL, HISTORICAL_CLAIMS_REL],
        },
        {
            "counterexample_id": "COUNTEREXAMPLE::PARADOX_VERIFICATION_ARTIFACTS_MISSING",
            "claim_class_id": "paradox_bound_claim",
            "severity": "P1_claim_evidence",
            "description": "Dedicated paradox verification artifacts are not yet present.",
            "observed": {"missing_artifacts": paradox_missing},
            "expected": {"missing_artifacts": []},
            "evidence_refs": [WORK_ORDER_REL, FRONTIER_SETTLEMENT_REL],
        },
    ]

    sorted_rows = sorted(rows, key=lambda row: (CONFLICT_SEVERITY_ORDER[row["severity"]], row["counterexample_id"]))
    return {
        "schema_id": "kt.operator.counterexample_register.v1",
        "generated_utc": generated_utc,
        "counterexamples": sorted_rows,
    }


def _build_conflict_register(ctx: Dict[str, Any], counterexamples: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    blocker_rows = {
        str(row.get("blocker_id", "")).strip(): row
        for row in ctx["open_blocker_ladder"].get("blocker_ladder", [])
        if isinstance(row, dict) and str(row.get("blocker_id", "")).strip()
    }
    reopened = {
        str(row.get("defect_id", "")).strip(): row
        for row in ctx["reopened_defects"].get("defects", [])
        if isinstance(row, dict) and str(row.get("defect_id", "")).strip()
    }

    rows = [
        {
            "conflict_id": "AUTHORITY_CONVERGENCE_UNRESOLVED",
            "severity": "P0_authority",
            "status": "ACTIVE",
            "description": "Current-head authority surfaces remain divergent on pointer and posture state.",
            "affected_claim_classes": ["truth_authority_claim", "release_readiness_claim"],
            "evidence_refs": list(blocker_rows["AUTHORITY_CONVERGENCE_UNRESOLVED"].get("evidence_refs", [])),
            "counterexample_ids": ["COUNTEREXAMPLE::CURRENT_HEAD_AUTHORITY_DIVERGENCE"],
        },
        {
            "conflict_id": "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED",
            "severity": "P0_authority",
            "status": "ACTIVE",
            "description": "Published-head self-convergence remains local-ledger-only and does not support current-head authority closure.",
            "affected_claim_classes": ["truth_authority_claim", "release_readiness_claim"],
            "evidence_refs": list(blocker_rows["PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED"].get("evidence_refs", [])),
            "counterexample_ids": ["COUNTEREXAMPLE::HEAD_NOT_EQUAL_TRUTH_SUBJECT"],
        },
        {
            "conflict_id": "LOCAL_RESIDUE_PRESENT",
            "severity": "P0_runtime_integrity",
            "status": str(reopened["LOCAL_RESIDUE_PRESENT"].get("current_status", "")).strip() or "ACTIVE",
            "description": str(reopened["LOCAL_RESIDUE_PRESENT"].get("current_summary", "")).strip(),
            "affected_claim_classes": ["release_readiness_claim"],
            "evidence_refs": list(reopened["LOCAL_RESIDUE_PRESENT"].get("current_evidence_refs", [])),
            "counterexample_ids": ["COUNTEREXAMPLE::LOCAL_SECRET_RESIDUE_PRESENT"],
        },
        {
            "conflict_id": "PLATFORM_ENFORCEMENT_UNPROVEN",
            "severity": "P1_governance",
            "status": "ACTIVE",
            "description": "Governance remains workflow-only because platform branch-protection enforcement is not proven.",
            "affected_claim_classes": ["governance_legitimacy_claim"],
            "evidence_refs": list(blocker_rows["PLATFORM_ENFORCEMENT_UNPROVEN"].get("evidence_refs", [])),
            "counterexample_ids": ["COUNTEREXAMPLE::PLATFORM_ENFORCEMENT_BLOCKED"],
        },
        {
            "conflict_id": "H1_ACTIVATION_GATE_CLOSED",
            "severity": "P1_governance",
            "status": "ACTIVE",
            "description": "H1 and higher-horizon activation remain blocked.",
            "affected_claim_classes": ["release_readiness_claim"],
            "evidence_refs": list(blocker_rows["H1_ACTIVATION_GATE_CLOSED"].get("evidence_refs", [])),
            "counterexample_ids": ["COUNTEREXAMPLE::H1_GATE_CLOSED"],
        },
        {
            "conflict_id": "TRUTH_PUBLICATION_STABILIZED_FALSE",
            "severity": "P1_claim_evidence",
            "status": "ACTIVE",
            "description": "Truth publication stabilization remains false on the retained execution surfaces.",
            "affected_claim_classes": ["truth_authority_claim", "release_readiness_claim"],
            "evidence_refs": list(blocker_rows["TRUTH_PUBLICATION_STABILIZED_FALSE"].get("evidence_refs", [])),
            "counterexample_ids": ["COUNTEREXAMPLE::CURRENT_HEAD_AUTHORITY_DIVERGENCE"],
        },
        {
            "conflict_id": "CROSS_ENV_CONTROLLED_VARIATION_NOT_RUN",
            "severity": "P1_claim_evidence",
            "status": "ACTIVE",
            "description": "Cross-environment controlled variation remains unproven, limiting reproducibility to the representative same-MVE band.",
            "affected_claim_classes": ["reproducibility_claim"],
            "evidence_refs": list(blocker_rows["CROSS_ENV_CONTROLLED_VARIATION_NOT_RUN"].get("evidence_refs", [])),
            "counterexample_ids": ["COUNTEREXAMPLE::CROSS_ENV_VARIATION_NOT_RUN"],
        },
        {
            "conflict_id": "DELTA_LINEAGE_MISSING",
            "severity": "P1_claim_evidence",
            "status": "ACTIVE",
            "description": "Dedicated experiment and learning-delta registries are not yet present.",
            "affected_claim_classes": ["experiment_lineage_claim"],
            "evidence_refs": [WORK_ORDER_REL, DATA_LINEAGE_REL, HISTORICAL_CLAIMS_REL],
            "counterexample_ids": ["COUNTEREXAMPLE::EXPERIMENT_DELTA_LINEAGE_ARTIFACTS_MISSING"],
        },
        {
            "conflict_id": "PARADOX_PROGRAM_UNBOUNDED",
            "severity": "P1_claim_evidence",
            "status": "ACTIVE",
            "description": "Dedicated paradox verification artifacts are not yet present, so paradox metabolism is not yet formally bounded by its own program.",
            "affected_claim_classes": ["paradox_bound_claim"],
            "evidence_refs": [WORK_ORDER_REL, FRONTIER_SETTLEMENT_REL],
            "counterexample_ids": ["COUNTEREXAMPLE::PARADOX_VERIFICATION_ARTIFACTS_MISSING"],
        },
        {
            "conflict_id": "ROOT_ARCHIVE_CONTAMINATION",
            "severity": "P2_duplicate_surface",
            "status": str(reopened["ROOT_ARCHIVE_CONTAMINATION"].get("current_status", "")).strip() or "ACTIVE",
            "description": str(reopened["ROOT_ARCHIVE_CONTAMINATION"].get("current_summary", "")).strip(),
            "affected_claim_classes": ["historical_lineage_claim"],
            "evidence_refs": list(reopened["ROOT_ARCHIVE_CONTAMINATION"].get("current_evidence_refs", [])),
            "counterexample_ids": ["COUNTEREXAMPLE::ROOT_ARCHIVE_CONTAMINATION_PRESENT"],
        },
    ]

    counterexample_ids = {row["counterexample_id"] for row in counterexamples.get("counterexamples", []) if isinstance(row, dict)}
    for row in rows:
        if not set(row["counterexample_ids"]).issubset(counterexample_ids):
            raise RuntimeError(f"FAIL_CLOSED: conflict references unknown counterexamples: {row['conflict_id']}")

    return {
        "schema_id": "kt.operator.conflict_register.v1",
        "generated_utc": generated_utc,
        "conflicts": sorted(rows, key=lambda row: (CONFLICT_SEVERITY_ORDER[row["severity"]], row["conflict_id"])),
    }


def _build_claim_evidence_matrix(claim_registry: Dict[str, Any], rule_results: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    rule_ids_by_target: DefaultDict[str, List[str]] = defaultdict(list)
    for section in ("class_rule_results", "readiness_profile_results", "derived_rule_results"):
        for row in rule_results.get(section, []):
            if not isinstance(row, dict):
                continue
            target_id = str(row.get("target_id", "")).strip()
            if target_id:
                rule_ids_by_target[target_id].append(str(row.get("rule_id", "")).strip())

    matrix_rows = []
    for row in claim_registry.get("claim_classes", []):
        if not isinstance(row, dict):
            continue
        claim_class_id = str(row.get("claim_class_id", "")).strip()
        matrix_rows.append(
            {
                "claim_class_id": claim_class_id,
                "status": str(row.get("status", "")).strip(),
                "current_admissibility_ceiling": str(row.get("current_admissibility_ceiling", "")).strip(),
                "evidence_refs": list(row.get("evidence_refs", [])),
                "raw_claim_ids": list(row.get("raw_claim_ids", [])),
                "supporting_rule_ids": sorted(set(rule_ids_by_target.get(claim_class_id, []))),
                "blockers": list(row.get("blockers", [])),
            }
        )
    return {
        "schema_id": "kt.operator.claim_evidence_matrix.v1",
        "generated_utc": generated_utc,
        "matrix": sorted(matrix_rows, key=lambda row: row["claim_class_id"]),
    }


def _lineage_completeness(root: Path, ctx: Dict[str, Any]) -> Tuple[str, float]:
    domains = {
        "historical_memory": str(ctx["historical_memory_receipt"].get("status", "")).strip() == "PASS",
        "governance_subject_map": str(ctx["governance_baseline_receipt"].get("status", "")).strip() == "PASS",
        "adapter_lineage": bool(ctx["adapter_registry"].get("adapters")),
        "model_lineage": bool(ctx["model_registry"].get("models")),
        "sector_lineage": bool(ctx["sector_registry"].get("sectors")),
        "data_lineage_graph": bool(ctx["data_lineage"].get("nodes")),
        "experiment_delta_lineage": not _missing_artifact_refs(root, FUTURE_STEP_ARTIFACTS["experiment_lineage"]),
    }
    covered = sum(1 for present in domains.values() if present)
    ratio = covered / len(domains)
    status = "PARTIAL_EXPERIMENT_DELTA_LINEAGE_PENDING" if not domains["experiment_delta_lineage"] else "COMPLETE"
    return status, ratio


def _build_state_vector(ctx: Dict[str, Any], root: Path, claim_registry: Dict[str, Any], conflicts: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    open_blockers = [str(row.get("blocker_id", "")).strip() for row in ctx["open_blocker_ladder"].get("blocker_ladder", []) if isinstance(row, dict)]
    lineage_status, lineage_ratio = _lineage_completeness(root, ctx)
    doctrine_missing = _missing_artifact_refs(root, FUTURE_STEP_ARTIFACTS["doctrine_generation"])
    canon_missing = _missing_artifact_refs(root, FUTURE_STEP_ARTIFACTS["canon_normalization"])
    adjudication_missing = _missing_artifact_refs(root, FUTURE_STEP_ARTIFACTS["full_stack_adjudication"])

    organ_rows = []
    for row in ctx["organ_ontology"].get("organs", []):
        if not isinstance(row, dict):
            continue
        organ_id = str(row.get("organ_id", "")).strip()
        quality_level, status, blockers = ORGAN_STATUS_MAP[organ_id]
        organ_rows.append(
            {
                "organ_id": organ_id,
                "quality_level": quality_level,
                "status": status,
                "blockers": list(blockers),
            }
        )

    proof_obligations = [
        {
            "obligation_id": "OBLIGATION::PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN",
            "description": "Promote published-head self-convergence beyond local-ledger-only proof.",
            "severity": "P0_authority",
            "status": "OPEN",
            "evidence_refs": [PUBLISHED_HEAD_SELF_CONVERGENCE_REL, OPEN_BLOCKER_LADDER_REL],
        },
        {
            "obligation_id": "OBLIGATION::AUTHORITY_CONVERGENCE_PASS",
            "description": "Reconcile authority surfaces so the current authority head converges without fail-closed mismatches.",
            "severity": "P0_authority",
            "status": "OPEN",
            "evidence_refs": [AUTHORITY_CONVERGENCE_REL, OPEN_BLOCKER_LADDER_REL],
        },
        {
            "obligation_id": "OBLIGATION::TRUTH_PUBLICATION_STABILIZED_TRUE",
            "description": "Raise truth-publication stabilization from false to true on the retained execution surfaces.",
            "severity": "P1_claim_evidence",
            "status": "OPEN",
            "evidence_refs": [FRONTIER_SETTLEMENT_REL, H1_GATE_REL],
        },
        {
            "obligation_id": "OBLIGATION::PLATFORM_ENFORCEMENT_PROVEN",
            "description": "Prove platform branch-protection enforcement before any platform-governance claim beyond workflow-only legitimacy.",
            "severity": "P1_governance",
            "status": "OPEN",
            "evidence_refs": [PLATFORM_GOVERNANCE_REL, PUBLIC_VERIFIER_REL],
        },
        {
            "obligation_id": "OBLIGATION::CROSS_ENV_CONTROLLED_VARIATION_COMPLETE",
            "description": "Extend reproducibility beyond the representative same-MVE band by running controlled cross-environment proof.",
            "severity": "P1_claim_evidence",
            "status": "OPEN",
            "evidence_refs": [REPRODUCIBILITY_REL, OPEN_BLOCKER_LADDER_REL],
        },
        {
            "obligation_id": "OBLIGATION::EXPERIMENT_DELTA_LINEAGE_SEALED",
            "description": "Emit experiment, learning-delta, and receipt-lineage registries so experiment lineage becomes fully auditable.",
            "severity": "P1_claim_evidence",
            "status": "OPEN",
            "evidence_refs": [WORK_ORDER_REL, DATA_LINEAGE_REL, HISTORICAL_CLAIMS_REL],
        },
        {
            "obligation_id": "OBLIGATION::PARADOX_PROGRAM_BOUNDED",
            "description": "Emit the dedicated paradox models, invariants, counterexamples, and stress results.",
            "severity": "P1_claim_evidence",
            "status": "OPEN",
            "evidence_refs": [WORK_ORDER_REL, FRONTIER_SETTLEMENT_REL],
        },
        {
            "obligation_id": "OBLIGATION::CANON_AND_NORMALIZATION_PLANNED",
            "description": "Propose canon, normalization, and repo professionalization artifacts before any whole-repo normalization work.",
            "severity": "P2_schema_drift",
            "status": "OPEN",
            "evidence_refs": [WORK_ORDER_REL, STEP6_RECEIPT_REL],
        },
        {
            "obligation_id": "OBLIGATION::DOCTRINE_AND_PROFILES_GENERATED",
            "description": "Generate doctrine, profiles, and playbooks directly from machine state.",
            "severity": "P3_doc_staleness",
            "status": "OPEN",
            "evidence_refs": [WORK_ORDER_REL, SELF_DESCRIPTION_REL, CONSTITUTION_MANIFEST_REL],
        },
        {
            "obligation_id": "OBLIGATION::FULL_STACK_ADJUDICATION_COMPLETE",
            "description": "Run final whole-system adjudication and emit release-readiness and closeout artifacts.",
            "severity": "P1_claim_evidence",
            "status": "OPEN",
            "evidence_refs": [WORK_ORDER_REL, CLAIM_REGISTRY_REL],
        },
    ]

    state_vector = {
        "schema_id": "kt.operator.state_vector.v1",
        "state_vector_id": f"kt_state_vector::{_git_head(root)}",
        "generated_utc": generated_utc,
        "repo_head_commit": _git_head(root),
        "claim_ceiling_status": {
            "current_ceiling": str(ctx["claim_ceiling_summary"].get("highest_attained_proof_class", {}).get("proof_class_id", "")).strip()
            or "SEALED_WITH_OPEN_BLOCKERS",
            "blocked_horizons": [
                str(row.get("proof_class_id", "")).strip()
                for row in ctx["claim_ceiling_summary"].get("unattained_proof_classes", [])
                if isinstance(row, dict) and str(row.get("proof_class_id", "")).strip()
            ],
        },
        "open_blockers": open_blockers,
        "organ_readiness": sorted(organ_rows, key=lambda row: row["organ_id"]),
        "doctrine_version": "UNGENERATED_STEP_11_PENDING" if doctrine_missing else "GENERATED",
        "canon_version": "UNRATIFIED_STEP_8_PENDING" if canon_missing else "RATIFIED",
        "proof_obligations": proof_obligations,
        "lineage_completeness": {
            "status": lineage_status,
            "coverage_ratio": round(lineage_ratio, 6),
        },
        "normalization_status": "PLANNING_PENDING_STEP_8" if canon_missing else "PLANNED",
        "adjudication_status": "PRE_ADJUDICATION_PENDING_STEP_12" if adjudication_missing else "ADJUDICATED",
    }

    jsonschema.validate(instance=state_vector, schema=ctx["state_vector_schema"])
    if not conflicts.get("conflicts"):
        raise RuntimeError("FAIL_CLOSED: state vector requires explicit conflicts.")
    if not claim_registry.get("claim_classes"):
        raise RuntimeError("FAIL_CLOSED: state vector requires claim registry input.")
    return state_vector


def build_judgment_outputs(root: Path, generated_utc: Optional[str] = None) -> Dict[str, Any]:
    generated = generated_utc or utc_now_iso_z()
    ctx = _step_context(root)
    raw_claims = _build_raw_claims(ctx, root, generated_utc=generated)
    claim_registry = _build_claim_registry(ctx, root, raw_claims["claims"], generated_utc=generated)
    rule_results = _build_rule_results(ctx, claim_registry, generated_utc=generated)
    counterexamples = _build_counterexample_register(ctx, root, generated_utc=generated)
    conflicts = _build_conflict_register(ctx, counterexamples, generated_utc=generated)
    evidence_matrix = _build_claim_evidence_matrix(claim_registry, rule_results, generated_utc=generated)
    state_vector = _build_state_vector(ctx, root, claim_registry, conflicts, generated_utc=generated)

    for row in claim_registry.get("claim_classes", []):
        if not row.get("evidence_chain_complete"):
            raise RuntimeError(f"FAIL_CLOSED: claim class missing evidence chain: {row.get('claim_class_id')}")

    return {
        "claims_raw": raw_claims,
        "claim_registry": claim_registry,
        "rule_results": rule_results,
        "conflict_register": conflicts,
        "counterexample_register": counterexamples,
        "claim_evidence_matrix": evidence_matrix,
        "state_vector": state_vector,
    }


def build_judgment_receipt(root: Path) -> Dict[str, Any]:
    ctx = _step_context(root)
    generated_utc = utc_now_iso_z()
    first = build_judgment_outputs(root, generated_utc=generated_utc)
    second = build_judgment_outputs(root, generated_utc=generated_utc)

    for key in first:
        if not semantically_equal_json(first[key], second[key]):
            raise RuntimeError(f"FAIL_CLOSED: nondeterministic Step 7 output detected: {key}")

    claim_classes = first["claim_registry"].get("claim_classes", [])
    conflict_rows = first["conflict_register"].get("conflicts", [])
    counterexample_rows = first["counterexample_register"].get("counterexamples", [])

    severity_pairs = [(CONFLICT_SEVERITY_ORDER[row["severity"]], row["conflict_id"]) for row in conflict_rows]
    if severity_pairs != sorted(severity_pairs):
        raise RuntimeError("FAIL_CLOSED: Step 7 conflicts are not severity-ranked.")

    compiled_head = _git_head(root)
    parent = _git_parent(root, compiled_head)
    actual_touched = sorted(set(_git_diff_files(root, parent, compiled_head, SUBJECT_ARTIFACT_REFS) + [RECEIPT_REL]))
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = [path for path in actual_touched if _is_protected(path)]

    open_blockers = _open_blockers(ctx)
    return {
        "schema_id": "kt.operator.judgment_plane_computation_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "pass_verdict": "JUDGMENT_PLANE_COMPUTED",
        "compiled_head_commit": compiled_head,
        "current_head_commit": compiled_head,
        "controlling_work_order": {
            "schema_id": WORK_ORDER_SCHEMA_ID,
            "work_order_id": WORK_ORDER_ID,
            "step_id": 7,
            "step_name": "CLAIM_EXTRACTION_JUDGMENT_ENGINE_AND_STATE_VECTOR",
        },
        "step6_gate_subject_commit": str(ctx["step6_receipt"].get("compiled_head_commit", "")).strip(),
        "step6_gate_evidence_commit": _git_last_commit_for_paths(root, [STEP6_RECEIPT_REL]),
        "claim_boundary": (
            "This receipt validates the Step 7 judgment-plane outputs for compiled_head_commit only. "
            "A later repository head that contains this receipt is evidence about compiled_head_commit, not a fresh Step 7 judgment for itself."
        ),
        "summary": {
            "raw_claim_count": len(first["claims_raw"].get("claims", [])),
            "claim_class_count": len(claim_classes),
            "active_conflict_count": len(conflict_rows),
            "counterexample_count": len(counterexample_rows),
            "open_blocker_count": len(open_blockers),
        },
        "checks": [
            {
                "check": "step6_gate_passed",
                "detail": "Step 7 requires the Step 6 graph and catalog receipt to be PASS.",
                "refs": [STEP6_RECEIPT_REL],
                "status": "PASS",
            },
            {
                "check": "major_claim_surfaces_extracted",
                "detail": "Closeout, verifier, runtime, governance, commercial, frontier, historical, and work-order claim-bearing surfaces are all represented in the raw claim set.",
                "refs": [
                    CLAIMS_RAW_REL,
                    WS0_WS11_SUMMARY_REL,
                    PUBLIC_VERIFIER_REL,
                    PLATFORM_GOVERNANCE_REL,
                    RUNTIME_BOUNDARY_REL,
                    COMMERCIAL_COMPILER_REL,
                    FRONTIER_SETTLEMENT_REL,
                    HISTORICAL_CLAIMS_REL,
                    WORK_ORDER_REL,
                ],
                "status": "PASS" if len(first["claims_raw"].get("source_surfaces", [])) >= 9 else "FAIL",
            },
            {
                "check": "every_judgment_has_evidence_chains",
                "detail": "Every claim-class judgment must carry evidence refs and raw claim IDs.",
                "refs": [CLAIM_REGISTRY_REL, CLAIM_EVIDENCE_MATRIX_REL],
                "status": "PASS"
                if all(row.get("evidence_chain_complete") and row.get("evidence_refs") and row.get("raw_claim_ids") for row in claim_classes)
                else "FAIL",
            },
            {
                "check": "state_vector_validates_schema",
                "detail": "The Step 7 state vector validates against the ratified foundation schema and includes the required fields.",
                "refs": [STATE_VECTOR_REL, STATE_VECTOR_SCHEMA_REL],
                "status": "PASS",
            },
            {
                "check": "conflicts_severity_ranked",
                "detail": "Active conflicts are severity-ranked according to the ratified conflict model.",
                "refs": [CONFLICT_REGISTER_REL],
                "status": "PASS",
            },
            {
                "check": "post_touch_accounting_clean",
                "detail": "Actual touched set must match the lawful Step 7 subject files plus the judgment receipt.",
                "refs": SUBJECT_ARTIFACT_REFS + [RECEIPT_REL],
                "status": "PASS" if not unexpected_touches and not protected_touch_violations else "FAIL",
            },
        ],
        "planned_mutates": PLANNED_MUTATES,
        "actual_touched": actual_touched,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "next_lawful_step": {
            "step_id": 8,
            "step_name": "CANON_PROPOSAL_NORMALIZATION_PLAN_AND_REPO_PROFESSIONALIZATION_PLAN",
            "status_after_step_7": "UNLOCKED" if not unexpected_touches and not protected_touch_violations else "BLOCKED",
        },
    }


def write_judgment_outputs(root: Path) -> Dict[str, Any]:
    outputs = build_judgment_outputs(root)
    artifact_map = {
        CLAIMS_RAW_REL: outputs["claims_raw"],
        CLAIM_REGISTRY_REL: outputs["claim_registry"],
        RULE_RESULTS_REL: outputs["rule_results"],
        CONFLICT_REGISTER_REL: outputs["conflict_register"],
        COUNTEREXAMPLE_REGISTER_REL: outputs["counterexample_register"],
        CLAIM_EVIDENCE_MATRIX_REL: outputs["claim_evidence_matrix"],
        STATE_VECTOR_REL: outputs["state_vector"],
    }
    writes = []
    for rel, payload in artifact_map.items():
        changed = write_json_stable(root / Path(rel), payload)
        writes.append({"artifact_ref": rel, "updated": bool(changed), "schema_id": str(payload.get("schema_id", "")).strip()})
    return {"status": "PASS", "artifacts_written": writes}


def emit_judgment_receipt(root: Path) -> Dict[str, Any]:
    receipt = build_judgment_receipt(root)
    write_json_stable(root / Path(RECEIPT_REL), receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile Step 7 claim extraction, judgments, conflicts, counterexamples, and state vector.")
    parser.add_argument("--emit-receipt", action="store_true", help="Emit the Step 7 receipt instead of only the subject artifacts.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    result = emit_judgment_receipt(root) if args.emit_receipt else write_judgment_outputs(root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
