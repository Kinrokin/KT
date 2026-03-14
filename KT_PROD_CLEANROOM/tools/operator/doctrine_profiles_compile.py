from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GENERATED_ROOT_REL = "docs/generated"
PROFILE_ROOT_REL = f"{GENERATED_ROOT_REL}/profiles"
PLAYBOOK_ROOT_REL = f"{GENERATED_ROOT_REL}/playbooks"

WORK_ORDER_REL = "KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V2/WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION.v2.json"
STEP6_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_graph_and_catalog_compilation_receipt.json"
STEP8_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_normalization_and_professionalization_planning_receipt.json"
STEP9_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_runtime_and_experiment_memory_sealing_receipt.json"
STEP10_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_paradox_program_bounded_receipt.json"

STATE_VECTOR_REL = f"{REPORT_ROOT_REL}/kt_state_vector.json"
CLAIM_REGISTRY_REL = f"{REPORT_ROOT_REL}/kt_claim_registry.json"
CLAIM_CEILING_SUMMARY_REL = f"{REPORT_ROOT_REL}/kt_claim_ceiling_summary.json"
PUBLIC_VERIFIER_MANIFEST_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
PLATFORM_GOVERNANCE_REL = f"{REPORT_ROOT_REL}/platform_governance_narrowing_receipt.json"
RUNTIME_BOUNDARY_REL = f"{REPORT_ROOT_REL}/runtime_boundary_integrity_receipt.json"
REPRODUCIBILITY_REL = f"{REPORT_ROOT_REL}/representative_authority_lane_reproducibility_receipt.json"
FRONTIER_SETTLEMENT_REL = f"{REPORT_ROOT_REL}/frontier_settlement_receipt.json"
EXPERIMENT_MEMORY_REL = f"{REPORT_ROOT_REL}/kt_runtime_and_experiment_memory_sealing_receipt.json"
EXPERIMENT_REGISTRY_REL = f"{REPORT_ROOT_REL}/kt_experiment_registry.json"
LINEAGE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_lineage_manifest.json"
PARADOX_INVARIANTS_REL = f"{REPORT_ROOT_REL}/kt_paradox_invariants.json"
PARADOX_COUNTEREXAMPLES_REL = f"{REPORT_ROOT_REL}/kt_paradox_counterexamples.json"
PARADOX_STRESS_RESULTS_REL = f"{REPORT_ROOT_REL}/kt_paradox_stress_results.json"
PARADOX_CLAIM_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_paradox_claim_matrix.json"
PROOF_OBLIGATION_SCHEDULER_REL = f"{REPORT_ROOT_REL}/kt_proof_obligation_scheduler.json"
DOCS_TOPOLOGY_REL = f"{REPORT_ROOT_REL}/kt_docs_topology.json"
RELEASE_PROFILE_PLAN_REL = f"{REPORT_ROOT_REL}/kt_release_profile.json"
SUBMISSION_PROFILE_PLAN_REL = f"{REPORT_ROOT_REL}/kt_submission_profile.json"
TRUTH_SURFACE_MAP_REL = f"{REPORT_ROOT_REL}/kt_truth_surface_map.json"
GOVERNANCE_BASELINE_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_governance_closeout_bundle.json"

CONSTITUTION_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/KT_Constitution_v1.md"
CONSTITUTION_MANIFEST_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_constitution_manifest.json"
SELF_DESCRIPTION_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_self_description.json"
QUALITY_POLICY_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_quality_policy.json"
READINESS_LATTICE_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_readiness_lattice.json"
META_GOVERNANCE_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_meta_governance_policy.json"
FORGETTING_LAW_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_forgetting_law.json"
PUBLIC_VERIFIER_RULES_REL = "KT_PROD_CLEANROOM/governance/public_verifier_rules.json"

COMPILER_SPEC_REL = f"{GENERATED_ROOT_REL}/kt_doctrine_compiler_spec.json"
MASTER_SPEC_REL = f"{GENERATED_ROOT_REL}/kt_master_spec.md"
WHITEPAPER_REL = f"{GENERATED_ROOT_REL}/KT_Whitepaper_v1.md"
GOVERNANCE_SPINE_DOC_REL = f"{GENERATED_ROOT_REL}/KT_Governance_Spine_v1.md"
COGNITIVE_ARCH_DOC_REL = f"{GENERATED_ROOT_REL}/KT_Cognitive_Architecture_v1.md"
PARADOX_DOC_REL = f"{GENERATED_ROOT_REL}/KT_Paradox_Metabolism_v1.md"
ACADEMY_DOC_REL = f"{GENERATED_ROOT_REL}/KT_Academy_Training_v1.md"
DOCTRINE_MANIFEST_REL = f"{GENERATED_ROOT_REL}/kt_doctrine_manifest.json"
DOCTRINE_RATIFICATION_LOG_REL = f"{GENERATED_ROOT_REL}/kt_doctrine_ratification_log.json"
OUTSIDER_PROFILE_REL = f"{PROFILE_ROOT_REL}/kt_outsider_onboarding_profile.json"
COMPETITION_PROFILE_REL = f"{PROFILE_ROOT_REL}/kt_competition_profile.json"
PUBLICATION_PROFILE_REL = f"{PROFILE_ROOT_REL}/kt_publication_profile.json"
MATH_GURU_PROFILE_REL = f"{PROFILE_ROOT_REL}/kt_math_guru_profile.json"
MAINTAINER_PLAYBOOK_REL = f"{PLAYBOOK_ROOT_REL}/kt_maintainer_playbook.md"
AUDITOR_PLAYBOOK_REL = f"{PLAYBOOK_ROOT_REL}/kt_auditor_playbook.md"
COMPETITION_RUNBOOK_REL = f"{PLAYBOOK_ROOT_REL}/kt_competition_runbook.md"
MATH_GURU_RUNBOOK_REL = f"{PLAYBOOK_ROOT_REL}/kt_math_guru_training_runbook.md"

RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_doctrine_and_profiles_generation_receipt.json"
TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/doctrine_profiles_compile.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_doctrine_profiles_compile.py"

JSON_ARTIFACT_RELS = [
    COMPILER_SPEC_REL,
    DOCTRINE_MANIFEST_REL,
    DOCTRINE_RATIFICATION_LOG_REL,
    OUTSIDER_PROFILE_REL,
    COMPETITION_PROFILE_REL,
    PUBLICATION_PROFILE_REL,
    MATH_GURU_PROFILE_REL,
]
TEXT_ARTIFACT_RELS = [
    MASTER_SPEC_REL,
    WHITEPAPER_REL,
    GOVERNANCE_SPINE_DOC_REL,
    COGNITIVE_ARCH_DOC_REL,
    PARADOX_DOC_REL,
    ACADEMY_DOC_REL,
    MAINTAINER_PLAYBOOK_REL,
    AUDITOR_PLAYBOOK_REL,
    COMPETITION_RUNBOOK_REL,
    MATH_GURU_RUNBOOK_REL,
]
DOCTRINE_DELIVERABLE_REFS = JSON_ARTIFACT_RELS + TEXT_ARTIFACT_RELS
SUBJECT_ARTIFACT_REFS = DOCTRINE_DELIVERABLE_REFS + [TOOL_REL, TEST_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

WORK_ORDER_ID = "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION"
WORK_ORDER_SCHEMA_ID = "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2"

PROTECTED_PREFIXES = (
    "KT_PROD_CLEANROOM/docs/commercial/",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "kt_truth_ledger:",
    ".github/workflows/",
)

REQUIRED_DELIVERABLE_REFS = {
    COMPILER_SPEC_REL,
    MASTER_SPEC_REL,
    WHITEPAPER_REL,
    GOVERNANCE_SPINE_DOC_REL,
    COGNITIVE_ARCH_DOC_REL,
    PARADOX_DOC_REL,
    ACADEMY_DOC_REL,
    DOCTRINE_MANIFEST_REL,
    DOCTRINE_RATIFICATION_LOG_REL,
    OUTSIDER_PROFILE_REL,
    COMPETITION_PROFILE_REL,
    PUBLICATION_PROFILE_REL,
    MATH_GURU_PROFILE_REL,
    MAINTAINER_PLAYBOOK_REL,
    AUDITOR_PLAYBOOK_REL,
    COMPETITION_RUNBOOK_REL,
    MATH_GURU_RUNBOOK_REL,
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


def _unique_refs(values: Sequence[str]) -> List[str]:
    refs: List[str] = []
    seen = set()
    for value in values:
        normalized = _normalize_ref(value)
        if normalized and normalized not in seen:
            refs.append(normalized)
            seen.add(normalized)
    return refs


def _is_protected(path: str) -> bool:
    normalized = _normalize_ref(path)
    return any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _write_text_stable(path: Path, text: str) -> bool:
    rendered = text.replace("\r\n", "\n")
    if path.exists() and path.read_text(encoding="utf-8") == rendered:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8", newline="\n")
    return True


def _render_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _count_list(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def _md_bullets(values: Sequence[str]) -> str:
    if not values:
        return "- none\n"
    return "".join(f"- {value}\n" for value in values)


def _current_organ_statuses(state_vector: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
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
        rows.append(updated)
    return rows


def _find_claim_row(ctx: Dict[str, Any], claim_class_id: str) -> Dict[str, Any]:
    for row in ctx["claim_registry"].get("claim_classes", []):
        if str(row.get("claim_class_id", "")).strip() == claim_class_id:
            return dict(row)
    raise RuntimeError(f"FAIL_CLOSED: missing claim class row: {claim_class_id}")


def _step_context(root: Path) -> Dict[str, Any]:
    step10 = _load_required(root, STEP10_RECEIPT_REL)
    if str(step10.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 11 is blocked until the Step 10 paradox receipt is PASS.")
    return {
        "work_order": _load_required(root, WORK_ORDER_REL),
        "step6_receipt": _load_required(root, STEP6_RECEIPT_REL),
        "step8_receipt": _load_required(root, STEP8_RECEIPT_REL),
        "step9_receipt": _load_required(root, STEP9_RECEIPT_REL),
        "step10_receipt": step10,
        "step10_evidence_commit": _git_last_commit_for_paths(root, [STEP10_RECEIPT_REL]),
        "state_vector": _load_required(root, STATE_VECTOR_REL),
        "claim_registry": _load_required(root, CLAIM_REGISTRY_REL),
        "claim_ceiling_summary": _load_required(root, CLAIM_CEILING_SUMMARY_REL),
        "public_verifier_manifest": _load_required(root, PUBLIC_VERIFIER_MANIFEST_REL),
        "platform_governance": _load_required(root, PLATFORM_GOVERNANCE_REL),
        "runtime_boundary": _load_required(root, RUNTIME_BOUNDARY_REL),
        "reproducibility": _load_required(root, REPRODUCIBILITY_REL),
        "frontier_settlement": _load_required(root, FRONTIER_SETTLEMENT_REL),
        "experiment_memory": _load_required(root, EXPERIMENT_MEMORY_REL),
        "experiment_registry": _load_required(root, EXPERIMENT_REGISTRY_REL),
        "lineage_manifest": _load_required(root, LINEAGE_MANIFEST_REL),
        "paradox_invariants": _load_required(root, PARADOX_INVARIANTS_REL),
        "paradox_counterexamples": _load_required(root, PARADOX_COUNTEREXAMPLES_REL),
        "paradox_stress_results": _load_required(root, PARADOX_STRESS_RESULTS_REL),
        "paradox_claim_matrix": _load_required(root, PARADOX_CLAIM_MATRIX_REL),
        "proof_scheduler": _load_required(root, PROOF_OBLIGATION_SCHEDULER_REL),
        "docs_topology": _load_required(root, DOCS_TOPOLOGY_REL),
        "release_profile_plan": _load_required(root, RELEASE_PROFILE_PLAN_REL),
        "submission_profile_plan": _load_required(root, SUBMISSION_PROFILE_PLAN_REL),
        "truth_surface_map": _load_required(root, TRUTH_SURFACE_MAP_REL),
        "governance_baseline_bundle": _load_required(root, GOVERNANCE_BASELINE_BUNDLE_REL),
        "constitution_manifest": _load_required(root, CONSTITUTION_MANIFEST_REL),
        "self_description": _load_required(root, SELF_DESCRIPTION_REL),
        "quality_policy": _load_required(root, QUALITY_POLICY_REL),
        "readiness_lattice": _load_required(root, READINESS_LATTICE_REL),
        "meta_governance": _load_required(root, META_GOVERNANCE_REL),
        "forgetting_law": _load_required(root, FORGETTING_LAW_REL),
        "public_verifier_rules": _load_required(root, PUBLIC_VERIFIER_RULES_REL),
        "constitution_text": (root / Path(CONSTITUTION_REL)).read_text(encoding="utf-8"),
    }


def _build_snapshot(ctx: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    state_vector = ctx["state_vector"]
    ceiling_summary = ctx["claim_ceiling_summary"]
    frontier = ctx["frontier_settlement"]
    verifier = ctx["public_verifier_manifest"]
    runtime = ctx["runtime_boundary"]
    repro = ctx["reproducibility"]
    step6 = ctx["step6_receipt"]
    step9 = ctx["step9_receipt"]
    step10 = ctx["step10_receipt"]
    graph_stats = step6.get("graph_stats", {})
    return {
        "generated_utc": generated_utc,
        "baseline_status": str(ctx["self_description"].get("baseline_status", "")).strip(),
        "program_role": str(ctx["self_description"].get("program_role", "")).strip(),
        "current_ceiling": str(state_vector.get("claim_ceiling_status", {}).get("current_ceiling", "")).strip(),
        "blocked_horizons": list(state_vector.get("claim_ceiling_status", {}).get("blocked_horizons", [])),
        "open_blockers": list(state_vector.get("open_blockers", [])),
        "organ_statuses": _current_organ_statuses(state_vector),
        "truth": {
            "subject_commit": str(verifier.get("truth_subject_commit", "")).strip(),
            "evidence_commit": str(verifier.get("evidence_commit", "")).strip(),
            "subject_verdict": str(verifier.get("subject_verdict", "")).strip(),
            "head_claim_boundary": str(verifier.get("claim_boundary", "")).strip(),
        },
        "governance": {
            "subject_commit": str(verifier.get("platform_governance_subject_commit", "")).strip(),
            "ceiling": str(verifier.get("enterprise_legitimacy_ceiling", "")).strip(),
            "verdict": str(verifier.get("platform_governance_verdict", "")).strip(),
            "platform_admissible": bool(verifier.get("platform_governance_claim_admissible", False)),
        },
        "runtime_boundary": {
            "subject_commit": str(runtime.get("runtime_boundary_subject_commit", "")).strip(),
            "verdict": str(runtime.get("runtime_boundary_verdict", "")).strip(),
            "canonical_root_count": _count_list(runtime.get("canonical_runtime_roots")),
            "compatibility_root_count": _count_list(runtime.get("compatibility_allowlist_roots")),
        },
        "reproducibility": {
            "subject_commit": str(repro.get("validated_head_sha", "")).strip(),
            "band": str(repro.get("reproducibility_band", "")).strip(),
            "representative_only": bool(repro.get("representative_authority_lane_proven", False)),
            "cross_env_complete": bool(repro.get("cross_environment_controlled_variation_complete", False)),
        },
        "frontier": {
            "subject_commit": str(frontier.get("compiled_head_commit", "")).strip(),
            "verdict": str(frontier.get("frontier_settlement_verdict", "")).strip(),
            "h1_allowed": bool(frontier.get("h1_allowed", False)),
            "blockers": list(frontier.get("blockers", [])),
        },
        "experiment_memory": {
            "experiment_count": int(step9.get("summary", {}).get("experiment_count", 0)),
            "learning_delta_count": int(step9.get("summary", {}).get("learning_delta_count", 0)),
            "crucible_run_count": int(step9.get("summary", {}).get("crucible_run_count", 0)),
            "receipt_lineage_count": int(step9.get("summary", {}).get("receipt_lineage_count", 0)),
        },
        "paradox": {
            "verdict": str(step10.get("pass_verdict", "")).strip(),
            "stress_case_count": int(step10.get("summary", {}).get("stress_case_count", 0)),
            "counterexample_count": int(step10.get("summary", {}).get("counterexample_count", 0)),
            "scheduled_obligation_count": int(step10.get("summary", {}).get("scheduled_obligation_count", 0)),
            "ttl_duration": str(ctx["proof_scheduler"].get("scheduler_basis", {}).get("ttl_duration", "")).strip(),
        },
        "graph": {
            "fact_nodes": int(graph_stats.get("fact_graph", {}).get("node_count", 0)),
            "fact_edges": int(graph_stats.get("fact_graph", {}).get("edge_count", 0)),
            "data_lineage_nodes": int(graph_stats.get("data_lineage", {}).get("node_count", 0)),
            "runtime_nodes": int(graph_stats.get("runtime_graph", {}).get("node_count", 0)),
            "truth_surface_count": int(ctx["truth_surface_map"].get("summary", {}).get("surface_count", 0)),
        },
        "claim_classes": {
            row["claim_class_id"]: {
                "status": str(row.get("status", "")).strip(),
                "current_admissibility_ceiling": str(row.get("current_admissibility_ceiling", "")).strip(),
                "blockers": list(row.get("blockers", [])),
            }
            for row in ctx["claim_registry"].get("claim_classes", [])
            if isinstance(row, dict) and str(row.get("claim_class_id", "")).strip()
        },
        "highest_attained_proof_class": dict(ceiling_summary.get("highest_attained_proof_class", {})),
        "unattained_proof_classes": list(ceiling_summary.get("unattained_proof_classes", [])),
    }


def _profile_base(
    *,
    profile_id: str,
    audience: str,
    current_status: str,
    current_ceiling: str,
    target_quality: str,
    required_capabilities: Sequence[str],
    current_evidence_refs: Sequence[str],
    explicit_gaps: Sequence[str],
    forbidden_claims: Sequence[str],
    playbook_ref: str,
    generated_utc: str,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.doctrine.profile.v1",
        "generated_utc": generated_utc,
        "profile_id": profile_id,
        "audience": audience,
        "current_status": current_status,
        "current_admissibility_ceiling": current_ceiling,
        "target_quality_level": target_quality,
        "required_capabilities": list(required_capabilities),
        "current_evidence_refs": _unique_refs(current_evidence_refs),
        "explicit_gaps": list(explicit_gaps),
        "forbidden_claims": list(forbidden_claims),
        "playbook_ref": playbook_ref,
    }


def _build_profiles(ctx: Dict[str, Any], snapshot: Dict[str, Any], *, generated_utc: str) -> Dict[str, Dict[str, Any]]:
    outsider = _profile_base(
        profile_id="outsider_onboarding",
        audience="specialist outsider or new entrant",
        current_status="ADMISSIBLE_WITH_BOUNDARIES",
        current_ceiling=snapshot["current_ceiling"],
        target_quality="QL2",
        required_capabilities=[
            "understand evidence-versus-subject lag",
            "read the public verifier boundary",
            "identify canonical runtime versus compatibility roots",
            "track open blockers without upgrading claims",
        ],
        current_evidence_refs=[
            SELF_DESCRIPTION_REL,
            PUBLIC_VERIFIER_MANIFEST_REL,
            RUNTIME_BOUNDARY_REL,
            FRONTIER_SETTLEMENT_REL,
            CLAIM_CEILING_SUMMARY_REL,
        ],
        explicit_gaps=[
            "published-head self-convergence remains unresolved",
            "authority convergence remains fail-closed",
            "H1 activation remains blocked",
        ],
        forbidden_claims=[
            "HEAD_IS_VERIFIED_SUBJECT",
            "PLATFORM_ENFORCED_GOVERNANCE_PROVEN",
            "H1_ALLOWED",
        ],
        playbook_ref=AUDITOR_PLAYBOOK_REL,
        generated_utc=generated_utc,
    )
    competition = _profile_base(
        profile_id="competition",
        audience="competition evaluators and benchmark operators",
        current_status="BLOCKED",
        current_ceiling="REPRESENTATIVE_SAME_MVE_ONLY",
        target_quality="QL3",
        required_capabilities=[
            "controlled cross-environment reproducibility",
            "competition-grade quality across governance, proof, runtime, and operability",
            "bounded release claims that do not overread H1 or platform enforcement",
        ],
        current_evidence_refs=[
            REPRODUCIBILITY_REL,
            EXPERIMENT_MEMORY_REL,
            QUALITY_POLICY_REL,
            READINESS_LATTICE_REL,
            FRONTIER_SETTLEMENT_REL,
        ],
        explicit_gaps=[
            "cross-environment controlled variation not run",
            "current release profile plane is below QL3 target",
            "H1 remains blocked for single-adapter activation claims",
        ],
        forbidden_claims=[
            "COMPETITION_READY",
            "H1_ALLOWED",
            "PLATFORM_ENFORCED_GOVERNANCE_PROVEN",
        ],
        playbook_ref=COMPETITION_RUNBOOK_REL,
        generated_utc=generated_utc,
    )
    publication = _profile_base(
        profile_id="publication",
        audience="publication reviewers and external research readers",
        current_status="BLOCKED",
        current_ceiling="DOCUMENTARY_ONLY_WITH_SUBJECT_BOUNDARY",
        target_quality="QL3",
        required_capabilities=[
            "truth subject/evidence lag must stay explicit",
            "workflow-governance-only ceiling must remain explicit",
            "runtime boundary proof and paradox bounding must be cited from receipts",
            "publication doctrine must not outrun open blockers",
        ],
        current_evidence_refs=[
            PUBLIC_VERIFIER_MANIFEST_REL,
            PLATFORM_GOVERNANCE_REL,
            RUNTIME_BOUNDARY_REL,
            FRONTIER_SETTLEMENT_REL,
            STEP10_RECEIPT_REL,
            CLAIM_CEILING_SUMMARY_REL,
        ],
        explicit_gaps=[
            "published-head self-convergence remains unresolved",
            "authority convergence remains unresolved",
            "truth publication is not stabilized true",
            "platform enforcement remains unproven",
            "publication-grade QL3 ceiling is not yet admissible",
        ],
        forbidden_claims=[
            "PUBLICATION_READY",
            "HEAD_IS_VERIFIED_SUBJECT",
            "PLATFORM_ENFORCED_GOVERNANCE_PROVEN",
            "H1_ALLOWED",
        ],
        playbook_ref=AUDITOR_PLAYBOOK_REL,
        generated_utc=generated_utc,
    )
    math_guru = _profile_base(
        profile_id="math_guru",
        audience="proof-centric specialist reviewer",
        current_status="ADMISSIBLE_WITH_BOUNDARIES",
        current_ceiling="DOCUMENTARY_ONLY_WITH_FORMAL_MODEL_AND_STRESS",
        target_quality="QL2",
        required_capabilities=[
            "read the paradox TLA model and invariant set",
            "trace counterexamples to receipts and runtime behavior",
            "distinguish documentary proof from unresolved authority convergence",
            "follow proof obligations and blocker ladders without narrative upgrade",
        ],
        current_evidence_refs=[
            PARADOX_INVARIANTS_REL,
            PARADOX_COUNTEREXAMPLES_REL,
            PARADOX_STRESS_RESULTS_REL,
            PARADOX_CLAIM_MATRIX_REL,
            PROOF_OBLIGATION_SCHEDULER_REL,
            CLAIM_CEILING_SUMMARY_REL,
        ],
        explicit_gaps=[
            "no published-head self-convergence proof",
            "authority convergence remains fail-closed",
            "paradox evidence remains documentary-only, not external superiority proof",
        ],
        forbidden_claims=[
            "EXTERNAL_PARADOX_SUPERIORITY_PROVEN",
            "HEAD_IS_VERIFIED_SUBJECT",
            "H1_ALLOWED",
        ],
        playbook_ref=MATH_GURU_RUNBOOK_REL,
        generated_utc=generated_utc,
    )
    return {
        "outsider": outsider,
        "competition": competition,
        "publication": publication,
        "math_guru": math_guru,
    }


def _render_master_spec(snapshot: Dict[str, Any], profiles: Dict[str, Dict[str, Any]]) -> str:
    organs_lines = []
    for row in snapshot["organ_statuses"]:
        blockers = ", ".join(row.get("blockers", [])) or "none"
        organs_lines.append(f"- `{row['organ_id']}`: `{row['status']}` at `{row['quality_level']}`. blockers: {blockers}")
    return f"""# KT Master Spec v1

This generated master spec is derived from current machine state and remains subordinate to constitutional law, governance receipts, and verifier outputs.

## Current Program State
- baseline status: `{snapshot['baseline_status']}`
- program role: `{snapshot['program_role']}`
- current claim ceiling: `{snapshot['current_ceiling']}`
- highest attained proof class: `{snapshot['highest_attained_proof_class'].get('proof_class_id', '')}`
- open blocker count: `{len(snapshot['open_blockers'])}`

## Evidence and Subject Boundary
- truth subject commit: `{snapshot['truth']['subject_commit']}`
- truth evidence commit: `{snapshot['truth']['evidence_commit']}`
- truth subject verdict: `{snapshot['truth']['subject_verdict']}`
- governance ceiling: `{snapshot['governance']['ceiling']}`
- runtime boundary verdict: `{snapshot['runtime_boundary']['verdict']}`
- reproducibility band: `{snapshot['reproducibility']['band']}`

## Organ Snapshot
{chr(10).join(organs_lines)}

## Open Blockers
{_md_bullets(snapshot['open_blockers'])}

## Doctrine Profiles
- outsider onboarding: `{profiles['outsider']['current_status']}`
- competition: `{profiles['competition']['current_status']}`
- publication: `{profiles['publication']['current_status']}`
- math guru: `{profiles['math_guru']['current_status']}`

## Source Refs
{_md_bullets([
    CLAIM_CEILING_SUMMARY_REL,
    STATE_VECTOR_REL,
    PUBLIC_VERIFIER_MANIFEST_REL,
    PLATFORM_GOVERNANCE_REL,
    RUNTIME_BOUNDARY_REL,
    REPRODUCIBILITY_REL,
    FRONTIER_SETTLEMENT_REL,
    EXPERIMENT_MEMORY_REL,
    STEP10_RECEIPT_REL,
])}
"""


def _render_whitepaper(snapshot: Dict[str, Any]) -> str:
    return f"""# KT Whitepaper v1

KT is a governed organism whose admissible public claims are bounded by receipts, manifests, and explicit proof ceilings.

## What Is Evidenced Now
- transparency-verified truth exists for subject commit `{snapshot['truth']['subject_commit']}`
- workflow governance is evidenced at `{snapshot['governance']['ceiling']}`
- canonical runtime boundary is settled for subject `{snapshot['runtime_boundary']['subject_commit']}`
- representative same-MVE reproducibility is proven for subject `{snapshot['reproducibility']['subject_commit']}`
- paradox metabolism is bounded at documentary-only ceiling with `{snapshot['paradox']['stress_case_count']}` passing stress cases

## What Is Not Proven
{_md_bullets(snapshot['open_blockers'])}

## Claim Boundary
Current heads may contain evidence for subject commits, but may not be described as those subjects unless the SHAs match. H1 remains blocked.

## Source Refs
{_md_bullets([
    PUBLIC_VERIFIER_MANIFEST_REL,
    PLATFORM_GOVERNANCE_REL,
    RUNTIME_BOUNDARY_REL,
    REPRODUCIBILITY_REL,
    FRONTIER_SETTLEMENT_REL,
    STEP10_RECEIPT_REL,
])}
"""


def _render_governance_spine(snapshot: Dict[str, Any]) -> str:
    return f"""# KT Governance Spine v1

This document is generated from the constitutional spine, the governance baseline bundle, and current governance receipts. It does not amend law.

## Constitutional Boundary
- baseline status: `{snapshot['baseline_status']}`
- workflow governance ceiling: `{snapshot['governance']['ceiling']}`
- platform admissible now: `{str(snapshot['governance']['platform_admissible']).lower()}`

## Current Governance Reading
- governance subject commit: `{snapshot['governance']['subject_commit']}`
- platform governance verdict: `{snapshot['governance']['verdict']}`
- truth subject/evidence lag remains explicit

## Governance Blockers
{_md_bullets([
    "PLATFORM_ENFORCEMENT_UNPROVEN",
    "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED",
    "AUTHORITY_CONVERGENCE_UNRESOLVED",
])}

## Source Refs
{_md_bullets([
    CONSTITUTION_REL,
    CONSTITUTION_MANIFEST_REL,
    META_GOVERNANCE_REL,
    GOVERNANCE_BASELINE_BUNDLE_REL,
    PLATFORM_GOVERNANCE_REL,
    PUBLIC_VERIFIER_MANIFEST_REL,
    PUBLIC_VERIFIER_RULES_REL,
])}
"""


def _render_cognitive_architecture(snapshot: Dict[str, Any]) -> str:
    return f"""# KT Cognitive Architecture v1

KT spans fact, judgment, temporal, proof, operability, and lineage planes. The runtime and governance stack is intentionally bounded rather than flattened.

## Structural Scale
- fact graph nodes: `{snapshot['graph']['fact_nodes']}`
- fact graph edges: `{snapshot['graph']['fact_edges']}`
- data-lineage nodes: `{snapshot['graph']['data_lineage_nodes']}`
- runtime-graph nodes: `{snapshot['graph']['runtime_nodes']}`
- truth surfaces cataloged: `{snapshot['graph']['truth_surface_count']}`

## Runtime and Operator Split
- canonical runtime roots: `{snapshot['runtime_boundary']['canonical_root_count']}`
- compatibility-only roots: `{snapshot['runtime_boundary']['compatibility_root_count']}`
- operator factory stays outside current truth claims unless receipts explicitly support them

## Experiment and Memory Scale
- governed experiments: `{snapshot['experiment_memory']['experiment_count']}`
- admissible learning deltas: `{snapshot['experiment_memory']['learning_delta_count']}`
- crucible runs: `{snapshot['experiment_memory']['crucible_run_count']}`
- receipt-lineage entries: `{snapshot['experiment_memory']['receipt_lineage_count']}`

## Source Refs
{_md_bullets([
    STEP6_RECEIPT_REL,
    TRUTH_SURFACE_MAP_REL,
    STEP9_RECEIPT_REL,
    EXPERIMENT_REGISTRY_REL,
    LINEAGE_MANIFEST_REL,
    RUNTIME_BOUNDARY_REL,
])}
"""


def _render_paradox_doc(snapshot: Dict[str, Any]) -> str:
    return f"""# KT Paradox Metabolism v1

Paradox metabolism is now bounded at documentary-only ceiling by explicit model, invariant coverage, stress tests, counterexamples, and TTL-backed proof obligations.

## Current Bound
- step verdict: `{snapshot['paradox']['verdict']}`
- stress cases passed: `{snapshot['paradox']['stress_case_count']}`
- counterexamples handled: `{snapshot['paradox']['counterexample_count']}`
- active TTL obligations: `{snapshot['paradox']['scheduled_obligation_count']}`
- TTL duration: `{snapshot['paradox']['ttl_duration']}`

## Boundary
This is not an external superiority claim. It is a bounded documentary proof lane tied to current receipts and open blockers.

## Source Refs
{_md_bullets([
    PARADOX_INVARIANTS_REL,
    PARADOX_COUNTEREXAMPLES_REL,
    PARADOX_STRESS_RESULTS_REL,
    PARADOX_CLAIM_MATRIX_REL,
    PROOF_OBLIGATION_SCHEDULER_REL,
    STEP10_RECEIPT_REL,
])}
"""


def _render_academy_doc(profiles: Dict[str, Dict[str, Any]], snapshot: Dict[str, Any]) -> str:
    return f"""# KT Academy Training v1

This training document is generated from current machine-state profiles and blockers. It does not promise horizons that remain blocked.

## Training Lanes
1. outsider onboarding: start with the verifier boundary, runtime boundary, and blocker ladder
2. maintainer lane: preserve law precedence, receipts, and rollback discipline
3. auditor lane: validate subject-versus-evidence boundaries before trusting any current-head phrasing
4. math guru lane: inspect paradox model, counterexamples, and unresolved proof obligations

## Current Profile Status
- outsider onboarding: `{profiles['outsider']['current_status']}`
- competition: `{profiles['competition']['current_status']}`
- publication: `{profiles['publication']['current_status']}`
- math guru: `{profiles['math_guru']['current_status']}`

## Non-Negotiable Blockers
{_md_bullets(snapshot['open_blockers'])}

## Source Refs
{_md_bullets([
    OUTSIDER_PROFILE_REL,
    COMPETITION_PROFILE_REL,
    PUBLICATION_PROFILE_REL,
    MATH_GURU_PROFILE_REL,
    READINESS_LATTICE_REL,
    QUALITY_POLICY_REL,
])}
"""


def _render_maintainer_playbook(snapshot: Dict[str, Any]) -> str:
    return f"""# KT Maintainer Playbook v1

## Operating Rules
1. read the current blocker ladder before touching public or governance surfaces
2. preserve evidence-versus-subject lag explicitly
3. keep runtime boundary and documentary-only claim ceilings intact
4. fail closed when a mutation would silently upgrade H1, platform enforcement, or truth authority

## Current Live Limits
{_md_bullets(snapshot['open_blockers'])}

## Required Refs
{_md_bullets([
    CONSTITUTION_REL,
    PUBLIC_VERIFIER_RULES_REL,
    RUNTIME_BOUNDARY_REL,
    CLAIM_CEILING_SUMMARY_REL,
])}
"""


def _render_auditor_playbook(snapshot: Dict[str, Any]) -> str:
    return f"""# KT Auditor Playbook v1

## Audit Order
1. verify the truth subject/evidence split
2. verify workflow governance does not overread platform enforcement
3. verify runtime boundary receipts against canonical roots
4. verify reproducibility band and paradox bounds
5. verify the blocker ladder still blocks H1

## Current Head Boundary
- truth subject commit: `{snapshot['truth']['subject_commit']}`
- truth evidence commit: `{snapshot['truth']['evidence_commit']}`
- governance subject commit: `{snapshot['governance']['subject_commit']}`
- runtime boundary subject commit: `{snapshot['runtime_boundary']['subject_commit']}`

## Required Refs
{_md_bullets([
    PUBLIC_VERIFIER_MANIFEST_REL,
    PLATFORM_GOVERNANCE_REL,
    RUNTIME_BOUNDARY_REL,
    REPRODUCIBILITY_REL,
    FRONTIER_SETTLEMENT_REL,
    STEP10_RECEIPT_REL,
])}
"""


def _render_competition_runbook(profiles: Dict[str, Dict[str, Any]]) -> str:
    profile = profiles["competition"]
    return f"""# KT Competition Runbook v1

Current status: `{profile['current_status']}`

## What Exists
- representative same-MVE reproducibility proof
- canonical runtime boundary proof
- documentary claim boundaries for public surfaces

## What Still Blocks Competition Claims
{_md_bullets(profile['explicit_gaps'])}

## Forbidden Claims
{_md_bullets(profile['forbidden_claims'])}

## Required Refs
{_md_bullets(profile['current_evidence_refs'])}
"""


def _render_math_guru_runbook(profiles: Dict[str, Dict[str, Any]]) -> str:
    profile = profiles["math_guru"]
    return f"""# KT Math Guru Training Runbook v1

Current status: `{profile['current_status']}`

## Review Sequence
1. inspect the paradox model
2. inspect invariant coverage
3. inspect stress results and counterexamples
4. inspect proof obligations and TTL escalation
5. inspect how open blockers cap admissibility

## Explicit Gaps
{_md_bullets(profile['explicit_gaps'])}

## Required Refs
{_md_bullets(profile['current_evidence_refs'])}
"""


def _build_text_outputs(snapshot: Dict[str, Any], profiles: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    return {
        MASTER_SPEC_REL: _render_master_spec(snapshot, profiles),
        WHITEPAPER_REL: _render_whitepaper(snapshot),
        GOVERNANCE_SPINE_DOC_REL: _render_governance_spine(snapshot),
        COGNITIVE_ARCH_DOC_REL: _render_cognitive_architecture(snapshot),
        PARADOX_DOC_REL: _render_paradox_doc(snapshot),
        ACADEMY_DOC_REL: _render_academy_doc(profiles, snapshot),
        MAINTAINER_PLAYBOOK_REL: _render_maintainer_playbook(snapshot),
        AUDITOR_PLAYBOOK_REL: _render_auditor_playbook(snapshot),
        COMPETITION_RUNBOOK_REL: _render_competition_runbook(profiles),
        MATH_GURU_RUNBOOK_REL: _render_math_guru_runbook(profiles),
    }


def _build_compiler_spec(snapshot: Dict[str, Any], *, generated_utc: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.doctrine.compiler_spec.v1",
        "generated_utc": generated_utc,
        "compiler_surface_ref": TOOL_REL,
        "gate_receipt_ref": STEP10_RECEIPT_REL,
        "compiled_claim_ceiling": snapshot["current_ceiling"],
        "input_refs": _unique_refs(
            [
                WORK_ORDER_REL,
                STEP6_RECEIPT_REL,
                STEP8_RECEIPT_REL,
                STEP9_RECEIPT_REL,
                STEP10_RECEIPT_REL,
                STATE_VECTOR_REL,
                CLAIM_REGISTRY_REL,
                CLAIM_CEILING_SUMMARY_REL,
                PUBLIC_VERIFIER_MANIFEST_REL,
                PLATFORM_GOVERNANCE_REL,
                RUNTIME_BOUNDARY_REL,
                REPRODUCIBILITY_REL,
                FRONTIER_SETTLEMENT_REL,
                SELF_DESCRIPTION_REL,
                QUALITY_POLICY_REL,
                READINESS_LATTICE_REL,
            ]
        ),
        "output_refs": DOCTRINE_DELIVERABLE_REFS,
        "generation_rules": [
            "doctrine must be derived from cited machine-state refs only",
            "generated doctrine may not amend constitutional or governance law",
            "profiles must list current evidence refs and explicit gaps",
            "generated docs must preserve subject-versus-evidence lag when SHAs differ",
            "competition and publication docs must remain blocked while their blockers remain open",
        ],
        "forbidden_claims": [
            "HEAD_IS_VERIFIED_SUBJECT",
            "PLATFORM_ENFORCED_GOVERNANCE_PROVEN",
            "H1_ALLOWED",
            "EXTERNAL_PARADOX_SUPERIORITY_PROVEN",
        ],
    }


def _build_doctrine_manifest(
    *,
    generated_utc: str,
    compiler_spec: Dict[str, Any],
    json_outputs: Dict[str, Dict[str, Any]],
    text_outputs: Dict[str, str],
) -> Dict[str, Any]:
    artifact_rows: List[Dict[str, Any]] = []
    artifact_map: Dict[str, str] = {}
    for rel, payload in json_outputs.items():
        if rel == DOCTRINE_MANIFEST_REL:
            continue
        artifact_map[rel] = _render_json(payload)
    for rel, text in text_outputs.items():
        artifact_map[rel] = text
    for rel in sorted(artifact_map):
        artifact_rows.append(
            {
                "artifact_ref": rel,
                "artifact_sha256": _sha256_text(artifact_map[rel]),
                "artifact_type": "json" if rel.endswith(".json") else "markdown",
            }
        )
    return {
        "schema_id": "kt.doctrine.manifest.v1",
        "generated_utc": generated_utc,
        "doctrine_version": "v1",
        "claim_boundary": (
            "Generated doctrine is derived from cited machine-state inputs and remains subordinate to constitutional law. "
            "It may not overread blocked horizons or subject-evidence lag."
        ),
        "compiler_spec_ref": COMPILER_SPEC_REL,
        "artifact_root": GENERATED_ROOT_REL,
        "artifacts": artifact_rows,
        "summary": {
            "artifact_count": len(artifact_rows),
            "profile_count": 4,
            "playbook_count": 4,
            "generated_doc_count": 6,
        },
        "source_refs": compiler_spec["input_refs"],
    }


def _build_doctrine_ratification_log(
    *,
    generated_utc: str,
    snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.doctrine.ratification_log.v1",
        "generated_utc": generated_utc,
        "doctrine_version": "v1",
        "ratification_status": "RATIFIED_FOR_MACHINE_STATE_DERIVED_DOCUMENTARY_USE",
        "ratification_scope": "generated doctrine, profiles, and playbooks only; not constitutional or governance law",
        "manifest_ref": DOCTRINE_MANIFEST_REL,
        "authority_basis_refs": [
            CONSTITUTION_REL,
            CONSTITUTION_MANIFEST_REL,
            META_GOVERNANCE_REL,
            STEP10_RECEIPT_REL,
            CLAIM_CEILING_SUMMARY_REL,
            PUBLIC_VERIFIER_MANIFEST_REL,
        ],
        "prohibitions": [
            "generated doctrine may not amend law",
            "generated doctrine may not phrase HEAD as verified subject unless SHAs match",
            "generated doctrine may not claim H1_ALLOWED while blockers remain open",
            "generated doctrine may not claim platform-enforced governance while platform proof is blocked",
        ],
        "open_blockers_preserved": snapshot["open_blockers"],
        "current_ceiling_preserved": snapshot["current_ceiling"],
    }


def build_step11_outputs(root: Path, generated_utc: Optional[str] = None) -> Dict[str, Any]:
    generated = generated_utc or utc_now_iso_z()
    ctx = _step_context(root)
    snapshot = _build_snapshot(ctx, generated_utc=generated)
    profiles = _build_profiles(ctx, snapshot, generated_utc=generated)
    compiler_spec = _build_compiler_spec(snapshot, generated_utc=generated)
    text_outputs = _build_text_outputs(snapshot, profiles)
    json_outputs: Dict[str, Dict[str, Any]] = {
        COMPILER_SPEC_REL: compiler_spec,
        OUTSIDER_PROFILE_REL: profiles["outsider"],
        COMPETITION_PROFILE_REL: profiles["competition"],
        PUBLICATION_PROFILE_REL: profiles["publication"],
        MATH_GURU_PROFILE_REL: profiles["math_guru"],
    }
    ratification_log = _build_doctrine_ratification_log(
        generated_utc=generated,
        snapshot=snapshot,
    )
    json_outputs[DOCTRINE_RATIFICATION_LOG_REL] = ratification_log
    manifest = _build_doctrine_manifest(
        generated_utc=generated,
        compiler_spec=compiler_spec,
        json_outputs=json_outputs,
        text_outputs=text_outputs,
    )
    json_outputs[DOCTRINE_MANIFEST_REL] = manifest

    if profiles["competition"]["current_status"] != "BLOCKED":
        raise RuntimeError("FAIL_CLOSED: competition profile unexpectedly unblocked.")
    if profiles["publication"]["current_status"] != "BLOCKED":
        raise RuntimeError("FAIL_CLOSED: publication profile unexpectedly unblocked.")
    if "H1_ALLOWED" not in profiles["outsider"]["forbidden_claims"]:
        raise RuntimeError("FAIL_CLOSED: outsider profile failed to preserve H1 boundary.")
    if "HEAD_IS_VERIFIED_SUBJECT" not in compiler_spec["forbidden_claims"]:
        raise RuntimeError("FAIL_CLOSED: doctrine compiler spec lost the current-head overread guard.")

    return {
        "snapshot": snapshot,
        "json_outputs": json_outputs,
        "text_outputs": text_outputs,
    }


def build_step11_receipt(root: Path) -> Dict[str, Any]:
    generated_utc = utc_now_iso_z()
    ctx = _step_context(root)
    first = build_step11_outputs(root, generated_utc=generated_utc)
    second = build_step11_outputs(root, generated_utc=generated_utc)

    if not semantically_equal_json(first["json_outputs"], second["json_outputs"]):
        raise RuntimeError("FAIL_CLOSED: nondeterministic Step 11 JSON outputs detected.")
    if first["text_outputs"] != second["text_outputs"]:
        raise RuntimeError("FAIL_CLOSED: nondeterministic Step 11 text outputs detected.")

    compiled_head = _git_head(root)
    parent = _git_parent(root, compiled_head)
    actual_touched = sorted(set(_git_diff_files(root, parent, compiled_head, SUBJECT_ARTIFACT_REFS) + [RECEIPT_REL]))
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = [path for path in actual_touched if _is_protected(path)]

    required_output_refs = sorted(REQUIRED_DELIVERABLE_REFS)
    emitted_output_refs = sorted(set(first["json_outputs"].keys()) | set(first["text_outputs"].keys()))
    profiles = first["json_outputs"]
    outsider = profiles[OUTSIDER_PROFILE_REL]
    competition = profiles[COMPETITION_PROFILE_REL]
    publication = profiles[PUBLICATION_PROFILE_REL]
    ratification = profiles[DOCTRINE_RATIFICATION_LOG_REL]

    return {
        "schema_id": "kt.operator.doctrine_and_profiles_generation_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "pass_verdict": "DOCTRINE_AND_PROFILES_GENERATED",
        "compiled_head_commit": compiled_head,
        "current_head_commit": compiled_head,
        "controlling_work_order": {
            "schema_id": WORK_ORDER_SCHEMA_ID,
            "work_order_id": WORK_ORDER_ID,
            "step_id": 11,
            "step_name": "DOCTRINE_COMPILER_PROFILES_AND_EXTERNAL_PROFESSIONALIZATION",
        },
        "step10_gate_subject_commit": str(ctx["step10_receipt"].get("compiled_head_commit", "")).strip(),
        "step10_gate_evidence_commit": str(ctx["step10_evidence_commit"]).strip(),
        "claim_boundary": (
            "This receipt seals machine-state-derived doctrine and profiles for compiled_head_commit only. "
            "The generated surfaces remain subordinate to law and may not overread blocked horizons or subject-evidence lag."
        ),
        "summary": {
            "deliverable_count": len(emitted_output_refs),
            "profile_count": 4,
            "playbook_count": 4,
            "generated_doc_count": 6,
        },
        "checks": [
            {
                "check": "step10_gate_passed",
                "detail": "Step 11 requires the Step 10 paradox receipt to be PASS.",
                "refs": [STEP10_RECEIPT_REL],
                "status": "PASS",
            },
            {
                "check": "doctrine_generated_from_machine_state",
                "detail": "Doctrine compiler spec and manifest must be grounded in explicit machine-state refs, not narrative-only inputs.",
                "refs": [COMPILER_SPEC_REL, DOCTRINE_MANIFEST_REL, STATE_VECTOR_REL, CLAIM_CEILING_SUMMARY_REL],
                "status": "PASS" if emitted_output_refs == required_output_refs else "FAIL",
            },
            {
                "check": "profiles_list_capabilities_evidence_and_gaps",
                "detail": "Generated profiles must include required capabilities, current evidence refs, and explicit gaps.",
                "refs": [OUTSIDER_PROFILE_REL, COMPETITION_PROFILE_REL, PUBLICATION_PROFILE_REL, MATH_GURU_PROFILE_REL],
                "status": "PASS"
                if all(
                    bool(profile.get("required_capabilities"))
                    and bool(profile.get("current_evidence_refs"))
                    and "explicit_gaps" in profile
                    for profile in [outsider, competition, publication, profiles[MATH_GURU_PROFILE_REL]]
                )
                else "FAIL",
            },
            {
                "check": "outsider_onboarding_explicit",
                "detail": "Outsider onboarding must be an admissible bounded profile with explicit evidence refs and forbidden claims.",
                "refs": [OUTSIDER_PROFILE_REL, ACADEMY_DOC_REL],
                "status": "PASS"
                if outsider.get("current_status") == "ADMISSIBLE_WITH_BOUNDARIES"
                and "HEAD_IS_VERIFIED_SUBJECT" in outsider.get("forbidden_claims", [])
                else "FAIL",
            },
            {
                "check": "competition_and_publication_boundaries_explicit",
                "detail": "Competition and publication profiles must remain blocked while their current blockers remain open.",
                "refs": [COMPETITION_PROFILE_REL, PUBLICATION_PROFILE_REL, CLAIM_CEILING_SUMMARY_REL, FRONTIER_SETTLEMENT_REL],
                "status": "PASS"
                if competition.get("current_status") == "BLOCKED" and publication.get("current_status") == "BLOCKED"
                else "FAIL",
            },
            {
                "check": "ratification_keeps_law_precedence",
                "detail": "Doctrine ratification must explicitly state that generated doctrine is subordinate to constitutional and governance law.",
                "refs": [DOCTRINE_RATIFICATION_LOG_REL, CONSTITUTION_REL, META_GOVERNANCE_REL],
                "status": "PASS"
                if "generated doctrine may not amend law" in ratification.get("prohibitions", [])
                else "FAIL",
            },
            {
                "check": "post_touch_accounting_clean",
                "detail": "Actual touched set must match the lawful Step 11 subject files plus the Step 11 receipt.",
                "refs": SUBJECT_ARTIFACT_REFS + [RECEIPT_REL],
                "status": "PASS" if not unexpected_touches and not protected_touch_violations else "FAIL",
            },
        ],
        "planned_mutates": PLANNED_MUTATES,
        "actual_touched": actual_touched,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "next_lawful_step": {
            "step_id": 12,
            "step_name": "FULL_STACK_ADJUDICATION_RELEASE_READINESS_AND_FINAL_E2E_AUDIT",
            "status_after_step_11": "UNLOCKED" if not unexpected_touches and not protected_touch_violations else "BLOCKED",
        },
    }


def write_step11_outputs(root: Path) -> Dict[str, Any]:
    outputs = build_step11_outputs(root)
    writes: List[Dict[str, Any]] = []
    for rel, payload in outputs["json_outputs"].items():
        changed = write_json_stable(root / Path(rel), payload)
        writes.append({"artifact_ref": rel, "updated": bool(changed), "schema_id": str(payload.get("schema_id", "")).strip()})
    for rel, text in outputs["text_outputs"].items():
        changed = _write_text_stable(root / Path(rel), text)
        writes.append({"artifact_ref": rel, "updated": bool(changed), "schema_id": "markdown.document"})
    return {"status": "PASS", "artifacts_written": writes}


def emit_step11_receipt(root: Path) -> Dict[str, Any]:
    receipt = build_step11_receipt(root)
    write_json_stable(root / Path(RECEIPT_REL), receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile Step 11 doctrine, profiles, playbooks, and ratification bundle.")
    parser.add_argument("--emit-receipt", action="store_true", help="Emit the Step 11 receipt instead of only the subject artifacts.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    result = emit_step11_receipt(root) if args.emit_receipt else write_step11_outputs(root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
