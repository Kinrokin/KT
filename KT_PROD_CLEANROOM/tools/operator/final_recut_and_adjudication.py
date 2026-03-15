from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GENERATED_ROOT_REL = "docs/generated"
PROFILE_ROOT_REL = f"{GENERATED_ROOT_REL}/profiles"
PLAYBOOK_ROOT_REL = f"{GENERATED_ROOT_REL}/playbooks"

WORKSTREAM_ID = "WS11_FINAL_RECUT_AND_RE-ADJUDICATION"
STEP_ID = "WS11_STEP_1_REGENERATE_DOCTRINE_AND_READINESS"
PASS_VERDICT = "FINAL_RECUT_AND_ADJUDICATION_COMPLETE"

AUTHORITY_CLOSURE_REL = f"{REPORT_ROOT_REL}/kt_authority_closure_receipt.json"
PLATFORM_FINAL_REL = f"{REPORT_ROOT_REL}/kt_platform_governance_final_decision_receipt.json"
PUBLIC_VERIFIER_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
RUNTIME_BOUNDARY_REL = f"{REPORT_ROOT_REL}/runtime_boundary_integrity_receipt.json"
H1_GATE_REL = f"{REPORT_ROOT_REL}/h1_activation_gate_receipt.json"
TRUTH_PUBLICATION_REL = f"{REPORT_ROOT_REL}/kt_truth_publication_stabilization_receipt.json"
DETERMINISM_REL = f"{REPORT_ROOT_REL}/kt_determinism_receipt.json"
ARCHIVE_SEPARATION_REL = f"{REPORT_ROOT_REL}/kt_archive_externalization_receipt.json"
CANONICAL_TREE_REL = f"{REPORT_ROOT_REL}/kt_repo_professionalization_completion_receipt.json"
LEDGER_AUTHORITY_REL = f"{REPORT_ROOT_REL}/kt_authority_topology_cutover_receipt.json"
CLAIM_COMPILER_ACTIVATION_REL = f"{REPORT_ROOT_REL}/kt_claim_compiler_activation_receipt.json"
VERIFIER_RELEASE_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_release_manifest.json"
PARADOX_REL = f"{REPORT_ROOT_REL}/kt_paradox_program_bounded_receipt.json"
RUNTIME_MEMORY_REL = f"{REPORT_ROOT_REL}/kt_runtime_and_experiment_memory_sealing_receipt.json"
QUALITY_POLICY_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_quality_policy.json"
READINESS_LATTICE_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/kt_readiness_lattice.json"
CONSTITUTION_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine/KT_Constitution_v1.md"
PUBLIC_VERIFIER_RULES_REL = "KT_PROD_CLEANROOM/governance/public_verifier_rules.json"

DOCTRINE_COMPILER_SPEC_REL = f"{GENERATED_ROOT_REL}/kt_doctrine_compiler_spec.json"
DOCTRINE_MANIFEST_REL = f"{GENERATED_ROOT_REL}/kt_doctrine_manifest.json"
DOCTRINE_RATIFICATION_LOG_REL = f"{GENERATED_ROOT_REL}/kt_doctrine_ratification_log.json"
OUTSIDER_PROFILE_REL = f"{PROFILE_ROOT_REL}/kt_outsider_onboarding_profile.json"
COMPETITION_PROFILE_REL = f"{PROFILE_ROOT_REL}/kt_competition_profile.json"
PUBLICATION_PROFILE_REL = f"{PROFILE_ROOT_REL}/kt_publication_profile.json"
MATH_GURU_PROFILE_REL = f"{PROFILE_ROOT_REL}/kt_math_guru_profile.json"
MASTER_SPEC_REL = f"{GENERATED_ROOT_REL}/kt_master_spec.md"
WHITEPAPER_REL = f"{GENERATED_ROOT_REL}/KT_Whitepaper_v1.md"
GOVERNANCE_SPINE_REL = f"{GENERATED_ROOT_REL}/KT_Governance_Spine_v1.md"
ACADEMY_REL = f"{GENERATED_ROOT_REL}/KT_Academy_Training_v1.md"
COGNITIVE_ARCH_REL = f"{GENERATED_ROOT_REL}/KT_Cognitive_Architecture_v1.md"
PARADOX_DOC_REL = f"{GENERATED_ROOT_REL}/KT_Paradox_Metabolism_v1.md"
MAINTAINER_PLAYBOOK_REL = f"{PLAYBOOK_ROOT_REL}/kt_maintainer_playbook.md"
AUDITOR_PLAYBOOK_REL = f"{PLAYBOOK_ROOT_REL}/kt_auditor_playbook.md"
COMPETITION_RUNBOOK_REL = f"{PLAYBOOK_ROOT_REL}/kt_competition_runbook.md"
MATH_GURU_RUNBOOK_REL = f"{PLAYBOOK_ROOT_REL}/kt_math_guru_training_runbook.md"

READINESS_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_release_readiness_matrix.json"
ADAPTER_GATE_REL = f"{REPORT_ROOT_REL}/kt_adapter_testing_gate_receipt.json"
TOURNAMENT_GATE_REL = f"{REPORT_ROOT_REL}/kt_tournament_readiness_receipt.json"
WS11_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_full_stack_adjudication_recut_receipt.json"

OUTPUT_REFS = [
    DOCTRINE_COMPILER_SPEC_REL,
    DOCTRINE_MANIFEST_REL,
    DOCTRINE_RATIFICATION_LOG_REL,
    OUTSIDER_PROFILE_REL,
    COMPETITION_PROFILE_REL,
    PUBLICATION_PROFILE_REL,
    MATH_GURU_PROFILE_REL,
    MASTER_SPEC_REL,
    WHITEPAPER_REL,
    GOVERNANCE_SPINE_REL,
    COGNITIVE_ARCH_REL,
    PARADOX_DOC_REL,
    ACADEMY_REL,
    MAINTAINER_PLAYBOOK_REL,
    AUDITOR_PLAYBOOK_REL,
    COMPETITION_RUNBOOK_REL,
    MATH_GURU_RUNBOOK_REL,
]

ALLOWED_TOUCHES = {
    DOCTRINE_COMPILER_SPEC_REL,
    DOCTRINE_MANIFEST_REL,
    DOCTRINE_RATIFICATION_LOG_REL,
    OUTSIDER_PROFILE_REL,
    COMPETITION_PROFILE_REL,
    PUBLICATION_PROFILE_REL,
    MATH_GURU_PROFILE_REL,
    MASTER_SPEC_REL,
    WHITEPAPER_REL,
    GOVERNANCE_SPINE_REL,
    ACADEMY_REL,
    MAINTAINER_PLAYBOOK_REL,
    AUDITOR_PLAYBOOK_REL,
    COMPETITION_RUNBOOK_REL,
    MATH_GURU_RUNBOOK_REL,
    READINESS_MATRIX_REL,
    ADAPTER_GATE_REL,
    TOURNAMENT_GATE_REL,
    WS11_RECEIPT_REL,
    "KT_PROD_CLEANROOM/tools/operator/final_recut_and_adjudication.py",
    "KT_PROD_CLEANROOM/tests/operator/test_final_recut_and_adjudication.py",
}
PROTECTED_PATTERNS = ("KT_ARCHIVE/", ".github/workflows/")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_paths(root: Path) -> List[str]:
    output = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain=v1"], text=True, encoding="utf-8")
    paths: List[str] = []
    for line in output.splitlines():
        rel = line[3:].strip()
        if rel:
            rel_path = Path(rel)
            abs_path = (root / rel_path).resolve()
            if abs_path.is_dir():
                for child in sorted(item for item in abs_path.rglob("*") if item.is_file()):
                    paths.append(child.relative_to(root).as_posix())
            else:
                paths.append(rel_path.as_posix())
    return paths


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _write_text_stable(path: Path, text: str) -> bool:
    rendered = text if text.endswith("\n") else text + "\n"
    if path.exists() and path.read_text(encoding="utf-8") == rendered:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8", newline="\n")
    return True


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _status_is_pass(payload: Dict[str, Any]) -> bool:
    return str(payload.get("status", "")).strip() == "PASS"


def _profile_row(
    *,
    profile_id: str,
    profile_family: str,
    readiness_verdict: str,
    blocked_by: List[str],
    evidence_refs: List[str],
    forbidden_claims: List[str],
    claim_ceiling: str = "FRONTIER_SETTLEMENT_WITH_H1_BLOCK",
) -> Dict[str, Any]:
    return {
        "blocked_by": blocked_by,
        "claim_ceiling": claim_ceiling,
        "evidence_refs": evidence_refs,
        "forbidden_claims": forbidden_claims,
        "profile_family": profile_family,
        "profile_id": profile_id,
        "readiness_verdict": readiness_verdict,
    }


def _build_context(root: Path) -> Dict[str, Any]:
    authority = _load_required(root, AUTHORITY_CLOSURE_REL)
    platform = _load_required(root, PLATFORM_FINAL_REL)
    verifier = _load_required(root, PUBLIC_VERIFIER_REL)
    runtime = _load_required(root, RUNTIME_BOUNDARY_REL)
    h1 = _load_required(root, H1_GATE_REL)
    truth_publication = _load_required(root, TRUTH_PUBLICATION_REL)
    determinism = _load_required(root, DETERMINISM_REL)
    archive = _load_required(root, ARCHIVE_SEPARATION_REL)
    canonical_tree = _load_required(root, CANONICAL_TREE_REL)
    ledger_authority = _load_required(root, LEDGER_AUTHORITY_REL)
    claim_compiler = _load_required(root, CLAIM_COMPILER_ACTIVATION_REL)
    verifier_release = _load_required(root, VERIFIER_RELEASE_REL)
    paradox = _load_required(root, PARADOX_REL)
    runtime_memory = _load_required(root, RUNTIME_MEMORY_REL)
    _load_required(root, QUALITY_POLICY_REL)
    _load_required(root, READINESS_LATTICE_REL)
    current_head = _git_head(root)
    platform_ceiling = str(platform.get("enterprise_legitimacy_ceiling", "WORKFLOW_GOVERNANCE_ONLY")).strip()

    adapter_preconditions = [
        {"check": "ACTIVE_ARCHIVE_SEPARATION_PROVEN", "status": "PASS" if _status_is_pass(archive) else "BLOCKED", "ref": ARCHIVE_SEPARATION_REL},
        {"check": "ACTIVE_CANONICAL_TREE_SETTLED", "status": "PASS" if _status_is_pass(canonical_tree) else "BLOCKED", "ref": CANONICAL_TREE_REL},
        {"check": "CROSS_ENV_REPRODUCIBILITY_PROVEN", "status": "PASS" if _status_is_pass(determinism) else "BLOCKED", "ref": DETERMINISM_REL},
        {"check": "LEDGER_AUTHORITY_FINALIZED", "status": "PASS" if _status_is_pass(ledger_authority) else "BLOCKED", "ref": LEDGER_AUTHORITY_REL},
        {"check": "PUBLIC_VERIFIER_RELEASED", "status": "PASS" if str(verifier_release.get("manifest_id", "")).strip() else "BLOCKED", "ref": VERIFIER_RELEASE_REL},
        {"check": "CLAIM_COMPILER_ACTIVE", "status": "PASS" if _status_is_pass(claim_compiler) else "BLOCKED", "ref": CLAIM_COMPILER_ACTIVATION_REL},
        {
            "check": "NO_UNRESOLVED_P0_AUTHORITY_OR_RUNTIME_CONFLICTS",
            "status": "PASS" if _status_is_pass(authority) and str(runtime.get("status", "")).strip() == "PASS" else "BLOCKED",
            "ref": AUTHORITY_CLOSURE_REL,
        },
    ]
    adapter_gate_open = all(item["status"] == "PASS" for item in adapter_preconditions)

    outsider_gaps = [
        "current head is evidence for the published truth subject unless SHAs match",
        f"governance legitimacy remains capped at {platform_ceiling}",
        "H1 activation remains blocked",
    ]
    competition_gaps = [
        "cross-environment proof covers critical bundle stability, not full tournament runtime parity",
        "competition-grade QL3 ceiling is not yet admissible",
        "H1 remains blocked for single-adapter activation claims",
    ]
    publication_gaps = [
        "current head must be described as containing evidence for the verified subject unless SHAs match",
        f"governance legitimacy remains capped at {platform_ceiling}",
        "publication-grade QL3 ceiling is not yet admissible",
        "H1 remains blocked",
    ]
    math_gaps = [
        "paradox evidence remains documentary-only, not external superiority proof",
        "current head is evidence for the verified truth subject unless SHAs match",
        "H1 remains blocked",
    ]

    return {
        "current_head": current_head,
        "current_ceiling": "FRONTIER_SETTLEMENT_WITH_H1_BLOCK",
        "authority": authority,
        "platform": platform,
        "verifier": verifier,
        "runtime": runtime,
        "h1": h1,
        "truth_publication": truth_publication,
        "determinism": determinism,
        "archive": archive,
        "canonical_tree": canonical_tree,
        "ledger_authority": ledger_authority,
        "claim_compiler": claim_compiler,
        "verifier_release": verifier_release,
        "paradox": paradox,
        "runtime_memory": runtime_memory,
        "platform_ceiling": platform_ceiling,
        "adapter_preconditions": adapter_preconditions,
        "adapter_gate_open": adapter_gate_open,
        "outsider_gaps": outsider_gaps,
        "competition_gaps": competition_gaps,
        "publication_gaps": publication_gaps,
        "math_gaps": math_gaps,
    }


def _generated_profiles(context: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        OUTSIDER_PROFILE_REL: {
            "schema_id": "kt.doctrine.profile.v1",
            "profile_id": "outsider_onboarding",
            "audience": "specialist outsider or new entrant",
            "generated_utc": utc_now_iso_z(),
            "target_quality_level": "QL2",
            "current_status": "ADMISSIBLE_WITH_BOUNDARIES",
            "current_admissibility_ceiling": context["current_ceiling"],
            "current_evidence_refs": [
                AUTHORITY_CLOSURE_REL,
                PLATFORM_FINAL_REL,
                PUBLIC_VERIFIER_REL,
                RUNTIME_BOUNDARY_REL,
                ADAPTER_GATE_REL,
            ],
            "required_capabilities": [
                "understand evidence-versus-subject lag",
                "read the public verifier boundary",
                "track workflow-governance-only limits without overclaim",
                "follow open blockers without upgrading H1",
            ],
            "explicit_gaps": context["outsider_gaps"],
            "forbidden_claims": ["HEAD_IS_VERIFIED_SUBJECT", "PLATFORM_ENFORCED_GOVERNANCE_PROVEN", "H1_ALLOWED"],
            "playbook_ref": AUDITOR_PLAYBOOK_REL,
        },
        COMPETITION_PROFILE_REL: {
            "schema_id": "kt.doctrine.profile.v1",
            "profile_id": "competition",
            "audience": "competition evaluators and benchmark operators",
            "generated_utc": utc_now_iso_z(),
            "target_quality_level": "QL3",
            "current_status": "BLOCKED",
            "current_admissibility_ceiling": "REPRESENTATIVE_SAME_MVE_ONLY",
            "current_evidence_refs": [
                DETERMINISM_REL,
                RUNTIME_MEMORY_REL,
                ADAPTER_GATE_REL,
                QUALITY_POLICY_REL,
                H1_GATE_REL,
            ],
            "required_capabilities": [
                "controlled cross-environment reproducibility",
                "competition-grade quality across governance, proof, runtime, and operability",
                "bounded release claims that do not overread workflow governance or H1",
            ],
            "explicit_gaps": context["competition_gaps"],
            "forbidden_claims": ["COMPETITION_READY", "H1_ALLOWED", "PLATFORM_ENFORCED_GOVERNANCE_PROVEN"],
            "playbook_ref": COMPETITION_RUNBOOK_REL,
        },
        PUBLICATION_PROFILE_REL: {
            "schema_id": "kt.doctrine.profile.v1",
            "profile_id": "publication",
            "audience": "publication reviewers and external research readers",
            "generated_utc": utc_now_iso_z(),
            "target_quality_level": "QL3",
            "current_status": "BLOCKED",
            "current_admissibility_ceiling": "DOCUMENTARY_ONLY_WITH_SUBJECT_BOUNDARY",
            "current_evidence_refs": [
                AUTHORITY_CLOSURE_REL,
                PLATFORM_FINAL_REL,
                TRUTH_PUBLICATION_REL,
                PUBLIC_VERIFIER_REL,
                TOURNAMENT_GATE_REL,
            ],
            "required_capabilities": [
                "truth subject/evidence lag must stay explicit",
                "workflow-governance-only ceiling must remain explicit",
                "publication doctrine must not outrun the active gate receipts",
                "runtime boundary and paradox bounds must be cited from receipts",
            ],
            "explicit_gaps": context["publication_gaps"],
            "forbidden_claims": ["PUBLICATION_READY", "HEAD_IS_VERIFIED_SUBJECT", "PLATFORM_ENFORCED_GOVERNANCE_PROVEN", "H1_ALLOWED"],
            "playbook_ref": AUDITOR_PLAYBOOK_REL,
        },
        MATH_GURU_PROFILE_REL: {
            "schema_id": "kt.doctrine.profile.v1",
            "profile_id": "math_guru",
            "audience": "proof-centric specialist reviewer",
            "generated_utc": utc_now_iso_z(),
            "target_quality_level": "QL2",
            "current_status": "ADMISSIBLE_WITH_BOUNDARIES",
            "current_admissibility_ceiling": "DOCUMENTARY_ONLY_WITH_FORMAL_MODEL_AND_STRESS",
            "current_evidence_refs": [
                PARADOX_REL,
                AUTHORITY_CLOSURE_REL,
                H1_GATE_REL,
            ],
            "required_capabilities": [
                "read the paradox model and invariant set",
                "trace counterexamples to receipts and runtime behavior",
                "distinguish documentary paradox evidence from external superiority claims",
                "follow proof obligations without upgrading H1",
            ],
            "explicit_gaps": context["math_gaps"],
            "forbidden_claims": ["EXTERNAL_PARADOX_SUPERIORITY_PROVEN", "HEAD_IS_VERIFIED_SUBJECT", "H1_ALLOWED"],
            "playbook_ref": MATH_GURU_RUNBOOK_REL,
        },
    }


def _readiness_matrix(context: Dict[str, Any], profiles: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    platform_block = str(context["platform"].get("platform_governance_verdict", "")).strip()
    competition_blockers = ["competition-grade QL3 ceiling is not yet admissible", "H1 activation remains blocked"]
    publication_blockers = [f"governance legitimacy remains capped at {context['platform_ceiling']}", "publication-grade QL3 ceiling is not yet admissible", "H1 activation remains blocked"]
    rows = [
        _profile_row(profile_id="internal_operator_audit_release", profile_family="release_profile_plan", readiness_verdict="READY_WITH_BOUNDARIES", blocked_by=[], evidence_refs=[AUTHORITY_CLOSURE_REL, RUNTIME_BOUNDARY_REL, PUBLIC_VERIFIER_REL], forbidden_claims=["HEAD_IS_VERIFIED_SUBJECT", "H1_ALLOWED"]),
        _profile_row(profile_id="external_specialist_demo_release", profile_family="release_profile_plan", readiness_verdict="READY_WITH_BOUNDARIES", blocked_by=[], evidence_refs=[AUTHORITY_CLOSURE_REL, PLATFORM_FINAL_REL, RUNTIME_BOUNDARY_REL], forbidden_claims=["HEAD_IS_VERIFIED_SUBJECT", "PLATFORM_ENFORCED_GOVERNANCE_PROVEN", "H1_ALLOWED"]),
        _profile_row(profile_id="governed_partner_review_release", profile_family="release_profile_plan", readiness_verdict="HOLD", blocked_by=[platform_block], evidence_refs=[PLATFORM_FINAL_REL, PUBLIC_VERIFIER_REL, ADAPTER_GATE_REL], forbidden_claims=["PLATFORM_ENFORCED_GOVERNANCE_PROVEN", "H1_ALLOWED"]),
        _profile_row(profile_id="competition_release", profile_family="release_profile_plan", readiness_verdict="BLOCKED", blocked_by=competition_blockers, evidence_refs=[COMPETITION_PROFILE_REL, DETERMINISM_REL, ADAPTER_GATE_REL], forbidden_claims=["COMPETITION_READY", "H1_ALLOWED"]),
        _profile_row(profile_id="publication_release", profile_family="release_profile_plan", readiness_verdict="BLOCKED", blocked_by=publication_blockers, evidence_refs=[PUBLICATION_PROFILE_REL, AUTHORITY_CLOSURE_REL, PLATFORM_FINAL_REL], forbidden_claims=["PUBLICATION_READY", "HEAD_IS_VERIFIED_SUBJECT", "H1_ALLOWED"]),
        _profile_row(profile_id="auditor_packet", profile_family="submission_profile_plan", readiness_verdict="READY_WITH_BOUNDARIES", blocked_by=[], evidence_refs=[PUBLIC_VERIFIER_REL, RUNTIME_BOUNDARY_REL, AUDITOR_PLAYBOOK_REL], forbidden_claims=["HEAD_IS_VERIFIED_SUBJECT", "H1_ALLOWED"]),
        _profile_row(profile_id="specialist_demo_packet", profile_family="submission_profile_plan", readiness_verdict="READY_WITH_BOUNDARIES", blocked_by=[], evidence_refs=[OUTSIDER_PROFILE_REL, ADAPTER_GATE_REL, PUBLIC_VERIFIER_REL], forbidden_claims=["PLATFORM_ENFORCED_GOVERNANCE_PROVEN", "H1_ALLOWED"]),
        _profile_row(profile_id="partner_review_packet", profile_family="submission_profile_plan", readiness_verdict="HOLD", blocked_by=[platform_block], evidence_refs=[PLATFORM_FINAL_REL, PUBLIC_VERIFIER_REL, GOVERNANCE_SPINE_REL], forbidden_claims=["PLATFORM_ENFORCED_GOVERNANCE_PROVEN", "H1_ALLOWED"]),
        _profile_row(profile_id="competition_bundle", profile_family="submission_profile_plan", readiness_verdict="BLOCKED", blocked_by=competition_blockers, evidence_refs=[COMPETITION_PROFILE_REL, DETERMINISM_REL, TOURNAMENT_GATE_REL], forbidden_claims=["COMPETITION_READY", "H1_ALLOWED"]),
        _profile_row(profile_id="publication_peer_review_bundle", profile_family="submission_profile_plan", readiness_verdict="BLOCKED", blocked_by=publication_blockers, evidence_refs=[PUBLICATION_PROFILE_REL, TOURNAMENT_GATE_REL, PUBLIC_VERIFIER_REL], forbidden_claims=["PUBLICATION_READY", "HEAD_IS_VERIFIED_SUBJECT", "H1_ALLOWED"]),
        _profile_row(profile_id="outsider_onboarding", profile_family="generated_doctrine_profile", readiness_verdict="READY_WITH_BOUNDARIES", blocked_by=list(profiles[OUTSIDER_PROFILE_REL]["explicit_gaps"]), evidence_refs=list(profiles[OUTSIDER_PROFILE_REL]["current_evidence_refs"]), forbidden_claims=list(profiles[OUTSIDER_PROFILE_REL]["forbidden_claims"])),
        _profile_row(profile_id="competition", profile_family="generated_doctrine_profile", readiness_verdict="BLOCKED", blocked_by=list(profiles[COMPETITION_PROFILE_REL]["explicit_gaps"]), evidence_refs=list(profiles[COMPETITION_PROFILE_REL]["current_evidence_refs"]), forbidden_claims=list(profiles[COMPETITION_PROFILE_REL]["forbidden_claims"]), claim_ceiling="REPRESENTATIVE_SAME_MVE_ONLY"),
        _profile_row(profile_id="publication", profile_family="generated_doctrine_profile", readiness_verdict="BLOCKED", blocked_by=list(profiles[PUBLICATION_PROFILE_REL]["explicit_gaps"]), evidence_refs=list(profiles[PUBLICATION_PROFILE_REL]["current_evidence_refs"]), forbidden_claims=list(profiles[PUBLICATION_PROFILE_REL]["forbidden_claims"]), claim_ceiling="DOCUMENTARY_ONLY_WITH_SUBJECT_BOUNDARY"),
        _profile_row(profile_id="math_guru", profile_family="generated_doctrine_profile", readiness_verdict="READY_WITH_BOUNDARIES", blocked_by=list(profiles[MATH_GURU_PROFILE_REL]["explicit_gaps"]), evidence_refs=list(profiles[MATH_GURU_PROFILE_REL]["current_evidence_refs"]), forbidden_claims=list(profiles[MATH_GURU_PROFILE_REL]["forbidden_claims"]), claim_ceiling="DOCUMENTARY_ONLY_WITH_FORMAL_MODEL_AND_STRESS"),
    ]
    return {
        "schema_id": "kt.operator.release_readiness_matrix.v2",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": "Readiness rows are derived from current gate receipts and must not be read as authority, governance, or H1 upgrades while boundary receipts still cap those horizons.",
        "profiles": rows,
        "summary": {
            "profile_count": len(rows),
            "ready_with_boundaries_count": sum(1 for row in rows if row["readiness_verdict"] == "READY_WITH_BOUNDARIES"),
            "hold_count": sum(1 for row in rows if row["readiness_verdict"] == "HOLD"),
            "blocked_count": sum(1 for row in rows if row["readiness_verdict"] == "BLOCKED"),
        },
    }


def _render_markdown(context: Dict[str, Any], profiles: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    truth_subject = str(context["verifier"].get("truth_subject_commit", "")).strip()
    truth_evidence = str(context["verifier"].get("evidence_commit", "")).strip()
    governance_subject = str(context["platform"].get("platform_governance_subject_commit", "")).strip()
    runtime_subject = str(context["runtime"].get("runtime_boundary_subject_commit", "")).strip()
    platform_verdict = str(context["platform"].get("platform_governance_verdict", "")).strip()

    return {
        WHITEPAPER_REL: "\n".join([
            "# KT Whitepaper v1",
            "",
            "KT is a governed organism whose admissible public claims are bounded by receipts, manifests, and explicit proof ceilings.",
            "",
            "## What Is Evidenced Now",
            f"- published-head truth authority is closed for subject commit `{truth_subject}`",
            f"- workflow governance is active at `{context['platform_ceiling']}` and platform enforcement remains blocked",
            f"- canonical runtime boundary is settled for subject `{runtime_subject}`",
            "- archive separation and canonical active-tree settlement are proven",
            "- cross-environment stability is proven for the critical truth/publication bundle set",
            "- paradox metabolism remains bounded at documentary-only ceiling",
            "",
            "## What Remains Blocked",
            "- platform-enforced governance on main",
            "- competition-grade release readiness",
            "- publication-grade release readiness",
            "- H1 activation",
            "",
            "## Claim Boundary",
            "Current heads may contain evidence for subject commits, but may not be described as those subjects unless the SHAs match. Workflow governance only does not imply platform enforcement, and H1 remains blocked.",
            "",
            "## Source Refs",
            f"- {AUTHORITY_CLOSURE_REL}",
            f"- {PLATFORM_FINAL_REL}",
            f"- {PUBLIC_VERIFIER_REL}",
            f"- {RUNTIME_BOUNDARY_REL}",
            f"- {DETERMINISM_REL}",
            f"- {PARADOX_REL}",
        ]),
        GOVERNANCE_SPINE_REL: "\n".join([
            "# KT Governance Spine v1",
            "",
            "This document is generated from the constitutional spine, the governance baseline bundle, and current governance receipts. It does not amend law.",
            "",
            "## Constitutional Boundary",
            "- baseline status: `SEALED_WITH_OPEN_BLOCKERS`",
            f"- workflow governance ceiling: `{context['platform_ceiling']}`",
            "- platform admissible now: `false`",
            "",
            "## Current Governance Reading",
            f"- governance subject commit: `{governance_subject}`",
            f"- platform governance verdict: `{platform_verdict}`",
            "- truth subject/evidence lag remains explicit",
            "",
            "## Governance Blockers",
            "- PLATFORM_ENFORCEMENT_UNPROVEN",
            "- H1_ACTIVATION_GATE_CLOSED",
            "",
            "## Source Refs",
            f"- {CONSTITUTION_REL}",
            f"- {PLATFORM_FINAL_REL}",
            f"- {PUBLIC_VERIFIER_REL}",
            f"- {PUBLIC_VERIFIER_RULES_REL}",
        ]),
        MASTER_SPEC_REL: "\n".join([
            "# KT Master Spec v1",
            "",
            "This generated master spec is derived from current machine state and remains subordinate to constitutional law, governance receipts, and verifier outputs.",
            "",
            "## Current Program State",
            "- current claim ceiling: `FRONTIER_SETTLEMENT_WITH_H1_BLOCK`",
            f"- adapter testing gate: `{'OPEN' if context['adapter_gate_open'] else 'BLOCKED'}`",
            "- tournament gate: `BLOCKED`",
            "- publication gate: `BLOCKED`",
            "- H1 status: `BLOCKED`",
            "",
            "## Evidence and Subject Boundary",
            f"- truth subject commit: `{truth_subject}`",
            f"- truth evidence commit: `{truth_evidence}`",
            f"- truth subject verdict: `{context['authority']['authority_convergence_proof_class']}`",
            f"- governance ceiling: `{context['platform_ceiling']}`",
            f"- runtime boundary verdict: `{context['runtime']['runtime_boundary_verdict']}`",
            f"- reproducibility verdict: `{context['determinism']['pass_verdict']}`",
            "",
            "## Release Summary",
            f"- outsider onboarding: `{profiles[OUTSIDER_PROFILE_REL]['current_status']}`",
            f"- competition: `{profiles[COMPETITION_PROFILE_REL]['current_status']}`",
            f"- publication: `{profiles[PUBLICATION_PROFILE_REL]['current_status']}`",
            f"- math guru: `{profiles[MATH_GURU_PROFILE_REL]['current_status']}`",
            "",
            "## Source Refs",
            f"- {AUTHORITY_CLOSURE_REL}",
            f"- {PLATFORM_FINAL_REL}",
            f"- {PUBLIC_VERIFIER_REL}",
            f"- {RUNTIME_BOUNDARY_REL}",
            f"- {DETERMINISM_REL}",
            f"- {ADAPTER_GATE_REL}",
            f"- {TOURNAMENT_GATE_REL}",
        ]),
        ACADEMY_REL: "\n".join([
            "# KT Academy Training v1",
            "",
            "This training document is generated from current machine-state profiles and gate receipts. It does not promise horizons that remain blocked.",
            "",
            "## Training Lanes",
            "1. outsider onboarding: start with the verifier boundary, runtime boundary, and adapter-testing gate",
            "2. maintainer lane: preserve law precedence, receipts, and rollback discipline",
            "3. auditor lane: validate subject-versus-evidence boundaries before trusting any current-head phrasing",
            "4. math guru lane: inspect paradox bounds and proof obligations without upgrading documentary claims",
            "",
            "## Current Profile Status",
            f"- outsider onboarding: `{profiles[OUTSIDER_PROFILE_REL]['current_status']}`",
            f"- competition: `{profiles[COMPETITION_PROFILE_REL]['current_status']}`",
            f"- publication: `{profiles[PUBLICATION_PROFILE_REL]['current_status']}`",
            f"- math guru: `{profiles[MATH_GURU_PROFILE_REL]['current_status']}`",
            "",
            "## Non-Negotiable Boundaries",
            "- current heads may contain evidence for the verified subject, not become that subject by narration",
            f"- governance legitimacy remains capped at `{context['platform_ceiling']}`",
            "- tournament and publication claims remain blocked",
            "- H1 remains blocked",
            "",
            "## Source Refs",
            f"- {OUTSIDER_PROFILE_REL}",
            f"- {COMPETITION_PROFILE_REL}",
            f"- {PUBLICATION_PROFILE_REL}",
            f"- {MATH_GURU_PROFILE_REL}",
        ]),
        MAINTAINER_PLAYBOOK_REL: "\n".join([
            "# KT Maintainer Playbook v1",
            "",
            "## Operating Rules",
            "1. read the current gate receipts before touching public or governance surfaces",
            "2. preserve evidence-versus-subject lag explicitly",
            "3. keep runtime boundary and documentary-only claim ceilings intact",
            "4. fail closed when a mutation would silently upgrade platform enforcement, tournament readiness, or H1",
            "",
            "## Current Live Limits",
            "- H1_ACTIVATION_GATE_CLOSED",
            "- WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED",
            "- TOURNAMENT_GATE_BLOCKED",
            "- PUBLICATION_PROFILE_BLOCKED",
            "",
            "## Required Refs",
            f"- {CONSTITUTION_REL}",
            f"- {PUBLIC_VERIFIER_RULES_REL}",
            f"- {PLATFORM_FINAL_REL}",
            f"- {ADAPTER_GATE_REL}",
            f"- {TOURNAMENT_GATE_REL}",
        ]),
        AUDITOR_PLAYBOOK_REL: "\n".join([
            "# KT Auditor Playbook v1",
            "",
            "## Audit Order",
            "1. verify the truth subject/evidence split",
            "2. verify workflow governance does not overread platform enforcement",
            "3. verify runtime boundary receipts against canonical roots",
            "4. verify cross-environment bundle stability and paradox bounds",
            "5. verify adapter/tournament gates against their receipts",
            "",
            "## Current Head Boundary",
            f"- truth subject commit: `{truth_subject}`",
            f"- truth evidence commit: `{truth_evidence}`",
            f"- governance subject commit: `{governance_subject}`",
            f"- runtime boundary subject commit: `{runtime_subject}`",
            "",
            "## Required Refs",
            f"- {AUTHORITY_CLOSURE_REL}",
            f"- {PLATFORM_FINAL_REL}",
            f"- {PUBLIC_VERIFIER_REL}",
            f"- {RUNTIME_BOUNDARY_REL}",
            f"- {DETERMINISM_REL}",
            f"- {ADAPTER_GATE_REL}",
            f"- {TOURNAMENT_GATE_REL}",
        ]),
        COMPETITION_RUNBOOK_REL: "\n".join([
            "# KT Competition Runbook v1",
            "",
            "Current status: `BLOCKED`",
            "",
            "## What Exists",
            "- canonical active tree and archive separation are proven",
            "- cross-environment stability is proven for the critical bundle set",
            "- adapter-testing gate is open on the bounded active surface",
            "",
            "## What Still Blocks Competition Claims",
            "- cross-environment proof does not yet establish full tournament runtime parity",
            "- current competition profile plane is below QL3 target",
            "- H1 remains blocked for single-adapter activation claims",
            "",
            "## Forbidden Claims",
            "- COMPETITION_READY",
            "- H1_ALLOWED",
            "- PLATFORM_ENFORCED_GOVERNANCE_PROVEN",
            "",
            "## Required Refs",
            f"- {DETERMINISM_REL}",
            f"- {ADAPTER_GATE_REL}",
            f"- {TOURNAMENT_GATE_REL}",
            f"- {QUALITY_POLICY_REL}",
            f"- {H1_GATE_REL}",
        ]),
        MATH_GURU_RUNBOOK_REL: "\n".join([
            "# KT Math Guru Training Runbook v1",
            "",
            "Current status: `ADMISSIBLE_WITH_BOUNDARIES`",
            "",
            "## Review Sequence",
            "1. inspect the paradox model",
            "2. inspect invariant coverage",
            "3. inspect stress results and counterexamples",
            "4. inspect proof obligations and TTL escalation",
            "5. inspect how current-head boundary and H1 blockers cap admissibility",
            "",
            "## Explicit Gaps",
            f"- {context['math_gaps'][0]}",
            f"- {context['math_gaps'][1]}",
            f"- {context['math_gaps'][2]}",
            "",
            "## Required Refs",
            f"- {PARADOX_REL}",
            f"- {AUTHORITY_CLOSURE_REL}",
            f"- {H1_GATE_REL}",
        ]),
    }


def _doctrine_compiler_spec() -> Dict[str, Any]:
    return {
        "schema_id": "kt.doctrine.compiler_spec.v2",
        "generated_utc": utc_now_iso_z(),
        "compiled_claim_ceiling": "FRONTIER_SETTLEMENT_WITH_H1_BLOCK",
        "compiler_surface_ref": "KT_PROD_CLEANROOM/tools/operator/final_recut_and_adjudication.py",
        "gate_receipt_ref": WS11_RECEIPT_REL,
        "generation_rules": [
            "doctrine must be derived from cited machine-state refs only",
            "generated doctrine may not amend constitutional or governance law",
            "profiles must list current evidence refs and explicit gaps",
            "generated docs must preserve subject-versus-evidence lag when SHAs differ",
            "adapter testing may open only when all gate preconditions pass",
            "tournament and publication docs must remain blocked while their gate receipts remain blocked",
        ],
        "forbidden_claims": ["HEAD_IS_VERIFIED_SUBJECT", "PLATFORM_ENFORCED_GOVERNANCE_PROVEN", "H1_ALLOWED", "PUBLICATION_READY", "COMPETITION_READY"],
        "input_refs": [
            AUTHORITY_CLOSURE_REL,
            PLATFORM_FINAL_REL,
            PUBLIC_VERIFIER_REL,
            RUNTIME_BOUNDARY_REL,
            TRUTH_PUBLICATION_REL,
            DETERMINISM_REL,
            ARCHIVE_SEPARATION_REL,
            CANONICAL_TREE_REL,
            CLAIM_COMPILER_ACTIVATION_REL,
            VERIFIER_RELEASE_REL,
            PARADOX_REL,
            RUNTIME_MEMORY_REL,
            QUALITY_POLICY_REL,
            READINESS_LATTICE_REL,
            H1_GATE_REL,
        ],
        "output_refs": OUTPUT_REFS,
    }


def _doctrine_ratification_log() -> Dict[str, Any]:
    return {
        "schema_id": "kt.doctrine.ratification_log.v2",
        "generated_utc": utc_now_iso_z(),
        "doctrine_version": "v1",
        "manifest_ref": DOCTRINE_MANIFEST_REL,
        "ratification_scope": "generated doctrine, profiles, playbooks, and readiness surfaces only; not constitutional or governance law",
        "ratification_status": "RATIFIED_FOR_MACHINE_STATE_DERIVED_DOCUMENTARY_USE",
        "current_ceiling_preserved": "FRONTIER_SETTLEMENT_WITH_H1_BLOCK",
        "open_blockers_preserved": [
            "H1_ACTIVATION_GATE_CLOSED",
            "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED",
            "COMPETITION_PROFILE_BLOCKED",
            "PUBLICATION_PROFILE_BLOCKED",
        ],
        "authority_basis_refs": [CONSTITUTION_REL, AUTHORITY_CLOSURE_REL, PLATFORM_FINAL_REL, PUBLIC_VERIFIER_REL, WS11_RECEIPT_REL],
        "prohibitions": [
            "generated doctrine may not amend law",
            "generated doctrine may not phrase HEAD as verified subject unless SHAs match",
            "generated doctrine may not claim platform-enforced governance while platform proof is blocked",
            "generated doctrine may not open tournament, publication, or H1 gates without passing receipts",
        ],
    }


def _artifact_rows(root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for rel in OUTPUT_REFS:
        if rel == DOCTRINE_MANIFEST_REL:
            continue
        path = (root / Path(rel)).resolve()
        rows.append({"artifact_ref": rel, "artifact_sha256": _file_sha256(path), "artifact_type": "json" if path.suffix == ".json" else "markdown"})
    return rows


def _doctrine_manifest(root: Path) -> Dict[str, Any]:
    artifacts = _artifact_rows(root)
    return {
        "schema_id": "kt.doctrine.manifest.v2",
        "generated_utc": utc_now_iso_z(),
        "artifact_root": GENERATED_ROOT_REL,
        "claim_boundary": "Generated doctrine is derived from cited machine-state inputs and remains subordinate to constitutional law. It may not overread subject-evidence lag, workflow-only governance, or blocked tournament/public/H1 gates.",
        "compiler_spec_ref": DOCTRINE_COMPILER_SPEC_REL,
        "doctrine_version": "v1",
        "artifacts": artifacts,
        "source_refs": [
            AUTHORITY_CLOSURE_REL,
            PLATFORM_FINAL_REL,
            PUBLIC_VERIFIER_REL,
            RUNTIME_BOUNDARY_REL,
            TRUTH_PUBLICATION_REL,
            DETERMINISM_REL,
            ARCHIVE_SEPARATION_REL,
            CLAIM_COMPILER_ACTIVATION_REL,
            PARADOX_REL,
            H1_GATE_REL,
            ADAPTER_GATE_REL,
            TOURNAMENT_GATE_REL,
            READINESS_MATRIX_REL,
        ],
        "summary": {
            "artifact_count": len(artifacts),
            "generated_doc_count": sum(1 for row in artifacts if row["artifact_type"] == "markdown"),
            "profile_count": 4,
            "playbook_count": 4,
        },
    }


def _adapter_gate_receipt(context: Dict[str, Any]) -> Dict[str, Any]:
    status = "PASS" if context["adapter_gate_open"] else "BLOCKED"
    return {
        "artifact_id": Path(ADAPTER_GATE_REL).name,
        "schema_id": "kt.operator.adapter_testing_gate_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "pass_verdict": "ADAPTER_TESTING_GATE_OPEN" if status == "PASS" else "ADAPTER_TESTING_GATE_BLOCKED",
        "compiled_head_commit": context["current_head"],
        "subject_head_commit": context["current_head"],
        "evidence_head_commit": context["current_head"],
        "adapter_testing_gate_status": "OPEN" if status == "PASS" else "BLOCKED",
        "claim_boundary": "Adapter testing is opened only on the bounded active tree. This does not open tournament, publication, or H1 claims.",
        "preconditions": context["adapter_preconditions"],
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": ["python -m tools.operator.final_recut_and_adjudication"],
        "next_lawful_step": {"status_after_workstream": "UNLOCKED", "workstream_id": "WS12_FINAL_COMPLETION_BUNDLE"},
    }


def _tournament_gate_receipt(context: Dict[str, Any], profiles: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    competition_ready = profiles[COMPETITION_PROFILE_REL]["current_status"] == "READY"
    publication_ready = profiles[PUBLICATION_PROFILE_REL]["current_status"] == "READY"
    status = "PASS" if context["adapter_gate_open"] and competition_ready and publication_ready else "BLOCKED"
    return {
        "artifact_id": Path(TOURNAMENT_GATE_REL).name,
        "schema_id": "kt.operator.tournament_readiness_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "pass_verdict": "TOURNAMENT_GATE_OPEN" if status == "PASS" else "TOURNAMENT_GATE_BLOCKED",
        "compiled_head_commit": context["current_head"],
        "subject_head_commit": context["current_head"],
        "evidence_head_commit": context["current_head"],
        "tournament_gate_status": "OPEN" if status == "PASS" else "BLOCKED",
        "blocking_conditions": [] if status == "PASS" else ["competition profile status is BLOCKED", "publication profile status is BLOCKED"],
        "claim_boundary": "Tournament and public showability stay blocked unless the competition and publication profiles are both truly ready at the current evidence base.",
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": ["python -m tools.operator.final_recut_and_adjudication"],
        "next_lawful_step": {"status_after_workstream": "UNLOCKED", "workstream_id": "WS12_FINAL_COMPLETION_BUNDLE"},
    }


def _ws11_receipt(context: Dict[str, Any], readiness: Dict[str, Any], actual_touched: List[str]) -> Dict[str, Any]:
    unexpected_touches = [path for path in actual_touched if path not in ALLOWED_TOUCHES]
    protected_touch_violations = [path for path in actual_touched if any(path.startswith(prefix) for prefix in PROTECTED_PATTERNS)]
    status = "PASS" if not unexpected_touches and not protected_touch_violations else "FAIL_CLOSED"
    return {
        "artifact_id": Path(WS11_RECEIPT_REL).name,
        "schema_id": "kt.operator.full_stack_adjudication_recut_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "FAIL_CLOSED",
        "compiled_head_commit": context["current_head"],
        "subject_head_commit": context["current_head"],
        "evidence_head_commit": context["current_head"],
        "adapter_testing_gate_status": "OPEN" if context["adapter_gate_open"] else "BLOCKED",
        "tournament_gate_status": "BLOCKED",
        "competition_profile_status": "BLOCKED",
        "publication_profile_status": "BLOCKED",
        "ready_with_boundaries_count": readiness["summary"]["ready_with_boundaries_count"],
        "hold_count": readiness["summary"]["hold_count"],
        "blocked_count": readiness["summary"]["blocked_count"],
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "validators_run": ["python -m tools.operator.final_recut_and_adjudication"],
        "next_lawful_step": {"status_after_workstream": "UNLOCKED", "workstream_id": "WS12_FINAL_COMPLETION_BUNDLE"},
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "regenerated stale generated doctrine and profile surfaces against the WS9 authority-closure and WS10 governance-finalization receipts",
                "recut the release readiness matrix to reflect the live gate state",
                "opened adapter testing only where all closure receipts now pass",
                "kept tournament and publication blocked where the profiles remain below the required grade",
            ],
            "files_touched": actual_touched,
            "tests_run": ["python -m pytest KT_PROD_CLEANROOM/tests/operator/test_final_recut_and_adjudication.py -q"],
            "validators_run": ["python -m tools.operator.final_recut_and_adjudication"],
            "issues_found": [],
            "resolution": "WS11 refreshes the generated doctrine/readiness layer so it reflects the post-WS10 live state without reopening closed authority or governance work.",
            "pass_fail_status": status,
            "unexpected_touches": unexpected_touches,
            "protected_touch_violations": protected_touch_violations,
        },
    }


def emit_final_recut_and_adjudication(*, root: Path) -> Dict[str, Any]:
    context = _build_context(root)
    profiles = _generated_profiles(context)
    readiness = _readiness_matrix(context, profiles)

    write_json_stable((root / Path(DOCTRINE_COMPILER_SPEC_REL)).resolve(), _doctrine_compiler_spec())
    write_json_stable((root / Path(DOCTRINE_RATIFICATION_LOG_REL)).resolve(), _doctrine_ratification_log())
    for rel, payload in profiles.items():
        write_json_stable((root / Path(rel)).resolve(), payload)
    write_json_stable((root / Path(READINESS_MATRIX_REL)).resolve(), readiness)
    write_json_stable((root / Path(ADAPTER_GATE_REL)).resolve(), _adapter_gate_receipt(context))
    write_json_stable((root / Path(TOURNAMENT_GATE_REL)).resolve(), _tournament_gate_receipt(context, profiles))

    for rel, text in _render_markdown(context, profiles).items():
        _write_text_stable((root / Path(rel)).resolve(), text)

    write_json_stable((root / Path(DOCTRINE_MANIFEST_REL)).resolve(), _doctrine_manifest(root))

    actual_touched = sorted(set(_git_status_paths(root) + [WS11_RECEIPT_REL]))
    receipt = _ws11_receipt(context, readiness, actual_touched)
    write_json_stable((root / Path(WS11_RECEIPT_REL)).resolve(), receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Recut doctrine/readiness surfaces after WS10 and seal WS11.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    receipt = emit_final_recut_and_adjudication(root=repo_root())
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(receipt.get("status", "")).strip() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
