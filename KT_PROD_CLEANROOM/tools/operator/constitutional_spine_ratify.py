from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


CONSTITUTION_ROOT_REL = "KT_PROD_CLEANROOM/governance/constitutional_spine"
CONSTITUTION_DOC_REL = f"{CONSTITUTION_ROOT_REL}/KT_Constitution_v1.md"
MANIFEST_REL = f"{CONSTITUTION_ROOT_REL}/kt_constitution_manifest.json"
META_GOVERNANCE_REL = f"{CONSTITUTION_ROOT_REL}/kt_meta_governance_policy.json"
COURT_PROCEDURE_REL = f"{CONSTITUTION_ROOT_REL}/kt_constitutional_court_procedure.json"
DEPENDENCY_MATRIX_REL = f"{CONSTITUTION_ROOT_REL}/kt_organ_dependency_matrix.json"
EPOCH_MODEL_REL = f"{CONSTITUTION_ROOT_REL}/kt_epoch_model.json"
QUALITY_POLICY_REL = f"{CONSTITUTION_ROOT_REL}/kt_quality_policy.json"
READINESS_LATTICE_REL = f"{CONSTITUTION_ROOT_REL}/kt_readiness_lattice.json"
FORGETTING_LAW_REL = f"{CONSTITUTION_ROOT_REL}/kt_forgetting_law.json"
ACCREDITATION_POLICY_REL = f"{CONSTITUTION_ROOT_REL}/kt_accreditation_policy.json"
SELF_DESCRIPTION_REL = f"{CONSTITUTION_ROOT_REL}/kt_self_description.json"
COST_MODEL_REL = f"{CONSTITUTION_ROOT_REL}/kt_cost_model.json"

JSON_ARTIFACT_REFS = [
    MANIFEST_REL,
    META_GOVERNANCE_REL,
    COURT_PROCEDURE_REL,
    DEPENDENCY_MATRIX_REL,
    EPOCH_MODEL_REL,
    QUALITY_POLICY_REL,
    READINESS_LATTICE_REL,
    FORGETTING_LAW_REL,
    ACCREDITATION_POLICY_REL,
    SELF_DESCRIPTION_REL,
    COST_MODEL_REL,
]
DELIVERABLE_REFS = [CONSTITUTION_DOC_REL] + JSON_ARTIFACT_REFS

RECEIPT_REL = "KT_PROD_CLEANROOM/reports/kt_constitutional_spine_ratification_receipt.json"
TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/constitutional_spine_ratify.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_constitutional_spine_ratify.py"
SUBJECT_ARTIFACT_REFS = DELIVERABLE_REFS + [TOOL_REL, TEST_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

FOUNDATION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/kt_foundation_pack_ratification_receipt.json"
BASELINE_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/kt_governance_baseline_ingestion_receipt.json"
BASELINE_BUNDLE_REL = "KT_PROD_CLEANROOM/reports/kt_governance_closeout_bundle.json"
BASELINE_CEILING_REL = "KT_PROD_CLEANROOM/reports/kt_claim_ceiling_summary.json"
BASELINE_EVIDENCE_MAP_REL = "KT_PROD_CLEANROOM/reports/kt_governance_evidence_subject_map.json"
BASELINE_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/kt_open_blocker_ladder.json"

ONTOLOGY_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_organ_ontology.json"
INVARIANTS_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_organ_invariants.json"
CLAIM_TAXONOMY_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_claim_taxonomy.json"
RUN_MODES_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_run_modes.json"
RELEASE_LAW_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_release_law.json"
INTERFACE_LAW_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_interface_law.json"
TRUST_ZONE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"

COURT_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/constitutional_court_contract.json"
AMENDMENT_LAW_REL = "KT_PROD_CLEANROOM/governance/amendment_law.json"
APPEAL_LAW_REL = "KT_PROD_CLEANROOM/governance/appeal_law.json"
REVIEW_TRIGGERS_REL = "KT_PROD_CLEANROOM/governance/constitutional_review_triggers.json"
AMENDMENT_SCOPE_REL = "KT_PROD_CLEANROOM/governance/amendment_scope_manifest.json"
PUBLIC_VERIFIER_RULES_REL = "KT_PROD_CLEANROOM/governance/public_verifier_rules.json"

WORK_ORDER_ID = "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION"
WORK_ORDER_SCHEMA_ID = "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2"

REQUIRED_SECTION_HEADINGS = [
    "## What KT Is",
    "## What KT Is Not",
    "## What KT May Do",
    "## What KT Must Not Do",
    "## Law, Evidence, Proof, and Violation",
    "## Organ and Zone Boundaries",
    "## Constitutional Change Procedure",
    "## Claim Ceiling and Proof Boundary",
    "## Open Blockers",
    "## Ratification Inputs",
]

QUALITY_AXES = [
    "governance_quality",
    "runtime_quality",
    "proof_quality",
    "operability_quality",
    "competition_quality",
    "publication_quality",
]

SOVEREIGN_DESIGN_LAWS = [
    "Before KT can be judged, KT must be reconstructed.",
    "Before KT can be normalized, KT must be remembered mechanically.",
    "Before KT can claim paradox superiority, paradox metabolism must be modeled, stressed, and bounded.",
    "No current-head claim may overread subject-evidence lag.",
    "No freeform inference is allowed. Only schema-bound, rule-derived judgments with explicit evidence chains are admissible.",
    "The cartographer may propose canon. It may not ratify canon.",
    "No mutation may begin until the relevant audit contracts pass.",
    "If an unparseable or opaque artifact contaminates a sovereign or critical runtime path, that path must be marked STATE_TAINTED until isolated or resolved.",
    "No learning delta is admissible unless it is lineaged to an experiment or crucible record with explicit receipts.",
    "Paradox hold states must have TTL or forced fail-closed or escalation semantics. Indefinite hold is forbidden.",
]

WHAT_KT_IS = [
    "KT is a governed organism composed of organs, interfaces, invariants, receipts, and claim ceilings.",
    "KT is a compiler-bearing repository whose public claims must remain subordinate to explicit machine evidence.",
    "KT is a sovereign runtime and governance surface with canonical, lab, archive, commercial, generated-runtime-truth, and quarantined zones.",
]

WHAT_KT_IS_NOT = [
    "KT is not a freeform narrative project that can ratify itself by prose alone.",
    "KT is not a single-head authority system when evidence-head and subject-head SHAs differ.",
    "KT is not allowed to treat archive, quarantine, documentary mirrors, or commercial surfaces as current truth.",
]

WHAT_KT_MAY_DO = [
    "Compile governed receipts, manifests, and doctrine from ratified machine state.",
    "Promote lab and experiment surfaces into canon only through explicit ratification paths.",
    "Carry documentary and commercial descriptions only within explicit claim ceilings.",
]

WHAT_KT_MUST_NOT_DO = [
    "Silently upgrade authority, runtime, governance, publication, or activation claims.",
    "Bypass constitutional amendment, appeal, or precedent procedure for governance changes.",
    "Leave paradox holds indefinite without TTL, escalation, or fail-closed semantics.",
]

PROTECTED_PREFIXES = (
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "kt_truth_ledger:",
    ".github/workflows/",
    "KT_PROD_CLEANROOM/docs/commercial/",
)


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "HEAD")
    except Exception:  # noqa: BLE001
        return ""


def _git_last_commit_for_paths(root: Path, paths: Sequence[str]) -> str:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return ""
    try:
        return _git(root, "log", "-1", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return ""


def _git_history_for_paths(root: Path, paths: Sequence[str]) -> List[str]:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "log", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    return [str(line).strip() for line in output.splitlines() if str(line).strip()]


def _git_parent(root: Path, commit: str) -> str:
    if not str(commit).strip():
        return ""
    try:
        return _git(root, "rev-parse", f"{commit}^")
    except Exception:  # noqa: BLE001
        return ""


def _git_changed_files(root: Path, commit: str) -> List[str]:
    if not str(commit).strip():
        return []
    try:
        output = _git(root, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit)
    except Exception:  # noqa: BLE001
        return []
    files: List[str] = []
    for line in output.splitlines():
        value = str(line).strip().replace("\\", "/")
        if value:
            files.append(value)
    return files


def _git_diff_files(root: Path, older: str, newer: str, paths: Sequence[str]) -> List[str]:
    if not str(older).strip() or not str(newer).strip():
        return []
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "diff", "--name-only", older, newer, "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    files: List[str] = []
    for line in output.splitlines():
        value = str(line).strip().replace("\\", "/")
        if value:
            files.append(value)
    return files


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _write_text_stable(path: Path, text: str) -> bool:
    rendered = text if text.endswith("\n") else f"{text}\n"
    if path.exists() and path.read_text(encoding="utf-8") == rendered:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8", newline="\n")
    return True


def _artifact_digests(root: Path, refs: Sequence[str]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for rel in refs:
        path = (root / Path(rel)).resolve()
        if path.exists():
            rows.append({"artifact_ref": rel, "sha256": file_sha256(path)})
    return rows


def _status_row(*, check: str, passed: bool, detail: str, refs: Sequence[str]) -> Dict[str, Any]:
    return {
        "check": check,
        "detail": detail,
        "refs": list(refs),
        "status": "PASS" if passed else "FAIL",
    }


def _is_protected(path: str) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _organ_quality_targets(organ_class: str) -> Dict[str, str]:
    default_targets = {
        "governance_quality": "QL2",
        "runtime_quality": "QL1",
        "proof_quality": "QL1",
        "operability_quality": "QL1",
        "competition_quality": "QL0",
        "publication_quality": "QL0",
    }
    targets_by_class = {
        "governance": {"governance_quality": "QL3", "runtime_quality": "QL1", "proof_quality": "QL2", "operability_quality": "QL2", "competition_quality": "QL1", "publication_quality": "QL2"},
        "constitutional": {"governance_quality": "QL3", "runtime_quality": "QL1", "proof_quality": "QL2", "operability_quality": "QL2", "competition_quality": "QL1", "publication_quality": "QL2"},
        "truth": {"governance_quality": "QL2", "runtime_quality": "QL2", "proof_quality": "QL3", "operability_quality": "QL2", "competition_quality": "QL2", "publication_quality": "QL3"},
        "runtime": {"governance_quality": "QL2", "runtime_quality": "QL3", "proof_quality": "QL2", "operability_quality": "QL2", "competition_quality": "QL3", "publication_quality": "QL2"},
        "operations": {"governance_quality": "QL2", "runtime_quality": "QL2", "proof_quality": "QL2", "operability_quality": "QL3", "competition_quality": "QL2", "publication_quality": "QL2"},
        "verification": {"governance_quality": "QL2", "runtime_quality": "QL2", "proof_quality": "QL3", "operability_quality": "QL2", "competition_quality": "QL2", "publication_quality": "QL2"},
        "laboratory": {"governance_quality": "QL1", "runtime_quality": "QL1", "proof_quality": "QL1", "operability_quality": "QL1", "competition_quality": "QL0", "publication_quality": "QL0"},
        "experiment": {"governance_quality": "QL2", "runtime_quality": "QL2", "proof_quality": "QL2", "operability_quality": "QL2", "competition_quality": "QL2", "publication_quality": "QL2"},
        "paradox": {"governance_quality": "QL2", "runtime_quality": "QL2", "proof_quality": "QL2", "operability_quality": "QL1", "competition_quality": "QL1", "publication_quality": "QL1"},
        "claims": {"governance_quality": "QL2", "runtime_quality": "QL1", "proof_quality": "QL2", "operability_quality": "QL3", "competition_quality": "QL2", "publication_quality": "QL3"},
        "commercial": {"governance_quality": "QL2", "runtime_quality": "QL1", "proof_quality": "QL1", "operability_quality": "QL3", "competition_quality": "QL1", "publication_quality": "QL2"},
        "archive": {"governance_quality": "QL1", "runtime_quality": "QL0", "proof_quality": "QL1", "operability_quality": "QL1", "competition_quality": "QL0", "publication_quality": "QL1"},
        "release": {"governance_quality": "QL2", "runtime_quality": "QL2", "proof_quality": "QL2", "operability_quality": "QL3", "competition_quality": "QL3", "publication_quality": "QL3"},
        "adjudication": {"governance_quality": "QL2", "runtime_quality": "QL1", "proof_quality": "QL3", "operability_quality": "QL2", "competition_quality": "QL2", "publication_quality": "QL2"},
    }
    return targets_by_class.get(organ_class, default_targets)


def _mode_cost_class(mode_id: str) -> Dict[str, Any]:
    cost_map = {
        "read_only_plus_bundle_emit": {"operator_review_hours": 2, "compute_units": 1, "risk_multiplier": 1.0},
        "proposal_then_ratification": {"operator_review_hours": 6, "compute_units": 2, "risk_multiplier": 1.4},
        "read_only_ingestion": {"operator_review_hours": 3, "compute_units": 2, "risk_multiplier": 1.1},
        "read_only_compiler_run": {"operator_review_hours": 4, "compute_units": 3, "risk_multiplier": 1.2},
        "read_only_rule_engine_run": {"operator_review_hours": 4, "compute_units": 2, "risk_multiplier": 1.2},
        "proposal_only": {"operator_review_hours": 5, "compute_units": 2, "risk_multiplier": 1.2},
        "read_only_registry_compilation": {"operator_review_hours": 4, "compute_units": 3, "risk_multiplier": 1.2},
        "mixed_modeling_and_testing": {"operator_review_hours": 8, "compute_units": 5, "risk_multiplier": 1.8},
        "generated_docs_plus_ratification": {"operator_review_hours": 6, "compute_units": 3, "risk_multiplier": 1.5},
        "adversarial_tribunal": {"operator_review_hours": 12, "compute_units": 6, "risk_multiplier": 2.0},
    }
    return cost_map[mode_id]


def _context(root: Path) -> Dict[str, Any]:
    foundation_receipt = _load_required_json(root, FOUNDATION_RECEIPT_REL)
    baseline_receipt = _load_required_json(root, BASELINE_RECEIPT_REL)
    if str(foundation_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 3 is blocked until Step 2 foundation pack ratification is PASS.")
    if str(baseline_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 3 is blocked until Step 1 governance baseline ingestion is PASS.")

    ontology = _load_required_json(root, ONTOLOGY_REL)
    invariants = _load_required_json(root, INVARIANTS_REL)
    claim_taxonomy = _load_required_json(root, CLAIM_TAXONOMY_REL)
    run_modes = _load_required_json(root, RUN_MODES_REL)
    release_law = _load_required_json(root, RELEASE_LAW_REL)
    interface_law = _load_required_json(root, INTERFACE_LAW_REL)
    trust_zones = _load_required_json(root, TRUST_ZONE_REGISTRY_REL)
    constitutional_court_contract = _load_required_json(root, COURT_CONTRACT_REL)
    amendment_law = _load_required_json(root, AMENDMENT_LAW_REL)
    appeal_law = _load_required_json(root, APPEAL_LAW_REL)
    review_triggers = _load_required_json(root, REVIEW_TRIGGERS_REL)
    amendment_scope = _load_required_json(root, AMENDMENT_SCOPE_REL)
    public_verifier_rules = _load_required_json(root, PUBLIC_VERIFIER_RULES_REL)
    governance_bundle = _load_required_json(root, BASELINE_BUNDLE_REL)
    claim_ceiling = _load_required_json(root, BASELINE_CEILING_REL)
    evidence_subject_map = _load_required_json(root, BASELINE_EVIDENCE_MAP_REL)
    open_blockers = _load_required_json(root, BASELINE_BLOCKERS_REL)

    organs = [row for row in ontology.get("organs", []) if isinstance(row, dict)]
    organ_map = {str(row.get("organ_id", "")).strip(): row for row in organs}
    invariants_by_organ: Dict[str, List[Dict[str, Any]]] = {}
    for row in invariants.get("invariants", []):
        if isinstance(row, dict):
            invariants_by_organ.setdefault(str(row.get("organ_id", "")).strip(), []).append(row)

    downstream_map: Dict[str, List[str]] = {organ_id: [] for organ_id in organ_map}
    for organ_id, row in organ_map.items():
        for upstream in row.get("upstream_organs", []):
            upstream_id = str(upstream).strip()
            if upstream_id in downstream_map:
                downstream_map[upstream_id].append(organ_id)
    for organ_id in list(downstream_map.keys()):
        downstream_map[organ_id] = sorted(set(downstream_map[organ_id]))

    planes = sorted({str(plane).strip() for row in organs for plane in row.get("primary_planes", []) if isinstance(plane, str) and str(plane).strip()})
    evidence_entries = [row for row in evidence_subject_map.get("entries", []) if isinstance(row, dict)]

    return {
        "foundation_receipt": foundation_receipt,
        "foundation_evidence_commit": _git_last_commit_for_paths(root, [FOUNDATION_RECEIPT_REL]),
        "baseline_receipt": baseline_receipt,
        "baseline_evidence_commit": _git_last_commit_for_paths(root, [BASELINE_RECEIPT_REL]),
        "baseline_bundle": governance_bundle,
        "claim_ceiling": claim_ceiling,
        "open_blockers": open_blockers,
        "evidence_subject_map": evidence_subject_map,
        "evidence_by_domain": {str(row.get("domain_id", "")).strip(): row for row in evidence_entries},
        "ontology": ontology,
        "organs": organs,
        "organ_map": organ_map,
        "invariants_by_organ": invariants_by_organ,
        "downstream_map": downstream_map,
        "planes": planes,
        "claim_taxonomy": claim_taxonomy,
        "run_modes": run_modes,
        "release_law": release_law,
        "interface_law": interface_law,
        "trust_zones": trust_zones,
        "constitutional_court_contract": constitutional_court_contract,
        "amendment_law": amendment_law,
        "appeal_law": appeal_law,
        "review_triggers": review_triggers,
        "amendment_scope": amendment_scope,
        "public_verifier_rules": public_verifier_rules,
    }


def build_constitution_markdown(*, ctx: Dict[str, Any]) -> str:
    blocker_rows = [row for row in ctx["open_blockers"].get("blocker_ladder", []) if isinstance(row, dict)]
    blockers = "\n".join(
        f"- `{row.get('blocker_id', '')}`: blocks {', '.join(str(item) for item in row.get('blocked_proof_classes', [])) or 'named downstream proof classes'}"
        for row in blocker_rows
    )
    organs = "\n".join(
        f"- `{row.get('organ_id', '')}`: {row.get('description', '')}"
        for row in sorted(ctx["organs"], key=lambda item: str(item.get("organ_id", "")))
    )
    ratification_inputs = "\n".join(
        [
            f"- Baseline closeout subject: `{ctx['baseline_bundle'].get('baseline_subject_commit', '')}`",
            f"- Baseline closeout evidence: `{ctx['baseline_bundle'].get('baseline_evidence_commit', '')}`",
            f"- Foundation pack subject: `{ctx['foundation_receipt'].get('compiled_head_commit', '')}`",
            f"- Foundation pack evidence: `{ctx['foundation_evidence_commit']}`",
            f"- Governance baseline ingestion receipt: `{BASELINE_RECEIPT_REL}`",
            f"- Public verifier rules: `{PUBLIC_VERIFIER_RULES_REL}`",
        ]
    )
    design_laws = "\n".join(f"{index + 1}. {law}" for index, law in enumerate(SOVEREIGN_DESIGN_LAWS))
    what_is = "\n".join(f"- {item}" for item in WHAT_KT_IS)
    what_is_not = "\n".join(f"- {item}" for item in WHAT_KT_IS_NOT)
    may_do = "\n".join(f"- {item}" for item in WHAT_KT_MAY_DO)
    must_not_do = "\n".join(f"- {item}" for item in WHAT_KT_MUST_NOT_DO)

    return (
        "# KT Constitution v1\n\n"
        "This constitution defines KT as a governed organism whose admissible claims are bounded by machine evidence, not narrative preference.\n\n"
        "## What KT Is\n"
        f"{what_is}\n\n"
        "## What KT Is Not\n"
        f"{what_is_not}\n\n"
        "## What KT May Do\n"
        f"{may_do}\n\n"
        "## What KT Must Not Do\n"
        f"{must_not_do}\n\n"
        "## Law, Evidence, Proof, and Violation\n"
        "- Law is a ratified machine-readable contract, policy, manifest, or constitution surface under canonical governance.\n"
        "- Evidence is a cited receipt, manifest, digest, or reproducible artifact chain bound to explicit refs.\n"
        "- Proof is the highest admissibility class supported by active law plus explicit evidence chains.\n"
        "- A violation is any mutation or claim that outruns law, bypasses governed procedure, or overreads subject-evidence lag.\n\n"
        "## Organ and Zone Boundaries\n"
        "KT is composed of the following first-class organs:\n"
        f"{organs}\n\n"
        "Trust zones remain canonical, lab, archive, commercial, generated-runtime-truth, and quarantined; cross-zone promotion requires ratified transitions.\n\n"
        "## Constitutional Change Procedure\n"
        "- Governance change requires constitutional review triggers, amendment scope control, and explicit receipts.\n"
        "- Appeals, dissents, and precedent entries must remain explicit even when empty.\n"
        "- No doctrine or generated narrative may silently amend law.\n"
        "- Auditors remain auditable through constitutional court procedure and cited evidence chains.\n\n"
        "## Claim Ceiling and Proof Boundary\n"
        f"- Highest attained proof class remains `{ctx['claim_ceiling']['highest_attained_proof_class']['proof_class_id']}`.\n"
        "- Current-head truth, governance, and runtime surfaces must preserve evidence-versus-subject distinctions unless SHAs match.\n"
        "- Workflow governance remains admissible only as workflow governance while platform enforcement is unproven.\n"
        "- H1 remains blocked until the named blocker ladder is resolved by future ratified work.\n\n"
        "## Open Blockers\n"
        f"{blockers}\n\n"
        "## Ratification Inputs\n"
        f"{ratification_inputs}\n\n"
        "## Sovereign Design Laws\n"
        f"{design_laws}\n"
    )


def build_meta_governance_policy(*, ctx: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.constitution.meta_governance_policy.v1",
        "policy_id": "KT_META_GOVERNANCE_POLICY_V1_20260314",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "baseline_is_frozen_input": True,
        "baseline_subject_commit": ctx["baseline_bundle"].get("baseline_subject_commit"),
        "baseline_evidence_commit": ctx["baseline_bundle"].get("baseline_evidence_commit"),
        "governance_of_governance": {
            "governing_organ_id": "constitutional_meta_governance",
            "authority_refs": [COURT_CONTRACT_REL, AMENDMENT_LAW_REL, APPEAL_LAW_REL, REVIEW_TRIGGERS_REL, AMENDMENT_SCOPE_REL, MANIFEST_REL, CONSTITUTION_DOC_REL],
            "allowed_change_paths": ["constitutional_review", "amendment_receipt", "appeal_receipt", "precedent_registration"],
            "forbidden_shortcuts": [
                "generated_doctrine_as_law_without_ratification",
                "silent_claim_upgrade",
                "freeform_reopening_of_sealed_baseline",
            ],
        },
        "auditor_of_auditors": {
            "role_id": "constitutional_court",
            "authority_refs": [COURT_CONTRACT_REL, COURT_PROCEDURE_REL, BASELINE_BUNDLE_REL, BASELINE_CEILING_REL],
            "required_evidence_chain_classes": ["governance_contract", "receipt", "manifest"],
            "independence_rule": "Auditors may not ratify their own governance changes without a constitutional court path and explicit evidence chain.",
        },
        "reopen_rules": [
            "A sealed baseline may be cited as immutable input but may not be reopened without a named amendment or appeal artifact.",
            "Any contradiction touching authority, runtime integrity, publication claims, security, or external profiles fails closed until reviewed.",
            "Generated doctrine may propose canon but may not ratify canon.",
        ],
        "successor_law_rule": "Future constitutional versions must cite superseded surfaces, rationale, rollback path, and precedent disposition.",
    }


def build_constitutional_court_procedure(*, ctx: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.constitution.court_procedure.v1",
        "procedure_id": "KT_CONSTITUTIONAL_COURT_PROCEDURE_V1_20260314",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "court_contract_ref": COURT_CONTRACT_REL,
        "review_trigger_ref": REVIEW_TRIGGERS_REL,
        "amendment_scope_ref": AMENDMENT_SCOPE_REL,
        "filing_types": [
            {
                "filing_type": "amendment",
                "required_fields": ["subject_surfaces", "rationale", "rollback_refs", "required_signers"],
                "governing_law_ref": AMENDMENT_LAW_REL,
                "allowed_dispositions": ["RATIFIED", "REJECTED", "FAIL_CLOSED"],
            },
            {
                "filing_type": "appeal",
                "required_fields": ["disputed_act", "desired_disposition", "evidence_refs"],
                "governing_law_ref": APPEAL_LAW_REL,
                "allowed_dispositions": ["UPHELD", "REMANDED", "REJECTED", "FAIL_CLOSED"],
            },
            {
                "filing_type": "dissent",
                "required_fields": ["reviewed_act", "reason", "evidence_refs"],
                "governing_law_ref": COURT_CONTRACT_REL,
                "allowed_dispositions": ["RECORDED"],
            },
            {
                "filing_type": "precedent_entry",
                "required_fields": ["reviewed_act", "disposition", "authority_refs"],
                "governing_law_ref": COURT_CONTRACT_REL,
                "allowed_dispositions": ["REGISTERED", "FAIL_CLOSED"],
            },
        ],
        "precedent_registry_policy": {
            "appeal_and_dissent_channels_must_be_explicit": True,
            "empty_channels_still_require_presence": True,
            "required_fields": ["reviewed_act", "disposition", "authority_refs"],
        },
        "emergency_fail_closed_rule": "If authority, runtime integrity, or publication semantics are ambiguous, the court freezes the act and requires explicit contradiction evidence.",
    }


def build_organ_dependency_matrix(*, ctx: Dict[str, Any]) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    for organ in sorted(ctx["organs"], key=lambda row: str(row.get("organ_id", ""))):
        organ_id = str(organ.get("organ_id", "")).strip()
        upstream = sorted(str(item).strip() for item in organ.get("upstream_organs", []) if str(item).strip())
        downstream = ctx["downstream_map"].get(organ_id, [])
        entries.append(
            {
                "organ_id": organ_id,
                "label": str(organ.get("label", "")).strip(),
                "organ_class": str(organ.get("organ_class", "")).strip(),
                "primary_planes": list(organ.get("primary_planes", [])),
                "trust_zones": list(organ.get("trust_zones", [])),
                "current_ceiling": str(organ.get("current_ceiling", "")).strip(),
                "upstream_organs": upstream,
                "downstream_organs": downstream,
                "law_refs": list(organ.get("law_refs", [])),
                "primary_surfaces": list(organ.get("primary_surfaces", [])),
                "state_signals": list(organ.get("state_signals", [])),
                "invariant_ids": sorted(str(row.get("invariant_id", "")).strip() for row in ctx["invariants_by_organ"].get(organ_id, [])),
            }
        )
        for upstream_id in upstream:
            edges.append(
                {
                    "from_organ_id": upstream_id,
                    "to_organ_id": organ_id,
                    "dependency_kind": "declared_upstream",
                    "justification": f"`{organ_id}` declares `{upstream_id}` as an upstream organ in the Step 2 ontology.",
                }
            )
    return {
        "schema_id": "kt.constitution.organ_dependency_matrix.v1",
        "matrix_id": "KT_ORGAN_DEPENDENCY_MATRIX_V1_20260314",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "organ_count": len(entries),
        "edge_count": len(edges),
        "entries": entries,
        "edges": edges,
    }


def build_epoch_model(*, ctx: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.constitution.epoch_model.v1",
        "model_id": "KT_EPOCH_MODEL_V1_20260314",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "current_epoch_id": "epoch_2_foundation_and_baseline_frozen",
        "pending_epoch_id": "epoch_3_constitutional_spine_ratification",
        "epochs": [
            {
                "epoch_id": "epoch_0_historical_pre_baseline",
                "status": "historical",
                "entry_condition": "Pre-refactor KT history exists but is not yet compiler-ingested under the new constitutional packet.",
            },
            {
                "epoch_id": "epoch_1_governance_closeout_frozen",
                "status": "ratified",
                "subject_commit": ctx["baseline_bundle"].get("baseline_subject_commit"),
                "evidence_commit": ctx["baseline_bundle"].get("baseline_evidence_commit"),
                "entry_receipt_ref": BASELINE_BUNDLE_REL,
            },
            {
                "epoch_id": "epoch_2_foundation_and_baseline_frozen",
                "status": "ratified",
                "subject_commit": ctx["foundation_receipt"].get("compiled_head_commit"),
                "evidence_commit": ctx["foundation_evidence_commit"],
                "entry_receipt_ref": FOUNDATION_RECEIPT_REL,
            },
            {
                "epoch_id": "epoch_3_constitutional_spine_ratification",
                "status": "pending_step_3_receipt",
                "subject_commit": "SET_BY_GIT_AFTER_STEP_3_SUBJECT_COMMIT",
                "evidence_commit": "SET_BY_GIT_AFTER_STEP_3_RECEIPT_COMMIT",
                "entry_receipt_ref": RECEIPT_REL,
            },
        ],
        "transition_rules": [
            "An epoch transition is admissible only when its governing receipt exists and passes.",
            "Later evidence heads may describe an earlier subject epoch but do not become that subject epoch unless SHAs match.",
            "Historical ingestion may widen memory, but it may not silently rewrite earlier epoch boundaries.",
        ],
    }


def build_quality_policy(*, ctx: Dict[str, Any]) -> Dict[str, Any]:
    release_profiles = [row for row in ctx["release_law"].get("release_profiles", []) if isinstance(row, dict)]
    organ_targets = [
        {
            "organ_id": str(organ.get("organ_id", "")).strip(),
            "organ_class": str(organ.get("organ_class", "")).strip(),
            "minimum_targets": _organ_quality_targets(str(organ.get("organ_class", "")).strip()),
            "current_claim_ceiling": str(organ.get("current_ceiling", "")).strip(),
        }
        for organ in sorted(ctx["organs"], key=lambda row: str(row.get("organ_id", "")))
    ]
    return {
        "schema_id": "kt.constitution.quality_policy.v1",
        "policy_id": "KT_QUALITY_POLICY_V1_20260314",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "quality_axes": list(QUALITY_AXES),
        "quality_levels": dict(ctx["release_law"].get("quality_levels", {})),
        "quality_gate_rule": str(ctx["release_law"].get("quality_gate_rule", "")).strip(),
        "required_quality_by_profile": [
            {
                "profile_id": str(row.get("profile_id", "")).strip(),
                "minimum_quality_level": str(row.get("minimum_quality_level", "")).strip(),
                "current_admissibility_ceiling": str(row.get("current_admissibility_ceiling", "")).strip(),
                "blocking_conditions": list(row.get("blocking_conditions", [])),
            }
            for row in release_profiles
        ],
        "organ_minimum_quality_targets": organ_targets,
    }


def build_readiness_lattice(*, ctx: Dict[str, Any]) -> Dict[str, Any]:
    release_profiles = [row for row in ctx["release_law"].get("release_profiles", []) if isinstance(row, dict)]
    nodes = []
    for row in release_profiles:
        nodes.append(
            {
                "profile_id": str(row.get("profile_id", "")).strip(),
                "minimum_quality_level": str(row.get("minimum_quality_level", "")).strip(),
                "required_claim_classes": list(row.get("required_claim_classes", [])),
                "blocking_conditions": list(row.get("blocking_conditions", [])),
                "current_admissibility_ceiling": str(row.get("current_admissibility_ceiling", "")).strip(),
            }
        )
    return {
        "schema_id": "kt.constitution.readiness_lattice.v1",
        "lattice_id": "KT_READINESS_LATTICE_V1_20260314",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "nodes": nodes,
        "current_system_caps": {
            "governance_ceiling": ctx["claim_ceiling"]["current_ceiling_by_domain"]["governance"]["ceiling_id"],
            "runtime_boundary_ceiling": ctx["claim_ceiling"]["current_ceiling_by_domain"]["runtime_boundary"]["ceiling_id"],
            "reproducibility_ceiling": ctx["claim_ceiling"]["current_ceiling_by_domain"]["reproducibility"]["ceiling_id"],
            "activation_ceiling": ctx["claim_ceiling"]["current_ceiling_by_domain"]["activation"]["ceiling_id"],
        },
        "current_open_blockers": [str(row.get("blocker_id", "")).strip() for row in ctx["open_blockers"].get("blocker_ladder", []) if isinstance(row, dict)],
    }


def build_forgetting_law(*, ctx: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.constitution.forgetting_law.v1",
        "law_id": "KT_FORGETTING_LAW_V1_20260314",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "retention_classes": [
            {
                "class_id": "canonical_law",
                "surface_globs": ["KT_PROD_CLEANROOM/governance/**"],
                "forgetting_policy": "never_delete_without_ratified_supersession",
            },
            {
                "class_id": "generated_runtime_truth",
                "surface_globs": ["KT_PROD_CLEANROOM/reports/**", "KT_PROD_CLEANROOM/exports/_truth/**"],
                "forgetting_policy": "retain_latest_subject_evidence_and_supersession_lineage",
            },
            {
                "class_id": "archive_lineage",
                "surface_globs": ["KT_ARCHIVE/vault/**", "KT_ARCHIVE/docs/audit/**"],
                "forgetting_policy": "preserve_lineage_but_do_not_promote_to_current_truth",
            },
        ],
        "reopen_triggers": [
            "historical_conflict_reintroduced",
            "state_taint_detected_on_sovereign_path",
            "claim_ceiling_contradicted_by_new_receipt",
        ],
        "forbidden_forgetting": [
            "deleting ratified law without supersession",
            "discarding blocker lineage while blockers remain open",
            "flattening evidence-subject distinctions into HEAD-only narratives",
        ],
    }


def build_accreditation_policy(*, ctx: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.constitution.accreditation_policy.v1",
        "policy_id": "KT_ACCREDITATION_POLICY_V1_20260314",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "roles": [
            {
                "role_id": "operator",
                "required_refs": [FOUNDATION_RECEIPT_REL, BASELINE_RECEIPT_REL],
                "minimum_profile": "internal_only",
                "may_emit": ["reports", "manifests", "receipts"],
            },
            {
                "role_id": "maintainer",
                "required_refs": [COURT_PROCEDURE_REL, META_GOVERNANCE_REL],
                "minimum_profile": "external_demo_or_specialist_use",
                "may_emit": ["ratified_governance_changes", "canonical_runtime_changes"],
            },
            {
                "role_id": "auditor",
                "required_refs": [MANIFEST_REL, COURT_PROCEDURE_REL, BASELINE_CEILING_REL],
                "minimum_profile": "competition_and_publication_grade",
                "may_emit": ["audits", "contradiction_reports", "ceiling_reviews"],
            },
            {
                "role_id": "publication_author",
                "required_refs": [PUBLIC_VERIFIER_RULES_REL, BASELINE_CEILING_REL],
                "minimum_profile": "competition_and_publication_grade",
                "may_emit": ["documentary_only_public_profiles"],
            },
        ],
        "forbidden_accreditations": [
            "No role may ratify canon from lab or archive surfaces without governed promotion.",
            "No publication-facing role may exceed documentary or evidence-backed claim ceilings.",
        ],
    }


def build_self_description(*, ctx: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.constitution.self_description.v1",
        "document_id": "KT_SELF_DESCRIPTION_V1_20260314",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "program_role": "freeze_governance_baseline_then_reconstruct_define_catalog_tag_normalize_professionalize_and_adjudicate_kt_as_a_whole",
        "what_kt_is": list(WHAT_KT_IS),
        "what_kt_is_not": list(WHAT_KT_IS_NOT),
        "organ_count": len(ctx["organs"]),
        "plane_count": len(ctx["planes"]),
        "planes": list(ctx["planes"]),
        "organ_ids": [str(row.get("organ_id", "")).strip() for row in sorted(ctx["organs"], key=lambda row: str(row.get("organ_id", "")))],
        "baseline_status": str(ctx["baseline_bundle"].get("closeout_verdict", "")).strip(),
        "governance_ceiling": ctx["claim_ceiling"]["current_ceiling_by_domain"]["governance"]["ceiling_id"],
        "published_head_self_convergence_status": "UNRESOLVED",
        "h1_status": "BLOCKED",
        "active_claim_boundary": "Current heads may contain evidence for subject commits but may not be phrased as those subjects unless SHAs match.",
    }


def build_cost_model(*, ctx: Dict[str, Any]) -> Dict[str, Any]:
    modes = [row for row in ctx["run_modes"].get("modes", []) if isinstance(row, dict)]
    return {
        "schema_id": "kt.constitution.cost_model.v1",
        "model_id": "KT_COST_MODEL_V1_20260314",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "cost_axes": [
            "compute_units",
            "operator_review_hours",
            "risk_multiplier",
            "reproduction_cost_band",
            "publication_cost_band",
            "governance_change_cost_band",
        ],
        "mode_cost_classes": [
            {
                "mode_id": str(row.get("mode_id", "")).strip(),
                **_mode_cost_class(str(row.get("mode_id", "")).strip()),
            }
            for row in modes
        ],
        "zone_risk_multipliers": [
            {"zone_id": "CANONICAL", "risk_multiplier": 1.5},
            {"zone_id": "LAB", "risk_multiplier": 1.2},
            {"zone_id": "ARCHIVE", "risk_multiplier": 1.0},
            {"zone_id": "COMMERCIAL", "risk_multiplier": 1.3},
            {"zone_id": "GENERATED_RUNTIME_TRUTH", "risk_multiplier": 1.4},
            {"zone_id": "QUARANTINED", "risk_multiplier": 1.8},
        ],
        "high_cost_triggers": [str(row.get("blocker_id", "")).strip() for row in ctx["open_blockers"].get("blocker_ladder", []) if isinstance(row, dict)],
    }


def build_constitution_manifest(*, ctx: Dict[str, Any], root: Path) -> Dict[str, Any]:
    digest_refs = [
        CONSTITUTION_DOC_REL,
        META_GOVERNANCE_REL,
        COURT_PROCEDURE_REL,
        DEPENDENCY_MATRIX_REL,
        EPOCH_MODEL_REL,
        QUALITY_POLICY_REL,
        READINESS_LATTICE_REL,
        FORGETTING_LAW_REL,
        ACCREDITATION_POLICY_REL,
        SELF_DESCRIPTION_REL,
        COST_MODEL_REL,
    ]
    return {
        "schema_id": "kt.constitution.manifest.v1",
        "manifest_id": "KT_CONSTITUTION_MANIFEST_V1_20260314",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "constitution_doc_ref": CONSTITUTION_DOC_REL,
        "required_section_headings": list(REQUIRED_SECTION_HEADINGS),
        "artifact_refs": list(DELIVERABLE_REFS),
        "artifact_digests": _artifact_digests(root, digest_refs),
        "supporting_law_refs": [
            COURT_CONTRACT_REL,
            AMENDMENT_LAW_REL,
            APPEAL_LAW_REL,
            REVIEW_TRIGGERS_REL,
            AMENDMENT_SCOPE_REL,
            PUBLIC_VERIFIER_RULES_REL,
            INTERFACE_LAW_REL,
        ],
        "baseline_input_refs": [
            FOUNDATION_RECEIPT_REL,
            BASELINE_RECEIPT_REL,
            BASELINE_BUNDLE_REL,
            BASELINE_CEILING_REL,
            BASELINE_EVIDENCE_MAP_REL,
        ],
        "ratification_receipt_ref": RECEIPT_REL,
    }


def emit_subject_artifacts(*, root: Path) -> List[Dict[str, Any]]:
    ctx = _context(root)
    writes: List[Dict[str, Any]] = []

    changed = _write_text_stable((root / Path(CONSTITUTION_DOC_REL)).resolve(), build_constitution_markdown(ctx=ctx))
    writes.append({"artifact_ref": CONSTITUTION_DOC_REL, "updated": changed, "schema_id": "markdown"})

    payloads = {
        META_GOVERNANCE_REL: build_meta_governance_policy(ctx=ctx),
        COURT_PROCEDURE_REL: build_constitutional_court_procedure(ctx=ctx),
        DEPENDENCY_MATRIX_REL: build_organ_dependency_matrix(ctx=ctx),
        EPOCH_MODEL_REL: build_epoch_model(ctx=ctx),
        QUALITY_POLICY_REL: build_quality_policy(ctx=ctx),
        READINESS_LATTICE_REL: build_readiness_lattice(ctx=ctx),
        FORGETTING_LAW_REL: build_forgetting_law(ctx=ctx),
        ACCREDITATION_POLICY_REL: build_accreditation_policy(ctx=ctx),
        SELF_DESCRIPTION_REL: build_self_description(ctx=ctx),
        COST_MODEL_REL: build_cost_model(ctx=ctx),
    }
    for rel, payload in payloads.items():
        changed = write_json_stable((root / Path(rel)).resolve(), payload)
        writes.append({"artifact_ref": rel, "updated": changed, "schema_id": str(payload.get("schema_id", "")).strip()})

    manifest = build_constitution_manifest(ctx=ctx, root=root)
    changed = write_json_stable((root / Path(MANIFEST_REL)).resolve(), manifest)
    writes.append({"artifact_ref": MANIFEST_REL, "updated": changed, "schema_id": str(manifest.get("schema_id", "")).strip()})
    return writes


def build_constitutional_spine_ratification_report(*, root: Path) -> Dict[str, Any]:
    ctx = _context(root)
    manifest = _load_required_json(root, MANIFEST_REL)
    meta_governance = _load_required_json(root, META_GOVERNANCE_REL)
    court_procedure = _load_required_json(root, COURT_PROCEDURE_REL)
    dependency_matrix = _load_required_json(root, DEPENDENCY_MATRIX_REL)
    epoch_model = _load_required_json(root, EPOCH_MODEL_REL)
    quality_policy = _load_required_json(root, QUALITY_POLICY_REL)
    readiness_lattice = _load_required_json(root, READINESS_LATTICE_REL)
    forgetting_law = _load_required_json(root, FORGETTING_LAW_REL)
    accreditation_policy = _load_required_json(root, ACCREDITATION_POLICY_REL)
    self_description = _load_required_json(root, SELF_DESCRIPTION_REL)
    cost_model = _load_required_json(root, COST_MODEL_REL)
    constitution_text = (root / Path(CONSTITUTION_DOC_REL)).read_text(encoding="utf-8")

    checks: List[Dict[str, Any]] = []
    failures: List[str] = []

    foundation_passed = str(ctx["foundation_receipt"].get("status", "")).strip() == "PASS"
    checks.append(_status_row(check="foundation_pack_gate_passed", passed=foundation_passed, detail="Step 2 foundation pack ratification must remain PASS before Step 3 is admissible.", refs=[FOUNDATION_RECEIPT_REL]))
    if not foundation_passed:
        failures.append("foundation_pack_gate_passed")

    baseline_passed = str(ctx["baseline_receipt"].get("status", "")).strip() == "PASS"
    checks.append(_status_row(check="governance_baseline_gate_passed", passed=baseline_passed, detail="Step 1 governance baseline ingestion must remain PASS before Step 3 is admissible.", refs=[BASELINE_RECEIPT_REL]))
    if not baseline_passed:
        failures.append("governance_baseline_gate_passed")

    sections_present = all(section in constitution_text for section in REQUIRED_SECTION_HEADINGS)
    checks.append(_status_row(check="constitution_defines_identity_and_boundaries", passed=sections_present, detail="The constitution document must define KT identity, prohibitions, law/evidence/proof semantics, and ratification inputs.", refs=[CONSTITUTION_DOC_REL]))
    if not sections_present:
        failures.append("constitution_defines_identity_and_boundaries")

    meta_governance_explicit = str(((meta_governance.get("governance_of_governance") or {}).get("governing_organ_id", ""))).strip() == "constitutional_meta_governance" and bool(((meta_governance.get("auditor_of_auditors") or {}).get("role_id"))) and bool(meta_governance.get("reopen_rules"))
    checks.append(_status_row(check="meta_governance_explicit", passed=meta_governance_explicit, detail="Meta-governance must define who governs governance, who audits auditors, and how reopening works.", refs=[META_GOVERNANCE_REL]))
    if not meta_governance_explicit:
        failures.append("meta_governance_explicit")

    filing_types = {str(row.get("filing_type", "")).strip() for row in court_procedure.get("filing_types", []) if isinstance(row, dict)}
    court_procedure_explicit = {"amendment", "appeal", "dissent", "precedent_entry"}.issubset(filing_types)
    checks.append(_status_row(check="constitutional_court_procedure_explicit", passed=court_procedure_explicit, detail="Court procedure must define amendment, appeal, dissent, and precedent paths.", refs=[COURT_PROCEDURE_REL, COURT_CONTRACT_REL, AMENDMENT_LAW_REL, APPEAL_LAW_REL]))
    if not court_procedure_explicit:
        failures.append("constitutional_court_procedure_explicit")

    epoch_model_explicit = str(epoch_model.get("current_epoch_id", "")).strip() == "epoch_2_foundation_and_baseline_frozen" and str(epoch_model.get("pending_epoch_id", "")).strip() == "epoch_3_constitutional_spine_ratification" and len(epoch_model.get("epochs", [])) >= 4
    checks.append(_status_row(check="epoch_model_exists", passed=epoch_model_explicit, detail="Epoch model must define current and pending constitutional epochs.", refs=[EPOCH_MODEL_REL]))
    if not epoch_model_explicit:
        failures.append("epoch_model_exists")

    forgetting_law_explicit = bool(forgetting_law.get("retention_classes")) and bool(forgetting_law.get("reopen_triggers"))
    checks.append(_status_row(check="forgetting_law_exists", passed=forgetting_law_explicit, detail="Forgetting law must define retention classes and reopening triggers.", refs=[FORGETTING_LAW_REL]))
    if not forgetting_law_explicit:
        failures.append("forgetting_law_exists")

    dependency_entries = [row for row in dependency_matrix.get("entries", []) if isinstance(row, dict)]
    dependency_organs = {str(row.get("organ_id", "")).strip() for row in dependency_entries}
    ontology_organs = {str(row.get("organ_id", "")).strip() for row in ctx["organs"]}
    dependency_matrix_complete = dependency_organs == ontology_organs and int(dependency_matrix.get("edge_count", 0)) >= 1
    checks.append(_status_row(check="dependency_matrix_exists", passed=dependency_matrix_complete, detail="Dependency matrix must cover every first-class organ and at least one dependency edge.", refs=[DEPENDENCY_MATRIX_REL, ONTOLOGY_REL]))
    if not dependency_matrix_complete:
        failures.append("dependency_matrix_exists")

    self_description_explicit = bool(self_description.get("what_kt_is")) and bool(self_description.get("what_kt_is_not")) and int(self_description.get("organ_count", 0)) == len(ctx["organs"])
    checks.append(_status_row(check="self_description_exists", passed=self_description_explicit, detail="Self-description must state what KT is, is not, and how many organs it declares.", refs=[SELF_DESCRIPTION_REL]))
    if not self_description_explicit:
        failures.append("self_description_exists")

    quality_and_lattice_explicit = list(quality_policy.get("quality_axes", [])) == QUALITY_AXES and bool(quality_policy.get("required_quality_by_profile")) and bool(readiness_lattice.get("nodes"))
    checks.append(_status_row(check="quality_policy_and_readiness_lattice_exist", passed=quality_and_lattice_explicit, detail="Quality policy and readiness lattice must be explicit and profile-aware.", refs=[QUALITY_POLICY_REL, READINESS_LATTICE_REL]))
    if not quality_and_lattice_explicit:
        failures.append("quality_policy_and_readiness_lattice_exist")

    cost_model_explicit = len(cost_model.get("mode_cost_classes", [])) == len(ctx["run_modes"].get("modes", []))
    checks.append(_status_row(check="cost_model_exists", passed=cost_model_explicit, detail="Cost model must cover every Step 2 run mode.", refs=[COST_MODEL_REL, RUN_MODES_REL]))
    if not cost_model_explicit:
        failures.append("cost_model_exists")

    accreditation_explicit = bool(accreditation_policy.get("roles")) and len(accreditation_policy.get("roles", [])) >= 4
    checks.append(_status_row(check="accreditation_policy_exists", passed=accreditation_explicit, detail="Accreditation policy must define governed roles and forbidden accreditations.", refs=[ACCREDITATION_POLICY_REL]))
    if not accreditation_explicit:
        failures.append("accreditation_policy_exists")

    manifest_refs_complete = set(manifest.get("artifact_refs", [])) == set(DELIVERABLE_REFS)
    manifest_digests_match = manifest.get("artifact_digests") == _artifact_digests(root, [CONSTITUTION_DOC_REL, META_GOVERNANCE_REL, COURT_PROCEDURE_REL, DEPENDENCY_MATRIX_REL, EPOCH_MODEL_REL, QUALITY_POLICY_REL, READINESS_LATTICE_REL, FORGETTING_LAW_REL, ACCREDITATION_POLICY_REL, SELF_DESCRIPTION_REL, COST_MODEL_REL])
    checks.append(_status_row(check="constitution_manifest_complete", passed=manifest_refs_complete and manifest_digests_match, detail="Manifest must reference the full Step 3 deliverable set and carry matching digests for ratified inputs.", refs=[MANIFEST_REL]))
    if not (manifest_refs_complete and manifest_digests_match):
        failures.append("constitution_manifest_complete")

    ceiling_boundary_preserved = str(self_description.get("governance_ceiling", "")).strip() == "WORKFLOW_GOVERNANCE_ONLY" and str(self_description.get("published_head_self_convergence_status", "")).strip() == "UNRESOLVED" and str(self_description.get("h1_status", "")).strip() == "BLOCKED" and "No current-head claim may overread subject-evidence lag." in constitution_text
    checks.append(_status_row(check="claim_boundary_preserved", passed=ceiling_boundary_preserved, detail="Step 3 must not silently upgrade governance, truth, or H1 ceilings while defining the constitutional spine.", refs=[CONSTITUTION_DOC_REL, SELF_DESCRIPTION_REL, BASELINE_CEILING_REL]))
    if not ceiling_boundary_preserved:
        failures.append("claim_boundary_preserved")

    subject_commit = _git_last_commit_for_paths(root, SUBJECT_ARTIFACT_REFS)
    current_head_commit = _git_head(root)
    subject_history = _git_history_for_paths(root, SUBJECT_ARTIFACT_REFS)
    earliest_subject_commit = subject_history[-1] if subject_history else ""
    step_baseline_commit = _git_parent(root, earliest_subject_commit)
    actual_subject_touched = _git_diff_files(root, step_baseline_commit, subject_commit, SUBJECT_ARTIFACT_REFS)
    if not actual_subject_touched:
        actual_subject_touched = _git_changed_files(root, subject_commit)
    actual_touched = sorted(set(actual_subject_touched + [RECEIPT_REL]))
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = sorted(path for path in actual_touched if _is_protected(path))
    post_touch_ok = set(actual_touched) == set(PLANNED_MUTATES) and not unexpected_touches and not protected_touch_violations
    checks.append(_status_row(check="post_touch_accounting_clean", passed=post_touch_ok, detail="Actual touched set must match the lawful Step 3 subject files plus the Step 3 receipt.", refs=PLANNED_MUTATES))
    if not post_touch_ok:
        failures.append("post_touch_accounting_clean")

    status = "PASS" if not failures else "FAIL_CLOSED"
    verdict = "CONSTITUTIONAL_SPINE_RATIFIED" if status == "PASS" else "CONSTITUTIONAL_SPINE_INCOMPLETE_FAIL_CLOSED"
    return {
        "schema_id": "kt.operator.constitutional_spine_ratification_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "pass_verdict": verdict,
        "controlling_work_order": {
            "schema_id": WORK_ORDER_SCHEMA_ID,
            "work_order_id": WORK_ORDER_ID,
            "step_id": 3,
            "step_name": "CONSTITUTIONAL_SPINE_AND_META_GOVERNANCE",
        },
        "foundation_gate_ref": FOUNDATION_RECEIPT_REL,
        "baseline_gate_ref": BASELINE_RECEIPT_REL,
        "current_head_commit": current_head_commit,
        "compiled_head_commit": subject_commit,
        "claim_boundary": "This receipt ratifies the Step 3 constitutional spine for compiled_head_commit only. A later repository head that contains this receipt is evidence about compiled_head_commit, not automatically the compiled head itself.",
        "planned_mutates": list(PLANNED_MUTATES),
        "actual_touched": actual_touched,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "artifact_digests": _artifact_digests(root, SUBJECT_ARTIFACT_REFS),
        "checks": checks,
        "next_lawful_step": {
            "step_id": 4,
            "step_name": "HISTORICAL_EVIDENCE_INGESTION_AND_FORGOTTEN_SURFACE_RECOVERY",
            "status_after_step_3": "UNLOCKED" if status == "PASS" else "BLOCKED",
        },
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit and ratify the Step 3 constitutional spine artifacts.")
    parser.add_argument("--root", default="", help="Optional repository root override.")
    parser.add_argument("--emit-receipt", action="store_true", help="Write the Step 3 receipt instead of subject artifacts.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = Path(str(args.root)).resolve() if str(args.root).strip() else repo_root()
    if bool(args.emit_receipt):
        report = build_constitutional_spine_ratification_report(root=root)
        write_json_stable((root / Path(RECEIPT_REL)).resolve(), report)
        print(json.dumps({"status": report["status"], "pass_verdict": report["pass_verdict"], "compiled_head_commit": report["compiled_head_commit"], "current_head_commit": report["current_head_commit"], "unexpected_touches": report["unexpected_touches"], "protected_touch_violations": report["protected_touch_violations"]}, indent=2, sort_keys=True))
        return 0 if report["status"] == "PASS" else 1
    writes = emit_subject_artifacts(root=root)
    print(json.dumps({"status": "PASS", "artifact_count": len(DELIVERABLE_REFS), "artifacts_written": writes}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
