from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from tools.operator.canonical_tree_execute import ARCHIVE_DOCS_AUDIT_GLOB, ARCHIVE_GLOB, CURRENT_ARCHIVE_LITERAL
from tools.operator.claim_compiler import build_claim_compiler_receipt
from tools.operator.platform_governance_finalize import build_platform_governance_final_claims
from tools.operator.public_verifier import build_public_verifier_claims, build_public_verifier_report
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DEFAULT_GENERATED_ROOT_REL = "docs/generated"

WORKSTREAM_ID = "WS8_PUBLIC_VERIFIER_AND_CLAIM_COMPILER_ACTIVATION"
STEP_ID = "WS8_STEP_1_PUBLIC_VERIFIER_RELEASE_AND_COMPILER_ACTIVATION"
PASS_VERDICT = "PUBLIC_VERIFIER_AND_CLAIM_COMPILER_ACTIVE"

PUBLIC_VERIFIER_SOURCE_REL = "KT_PROD_CLEANROOM/tools/operator/public_verifier.py"
PUBLIC_VERIFIER_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/closure_foundation/kt_public_verifier_contract.json"
CLAIM_COMPILER_POLICY_REL = "KT_PROD_CLEANROOM/governance/closure_foundation/kt_claim_compiler_policy.json"
PUBLIC_VERIFIER_RULES_REL = "KT_PROD_CLEANROOM/governance/public_verifier_rules.json"

PUBLIC_VERIFIER_MANIFEST_REL = f"{DEFAULT_REPORT_ROOT_REL}/public_verifier_manifest.json"
COMMERCIAL_COMPILER_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/commercial_claim_compiler_receipt.json"
COMMERCIAL_PROGRAM_CATALOG_REL = f"{DEFAULT_REPORT_ROOT_REL}/commercial_program_catalog.json"
DOCUMENTARY_LABELS_REL = f"{DEFAULT_REPORT_ROOT_REL}/documentary_authority_labels.json"
PUBLIC_VERIFIER_RELEASE_MANIFEST_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_public_verifier_release_manifest.json"
PUBLIC_VERIFIER_SBOM_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_public_verifier_sbom.json"
PUBLIC_VERIFIER_ATTESTATION_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_public_verifier_attestation.json"
CLAIM_COMPILER_ACTIVATION_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_claim_compiler_activation_receipt.json"

SETTLED_TRUTH_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/settled_truth_source_receipt.json"
AUTHORITY_CONVERGENCE_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/authority_convergence_receipt.json"
CLAIM_CEILING_SUMMARY_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_claim_ceiling_summary.json"
RUNTIME_BOUNDARY_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/runtime_boundary_integrity_receipt.json"
RELEASE_READINESS_MATRIX_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_release_readiness_matrix.json"

DOCTRINE_MANIFEST_REL = f"{DEFAULT_GENERATED_ROOT_REL}/kt_doctrine_manifest.json"
DOCTRINE_RATIFICATION_LOG_REL = f"{DEFAULT_GENERATED_ROOT_REL}/kt_doctrine_ratification_log.json"
OUTSIDER_PROFILE_REL = f"{DEFAULT_GENERATED_ROOT_REL}/profiles/kt_outsider_onboarding_profile.json"
COMPETITION_PROFILE_REL = f"{DEFAULT_GENERATED_ROOT_REL}/profiles/kt_competition_profile.json"
PUBLICATION_PROFILE_REL = f"{DEFAULT_GENERATED_ROOT_REL}/profiles/kt_publication_profile.json"

TUF_ROOT_INITIALIZATION_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_tuf_root_initialization.json"
SIGSTORE_PUBLICATION_BUNDLE_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_sigstore_publication_bundle.json"
REKOR_INCLUSION_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_rekor_inclusion_receipt.json"
PUBLICATION_STABILIZATION_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/kt_truth_publication_stabilization_receipt.json"

COMMERCIAL_DOC_PATHS = (
    "KT_PROD_CLEANROOM/docs/commercial/KT_CERTIFICATION_PACK.md",
    "KT_PROD_CLEANROOM/docs/commercial/KT_OPERATOR_FACTORY_SKU_CATALOG.md",
)

ALLOWED_SOURCE_ROOTS = (
    "KT_PROD_CLEANROOM/tools/operator/",
    "KT_PROD_CLEANROOM/tools/canonicalize/",
    "KT_PROD_CLEANROOM/tools/verification/",
)
FORBIDDEN_DEPENDENCY_PATTERNS = (
    CURRENT_ARCHIVE_LITERAL,
    "docs/generated/",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
)
PROTECTED_TOUCH_PATTERNS = (
    CURRENT_ARCHIVE_LITERAL,
    ".github/workflows/",
)

PLANNED_MUTATES = [
    PUBLIC_VERIFIER_MANIFEST_REL,
    COMMERCIAL_COMPILER_RECEIPT_REL,
    COMMERCIAL_PROGRAM_CATALOG_REL,
    DOCUMENTARY_LABELS_REL,
    PUBLIC_VERIFIER_RELEASE_MANIFEST_REL,
    PUBLIC_VERIFIER_SBOM_REL,
    PUBLIC_VERIFIER_ATTESTATION_REL,
    CLAIM_COMPILER_ACTIVATION_RECEIPT_REL,
]


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_lines(root: Path) -> List[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return [line.rstrip("\n") for line in result.stdout.splitlines() if line.strip()]


def _dirty_relpaths(status_lines: Sequence[str]) -> List[str]:
    rows: List[str] = []
    for line in status_lines:
        rel = line[3:].strip()
        if rel:
            rows.append(Path(rel).as_posix())
    return rows


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _report_ref(report_root_rel: str, name: str) -> str:
    return str((Path(report_root_rel) / name).as_posix())


def _canonical_hash(payload: Dict[str, Any]) -> str:
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _file_component(root: Path, rel: str, *, component_type: str, role: str) -> Dict[str, Any]:
    return {
        "component_type": component_type,
        "path": str(Path(rel).as_posix()),
        "role": role,
        "sha256": file_sha256((root / Path(rel)).resolve()),
    }


def _parse_local_imports(path: Path) -> Set[str]:
    module = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    imports: Set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = str(alias.name).strip()
                if name.startswith("tools."):
                    imports.add(name)
        elif isinstance(node, ast.ImportFrom):
            name = str(node.module or "").strip()
            if name.startswith("tools."):
                imports.add(name)
    return imports


def _resolve_local_module(root: Path, module_name: str) -> str:
    rel = Path("KT_PROD_CLEANROOM") / Path(*module_name.split("."))
    candidate = rel.with_suffix(".py")
    return candidate.as_posix() if (root / candidate).exists() else ""


def _local_dependency_closure(root: Path, start_rel: str) -> List[str]:
    pending = [Path(start_rel).as_posix()]
    seen: Set[str] = set()
    ordered: List[str] = []
    while pending:
        current = pending.pop(0)
        if current in seen:
            continue
        seen.add(current)
        ordered.append(current)
        current_path = (root / Path(current)).resolve()
        if not current_path.exists():
            raise RuntimeError(f"FAIL_CLOSED: missing verifier source dependency: {current}")
        for module_name in sorted(_parse_local_imports(current_path)):
            rel = _resolve_local_module(root, module_name)
            if rel and rel not in seen:
                pending.append(rel)
    return ordered


def _public_verifier_manifest_payload(*, root: Path, live_head: str, report_root_rel: str) -> Dict[str, Any]:
    claims = build_public_verifier_claims(root=root, live_head=live_head, report_root_rel=report_root_rel)
    governance_claims = build_platform_governance_final_claims(root=root, report_root_rel=report_root_rel)
    settled_truth = _load_required_json(root, SETTLED_TRUTH_RECEIPT_REL)
    convergence = _load_required_json(root, AUTHORITY_CONVERGENCE_RECEIPT_REL)
    status = "PASS" if str(convergence.get("status", "")).strip() == "PASS" and str(claims.get("publication_receipt_status", "")).strip() == "PASS" else "HOLD"
    return {
        "schema_id": "kt.public_verifier_manifest.v4",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "validated_head_sha": live_head,
        "evidence_commit": str(claims.get("evidence_commit", "")).strip(),
        "truth_subject_commit": str(claims.get("truth_subject_commit", "")).strip(),
        "subject_verdict": str(claims.get("subject_verdict", "")).strip(),
        "publication_receipt_status": str(claims.get("publication_receipt_status", "")).strip() or "MISSING",
        "evidence_contains_subject": bool(claims.get("evidence_contains_subject")),
        "evidence_equals_subject": bool(claims.get("evidence_equals_subject")),
        "claim_boundary": str(claims.get("claim_boundary", "")).strip(),
        "platform_governance_subject_commit": str(governance_claims.get("platform_governance_subject_commit", "")).strip(),
        "platform_governance_verdict": str(governance_claims.get("platform_governance_verdict", "")).strip(),
        "platform_governance_claim_admissible": bool(governance_claims.get("platform_governance_claim_admissible")),
        "workflow_governance_status": str(governance_claims.get("workflow_governance_status", "")).strip(),
        "branch_protection_status": str(governance_claims.get("branch_protection_status", "")).strip(),
        "platform_governance_claim_boundary": str(governance_claims.get("platform_governance_claim_boundary", "")).strip(),
        "enterprise_legitimacy_ceiling": str(governance_claims.get("enterprise_legitimacy_ceiling", "")).strip(),
        "platform_governance_receipt_refs": list(governance_claims.get("platform_governance_receipt_refs", [])),
        "platform_block": governance_claims.get("platform_block"),
        "truth_pointer_ref": str(settled_truth.get("authoritative_current_pointer_ref", "")).strip(),
        "state_receipts": [
            _report_ref(report_root_rel, "current_state_receipt.json"),
            _report_ref(report_root_rel, "kt_truth_publication_stabilization_receipt.json"),
            _report_ref(report_root_rel, "main_branch_protection_receipt.json"),
            _report_ref(report_root_rel, "ci_gate_promotion_receipt.json"),
            _report_ref(report_root_rel, "kt_platform_governance_final_decision_receipt.json"),
            _report_ref(report_root_rel, "authority_convergence_receipt.json"),
            _report_ref(report_root_rel, "documentary_truth_validation_receipt.json"),
            _report_ref(report_root_rel, "dependency_inventory_validation_receipt.json"),
        ],
        "publication_evidence_refs": list(claims.get("publication_evidence_refs", [])),
        "integrity_supporting_artifacts": [
            _report_ref(report_root_rel, "dependency_inventory.json"),
            _report_ref(report_root_rel, "python_environment_manifest.json"),
            _report_ref(report_root_rel, "sbom_cyclonedx.json"),
        ],
    }


def _program_catalog_payload(*, root: Path, compiler_receipt: Dict[str, Any], report_root_rel: str) -> Dict[str, Any]:
    catalog = _load_required_json(root, "KT_PROD_CLEANROOM/governance/program_catalog.json")
    programs = catalog.get("programs") if isinstance(catalog.get("programs"), list) else []
    return {
        "schema_id": "kt.commercial_program_catalog.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE" if compiler_receipt["status"] == "PASS" else "HOLD",
        "documentary_only": True,
        "compiled_head_commit": compiler_receipt["compiled_head_commit"],
        "claim_compiler_claim_boundary": compiler_receipt["claim_compiler_claim_boundary"],
        "active_truth_source_ref": compiler_receipt["active_truth_source_ref"],
        "documentary_mirror_ref": compiler_receipt["documentary_mirror_ref"],
        "claim_compiler_receipt_ref": _report_ref(report_root_rel, "commercial_claim_compiler_receipt.json"),
        "public_verifier_manifest_ref": _report_ref(report_root_rel, "public_verifier_manifest.json"),
        "runtime_boundary_receipt_ref": _report_ref(report_root_rel, "runtime_boundary_integrity_receipt.json"),
        "truth_head_claim_verdict": compiler_receipt["truth_head_claim_verdict"],
        "platform_governance_head_claim_verdict": compiler_receipt["platform_governance_head_claim_verdict"],
        "runtime_boundary_head_claim_verdict": compiler_receipt["runtime_boundary_head_claim_verdict"],
        "allowed_current_claims": list(compiler_receipt["allowed_current_claims"]),
        "forbidden_current_claims": list(compiler_receipt["forbidden_current_claims"]),
        "program_count": len(programs),
        "programs": [
            {
                "program_id": str(row.get("program_id", "")).strip(),
                "implementation_path": str(row.get("implementation_path", "")).strip(),
                "commercial_surface": "operator" if "operator" in str(row.get("implementation_path", "")) else "delivery_or_ci",
            }
            for row in programs
            if isinstance(row, dict)
        ],
    }


def _documentary_labels_payload(*, report_root_rel: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.documentary_authority_labels.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "labels": [
            {"glob": "KT_PROD_CLEANROOM/docs/operator/*.md", "label": "DOCUMENTARY_ONLY_UNLESS_CITED_BY_BOARD"},
            {
                "glob": "KT_PROD_CLEANROOM/docs/commercial/*.md",
                "label": "DOCUMENTARY_ONLY_COMMERCIAL_CLAIMS_BIND_TO_CLAIM_COMPILER",
            },
            {"glob": ARCHIVE_DOCS_AUDIT_GLOB, "label": "AUDIT_DOCUMENTARY_ONLY"},
            {"glob": ARCHIVE_GLOB, "label": "HISTORICAL_ONLY"},
        ],
        "claim_compiler_receipt_ref": _report_ref(report_root_rel, "commercial_claim_compiler_receipt.json"),
    }


def _surface_check(check_id: str, ok: bool, detail: str, refs: Sequence[str], failures: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    row = {
        "check": check_id,
        "status": "PASS" if ok else "FAIL",
        "detail": detail,
        "refs": [str(Path(ref).as_posix()) for ref in refs],
    }
    if failures:
        row["failures"] = [str(item) for item in failures]
    return row


def _generated_public_surface_checks(root: Path) -> List[Dict[str, Any]]:
    doctrine_manifest = _load_required_json(root, DOCTRINE_MANIFEST_REL)
    doctrine_ratification = _load_required_json(root, DOCTRINE_RATIFICATION_LOG_REL)
    readiness_matrix = _load_required_json(root, RELEASE_READINESS_MATRIX_REL)
    outsider = _load_required_json(root, OUTSIDER_PROFILE_REL)
    competition = _load_required_json(root, COMPETITION_PROFILE_REL)
    publication = _load_required_json(root, PUBLICATION_PROFILE_REL)

    manifest_refs = doctrine_manifest.get("source_refs", []) if isinstance(doctrine_manifest.get("source_refs"), list) else []
    prohibitions = doctrine_ratification.get("prohibitions", []) if isinstance(doctrine_ratification.get("prohibitions"), list) else []
    readiness_rows = readiness_matrix.get("profiles", []) if isinstance(readiness_matrix.get("profiles"), list) else []

    return [
        _surface_check(
            "generated_doctrine_manifest_bound_to_verifier_and_ceiling",
            PUBLIC_VERIFIER_MANIFEST_REL in manifest_refs and CLAIM_CEILING_SUMMARY_REL in manifest_refs,
            "Generated doctrine must cite the public verifier manifest and claim ceiling summary.",
            [DOCTRINE_MANIFEST_REL, PUBLIC_VERIFIER_MANIFEST_REL, CLAIM_CEILING_SUMMARY_REL],
        ),
        _surface_check(
            "generated_doctrine_ratification_preserves_downgrade_prohibitions",
            "generated doctrine may not phrase HEAD as verified subject unless SHAs match" in prohibitions
            and "generated doctrine may not claim H1_ALLOWED while blockers remain open" in prohibitions,
            "Generated doctrine ratification must preserve current-head and H1 downgrade guards.",
            [DOCTRINE_RATIFICATION_LOG_REL],
        ),
        _surface_check(
            "generated_profiles_preserve_bounded_status",
            outsider.get("current_status") == "ADMISSIBLE_WITH_BOUNDARIES"
            and competition.get("current_status") == "BLOCKED"
            and publication.get("current_status") == "BLOCKED",
            "Generated outsider/competition/publication profiles must stay bounded or blocked.",
            [OUTSIDER_PROFILE_REL, COMPETITION_PROFILE_REL, PUBLICATION_PROFILE_REL],
        ),
        _surface_check(
            "release_readiness_matrix_has_forbidden_claims_and_verifier_refs",
            bool(readiness_rows)
            and all(isinstance(row, dict) and row.get("forbidden_claims") for row in readiness_rows)
            and any(
                isinstance(row, dict) and PUBLIC_VERIFIER_MANIFEST_REL in (row.get("evidence_refs") or [])
                for row in readiness_rows
            ),
            "Release readiness rows must carry forbidden claims and cite verifier evidence where applicable.",
            [RELEASE_READINESS_MATRIX_REL, PUBLIC_VERIFIER_MANIFEST_REL],
        ),
    ]


def _dependency_checks(root: Path, dependency_closure: Sequence[str]) -> List[Dict[str, Any]]:
    verifier_contract = _load_required_json(root, PUBLIC_VERIFIER_CONTRACT_REL)
    outside_allowed = [rel for rel in dependency_closure if not any(str(Path(rel).as_posix()).startswith(prefix) for prefix in ALLOWED_SOURCE_ROOTS)]
    forbidden = [rel for rel in dependency_closure if any(str(Path(rel).as_posix()).startswith(prefix) for prefix in FORBIDDEN_DEPENDENCY_PATTERNS)]
    required_inputs = [str(item) for item in verifier_contract.get("required_inputs", []) if str(item).strip()]
    missing_inputs = [rel for rel in required_inputs if not (root / Path(rel)).exists()]
    return [
        _surface_check(
            "public_verifier_local_dependency_closure_within_allowed_source_roots",
            not outside_allowed,
            "Public verifier local dependency closure must stay within operator/canonicalize/verification helper roots.",
            dependency_closure,
            failures=outside_allowed,
        ),
        _surface_check(
            "public_verifier_local_dependency_closure_avoids_forbidden_paths",
            not forbidden,
            "Public verifier local dependency closure must not touch archive, generated docs, or prod runtime internals.",
            dependency_closure,
            failures=forbidden,
        ),
        _surface_check(
            "public_verifier_offline_required_inputs_present",
            not missing_inputs,
            "Public verifier release requires all offline verification inputs from the ratified contract.",
            required_inputs,
            failures=missing_inputs,
        ),
    ]


def _build_release_manifest(
    *,
    generated_utc: str,
    compiled_head_commit: str,
    verifier_contract: Dict[str, Any],
    verifier_report: Dict[str, Any],
    dependency_closure: Sequence[str],
) -> Dict[str, Any]:
    payload = {
        "schema_id": "kt.operator.public_verifier_release_manifest.v1",
        "manifest_id": "KT_PUBLIC_VERIFIER_RELEASE_MANIFEST_V1",
        "version": "1.0.0",
        "scope": "public_verifier_release",
        "included_paths": [
            PUBLIC_VERIFIER_SOURCE_REL,
            PUBLIC_VERIFIER_MANIFEST_REL,
            PUBLIC_VERIFIER_CONTRACT_REL,
            PUBLIC_VERIFIER_RULES_REL,
            TUF_ROOT_INITIALIZATION_REL,
            SIGSTORE_PUBLICATION_BUNDLE_REL,
            REKOR_INCLUSION_RECEIPT_REL,
            PUBLICATION_STABILIZATION_RECEIPT_REL,
        ],
        "excluded_paths": list(verifier_contract.get("forbidden_runtime_dependencies", [])),
        "generated_from": [
            PUBLIC_VERIFIER_CONTRACT_REL,
            CLAIM_COMPILER_POLICY_REL,
            TUF_ROOT_INITIALIZATION_REL,
            SIGSTORE_PUBLICATION_BUNDLE_REL,
            REKOR_INCLUSION_RECEIPT_REL,
            PUBLICATION_STABILIZATION_RECEIPT_REL,
            PUBLIC_VERIFIER_MANIFEST_REL,
        ],
        "generated_at": generated_utc,
        "compiled_head_commit": compiled_head_commit,
        "verifier_id": str(verifier_contract.get("verifier_id", "")).strip(),
        "supported_proof_classes": list(verifier_contract.get("supported_proof_classes", [])),
        "required_inputs": list(verifier_contract.get("required_inputs", [])),
        "offline_verification_capable": bool(verifier_contract.get("offline_verification_capable")),
        "subject_evidence_boundary_rules": list(verifier_contract.get("subject_evidence_boundary_rules", [])),
        "fail_closed_conditions": list(verifier_contract.get("fail_closed_conditions", [])),
        "allowed_contract_dependencies": list(verifier_contract.get("allowed_contract_dependencies", [])),
        "release_entrypoint": "python -m tools.operator.public_verifier",
        "local_dependency_closure": list(dependency_closure),
        "truth_subject_commit": str(verifier_report.get("truth_subject_commit", "")).strip(),
        "evidence_commit": str(verifier_report.get("evidence_commit", "")).strip(),
        "subject_verdict": str(verifier_report.get("subject_verdict", "")).strip(),
        "head_claim_verdict": str(verifier_report.get("head_claim_verdict", "")).strip(),
        "platform_governance_head_claim_verdict": str(verifier_report.get("platform_governance_head_claim_verdict", "")).strip(),
        "claim_boundary": str(verifier_report.get("claim_boundary", "")).strip(),
        "head_claim_boundary": str(verifier_report.get("head_claim_boundary", "")).strip(),
    }
    payload["sha256"] = _canonical_hash(payload)
    return payload


def _build_verifier_sbom(*, root: Path, generated_utc: str, compiled_head_commit: str, dependency_closure: Sequence[str], verifier_contract: Dict[str, Any]) -> Dict[str, Any]:
    components = [_file_component(root, rel, component_type="source", role="local_dependency") for rel in dependency_closure]
    components.extend(
        _file_component(root, rel, component_type="contract_input", role="required_input")
        for rel in verifier_contract.get("required_inputs", [])
        if isinstance(rel, str) and (root / Path(rel)).exists()
    )
    payload = {
        "schema_id": "kt.operator.public_verifier_sbom.v1",
        "manifest_id": "KT_PUBLIC_VERIFIER_SBOM_V1",
        "version": "1.0.0",
        "scope": "public_verifier_release",
        "included_paths": [row["path"] for row in components],
        "excluded_paths": list(verifier_contract.get("forbidden_runtime_dependencies", [])),
        "generated_from": [PUBLIC_VERIFIER_SOURCE_REL, PUBLIC_VERIFIER_CONTRACT_REL, PUBLIC_VERIFIER_RULES_REL],
        "generated_at": generated_utc,
        "compiled_head_commit": compiled_head_commit,
        "component_count": len(components),
        "third_party_component_count": 0,
        "components": components,
    }
    payload["sha256"] = _canonical_hash(payload)
    return payload


def _build_public_verifier_attestation(
    *,
    root: Path,
    generated_utc: str,
    compiled_head_commit: str,
    release_manifest: Dict[str, Any],
    verifier_sbom: Dict[str, Any],
    verifier_report: Dict[str, Any],
    compiler_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    tuf_root = _load_required_json(root, TUF_ROOT_INITIALIZATION_REL)
    rekor_receipt = _load_required_json(root, REKOR_INCLUSION_RECEIPT_REL)
    sigstore_bundle = _load_required_json(root, SIGSTORE_PUBLICATION_BUNDLE_REL)
    stabilization = _load_required_json(root, PUBLICATION_STABILIZATION_RECEIPT_REL)
    return {
        "schema_id": "kt.operator.public_verifier_attestation.v1",
        "artifact_id": Path(PUBLIC_VERIFIER_ATTESTATION_REL).name,
        "status": "PASS",
        "generated_utc": generated_utc,
        "compiled_head_commit": compiled_head_commit,
        "release_manifest_ref": PUBLIC_VERIFIER_RELEASE_MANIFEST_REL,
        "release_manifest_sha256": str(release_manifest.get("sha256", "")).strip(),
        "sbom_ref": PUBLIC_VERIFIER_SBOM_REL,
        "sbom_sha256": str(verifier_sbom.get("sha256", "")).strip(),
        "public_verifier_manifest_ref": PUBLIC_VERIFIER_MANIFEST_REL,
        "public_verifier_manifest_sha256": file_sha256((root / Path(PUBLIC_VERIFIER_MANIFEST_REL)).resolve()),
        "claim_compiler_receipt_ref": COMMERCIAL_COMPILER_RECEIPT_REL,
        "claim_compiler_receipt_sha256": file_sha256((root / Path(COMMERCIAL_COMPILER_RECEIPT_REL)).resolve()),
        "tuf_root_initialization_ref": TUF_ROOT_INITIALIZATION_REL,
        "trust_root_id": str(tuf_root.get("trust_root_id", "")).strip(),
        "sigstore_publication_bundle_ref": SIGSTORE_PUBLICATION_BUNDLE_REL,
        "sigstore_bundle_sha256": file_sha256((root / Path(SIGSTORE_PUBLICATION_BUNDLE_REL)).resolve()),
        "rekor_inclusion_receipt_ref": REKOR_INCLUSION_RECEIPT_REL,
        "rekor_log_id": str(rekor_receipt.get("log_id", "")).strip(),
        "rekor_log_index": rekor_receipt.get("log_index"),
        "publication_stabilization_receipt_ref": PUBLICATION_STABILIZATION_RECEIPT_REL,
        "truth_subject_commit": str(verifier_report.get("truth_subject_commit", "")).strip(),
        "truth_evidence_commit": str(verifier_report.get("evidence_commit", "")).strip(),
        "head_claim_verdict": str(verifier_report.get("head_claim_verdict", "")).strip(),
        "claim_compiler_status": str(compiler_receipt.get("status", "")).strip(),
        "semantic_boundary": {
            "authority_convergence_resolved": False,
            "published_head_self_convergence_resolved": False,
            "h1_allowed": False,
        },
        "checks": [
            {"check": "publication_stabilization_receipt_pass", "status": str(stabilization.get("status", "")).strip()},
            {"check": "sigstore_bundle_pass", "status": str(sigstore_bundle.get("status", "")).strip()},
            {"check": "rekor_receipt_pass", "status": str(rekor_receipt.get("status", "")).strip()},
        ],
    }


def build_public_verifier_release_outputs(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL, generated_utc: str = "") -> Dict[str, Any]:
    generated = str(generated_utc).strip() or utc_now_iso_z()
    compiled_head_commit = _git_head(root)
    verifier_contract = _load_required_json(root, PUBLIC_VERIFIER_CONTRACT_REL)
    claim_policy = _load_required_json(root, CLAIM_COMPILER_POLICY_REL)

    dependency_closure = _local_dependency_closure(root, PUBLIC_VERIFIER_SOURCE_REL)
    dependency_checks = _dependency_checks(root, dependency_closure)
    if any(row["status"] != "PASS" for row in dependency_checks):
        raise RuntimeError("FAIL_CLOSED: public verifier dependency boundary is not releasable")

    fresh_manifest = _public_verifier_manifest_payload(root=root, live_head=compiled_head_commit, report_root_rel=report_root_rel)
    write_json_stable((root / Path(PUBLIC_VERIFIER_MANIFEST_REL)).resolve(), fresh_manifest)
    verifier_report = build_public_verifier_report(root=root, report_root_rel=report_root_rel)

    compiler_receipt = build_claim_compiler_receipt(root=root, report_root_rel=report_root_rel)
    write_json_stable((root / Path(COMMERCIAL_COMPILER_RECEIPT_REL)).resolve(), compiler_receipt)
    write_json_stable(
        (root / Path(COMMERCIAL_PROGRAM_CATALOG_REL)).resolve(),
        _program_catalog_payload(root=root, compiler_receipt=compiler_receipt, report_root_rel=report_root_rel),
    )
    write_json_stable((root / Path(DOCUMENTARY_LABELS_REL)).resolve(), _documentary_labels_payload(report_root_rel=report_root_rel))

    public_surface_checks = _generated_public_surface_checks(root)
    downgrade_checks = [
        _surface_check(
            "truth_claim_downgraded_on_subject_evidence_lag",
            verifier_report.get("head_claim_verdict") == "HEAD_CONTAINS_TRANSPARENCY_VERIFIED_SUBJECT_EVIDENCE",
            "When HEAD differs from truth_subject_commit, the public verifier must say HEAD contains evidence rather than HEAD is the verified subject.",
            [PUBLIC_VERIFIER_MANIFEST_REL, PUBLIC_VERIFIER_RULES_REL],
        ),
        _surface_check(
            "claim_compiler_downgrades_runtime_boundary_on_head_lag",
            compiler_receipt.get("runtime_boundary_head_claim_verdict") == "HEAD_CONTAINS_RUNTIME_BOUNDARY_EVIDENCE_FOR_SUBJECT",
            "Commercial claim compilation must downgrade runtime-boundary freshness when HEAD differs from runtime_boundary_subject_commit.",
            [COMMERCIAL_COMPILER_RECEIPT_REL, RUNTIME_BOUNDARY_RECEIPT_REL],
        ),
        _surface_check(
            "claim_compiler_commercial_docs_pass",
            compiler_receipt.get("status") == "PASS" and all(row.get("status") == "PASS" for row in compiler_receipt.get("commercial_doc_checks", [])),
            "Commercial claim compiler must pass and keep required boundary markers on commercial docs.",
            [COMMERCIAL_COMPILER_RECEIPT_REL, *COMMERCIAL_DOC_PATHS],
        ),
        _surface_check(
            "claim_compiler_policy_always_on_surfaces_are_resolved",
            list(claim_policy.get("always_on_surfaces", []))
            == [
                "docs/generated/**",
                "KT_PROD_CLEANROOM/docs/commercial/**",
                "KT_PROD_CLEANROOM/reports/kt_release_readiness_matrix.json",
                "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
            ],
            "The ratified always-on claim compiler surfaces must remain explicit during WS8 activation.",
            [CLAIM_COMPILER_POLICY_REL],
        ),
    ]

    release_manifest = _build_release_manifest(
        generated_utc=generated,
        compiled_head_commit=compiled_head_commit,
        verifier_contract=verifier_contract,
        verifier_report=verifier_report,
        dependency_closure=dependency_closure,
    )
    verifier_sbom = _build_verifier_sbom(
        root=root,
        generated_utc=generated,
        compiled_head_commit=compiled_head_commit,
        dependency_closure=dependency_closure,
        verifier_contract=verifier_contract,
    )
    verifier_attestation = _build_public_verifier_attestation(
        root=root,
        generated_utc=generated,
        compiled_head_commit=compiled_head_commit,
        release_manifest=release_manifest,
        verifier_sbom=verifier_sbom,
        verifier_report=verifier_report,
        compiler_receipt=compiler_receipt,
    )
    checks = dependency_checks + public_surface_checks + downgrade_checks + [
        _surface_check(
            "public_verifier_release_bundle_emitted",
            True,
            "WS8 must emit the verifier release manifest, verifier SBOM, and verifier attestation.",
            [PUBLIC_VERIFIER_RELEASE_MANIFEST_REL, PUBLIC_VERIFIER_SBOM_REL, PUBLIC_VERIFIER_ATTESTATION_REL],
        )
    ]
    return {
        "generated_utc": generated,
        "compiled_head_commit": compiled_head_commit,
        "fresh_public_verifier_manifest": fresh_manifest,
        "verifier_report": verifier_report,
        "compiler_receipt": compiler_receipt,
        "release_manifest": release_manifest,
        "verifier_sbom": verifier_sbom,
        "verifier_attestation": verifier_attestation,
        "checks": checks,
    }


def emit_public_verifier_release_bundle(*, root: Optional[Path] = None, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    repo = root or repo_root()
    outputs = build_public_verifier_release_outputs(root=repo, report_root_rel=report_root_rel)
    generated_utc = str(outputs["generated_utc"]).strip()
    compiled_head_commit = str(outputs["compiled_head_commit"]).strip()

    write_json_stable((repo / Path(PUBLIC_VERIFIER_MANIFEST_REL)).resolve(), outputs["fresh_public_verifier_manifest"])
    write_json_stable((repo / Path(PUBLIC_VERIFIER_RELEASE_MANIFEST_REL)).resolve(), outputs["release_manifest"])
    write_json_stable((repo / Path(PUBLIC_VERIFIER_SBOM_REL)).resolve(), outputs["verifier_sbom"])
    write_json_stable((repo / Path(PUBLIC_VERIFIER_ATTESTATION_REL)).resolve(), outputs["verifier_attestation"])

    actual_touched = sorted(set(_dirty_relpaths(_git_status_lines(repo)) + [Path(CLAIM_COMPILER_ACTIVATION_RECEIPT_REL).as_posix()]))
    unexpected_touches = sorted(path for path in actual_touched if path not in PLANNED_MUTATES)
    protected_touch_violations = sorted(path for path in actual_touched if any(path.startswith(prefix) for prefix in PROTECTED_TOUCH_PATTERNS))
    checks = list(outputs["checks"])
    checks.append(
        _surface_check(
            "unexpected_touches_present",
            not unexpected_touches,
            "WS8 may only touch the verifier/claim-compiler release bundle and supporting public report surfaces.",
            actual_touched,
            failures=unexpected_touches,
        )
    )
    checks.append(
        _surface_check(
            "protected_touch_violations_present",
            not protected_touch_violations,
            "WS8 may not touch archive or workflow-protected paths.",
            protected_touch_violations,
            failures=protected_touch_violations,
        )
    )
    failed_checks = [row["check"] for row in checks if row["status"] != "PASS"]
    receipt = {
        "schema_id": "kt.operator.claim_compiler_activation_receipt.v1",
        "artifact_id": Path(CLAIM_COMPILER_ACTIVATION_RECEIPT_REL).name,
        "status": "PASS" if not failed_checks else "FAIL_CLOSED",
        "pass_verdict": PASS_VERDICT,
        "generated_utc": generated_utc,
        "compiled_head_commit": compiled_head_commit,
        "subject_head_commit": compiled_head_commit,
        "evidence_head_commit": compiled_head_commit,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "validators_run": ["python -m tools.operator.public_verifier_release_validate"],
        "next_lawful_step": {
            "status_after_workstream": "UNLOCKED" if not failed_checks else "BLOCKED",
            "workstream_id": "WS9_AUTHORITY_AND_PUBLISHED_HEAD_CLOSURE",
        },
        "checks": checks,
        "issues_found": ["stale_public_verifier_manifest_refreshed_from_ws7_receipts"],
        "resolution": "WS8 refreshed the verifier boundary from ratified receipts, activated claim compilation on designated public surfaces, and emitted a minimal independent verifier release bundle.",
        "step_report": {
            "timestamp": generated_utc,
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "refreshed public_verifier_manifest.json from current ratified authority and governance receipts",
                "recompiled commercial claim compiler surfaces against the refreshed verifier boundary",
                "validated public-surface downgrade guards on generated doctrine, release readiness, and commercial docs",
                "emitted the public verifier release manifest, verifier SBOM, and verifier attestation",
                "sealed WS8 without reopening authority convergence, published-head self-convergence, or H1",
            ],
            "files_touched": actual_touched,
            "tests_run": ["python -m pytest KT_PROD_CLEANROOM/tests/operator/test_public_verifier_release_validate.py -q"],
            "validators_run": ["python -m tools.operator.public_verifier_release_validate"],
            "issues_found": ["stale_public_verifier_manifest_refreshed_from_ws7_receipts"],
            "resolution": "The verifier release bundle is now compiled from current receipts, and claim surfaces downgrade automatically when subject/evidence lag remains.",
            "pass_fail_status": "PASS" if not failed_checks else "FAIL_CLOSED",
            "unexpected_touches": unexpected_touches,
            "protected_touch_violations": protected_touch_violations,
        },
    }
    write_json_stable((repo / Path(CLAIM_COMPILER_ACTIVATION_RECEIPT_REL)).resolve(), receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WS8: release the minimal public verifier and activate always-on claim compilation.")
    parser.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    receipt = emit_public_verifier_release_bundle(root=repo_root(), report_root_rel=str(args.report_root))
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(receipt.get("status", "")).strip() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
