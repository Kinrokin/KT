from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.canonical_tree_execute import ARCHIVE_GLOB
from tools.operator.public_verifier import build_public_verifier_report
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.verification.attestation_hmac import env_key_name_for_key_id, hmac_key_fingerprint_hex, sign_hmac, verify_hmac_signoff


WORK_ORDER_ID = "WORK_ORDER_KT_FRONTIER_ELEVATION_AND_PUBLIC_DEFENSIBILITY"
WORK_ORDER_SCHEMA_ID = "kt.work_order.frontier_elevation_and_public_defensibility.v2"
WORKSTREAM_ID = "WS19_DETACHED_PUBLIC_VERIFIER_PACKAGE"
STEP_ID = "WS19_STEP_1_PACKAGE_AND_PROVE_DETACHED_VERIFIER_PARITY"
PASS_VERDICT = "DETACHED_PUBLIC_VERIFIER_PACKAGE_PROVEN"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_detached_release_manifest.json"
SBOM_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_detached_sbom.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_detached_receipt.json"

DEFAULT_WS17_POLICY_REL = f"{REPORT_ROOT_REL}/kt_signed_revision_policy.json"
DEFAULT_WS17_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_revision_trust_receipt.json"
DEFAULT_SOURCE_PROVENANCE_REL = f"{REPORT_ROOT_REL}/kt_source_provenance.dsse"
DEFAULT_SOURCE_AUTHORITY_BUNDLE_REL = f"{REPORT_ROOT_REL}/source_build_attestation/authority_bundle.json"
DEFAULT_SOURCE_AUTHORITY_SUBJECT_REL = f"{REPORT_ROOT_REL}/source_build_attestation/authority_subject.json"
DEFAULT_SOURCE_IN_TOTO_STATEMENT_REL = f"{REPORT_ROOT_REL}/source_build_attestation/in_toto_statement.json"
DEFAULT_WS18_BUILD_PROVENANCE_REL = f"{REPORT_ROOT_REL}/kt_build_provenance.dsse"
DEFAULT_WS18_VSA_REL = f"{REPORT_ROOT_REL}/kt_verification_summary_attestation.dsse"
DEFAULT_WS18_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_build_verification_receipt.json"
DEFAULT_PUBLIC_VERIFIER_MANIFEST_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
DEFAULT_CRYPTO_PUBLICATION_RECEIPT_REL = f"{REPORT_ROOT_REL}/cryptographic_publication_receipt.json"
DEFAULT_CRYPTO_PUBLICATION_SUBJECT_REL = f"{REPORT_ROOT_REL}/cryptographic_publication/authority_subject.json"
DEFAULT_CRYPTO_PUBLICATION_BUNDLE_REL = f"{REPORT_ROOT_REL}/cryptographic_publication/authority_bundle.json"
DEFAULT_CRYPTO_PUBLICATION_STATEMENT_REL = f"{REPORT_ROOT_REL}/cryptographic_publication/in_toto_statement.json"
DEFAULT_CRYPTO_PUBLICATION_SIGNATURE_REL = f"{REPORT_ROOT_REL}/cryptographic_publication/in_toto_statement.sig"
DEFAULT_CRYPTO_PUBLICATION_BUNDLE_JSON_REL = f"{REPORT_ROOT_REL}/cryptographic_publication/in_toto_statement.bundle.json"
DEFAULT_FINAL_GOVERNANCE_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_platform_governance_final_decision_receipt.json"
DEFAULT_TUF_ROOT_INITIALIZATION_REL = f"{REPORT_ROOT_REL}/kt_tuf_root_initialization.json"
DEFAULT_SIGSTORE_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_sigstore_publication_bundle.json"
DEFAULT_REKOR_INCLUSION_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_rekor_inclusion_receipt.json"

DETACHED_RUNTIME_TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/public_verifier_detached_runtime.py"
TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/public_verifier_detached_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_public_verifier_detached_validate.py"

DETACHED_PROOF_ROOT_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS19_detached_public_verifier_proof"
DETACHED_PACKAGE_ROOT_REL = f"{DETACHED_PROOF_ROOT_REL}/package"
DETACHED_RUNTIME_RECEIPT_REF = f"{DETACHED_PROOF_ROOT_REL}/reports/detached_runtime_receipt.json"
DETACHED_RUNTIME_REPORT_REF = f"{DETACHED_PROOF_ROOT_REL}/reports/detached_public_verifier_report.json"
DETACHED_ENTRYPOINT = "python -m tools.operator.public_verifier_detached_runtime"

STRONGER_CLAIM_NOT_MADE = (
    "WS19 does not claim independent external reproduction, third-party detached replay, or public horizon opening."
)
PARITY_FIELDS = (
    "status",
    "subject_verdict",
    "publication_receipt_status",
    "head_claim_verdict",
    "claim_boundary",
    "head_claim_boundary",
    "platform_governance_verdict",
    "platform_governance_head_claim_verdict",
    "platform_governance_claim_boundary",
    "platform_governance_head_claim_boundary",
    "enterprise_legitimacy_ceiling",
)
VALIDATORS_RUN = ["python -m tools.operator.public_verifier_detached_validate"]
TESTS_RUN = ["python -m pytest KT_PROD_CLEANROOM/tests/operator/test_public_verifier_detached_validate.py -q"]
PROTECTED_PATTERNS = (ARCHIVE_GLOB, "**/archive/**", "**/historical/**")
VOLATILE_JSON_KEYS = ("generated_utc", "timestamp")
PACKAGED_INPUT_REFS = [
    DEFAULT_WS17_POLICY_REL,
    DEFAULT_WS17_RECEIPT_REL,
    DEFAULT_SOURCE_PROVENANCE_REL,
    DEFAULT_SOURCE_AUTHORITY_SUBJECT_REL,
    DEFAULT_SOURCE_IN_TOTO_STATEMENT_REL,
    DEFAULT_SOURCE_AUTHORITY_BUNDLE_REL,
    DEFAULT_WS18_BUILD_PROVENANCE_REL,
    DEFAULT_WS18_VSA_REL,
    DEFAULT_WS18_RECEIPT_REL,
    DEFAULT_PUBLIC_VERIFIER_MANIFEST_REL,
    DEFAULT_CRYPTO_PUBLICATION_RECEIPT_REL,
    DEFAULT_CRYPTO_PUBLICATION_SUBJECT_REL,
    DEFAULT_CRYPTO_PUBLICATION_BUNDLE_REL,
    DEFAULT_CRYPTO_PUBLICATION_STATEMENT_REL,
    DEFAULT_CRYPTO_PUBLICATION_SIGNATURE_REL,
    DEFAULT_CRYPTO_PUBLICATION_BUNDLE_JSON_REL,
    DEFAULT_FINAL_GOVERNANCE_RECEIPT_REL,
    DEFAULT_TUF_ROOT_INITIALIZATION_REL,
    DEFAULT_SIGSTORE_BUNDLE_REL,
    DEFAULT_REKOR_INCLUSION_RECEIPT_REL,
    "KT_PROD_CLEANROOM/governance/public_verifier_rules.json",
    "KT_PROD_CLEANROOM/governance/closure_foundation/kt_public_verifier_contract.json",
    "KT_PROD_CLEANROOM/governance/closure_foundation/kt_tuf_root_policy.json",
    "KT_PROD_CLEANROOM/governance/signer_identity_policy.json",
    "KT_PROD_CLEANROOM/governance/signers/kt_op1_cosign.pub",
    "KT_PROD_CLEANROOM/governance/attestation_fabric_contract.json",
    "KT_PROD_CLEANROOM/governance/authority_bundle.schema.json",
    "KT_PROD_CLEANROOM/governance/supply_chain_layout.json",
]
CREATED_FILES = [
    DETACHED_RUNTIME_TOOL_REL,
    TOOL_REL,
    TEST_REL,
    MANIFEST_REL,
    SBOM_REL,
    RECEIPT_REL,
]
WORKSTREAM_FILES_TOUCHED = list(CREATED_FILES)
SURFACE_CLASSIFICATIONS = {
    DETACHED_RUNTIME_TOOL_REL: "detached runtime wrapper",
    TOOL_REL: "canonical active file",
    TEST_REL: "validator/test file",
    MANIFEST_REL: "generated detached release manifest",
    SBOM_REL: "generated detached verifier sbom",
    RECEIPT_REL: "generated receipt",
}


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


def _dirty_relpaths(root: Path, status_lines: Sequence[str]) -> List[str]:
    rows: List[str] = []
    for line in status_lines:
        rel = line[3:].strip()
        if not rel:
            continue
        path = (root / Path(rel)).resolve()
        if path.exists() and path.is_dir():
            rows.extend(child.resolve().relative_to(root.resolve()).as_posix() for child in path.rglob("*") if child.is_file())
        else:
            rows.append(Path(rel).as_posix())
    return sorted(set(rows))


def _is_protected(path: str) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in PROTECTED_PATTERNS)


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS19 input: {rel}")
    return load_json(path)


def _canonical_hash(payload: Any) -> str:
    return sha256_hex(canonicalize_bytes(payload))


def _must_env_key_bytes(key_id: str) -> Tuple[bytes, str]:
    env_name = env_key_name_for_key_id(key_id)
    value = str(os.environ.get(env_name, "")).strip()
    if not value:
        raise RuntimeError(f"FAIL_CLOSED: missing required HMAC env key: {env_name}")
    return value.encode("utf-8"), env_name


def _validate_revision_policy_trust_roots(revision_policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    trust_roots = revision_policy.get("trust_roots")
    if not isinstance(trust_roots, list) or not trust_roots:
        raise RuntimeError("FAIL_CLOSED: WS17 revision policy missing trust_roots")
    verified: List[Dict[str, Any]] = []
    for row in trust_roots:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: revision policy trust_roots malformed")
        key_id = str(row.get("key_id", "")).strip()
        expected_fp = str(row.get("fingerprint_sha256", "")).strip()
        if not key_id or len(expected_fp) != 64:
            raise RuntimeError("FAIL_CLOSED: revision policy trust root incomplete")
        key_bytes, env_name = _must_env_key_bytes(key_id)
        actual_fp = hmac_key_fingerprint_hex(key_bytes)
        if actual_fp != expected_fp:
            raise RuntimeError(f"FAIL_CLOSED: HMAC trust root fingerprint mismatch for {key_id}")
        verified.append({"key_id": key_id, "env_var": env_name, "fingerprint_sha256": actual_fp})
    return verified


def _build_hmac_signoffs(payload_hash: str, trust_roots: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    signoffs: List[Dict[str, Any]] = []
    for row in trust_roots:
        key_id = str(row.get("key_id", "")).strip()
        key_bytes, env_name = _must_env_key_bytes(key_id)
        signature, fingerprint = sign_hmac(key_bytes=key_bytes, key_id=key_id, payload_hash=payload_hash)
        signoff = {
            "key_id": key_id,
            "env_var": env_name,
            "payload_hash": payload_hash,
            "hmac_signature": signature,
            "hmac_key_fingerprint": fingerprint,
            "mode": "HMAC_DETACHED_RELEASE_BINDING",
        }
        ok, err = verify_hmac_signoff(signoff=signoff, key_bytes=key_bytes)
        if not ok:
            raise RuntimeError(f"FAIL_CLOSED: HMAC signoff self-verification failed for {key_id}: {err}")
        signoffs.append(signoff)
    return signoffs


def _verify_signoffs(signoffs: Sequence[Dict[str, Any]], payload_hash: str) -> bool:
    if not isinstance(signoffs, list) or len(signoffs) < 2:
        return False
    for row in signoffs:
        if str(row.get("payload_hash", "")).strip() != str(payload_hash).strip():
            return False
        key_id = str(row.get("key_id", "")).strip()
        key_bytes, _ = _must_env_key_bytes(key_id)
        ok, _ = verify_hmac_signoff(signoff=row, key_bytes=key_bytes)
        if not ok:
            return False
    return True


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
            raise RuntimeError(f"FAIL_CLOSED: missing detached verifier source dependency: {current}")
        for module_name in sorted(_parse_local_imports(current_path)):
            rel = _resolve_local_module(root, module_name)
            if rel and rel not in seen:
                pending.append(rel)
    return ordered


def _copy_packaged_file(root: Path, package_root: Path, rel: str) -> Dict[str, Any]:
    source = (root / Path(rel)).resolve()
    if not source.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing packaged detached verifier input: {rel}")
    destination = (package_root / Path(rel)).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return {"path": str(Path(rel).as_posix()), "sha256": file_sha256(destination)}


def _package_component_role(path: str) -> Tuple[str, str]:
    normalized = str(path).replace("\\", "/")
    if normalized == DETACHED_RUNTIME_TOOL_REL:
        return "source", "detached_runtime_wrapper"
    if normalized.startswith("KT_PROD_CLEANROOM/tools/"):
        return "source", "runtime_source"
    if normalized.startswith("KT_PROD_CLEANROOM/governance/"):
        return "governance_input", "policy_or_schema"
    return "report_input", "detached_verifier_input"


def _package_root_sha256(components: Sequence[Dict[str, Any]]) -> str:
    payload = [{"path": row["path"], "sha256": row["sha256"]} for row in sorted(components, key=lambda row: row["path"])]
    return _canonical_hash(payload)


def _check_status(receipt: Dict[str, Any], check_id: str) -> bool:
    checks = receipt.get("checks")
    if not isinstance(checks, list):
        return False
    for row in checks:
        if isinstance(row, dict) and str(row.get("check", "")).strip() == check_id:
            return str(row.get("status", "")).strip() == "PASS"
    return False


def _parity_map(repo_local_report: Dict[str, Any], detached_report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        field: {
            "repo_local": repo_local_report.get(field),
            "detached": detached_report.get(field),
            "match": repo_local_report.get(field) == detached_report.get(field),
        }
        for field in PARITY_FIELDS
    }


def build_detached_public_verifier_outputs_from_artifacts(
    *,
    current_repo_head: str,
    ws17_receipt: Dict[str, Any],
    ws18_receipt: Dict[str, Any],
    package_manifest: Dict[str, Any],
    detached_runtime_receipt: Dict[str, Any],
    repo_local_report: Dict[str, Any],
    changed_files: Sequence[str],
    prewrite_scope_clean: bool,
) -> Dict[str, Dict[str, Any]]:
    changed = sorted(set(str(path).replace("\\", "/") for path in changed_files))
    unexpected = sorted(path for path in changed if path not in WORKSTREAM_FILES_TOUCHED)
    protected = sorted(path for path in changed if _is_protected(path))
    if unexpected or protected:
        raise RuntimeError("FAIL_CLOSED: unexpected subject touches detected: " + ", ".join(unexpected + protected))

    ws17_ok = str(ws17_receipt.get("status", "")).strip() == "PASS" and str(ws17_receipt.get("pass_verdict", "")).strip() == "SOURCE_BUILD_ATTESTATION_PROVEN"
    ws18_ok = str(ws18_receipt.get("status", "")).strip() == "PASS" and str(ws18_receipt.get("pass_verdict", "")).strip() == "BUILD_PROVENANCE_AND_VSA_ALIGNED"
    manifest_signoffs_ok = _verify_signoffs(
        list(package_manifest.get("release_signatures", [])),
        str(package_manifest.get("package_root_sha256", "")).strip(),
    )
    detached_runtime_ok = (
        str(detached_runtime_receipt.get("status", "")).strip() == "PASS"
        and detached_runtime_receipt.get("detached_environment", {}).get("detached_root_detected") is True
        and detached_runtime_receipt.get("detached_environment", {}).get("git_head_available") is False
    )
    detached_checks_ok = all(
        _check_status(detached_runtime_receipt, check_id)
        for check_id in (
            "detached_root_without_git_checkout",
            "trust_root_resolved_from_packaged_policy",
            "source_and_build_provenance_resolved",
            "rekor_and_sigstore_bundle_resolved",
            "authority_state_resolved",
        )
    )
    detached_report = detached_runtime_receipt.get("public_verifier_report")
    parity_rows = _parity_map(repo_local_report, detached_report if isinstance(detached_report, dict) else {})
    parity_ok = all(row["match"] for row in parity_rows.values())
    stronger_claim_ok = (
        str(package_manifest.get("stronger_claim_not_made", "")).strip() == STRONGER_CLAIM_NOT_MADE
        and str(detached_runtime_receipt.get("stronger_claim_not_made", "")).strip() == STRONGER_CLAIM_NOT_MADE
    )
    status = "PASS" if all([prewrite_scope_clean, ws17_ok, ws18_ok, manifest_signoffs_ok, detached_runtime_ok, detached_checks_ok, parity_ok, stronger_claim_ok]) else "BLOCKED"

    receipt = {
        "schema_id": "kt.operator.public_verifier_detached_receipt.v1",
        "artifact_id": Path(RECEIPT_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": str(ws18_receipt.get("subject_head_commit", "")).strip(),
        "compiled_head_commit": current_repo_head,
        "evidence_head_commit": str(ws18_receipt.get("evidence_head_commit", "")).strip(),
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "DETACHED_PUBLIC_VERIFIER_PACKAGE_BLOCKED",
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": list(VALIDATORS_RUN),
        "tests_run": list(TESTS_RUN),
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "workstream_id": WORKSTREAM_ID,
        "created_files": list(CREATED_FILES),
        "deleted_files": [],
        "retained_new_files": list(CREATED_FILES),
        "temporary_files_removed": [],
        "superseded_files_removed_or_demoted": [],
        "surface_classifications": dict(SURFACE_CLASSIFICATIONS),
        "input_refs": [
            DEFAULT_WS17_POLICY_REL,
            DEFAULT_WS17_RECEIPT_REL,
            DEFAULT_SOURCE_PROVENANCE_REL,
            DEFAULT_SOURCE_AUTHORITY_BUNDLE_REL,
            DEFAULT_WS18_BUILD_PROVENANCE_REL,
            DEFAULT_WS18_VSA_REL,
            DEFAULT_WS18_RECEIPT_REL,
            DEFAULT_PUBLIC_VERIFIER_MANIFEST_REL,
            DEFAULT_CRYPTO_PUBLICATION_RECEIPT_REL,
            DEFAULT_FINAL_GOVERNANCE_RECEIPT_REL,
            DEFAULT_TUF_ROOT_INITIALIZATION_REL,
            DEFAULT_SIGSTORE_BUNDLE_REL,
            DEFAULT_REKOR_INCLUSION_RECEIPT_REL,
            DETACHED_RUNTIME_TOOL_REL,
            TOOL_REL,
            TEST_REL,
            MANIFEST_REL,
            SBOM_REL,
        ],
        "checks": [
            {"check": "prewrite_workspace_scope_clean", "status": "PASS" if prewrite_scope_clean else "FAIL", "refs": list(WORKSTREAM_FILES_TOUCHED)},
            {"check": "workstream_touches_remain_in_scope", "status": "PASS", "refs": list(WORKSTREAM_FILES_TOUCHED)},
            {"check": "ws17_source_attestation_pass", "status": "PASS" if ws17_ok else "FAIL", "refs": [DEFAULT_WS17_RECEIPT_REL]},
            {"check": "ws18_build_verification_pass", "status": "PASS" if ws18_ok else "FAIL", "refs": [DEFAULT_WS18_RECEIPT_REL]},
            {"check": "detached_release_manifest_signoffs_verified", "status": "PASS" if manifest_signoffs_ok else "FAIL", "refs": [MANIFEST_REL]},
            {"check": "detached_runtime_executes_without_repo_checkout", "status": "PASS" if detached_runtime_ok else "FAIL", "refs": [DETACHED_RUNTIME_RECEIPT_REF]},
            {"check": "detached_runtime_checks_trust_surfaces", "status": "PASS" if detached_checks_ok else "FAIL", "refs": [DETACHED_RUNTIME_RECEIPT_REF]},
            {"check": "detached_vs_repo_local_conclusion_parity", "status": "PASS" if parity_ok else "FAIL", "refs": [DETACHED_RUNTIME_RECEIPT_REF, DETACHED_RUNTIME_REPORT_REF]},
            {"check": "stronger_claims_explicitly_withheld", "status": "PASS" if stronger_claim_ok else "FAIL", "refs": [MANIFEST_REL, DETACHED_RUNTIME_RECEIPT_REF]},
        ],
        "summary": {
            "detached_package_root_ref": str(package_manifest.get("detached_package_root_ref", "")).strip(),
            "detached_runtime_receipt_ref": DETACHED_RUNTIME_RECEIPT_REF,
            "detached_runtime_report_ref": DETACHED_RUNTIME_REPORT_REF,
            "repo_local_current_head_commit": str(repo_local_report.get("current_head_commit", "")).strip(),
            "detached_current_head_commit": str((detached_report or {}).get("current_head_commit", "")).strip() if isinstance(detached_report, dict) else "",
            "repo_local_parity_fields": list(PARITY_FIELDS),
            "publication_surface_boundary": str(package_manifest.get("publication_surface_boundary", "")).strip(),
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        },
        "detached_vs_repo_local_conclusion_parity": parity_rows,
        "supporting_runtime_artifacts": [DETACHED_RUNTIME_RECEIPT_REF, DETACHED_RUNTIME_REPORT_REF],
        "next_lawful_step": {"status_after_workstream": "UNLOCKED" if status == "PASS" else "BLOCKED", "workstream_id": "WS20_INDEPENDENT_EXTERNAL_REPRODUCTION"},
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "packaged the detached public verifier runtime and its bounded trust/provenance/governance inputs",
                "emitted the detached verifier release manifest and SBOM with dual local HMAC release signoffs",
                "ran the verifier outside a repo checkout and compared its conclusion fields to the repo-local verifier output",
            ],
            "files_touched": list(changed),
            "tests_run": list(TESTS_RUN),
            "validators_run": list(VALIDATORS_RUN),
            "issues_found": [],
            "resolution": (
                "WS19 proves that the repo-authored detached verifier package reproduces the repo-local verifier conclusion from packaged trust surfaces only."
                if status == "PASS"
                else "WS19 remains blocked until the detached verifier package resolves trust/provenance/governance inputs and matches the repo-local verifier conclusion."
            ),
            "pass_fail_status": status,
            "unexpected_touches": [],
            "protected_touch_violations": [],
        },
    }
    return {"receipt": receipt}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the detached public verifier package and parity against the repo-local verifier.")
    parser.add_argument("--proof-root", default=DETACHED_PROOF_ROOT_REL)
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    current_repo_head = _git_head(root)
    prewrite_dirty = _dirty_relpaths(root, _git_status_lines(root))
    prewrite_scope_clean = not prewrite_dirty or all(path in WORKSTREAM_FILES_TOUCHED for path in prewrite_dirty)

    ws17_policy = _load_required_json(root, DEFAULT_WS17_POLICY_REL)
    ws17_receipt = _load_required_json(root, DEFAULT_WS17_RECEIPT_REL)
    ws18_receipt = _load_required_json(root, DEFAULT_WS18_RECEIPT_REL)
    trust_roots = _validate_revision_policy_trust_roots(ws17_policy)

    proof_root = (root / Path(str(args.proof_root))).resolve()
    if proof_root.exists():
        shutil.rmtree(proof_root)
    package_root = (proof_root / "package").resolve()
    detached_cwd = (package_root / "KT_PROD_CLEANROOM").resolve()
    (proof_root / "reports").mkdir(parents=True, exist_ok=True)

    source_closure = _local_dependency_closure(root, DETACHED_RUNTIME_TOOL_REL)
    package_components = [_copy_packaged_file(root, package_root, rel) for rel in sorted(set([*source_closure, *PACKAGED_INPUT_REFS]))]
    package_root_sha256 = _package_root_sha256(package_components)
    package_manifest = {
        "schema_id": "kt.operator.public_verifier_detached_release_manifest.v1",
        "artifact_id": Path(MANIFEST_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": str(ws18_receipt.get("subject_head_commit", "")).strip(),
        "compiled_head_commit": current_repo_head,
        "evidence_head_commit": str(ws18_receipt.get("evidence_head_commit", "")).strip(),
        "status": "PASS",
        "detached_package_root_ref": DETACHED_PACKAGE_ROOT_REL,
        "detached_entrypoint": DETACHED_ENTRYPOINT,
        "detached_runtime_receipt_ref": DETACHED_RUNTIME_RECEIPT_REF,
        "detached_runtime_report_ref": DETACHED_RUNTIME_REPORT_REF,
        "publication_surface_boundary": str(ws18_receipt.get("questions", {}).get("provenance_vsa_publication_subject_alignment", {}).get("publication_surface_boundary", "")).strip(),
        "source_dependency_closure": list(source_closure),
        "packaged_input_refs": list(PACKAGED_INPUT_REFS),
        "packaged_file_count": len(package_components),
        "package_root_sha256": package_root_sha256,
        "release_signatures": _build_hmac_signoffs(package_root_sha256, trust_roots),
        "repo_local_parity_fields": list(PARITY_FIELDS),
        "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        "included_paths": [row["path"] for row in package_components],
    }
    package_sbom = {
        "schema_id": "kt.operator.public_verifier_detached_sbom.v1",
        "artifact_id": Path(SBOM_REL).name,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": str(ws18_receipt.get("subject_head_commit", "")).strip(),
        "compiled_head_commit": current_repo_head,
        "detached_package_root_ref": DETACHED_PACKAGE_ROOT_REL,
        "package_root_sha256": package_root_sha256,
        "component_count": len(package_components),
        "third_party_component_count": 0,
        "components": [
            {"component_type": _package_component_role(row["path"])[0], "role": _package_component_role(row["path"])[1], "path": row["path"], "sha256": row["sha256"]}
            for row in package_components
        ],
    }
    write_json_stable((root / Path(MANIFEST_REL)).resolve(), package_manifest, volatile_keys=VOLATILE_JSON_KEYS)
    write_json_stable((root / Path(SBOM_REL)).resolve(), package_sbom, volatile_keys=VOLATILE_JSON_KEYS)

    detached_report_path = (proof_root / "reports" / "detached_public_verifier_report.json").resolve()
    detached_runtime_receipt_path = (proof_root / "reports" / "detached_runtime_receipt.json").resolve()
    detached_env = dict(os.environ)
    detached_env.pop("PYTHONPATH", None)
    detached_env.pop("GIT_DIR", None)
    detached_env.pop("GIT_WORK_TREE", None)
    detached_env["GIT_CEILING_DIRECTORIES"] = str(package_root)
    result = subprocess.run(
        [sys.executable, "-m", "tools.operator.public_verifier_detached_runtime", "--report-output", str(detached_report_path), "--receipt-output", str(detached_runtime_receipt_path)],
        cwd=str(detached_cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=detached_env,
        check=False,
    )
    if not detached_runtime_receipt_path.exists():
        raise RuntimeError(f"FAIL_CLOSED: detached verifier did not emit a runtime receipt\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")

    detached_runtime_receipt = load_json(detached_runtime_receipt_path)
    repo_local_report = build_public_verifier_report(root=root)
    changed_before_receipt = _dirty_relpaths(root, _git_status_lines(root))
    outputs = build_detached_public_verifier_outputs_from_artifacts(
        current_repo_head=current_repo_head,
        ws17_receipt=ws17_receipt,
        ws18_receipt=ws18_receipt,
        package_manifest=package_manifest,
        detached_runtime_receipt=detached_runtime_receipt,
        repo_local_report=repo_local_report,
        changed_files=[*changed_before_receipt, RECEIPT_REL],
        prewrite_scope_clean=prewrite_scope_clean,
    )
    write_json_stable((root / Path(RECEIPT_REL)).resolve(), outputs["receipt"], volatile_keys=VOLATILE_JSON_KEYS)

    print(
        json.dumps(
            {
                "artifact_id": outputs["receipt"]["artifact_id"],
                "status": outputs["receipt"]["status"],
                "pass_verdict": outputs["receipt"]["pass_verdict"],
                "subject_head_commit": outputs["receipt"]["subject_head_commit"],
                "supporting_runtime_artifacts": outputs["receipt"]["supporting_runtime_artifacts"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if outputs["receipt"]["status"] == "PASS" and result.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
