from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


WORKSTREAM_ID = "WS17A_EXTERNAL_CONFIRMATION_ASSURANCE"
STEP_ID = "WS17A_STEP_1_PROVE_SECRET_FREE_OUTSIDER_ASSURANCE_REPLAY"
PASS_VERDICT = "SECRET_FREE_OUTSIDER_ASSURANCE_REPLAY_PROVEN"
BLOCKED_VERDICT = "SECRET_FREE_OUTSIDER_ASSURANCE_REPLAY_NOT_PROVEN"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GOVERNANCE_ROOT_REL = "KT_PROD_CLEANROOM/governance"
TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/ws17a_external_assurance_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_ws17a_external_assurance_validate.py"

EXECUTION_DAG_REL = f"{GOVERNANCE_ROOT_REL}/kt_execution_dag.json"
WS14_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_release_receipt.json"
WS16_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_tevv_dataset_registry_receipt.json"
ACCEPTANCE_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_public_verifier_acceptance_policy.json"
DISTRIBUTION_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_public_verifier_distribution_policy.json"
STATIC_RELEASE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_static_verifier_release_manifest.json"
STATIC_VERIFIER_ATTESTATION_REL = f"{REPORT_ROOT_REL}/kt_static_verifier_attestation.json"
SIGNED_SURFACE_REL = f"{REPORT_ROOT_REL}/ws13_determinism/ci/public_verifier_manifest.json"
SIGSTORE_BUNDLE_REL = f"{REPORT_ROOT_REL}/ws13_determinism/ci/public_verifier_manifest.sigstore.json"
KEYLESS_RECEIPT_REL = f"{REPORT_ROOT_REL}/ws13_determinism/ci/kt_ws11_keyless_execution_receipt.json"
REMOTE_DIAGNOSTIC_REL = f"{REPORT_ROOT_REL}/ws13_determinism/ci/kt_truth_barrier_remote_diagnostic.json"
IMPORT_MANIFEST_REL = f"{REPORT_ROOT_REL}/ws17a_assurance/kt_external_assurance_import_manifest.json"
REPLAY_REPORT_REL = f"{REPORT_ROOT_REL}/ws17a_assurance/kt_outsider_assurance_replay_report.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_external_assurance_confirmation_receipt.json"

EXPECTED_KEYLESS_SURFACE = "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json"
EXPECTED_KEYLESS_SIGNER_ID = "KT_CI_TRUTH_BARRIER_KEYLESS_MAIN"
NEXT_WORKSTREAM_ON_PASS = "WS17B_EXTERNAL_CONFIRMATION_CAPABILITY"

REQUIRED_PUBLIC_REFS = [
    ACCEPTANCE_POLICY_REL,
    DISTRIBUTION_POLICY_REL,
    STATIC_RELEASE_MANIFEST_REL,
    STATIC_VERIFIER_ATTESTATION_REL,
    WS14_RECEIPT_REL,
    WS16_RECEIPT_REL,
    SIGNED_SURFACE_REL,
    SIGSTORE_BUNDLE_REL,
    KEYLESS_RECEIPT_REL,
    REMOTE_DIAGNOSTIC_REL,
]
PLANNED_MUTATES = [
    TOOL_REL,
    TEST_REL,
    IMPORT_MANIFEST_REL,
    REPLAY_REPORT_REL,
    RECEIPT_REL,
    EXECUTION_DAG_REL,
]
SECRET_ENV_PREFIXES = ("KT_HMAC_KEY_",)
FORBIDDEN_SECRET_TERMS = ("hmac", "private key", "private_key", "secret", "env-secret")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


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
    rels: List[str] = []
    for line in status_lines:
        rel = line[3:].strip()
        if rel:
            rels.append(Path(rel).as_posix())
    return sorted(set(rels))


def _path_in_scope(path: str) -> bool:
    normalized = Path(path).as_posix()
    planned = {Path(item).as_posix() for item in PLANNED_MUTATES}
    return normalized in planned or any(
        normalized.startswith(f"{item}/") or item.startswith(f"{normalized}/") for item in planned
    )


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS17A input: {rel}")
    return _read_json(path)


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check(
    ok: bool,
    check_id: str,
    detail: str,
    refs: Sequence[str],
    failures: Optional[Sequence[str]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "check": check_id,
        "status": "PASS" if ok else "FAIL",
        "detail": detail,
        "refs": [Path(ref).as_posix() for ref in refs],
    }
    if failures:
        row["failures"] = [str(item) for item in failures]
    row.update(extra)
    return row


def _copy_public_inputs(root: Path, package_root: Path) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    for rel in REQUIRED_PUBLIC_REFS + [TOOL_REL]:
        source = (root / Path(rel)).resolve()
        if not source.exists():
            raise RuntimeError(f"FAIL_CLOSED: package input missing: {rel}")
        target = (package_root / Path(rel)).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        hashes[Path(rel).as_posix()] = _file_sha256(source)
    return hashes


def _detached_env() -> Tuple[Dict[str, str], List[str]]:
    env = dict(os.environ)
    removed: List[str] = []
    for key in list(env):
        if key in {"PYTHONPATH", "GIT_DIR", "GIT_WORK_TREE"} or any(key.startswith(prefix) for prefix in SECRET_ENV_PREFIXES):
            env.pop(key, None)
            removed.append(key)
    return env, sorted(set(removed))


def _expected_identity_fields(acceptance_policy: Dict[str, Any]) -> Tuple[str, str]:
    accepted = acceptance_policy.get("accepted_signature_trust_roots")
    if not isinstance(accepted, list):
        return "", ""
    for row in accepted:
        if isinstance(row, dict) and str(row.get("mode", "")).strip() == "sigstore_keyless":
            return str(row.get("certificate_identity", "")).strip(), str(row.get("certificate_oidc_issuer", "")).strip()
    return "", ""


def _run_detached_replay(package_root: Path, report_output: Path) -> Tuple[Dict[str, Any], Dict[str, str], List[str], str, str]:
    env, removed_env_keys = _detached_env()
    command = [
        sys.executable,
        str((package_root / Path(TOOL_REL)).resolve()),
        "--detached-package-root",
        str(package_root.resolve()),
        "--report-output",
        str(report_output.resolve()),
    ]
    result = subprocess.run(
        command,
        cwd=str(package_root.resolve()),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=False,
    )
    if not report_output.exists():
        raise RuntimeError(
            "FAIL_CLOSED: detached outsider assurance replay did not emit a report\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    report = _read_json(report_output)
    package_hashes = {Path(rel).as_posix(): _file_sha256((package_root / Path(rel)).resolve()) for rel in REQUIRED_PUBLIC_REFS}
    return report, package_hashes, removed_env_keys, result.stdout, result.stderr


def validate_detached_package(package_root: Path) -> Dict[str, Any]:
    acceptance_policy = _load_required_json(package_root, ACCEPTANCE_POLICY_REL)
    distribution_policy = _load_required_json(package_root, DISTRIBUTION_POLICY_REL)
    static_release_manifest = _load_required_json(package_root, STATIC_RELEASE_MANIFEST_REL)
    static_attestation = _load_required_json(package_root, STATIC_VERIFIER_ATTESTATION_REL)
    ws14_receipt = _load_required_json(package_root, WS14_RECEIPT_REL)
    ws16_receipt = _load_required_json(package_root, WS16_RECEIPT_REL)
    keyless_receipt = _load_required_json(package_root, KEYLESS_RECEIPT_REL)
    remote_diagnostic = _load_required_json(package_root, REMOTE_DIAGNOSTIC_REL)
    signed_surface_path = (package_root / Path(SIGNED_SURFACE_REL)).resolve()
    sigstore_bundle_path = (package_root / Path(SIGSTORE_BUNDLE_REL)).resolve()
    package_git_dir = (package_root / ".git").exists()
    expected_identity, expected_issuer = _expected_identity_fields(acceptance_policy)
    signed_surface_sha = _file_sha256(signed_surface_path)
    bundle_sha = _file_sha256(sigstore_bundle_path)
    ws16_dataset_hashes = ws16_receipt.get("dataset_hashes") if isinstance(ws16_receipt.get("dataset_hashes"), dict) else {}
    allowed_public_refs = acceptance_policy.get("private_secret_dependency_rules", {}).get("allowed_public_material_refs")
    release_surface = static_release_manifest.get("accepted_current_head_surface") if isinstance(static_release_manifest.get("accepted_current_head_surface"), dict) else {}

    checks: List[Dict[str, Any]] = []
    blockers: List[str] = []

    required_present = all((package_root / Path(rel)).exists() for rel in REQUIRED_PUBLIC_REFS)
    checks.append(
        _check(
            required_present,
            "required_public_inputs_present",
            "Detached outsider assurance replay requires the WS14/WS16 public policy and bounded current-surface evidence package only.",
            REQUIRED_PUBLIC_REFS,
        )
    )
    if not required_present:
        blockers.append("REQUIRED_PUBLIC_INPUTS_MISSING")

    acceptance_ok = (
        str(acceptance_policy.get("status", "")).strip() == "ACTIVE"
        and str(acceptance_policy.get("schema_id", "")).strip() == "kt.governance.public_verifier_acceptance_policy.v1"
        and str(acceptance_policy.get("private_secret_dependency_rules", {}).get("rule", "")).strip()
        == "Declared verifier release surfaces must be verifiable from packaged public material only."
    )
    checks.append(
        _check(
            acceptance_ok,
            "acceptance_policy_declares_secret_free_public_verification",
            "The active acceptance policy must declare a public-material-only verifier path with no hidden secret dependency.",
            [ACCEPTANCE_POLICY_REL],
        )
    )
    if not acceptance_ok:
        blockers.append("ACCEPTANCE_POLICY_NOT_SECRET_FREE")

    distribution_ok = (
        str(distribution_policy.get("status", "")).strip() == "ACTIVE"
        and bool(distribution_policy.get("no_private_secret_dependency")) is True
        and bool(distribution_policy.get("offline_verification_capable")) is True
        and "secret_backed_remote_verification" in list(distribution_policy.get("forbidden_distribution_channels", []))
    )
    checks.append(
        _check(
            distribution_ok,
            "distribution_policy_secret_free_and_offline_capable",
            "The distribution policy must keep outsider verification offline-capable and explicitly forbid secret-backed verification.",
            [DISTRIBUTION_POLICY_REL],
        )
    )
    if not distribution_ok:
        blockers.append("DISTRIBUTION_POLICY_NOT_SECRET_FREE")

    schema_ok = (
        str(ws14_receipt.get("status", "")).strip() == "PASS"
        and str(ws16_receipt.get("status", "")).strip() == "PASS"
        and str(keyless_receipt.get("schema_id", "")).strip() == "kt.operator.ws11_keyless_execution_receipt.v1"
        and str(remote_diagnostic.get("schema_id", "")).strip() == "kt.operator.truth_barrier_remote_diagnostic.v1"
    )
    checks.append(
        _check(
            schema_ok,
            "upstream_receipts_and_imported_evidence_schema_valid",
            "WS17A must bind only to schema-valid, PASS upstream receipts and imported assurance evidence.",
            [WS14_RECEIPT_REL, WS16_RECEIPT_REL, KEYLESS_RECEIPT_REL, REMOTE_DIAGNOSTIC_REL],
        )
    )
    if not schema_ok:
        blockers.append("SCHEMA_OR_UPSTREAM_PASS_INVALID")

    secret_ref_failures = [
        ref for ref in (allowed_public_refs or [])
        if any(term in str(ref).lower() for term in FORBIDDEN_SECRET_TERMS)
    ]
    secret_ref_ok = isinstance(allowed_public_refs, list) and not secret_ref_failures
    checks.append(
        _check(
            secret_ref_ok,
            "allowed_public_refs_contain_no_secret_material",
            "Allowed public verification refs must not contain secret or HMAC-backed material.",
            [ACCEPTANCE_POLICY_REL],
            failures=secret_ref_failures,
        )
    )
    if not secret_ref_ok:
        blockers.append("PUBLIC_REFS_INCLUDE_SECRET_MATERIAL")

    keyless_ok = (
        str(keyless_receipt.get("status", "")).strip() == "PASS"
        and str(keyless_receipt.get("verification_status", "")).strip() == "PASS"
        and str(keyless_receipt.get("executed_signer_mode", "")).strip() == "sigstore_keyless"
        and str(keyless_receipt.get("executed_signer_id", "")).strip() in {"", EXPECTED_KEYLESS_SIGNER_ID}
        and str(keyless_receipt.get("certificate_identity", "")).strip() == expected_identity
        and str(keyless_receipt.get("certificate_oidc_issuer", "")).strip() == expected_issuer
        and str(keyless_receipt.get("signed_surface_path", "")).strip() == EXPECTED_KEYLESS_SURFACE
        and str(keyless_receipt.get("signed_surface_sha256", "")).strip().lower() == signed_surface_sha.lower()
        and str(keyless_receipt.get("bundle_sha256", "")).strip().lower() == bundle_sha.lower()
        and EXPECTED_KEYLESS_SURFACE in list(keyless_receipt.get("keyless_backed_surfaces", []))
    )
    checks.append(
        _check(
            keyless_ok,
            "keyless_receipt_matches_bounded_signed_surface_and_identity",
            "The bounded keyless receipt must match the declared signer identity, issuer, signed surface, and imported Sigstore bundle.",
            [KEYLESS_RECEIPT_REL, SIGNED_SURFACE_REL, SIGSTORE_BUNDLE_REL, ACCEPTANCE_POLICY_REL],
            signed_surface_sha256=signed_surface_sha,
            bundle_sha256=bundle_sha,
        )
    )
    if not keyless_ok:
        blockers.append("BOUNDED_KEYLESS_SURFACE_BINDING_NOT_PROVEN")

    diagnostic_ok = (
        str(remote_diagnostic.get("status", "")).strip() == "PASS"
        and str(remote_diagnostic.get("truth_barrier_step_outcome", "")).strip() == "success"
        and str(remote_diagnostic.get("run_id", "")).strip() == str(keyless_receipt.get("run_id", "")).strip()
    )
    checks.append(
        _check(
            diagnostic_ok,
            "remote_truth_barrier_diagnostic_matches_keyless_run",
            "The imported CI truth-barrier diagnostic must remain PASS and agree with the keyless run id.",
            [REMOTE_DIAGNOSTIC_REL, KEYLESS_RECEIPT_REL],
            run_id=str(keyless_receipt.get("run_id", "")).strip(),
        )
    )
    if not diagnostic_ok:
        blockers.append("REMOTE_DIAGNOSTIC_MISMATCH")

    carry_forward_subject = str(ws16_receipt.get("tevv_subject_head_commit", "")).strip()
    carry_forward_ok = (
        carry_forward_subject
        and str(ws14_receipt.get("compiled_against", "")).strip() == carry_forward_subject
        and str(acceptance_policy.get("ws13_subject_head_commit", "")).strip() == carry_forward_subject
        and str(static_release_manifest.get("ws13_subject_head_commit", "")).strip() == carry_forward_subject
        and str(static_attestation.get("current_repo_head", "")).strip() == carry_forward_subject
    )
    checks.append(
        _check(
            carry_forward_ok,
            "carried_forward_subject_head_stable_across_ws14_ws16_and_release_package",
            "The outsider assurance replay must remain bound to the same bounded verifier subject carried forward through WS14 and WS16.",
            [WS14_RECEIPT_REL, WS16_RECEIPT_REL, ACCEPTANCE_POLICY_REL, STATIC_RELEASE_MANIFEST_REL, STATIC_VERIFIER_ATTESTATION_REL],
            subject_head_commit=carry_forward_subject,
        )
    )
    if not carry_forward_ok:
        blockers.append("CARRIED_FORWARD_SUBJECT_HEAD_MISMATCH")

    pin_ok = (
        str(ws16_dataset_hashes.get(SIGNED_SURFACE_REL, "")).strip().lower() == signed_surface_sha.lower()
        and str(ws16_dataset_hashes.get(SIGSTORE_BUNDLE_REL, "")).strip().lower() == bundle_sha.lower()
    )
    checks.append(
        _check(
            pin_ok,
            "ws16_dataset_pins_match_detached_public_package",
            "The detached public package must still match the WS16 pinned bounded signed surface and Sigstore bundle hashes.",
            [WS16_RECEIPT_REL, SIGNED_SURFACE_REL, SIGSTORE_BUNDLE_REL],
        )
    )
    if not pin_ok:
        blockers.append("DETACHED_PACKAGE_HASH_NOT_PINNED_BY_WS16")

    release_manifest_ok = (
        str(static_release_manifest.get("status", "")).strip() == "PASS"
        and str(static_release_manifest.get("acceptance_policy_ref", "")).strip() == ACCEPTANCE_POLICY_REL
        and str(static_release_manifest.get("distribution_policy_ref", "")).strip() == DISTRIBUTION_POLICY_REL
        and str(release_surface.get("signed_surface_import_ref", "")).strip() == SIGNED_SURFACE_REL
        and str(release_surface.get("signed_surface_sha256", "")).strip().lower() == signed_surface_sha.lower()
        and str(release_surface.get("keyless_bundle_ref", "")).strip() == SIGSTORE_BUNDLE_REL
        and str(release_surface.get("keyless_bundle_sha256", "")).strip().lower() == bundle_sha.lower()
        and str(release_surface.get("keyless_execution_receipt_ref", "")).strip() == KEYLESS_RECEIPT_REL
        and str(release_surface.get("truth_barrier_diagnostic_ref", "")).strip() == REMOTE_DIAGNOSTIC_REL
        and str(release_surface.get("keyless_execution_run_id", "")).strip() == str(keyless_receipt.get("run_id", "")).strip()
    )
    checks.append(
        _check(
            release_manifest_ok,
            "static_release_manifest_matches_bounded_assurance_surface",
            "The static verifier release manifest must package the exact bounded current surface accepted by WS14 and pinned by WS16.",
            [STATIC_RELEASE_MANIFEST_REL, SIGNED_SURFACE_REL, SIGSTORE_BUNDLE_REL, KEYLESS_RECEIPT_REL, REMOTE_DIAGNOSTIC_REL],
        )
    )
    if not release_manifest_ok:
        blockers.append("STATIC_RELEASE_MANIFEST_BOUNDARY_MISMATCH")

    detached_ok = not package_git_dir
    checks.append(
        _check(
            detached_ok,
            "detached_package_has_no_repo_checkout",
            "Outsider assurance replay must run from a detached package without a git checkout.",
            [TOOL_REL],
            detached_package_root=str(package_root.resolve()),
        )
    )
    if not detached_ok:
        blockers.append("DETACHED_PACKAGE_CONTAINS_GIT_CHECKOUT")

    status = "PASS" if not blockers else "BLOCKED"
    return {
        "schema_id": "kt.operator.ws17a.outsider_assurance_replay_report.v1",
        "artifact_id": "kt_outsider_assurance_replay_report.json",
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else BLOCKED_VERDICT,
        "assurance_confirmation_mode": "OUTSIDER_VERIFIABLE_SECRET_FREE_DETACHED_REPLAY",
        "assurance_scope": "ASSURANCE_ONLY_NOT_CAPABILITY",
        "independent_third_party_confirmation": False,
        "outsider_verifiable": True,
        "bounded_current_surface": SIGNED_SURFACE_REL,
        "bounded_current_surface_sha256": signed_surface_sha,
        "sigstore_bundle_ref": SIGSTORE_BUNDLE_REL,
        "sigstore_bundle_sha256": bundle_sha,
        "bounded_subject_head_commit": carry_forward_subject,
        "run_id": str(keyless_receipt.get("run_id", "")).strip(),
        "certificate_identity": expected_identity,
        "certificate_oidc_issuer": expected_issuer,
        "repo_checkout_present": package_git_dir,
        "detached_package_root": str(package_root.resolve()),
        "checks": checks,
        "blocked_by": blockers,
        "limitations": [
            "WS17A proves a secret-free outsider-verifiable assurance replay only; it does not prove external capability confirmation.",
            "WS17A does not widen verifier coverage beyond the bounded imported current surface.",
            "WS17A does not activate threshold-root verifier acceptance, release readiness, or campaign completion.",
            "WS17A does not erase the repo-root import fragility."
        ],
        "stronger_claim_not_made": [
            "An independent third-party capability evaluation has been completed.",
            "Verifier coverage is broader than the bounded imported public_verifier_manifest surface.",
            "Release readiness or campaign completion is proven."
        ],
    }


def emit_ws17a_external_assurance(*, root: Optional[Path] = None) -> Dict[str, Any]:
    repo = root or _repo_root()
    pre_status = _git_status_lines(repo)
    pre_dirty = _dirty_relpaths(pre_status)
    if pre_dirty:
        out_of_scope = [path for path in pre_dirty if not _path_in_scope(path)]
        if out_of_scope:
            raise RuntimeError(f"FAIL_CLOSED: WS17A prewrite workspace not clean: {out_of_scope}")

    current_head = _git_head(repo)
    dag = _load_required_json(repo, EXECUTION_DAG_REL)
    ws14_receipt = _load_required_json(repo, WS14_RECEIPT_REL)
    ws16_receipt = _load_required_json(repo, WS16_RECEIPT_REL)
    acceptance_policy = _load_required_json(repo, ACCEPTANCE_POLICY_REL)
    distribution_policy = _load_required_json(repo, DISTRIBUTION_POLICY_REL)
    static_release_manifest = _load_required_json(repo, STATIC_RELEASE_MANIFEST_REL)
    ws17a_lawful_before_mutation = (
        str(dag.get("current_node", "")).strip() == WORKSTREAM_ID
        or any(isinstance(node, dict) and node.get("id") == WORKSTREAM_ID and str(node.get("status", "")).strip() in {"UNLOCKED", "PASS"} for node in dag.get("nodes", []))
        or
        str(dag.get("next_lawful_workstream", "")).strip() == WORKSTREAM_ID
    )

    temp_root = Path(tempfile.mkdtemp(prefix="kt_ws17a_assurance_")).resolve()
    package_root = temp_root / "package"
    package_hashes = _copy_public_inputs(repo, package_root)
    detached_report_output = package_root / Path(REPLAY_REPORT_REL)
    detached_report, detached_hashes, removed_env_keys, detached_stdout, detached_stderr = _run_detached_replay(package_root, detached_report_output)

    import_manifest = {
        "schema_id": "kt.operator.ws17a.external_assurance_import_manifest.v1",
        "artifact_id": "kt_external_assurance_import_manifest.json",
        "status": detached_report["status"],
        "compiled_against": current_head,
        "assurance_subject_head_commit": str(ws16_receipt.get("tevv_subject_head_commit", "")).strip(),
        "assurance_confirmation_mode": "OUTSIDER_VERIFIABLE_SECRET_FREE_DETACHED_REPLAY",
        "detached_package_ephemeral": True,
        "detached_package_root": str(package_root),
        "repo_checkout_present_in_detached_package": False,
        "removed_secret_env_keys": removed_env_keys,
        "imported_public_refs": {
            rel: {
                "source_sha256": package_hashes[rel],
                "detached_copy_sha256": detached_hashes[rel],
            }
            for rel in REQUIRED_PUBLIC_REFS
        },
        "detached_replay_report_sha256": _file_sha256(detached_report_output),
        "detached_replay_stdout": detached_stdout.strip(),
        "detached_replay_stderr": detached_stderr.strip(),
        "stronger_claim_not_made": [
            "The detached replay constitutes capability confirmation.",
            "The detached replay widens verifier coverage beyond the bounded public_verifier_manifest surface."
        ],
    }
    _write_json((repo / Path(IMPORT_MANIFEST_REL)).resolve(), import_manifest)
    _write_json((repo / Path(REPLAY_REPORT_REL)).resolve(), detached_report)

    blocked_by = list(detached_report.get("blocked_by", []))
    checks = [
        _check(
            str(ws14_receipt.get("status", "")).strip() == "PASS",
            "ws14_release_receipt_pass",
            "WS17A depends on the bounded WS14 static verifier release and acceptance policy lock.",
            [WS14_RECEIPT_REL],
        ),
        _check(
            str(ws16_receipt.get("status", "")).strip() == "PASS",
            "ws16_tevv_receipt_pass",
            "WS17A depends on the WS16 pinned TEVV pack and replayability rules remaining PASS.",
            [WS16_RECEIPT_REL],
        ),
        _check(
            ws17a_lawful_before_mutation,
            "ws17a_is_current_lawful_workstream",
            "WS17A may proceed only after the frozen WS16 boundary unlocks the assurance lane.",
            [EXECUTION_DAG_REL],
        ),
        _check(
            str(acceptance_policy.get("status", "")).strip() == "ACTIVE"
            and str(distribution_policy.get("status", "")).strip() == "ACTIVE"
            and str(static_release_manifest.get("status", "")).strip() == "PASS",
            "current_public_verifier_release_package_active",
            "WS17A reuses the active WS14 static verifier release and public acceptance/distribution policy surfaces.",
            [ACCEPTANCE_POLICY_REL, DISTRIBUTION_POLICY_REL, STATIC_RELEASE_MANIFEST_REL],
        ),
        _check(
            str(detached_report.get("status", "")).strip() == "PASS",
            "detached_outsider_assurance_replay_pass",
            "At least one outsider-verifiable assurance replay must succeed on a detached public package with no repo checkout or private secrets.",
            [REPLAY_REPORT_REL, IMPORT_MANIFEST_REL],
            failures=blocked_by,
        ),
    ]

    status = "PASS" if not blocked_by else "BLOCKED"
    next_lawful = NEXT_WORKSTREAM_ON_PASS if status == "PASS" else WORKSTREAM_ID
    current_claim = (
        "WS17A proves one secret-free outsider-verifiable assurance replay for the bounded imported current public_verifier_manifest surface only. "
        "It does not prove external capability confirmation, broader verifier coverage, threshold-root acceptance, release readiness, or campaign completion."
    )

    ws17a_node = next(node for node in dag["nodes"] if node["id"] == WORKSTREAM_ID)
    ws17b_node = next(node for node in dag["nodes"] if node["id"] == NEXT_WORKSTREAM_ON_PASS)
    ws18_node = next(node for node in dag["nodes"] if node["id"] == "WS18_RELEASE_CEREMONY_AND_FINAL_READJUDICATION")
    ws17a_node["status"] = status
    ws17a_node["ratification_checkpoint"] = Path(RECEIPT_REL).name
    ws17a_node["claim_boundary"] = (
        "WS17A PASS proves only a secret-free outsider-verifiable assurance replay of the bounded imported public_verifier_manifest surface; "
        "it is assurance-only and does not overread into capability, verifier widening, release readiness, or campaign completion."
    )
    ws17b_node["status"] = "UNLOCKED"
    ws18_node["status"] = "LOCKED_PENDING_WS17B_PASS" if status == "PASS" else "LOCKED_PENDING_WS17_PASS"
    dag["current_node"] = WORKSTREAM_ID
    dag["current_repo_head"] = current_head
    dag["next_lawful_workstream"] = next_lawful
    semantic = dag.get("semantic_boundary") if isinstance(dag.get("semantic_boundary"), dict) else {}
    semantic["lawful_current_claim"] = current_claim if status == "PASS" else str(semantic.get("lawful_current_claim", "")).strip()
    stronger = list(semantic.get("stronger_claim_not_made", [])) if isinstance(semantic.get("stronger_claim_not_made"), list) else []
    for item in [
        "WS17A constitutes capability confirmation.",
        "Verifier coverage is broader than the bounded imported public_verifier_manifest surface.",
        "Release readiness is proven.",
        "Campaign completion is proven.",
    ]:
        if item not in stronger:
            stronger.append(item)
    semantic["stronger_claim_not_made"] = list(dict.fromkeys(stronger))
    dag["semantic_boundary"] = semantic
    _write_json((repo / Path(EXECUTION_DAG_REL)).resolve(), dag)

    post_status = _git_status_lines(repo)
    unexpected_touches = [path for path in _dirty_relpaths(post_status) if not _path_in_scope(path)]
    if unexpected_touches:
        raise RuntimeError(f"FAIL_CLOSED: WS17A touched out-of-scope paths: {unexpected_touches}")

    receipt = {
        "schema_id": "kt.operator.ws17a.external_assurance_confirmation_receipt.v1",
        "artifact_id": "kt_external_assurance_confirmation_receipt.json",
        "workstream_id": WORKSTREAM_ID,
        "step_id": STEP_ID,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else BLOCKED_VERDICT,
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "bounded_assurance_subject_head_commit": str(ws16_receipt.get("tevv_subject_head_commit", "")).strip(),
        "bounded_assurance_surface": SIGNED_SURFACE_REL,
        "bounded_assurance_surface_sha256": detached_report["bounded_current_surface_sha256"],
        "sigstore_bundle_ref": SIGSTORE_BUNDLE_REL,
        "sigstore_bundle_sha256": detached_report["sigstore_bundle_sha256"],
        "assurance_confirmation_mode": "OUTSIDER_VERIFIABLE_SECRET_FREE_DETACHED_REPLAY",
        "assurance_only_not_capability": True,
        "independent_third_party_confirmation": False,
        "outsider_verifiable": True,
        "checks": checks,
        "blocked_by": blocked_by,
        "imported_evidence": {
            "import_manifest_ref": IMPORT_MANIFEST_REL,
            "outsider_replay_report_ref": REPLAY_REPORT_REL,
            "imported_hashes": {
                IMPORT_MANIFEST_REL: _file_sha256((repo / Path(IMPORT_MANIFEST_REL)).resolve()),
                REPLAY_REPORT_REL: _file_sha256((repo / Path(REPLAY_REPORT_REL)).resolve()),
            },
        },
        "limitations": [
            "WS17A proves outsider-verifiable assurance only, not external capability confirmation.",
            "WS17A remains bounded to the imported public_verifier_manifest current surface already accepted in WS14 and pinned in WS16.",
            "WS17A does not widen verifier coverage, activate threshold-root acceptance, prove release readiness, or prove campaign completion.",
            "The repo-root import fragility remains visible and unfixed."
        ],
        "next_lawful_workstream": next_lawful,
        "stronger_claim_not_made": [
            "WS17A constitutes external capability confirmation.",
            "WS17A widens verifier coverage beyond the bounded imported public_verifier_manifest surface.",
            "WS17A proves release readiness or campaign completion."
        ],
        "validators_run": ["python -m tools.operator.ws17a_external_assurance_validate"],
        "tests_run": ["python -m pytest -q tests/operator/test_ws17a_external_assurance_validate.py"],
        "unexpected_touches": [],
        "protected_touch_violations": [],
    }
    _write_json((repo / Path(RECEIPT_REL)).resolve(), receipt)
    return receipt


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="WS17A outsider-verifiable assurance replay validator")
    parser.add_argument("--detached-package-root", help="Run only the detached outsider replay against a public package root")
    parser.add_argument("--report-output", help="Path to the detached replay report JSON")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.detached_package_root:
        package_root = Path(args.detached_package_root).resolve()
        report_output = Path(args.report_output).resolve() if args.report_output else (package_root / Path(REPLAY_REPORT_REL)).resolve()
        report = validate_detached_package(package_root)
        _write_json(report_output, report)
        return 0 if report["status"] == "PASS" else 1

    receipt = emit_ws17a_external_assurance(root=_repo_root())
    print(json.dumps({"status": receipt["status"], "next_lawful_workstream": receipt["next_lawful_workstream"]}, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
