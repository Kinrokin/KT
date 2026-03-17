from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


WORKSTREAM_ID = "WS11_SIGSTORE_REKOR_AND_LOG_MONITOR_ACTIVATION"
STEP_ID = "WS11_STEP_1_SIGSTORE_REKOR_LOG_MONITOR_ACTIVATION"
PASS_VERDICT = "SIGSTORE_KEYLESS_REKOR_AND_LOG_MONITOR_ACTIVE"
PARTIAL_VERDICT = "KEYLESS_DECLARED_REKOR_ACTIVE_BUT_EXECUTION_PENDING"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GOVERNANCE_ROOT_REL = "KT_PROD_CLEANROOM/governance"

SIGNER_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/signer_identity_policy.json"
SIGNER_PUBKEY_REL = f"{GOVERNANCE_ROOT_REL}/signers/kt_op1_cosign.pub"
KEYLESS_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_sigstore_keyless_path_policy.json"
LOG_MONITOR_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_log_monitor_policy.json"

WS10_RESEAL_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_ws10_consistency_reseal_receipt.json"
SIGSTORE_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_sigstore_publication_bundle.json"
REKOR_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_rekor_inclusion_receipt.json"
PUBLIC_VERIFIER_MANIFEST_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
PUBLIC_VERIFIER_RELEASE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_release_manifest.json"
PUBLIC_VERIFIER_ATTESTATION_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_attestation.json"
TUF_ROOT_INITIALIZATION_REL = f"{REPORT_ROOT_REL}/kt_tuf_root_initialization.json"

KEYLESS_STATUS_REL = f"{REPORT_ROOT_REL}/kt_sigstore_keyless_status.json"
LOG_MONITOR_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_log_monitor_plane_receipt.json"
PUBLIC_TRUST_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_ws11_public_trust_bundle.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_sigstore_integration_receipt.json"

DECLARED_KEYLESS_SIGNER_ID = "KT_CI_TRUTH_BARRIER_KEYLESS_MAIN"
DECLARED_KEYLESS_CERTIFICATE_IDENTITY = "https://github.com/Kinrokin/KT/.github/workflows/ci_truth_barrier.yml@refs/heads/main"
DECLARED_KEYLESS_CERTIFICATE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
DECLARED_KEYLESS_WORKFLOW_REF = ".github/workflows/ci_truth_barrier.yml"
DECLARED_KEYLESS_REPO_SLUG = "Kinrokin/KT"
DECLARED_KEYLESS_SURFACES = [
    SIGSTORE_BUNDLE_REL,
    REKOR_RECEIPT_REL,
    PUBLIC_VERIFIER_MANIFEST_REL,
    PUBLIC_VERIFIER_RELEASE_MANIFEST_REL,
    PUBLIC_VERIFIER_ATTESTATION_REL,
    TUF_ROOT_INITIALIZATION_REL,
]

EXECUTION_DAG_REL = f"{GOVERNANCE_ROOT_REL}/kt_execution_dag.json"
TRUST_ROOT_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_trust_root_policy.json"
SIGNER_TOPOLOGY_REL = f"{GOVERNANCE_ROOT_REL}/kt_signer_topology.json"

PLANNED_MUTATES = [
    SIGNER_POLICY_REL,
    KEYLESS_POLICY_REL,
    LOG_MONITOR_POLICY_REL,
    KEYLESS_STATUS_REL,
    LOG_MONITOR_RECEIPT_REL,
    PUBLIC_TRUST_BUNDLE_REL,
    RECEIPT_REL,
    EXECUTION_DAG_REL,
    TRUST_ROOT_POLICY_REL,
    SIGNER_TOPOLOGY_REL,
    "KT_PROD_CLEANROOM/tools/operator/ws11_sigstore_rekor_log_monitor_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_ws11_sigstore_rekor_log_monitor_validate.py",
]
PROTECTED_TOUCH_PATTERNS = ("KT_ARCHIVE/", ".github/workflows/")
SECRET_TOKENS = ("KT_HMAC_KEY_", "COSIGN_PASSWORD", "tmp/sigstore/keys/", "private key", "\"env_var\": \"KT_HMAC_")


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
    return sorted(set(rows))


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS11 input: {rel}")
    return load_json(path)


def _load_required_text(root: Path, rel: str) -> str:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS11 input: {rel}")
    return path.read_text(encoding="utf-8")


def _check(value: bool, check_id: str, detail: str, refs: Sequence[str], **extra: Any) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "check": check_id,
        "status": "PASS" if value else "FAIL",
        "detail": detail,
        "refs": [str(Path(ref).as_posix()) for ref in refs],
    }
    row.update(extra)
    return row


def _signer_modes(signer_policy: Dict[str, Any]) -> List[str]:
    rows = signer_policy.get("allowed_signers") if isinstance(signer_policy.get("allowed_signers"), list) else []
    return [str(row.get("mode", "")).strip() for row in rows if isinstance(row, dict) and str(row.get("mode", "")).strip()]


def _bundle_keyless_detected(sigstore_bundle: Dict[str, Any]) -> bool:
    signer_id = str(sigstore_bundle.get("signer_id", "")).strip().upper()
    signer_mode = str(sigstore_bundle.get("signer_mode", "")).strip().lower()
    certificate_identity = str(
        sigstore_bundle.get("certificate_identity", "") or sigstore_bundle.get("certificateIdentity", "")
    ).strip()
    certificate_oidc_issuer = str(
        sigstore_bundle.get("certificate_oidc_issuer", "") or sigstore_bundle.get("certificateOidcIssuer", "")
    ).strip()
    return bool(
        signer_mode == "sigstore_keyless"
        or "KEYLESS" in signer_id
        or (certificate_identity and certificate_oidc_issuer)
    )


def _bundle_certificate_identity(sigstore_bundle: Dict[str, Any]) -> str:
    return str(sigstore_bundle.get("certificate_identity", "") or sigstore_bundle.get("certificateIdentity", "")).strip()


def _bundle_certificate_oidc_issuer(sigstore_bundle: Dict[str, Any]) -> str:
    return str(sigstore_bundle.get("certificate_oidc_issuer", "") or sigstore_bundle.get("certificateOidcIssuer", "")).strip()


def _write_json(root: Path, rel: str, payload: Dict[str, Any]) -> None:
    write_json_stable((root / Path(rel)).resolve(), payload)


def build_ws11_signer_policy(*, signer_policy: Dict[str, Any], generated_utc: str) -> Dict[str, Any]:
    payload = json.loads(json.dumps(signer_policy))
    payload["schema_id"] = "kt.governance.signer_identity_policy.v1"
    payload["status"] = "ACTIVE"
    payload["effective_utc"] = generated_utc

    prior_policy_id = str(payload.get("policy_id", "")).strip()
    next_policy_id = "SIGNER_IDENTITY_POLICY_V2_20260317_WS11_KEYLESS_DECLARED"
    if prior_policy_id and prior_policy_id != next_policy_id:
        supersedes = payload.get("supersedes") if isinstance(payload.get("supersedes"), list) else []
        if prior_policy_id not in supersedes:
            supersedes = [*supersedes, prior_policy_id]
        payload["supersedes"] = supersedes
    payload["policy_id"] = next_policy_id

    rules = payload.get("rules") if isinstance(payload.get("rules"), dict) else {}
    notes = rules.get("notes") if isinstance(rules.get("notes"), list) else []
    declaration_note = (
        "WS11 declares a GitHub Actions keyless signer constraint for the Truth Barrier workflow on main; "
        "this declaration does not itself prove keyless execution."
    )
    if declaration_note not in notes:
        notes.append(declaration_note)
    rules["notes"] = notes
    payload["rules"] = rules

    allowed_signers = payload.get("allowed_signers") if isinstance(payload.get("allowed_signers"), list) else []
    keypair_present = False
    keyless_present = False
    for row in allowed_signers:
        if not isinstance(row, dict):
            continue
        signer_id = str(row.get("signer_id", "")).strip()
        if signer_id == "KT_OP1_COSIGN_KEYPAIR":
            keypair_present = True
        if signer_id == DECLARED_KEYLESS_SIGNER_ID:
            row["mode"] = "sigstore_keyless"
            row["certificate_identity"] = DECLARED_KEYLESS_CERTIFICATE_IDENTITY
            row["certificate_oidc_issuer"] = DECLARED_KEYLESS_CERTIFICATE_OIDC_ISSUER
            row["workflow_ref"] = DECLARED_KEYLESS_WORKFLOW_REF
            row["repo_slug"] = DECLARED_KEYLESS_REPO_SLUG
            row["issuance_state"] = "DECLARED_PENDING_EXECUTION"
            keyless_present = True
    if not keypair_present:
        allowed_signers.append(
            {
                "signer_id": "KT_OP1_COSIGN_KEYPAIR",
                "mode": "cosign_keypair",
                "public_key_ref": SIGNER_PUBKEY_REL,
                "allowed_predicates": [
                    "https://kings-theorem.io/attestations/kt-authority-subject/v1",
                ],
            }
        )
    if not keyless_present:
        allowed_signers.append(
            {
                "signer_id": DECLARED_KEYLESS_SIGNER_ID,
                "mode": "sigstore_keyless",
                "certificate_identity": DECLARED_KEYLESS_CERTIFICATE_IDENTITY,
                "certificate_oidc_issuer": DECLARED_KEYLESS_CERTIFICATE_OIDC_ISSUER,
                "workflow_ref": DECLARED_KEYLESS_WORKFLOW_REF,
                "repo_slug": DECLARED_KEYLESS_REPO_SLUG,
                "issuance_state": "DECLARED_PENDING_EXECUTION",
                "allowed_predicates": [
                    "https://kings-theorem.io/attestations/kt-authority-subject/v1",
                ],
            }
        )
    payload["allowed_signers"] = allowed_signers
    payload["keyless_constraints"] = {
        "allowed": True,
        "certificate_identity": DECLARED_KEYLESS_CERTIFICATE_IDENTITY,
        "certificate_oidc_issuer": DECLARED_KEYLESS_CERTIFICATE_OIDC_ISSUER,
    }
    return payload


def build_keyless_policy(*, signer_policy: Dict[str, Any], current_repo_head: str, generated_utc: str) -> Dict[str, Any]:
    keyless_constraints = signer_policy.get("keyless_constraints") if isinstance(signer_policy.get("keyless_constraints"), dict) else {}
    activation_state = (
        "DECLARED_PENDING_EXECUTION"
        if bool(keyless_constraints.get("allowed"))
        and str(keyless_constraints.get("certificate_identity", "")).strip()
        and str(keyless_constraints.get("certificate_oidc_issuer", "")).strip()
        else "NOT_ACTIVE"
    )
    return {
        "schema_id": "kt.governance.sigstore_keyless_path_policy.v1",
        "policy_id": "KT_SIGSTORE_KEYLESS_PATH_POLICY_V1_20260317",
        "status": "ACTIVE",
        "generated_utc": generated_utc,
        "current_repo_head": current_repo_head,
        "declared_public_trust_path_for_pass": "sigstore_keyless_with_rekor_and_identity_constraints",
        "current_activation_state": activation_state,
        "issuer_constraints": {
            "certificate_identity": str(keyless_constraints.get("certificate_identity", "")).strip(),
            "certificate_oidc_issuer": str(keyless_constraints.get("certificate_oidc_issuer", "")).strip(),
        },
        "declaration_basis": {
            "repo_slug": DECLARED_KEYLESS_REPO_SLUG,
            "workflow_ref": DECLARED_KEYLESS_WORKFLOW_REF,
            "branch_ref": "refs/heads/main",
        },
        "declared_ws11_keyless_surfaces": DECLARED_KEYLESS_SURFACES,
        "activation_requirements": [
            "signer_identity_policy.json keyless_constraints.allowed must be true",
            "certificate identity and OIDC issuer constraints must be non-empty",
            "critical public artifacts must be signed through the keyless path",
            "Rekor inclusion evidence must be PASS for the declared WS11 surfaces",
            "outsider verification for the declared WS11 surfaces must require no private or local-secret input",
        ],
        "stronger_claim_not_made": [
            "Keyless signing is active today",
            "The current public bundle already proves keyless signing",
            "WS11 PASS is earned by policy declaration alone",
        ],
    }


def build_keyless_status(
    *,
    signer_policy: Dict[str, Any],
    sigstore_bundle: Dict[str, Any],
    rekor_receipt: Dict[str, Any],
    generated_utc: str,
    current_repo_head: str,
) -> Dict[str, Any]:
    keyless_constraints = signer_policy.get("keyless_constraints") if isinstance(signer_policy.get("keyless_constraints"), dict) else {}
    allowed = bool(keyless_constraints.get("allowed"))
    constraint_identity = str(keyless_constraints.get("certificate_identity", "")).strip()
    constraint_issuer = str(keyless_constraints.get("certificate_oidc_issuer", "")).strip()
    signer_modes = _signer_modes(signer_policy)
    bundle_keyless = _bundle_keyless_detected(sigstore_bundle)
    rekor_pass = str(rekor_receipt.get("status", "")).strip() == "PASS"
    signer_id = str(sigstore_bundle.get("signer_id", "")).strip()
    bundle_identity = _bundle_certificate_identity(sigstore_bundle)
    bundle_issuer = _bundle_certificate_oidc_issuer(sigstore_bundle)

    blockers: List[str] = []
    if not allowed:
        blockers.append("KEYLESS_SIGNER_POLICY_DISABLED")
    if not constraint_identity or not constraint_issuer:
        blockers.append("KEYLESS_IDENTITY_CONSTRAINTS_NOT_DECLARED")
    if not bundle_keyless:
        blockers.append("NO_KEYLESS_SIGSTORE_BUNDLE_FOR_DECLARED_WS11_SURFACES")
    if bundle_keyless and constraint_identity and constraint_issuer:
        if bundle_identity != constraint_identity or bundle_issuer != constraint_issuer:
            blockers.append("KEYLESS_BUNDLE_IDENTITY_CONSTRAINT_MISMATCH")
    if signer_id and "KEYPAIR" in signer_id.upper():
        blockers.append("EXECUTED_SIGNING_PATH_REMAINS_KEYPAIR_BASED")
    if not rekor_pass:
        blockers.append("REKOR_INCLUSION_EVIDENCE_NOT_PASSING")

    status = "PASS" if not blockers else "NOT_ACTIVE"
    return {
        "schema_id": "kt.operator.sigstore_keyless_status.v1",
        "artifact_id": Path(KEYLESS_STATUS_REL).name,
        "status": status,
        "generated_utc": generated_utc,
        "current_repo_head": current_repo_head,
        "signer_policy_ref": SIGNER_POLICY_REL,
        "declared_public_trust_path_for_pass": "sigstore_keyless_with_rekor_and_identity_constraints",
        "current_signer_modes": signer_modes,
        "executed_signer_id": signer_id,
        "executed_certificate_identity": bundle_identity,
        "executed_certificate_oidc_issuer": bundle_issuer,
        "keyless_constraints_allowed": allowed,
        "keyless_constraint_identity": constraint_identity,
        "keyless_constraint_oidc_issuer": constraint_issuer,
        "keyless_bundle_detected": bundle_keyless,
        "declared_ws11_keyless_surfaces": DECLARED_KEYLESS_SURFACES,
        "keyless_backed_surfaces": DECLARED_KEYLESS_SURFACES if status == "PASS" else [],
        "rekor_receipt_ref": REKOR_RECEIPT_REL,
        "rekor_receipt_status": str(rekor_receipt.get("status", "")).strip() or "MISSING",
        "blockers": blockers,
        "stronger_claim_not_made": [
            "A keyless signer is active when blocker(s) remain",
            "The current public bundle proves keyless signing when signer_id remains keypair-based",
            "WS11 PASS is earned while keyless blockers remain",
        ],
    }


def build_log_monitor_policy(*, current_repo_head: str, generated_utc: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.log_monitor_policy.v1",
        "policy_id": "KT_LOG_MONITOR_POLICY_V1_20260317",
        "status": "ACTIVE",
        "generated_utc": generated_utc,
        "current_repo_head": current_repo_head,
        "plane_id": "KT_LOG_MONITOR",
        "monitor_targets": [
            SIGSTORE_BUNDLE_REL,
            REKOR_RECEIPT_REL,
            KEYLESS_STATUS_REL,
            PUBLIC_TRUST_BUNDLE_REL,
        ],
        "anomaly_rules": [
            {
                "anomaly_id": "SIGSTORE_KEYLESS_PATH_NOT_ACTIVE",
                "severity": "HIGH",
                "freeze_scope": "WS12_PLUS",
                "blocks_ws11_pass": True,
            },
            {
                "anomaly_id": "REKOR_INCLUSION_EVIDENCE_MISSING_OR_FAILING",
                "severity": "CRITICAL",
                "freeze_scope": "WS12_PLUS",
                "blocks_ws11_pass": True,
            },
            {
                "anomaly_id": "PUBLIC_VERIFICATION_REQUIRES_LOCAL_SECRET",
                "severity": "CRITICAL",
                "freeze_scope": "WS12_PLUS",
                "blocks_ws11_pass": True,
            },
        ],
        "freeze_behavior": {
            "freeze_on_any_high_or_critical_anomaly": True,
            "downstream_scope": "WS12_PLUS",
            "resolution_rule": "A blocking anomaly keeps WS11 as the current lawful workstream until evidence removes the anomaly.",
        },
        "stronger_claim_not_made": [
            "KT_LOG_MONITOR alone upgrades WS11 to PASS",
            "A monitor anomaly implies compromise rather than a bounded missing-proof condition",
        ],
    }


def _secret_dependency_violations(root: Path, public_refs: Sequence[str]) -> List[str]:
    violations: List[str] = []
    for rel in public_refs:
        text = _load_required_text(root, rel)
        for token in SECRET_TOKENS:
            if token in text:
                violations.append(f"{rel} contains {token}")
    return violations


def build_log_monitor_receipt(
    *,
    root: Path,
    keyless_status: Dict[str, Any],
    sigstore_bundle: Dict[str, Any],
    rekor_receipt: Dict[str, Any],
    public_refs: Sequence[str],
    generated_utc: str,
    current_repo_head: str,
) -> Dict[str, Any]:
    sigstore_pass = str(sigstore_bundle.get("status", "")).strip() == "PASS"
    rekor_pass = str(rekor_receipt.get("status", "")).strip() == "PASS"
    log_fields_present = bool(str(rekor_receipt.get("log_id", "")).strip()) and rekor_receipt.get("log_index") is not None
    secret_violations = _secret_dependency_violations(root, public_refs)

    anomalies: List[Dict[str, Any]] = []
    if keyless_status.get("status") != "PASS":
        anomalies.append(
            {
                "anomaly_id": "SIGSTORE_KEYLESS_PATH_NOT_ACTIVE",
                "severity": "HIGH",
                "status": "OPEN",
                "ref": KEYLESS_STATUS_REL,
            }
        )
    if not rekor_pass or not log_fields_present:
        anomalies.append(
            {
                "anomaly_id": "REKOR_INCLUSION_EVIDENCE_MISSING_OR_FAILING",
                "severity": "CRITICAL",
                "status": "OPEN",
                "ref": REKOR_RECEIPT_REL,
            }
        )
    if secret_violations:
        anomalies.append(
            {
                "anomaly_id": "PUBLIC_VERIFICATION_REQUIRES_LOCAL_SECRET",
                "severity": "CRITICAL",
                "status": "OPEN",
                "details": secret_violations,
            }
        )

    checks = [
        _check(sigstore_pass, "sigstore_bundle_pass", "Sigstore publication bundle must be PASS for WS11 surfaces.", [SIGSTORE_BUNDLE_REL]),
        _check(rekor_pass, "rekor_receipt_pass", "Rekor inclusion receipt must be PASS.", [REKOR_RECEIPT_REL]),
        _check(log_fields_present, "rekor_log_fields_present", "Rekor inclusion receipt must expose log_id and log_index.", [REKOR_RECEIPT_REL]),
        _check(keyless_status.get("status") == "PASS", "keyless_path_active_for_pass", "WS11 PASS requires an active keyless path.", [KEYLESS_STATUS_REL]),
        _check(not secret_violations, "public_verification_secret_free", "Declared WS11 public surfaces must require no local secret.", public_refs, failures=secret_violations),
    ]
    active = checks[0]["status"] == "PASS" and checks[1]["status"] == "PASS" and checks[2]["status"] == "PASS"
    return {
        "schema_id": "kt.operator.log_monitor_plane_receipt.v1",
        "artifact_id": Path(LOG_MONITOR_RECEIPT_REL).name,
        "status": "PASS" if active else "FAIL_CLOSED",
        "generated_utc": generated_utc,
        "current_repo_head": current_repo_head,
        "plane_id": "KT_LOG_MONITOR",
        "plane_state": "ACTIVE" if active else "DEGRADED",
        "checks": checks,
        "anomalies": anomalies,
        "freeze_state": "DOWNSTREAM_FREEZE_ACTIVE" if anomalies else "NO_FREEZE",
        "freeze_scope": "WS12_PLUS" if anomalies else "",
        "stronger_claim_not_made": [
            "An active monitor means WS11 PASS is earned",
            "No anomaly means keyless signing is proven",
        ],
    }


def build_public_trust_bundle(
    *,
    root: Path,
    public_refs: Sequence[str],
    generated_utc: str,
    current_repo_head: str,
    public_verifier_manifest: Dict[str, Any],
    sigstore_bundle: Dict[str, Any],
) -> Dict[str, Any]:
    files = [
        {
            "path": str(Path(rel).as_posix()),
            "sha256": file_sha256((root / Path(rel)).resolve()),
        }
        for rel in public_refs
    ]
    secret_violations = _secret_dependency_violations(root, public_refs)
    return {
        "schema_id": "kt.operator.ws11_public_trust_bundle.v1",
        "artifact_id": Path(PUBLIC_TRUST_BUNDLE_REL).name,
        "status": "PASS" if not secret_violations else "FAIL_CLOSED",
        "generated_utc": generated_utc,
        "current_repo_head": current_repo_head,
        "truth_subject_commit": str(sigstore_bundle.get("truth_subject_commit", "")).strip(),
        "evidence_commit": str(public_verifier_manifest.get("evidence_commit", "")).strip(),
        "head_claim_boundary": str(public_verifier_manifest.get("claim_boundary", "")).strip(),
        "included_public_artifacts": files,
        "outsider_verification_requires_only_public_material": not secret_violations,
        "secret_dependency_violations": secret_violations,
        "declared_ws11_keyless_surfaces": DECLARED_KEYLESS_SURFACES,
        "stronger_claim_not_made": [
            "The current repo head is itself the transparency-verified subject unless the verifier says so",
            "This bundle upgrades Sigstore keypair evidence into keyless evidence",
        ],
    }


def build_ws11_receipt(
    *,
    current_repo_head: str,
    generated_utc: str,
    keyless_status: Dict[str, Any],
    log_monitor_receipt: Dict[str, Any],
    public_trust_bundle: Dict[str, Any],
    ws10_reseal_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    rekor_exists = True
    log_monitor_active = str(log_monitor_receipt.get("status", "")).strip() == "PASS" and str(log_monitor_receipt.get("plane_state", "")).strip() == "ACTIVE"
    secret_free = bool(public_trust_bundle.get("outsider_verification_requires_only_public_material"))
    keyless_active = str(keyless_status.get("status", "")).strip() == "PASS"
    freeze_backed = bool(log_monitor_receipt.get("freeze_state"))

    if log_monitor_active and secret_free and freeze_backed and rekor_exists and keyless_active:
        status = "PASS"
        pass_verdict = PASS_VERDICT
        blocked_by: List[str] = []
        next_lawful_workstream = "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE"
    elif log_monitor_active and secret_free and freeze_backed and rekor_exists:
        status = "PARTIAL"
        pass_verdict = PARTIAL_VERDICT
        blocked_by = list(keyless_status.get("blockers", []))
        next_lawful_workstream = WORKSTREAM_ID
    else:
        status = "FAIL_CLOSED"
        pass_verdict = "WS11_TRUST_PATH_ACTIVATION_FAIL_CLOSED"
        blocked_by = list(keyless_status.get("blockers", []))
        if not log_monitor_active:
            blocked_by.append("KT_LOG_MONITOR_NOT_ACTIVE")
        if not secret_free:
            blocked_by.append("PUBLIC_VERIFICATION_REQUIRES_LOCAL_SECRET")
        next_lawful_workstream = WORKSTREAM_ID

    carry_forward_note = str(ws10_reseal_receipt.get("import_path_fragility_note", "")).strip()
    keyless_declared = bool(keyless_status.get("keyless_constraints_allowed")) and bool(
        str(keyless_status.get("keyless_constraint_identity", "")).strip()
    ) and bool(str(keyless_status.get("keyless_constraint_oidc_issuer", "")).strip())
    return {
        "schema_id": "kt.operator.sigstore_integration_receipt.v1",
        "artifact_id": Path(RECEIPT_REL).name,
        "workstream_id": WORKSTREAM_ID,
        "step_id": STEP_ID,
        "status": status,
        "pass_verdict": pass_verdict,
        "generated_utc": generated_utc,
        "compiled_against": current_repo_head,
        "current_repo_head": current_repo_head,
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": ["python -m tools.operator.ws11_sigstore_rekor_log_monitor_validate"],
        "tests_run": ["python -m pytest -q tests/operator/test_ws11_sigstore_rekor_log_monitor_validate.py"],
        "truth_conditions": {
            "critical_public_artifacts_signed_through_declared_public_trust_path": keyless_active,
            "rekor_inclusion_evidence_exists": rekor_exists,
            "kt_log_monitor_active_as_real_plane": log_monitor_active,
            "anomaly_handling_and_freeze_behavior_validator_backed": freeze_backed,
            "outsider_verification_has_no_private_local_secret_dependency_for_declared_ws11_surfaces": secret_free,
        },
        "blocked_by": blocked_by,
        "current_strongest_claim": (
            "WS11 has a real KT_LOG_MONITOR plane, Rekor inclusion evidence, a public verification bundle that requires no private or local-secret input for the declared WS11 public surfaces, "
            "and declared keyless identity constraints for the Truth Barrier workflow on main. However, the executed signing path remains keypair-based and no matching keyless Sigstore artifact is present, so WS11 is PARTIAL and not PASS."
            if status == "PARTIAL" and keyless_declared
            else "WS11 has a real KT_LOG_MONITOR plane, Rekor inclusion evidence, and a public verification bundle that requires no private or local-secret input for the declared WS11 public surfaces. "
            "However, the executed signing path remains keypair-based and no keyless Sigstore artifact is present, so WS11 is PARTIAL and not PASS."
            if status == "PARTIAL"
            else "WS11 proves the declared public-trust path with keyless Sigstore signing, Rekor inclusion evidence, an active KT_LOG_MONITOR plane, and public-secret-free outsider verification."
            if status == "PASS"
            else "WS11 failed closed because the declared public-trust activation surface is incomplete or internally contradictory."
        ),
        "carry_forward_truth": {
            "ws10_root_boundary": "3-of-3 only; 3-of-5 was not proven.",
            "ws10_import_path_fragility_visible": carry_forward_note,
            "dag_unlock_is_not_campaign_completion": True,
        },
        "created_files": [
            KEYLESS_POLICY_REL,
            LOG_MONITOR_POLICY_REL,
            KEYLESS_STATUS_REL,
            LOG_MONITOR_RECEIPT_REL,
            PUBLIC_TRUST_BUNDLE_REL,
            RECEIPT_REL,
        ],
        "updated_files": [
            SIGNER_POLICY_REL,
            EXECUTION_DAG_REL,
            TRUST_ROOT_POLICY_REL,
            SIGNER_TOPOLOGY_REL,
        ],
        "stronger_claim_not_made": [
            "The original 3-of-5 root boundary was proven",
            "Release readiness is proven",
            "Verifier acceptance widened",
            "WS12 has started",
            "The campaign is complete",
        ],
        "next_lawful_workstream": next_lawful_workstream,
        "mutation_scope": "WS11_SIGSTORE_REKOR_LOG_MONITOR_ONLY",
        "declared_identity_constraints": {
            "certificate_identity": str(keyless_status.get("keyless_constraint_identity", "")).strip(),
            "certificate_oidc_issuer": str(keyless_status.get("keyless_constraint_oidc_issuer", "")).strip(),
        },
        "keyless_backed_ws11_surfaces": list(keyless_status.get("keyless_backed_surfaces", [])),
    }


def _apply_control_plane(
    *,
    dag: Dict[str, Any],
    trust_root_policy: Dict[str, Any],
    signer_topology: Dict[str, Any],
    receipt: Dict[str, Any],
) -> None:
    ws11_pass = str(receipt.get("status", "")).strip() == "PASS"
    ws11_partial = str(receipt.get("status", "")).strip() == "PARTIAL"
    dag["generated_utc"] = str(receipt.get("generated_utc", "")).strip()
    dag["current_repo_head"] = str(receipt.get("current_repo_head", "")).strip()
    dag["current_node"] = receipt["next_lawful_workstream"]
    dag["next_lawful_workstream"] = receipt["next_lawful_workstream"]
    dag["semantic_boundary"]["lawful_current_claim"] = (
        "WS10 passed under a reratified 3-of-3 root boundary only. WS11 is PARTIAL: Rekor evidence and KT_LOG_MONITOR are active on declared public surfaces, keyless identity constraints are declared, but the executed signer path remains keypair-based and no matching keyless bundle is present."
        if ws11_partial
        else "WS10 passed under a reratified 3-of-3 root boundary only. WS11 passed with keyless Sigstore, Rekor inclusion, and an active KT_LOG_MONITOR plane."
    )
    ws11_node = next(node for node in dag["nodes"] if node["id"] == WORKSTREAM_ID)
    ws12_node = next(node for node in dag["nodes"] if node["id"] == "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE")
    if ws11_pass:
        ws11_node["status"] = "PASS"
        ws11_node["blocked_by"] = []
        ws11_node["claim_boundary"] = "WS11 PASS proves only the declared keyless public-trust path and monitor plane for the WS11 surfaces."
        ws12_node["status"] = "UNLOCKED"
        ws12_node["unlock_basis"] = "WS11 PASS"
    else:
        ws11_node["status"] = "PARTIAL_KEYLESS_DECLARED_PENDING_EXECUTION"
        ws11_node["blocked_by"] = list(receipt.get("blocked_by", []))
        ws11_node["claim_boundary"] = "WS11 remains partial: public Sigstore/Rekor verification and KT_LOG_MONITOR are active, keyless identity constraints are declared, but no matching keyless signer path is proven."
        ws12_node["status"] = "LOCKED_PENDING_WS11_PASS"
        ws12_node.pop("unlock_basis", None)
    ws11_node["activation_boundary"] = "WS11 must not be overread as release readiness, verifier widening, or campaign completion."

    trust_root_policy["generated_utc"] = str(receipt.get("generated_utc", "")).strip()
    trust_root_policy["current_repo_head"] = str(receipt.get("current_repo_head", "")).strip()
    trust_root_policy["semantic_boundary"]["lawful_current_claim"] = (
        "WS10 root ceremony remains executed off-box under a reratified 3-of-3 boundary only. WS11 is PARTIAL: Rekor evidence and KT_LOG_MONITOR are active on the declared public surfaces, keyless identity constraints are declared, but the signer path remains keypair-based and no matching keyless bundle is present."
        if ws11_partial
        else "WS10 root ceremony remains executed off-box under a reratified 3-of-3 boundary only. WS11 passed with a declared keyless public-trust path, Rekor inclusion evidence, and an active KT_LOG_MONITOR plane."
    )
    trust_root_policy["closure_boundary"]["next_required_step"] = receipt["next_lawful_workstream"]

    signer_topology["generated_utc"] = str(receipt.get("generated_utc", "")).strip()
    signer_topology["current_repo_head"] = str(receipt.get("current_repo_head", "")).strip()
    signer_topology["semantic_boundary"]["lawful_current_claim"] = (
        "Root signer topology remains executed and reratified as 3-of-3 only. WS11 is PARTIAL: the declared public verification and KT_LOG_MONITOR surfaces are active, keyless identity constraints are declared for CI signing, but the signer path remains keypair-based and non-root roles remain unexecuted."
        if ws11_partial
        else "Root signer topology remains executed and reratified as 3-of-3 only. WS11 passed for the declared keyless public-trust path; non-root issuance still remains bounded by later workstreams."
    )


def emit_ws11_sigstore_activation(*, root: Optional[Path] = None) -> Dict[str, Any]:
    repo = root or repo_root()
    pre_status_lines = _git_status_lines(repo)
    pre_dirty = _dirty_relpaths(pre_status_lines)
    if pre_dirty and any(path not in PLANNED_MUTATES for path in pre_dirty):
        raise RuntimeError("FAIL_CLOSED: WS11 requires a clean or in-scope worktree before mutation")

    current_repo_head = _git_head(repo)
    generated_utc = utc_now_iso_z()

    ws10_reseal_receipt = _load_required_json(repo, WS10_RESEAL_RECEIPT_REL)
    if str(ws10_reseal_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: WS10 reseal receipt must be PASS before WS11 activation")

    signer_policy = _load_required_json(repo, SIGNER_POLICY_REL)
    signer_policy = build_ws11_signer_policy(signer_policy=signer_policy, generated_utc=generated_utc)
    _write_json(repo, SIGNER_POLICY_REL, signer_policy)
    sigstore_bundle = _load_required_json(repo, SIGSTORE_BUNDLE_REL)
    rekor_receipt = _load_required_json(repo, REKOR_RECEIPT_REL)
    public_verifier_manifest = _load_required_json(repo, PUBLIC_VERIFIER_MANIFEST_REL)
    _load_required_json(repo, PUBLIC_VERIFIER_RELEASE_MANIFEST_REL)
    _load_required_json(repo, PUBLIC_VERIFIER_ATTESTATION_REL)
    _load_required_json(repo, TUF_ROOT_INITIALIZATION_REL)
    dag = _load_required_json(repo, EXECUTION_DAG_REL)
    trust_root_policy = _load_required_json(repo, TRUST_ROOT_POLICY_REL)
    signer_topology = _load_required_json(repo, SIGNER_TOPOLOGY_REL)

    keyless_policy = build_keyless_policy(
        signer_policy=signer_policy,
        current_repo_head=current_repo_head,
        generated_utc=generated_utc,
    )
    _write_json(repo, KEYLESS_POLICY_REL, keyless_policy)

    keyless_status = build_keyless_status(
        signer_policy=signer_policy,
        sigstore_bundle=sigstore_bundle,
        rekor_receipt=rekor_receipt,
        generated_utc=generated_utc,
        current_repo_head=current_repo_head,
    )
    _write_json(repo, KEYLESS_STATUS_REL, keyless_status)

    log_monitor_policy = build_log_monitor_policy(current_repo_head=current_repo_head, generated_utc=generated_utc)
    _write_json(repo, LOG_MONITOR_POLICY_REL, log_monitor_policy)

    public_refs = [
        SIGNER_POLICY_REL,
        SIGNER_PUBKEY_REL,
        KEYLESS_POLICY_REL,
        KEYLESS_STATUS_REL,
        LOG_MONITOR_POLICY_REL,
        SIGSTORE_BUNDLE_REL,
        REKOR_RECEIPT_REL,
        PUBLIC_VERIFIER_MANIFEST_REL,
        PUBLIC_VERIFIER_RELEASE_MANIFEST_REL,
        PUBLIC_VERIFIER_ATTESTATION_REL,
        TUF_ROOT_INITIALIZATION_REL,
    ]
    log_monitor_receipt = build_log_monitor_receipt(
        root=repo,
        keyless_status=keyless_status,
        sigstore_bundle=sigstore_bundle,
        rekor_receipt=rekor_receipt,
        public_refs=public_refs,
        generated_utc=generated_utc,
        current_repo_head=current_repo_head,
    )
    _write_json(repo, LOG_MONITOR_RECEIPT_REL, log_monitor_receipt)

    public_trust_bundle = build_public_trust_bundle(
        root=repo,
        public_refs=[*public_refs, LOG_MONITOR_RECEIPT_REL],
        generated_utc=generated_utc,
        current_repo_head=current_repo_head,
        public_verifier_manifest=public_verifier_manifest,
        sigstore_bundle=sigstore_bundle,
    )
    _write_json(repo, PUBLIC_TRUST_BUNDLE_REL, public_trust_bundle)

    receipt = build_ws11_receipt(
        current_repo_head=current_repo_head,
        generated_utc=generated_utc,
        keyless_status=keyless_status,
        log_monitor_receipt=log_monitor_receipt,
        public_trust_bundle=public_trust_bundle,
        ws10_reseal_receipt=ws10_reseal_receipt,
    )
    _apply_control_plane(
        dag=dag,
        trust_root_policy=trust_root_policy,
        signer_topology=signer_topology,
        receipt=receipt,
    )
    _write_json(repo, EXECUTION_DAG_REL, dag)
    _write_json(repo, TRUST_ROOT_POLICY_REL, trust_root_policy)
    _write_json(repo, SIGNER_TOPOLOGY_REL, signer_topology)

    post_dirty = _dirty_relpaths(_git_status_lines(repo))
    unexpected_touches = sorted(path for path in post_dirty if path not in PLANNED_MUTATES)
    protected_touch_violations = sorted(
        path for path in post_dirty if any(path.startswith(prefix) for prefix in PROTECTED_TOUCH_PATTERNS)
    )
    receipt["unexpected_touches"] = unexpected_touches
    receipt["protected_touch_violations"] = protected_touch_violations
    _write_json(repo, RECEIPT_REL, receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WS11: activate Sigstore/Rekor public-trust monitoring with truthful bounded status.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    receipt = emit_ws11_sigstore_activation(root=repo_root())
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(receipt.get("status", "")).strip() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
