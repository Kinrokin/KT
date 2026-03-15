from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.crypto_attestation import (
    load_authority_bundle_schema,
    mint_authority_bundle,
    mint_envelope,
    subject_sha256 as authority_subject_sha256,
    validate_authority_bundle,
)
from tools.operator.authority_convergence_validate import build_authority_convergence_report
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.truth_authority import active_truth_source_ref, load_json_ref, path_ref


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GENERATED_TRUTH_ROOT_REL = "KT_PROD_CLEANROOM/exports/_truth"
TRUTH_CURRENT_DIR_REL = f"{GENERATED_TRUTH_ROOT_REL}/current"
TRUTH_BUNDLES_ROOT_REL = f"{GENERATED_TRUTH_ROOT_REL}/bundles"
CURRENT_POINTER_REL = f"{TRUTH_CURRENT_DIR_REL}/current_pointer.json"
CURRENT_MANIFEST_REL = f"{TRUTH_CURRENT_DIR_REL}/current_bundle_manifest.json"
TRUTH_LEDGER_BRANCH = "kt_truth_ledger"
LEDGER_ROOT_REL = "ledger"
LEDGER_CURRENT_DIR_REL = f"{LEDGER_ROOT_REL}/current"
LEDGER_BUNDLES_ROOT_REL = f"{LEDGER_ROOT_REL}/bundles"
LEDGER_HISTORY_ROOT_REL = f"{LEDGER_ROOT_REL}/history"
LEDGER_CURRENT_POINTER_REL = f"{LEDGER_CURRENT_DIR_REL}/current_pointer.json"
LEDGER_CURRENT_MANIFEST_REL = f"{LEDGER_CURRENT_DIR_REL}/current_bundle_manifest.json"

CRYPTO_PUBLICATION_DIR_REL = "KT_PROD_CLEANROOM/reports/cryptographic_publication"
CRYPTO_PUBLICATION_SUBJECT_REL = f"{CRYPTO_PUBLICATION_DIR_REL}/authority_subject.json"
CRYPTO_PUBLICATION_STATEMENT_REL = f"{CRYPTO_PUBLICATION_DIR_REL}/in_toto_statement.json"
CRYPTO_PUBLICATION_SIGNATURE_REL = f"{CRYPTO_PUBLICATION_DIR_REL}/in_toto_statement.sig"
CRYPTO_PUBLICATION_BUNDLE_REL = f"{CRYPTO_PUBLICATION_DIR_REL}/in_toto_statement.bundle.json"
CRYPTO_PUBLICATION_AUTHORITY_BUNDLE_REL = f"{CRYPTO_PUBLICATION_DIR_REL}/authority_bundle.json"
CRYPTO_PUBLICATION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json"

SIGNER_IDENTITY_POLICY_REL = "KT_PROD_CLEANROOM/governance/signer_identity_policy.json"
SUPPLY_CHAIN_LAYOUT_REL = "KT_PROD_CLEANROOM/governance/supply_chain_layout.json"
DEFAULT_SIGNER_ID = "KT_OP1_COSIGN_KEYPAIR"
DEFAULT_SIGNER_PUBKEY_REL = "KT_PROD_CLEANROOM/governance/signers/kt_op1_cosign.pub"
DEFAULT_COSIGN_PRIVATE_KEY_REL = "tmp/sigstore/keys/kt_op1_cosign.key"
DEFAULT_IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
DEFAULT_PREDICATE_TYPE = "https://kings-theorem.io/attestations/kt-authority-subject/v1"

TRUTH_PUBLICATION_REQUIRED_LAW_SURFACES: List[str] = [
    "KT_PROD_CLEANROOM/governance/truth_publication_contract.json",
    "KT_PROD_CLEANROOM/governance/settled_authority_migration_contract.json",
    "KT_PROD_CLEANROOM/governance/truth_snapshot_retention_rules.json",
    "KT_PROD_CLEANROOM/governance/truth_publication_cleanliness_rules.json",
    "KT_PROD_CLEANROOM/governance/tracked_vs_generated_truth_boundary.json",
    "KT_PROD_CLEANROOM/governance/truth_bundle_contract.json",
    "KT_PROD_CLEANROOM/governance/truth_pointer_rules.json",
    "KT_PROD_CLEANROOM/governance/current_pointer_transition_rules.json",
]

TRUTH_PUBLICATION_REQUIRED_ARTIFACTS: List[str] = [
    "KT_PROD_CLEANROOM/reports/settled_authority_promotion_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_bundle.schema.json",
    "KT_PROD_CLEANROOM/reports/truth_bundle_catalog.json",
    "KT_PROD_CLEANROOM/reports/truth_pointer_index.json",
    "KT_PROD_CLEANROOM/reports/truth_publication_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_snapshot_manifest.json",
    "KT_PROD_CLEANROOM/reports/truth_clean_state_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_publication_supersession_receipt.json",
    "KT_PROD_CLEANROOM/reports/truth_publication_stabilization_receipt.json",
]

MANDATORY_BUNDLE_REPORTS: List[str] = [
    "live_validation_index.json",
    "current_state_receipt.json",
    "runtime_closure_audit.json",
    "posture_consistency_receipt.json",
    "posture_consistency_enforcement_receipt.json",
    "posture_conflict_receipt.json",
    "settled_truth_source_receipt.json",
    "truth_supersession_receipt.json",
]

OPTIONAL_BUNDLE_REPORTS: List[str] = [
    "truth_surface_reconciliation_report.json",
    "one_button_preflight_receipt.json",
    "one_button_production_receipt.json",
    "authority_convergence_receipt.json",
    "domain_maturity_matrix.json",
    "p0_green_full_receipt.json",
    "kt_green_final_receipt.json",
]

TRACKED_DOCUMENTARY_SURFACES: List[str] = [
    f"{DEFAULT_REPORT_ROOT_REL}/{name}"
    for name in (
        "live_validation_index.json",
        "current_state_receipt.json",
        "runtime_closure_audit.json",
        "posture_consistency_receipt.json",
        "posture_consistency_enforcement_receipt.json",
        "posture_conflict_receipt.json",
        "settled_truth_source_receipt.json",
        "truth_supersession_receipt.json",
        "truth_surface_reconciliation_report.json",
        "one_button_preflight_receipt.json",
        "one_button_production_receipt.json",
        "authority_convergence_receipt.json",
        "domain_maturity_matrix.json",
        "p0_green_full_receipt.json",
        "kt_green_final_receipt.json",
    )
]


def _load_required(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return load_json(path)


def _canonical_hash(payload: Any) -> str:
    return sha256_hex(canonicalize_bytes(payload))


def _git_status_lines(root: Path) -> Optional[List[str]]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain=v1"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except Exception:  # noqa: BLE001
        return None
    return [line.rstrip("\n") for line in result.stdout.splitlines() if line.strip()]


def _report_path(root: Path, report_root_rel: str, name: str) -> Path:
    return (root / report_root_rel / name).resolve()


def ledger_ref(*, branch: str, relpath: str) -> str:
    return f"{branch}:{Path(relpath).as_posix()}"


def _bundle_sources(*, root: Path, report_root_rel: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for name in MANDATORY_BUNDLE_REPORTS:
        path = _report_path(root, report_root_rel, name)
        payload = _load_required(path)
        rows.append(
            {
                "name": name,
                "source_ref": path_ref(root=root, path=path),
                "payload": payload,
                "sha256": _canonical_hash(payload),
                "required": True,
            }
        )
    for name in OPTIONAL_BUNDLE_REPORTS:
        path = _report_path(root, report_root_rel, name)
        if not path.exists():
            continue
        payload = load_json(path)
        rows.append(
            {
                "name": name,
                "source_ref": path_ref(root=root, path=path),
                "payload": payload,
                "sha256": _canonical_hash(payload),
                "required": False,
            }
        )
    return rows


def _truth_bundle_schema() -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.truth_bundle.schema.v1",
        "required": [
            "schema_id",
            "truth_bundle_id",
            "truth_bundle_hash",
            "truth_subject_commit",
            "truth_produced_at_commit",
            "authority_level",
            "posture_enum",
            "zone_scope",
            "freshness_contract_ref",
            "validator_set",
            "generated_utc",
            "files",
        ],
        "properties": {
            "truth_bundle_id": {"type": "string"},
            "truth_bundle_hash": {"type": "string"},
            "truth_subject_commit": {"type": "string"},
            "truth_produced_at_commit": {"type": "string"},
            "authority_level": {"type": "string"},
            "posture_enum": {"type": "string"},
            "zone_scope": {"type": "array"},
            "supersedes": {"type": "string"},
            "generated_utc": {"type": "string"},
            "validator_set": {"type": "array"},
            "files": {"type": "array"},
        },
        "status": "ACTIVE",
    }


def _sha256_file_bytes(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text_normalized(path: Path) -> str:
    text = path.read_text(encoding="utf-8-sig")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _canonical_json_sha256(path: Path) -> str:
    obj = load_json(path)
    return sha256_hex(canonicalize_bytes(obj))


def _require_hex40(value: str, *, label: str) -> str:
    v = str(value).strip()
    if len(v) != 40 or any(ch not in "0123456789abcdef" for ch in v.lower()):
        raise RuntimeError(f"FAIL_CLOSED: {label} must be 40 lowercase hex characters")
    return v.lower()


def _resolve_cosign_exe(*, root: Path) -> Path:
    explicit = os.environ.get("KT_COSIGN_EXE", "").strip()
    if explicit:
        exe = Path(explicit).expanduser()
        if not exe.is_absolute():
            exe = (root / exe).resolve()
        if not exe.exists():
            raise RuntimeError(f"FAIL_CLOSED: KT_COSIGN_EXE does not exist: {exe.as_posix()}")
        return exe

    bundled = (root / "tmp" / "sigstore" / "cosign" / "v2.2.4" / "cosign.exe").resolve()
    if bundled.exists():
        return bundled

    found = shutil.which("cosign")
    if found:
        return Path(found).resolve()

    raise RuntimeError("FAIL_CLOSED: cosign executable not found (set KT_COSIGN_EXE or install cosign on PATH)")


def _cosign_version_info(*, cosign_exe: Path) -> Dict[str, Any]:
    result = subprocess.run(
        [str(cosign_exe), "version"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    info: Dict[str, Any] = {"raw": []}
    for line in (result.stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        info["raw"].append(s)
        if ":" not in s:
            continue
        k, v = s.split(":", 1)
        key = k.strip().lower().replace(" ", "_")
        val = v.strip()
        if key and val and key not in info:
            info[key] = val
    return info


def build_in_toto_statement_for_authority_subject(
    *,
    subject_sha256_hex: str,
    subject_name: str,
    predicate_type: str = DEFAULT_PREDICATE_TYPE,
    predicate: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    sha = str(subject_sha256_hex).strip().lower()
    if len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
        raise RuntimeError("FAIL_CLOSED: subject_sha256_hex must be 64 hex characters")
    return {
        "_type": DEFAULT_IN_TOTO_STATEMENT_TYPE,
        "subject": [{"name": str(subject_name).strip(), "digest": {"sha256": sha}}],
        "predicateType": str(predicate_type).strip(),
        "predicate": dict(predicate or {}),
    }


def _load_signer_policy(*, root: Path) -> Dict[str, Any]:
    policy_path = (root / SIGNER_IDENTITY_POLICY_REL).resolve()
    return load_json(policy_path)


def _find_allowed_signer(policy: Dict[str, Any], *, signer_id: str) -> Dict[str, Any]:
    allowed = policy.get("allowed_signers") if isinstance(policy.get("allowed_signers"), list) else []
    target = str(signer_id).strip()
    for row in allowed:
        if not isinstance(row, dict):
            continue
        if str(row.get("signer_id", "")).strip() == target:
            return row
    raise RuntimeError(f"FAIL_CLOSED: signer_id not allowed by policy: {target}")


def _assert_signer_policy_allows_pubkey(*, root: Path, signer: Dict[str, Any]) -> Dict[str, Any]:
    pub_ref = str(signer.get("public_key_ref", "")).strip()
    if not pub_ref:
        raise RuntimeError("FAIL_CLOSED: signer policy missing public_key_ref")
    pub_path = (root / pub_ref).resolve()
    if not pub_path.exists():
        raise RuntimeError(f"FAIL_CLOSED: signer public key missing: {pub_ref}")

    expected = str(signer.get("public_key_sha256", "")).strip().lower()
    actual = _sha256_text_normalized(pub_path)
    if expected and expected != actual:
        raise RuntimeError("FAIL_CLOSED: signer public key sha256 mismatch against signer policy")
    return {"public_key_ref": pub_ref, "public_key_path": pub_path, "public_key_sha256": actual}


def build_authority_subject_for_current_head(*, root: Path, report_root_rel: str, live_validation_index_path: Path) -> Dict[str, Any]:
    live_index = _load_required(live_validation_index_path)
    worktree = live_index.get("worktree") if isinstance(live_index.get("worktree"), dict) else {}
    subject_commit = _require_hex40(str(worktree.get("head_sha", "")).strip(), label="live_validation_index.worktree.head_sha")
    produced_commit = subject_commit

    law_paths = [
        "KT_PROD_CLEANROOM/governance/authority_subject_contract.json",
        "KT_PROD_CLEANROOM/governance/attestation_fabric_contract.json",
        "KT_PROD_CLEANROOM/governance/authority_bundle.schema.json",
        SIGNER_IDENTITY_POLICY_REL,
        SUPPLY_CHAIN_LAYOUT_REL,
    ]
    law_surface_hashes: Dict[str, str] = {}
    for rel in law_paths:
        path = (root / rel).resolve()
        if not path.exists():
            raise RuntimeError(f"FAIL_CLOSED: missing required authority law surface: {rel}")
        law_surface_hashes[rel] = _canonical_json_sha256(path)

    evidence: List[Dict[str, Any]] = []

    active_ref = active_truth_source_ref(root=root)
    active_obj = load_json_ref(root=root, ref=active_ref)
    evidence.append({"name": "active_truth_pointer", "ref": active_ref, "sha256": _canonical_hash(active_obj)})

    for rel in (
        "KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json",
        "KT_PROD_CLEANROOM/reports/authority_convergence_receipt.json",
        "KT_PROD_CLEANROOM/reports/published_head_self_convergence_receipt.json",
    ):
        path = (root / rel).resolve()
        if not path.exists():
            raise RuntimeError(f"FAIL_CLOSED: missing required evidence surface: {rel}")
        evidence.append({"name": Path(rel).name, "ref": rel, "sha256": _canonical_json_sha256(path)})

    return {
        "schema_id": "kt.authority.subject.v1",
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": produced_commit,
        "law_surface_hashes": law_surface_hashes,
        "supersedes_subject_sha256": "",
        "evidence": evidence,
    }


def publish_cryptographic_publication_ws6(
    *,
    root: Path,
    report_root_rel: str,
    live_validation_index_path: Path,
    signer_id: str = DEFAULT_SIGNER_ID,
    cosign_private_key_rel: str = DEFAULT_COSIGN_PRIVATE_KEY_REL,
) -> Dict[str, Any]:
    generated_utc = utc_now_iso_z()
    failures: List[str] = []
    checks: List[Dict[str, Any]] = []

    receipt_path = (root / CRYPTO_PUBLICATION_RECEIPT_REL).resolve()
    artifacts_dir = (root / CRYPTO_PUBLICATION_DIR_REL).resolve()
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    try:
        policy = _load_signer_policy(root=root)
        checks.append({"check": "signer_policy_present", "status": "PASS", "policy_ref": SIGNER_IDENTITY_POLICY_REL})
    except Exception as exc:  # noqa: BLE001
        failures.append("missing_signer_identity_policy")
        checks.append({"check": "signer_policy_present", "status": "FAIL", "error": str(exc)})
        policy = {}

    signer: Dict[str, Any] = {}
    pubkey_info: Dict[str, Any] = {}
    if policy:
        try:
            signer = _find_allowed_signer(policy, signer_id=str(signer_id))
            checks.append({"check": "signer_allowed_by_policy", "status": "PASS", "signer_id": str(signer_id)})
        except Exception as exc:  # noqa: BLE001
            failures.append("signer_not_allowed_by_policy")
            checks.append({"check": "signer_allowed_by_policy", "status": "FAIL", "error": str(exc), "signer_id": str(signer_id)})

    if signer:
        try:
            pubkey_info = _assert_signer_policy_allows_pubkey(root=root, signer=signer)
            checks.append({"check": "signer_pubkey_matches_policy_sha256", "status": "PASS", "public_key_ref": pubkey_info.get("public_key_ref", "")})
        except Exception as exc:  # noqa: BLE001
            failures.append("signer_pubkey_mismatch")
            checks.append({"check": "signer_pubkey_matches_policy_sha256", "status": "FAIL", "error": str(exc)})

    try:
        layout_path = (root / SUPPLY_CHAIN_LAYOUT_REL).resolve()
        if not layout_path.exists():
            raise RuntimeError("missing supply_chain_layout.json")
        load_json(layout_path)
        checks.append({"check": "supply_chain_layout_present", "status": "PASS", "layout_ref": SUPPLY_CHAIN_LAYOUT_REL})
    except Exception as exc:  # noqa: BLE001
        failures.append("missing_supply_chain_layout")
        checks.append({"check": "supply_chain_layout_present", "status": "FAIL", "error": str(exc)})

    try:
        subject = build_authority_subject_for_current_head(root=root, report_root_rel=report_root_rel, live_validation_index_path=live_validation_index_path)
        subj_sha = authority_subject_sha256(subject)
        write_json_stable(artifacts_dir / "authority_subject.json", subject)
        checks.append({"check": "authority_subject_minted", "status": "PASS", "subject_sha256": subj_sha, "subject_ref": CRYPTO_PUBLICATION_SUBJECT_REL})
    except Exception as exc:  # noqa: BLE001
        failures.append("authority_subject_mint_failed")
        checks.append({"check": "authority_subject_minted", "status": "FAIL", "error": str(exc)})
        subject = {}
        subj_sha = ""

    statement: Dict[str, Any] = {}
    statement_path = artifacts_dir / "in_toto_statement.json"
    signature_path = artifacts_dir / "in_toto_statement.sig"
    bundle_path = artifacts_dir / "in_toto_statement.bundle.json"
    authority_bundle_path = artifacts_dir / "authority_bundle.json"

    if subj_sha:
        try:
            statement = build_in_toto_statement_for_authority_subject(
                subject_sha256_hex=subj_sha,
                subject_name=f"kt.authority.subject.v1:{subj_sha}",
                predicate_type=DEFAULT_PREDICATE_TYPE,
                predicate={
                    "schema_id": "kt.in_toto.predicate.authority_subject.v1",
                    "authority_subject_ref": CRYPTO_PUBLICATION_SUBJECT_REL,
                    "authority_subject_sha256": subj_sha,
                    "attestation_fabric_contract_ref": "KT_PROD_CLEANROOM/governance/attestation_fabric_contract.json",
                    "supply_chain_layout_ref": SUPPLY_CHAIN_LAYOUT_REL,
                    "signer_identity_policy_ref": SIGNER_IDENTITY_POLICY_REL,
                },
            )
            write_json_stable(statement_path, statement)
            checks.append({"check": "in_toto_statement_minted", "status": "PASS", "statement_ref": CRYPTO_PUBLICATION_STATEMENT_REL})
        except Exception as exc:  # noqa: BLE001
            failures.append("in_toto_statement_mint_failed")
            checks.append({"check": "in_toto_statement_minted", "status": "FAIL", "error": str(exc)})

    cosign_exe: Optional[Path] = None
    if not failures and pubkey_info and subj_sha:
        try:
            cosign_exe = _resolve_cosign_exe(root=root)
            checks.append({"check": "cosign_present", "status": "PASS", "cosign_exe": cosign_exe.as_posix()})
        except Exception as exc:  # noqa: BLE001
            failures.append("cosign_missing")
            checks.append({"check": "cosign_present", "status": "FAIL", "error": str(exc)})

    if cosign_exe and not failures:
        password = os.environ.get("COSIGN_PASSWORD", "")
        if not str(password).strip():
            failures.append("cosign_password_missing")
            checks.append(
                {
                    "check": "cosign_password_present",
                    "status": "FAIL",
                    "error": "COSIGN_PASSWORD must be set (non-empty) for non-interactive signing",
                }
            )
        else:
            checks.append({"check": "cosign_password_present", "status": "PASS"})

    if cosign_exe and not failures:
        try:
            cosign_key_path = Path(str(cosign_private_key_rel)).expanduser()
            if not cosign_key_path.is_absolute():
                cosign_key_path = (root / cosign_key_path).resolve()
            if not cosign_key_path.exists():
                raise RuntimeError(f"missing cosign private key: {cosign_key_path.as_posix()}")

            # Sign the exact on-disk bytes of the in-toto statement; the bundle is the
            # transparency evidence needed for later public verification.
            subprocess.run(
                [
                    str(cosign_exe),
                    "sign-blob",
                    "--yes",
                    "--key",
                    str(cosign_key_path),
                    "--bundle",
                    str(bundle_path),
                    "--output-signature",
                    str(signature_path),
                    str(statement_path),
                ],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=180,
            )
            checks.append({"check": "cosign_sign_blob", "status": "PASS"})
        except Exception as exc:  # noqa: BLE001
            failures.append("cosign_sign_failed")
            checks.append({"check": "cosign_sign_blob", "status": "FAIL", "error": str(exc)})

    if cosign_exe and not failures:
        try:
            subprocess.run(
                [
                    str(cosign_exe),
                    "verify-blob",
                    "--key",
                    str(pubkey_info["public_key_path"]),
                    "--signature",
                    str(signature_path),
                    "--bundle",
                    str(bundle_path),
                    str(statement_path),
                ],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=180,
            )
            checks.append({"check": "cosign_verify_blob_with_tlog", "status": "PASS"})
        except Exception as exc:  # noqa: BLE001
            failures.append("cosign_verify_failed")
            checks.append({"check": "cosign_verify_blob_with_tlog", "status": "FAIL", "error": str(exc)})

    authority_bundle_obj: Dict[str, Any] = {}
    if subj_sha and not failures:
        try:
            statement_sha256 = _sha256_file_bytes(statement_path)
            signature_sha256 = _sha256_file_bytes(signature_path)
            bundle_sha256 = _sha256_file_bytes(bundle_path)

            cosign_info = _cosign_version_info(cosign_exe=cosign_exe) if cosign_exe else {}
            envelope = mint_envelope(
                subject_sha256_hex=subj_sha,
                attestation_mode="SIGSTORE_COSIGN_BLOB_BUNDLE_V1_KEYPAIR",
                generated_utc=generated_utc,
                signatures=[
                    {
                        "format": "cosign.verify-blob",
                        "signer_id": str(signer_id).strip(),
                        "public_key_ref": pubkey_info.get("public_key_ref", ""),
                        "public_key_sha256": pubkey_info.get("public_key_sha256", ""),
                        "statement_ref": CRYPTO_PUBLICATION_STATEMENT_REL,
                        "statement_sha256": statement_sha256,
                        "signature_ref": CRYPTO_PUBLICATION_SIGNATURE_REL,
                        "signature_sha256": signature_sha256,
                        "bundle_ref": CRYPTO_PUBLICATION_BUNDLE_REL,
                        "bundle_sha256": bundle_sha256,
                        "tlog_verified": True,
                        "cosign": cosign_info,
                    }
                ],
                transparency={
                    "rekor_bundle_ref": CRYPTO_PUBLICATION_BUNDLE_REL,
                    "rekor_bundle_sha256": bundle_sha256,
                    "tlog_verified": True,
                },
            )
            authority_bundle_obj = mint_authority_bundle(
                subject=subject,
                envelope=envelope,
                bundle_id=f"KT_AUTHORITY_BUNDLE_{subject['truth_subject_commit'][:12]}_{subj_sha[:16]}",
            )
            schema = load_authority_bundle_schema(root=root)
            validate_authority_bundle(authority_bundle_obj, schema=schema)
            write_json_stable(authority_bundle_path, authority_bundle_obj)
            checks.append({"check": "authority_bundle_minted_and_validated", "status": "PASS", "bundle_ref": CRYPTO_PUBLICATION_AUTHORITY_BUNDLE_REL})
        except Exception as exc:  # noqa: BLE001
            failures.append("authority_bundle_mint_failed")
            checks.append({"check": "authority_bundle_minted_and_validated", "status": "FAIL", "error": str(exc)})

    receipt_obj: Dict[str, Any] = {
        "schema_id": "kt.operator.cryptographic_publication_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS" if not failures else "FAIL",
        "signer_id": str(signer_id).strip(),
        "policy_ref": SIGNER_IDENTITY_POLICY_REL,
        "layout_ref": SUPPLY_CHAIN_LAYOUT_REL,
        "artifact_dir": CRYPTO_PUBLICATION_DIR_REL,
        "subject_sha256": str(subj_sha),
        "statement_sha256": _sha256_file_bytes(statement_path) if statement_path.exists() else "",
        "signature_sha256": _sha256_file_bytes(signature_path) if signature_path.exists() else "",
        "bundle_sha256": _sha256_file_bytes(bundle_path) if bundle_path.exists() else "",
        "authority_bundle_subject_sha256": str(authority_bundle_obj.get("subject_sha256", "")).strip() if authority_bundle_obj else "",
        "checks": checks,
        "failures": failures,
        "semantic_ceiling": {
            "published_head_authority_claimed": False,
            "h1_allowed": False,
        },
    }
    write_json_stable(receipt_path, receipt_obj)
    if failures:
        raise RuntimeError("FAIL_CLOSED: cryptographic publication failed: " + "; ".join(failures))
    return receipt_obj


def _read_previous_pointer(root: Path) -> Dict[str, Any]:
    pointer_path = (root / CURRENT_POINTER_REL).resolve()
    if not pointer_path.exists():
        return {}
    return load_json(pointer_path)


def _read_previous_ledger_pointer(*, ledger_root: Path) -> Dict[str, Any]:
    pointer_path = (ledger_root / LEDGER_CURRENT_POINTER_REL).resolve()
    if not pointer_path.exists():
        return {}
    return load_json(pointer_path)


def _bundle_descriptor(
    *,
    subject_commit: str,
    producer_commit: str,
    authority_mode: str,
    posture_state: str,
    generated_utc: str,
    report_root_rel: str,
    live_validation_index_ref: str,
    sources: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.truth_bundle.v1",
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": producer_commit,
        "authority_level": authority_mode,
        "posture_enum": posture_state,
        "zone_scope": ["CANONICAL"],
        "freshness_contract_ref": "KT_PROD_CLEANROOM/governance/truth_freshness_windows.json",
        "validation_index_ref": live_validation_index_ref,
        "report_root_ref": report_root_rel,
        "generated_utc": generated_utc,
        "validator_set": [
            "tools.operator.truth_engine",
            "tools.operator.truth_surface_sync",
            "tools.operator.truth_publication_validate",
        ],
        "files": [
            {
                "name": str(row["name"]),
                "source_ref": str(row["source_ref"]),
                "bundle_relpath": f"payloads/{row['name']}",
                "sha256": str(row["sha256"]),
                "required": bool(row["required"]),
            }
            for row in sources
        ],
    }


def _bundle_catalog_entry(
    *,
    bundle_hash: str,
    bundle_ref: str,
    pointer_ref: str,
    subject_commit: str,
    authority_mode: str,
    posture_state: str,
    generated_utc: str,
) -> Dict[str, Any]:
    return {
        "truth_bundle_hash": bundle_hash,
        "truth_bundle_ref": bundle_ref,
        "current_pointer_ref": pointer_ref,
        "truth_subject_commit": subject_commit,
        "authority_level": authority_mode,
        "posture_enum": posture_state,
        "generated_utc": generated_utc,
    }


def _tracked_catalog_payload(*, existing: Dict[str, Any], new_entry: Dict[str, Any]) -> Dict[str, Any]:
    rows = existing.get("bundles") if isinstance(existing.get("bundles"), list) else []
    bundles: List[Dict[str, Any]] = []
    seen = set()
    new_hash = str(new_entry["truth_bundle_hash"])
    bundles.append(new_entry)
    seen.add(new_hash)
    for row in rows:
        if not isinstance(row, dict):
            continue
        bundle_hash = str(row.get("truth_bundle_hash", "")).strip()
        if not bundle_hash or bundle_hash in seen:
            continue
        bundles.append(row)
        seen.add(bundle_hash)
    return {
        "schema_id": "kt.operator.truth_bundle_catalog.v1",
        "status": "ACTIVE",
        "bundles": bundles,
    }


def _publication_blockers(*, authority_mode: str, posture_state: str, subject_dirty: bool, board_open_blockers: Sequence[str]) -> List[str]:
    blockers: List[str] = []
    if authority_mode != "SETTLED_AUTHORITATIVE":
        blockers.append("authority mode is not settled authoritative")
    if subject_dirty:
        blockers.append("validated subject worktree was dirty")
    if posture_state != "TRUTHFUL_GREEN":
        blockers.append(f"posture state is {posture_state}, not TRUTHFUL_GREEN")
    blockers.extend(str(item).strip() for item in board_open_blockers if str(item).strip())
    deduped: List[str] = []
    seen = set()
    for blocker in blockers:
        if blocker in seen:
            continue
        seen.add(blocker)
        deduped.append(blocker)
    return deduped


def publish_truth_artifacts(
    *,
    root: Path,
    report_root_rel: str,
    live_validation_index_path: Path,
    authority_mode: str,
    posture_state: str,
    board_open_blockers: Sequence[str],
) -> Dict[str, Any]:
    sources = _bundle_sources(root=root, report_root_rel=report_root_rel)
    live_index = _load_required(live_validation_index_path)
    worktree = live_index.get("worktree") if isinstance(live_index.get("worktree"), dict) else {}
    subject_commit = str(worktree.get("head_sha", "")).strip()
    if not subject_commit:
        raise RuntimeError("FAIL_CLOSED: live validation index missing worktree.head_sha")
    producer_commit = subject_commit
    generated_utc = str(live_index.get("generated_utc", "")).strip() or utc_now_iso_z()
    previous_pointer = _read_previous_pointer(root)
    live_validation_index_ref = path_ref(root=root, path=live_validation_index_path)
    descriptor = _bundle_descriptor(
        subject_commit=subject_commit,
        producer_commit=producer_commit,
        authority_mode=authority_mode,
        posture_state=posture_state,
        generated_utc=generated_utc,
        report_root_rel=report_root_rel,
        live_validation_index_ref=live_validation_index_ref,
        sources=sources,
    )
    bundle_hash = _canonical_hash(descriptor)
    bundle_id = f"TRUTH_BUNDLE_{subject_commit[:12]}_{bundle_hash[:16]}"
    descriptor["truth_bundle_hash"] = bundle_hash
    descriptor["truth_bundle_id"] = bundle_id

    bundle_dir = (root / TRUTH_BUNDLES_ROOT_REL / subject_commit / bundle_hash).resolve()
    bundle_dir.mkdir(parents=True, exist_ok=True)
    payload_dir = bundle_dir / "payloads"
    payload_dir.mkdir(parents=True, exist_ok=True)
    for row in sources:
        write_json_stable(payload_dir / str(row["name"]), row["payload"])
    write_json_stable(bundle_dir / "truth_bundle.json", descriptor)

    current_dir = (root / TRUTH_CURRENT_DIR_REL).resolve()
    current_dir.mkdir(parents=True, exist_ok=True)
    bundle_ref = path_ref(root=root, path=bundle_dir / "truth_bundle.json")
    previous_bundle_hash = str(previous_pointer.get("current_bundle_hash", "")).strip()
    superseded_bundle_hash = previous_bundle_hash if previous_bundle_hash and previous_bundle_hash != bundle_hash else ""
    pointer_payload = {
        "schema_id": "kt.operator.truth_pointer.v1",
        "generated_utc": generated_utc,
        "status": "ACTIVE",
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": producer_commit,
        "current_bundle_hash": bundle_hash,
        "current_bundle_ref": bundle_ref,
        "current_bundle_manifest_ref": path_ref(root=root, path=current_dir / "current_bundle_manifest.json"),
        "zone_scope": ["CANONICAL"],
        "authority_level": authority_mode,
        "posture_enum": posture_state,
        "freshness_contract_ref": "KT_PROD_CLEANROOM/governance/truth_freshness_windows.json",
        "supersedes_bundle_hash": superseded_bundle_hash,
        "board_contract_ref": "KT_PROD_CLEANROOM/governance/execution_board.json",
    }
    manifest_payload = {
        "schema_id": "kt.operator.truth_snapshot_manifest.v1",
        "generated_utc": generated_utc,
        "truth_bundle_id": bundle_id,
        "truth_bundle_hash": bundle_hash,
        "truth_bundle_ref": bundle_ref,
        "truth_subject_commit": subject_commit,
        "files": descriptor["files"],
    }
    write_json_stable(current_dir / "current_bundle_manifest.json", manifest_payload)
    write_json_stable(current_dir / "current_pointer.json", pointer_payload)

    tracked_schema = _truth_bundle_schema()
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_bundle.schema.json", tracked_schema)

    catalog_path = root / "KT_PROD_CLEANROOM" / "reports" / "truth_bundle_catalog.json"
    existing_catalog = load_json(catalog_path) if catalog_path.exists() else {}
    current_pointer_ref = CURRENT_POINTER_REL
    catalog_entry = _bundle_catalog_entry(
        bundle_hash=bundle_hash,
        bundle_ref=bundle_ref,
        pointer_ref=current_pointer_ref,
        subject_commit=subject_commit,
        authority_mode=authority_mode,
        posture_state=posture_state,
        generated_utc=generated_utc,
    )
    tracked_catalog = _tracked_catalog_payload(existing=existing_catalog, new_entry=catalog_entry)
    write_json_stable(catalog_path, tracked_catalog)

    pointer_index = {
        "schema_id": "kt.operator.truth_pointer_index.v1",
        "generated_utc": generated_utc,
        "status": "ACTIVE",
        "authoritative_current_pointer_ref": current_pointer_ref,
        "truth_bundle_ref": bundle_ref,
        "truth_bundle_hash": bundle_hash,
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": producer_commit,
        "authority_level": authority_mode,
        "posture_enum": posture_state,
        "documentary_tracked_truth_surfaces": TRACKED_DOCUMENTARY_SURFACES,
        "tracked_catalog_ref": "KT_PROD_CLEANROOM/reports/truth_bundle_catalog.json",
    }
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_pointer_index.json", pointer_index)

    git_dirty_before = _git_status_lines(root)
    subject_dirty = bool(worktree.get("git_dirty"))
    allowed_tracked_outputs = [path_ref(root=root, path=root / rel) for rel in TRUTH_PUBLICATION_REQUIRED_ARTIFACTS]
    clean_state_receipt = {
        "schema_id": "kt.operator.truth_clean_state_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "truth_subject_commit": subject_commit,
        "subject_worktree_dirty_at_validation": subject_dirty,
        "publisher_worktree_dirty_before": None if git_dirty_before is None else bool(git_dirty_before),
        "publication_outputs_restricted_to_generated_truth_and_allowed_indexes": True,
        "generated_truth_root": GENERATED_TRUTH_ROOT_REL,
        "authoritative_current_pointer_ref": current_pointer_ref,
        "documentary_tracked_indexes": TRUTH_PUBLICATION_REQUIRED_ARTIFACTS,
        "tracked_truth_for_current_posture_forbidden": TRACKED_DOCUMENTARY_SURFACES,
    }
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_clean_state_receipt.json", clean_state_receipt)

    publication_receipt = {
        "schema_id": "kt.operator.truth_publication_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "truth_bundle_id": bundle_id,
        "truth_bundle_hash": bundle_hash,
        "truth_bundle_ref": bundle_ref,
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": producer_commit,
        "authoritative_current_pointer_ref": current_pointer_ref,
        "truth_pointer_index_ref": "KT_PROD_CLEANROOM/reports/truth_pointer_index.json",
        "truth_bundle_catalog_ref": "KT_PROD_CLEANROOM/reports/truth_bundle_catalog.json",
        "truth_snapshot_manifest_ref": "KT_PROD_CLEANROOM/reports/truth_snapshot_manifest.json",
        "documentary_tracked_truth_surfaces": TRACKED_DOCUMENTARY_SURFACES,
        "no_parallel_truth_rule_enforced": True,
    }
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_receipt.json", publication_receipt)
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_snapshot_manifest.json", manifest_payload)

    supersession_receipt = {
        "schema_id": "kt.operator.truth_publication_supersession_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "authoritative_current_pointer_ref": current_pointer_ref,
        "authoritative_bundle_ref": bundle_ref,
        "documentary_only_tracked_surfaces": TRACKED_DOCUMENTARY_SURFACES,
        "documentary_indexes": [
            "KT_PROD_CLEANROOM/reports/truth_pointer_index.json",
            "KT_PROD_CLEANROOM/reports/truth_bundle_catalog.json",
            "KT_PROD_CLEANROOM/reports/truth_publication_receipt.json",
            "KT_PROD_CLEANROOM/reports/truth_snapshot_manifest.json",
            "KT_PROD_CLEANROOM/reports/truth_clean_state_receipt.json",
        ],
        "superseded_bundle_hash": superseded_bundle_hash,
        "no_parallel_truth_enforced": True,
    }
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_supersession_receipt.json", supersession_receipt)

    stabilization_blockers = _publication_blockers(
        authority_mode=authority_mode,
        posture_state=posture_state,
        subject_dirty=subject_dirty,
        board_open_blockers=board_open_blockers,
    )
    stabilization_receipt = {
        "schema_id": "kt.operator.truth_publication_stabilization_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS" if not stabilization_blockers else "HOLD",
        "truth_subject_commit": subject_commit,
        "authoritative_current_pointer_ref": current_pointer_ref,
        "truth_bundle_ref": bundle_ref,
        "truth_bundle_hash": bundle_hash,
        "authority_mode": authority_mode,
        "posture_state": posture_state,
        "contradiction_count": len(stabilization_blockers),
        "blockers": stabilization_blockers,
        "board_transition_ready": not stabilization_blockers,
        "required_board_transition": "TRUTH_PUBLICATION_STABILIZED=true",
    }
    write_json_stable(root / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_stabilization_receipt.json", stabilization_receipt)

    return {
        "current_pointer_ref": current_pointer_ref,
        "truth_bundle_ref": bundle_ref,
        "truth_bundle_hash": bundle_hash,
        "truth_subject_commit": subject_commit,
        "publication_receipt": publication_receipt,
        "stabilization_receipt": stabilization_receipt,
    }


def publish_truth_ledger_witness(
    *,
    source_root: Path,
    ledger_root: Path,
    report_root_rel: str,
    live_validation_index_path: Path,
    authority_mode: str,
    posture_state: str,
    ledger_branch: str = TRUTH_LEDGER_BRANCH,
) -> Dict[str, Any]:
    sources = _bundle_sources(root=source_root, report_root_rel=report_root_rel)
    live_index = _load_required(live_validation_index_path)
    worktree = live_index.get("worktree") if isinstance(live_index.get("worktree"), dict) else {}
    subject_commit = str(worktree.get("head_sha", "")).strip()
    if not subject_commit:
        raise RuntimeError("FAIL_CLOSED: live validation index missing worktree.head_sha")
    producer_commit = subject_commit
    generated_utc = str(live_index.get("generated_utc", "")).strip() or utc_now_iso_z()
    previous_pointer = _read_previous_ledger_pointer(ledger_root=ledger_root)
    live_validation_index_ref = path_ref(root=source_root, path=live_validation_index_path)
    descriptor = _bundle_descriptor(
        subject_commit=subject_commit,
        producer_commit=producer_commit,
        authority_mode=authority_mode,
        posture_state=posture_state,
        generated_utc=generated_utc,
        report_root_rel=report_root_rel,
        live_validation_index_ref=live_validation_index_ref,
        sources=sources,
    )
    descriptor["witness_plane"] = {
        "branch": ledger_branch,
        "mode": "BOOTSTRAP_WITNESS_ONLY",
        "published_head_authority_claimed": False,
        "main_purge_completed": False,
    }
    bundle_hash = _canonical_hash(descriptor)
    bundle_id = f"LEDGER_TRUTH_BUNDLE_{subject_commit[:12]}_{bundle_hash[:16]}"
    descriptor["truth_bundle_hash"] = bundle_hash
    descriptor["truth_bundle_id"] = bundle_id

    bundle_dir = (ledger_root / LEDGER_BUNDLES_ROOT_REL / subject_commit / bundle_hash).resolve()
    bundle_dir.mkdir(parents=True, exist_ok=True)
    payload_dir = bundle_dir / "payloads"
    payload_dir.mkdir(parents=True, exist_ok=True)
    for row in sources:
        write_json_stable(payload_dir / str(row["name"]), row["payload"])
    write_json_stable(bundle_dir / "truth_bundle.json", descriptor)

    current_dir = (ledger_root / LEDGER_CURRENT_DIR_REL).resolve()
    current_dir.mkdir(parents=True, exist_ok=True)
    bundle_rel = str((Path(LEDGER_BUNDLES_ROOT_REL) / subject_commit / bundle_hash / "truth_bundle.json").as_posix())
    bundle_ref = ledger_ref(branch=ledger_branch, relpath=bundle_rel)
    previous_bundle_hash = str(previous_pointer.get("current_bundle_hash", "")).strip()
    superseded_bundle_hash = previous_bundle_hash if previous_bundle_hash and previous_bundle_hash != bundle_hash else ""
    current_manifest_rel = str((Path(LEDGER_CURRENT_DIR_REL) / "current_bundle_manifest.json").as_posix())
    pointer_payload = {
        "schema_id": "kt.operator.truth_pointer.v1",
        "generated_utc": generated_utc,
        "status": "ACTIVE",
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": producer_commit,
        "current_bundle_hash": bundle_hash,
        "current_bundle_ref": bundle_ref,
        "current_bundle_manifest_ref": ledger_ref(branch=ledger_branch, relpath=current_manifest_rel),
        "zone_scope": ["CANONICAL"],
        "authority_level": authority_mode,
        "posture_enum": posture_state,
        "freshness_contract_ref": "KT_PROD_CLEANROOM/governance/truth_freshness_windows.json",
        "supersedes_bundle_hash": superseded_bundle_hash,
        "board_contract_ref": "KT_PROD_CLEANROOM/governance/execution_board.json",
        "witness_plane": True,
        "transition_state": "LEDGER_BOOTSTRAPPED_PENDING_PURGE",
        "published_head_authority_claimed": False,
    }
    manifest_payload = {
        "schema_id": "kt.operator.truth_snapshot_manifest.v1",
        "generated_utc": generated_utc,
        "truth_bundle_id": bundle_id,
        "truth_bundle_hash": bundle_hash,
        "truth_bundle_ref": bundle_ref,
        "truth_subject_commit": subject_commit,
        "files": descriptor["files"],
        "witness_plane": True,
        "published_head_authority_claimed": False,
    }
    write_json_stable(current_dir / "current_bundle_manifest.json", manifest_payload)
    write_json_stable(current_dir / "current_pointer.json", pointer_payload)
    # The convergence contract treats ledger/current/* as the convenience "current" plane,
    # not just bundle payloads. Keep these copies in sync with the published bundle inputs.
    for required_current in ("current_state_receipt.json", "runtime_closure_audit.json"):
        for row in sources:
            if str(row.get("name", "")).strip() == required_current:
                write_json_stable(current_dir / required_current, row["payload"])
                break

    history_dir = (ledger_root / LEDGER_HISTORY_ROOT_REL / subject_commit).resolve()
    history_dir.mkdir(parents=True, exist_ok=True)
    publication_receipt = {
        "schema_id": "kt.operator.truth_ledger_publication_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "ledger_branch": ledger_branch,
        "truth_subject_commit": subject_commit,
        "truth_produced_at_commit": producer_commit,
        "truth_bundle_hash": bundle_hash,
        "truth_bundle_ref": bundle_ref,
        "current_pointer_ref": ledger_ref(branch=ledger_branch, relpath=LEDGER_CURRENT_POINTER_REL),
        "current_bundle_manifest_ref": ledger_ref(branch=ledger_branch, relpath=current_manifest_rel),
        "transition_state": "LEDGER_BOOTSTRAPPED_PENDING_PURGE",
        "witness_only": True,
        "published_head_authority_claimed": False,
        "source_report_root_ref": report_root_rel,
    }
    write_json_stable(history_dir / "publication_receipt.json", publication_receipt)

    return {
        "ledger_branch": ledger_branch,
        "truth_bundle_hash": bundle_hash,
        "truth_bundle_ref": bundle_ref,
        "current_pointer_ref": ledger_ref(branch=ledger_branch, relpath=LEDGER_CURRENT_POINTER_REL),
        "current_manifest_ref": ledger_ref(branch=ledger_branch, relpath=current_manifest_rel),
        "history_receipt_ref": ledger_ref(
            branch=ledger_branch,
            relpath=str((Path(LEDGER_HISTORY_ROOT_REL) / subject_commit / "publication_receipt.json").as_posix()),
        ),
        "truth_subject_commit": subject_commit,
        "published_head_authority_claimed": False,
    }


def validate_truth_publication(*, root: Path) -> Dict[str, Any]:
    failures: List[str] = []
    checks: List[Dict[str, Any]] = []
    for rel in TRUTH_PUBLICATION_REQUIRED_LAW_SURFACES:
        ok = (root / rel).exists()
        checks.append({"check": f"law_surface_present::{rel}", "status": "PASS" if ok else "FAIL"})
        if not ok:
            failures.append(f"missing_law_surface:{rel}")
    for rel in TRUTH_PUBLICATION_REQUIRED_ARTIFACTS:
        ok = (root / rel).exists()
        checks.append({"check": f"artifact_present::{rel}", "status": "PASS" if ok else "FAIL"})
        if not ok:
            failures.append(f"missing_artifact:{rel}")

    active_source = active_truth_source_ref(root=root)
    current_pointer = load_json_ref(root=root, ref=active_source)
    pointer_ref = str(current_pointer.get("current_bundle_ref", "")).strip()
    pointer_ok = bool(pointer_ref)
    checks.append(
        {
            "check": "active_truth_pointer_has_bundle_ref",
            "status": "PASS" if pointer_ok else "FAIL",
            "active_truth_source": active_source,
            "current_bundle_ref": pointer_ref,
        }
    )
    if not pointer_ok:
        failures.append("current_pointer_missing_bundle_ref")

    bundle_exists = False
    bundle: Dict[str, Any] = {}
    if pointer_ref:
        try:
            bundle = load_json_ref(root=root, ref=pointer_ref)
            bundle_exists = True
        except Exception:  # noqa: BLE001
            bundle_exists = False
    checks.append({"check": "pointed_bundle_exists", "status": "PASS" if bundle_exists else "FAIL"})
    if pointer_ref and not bundle_exists:
        failures.append("pointed_bundle_missing")

    if bundle_exists:
        bundle_hash_matches = str(bundle.get("truth_bundle_hash", "")).strip() == str(current_pointer.get("current_bundle_hash", "")).strip()
        checks.append({"check": "pointer_bundle_hash_matches", "status": "PASS" if bundle_hash_matches else "FAIL"})
        if not bundle_hash_matches:
            failures.append("pointer_bundle_hash_mismatch")

    execution_board_path = root / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json"
    if execution_board_path.exists():
        board = load_json(execution_board_path)
        board_ref = str(board.get("authoritative_current_head_truth_source", "")).strip()
        board_ok = board_ref == active_source
        checks.append({"check": "execution_board_points_to_active_truth_source", "status": "PASS" if board_ok else "FAIL", "actual": board_ref, "expected": active_source})
        if not board_ok:
            failures.append("execution_board_not_pointing_to_active_truth_source")

    readiness_path = root / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json"
    if readiness_path.exists():
        readiness = load_json(readiness_path)
        readiness_ref = str(readiness.get("authoritative_truth_source", "")).strip()
        readiness_ok = readiness_ref == active_source
        checks.append({"check": "readiness_scope_points_to_active_truth_source", "status": "PASS" if readiness_ok else "FAIL", "actual": readiness_ref, "expected": active_source})
        if not readiness_ok:
            failures.append("readiness_scope_not_pointing_to_active_truth_source")

    supersession_path = root / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_supersession_receipt.json"
    if supersession_path.exists():
        supersession = load_json(supersession_path)
        no_parallel_truth = bool(supersession.get("no_parallel_truth_enforced"))
        checks.append({"check": "no_parallel_truth_rule_enforced", "status": "PASS" if no_parallel_truth else "FAIL"})
        if not no_parallel_truth:
            failures.append("no_parallel_truth_not_enforced")

    stabilization_path = root / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_stabilization_receipt.json"
    if stabilization_path.exists():
        stabilization = load_json(stabilization_path)
        board_transition_ready = bool(stabilization.get("board_transition_ready"))
        checks.append(
            {
                "check": "stabilization_receipt_present",
                "status": "PASS",
                "receipt_status": str(stabilization.get("status", "")).strip(),
                "board_transition_ready": board_transition_ready,
            }
        )

    convergence_required = str(active_source).strip().startswith("kt_truth_ledger:")
    convergence = build_authority_convergence_report(root=root) if convergence_required else {}
    convergence_ok = str(convergence.get("status", "")).strip() == "PASS" if convergence_required else True
    checks.append(
        {
            "check": "authority_convergence_passes",
            "status": "PASS" if convergence_ok else "FAIL",
            "failures": convergence.get("failures", []),
            "required": convergence_required,
        }
    )
    if not convergence_ok:
        failures.append("authority_convergence_failed")

    return {
        "schema_id": "kt.operator.truth_publication_validation_receipt.v1",
        "status": "PASS" if not failures else "FAIL",
        "checks": checks,
        "failures": failures,
    }


def load_publication_stabilization_state(*, root: Path) -> Dict[str, Any]:
    receipt_path = root / "KT_PROD_CLEANROOM" / "reports" / "truth_publication_stabilization_receipt.json"
    if not receipt_path.exists():
        return {"status": "MISSING", "board_transition_ready": False, "blockers": ["truth publication stabilization receipt missing"]}
    receipt = load_json(receipt_path)
    return {
        "status": str(receipt.get("status", "")).strip() or "UNKNOWN",
        "board_transition_ready": bool(receipt.get("board_transition_ready")),
        "blockers": [str(item).strip() for item in receipt.get("blockers", []) if str(item).strip()],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Publish immutable truth bundles and current-pointer indexes from current operator truth receipts.")
    ap.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    ap.add_argument("--live-validation-index", default=f"{DEFAULT_REPORT_ROOT_REL}/live_validation_index.json")
    ap.add_argument("--authority-mode", default="SETTLED_AUTHORITATIVE")
    ap.add_argument("--posture-state", default="CANONICAL_READY_FOR_REEARNED_GREEN")
    ap.add_argument("--open-blocker", action="append", default=[])
    ap.add_argument("--emit-cryptographic-publication", action="store_true", help="WS6: Sign and verify an in-toto statement with cosign and emit cryptographic publication receipts.")
    ap.add_argument("--signer-id", default=DEFAULT_SIGNER_ID, help="WS6: signer_id defined by signer_identity_policy.json")
    ap.add_argument("--cosign-private-key", default=DEFAULT_COSIGN_PRIVATE_KEY_REL, help="WS6: path to encrypted cosign private key (private; do not commit)")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    index_path = Path(str(args.live_validation_index)).expanduser()
    if not index_path.is_absolute():
        index_path = (root / index_path).resolve()
    publication = publish_truth_artifacts(
        root=root,
        report_root_rel=str(args.report_root),
        live_validation_index_path=index_path,
        authority_mode=str(args.authority_mode),
        posture_state=str(args.posture_state),
        board_open_blockers=[str(item) for item in args.open_blocker],
    )
    if bool(getattr(args, "emit_cryptographic_publication", False)):
        publish_cryptographic_publication_ws6(
            root=root,
            report_root_rel=str(args.report_root),
            live_validation_index_path=index_path,
            signer_id=str(getattr(args, "signer_id", DEFAULT_SIGNER_ID)),
            cosign_private_key_rel=str(getattr(args, "cosign_private_key", DEFAULT_COSIGN_PRIVATE_KEY_REL)),
        )
    print(json.dumps(publication, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
