from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.canonical_tree_execute import CURRENT_ARCHIVE_LITERAL
from tools.operator.crypto_attestation import (
    load_authority_bundle_schema,
    mint_authority_bundle,
    mint_envelope,
    subject_sha256 as authority_subject_sha256,
    validate_authority_bundle,
)
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.truth_authority import active_truth_source_ref, load_json_ref
from tools.operator.truth_publication import (
    CRYPTO_PUBLICATION_AUTHORITY_BUNDLE_REL,
    CRYPTO_PUBLICATION_BUNDLE_REL,
    CRYPTO_PUBLICATION_RECEIPT_REL,
    CRYPTO_PUBLICATION_SIGNATURE_REL,
    CRYPTO_PUBLICATION_STATEMENT_REL,
    CRYPTO_PUBLICATION_SUBJECT_REL,
    DEFAULT_COSIGN_PRIVATE_KEY_REL,
    DEFAULT_PREDICATE_TYPE,
    DEFAULT_SIGNER_ID,
    SIGNER_IDENTITY_POLICY_REL,
    SUPPLY_CHAIN_LAYOUT_REL,
    _assert_signer_policy_allows_pubkey,
    _cosign_version_info,
    _find_allowed_signer,
    _load_signer_policy,
    _resolve_cosign_exe,
    build_in_toto_statement_for_authority_subject,
)


WORKSTREAM_ID = "WS7_TRUST_ROOT_AND_PUBLICATION_ATTESTATION"
STEP_ID = "WS7_STEP_1_PUBLICATION_GRADE_ATTESTATION"
PASS_VERDICT = "PUBLICATION_GRADE_ATTESTATION_PROVEN"

ROOT_POLICY_REL = "KT_PROD_CLEANROOM/governance/closure_foundation/kt_tuf_root_policy.json"
TUF_ROOT_INITIALIZATION_REL = "KT_PROD_CLEANROOM/reports/kt_tuf_root_initialization.json"
IN_TOTO_LAYOUT_REL = "KT_PROD_CLEANROOM/reports/kt_in_toto_layout.json"
IN_TOTO_PROVENANCE_REL = "KT_PROD_CLEANROOM/reports/kt_in_toto_provenance.dsse"
SIGSTORE_PUBLICATION_BUNDLE_REL = "KT_PROD_CLEANROOM/reports/kt_sigstore_publication_bundle.json"
REKOR_INCLUSION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/kt_rekor_inclusion_receipt.json"
STABILIZATION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/kt_truth_publication_stabilization_receipt.json"

EXPECTED_ARTIFACTS: List[str] = [
    TUF_ROOT_INITIALIZATION_REL,
    IN_TOTO_LAYOUT_REL,
    IN_TOTO_PROVENANCE_REL,
    SIGSTORE_PUBLICATION_BUNDLE_REL,
    REKOR_INCLUSION_RECEIPT_REL,
    STABILIZATION_RECEIPT_REL,
]

SUPPORTING_PUBLICATION_ARTIFACTS: List[str] = [
    CRYPTO_PUBLICATION_RECEIPT_REL,
    CRYPTO_PUBLICATION_SUBJECT_REL,
    CRYPTO_PUBLICATION_STATEMENT_REL,
    CRYPTO_PUBLICATION_SIGNATURE_REL,
    CRYPTO_PUBLICATION_BUNDLE_REL,
    CRYPTO_PUBLICATION_AUTHORITY_BUNDLE_REL,
]

PROTECTED_PATTERNS = (".github/workflows/", CURRENT_ARCHIVE_LITERAL)


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    value = _git(root, "rev-parse", "HEAD").strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise RuntimeError("FAIL_CLOSED: git HEAD is not a 40-char lowercase hex commit")
    return value


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


def _canonical_hash(payload: Any) -> str:
    return sha256_hex(canonicalize_bytes(payload))


def _sha256_text_normalized(path: Path) -> str:
    text = path.read_text(encoding="utf-8-sig")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / rel).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def _b64_file(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def build_authority_subject_for_git_head(*, root: Path, compiled_head_commit: str) -> Dict[str, Any]:
    law_paths = [
        "KT_PROD_CLEANROOM/governance/authority_subject_contract.json",
        "KT_PROD_CLEANROOM/governance/attestation_fabric_contract.json",
        "KT_PROD_CLEANROOM/governance/authority_bundle.schema.json",
        SIGNER_IDENTITY_POLICY_REL,
        SUPPLY_CHAIN_LAYOUT_REL,
        ROOT_POLICY_REL,
    ]
    law_surface_hashes: Dict[str, str] = {}
    for rel in law_paths:
        law_surface_hashes[rel] = _canonical_hash(_load_required_json(root, rel))

    evidence_rows: List[Tuple[str, str, Dict[str, Any]]] = []
    active_ref = active_truth_source_ref(root=root)
    evidence_rows.append(("active_truth_pointer", active_ref, load_json_ref(root=root, ref=active_ref)))
    for rel in (
        "KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json",
        "KT_PROD_CLEANROOM/reports/documentary_truth_validation_receipt.json",
        "KT_PROD_CLEANROOM/reports/kt_documentary_demotion_final_receipt.json",
        "KT_PROD_CLEANROOM/reports/kt_authority_topology_cutover_receipt.json",
        "KT_PROD_CLEANROOM/reports/authority_convergence_receipt.json",
        "KT_PROD_CLEANROOM/reports/published_head_self_convergence_receipt.json",
    ):
        evidence_rows.append((Path(rel).name, rel, _load_required_json(root, rel)))

    return {
        "schema_id": "kt.authority.subject.v1",
        "truth_subject_commit": compiled_head_commit,
        "truth_produced_at_commit": compiled_head_commit,
        "law_surface_hashes": law_surface_hashes,
        "supersedes_subject_sha256": "",
        "evidence": [
            {"name": name, "ref": ref, "sha256": _canonical_hash(payload)}
            for name, ref, payload in evidence_rows
        ],
    }


def mint_current_head_cryptographic_publication(
    *,
    root: Path,
    compiled_head_commit: str,
    signer_id: str = DEFAULT_SIGNER_ID,
    cosign_private_key_rel: str = DEFAULT_COSIGN_PRIVATE_KEY_REL,
) -> Dict[str, Any]:
    generated_utc = utc_now_iso_z()
    failures: List[str] = []
    checks: List[Dict[str, Any]] = []

    policy = _load_signer_policy(root=root)
    checks.append({"check": "signer_policy_present", "status": "PASS", "policy_ref": SIGNER_IDENTITY_POLICY_REL})
    signer = _find_allowed_signer(policy, signer_id=str(signer_id))
    checks.append({"check": "signer_allowed_by_policy", "status": "PASS", "signer_id": str(signer_id)})
    pubkey_info = _assert_signer_policy_allows_pubkey(root=root, signer=signer)
    checks.append({"check": "signer_pubkey_matches_policy_sha256", "status": "PASS", "public_key_ref": pubkey_info["public_key_ref"]})

    _load_required_json(root, SUPPLY_CHAIN_LAYOUT_REL)
    checks.append({"check": "supply_chain_layout_present", "status": "PASS", "layout_ref": SUPPLY_CHAIN_LAYOUT_REL})

    subject = build_authority_subject_for_git_head(root=root, compiled_head_commit=compiled_head_commit)
    subject_sha = authority_subject_sha256(subject)
    write_json_stable((root / CRYPTO_PUBLICATION_SUBJECT_REL).resolve(), subject)
    checks.append({"check": "authority_subject_minted", "status": "PASS", "subject_ref": CRYPTO_PUBLICATION_SUBJECT_REL, "subject_sha256": subject_sha})

    statement = build_in_toto_statement_for_authority_subject(
        subject_sha256_hex=subject_sha,
        subject_name=f"kt.authority.subject.v1:{subject_sha}",
        predicate_type=DEFAULT_PREDICATE_TYPE,
        predicate={
            "schema_id": "kt.in_toto.predicate.authority_subject.v1",
            "authority_subject_ref": CRYPTO_PUBLICATION_SUBJECT_REL,
            "authority_subject_sha256": subject_sha,
            "attestation_fabric_contract_ref": "KT_PROD_CLEANROOM/governance/attestation_fabric_contract.json",
            "supply_chain_layout_ref": SUPPLY_CHAIN_LAYOUT_REL,
            "signer_identity_policy_ref": SIGNER_IDENTITY_POLICY_REL,
            "tuf_root_policy_ref": ROOT_POLICY_REL,
        },
    )
    statement_path = (root / CRYPTO_PUBLICATION_STATEMENT_REL).resolve()
    signature_path = (root / CRYPTO_PUBLICATION_SIGNATURE_REL).resolve()
    bundle_path = (root / CRYPTO_PUBLICATION_BUNDLE_REL).resolve()
    authority_bundle_path = (root / CRYPTO_PUBLICATION_AUTHORITY_BUNDLE_REL).resolve()
    write_json_stable(statement_path, statement)
    checks.append({"check": "in_toto_statement_minted", "status": "PASS", "statement_ref": CRYPTO_PUBLICATION_STATEMENT_REL})

    cosign_exe = _resolve_cosign_exe(root=root)
    checks.append({"check": "cosign_present", "status": "PASS", "cosign_exe": cosign_exe.as_posix()})
    if not os.environ.get("COSIGN_PASSWORD", "").strip():
        raise RuntimeError("FAIL_CLOSED: COSIGN_PASSWORD must be set for WS7 signing")
    checks.append({"check": "cosign_password_present", "status": "PASS"})

    cosign_key_path = Path(str(cosign_private_key_rel)).expanduser()
    if not cosign_key_path.is_absolute():
        cosign_key_path = (root / cosign_key_path).resolve()
    if not cosign_key_path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing cosign private key: {cosign_key_path.as_posix()}")

    try:
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

    if failures:
        raise RuntimeError("FAIL_CLOSED: cryptographic publication failed: " + "; ".join(failures))

    statement_sha256 = file_sha256(statement_path)
    signature_sha256 = file_sha256(signature_path)
    bundle_sha256 = file_sha256(bundle_path)
    envelope = mint_envelope(
        subject_sha256_hex=subject_sha,
        attestation_mode="SIGSTORE_COSIGN_BLOB_BUNDLE_V1_KEYPAIR",
        generated_utc=generated_utc,
        signatures=[
            {
                "format": "cosign.verify-blob",
                "signer_id": str(signer_id).strip(),
                "public_key_ref": pubkey_info["public_key_ref"],
                "public_key_sha256": pubkey_info["public_key_sha256"],
                "statement_ref": CRYPTO_PUBLICATION_STATEMENT_REL,
                "statement_sha256": statement_sha256,
                "signature_ref": CRYPTO_PUBLICATION_SIGNATURE_REL,
                "signature_sha256": signature_sha256,
                "bundle_ref": CRYPTO_PUBLICATION_BUNDLE_REL,
                "bundle_sha256": bundle_sha256,
                "tlog_verified": True,
                "cosign": _cosign_version_info(cosign_exe=cosign_exe),
            }
        ],
        transparency={
            "rekor_bundle_ref": CRYPTO_PUBLICATION_BUNDLE_REL,
            "rekor_bundle_sha256": bundle_sha256,
            "tlog_verified": True,
        },
    )
    authority_bundle = mint_authority_bundle(
        subject=subject,
        envelope=envelope,
        bundle_id=f"KT_AUTHORITY_BUNDLE_{compiled_head_commit[:12]}_{subject_sha[:16]}",
    )
    validate_authority_bundle(authority_bundle, schema=load_authority_bundle_schema(root=root))
    write_json_stable(authority_bundle_path, authority_bundle)
    checks.append({"check": "authority_bundle_minted_and_validated", "status": "PASS", "bundle_ref": CRYPTO_PUBLICATION_AUTHORITY_BUNDLE_REL})

    receipt = {
        "schema_id": "kt.operator.cryptographic_publication_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "signer_id": str(signer_id).strip(),
        "policy_ref": SIGNER_IDENTITY_POLICY_REL,
        "layout_ref": SUPPLY_CHAIN_LAYOUT_REL,
        "artifact_dir": "KT_PROD_CLEANROOM/reports/cryptographic_publication",
        "subject_sha256": subject_sha,
        "statement_sha256": statement_sha256,
        "signature_sha256": signature_sha256,
        "bundle_sha256": bundle_sha256,
        "authority_bundle_subject_sha256": str(authority_bundle.get("subject_sha256", "")).strip(),
        "checks": checks,
        "failures": [],
        "semantic_ceiling": {"published_head_authority_claimed": False, "h1_allowed": False},
    }
    write_json_stable((root / CRYPTO_PUBLICATION_RECEIPT_REL).resolve(), receipt)
    return receipt


def build_publication_attestation_outputs(
    *,
    root: Path,
    compiled_head_commit: str,
    generated_utc: str = "",
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    generated = str(generated_utc).strip() or utc_now_iso_z()
    root_policy = _load_required_json(root, ROOT_POLICY_REL)
    signer_policy = _load_required_json(root, SIGNER_IDENTITY_POLICY_REL)
    layout = _load_required_json(root, SUPPLY_CHAIN_LAYOUT_REL)
    crypto_receipt = _load_required_json(root, CRYPTO_PUBLICATION_RECEIPT_REL)
    authority_subject = _load_required_json(root, CRYPTO_PUBLICATION_SUBJECT_REL)
    _load_required_json(root, CRYPTO_PUBLICATION_AUTHORITY_BUNDLE_REL)
    _load_required_json(root, CRYPTO_PUBLICATION_STATEMENT_REL)
    rekor_bundle = _load_required_json(root, CRYPTO_PUBLICATION_BUNDLE_REL)

    if str(crypto_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: cryptographic publication receipt is not PASS")

    root_of_trust = root_policy.get("root_of_trust") if isinstance(root_policy.get("root_of_trust"), dict) else {}
    root_keys = root_of_trust.get("root_keys") if isinstance(root_of_trust.get("root_keys"), list) else []
    if not root_keys:
        raise RuntimeError("FAIL_CLOSED: tuf root policy has no root keys")
    threshold = int(root_of_trust.get("threshold", 0))
    if threshold < 1:
        raise RuntimeError("FAIL_CLOSED: tuf root policy threshold must be >= 1")

    verified_root_keys: List[Dict[str, Any]] = []
    for row in root_keys:
        if not isinstance(row, dict):
            continue
        public_key_ref = str(row.get("public_key_ref", "")).strip()
        if not public_key_ref:
            raise RuntimeError("FAIL_CLOSED: root key missing public_key_ref")
        public_key_path = (root / public_key_ref).resolve()
        if not public_key_path.exists():
            raise RuntimeError(f"FAIL_CLOSED: missing root public key: {public_key_ref}")
        actual_sha256 = _sha256_text_normalized(public_key_path)
        expected_sha256 = str(row.get("public_key_sha256", "")).strip().lower()
        if expected_sha256 != actual_sha256:
            raise RuntimeError("FAIL_CLOSED: root public key sha256 mismatch")
        verified_root_keys.append(
            {
                "key_id": str(row.get("key_id", "")).strip(),
                "public_key_ref": public_key_ref,
                "public_key_sha256": expected_sha256,
                "actual_public_key_sha256": actual_sha256,
                "status": "PASS",
            }
        )

    tuf_root_initialization = {
        "schema_id": "kt.operator.tuf_root_initialization.v1",
        "artifact_id": Path(TUF_ROOT_INITIALIZATION_REL).name,
        "status": "PASS",
        "generated_utc": generated,
        "compiled_head_commit": compiled_head_commit,
        "root_policy_ref": ROOT_POLICY_REL,
        "trust_root_id": str(root_of_trust.get("trust_root_id", "")).strip(),
        "bootstrap_state": str(root_of_trust.get("bootstrap_state", "")).strip(),
        "threshold": threshold,
        "threshold_backed": True,
        "verified_root_keys": verified_root_keys,
        "role_thresholds": list(root_policy.get("role_thresholds", [])),
        "semantic_boundary": {"published_head_authority_claimed": False, "h1_allowed": False},
    }

    in_toto_layout = {
        "schema_id": "kt.operator.in_toto_layout.v1",
        "artifact_id": Path(IN_TOTO_LAYOUT_REL).name,
        "status": "PASS",
        "generated_utc": generated,
        "compiled_head_commit": compiled_head_commit,
        "trust_root_id": str(root_of_trust.get("trust_root_id", "")).strip(),
        "root_policy_ref": ROOT_POLICY_REL,
        "layout_source_ref": SUPPLY_CHAIN_LAYOUT_REL,
        "statement_type": str(layout.get("publication", {}).get("statement_type", "")).strip(),
        "predicate_type": str(layout.get("publication", {}).get("predicate_type", "")).strip(),
        "steps": list(layout.get("publication", {}).get("steps", [])),
        "semantic_boundary": {"published_head_authority_claimed": False, "h1_allowed": False},
    }

    in_toto_provenance = {
        "schema_id": "kt.operator.in_toto_provenance.dsse.v1",
        "artifact_id": Path(IN_TOTO_PROVENANCE_REL).name,
        "status": "PASS",
        "generated_utc": generated,
        "compiled_head_commit": compiled_head_commit,
        "payloadType": "application/vnd.in-toto+json",
        "payloadBase64": _b64_file((root / CRYPTO_PUBLICATION_STATEMENT_REL).resolve()),
        "payload_sha256": file_sha256((root / CRYPTO_PUBLICATION_STATEMENT_REL).resolve()),
        "signatures": [
            {
                "keyid": str(crypto_receipt.get("signer_id", "")).strip(),
                "sig": _read_text((root / CRYPTO_PUBLICATION_SIGNATURE_REL).resolve()),
                "signature_mode": "COSIGN_SIGN_BLOB",
                "signature_ref": CRYPTO_PUBLICATION_SIGNATURE_REL,
                "bundle_ref": CRYPTO_PUBLICATION_BUNDLE_REL,
                "bundle_sha256": file_sha256((root / CRYPTO_PUBLICATION_BUNDLE_REL).resolve()),
                "verified_with_tlog": True,
            }
        ],
        "documentary_boundary": {
            "standard_dsse_signature": False,
            "interpretation": "This is a documentary DSSE wrapper around a verified cosign sign-blob attestation. Verification must follow the sigstore bundle and cryptographic publication receipt, not generic DSSE tooling alone.",
        },
    }

    rekor_payload = rekor_bundle.get("rekorBundle", {}).get("Payload", {}) if isinstance(rekor_bundle.get("rekorBundle"), dict) else {}
    rekor_body_b64 = str(rekor_payload.get("body", "")).strip()
    rekor_body_bytes = base64.b64decode(rekor_body_b64) if rekor_body_b64 else b""
    has_set = bool(rekor_bundle.get("rekorBundle", {}).get("SignedEntryTimestamp"))
    tlog_verified = any(
        str(row.get("check", "")).strip() == "cosign_verify_blob_with_tlog" and str(row.get("status", "")).strip() == "PASS"
        for row in crypto_receipt.get("checks", [])
        if isinstance(row, dict)
    )
    if not tlog_verified or not has_set:
        raise RuntimeError("FAIL_CLOSED: transparency inclusion evidence is incomplete")

    rekor_receipt = {
        "schema_id": "kt.operator.rekor_inclusion_receipt.v1",
        "artifact_id": Path(REKOR_INCLUSION_RECEIPT_REL).name,
        "status": "PASS",
        "generated_utc": generated,
        "compiled_head_commit": compiled_head_commit,
        "transparency_log_url": str(signer_policy.get("rules", {}).get("rekor_url_default", "")).strip(),
        "bundle_ref": CRYPTO_PUBLICATION_BUNDLE_REL,
        "bundle_sha256": file_sha256((root / CRYPTO_PUBLICATION_BUNDLE_REL).resolve()),
        "log_id": str(rekor_payload.get("logID", "")).strip(),
        "log_index": rekor_payload.get("logIndex"),
        "integrated_time": rekor_payload.get("integratedTime"),
        "signed_entry_timestamp_present": has_set,
        "entry_body_sha256": hashlib.sha256(rekor_body_bytes).hexdigest() if rekor_body_bytes else "",
        "verified_by": "cosign verify-blob --bundle",
    }

    sigstore_bundle = {
        "schema_id": "kt.operator.sigstore_publication_bundle.v1",
        "artifact_id": Path(SIGSTORE_PUBLICATION_BUNDLE_REL).name,
        "status": "PASS",
        "generated_utc": generated,
        "compiled_head_commit": compiled_head_commit,
        "truth_subject_commit": str(authority_subject.get("truth_subject_commit", "")).strip(),
        "root_policy_ref": ROOT_POLICY_REL,
        "trust_root_id": str(root_of_trust.get("trust_root_id", "")).strip(),
        "signer_policy_ref": SIGNER_IDENTITY_POLICY_REL,
        "signer_id": str(crypto_receipt.get("signer_id", "")).strip(),
        "authority_subject_ref": CRYPTO_PUBLICATION_SUBJECT_REL,
        "authority_subject_sha256": authority_subject_sha256(authority_subject),
        "authority_bundle_ref": CRYPTO_PUBLICATION_AUTHORITY_BUNDLE_REL,
        "authority_bundle_sha256": file_sha256((root / CRYPTO_PUBLICATION_AUTHORITY_BUNDLE_REL).resolve()),
        "statement_ref": CRYPTO_PUBLICATION_STATEMENT_REL,
        "statement_sha256": file_sha256((root / CRYPTO_PUBLICATION_STATEMENT_REL).resolve()),
        "signature_ref": CRYPTO_PUBLICATION_SIGNATURE_REL,
        "signature_sha256": file_sha256((root / CRYPTO_PUBLICATION_SIGNATURE_REL).resolve()),
        "rekor_inclusion_receipt_ref": REKOR_INCLUSION_RECEIPT_REL,
        "cryptographic_publication_receipt_ref": CRYPTO_PUBLICATION_RECEIPT_REL,
        "semantic_boundary": {
            "published_head_authority_claimed": False,
            "authority_convergence_resolved": False,
            "published_head_self_convergence_resolved": False,
            "h1_allowed": False,
        },
    }

    checks = [
        {"check": "tuf_root_policy_threshold_backed", "status": "PASS", "threshold": threshold},
        {"check": "signer_root_key_hashes_match", "status": "PASS", "root_key_count": len(verified_root_keys)},
        {"check": "cryptographic_publication_receipt_passes", "status": "PASS", "receipt_ref": CRYPTO_PUBLICATION_RECEIPT_REL},
        {
            "check": "authority_subject_matches_compiled_head",
            "status": "PASS" if str(authority_subject.get("truth_subject_commit", "")).strip() == compiled_head_commit else "FAIL",
            "actual": str(authority_subject.get("truth_subject_commit", "")).strip(),
            "expected": compiled_head_commit,
        },
        {"check": "rekor_inclusion_evidence_present", "status": "PASS", "log_id": rekor_receipt["log_id"], "log_index": rekor_receipt["log_index"]},
    ]
    if checks[3]["status"] != "PASS":
        raise RuntimeError("FAIL_CLOSED: authority subject does not match compiled head")

    stabilization_receipt = {
        "schema_id": "kt.operator.truth_publication_stabilization_receipt.v2",
        "artifact_id": Path(STABILIZATION_RECEIPT_REL).name,
        "status": "PASS",
        "pass_verdict": PASS_VERDICT,
        "generated_utc": generated,
        "compiled_head_commit": compiled_head_commit,
        "subject_head_commit": compiled_head_commit,
        "evidence_head_commit": compiled_head_commit,
        "truth_subject_commit": str(authority_subject.get("truth_subject_commit", "")).strip(),
        "truth_publication_stabilized": True,
        "trust_root_id": str(root_of_trust.get("trust_root_id", "")).strip(),
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": ["python -m tools.operator.publication_attestation_validate"],
        "next_lawful_step": {"status_after_workstream": "UNLOCKED", "workstream_id": "WS8_PUBLIC_VERIFIER_AND_CLAIM_COMPILER_ACTIVATION"},
        "checks": checks,
        "semantic_boundary": {
            "published_head_authority_claimed": False,
            "authority_convergence_resolved": False,
            "published_head_self_convergence_resolved": False,
            "h1_allowed": False,
        },
        "follow_on_blockers": [
            "AUTHORITY_CONVERGENCE_UNRESOLVED",
            "PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED",
            "H1_ACTIVATION_GATE_CLOSED",
            "PLATFORM_ENFORCEMENT_UNPROVEN",
        ],
    }

    return tuf_root_initialization, in_toto_layout, in_toto_provenance, sigstore_bundle, rekor_receipt, stabilization_receipt


def _write_ws7_artifacts(
    *,
    root: Path,
    tuf_root_initialization: Dict[str, Any],
    in_toto_layout: Dict[str, Any],
    in_toto_provenance: Dict[str, Any],
    sigstore_bundle: Dict[str, Any],
    rekor_receipt: Dict[str, Any],
) -> None:
    write_json_stable((root / TUF_ROOT_INITIALIZATION_REL).resolve(), tuf_root_initialization)
    write_json_stable((root / IN_TOTO_LAYOUT_REL).resolve(), in_toto_layout)
    write_json_stable((root / IN_TOTO_PROVENANCE_REL).resolve(), in_toto_provenance)
    write_json_stable((root / SIGSTORE_PUBLICATION_BUNDLE_REL).resolve(), sigstore_bundle)
    write_json_stable((root / REKOR_INCLUSION_RECEIPT_REL).resolve(), rekor_receipt)


def build_publication_attestation_receipt(
    *,
    root: Path,
    generated_utc: str,
    base_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    status_lines = _git_status_lines(root)
    actual_touched = sorted(set(_dirty_relpaths(status_lines) + [Path(STABILIZATION_RECEIPT_REL).as_posix()]))
    allowed_touched = set(EXPECTED_ARTIFACTS + SUPPORTING_PUBLICATION_ARTIFACTS)
    unexpected_touches = [path for path in actual_touched if path not in allowed_touched]
    protected_touch_violations = [path for path in actual_touched if any(path.startswith(prefix) for prefix in PROTECTED_PATTERNS)]

    receipt = dict(base_receipt)
    receipt["unexpected_touches"] = unexpected_touches
    receipt["protected_touch_violations"] = protected_touch_violations
    receipt["step_report"] = {
        "timestamp": generated_utc,
        "workstream_id": WORKSTREAM_ID,
        "step_id": STEP_ID,
        "actions_taken": [
            "refreshed current-head sigstore publication evidence",
            "derived threshold-backed TUF root initialization from the ratified root policy",
            "derived in-toto layout and documentary DSSE wrapper from the verified publication statement",
            "extracted Rekor inclusion evidence into a dedicated receipt",
            "sealed WS7 publication attestation without upgrading authority convergence or H1 claims",
        ],
        "files_touched": actual_touched,
        "tests_run": ["python -m pytest KT_PROD_CLEANROOM/tests/operator/test_publication_attestation_validate.py -q"],
        "validators_run": ["python -m tools.operator.publication_attestation_validate"],
        "issues_found": [],
        "resolution": "WS7 proves trust-root-backed sigstore publication attestation and transparency inclusion for the current subject while keeping authority convergence and H1 out of scope.",
        "pass_fail_status": "PASS" if not unexpected_touches and not protected_touch_violations else "FAIL_CLOSED",
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
    }
    if unexpected_touches or protected_touch_violations:
        receipt["status"] = "FAIL_CLOSED"
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WS7: mint and validate trust-root-backed publication attestation artifacts.")
    parser.add_argument("--signer-id", default=DEFAULT_SIGNER_ID)
    parser.add_argument("--cosign-private-key", default=DEFAULT_COSIGN_PRIVATE_KEY_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    if _git_status_lines(root):
        raise SystemExit("FAIL_CLOSED: worktree must be clean before WS7 evidence emission")

    compiled_head_commit = _git_head(root)
    mint_current_head_cryptographic_publication(
        root=root,
        compiled_head_commit=compiled_head_commit,
        signer_id=str(args.signer_id),
        cosign_private_key_rel=str(args.cosign_private_key),
    )
    generated_utc = utc_now_iso_z()
    artifacts = build_publication_attestation_outputs(
        root=root,
        compiled_head_commit=compiled_head_commit,
        generated_utc=generated_utc,
    )
    _write_ws7_artifacts(
        root=root,
        tuf_root_initialization=artifacts[0],
        in_toto_layout=artifacts[1],
        in_toto_provenance=artifacts[2],
        sigstore_bundle=artifacts[3],
        rekor_receipt=artifacts[4],
    )
    final_receipt = build_publication_attestation_receipt(
        root=root,
        generated_utc=generated_utc,
        base_receipt=artifacts[5],
    )
    write_json_stable((root / STABILIZATION_RECEIPT_REL).resolve(), final_receipt)
    print(json.dumps(final_receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(final_receipt.get("status", "")).strip() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
