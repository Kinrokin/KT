from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

from tools.operator.public_verifier import (
    GOVERNANCE_HEAD_VERDICT_PLATFORM_CONTAINS,
    GOVERNANCE_HEAD_VERDICT_UNPROVEN,
    GOVERNANCE_HEAD_VERDICT_WORKFLOW_CONTAINS,
    HEAD_VERDICT_CONTAINS,
    HEAD_VERDICT_UNPROVEN,
    SUBJECT_VERDICT_PROVEN,
    build_public_verifier_report,
    manifest_supports_bounded_e1_verifier,
)
from tools.operator.titanium_common import load_json, repo_root, write_json_stable
from tools.verification.attestation_hmac import env_key_name_for_key_id, hmac_key_fingerprint_hex, verify_hmac_signoff


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
REVISION_POLICY_REL = f"{REPORT_ROOT_REL}/kt_signed_revision_policy.json"
REVISION_TRUST_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_revision_trust_receipt.json"
SOURCE_PROVENANCE_DSSE_REL = f"{REPORT_ROOT_REL}/kt_source_provenance.dsse"
SOURCE_AUTHORITY_SUBJECT_REL = f"{REPORT_ROOT_REL}/source_build_attestation/authority_subject.json"
SOURCE_IN_TOTO_STATEMENT_REL = f"{REPORT_ROOT_REL}/source_build_attestation/in_toto_statement.json"
SOURCE_AUTHORITY_BUNDLE_REL = f"{REPORT_ROOT_REL}/source_build_attestation/authority_bundle.json"
BUILD_PROVENANCE_REL = f"{REPORT_ROOT_REL}/kt_build_provenance.dsse"
VERIFICATION_SUMMARY_REL = f"{REPORT_ROOT_REL}/kt_verification_summary_attestation.dsse"
BUILD_VERIFICATION_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_build_verification_receipt.json"
PUBLIC_VERIFIER_MANIFEST_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
CRYPTO_PUBLICATION_RECEIPT_REL = f"{REPORT_ROOT_REL}/cryptographic_publication_receipt.json"
CRYPTO_PUBLICATION_SUBJECT_REL = f"{REPORT_ROOT_REL}/cryptographic_publication/authority_subject.json"
CRYPTO_PUBLICATION_BUNDLE_REL = f"{REPORT_ROOT_REL}/cryptographic_publication/authority_bundle.json"
CRYPTO_PUBLICATION_STATEMENT_REL = f"{REPORT_ROOT_REL}/cryptographic_publication/in_toto_statement.json"
CRYPTO_PUBLICATION_SIGNATURE_REL = f"{REPORT_ROOT_REL}/cryptographic_publication/in_toto_statement.sig"
CRYPTO_PUBLICATION_BUNDLE_JSON_REL = f"{REPORT_ROOT_REL}/cryptographic_publication/in_toto_statement.bundle.json"
FINAL_GOVERNANCE_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_platform_governance_final_decision_receipt.json"
TUF_ROOT_INITIALIZATION_REL = f"{REPORT_ROOT_REL}/kt_tuf_root_initialization.json"
SIGSTORE_PUBLICATION_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_sigstore_publication_bundle.json"
REKOR_INCLUSION_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_rekor_inclusion_receipt.json"

STRONGER_CLAIM_NOT_MADE = (
    "WS19 does not claim independent external reproduction, third-party detached replay, or public horizon opening."
)


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing detached verifier input: {rel}")
    return load_json(path)


def _resolve_output_path(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    return path if path.is_absolute() else (root / path).resolve()


def _must_env_key_bytes(key_id: str) -> Tuple[bytes, str]:
    env_name = env_key_name_for_key_id(key_id)
    value = str(os.environ.get(env_name, "")).strip()
    if not value:
        raise RuntimeError(f"FAIL_CLOSED: missing detached verifier HMAC env key: {env_name}")
    return value.encode("utf-8"), env_name


def _verify_trust_roots(revision_policy: Dict[str, Any]) -> bool:
    trust_roots = revision_policy.get("trust_roots")
    if not isinstance(trust_roots, list) or not trust_roots:
        return False
    for row in trust_roots:
        if not isinstance(row, dict):
            return False
        key_id = str(row.get("key_id", "")).strip()
        expected = str(row.get("fingerprint_sha256", "")).strip()
        if not key_id or not expected:
            return False
        key_bytes, _ = _must_env_key_bytes(key_id)
        if hmac_key_fingerprint_hex(key_bytes) != expected:
            return False
    return True


def _verify_hmac_signoffs(signoffs: list[dict], payload_hash: str) -> bool:
    if len(signoffs) < 2 or not str(payload_hash).strip():
        return False
    for signoff in signoffs:
        key_id = str(signoff.get("key_id", "")).strip()
        if not key_id or str(signoff.get("payload_hash", "")).strip() != str(payload_hash).strip():
            return False
        key_bytes, _ = _must_env_key_bytes(key_id)
        ok, _ = verify_hmac_signoff(signoff=signoff, key_bytes=key_bytes)
        if not ok:
            return False
    return True


def _ref_exists(root: Path, rel: str) -> bool:
    return (root / Path(str(rel))).exists()


def _check(check: str, ok: bool, refs: list[str], detail: str) -> Dict[str, Any]:
    return {
        "check": check,
        "status": "PASS" if ok else "FAIL",
        "refs": [str(Path(ref).as_posix()) for ref in refs],
        "detail": detail,
    }


def _detached_report_without_git(report: Dict[str, Any]) -> Dict[str, Any]:
    detached = dict(report)
    detached["current_head_commit"] = ""
    detached["head_equals_subject"] = False
    detached["platform_governance_head_equals_subject"] = False

    if str(detached.get("subject_verdict", "")).strip() == SUBJECT_VERDICT_PROVEN and bool(detached.get("evidence_contains_subject")):
        detached["head_claim_verdict"] = HEAD_VERDICT_CONTAINS
        detached["head_claim_boundary"] = (
            "Current HEAD contains transparency-verified evidence for truth_subject_commit; HEAD is not itself the verified subject."
        )
    else:
        detached["head_claim_verdict"] = HEAD_VERDICT_UNPROVEN
        detached["head_claim_boundary"] = "Current HEAD has no proven transparency claim boundary."

    governance_verdict = str(detached.get("platform_governance_verdict", "")).strip()
    governance_subject = str(detached.get("platform_governance_subject_commit", "")).strip()
    if governance_verdict == "PLATFORM_ENFORCEMENT_PROVEN" and governance_subject:
        detached["platform_governance_head_claim_verdict"] = GOVERNANCE_HEAD_VERDICT_PLATFORM_CONTAINS
        detached["platform_governance_head_claim_boundary"] = (
            "Current HEAD contains platform-governance evidence for platform_governance_subject_commit; it is not itself freshly governance-proven."
        )
    elif governance_verdict == "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED" and governance_subject:
        detached["platform_governance_head_claim_verdict"] = GOVERNANCE_HEAD_VERDICT_WORKFLOW_CONTAINS
        detached["platform_governance_head_claim_boundary"] = (
            "Current HEAD contains workflow-governance-only evidence for platform_governance_subject_commit; it is not itself freshly governance-proven."
        )
    else:
        detached["platform_governance_head_claim_verdict"] = GOVERNANCE_HEAD_VERDICT_UNPROVEN
        detached["platform_governance_head_claim_boundary"] = "Current HEAD has no proven platform-governance claim boundary."
    return detached


def build_detached_public_verifier_runtime_receipt(*, root: Path) -> Dict[str, Any]:
    revision_policy = _load_required_json(root, REVISION_POLICY_REL)
    revision_trust_receipt = _load_required_json(root, REVISION_TRUST_RECEIPT_REL)
    source_provenance_dsse = _load_required_json(root, SOURCE_PROVENANCE_DSSE_REL)
    source_authority_bundle = _load_required_json(root, SOURCE_AUTHORITY_BUNDLE_REL)
    build_provenance_dsse = _load_required_json(root, BUILD_PROVENANCE_REL)
    verification_summary_dsse = _load_required_json(root, VERIFICATION_SUMMARY_REL)
    build_verification_receipt = _load_required_json(root, BUILD_VERIFICATION_RECEIPT_REL)
    public_verifier_manifest = _load_required_json(root, PUBLIC_VERIFIER_MANIFEST_REL)
    cryptographic_publication_receipt = _load_required_json(root, CRYPTO_PUBLICATION_RECEIPT_REL)
    governance_final_receipt = _load_required_json(root, FINAL_GOVERNANCE_RECEIPT_REL)
    tuf_root = _load_required_json(root, TUF_ROOT_INITIALIZATION_REL)
    sigstore_bundle = _load_required_json(root, SIGSTORE_PUBLICATION_BUNDLE_REL)
    rekor_receipt = _load_required_json(root, REKOR_INCLUSION_RECEIPT_REL)

    detached_root_detected = not (root / ".git").exists()

    trust_root_ok = _verify_trust_roots(revision_policy) and str(tuf_root.get("status", "")).strip() == "PASS" and bool(
        tuf_root.get("threshold_backed")
    )
    trust_root_refs_ok = all(
        _ref_exists(root, ref)
        for ref in [
            str(tuf_root.get("root_policy_ref", "")).strip(),
            str(sigstore_bundle.get("root_policy_ref", "")).strip(),
            str(sigstore_bundle.get("signer_policy_ref", "")).strip(),
        ]
        if str(ref).strip()
    )

    source_provenance_refs_ok = all(
        _ref_exists(root, ref)
        for ref in [
            str(source_provenance_dsse.get("authority_bundle_ref", "")).strip(),
            str(source_provenance_dsse.get("authority_subject_ref", "")).strip(),
            str(source_provenance_dsse.get("in_toto_statement_ref", "")).strip(),
            SOURCE_AUTHORITY_SUBJECT_REL,
            SOURCE_IN_TOTO_STATEMENT_REL,
            SOURCE_AUTHORITY_BUNDLE_REL,
        ]
    )
    source_authority_signoffs_ok = _verify_hmac_signoffs(
        list(source_authority_bundle.get("envelope", {}).get("signatures", [])),
        str(source_authority_bundle.get("subject_sha256", "")).strip(),
    )
    source_provenance_ok = (
        str(revision_trust_receipt.get("status", "")).strip() == "PASS"
        and str(source_provenance_dsse.get("status", "")).strip() == "PASS"
        and bool(source_provenance_dsse.get("documentary_boundary"))
        and source_provenance_refs_ok
        and source_authority_signoffs_ok
    )

    build_provenance_ok = (
        str(build_provenance_dsse.get("status", "")).strip() == "PASS"
        and _verify_hmac_signoffs(
            list(build_provenance_dsse.get("signatures", [])),
            str(build_provenance_dsse.get("payload_sha256", "")).strip(),
        )
    )
    verification_summary_ok = (
        str(verification_summary_dsse.get("status", "")).strip() == "PASS"
        and _verify_hmac_signoffs(
            list(verification_summary_dsse.get("signatures", [])),
            str(verification_summary_dsse.get("payload_sha256", "")).strip(),
        )
    )
    provenance_ok = build_provenance_ok and verification_summary_ok and str(build_verification_receipt.get("status", "")).strip() == "PASS"

    rekor_refs_ok = all(
        _ref_exists(root, ref)
        for ref in [
            str(rekor_receipt.get("bundle_ref", "")).strip(),
            str(sigstore_bundle.get("authority_bundle_ref", "")).strip(),
            str(sigstore_bundle.get("authority_subject_ref", "")).strip(),
            str(sigstore_bundle.get("statement_ref", "")).strip(),
            str(sigstore_bundle.get("signature_ref", "")).strip(),
            str(sigstore_bundle.get("cryptographic_publication_receipt_ref", "")).strip(),
            str(sigstore_bundle.get("rekor_inclusion_receipt_ref", "")).strip(),
            CRYPTO_PUBLICATION_BUNDLE_JSON_REL,
            CRYPTO_PUBLICATION_BUNDLE_REL,
            CRYPTO_PUBLICATION_SUBJECT_REL,
            CRYPTO_PUBLICATION_STATEMENT_REL,
            CRYPTO_PUBLICATION_SIGNATURE_REL,
        ]
    )
    rekor_ok = (
        str(rekor_receipt.get("status", "")).strip() == "PASS"
        and str(sigstore_bundle.get("status", "")).strip() == "PASS"
        and str(sigstore_bundle.get("trust_root_id", "")).strip() == str(tuf_root.get("trust_root_id", "")).strip()
        and rekor_refs_ok
        and trust_root_refs_ok
    )

    authority_state_ok = (
        manifest_supports_bounded_e1_verifier(public_verifier_manifest)
        and str(cryptographic_publication_receipt.get("status", "")).strip() == "PASS"
        and str(governance_final_receipt.get("status", "")).strip() == "PASS"
        and _ref_exists(root, CRYPTO_PUBLICATION_SUBJECT_REL)
    )

    public_verifier_report = build_public_verifier_report(root=root)
    if detached_root_detected:
        public_verifier_report = _detached_report_without_git(public_verifier_report)
    status = "PASS" if all([detached_root_detected, trust_root_ok, source_provenance_ok, provenance_ok, rekor_ok, authority_state_ok]) else "BLOCKED"
    return {
        "schema_id": "kt.operator.public_verifier_detached_runtime_receipt.v1",
        "artifact_id": "detached_runtime_receipt.json",
        "status": status,
        "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        "checks": [
            _check(
                "detached_root_without_git_checkout",
                detached_root_detected,
                [],
                "Detached verifier must run from a copied package root without a repo checkout or .git metadata.",
            ),
            _check(
                "trust_root_resolved_from_packaged_policy",
                trust_root_ok and trust_root_refs_ok,
                [REVISION_POLICY_REL, TUF_ROOT_INITIALIZATION_REL, SIGSTORE_PUBLICATION_BUNDLE_REL],
                "Detached verifier must resolve trust roots from packaged WS17 policy and TUF root inputs.",
            ),
            _check(
                "source_and_build_provenance_resolved",
                source_provenance_ok and provenance_ok,
                [
                    REVISION_TRUST_RECEIPT_REL,
                    SOURCE_PROVENANCE_DSSE_REL,
                    SOURCE_AUTHORITY_BUNDLE_REL,
                    BUILD_PROVENANCE_REL,
                    VERIFICATION_SUMMARY_REL,
                    BUILD_VERIFICATION_RECEIPT_REL,
                ],
                "Detached verifier must resolve source/build attestation and WS18 provenance surfaces from packaged inputs only.",
            ),
            _check(
                "rekor_and_sigstore_bundle_resolved",
                rekor_ok,
                [TUF_ROOT_INITIALIZATION_REL, SIGSTORE_PUBLICATION_BUNDLE_REL, REKOR_INCLUSION_RECEIPT_REL, CRYPTO_PUBLICATION_BUNDLE_JSON_REL],
                "Detached verifier must resolve Rekor and Sigstore/TUF evidence from packaged refs only.",
            ),
            _check(
                "authority_state_resolved",
                authority_state_ok,
                [PUBLIC_VERIFIER_MANIFEST_REL, CRYPTO_PUBLICATION_RECEIPT_REL, FINAL_GOVERNANCE_RECEIPT_REL],
                "Detached verifier must resolve authority state from packaged verifier/governance/publication receipts.",
            ),
        ],
        "detached_environment": {
            "detached_root_detected": detached_root_detected,
            "repo_checkout_present": (root / ".git").exists(),
            "git_head_available": bool(str(public_verifier_report.get("current_head_commit", "")).strip()),
        },
        "public_verifier_report": public_verifier_report,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the detached public verifier package without repo-local assumptions.")
    parser.add_argument("--report-output", default="")
    parser.add_argument("--receipt-output", default="")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    receipt = build_detached_public_verifier_runtime_receipt(root=root)
    report = receipt["public_verifier_report"]
    if str(args.report_output).strip():
        write_json_stable(_resolve_output_path(root, str(args.report_output)), report)
    if str(args.receipt_output).strip():
        write_json_stable(_resolve_output_path(root, str(args.receipt_output)), receipt)
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "detached_environment": receipt["detached_environment"],
                "public_verifier_report": report,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
