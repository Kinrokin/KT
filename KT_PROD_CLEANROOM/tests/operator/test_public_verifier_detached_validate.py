from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.public_verifier_detached_validate import (  # noqa: E402
    CREATED_FILES,
    PARITY_FIELDS,
    STRONGER_CLAIM_NOT_MADE,
    build_detached_public_verifier_outputs_from_artifacts,
)
from tools.verification.attestation_hmac import sign_hmac  # noqa: E402


def _release_signatures(payload_hash: str) -> list[dict]:
    sig_a, fp_a = sign_hmac(key_bytes=b"alpha-secret", key_id="SIGNER_A", payload_hash=payload_hash)
    sig_b, fp_b = sign_hmac(key_bytes=b"beta-secret", key_id="SIGNER_B", payload_hash=payload_hash)
    return [
        {
            "key_id": "SIGNER_A",
            "env_var": "KT_HMAC_KEY_SIGNER_A",
            "payload_hash": payload_hash,
            "hmac_signature": sig_a,
            "hmac_key_fingerprint": fp_a,
            "mode": "HMAC_DETACHED_RELEASE_BINDING",
        },
        {
            "key_id": "SIGNER_B",
            "env_var": "KT_HMAC_KEY_SIGNER_B",
            "payload_hash": payload_hash,
            "hmac_signature": sig_b,
            "hmac_key_fingerprint": fp_b,
            "mode": "HMAC_DETACHED_RELEASE_BINDING",
        },
    ]


def _runtime_checks(status: str = "PASS") -> list[dict]:
    return [
        {"check": "detached_root_without_git_checkout", "status": status},
        {"check": "trust_root_resolved_from_packaged_policy", "status": status},
        {"check": "source_and_build_provenance_resolved", "status": status},
        {"check": "rekor_and_sigstore_bundle_resolved", "status": status},
        {"check": "authority_state_resolved", "status": status},
    ]


def _report(head_claim_verdict: str = "HEAD_CONTAINS_TRANSPARENCY_VERIFIED_SUBJECT_EVIDENCE", *, current_head_commit: str) -> dict:
    return {
        "status": "PASS",
        "subject_verdict": "PUBLISHED_HEAD_TRANSPARENCY_VERIFIED",
        "publication_receipt_status": "PASS",
        "head_claim_verdict": head_claim_verdict,
        "claim_boundary": "claim-boundary",
        "head_claim_boundary": "head-boundary",
        "platform_governance_verdict": "WORKFLOW_GOVERNANCE_ONLY_PLATFORM_BLOCKED",
        "platform_governance_head_claim_verdict": "HEAD_CONTAINS_WORKFLOW_GOVERNANCE_ONLY_EVIDENCE_FOR_SUBJECT",
        "platform_governance_claim_boundary": "governance-boundary",
        "platform_governance_head_claim_boundary": "governance-head-boundary",
        "enterprise_legitimacy_ceiling": "WORKFLOW_GOVERNANCE_ONLY",
        "current_head_commit": current_head_commit,
    }


def _common_kwargs() -> dict:
    payload_hash = "b" * 64
    return {
        "current_repo_head": "c55c19eea493e72f87b417593060dd91e86815e6",
        "ws17_receipt": {"status": "PASS", "pass_verdict": "SOURCE_BUILD_ATTESTATION_PROVEN"},
        "ws18_receipt": {
            "status": "PASS",
            "pass_verdict": "BUILD_PROVENANCE_AND_VSA_ALIGNED",
            "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
            "evidence_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        },
        "package_manifest": {
            "package_root_sha256": payload_hash,
            "release_signatures": _release_signatures(payload_hash),
            "detached_package_root_ref": "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS19_detached_public_verifier_proof/package",
            "publication_surface_boundary": "ws18-publication-boundary",
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
        },
        "detached_runtime_receipt": {
            "status": "PASS",
            "stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE,
            "checks": _runtime_checks(),
            "detached_environment": {"detached_root_detected": True, "git_head_available": False},
            "public_verifier_report": _report(current_head_commit=""),
        },
        "repo_local_report": _report(current_head_commit="repo-head"),
        "changed_files": list(CREATED_FILES),
        "prewrite_scope_clean": True,
    }


def test_detached_public_verifier_receipt_passes_on_clean_parity(monkeypatch) -> None:
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_A", "alpha-secret")
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_B", "beta-secret")

    outputs = build_detached_public_verifier_outputs_from_artifacts(**_common_kwargs())
    receipt = outputs["receipt"]
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == "DETACHED_PUBLIC_VERIFIER_PACKAGE_PROVEN"
    assert receipt["summary"]["stronger_claim_not_made"] == STRONGER_CLAIM_NOT_MADE
    assert set(receipt["detached_vs_repo_local_conclusion_parity"]) == set(PARITY_FIELDS)


def test_detached_public_verifier_receipt_blocks_on_parity_mismatch(monkeypatch) -> None:
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_A", "alpha-secret")
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_B", "beta-secret")

    kwargs = _common_kwargs()
    kwargs["detached_runtime_receipt"] = {
        **kwargs["detached_runtime_receipt"],
        "public_verifier_report": _report(
            head_claim_verdict="HEAD_TRANSPARENCY_CLAIM_UNPROVEN",
            current_head_commit="",
        ),
    }
    outputs = build_detached_public_verifier_outputs_from_artifacts(**kwargs)
    receipt = outputs["receipt"]
    assert receipt["status"] == "BLOCKED"
    assert receipt["checks"][7]["status"] == "FAIL"
