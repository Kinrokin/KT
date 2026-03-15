from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.build_verification_validate import (  # noqa: E402
    DOCUMENTARY_SIGNOFF_MODE,
    STRONGER_CLAIM_NOT_MADE,
    build_build_verification_outputs_from_artifacts,
)
from tools.verification.attestation_hmac import hmac_key_fingerprint_hex, sign_hmac  # noqa: E402


def _signoffs(payload_hash: str) -> list[dict]:
    sig_a, fp_a = sign_hmac(key_bytes=b"alpha-secret", key_id="SIGNER_A", payload_hash=payload_hash)
    sig_b, fp_b = sign_hmac(key_bytes=b"beta-secret", key_id="SIGNER_B", payload_hash=payload_hash)
    return [
        {
            "key_id": "SIGNER_A",
            "env_var": "KT_HMAC_KEY_SIGNER_A",
            "payload_hash": payload_hash,
            "hmac_signature": sig_a,
            "hmac_key_fingerprint": fp_a,
            "mode": DOCUMENTARY_SIGNOFF_MODE,
        },
        {
            "key_id": "SIGNER_B",
            "env_var": "KT_HMAC_KEY_SIGNER_B",
            "payload_hash": payload_hash,
            "hmac_signature": sig_b,
            "hmac_key_fingerprint": fp_b,
            "mode": DOCUMENTARY_SIGNOFF_MODE,
        },
    ]


def _mk_statement(path: str, sha: str) -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": path, "digest": {"sha256": sha}}],
        "predicateType": "https://kings-theorem.io/attestations/test/v1",
        "predicate": {"stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE},
    }


def _common_kwargs() -> dict:
    return {
        "ws16_manifest": {
            "status": "PASS",
            "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
            "critical_artifacts": [{"kind": "delivery_manifest", "path": "artifact.json", "sha256": "1" * 64}],
        },
        "ws16_receipt": {
            "status": "PASS",
            "pass_verdict": "NEAR_HERMETIC_BUILD_ENVELOPE_PROVEN",
            "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        },
        "ws17_receipt": {
            "status": "PASS",
            "pass_verdict": "SOURCE_BUILD_ATTESTATION_PROVEN",
            "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        },
        "ws17_policy": {
            "source_trust_mode": "SEALED_WS15_WS16_SUBSTRATE_PLUS_DUAL_LOCAL_HMAC_ATTESTATION",
            "trust_roots": [
                {"key_id": "SIGNER_A", "fingerprint_sha256": hmac_key_fingerprint_hex(b"alpha-secret")},
                {"key_id": "SIGNER_B", "fingerprint_sha256": hmac_key_fingerprint_hex(b"beta-secret")},
            ],
        },
        "source_provenance_dsse": {"status": "PASS"},
        "changed_files": [
            "KT_PROD_CLEANROOM/tools/operator/build_verification_validate.py",
            "KT_PROD_CLEANROOM/tests/operator/test_build_verification_validate.py",
            "KT_PROD_CLEANROOM/reports/kt_build_provenance.dsse",
            "KT_PROD_CLEANROOM/reports/kt_verification_summary_attestation.dsse",
            "KT_PROD_CLEANROOM/reports/kt_build_verification_receipt.json",
        ],
        "prewrite_scope_clean": True,
    }


def test_build_verification_answers_three_questions(monkeypatch) -> None:
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_A", "alpha-secret")
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_B", "beta-secret")

    payload_hash = "a" * 64
    statement = _mk_statement("artifact.json", "1" * 64)
    outputs = build_build_verification_outputs_from_artifacts(
        build_provenance_statement=statement,
        verification_summary_statement=statement,
        build_provenance_dsse={"payload_sha256": payload_hash, "signatures": _signoffs(payload_hash)},
        verification_summary_dsse={"payload_sha256": payload_hash, "signatures": _signoffs(payload_hash)},
        **_common_kwargs(),
    )

    receipt = outputs["receipt"]
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == "BUILD_PROVENANCE_AND_VSA_ALIGNED"
    assert receipt["questions"]["exact_artifact_subjects_covered"][0]["path"] == "artifact.json"
    assert receipt["questions"]["provenance_vsa_publication_subject_alignment"]["status"] == "PASS"
    assert receipt["questions"]["exact_stronger_claim_not_made"] == STRONGER_CLAIM_NOT_MADE


def test_build_verification_blocks_on_subject_mismatch(monkeypatch) -> None:
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_A", "alpha-secret")
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_B", "beta-secret")

    payload_hash = "a" * 64
    outputs = build_build_verification_outputs_from_artifacts(
        build_provenance_statement=_mk_statement("artifact-a.json", "1" * 64),
        verification_summary_statement=_mk_statement("artifact-b.json", "2" * 64),
        build_provenance_dsse={"payload_sha256": payload_hash, "signatures": _signoffs(payload_hash)},
        verification_summary_dsse={"payload_sha256": payload_hash, "signatures": _signoffs(payload_hash)},
        **_common_kwargs(),
    )

    assert outputs["receipt"]["status"] == "BLOCKED"
    assert outputs["receipt"]["checks"][7]["status"] == "FAIL"
