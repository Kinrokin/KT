from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.crypto_attestation import mint_authority_bundle, mint_envelope, subject_sha256
from tools.operator.publication_attestation_validate import ROOT_POLICY_REL, build_publication_attestation_outputs


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _normalized_text_sha256(text: str) -> str:
    import hashlib

    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _seed_ws7_publication_repo(root: Path, *, compiled_head_commit: str) -> None:
    pubkey_text = "-----BEGIN PUBLIC KEY-----\nTESTKEY\n-----END PUBLIC KEY-----\n"
    pubkey_sha = _normalized_text_sha256(pubkey_text)
    _write_text(root / "KT_PROD_CLEANROOM/governance/signers/kt_op1_cosign.pub", pubkey_text)
    _write_json(
        root / ROOT_POLICY_REL,
        {
            "root_of_trust": {
                "trust_root_id": "KT_TUF_ROOT_BOOTSTRAP_TEST",
                "bootstrap_state": "BOOTSTRAP_THRESHOLD_1_OF_1",
                "threshold": 1,
                "root_keys": [
                    {
                        "key_id": "KT_OP1_COSIGN_KEYPAIR",
                        "public_key_ref": "KT_PROD_CLEANROOM/governance/signers/kt_op1_cosign.pub",
                        "public_key_sha256": pubkey_sha,
                        "status": "ACTIVE",
                    }
                ],
            },
            "role_thresholds": [{"role_id": "root", "threshold": 1, "allowed_key_ids": ["KT_OP1_COSIGN_KEYPAIR"]}],
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/signer_identity_policy.json",
        {
            "rules": {"rekor_url_default": "https://rekor.sigstore.dev"},
            "allowed_signers": [
                {
                    "signer_id": "KT_OP1_COSIGN_KEYPAIR",
                    "public_key_ref": "KT_PROD_CLEANROOM/governance/signers/kt_op1_cosign.pub",
                    "public_key_sha256": pubkey_sha,
                }
            ],
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/supply_chain_layout.json",
        {
            "publication": {
                "statement_type": "https://in-toto.io/Statement/v0.1",
                "predicate_type": "https://kings-theorem.io/attestations/kt-authority-subject/v1",
                "steps": [{"step_name": "mint_authority_subject"}],
            }
        },
    )
    subject = {
        "schema_id": "kt.authority.subject.v1",
        "truth_subject_commit": compiled_head_commit,
        "truth_produced_at_commit": compiled_head_commit,
        "law_surface_hashes": {"a": "b" * 64},
        "supersedes_subject_sha256": "",
        "evidence": [{"name": "proof", "ref": "x", "sha256": "c" * 64}],
    }
    subject_hash = subject_sha256(subject)
    bundle = mint_authority_bundle(
        subject=subject,
        envelope=mint_envelope(
            subject_sha256_hex=subject_hash,
            attestation_mode="SIGSTORE_COSIGN_BLOB_BUNDLE_V1_KEYPAIR",
            generated_utc="2026-03-15T00:00:00Z",
            signatures=[],
            transparency={"tlog_verified": True},
        ),
        bundle_id="KT_AUTHORITY_BUNDLE_TEST",
    )
    _write_json(root / "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_subject.json", subject)
    _write_json(root / "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_bundle.json", bundle)
    _write_json(
        root / "KT_PROD_CLEANROOM/reports/cryptographic_publication/in_toto_statement.json",
        {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "kt.authority.subject.v1:test", "digest": {"sha256": subject_hash}}],
            "predicateType": "https://kings-theorem.io/attestations/kt-authority-subject/v1",
            "predicate": {},
        },
    )
    _write_text(root / "KT_PROD_CLEANROOM/reports/cryptographic_publication/in_toto_statement.sig", "MEQCITestSignature=\n")
    _write_json(
        root / "KT_PROD_CLEANROOM/reports/cryptographic_publication/in_toto_statement.bundle.json",
        {
            "rekorBundle": {
                "SignedEntryTimestamp": "MEUCITestSET=",
                "Payload": {
                    "body": "eyJ0ZXN0Ijp0cnVlfQ==",
                    "integratedTime": 1773437356,
                    "logIndex": 1097864221,
                    "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
                },
            }
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/reports/cryptographic_publication_receipt.json",
        {
            "status": "PASS",
            "signer_id": "KT_OP1_COSIGN_KEYPAIR",
            "checks": [{"check": "cosign_verify_blob_with_tlog", "status": "PASS"}],
        },
    )


def test_build_publication_attestation_outputs_passes_with_verified_root_and_rekor(tmp_path: Path) -> None:
    compiled_head_commit = "a" * 40
    _seed_ws7_publication_repo(tmp_path, compiled_head_commit=compiled_head_commit)

    tuf_root, layout, dsse, sigstore_bundle, rekor_receipt, stabilization = build_publication_attestation_outputs(
        root=tmp_path,
        compiled_head_commit=compiled_head_commit,
        generated_utc="2026-03-15T00:00:00Z",
    )

    assert tuf_root["status"] == "PASS"
    assert layout["status"] == "PASS"
    assert dsse["status"] == "PASS"
    assert sigstore_bundle["status"] == "PASS"
    assert rekor_receipt["status"] == "PASS"
    assert stabilization["status"] == "PASS"
    assert stabilization["pass_verdict"] == "PUBLICATION_GRADE_ATTESTATION_PROVEN"


def test_build_publication_attestation_outputs_fails_on_root_key_mismatch(tmp_path: Path) -> None:
    compiled_head_commit = "b" * 40
    _seed_ws7_publication_repo(tmp_path, compiled_head_commit=compiled_head_commit)
    root_policy_path = tmp_path / ROOT_POLICY_REL
    root_policy = json.loads(root_policy_path.read_text(encoding="utf-8"))
    root_policy["root_of_trust"]["root_keys"][0]["public_key_sha256"] = "0" * 64
    root_policy_path.write_text(json.dumps(root_policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="root public key sha256 mismatch"):
        build_publication_attestation_outputs(
            root=tmp_path,
            compiled_head_commit=compiled_head_commit,
            generated_utc="2026-03-15T00:00:00Z",
        )
