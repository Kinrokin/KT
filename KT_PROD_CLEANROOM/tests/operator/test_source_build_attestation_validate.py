from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.source_build_attestation_validate import (  # noqa: E402
    ATTESTATION_FORMAT,
    STRONGER_CLAIM_NOT_MADE,
    build_source_build_outputs_from_artifacts,
)
from tools.operator.crypto_attestation import subject_sha256 as authority_subject_sha256  # noqa: E402
from tools.verification.attestation_hmac import sign_hmac  # noqa: E402


def _mk_subject() -> dict:
    return {
        "schema_id": "kt.authority.subject.v1",
        "truth_subject_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        "truth_produced_at_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        "law_surface_hashes": {
            "KT_PROD_CLEANROOM/governance/attestation_fabric_contract.json": "a" * 64,
            "KT_PROD_CLEANROOM/governance/authority_bundle.schema.json": "b" * 64,
            "KT_PROD_CLEANROOM/governance/supply_chain_layout.json": "c" * 64,
            "KT_PROD_CLEANROOM/reports/kt_signed_revision_policy.json": "d" * 64,
        },
        "supersedes_subject_sha256": "",
        "evidence": [
            {"name": "ws15_status_report", "ref": "status.json", "sha256": "1" * 64},
            {"name": "ws15_authority_grade_report", "ref": "authority.json", "sha256": "2" * 64},
            {"name": "critical_artifact_1_delivery_manifest", "ref": "artifact.json", "sha256": "3" * 64},
        ],
    }


def _mk_bundle(subject: dict, subject_sha: str) -> dict:
    sig_a, fp_a = sign_hmac(key_bytes=b"alpha-secret", key_id="SIGNER_A", payload_hash=subject_sha)
    sig_b, fp_b = sign_hmac(key_bytes=b"beta-secret", key_id="SIGNER_B", payload_hash=subject_sha)
    return {
        "schema_id": "kt.authority.bundle.v1",
        "bundle_id": "KT_SOURCE_BUILD_ATTEST_test",
        "subject_sha256": subject_sha,
        "subject": subject,
        "envelope": {
            "schema_id": "kt.authority.envelope.v1",
            "subject_sha256": subject_sha,
            "generated_utc": "2026-03-15T19:10:00Z",
            "attestation_mode": "HMAC_DUAL_LOCAL_SIGNOFF_V1",
            "signatures": [
                {
                    "key_id": "SIGNER_A",
                    "env_var": "KT_HMAC_KEY_SIGNER_A",
                    "payload_hash": subject_sha,
                    "hmac_signature": sig_a,
                    "hmac_key_fingerprint": fp_a,
                },
                {
                    "key_id": "SIGNER_B",
                    "env_var": "KT_HMAC_KEY_SIGNER_B",
                    "payload_hash": subject_sha,
                    "hmac_signature": sig_b,
                    "hmac_key_fingerprint": fp_b,
                },
            ],
            "transparency": {"claimed": False, "mode": "NONE"},
        },
    }


def test_source_build_attestation_outputs_answer_four_questions(monkeypatch) -> None:
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_A", "alpha-secret")
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_B", "beta-secret")

    subject = _mk_subject()
    subject_sha = authority_subject_sha256(subject)
    bundle = _mk_bundle(subject, subject_sha)
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": "kt.source_build.subject.v1:test", "digest": {"sha256": subject_sha}}],
        "predicateType": "https://kings-theorem.io/attestations/kt-source-build-subject/v1",
        "predicate": {"stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE},
    }
    dsse = {
        "schema_id": "kt.operator.source_provenance.dsse.v1",
        "payloadType": "application/vnd.in-toto+json",
        "payloadBase64": base64.b64encode(b"{}").decode("ascii"),
        "payload_sha256": "9" * 64,
        "documentary_boundary": {"standard_dsse_signature": False},
    }

    outputs = build_source_build_outputs_from_artifacts(
        status_report={"status": "PASS", "head": "b4789a544954066ee6c225bc9cfa3fddb51c12ee"},
        authority_report={
            "status": "PASS",
            "grade": "A",
            "blockers": [],
            "head": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        },
        ws16_manifest={
            "status": "PASS",
            "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
            "evidence_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
            "critical_artifact_count": 1,
            "critical_artifact_root_sha256": "4" * 64,
            "critical_artifacts": [{"kind": "delivery_manifest", "path": "artifact.json", "sha256": "3" * 64}],
        },
        ws16_receipt={
            "status": "PASS",
            "pass_verdict": "NEAR_HERMETIC_BUILD_ENVELOPE_PROVEN",
            "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
            "evidence_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
        },
        revision_policy={"policy_exemption": {"stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE}},
        authority_subject=subject,
        in_toto_statement=statement,
        authority_bundle=bundle,
        source_provenance_dsse=dsse,
        changed_files=[
            "KT_PROD_CLEANROOM/tools/operator/source_build_attestation_validate.py",
            "KT_PROD_CLEANROOM/tests/operator/test_source_build_attestation_validate.py",
            "KT_PROD_CLEANROOM/reports/kt_signed_revision_policy.json",
            "KT_PROD_CLEANROOM/reports/source_build_attestation/authority_subject.json",
            "KT_PROD_CLEANROOM/reports/source_build_attestation/in_toto_statement.json",
            "KT_PROD_CLEANROOM/reports/source_build_attestation/authority_bundle.json",
            "KT_PROD_CLEANROOM/reports/kt_source_provenance.dsse",
            "KT_PROD_CLEANROOM/reports/kt_revision_trust_receipt.json",
        ],
        prewrite_scope_clean=True,
    )

    receipt = outputs["receipt"]
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == "SOURCE_BUILD_ATTESTATION_PROVEN"
    assert receipt["questions"]["exact_source_revision"] == "b4789a544954066ee6c225bc9cfa3fddb51c12ee"
    assert receipt["questions"]["exact_artifact_subjects_covered"][0]["path"] == "artifact.json"
    assert receipt["questions"]["exact_attestation_format_and_trust_path"]["attestation_format"] == ATTESTATION_FORMAT
    assert receipt["questions"]["exact_stronger_claim_not_made"] == STRONGER_CLAIM_NOT_MADE


def test_source_build_attestation_blocks_on_unexpected_touch(monkeypatch) -> None:
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_A", "alpha-secret")
    monkeypatch.setenv("KT_HMAC_KEY_SIGNER_B", "beta-secret")

    try:
        build_source_build_outputs_from_artifacts(
            status_report={"status": "PASS", "head": "b4789a544954066ee6c225bc9cfa3fddb51c12ee"},
            authority_report={
                "status": "PASS",
                "grade": "A",
                "blockers": [],
                "head": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
            },
            ws16_manifest={
                "status": "PASS",
                "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
                "evidence_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
                "critical_artifact_count": 1,
                "critical_artifact_root_sha256": "4" * 64,
                "critical_artifacts": [{"kind": "delivery_manifest", "path": "artifact.json", "sha256": "3" * 64}],
            },
            ws16_receipt={
                "status": "PASS",
                "pass_verdict": "NEAR_HERMETIC_BUILD_ENVELOPE_PROVEN",
                "subject_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
                "evidence_head_commit": "b4789a544954066ee6c225bc9cfa3fddb51c12ee",
            },
            revision_policy={"policy_exemption": {"stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE}},
            authority_subject=_mk_subject(),
            in_toto_statement={
                "_type": "https://in-toto.io/Statement/v0.1",
                "subject": [{"name": "kt.source_build.subject.v1:test", "digest": {"sha256": "e17802db2e841db659246356a9f10c2636cbadf1ce8ee77a1de7ef1e7598db50"}}],
                "predicateType": "https://kings-theorem.io/attestations/kt-source-build-subject/v1",
                "predicate": {"stronger_claim_not_made": STRONGER_CLAIM_NOT_MADE},
            },
            authority_bundle=_mk_bundle(_mk_subject(), authority_subject_sha256(_mk_subject())),
            source_provenance_dsse={
                "schema_id": "kt.operator.source_provenance.dsse.v1",
                "payloadType": "application/vnd.in-toto+json",
                "payloadBase64": base64.b64encode(b"{}").decode("ascii"),
                "payload_sha256": "9" * 64,
                "documentary_boundary": {"standard_dsse_signature": False},
            },
            changed_files=["KT_PROD_CLEANROOM/tools/operator/kt_cli.py"],
            prewrite_scope_clean=True,
        )
    except RuntimeError as exc:
        assert "unexpected subject touches" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")
