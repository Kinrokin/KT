from __future__ import annotations

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.verification.attestation_hmac import env_key_name_for_key_id, sign_hmac, verify_hmac_signoff  # noqa: E402


def test_attestation_hmac_roundtrip() -> None:
    key = b"test-key"
    key_id = "SIGNER_A"
    payload_hash = "a" * 64

    sig, fp = sign_hmac(key_bytes=key, key_id=key_id, payload_hash=payload_hash)
    assert len(sig) == 64
    assert len(fp) == 64

    ok, err = verify_hmac_signoff(
        signoff={"key_id": key_id, "payload_hash": payload_hash, "hmac_signature": sig, "hmac_key_fingerprint": fp},
        key_bytes=key,
    )
    assert ok, err


def test_attestation_env_key_name_is_sanitized() -> None:
    assert env_key_name_for_key_id("signer.a") == "KT_HMAC_KEY_SIGNER_A"

