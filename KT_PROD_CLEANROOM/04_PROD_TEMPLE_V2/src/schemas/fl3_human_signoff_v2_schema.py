from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
    validate_short_string,
)
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_HUMAN_SIGNOFF_V2_SCHEMA_ID = "kt.human_signoff.v2"
FL3_HUMAN_SIGNOFF_V2_SCHEMA_FILE = "fl3/kt.human_signoff.v2.json"
FL3_HUMAN_SIGNOFF_V2_SCHEMA_VERSION_HASH = schema_version_hash(FL3_HUMAN_SIGNOFF_V2_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "signoff_id",
    "attestation_mode",
    "key_id",
    "payload_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {
    "simulated_signature",
    "hmac_signature",
    "hmac_key_fingerprint",
    "pki_signature_b64",
    "pki_cert_fingerprint_sha256",
}
_HASH_DROP_KEYS = {"created_at", "signoff_id"}


def validate_fl3_human_signoff_v2(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 human signoff v2")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_HUMAN_SIGNOFF_V2_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_HUMAN_SIGNOFF_V2_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "signoff_id")
    validate_short_string(entry, "key_id", max_len=64)
    validate_hex_64(entry, "payload_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    mode = str(entry.get("attestation_mode", "")).strip().upper()
    if mode not in {"SIMULATED", "HMAC", "PKI"}:
        raise SchemaValidationError("attestation_mode invalid (fail-closed)")
    entry["attestation_mode"] = mode

    has_sim = entry.get("simulated_signature") is not None
    has_hmac = entry.get("hmac_signature") is not None
    has_pki = entry.get("pki_signature_b64") is not None or entry.get("pki_cert_fingerprint_sha256") is not None

    if mode == "SIMULATED":
        if not has_sim:
            raise SchemaValidationError("simulated_signature required for SIMULATED (fail-closed)")
        validate_hex_64(entry, "simulated_signature")
        if has_hmac or has_pki:
            raise SchemaValidationError("SIMULATED must not include HMAC/PKI fields (fail-closed)")
        expected_sim = sha256_hex_of_obj(
            {"key_id": str(entry.get("key_id")), "payload_hash": str(entry.get("payload_hash"))}, drop_keys=set()
        )
        if str(entry.get("simulated_signature")) != expected_sim:
            raise SchemaValidationError("simulated_signature mismatch (fail-closed)")

    elif mode == "HMAC":
        if not has_hmac:
            raise SchemaValidationError("hmac_signature required for HMAC (fail-closed)")
        validate_hex_64(entry, "hmac_signature")
        if entry.get("hmac_key_fingerprint") is None:
            raise SchemaValidationError("hmac_key_fingerprint required for HMAC (fail-closed)")
        validate_hex_64(entry, "hmac_key_fingerprint")
        if has_sim or has_pki:
            raise SchemaValidationError("HMAC must not include SIMULATED/PKI fields (fail-closed)")

    elif mode == "PKI":
        sig = entry.get("pki_signature_b64")
        cert = entry.get("pki_cert_fingerprint_sha256")
        if not isinstance(sig, str) or not sig.strip():
            raise SchemaValidationError("pki_signature_b64 required for PKI (fail-closed)")
        if cert is None:
            raise SchemaValidationError("pki_cert_fingerprint_sha256 required for PKI (fail-closed)")
        validate_hex_64(entry, "pki_cert_fingerprint_sha256")
        if has_sim or has_hmac:
            raise SchemaValidationError("PKI must not include SIMULATED/HMAC fields (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("signoff_id") != expected:
        raise SchemaValidationError("signoff_id does not match canonical hash surface (fail-closed)")
