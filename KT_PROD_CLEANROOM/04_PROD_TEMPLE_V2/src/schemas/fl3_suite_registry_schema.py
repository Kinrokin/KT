from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_canonical_json_bytes,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
    validate_short_string,
)
from schemas.fl3_human_signoff_v2_schema import validate_fl3_human_signoff_v2
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_SUITE_REGISTRY_SCHEMA_ID = "kt.suite_registry.v1"
FL3_SUITE_REGISTRY_SCHEMA_FILE = "fl3/kt.suite_registry.v1.json"
FL3_SUITE_REGISTRY_SCHEMA_VERSION_HASH = schema_version_hash(FL3_SUITE_REGISTRY_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "suite_registry_id",
    "attestation_mode",
    "suites",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "suite_registry_id"}

_SUITE_REQUIRED = {"suite_id", "suite_root_hash", "suite_definition_ref", "authorization_payload_hash", "signoffs"}
_SUITE_ALLOWED = set(_SUITE_REQUIRED) | {"notes"}


def _expected_suite_payload_hash(*, suite_id: str, suite_root_hash: str) -> str:
    return sha256_hex_of_obj({"suite_id": suite_id, "suite_root_hash": suite_root_hash}, drop_keys=set())


def _validate_suite_entry(entry: Dict[str, Any], *, attestation_mode: str) -> Tuple[str, str]:
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_SUITE_REQUIRED)
    reject_unknown_keys(entry, allowed=_SUITE_ALLOWED)

    suite_id = str(entry.get("suite_id", "")).strip()
    if not suite_id:
        raise SchemaValidationError("suite_id must be non-empty (fail-closed)")
    validate_short_string({"suite_id": suite_id}, "suite_id", max_len=128)
    entry["suite_id"] = suite_id

    suite_root_hash = str(entry.get("suite_root_hash", "")).strip()
    entry["suite_root_hash"] = suite_root_hash
    validate_hex_64(entry, "suite_root_hash")

    ref = str(entry.get("suite_definition_ref", "")).strip()
    if not ref:
        raise SchemaValidationError("suite_definition_ref must be non-empty (fail-closed)")
    validate_short_string({"suite_definition_ref": ref}, "suite_definition_ref", max_len=512)
    entry["suite_definition_ref"] = ref

    aph = str(entry.get("authorization_payload_hash", "")).strip()
    entry["authorization_payload_hash"] = aph
    validate_hex_64(entry, "authorization_payload_hash")
    expected_aph = _expected_suite_payload_hash(suite_id=suite_id, suite_root_hash=suite_root_hash)
    if aph != expected_aph:
        raise SchemaValidationError("authorization_payload_hash mismatch (fail-closed)")

    signoffs = entry.get("signoffs")
    if not isinstance(signoffs, list) or len(signoffs) < 2:
        raise SchemaValidationError("signoffs must be a list with >=2 entries (fail-closed)")

    key_ids: List[str] = []
    order: List[Tuple[str, str]] = []
    for s in signoffs:
        sd = require_dict(s, name="Suite signoff")
        validate_fl3_human_signoff_v2(sd)
        if str(sd.get("attestation_mode")) != attestation_mode:
            raise SchemaValidationError("suite signoff attestation_mode mismatch vs registry (fail-closed)")
        if str(sd.get("payload_hash")) != aph:
            raise SchemaValidationError("suite signoff payload_hash mismatch (fail-closed)")
        kid = str(sd.get("key_id", "")).strip()
        key_ids.append(kid)
        order.append((kid, str(sd.get("signoff_id", "")).strip()))

    if len(set(key_ids)) < 2:
        raise SchemaValidationError("signoffs must include two distinct key_id values (fail-closed)")
    if order != sorted(order):
        raise SchemaValidationError("signoffs must be sorted by (key_id, signoff_id) (fail-closed)")

    return suite_id, suite_root_hash


def validate_fl3_suite_registry(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 suite registry v1")
    enforce_max_fields(entry, max_fields=128)
    enforce_max_canonical_json_bytes(entry, max_bytes=256_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_SUITE_REGISTRY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_SUITE_REGISTRY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "suite_registry_id")
    validate_created_at_utc_z(entry.get("created_at"))

    mode = str(entry.get("attestation_mode", "")).strip().upper()
    if mode not in {"SIMULATED", "HMAC", "PKI"}:
        raise SchemaValidationError("attestation_mode invalid (fail-closed)")
    entry["attestation_mode"] = mode

    suites = entry.get("suites")
    if not isinstance(suites, list):
        raise SchemaValidationError("suites must be a list (fail-closed)")

    seen: Set[Tuple[str, str]] = set()
    order: List[Tuple[str, str]] = []
    for s in suites:
        sd = require_dict(s, name="Suite entry")
        suite_id, suite_root_hash = _validate_suite_entry(sd, attestation_mode=mode)
        key = (suite_id, suite_root_hash)
        if key in seen:
            raise SchemaValidationError("duplicate (suite_id, suite_root_hash) entry (fail-closed)")
        seen.add(key)
        order.append(key)

    if order != sorted(order):
        raise SchemaValidationError("suites must be sorted by (suite_id, suite_root_hash) (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("suite_registry_id") != expected:
        raise SchemaValidationError("suite_registry_id does not match canonical hash surface (fail-closed)")

