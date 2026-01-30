from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_DETERMINISM_CONTRACT_SCHEMA_ID = "kt.determinism_contract.v1"
FL3_DETERMINISM_CONTRACT_SCHEMA_FILE = "fl3/kt.determinism_contract.v1.json"
FL3_DETERMINISM_CONTRACT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_DETERMINISM_CONTRACT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "determinism_contract_id",
    "banned_entropy_sources",
    "required_seeding",
    "ordering_rules",
    "determinism_proof",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {
    "serialization",
    "platform_enforcement",
    "canary_expected_hash_manifest_root_hash",
}
_HASH_DROP_KEYS = {"created_at", "determinism_contract_id"}


def validate_fl3_determinism_contract(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="determinism_contract")
    enforce_max_fields(entry, max_fields=128)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_DETERMINISM_CONTRACT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_DETERMINISM_CONTRACT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "determinism_contract_id")
    validate_created_at_utc_z(entry.get("created_at"))

    banned = entry.get("banned_entropy_sources")
    if not isinstance(banned, list) or not all(isinstance(x, str) and x.strip() for x in banned):
        raise SchemaValidationError("banned_entropy_sources must be list of non-empty strings (fail-closed)")

    rs = require_dict(entry.get("required_seeding"), name="required_seeding")
    if not {"python_random", "numpy", "torch"} <= set(rs.keys()):
        raise SchemaValidationError("required_seeding missing keys (fail-closed)")
    for k in ("python_random", "numpy", "torch"):
        if not isinstance(rs.get(k), bool):
            raise SchemaValidationError("required_seeding values must be booleans (fail-closed)")

    require_dict(entry.get("ordering_rules"), name="ordering_rules")
    require_dict(entry.get("determinism_proof"), name="determinism_proof")

    ce = entry.get("canary_expected_hash_manifest_root_hash")
    if ce is not None:
        if not isinstance(ce, str) or len(ce) != 64:
            raise SchemaValidationError("canary_expected_hash_manifest_root_hash invalid (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("determinism_contract_id") != expected:
        raise SchemaValidationError("determinism_contract_id does not match canonical hash surface (fail-closed)")

