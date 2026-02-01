from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
)
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_METABOLISM_PROOF_SCHEMA_ID = "kt.metabolism_proof.v1"
FL3_METABOLISM_PROOF_SCHEMA_FILE = "fl3/kt.metabolism_proof.v1.json"
FL3_METABOLISM_PROOF_SCHEMA_VERSION_HASH = schema_version_hash(FL3_METABOLISM_PROOF_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "proof_id",
    "base_job_id",
    "perturbations",
    "assertions",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "proof_id"}


def validate_fl3_metabolism_proof(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="metabolism_proof")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_METABOLISM_PROOF_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_METABOLISM_PROOF_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "proof_id")
    validate_created_at_utc_z(entry.get("created_at"))

    base_job_id = entry.get("base_job_id")
    if not isinstance(base_job_id, str) or len(base_job_id) < 8:
        raise SchemaValidationError("base_job_id invalid (fail-closed)")

    perturbations = entry.get("perturbations")
    if not isinstance(perturbations, list) or len(perturbations) < 2:
        raise SchemaValidationError("perturbations must be list with >=2 entries (fail-closed)")
    seen_names: Set[str] = set()
    for it in perturbations:
        if not isinstance(it, dict):
            raise SchemaValidationError("perturbation entry must be object (fail-closed)")
        if set(it.keys()) != {"name", "job_id", "hash_manifest_root_hash"}:
            raise SchemaValidationError("perturbation entry keys mismatch (fail-closed)")
        name = it.get("name")
        job_id = it.get("job_id")
        root = it.get("hash_manifest_root_hash")
        if not isinstance(name, str) or not name.strip():
            raise SchemaValidationError("perturbation.name invalid (fail-closed)")
        if name in seen_names:
            raise SchemaValidationError("duplicate perturbation.name (fail-closed)")
        seen_names.add(name)
        if not isinstance(job_id, str) or len(job_id) < 8:
            raise SchemaValidationError("perturbation.job_id invalid (fail-closed)")
        if not isinstance(root, str) or len(root) != 64:
            raise SchemaValidationError("perturbation.hash_manifest_root_hash invalid (fail-closed)")
        if any(ch not in "0123456789abcdef" for ch in root):
            raise SchemaValidationError("perturbation.hash_manifest_root_hash must be hex (fail-closed)")

    assertions = entry.get("assertions")
    if not isinstance(assertions, dict) or set(assertions.keys()) != {"all_schema_valid", "roots_distinct"}:
        raise SchemaValidationError("assertions invalid (fail-closed)")
    if not isinstance(assertions.get("all_schema_valid"), bool):
        raise SchemaValidationError("assertions.all_schema_valid invalid (fail-closed)")
    if not isinstance(assertions.get("roots_distinct"), bool):
        raise SchemaValidationError("assertions.roots_distinct invalid (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("proof_id") != expected:
        raise SchemaValidationError("proof_id does not match canonical hash surface (fail-closed)")

