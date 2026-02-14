from __future__ import annotations

from typing import Any, Dict, List, Set

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


FL3_AUDIT_PROPOSAL_ADOPTION_SCHEMA_ID = "kt.audit_proposal_adoption.v1"
FL3_AUDIT_PROPOSAL_ADOPTION_SCHEMA_FILE = "fl3/kt.audit_proposal_adoption.v1.json"
FL3_AUDIT_PROPOSAL_ADOPTION_SCHEMA_VERSION_HASH = schema_version_hash(FL3_AUDIT_PROPOSAL_ADOPTION_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "adoption_id",
    "proposal_id",
    "decision",
    "reviewers",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)


def validate_fl3_audit_proposal_adoption(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 audit proposal adoption")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_AUDIT_PROPOSAL_ADOPTION_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_AUDIT_PROPOSAL_ADOPTION_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "adoption_id")
    validate_hex_64(entry, "proposal_id")
    validate_created_at_utc_z(entry.get("created_at"))

    if entry.get("decision") not in {"ACCEPT", "REJECT", "DEFER"}:
        raise SchemaValidationError("decision invalid (fail-closed)")

    reviewers = entry.get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) < 2:
        raise SchemaValidationError("reviewers must have >=2 entries (fail-closed)")
    stripped: List[str] = []
    for r in reviewers:
        if not isinstance(r, str) or not r.strip():
            raise SchemaValidationError("reviewers must be non-empty strings (fail-closed)")
        s = r.strip()
        if len(s) > 128:
            raise SchemaValidationError("reviewer id too long (fail-closed)")
        stripped.append(s)
    if stripped != sorted(stripped):
        raise SchemaValidationError("reviewers must be sorted (fail-closed)")
    if len(set(stripped)) < 2:
        raise SchemaValidationError("reviewers must include >=2 distinct reviewers (fail-closed)")

    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected_id = sha256_hex_of_obj(entry, drop_keys={"created_at", "adoption_id"})
    if entry.get("adoption_id") != expected_id:
        raise SchemaValidationError("adoption_id does not match canonical hash surface (fail-closed)")

