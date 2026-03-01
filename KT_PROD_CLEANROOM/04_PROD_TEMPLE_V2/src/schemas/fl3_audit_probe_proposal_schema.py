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


FL3_AUDIT_PROBE_PROPOSAL_SCHEMA_ID = "kt.audit_probe_proposal.v1"
FL3_AUDIT_PROBE_PROPOSAL_SCHEMA_FILE = "fl3/kt.audit_probe_proposal.v1.json"
FL3_AUDIT_PROBE_PROPOSAL_SCHEMA_VERSION_HASH = schema_version_hash(FL3_AUDIT_PROBE_PROPOSAL_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "proposal_id",
    "proposal_type",
    "title",
    "description",
    "reason_code",
    "evidence_event_ids",
    "requires_human_approval",
    "earliest_review_timestamp",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)


def validate_fl3_audit_probe_proposal(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 audit probe proposal")
    enforce_max_fields(entry, max_fields=24)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_AUDIT_PROBE_PROPOSAL_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_AUDIT_PROBE_PROPOSAL_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "proposal_id")
    validate_short_string(entry, "title", max_len=256)
    validate_short_string(entry, "description", max_len=8192)
    validate_short_string(entry, "reason_code", max_len=128)
    validate_created_at_utc_z(entry.get("created_at"))
    validate_created_at_utc_z(entry.get("earliest_review_timestamp"))

    if entry.get("proposal_type") not in {"NEW_TEST", "NEW_DRILL", "NEW_PROBE"}:
        raise SchemaValidationError("proposal_type invalid (fail-closed)")
    if entry.get("requires_human_approval") is not True:
        raise SchemaValidationError("requires_human_approval must be true (fail-closed)")

    ev = entry.get("evidence_event_ids")
    if not isinstance(ev, list) or not ev:
        raise SchemaValidationError("evidence_event_ids must be non-empty list (fail-closed)")
    prev = None
    for x in ev:
        if not isinstance(x, str):
            raise SchemaValidationError("evidence_event_ids entries must be strings (fail-closed)")
        validate_hex_64({"event_id": x}, "event_id")
        if prev is not None and x < prev:
            raise SchemaValidationError("evidence_event_ids must be sorted (fail-closed)")
        prev = x

    expected_id = sha256_hex_of_obj(entry, drop_keys={"created_at", "proposal_id"})
    if entry.get("proposal_id") != expected_id:
        raise SchemaValidationError("proposal_id does not match canonical hash surface (fail-closed)")

