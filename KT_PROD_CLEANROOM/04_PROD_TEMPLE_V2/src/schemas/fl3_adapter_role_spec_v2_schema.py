from __future__ import annotations

from typing import Any, Dict, List, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
)
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_ADAPTER_ROLE_SPEC_V2_SCHEMA_ID = "kt.adapter_role_spec.v2"
FL3_ADAPTER_ROLE_SPEC_V2_SCHEMA_FILE = "fl3/kt.adapter_role_spec.v2.json"
FL3_ADAPTER_ROLE_SPEC_V2_SCHEMA_VERSION_HASH = schema_version_hash(FL3_ADAPTER_ROLE_SPEC_V2_SCHEMA_FILE)

_REQUIRED_ORDER = ("schema_id", "schema_version_hash", "role_spec_id", "roles", "created_at")
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "role_spec_id"}


def _validate_axis_weights(items: Any) -> None:
    if not isinstance(items, list) or len(items) < 1:
        raise SchemaValidationError("positive must be a non-empty list (fail-closed)")
    for it in items:
        d = require_dict(it, name="positive axis weight")
        enforce_max_fields(d, max_fields=8)
        require_keys(d, required={"axis", "weight"})
        reject_unknown_keys(d, allowed={"axis", "weight"})
        axis = d.get("axis")
        w = d.get("weight")
        if not isinstance(axis, str) or not axis.strip():
            raise SchemaValidationError("positive.axis must be non-empty string (fail-closed)")
        if not isinstance(w, (int, float)) or w < 0.0 or w > 1.0:
            raise SchemaValidationError("positive.weight must be in [0,1] (fail-closed)")


def _validate_negative_axes(items: Any) -> None:
    if items is None:
        raise SchemaValidationError("negative must be present (fail-closed)")
    if not isinstance(items, list):
        raise SchemaValidationError("negative must be a list (fail-closed)")
    for it in items:
        d = require_dict(it, name="negative axis limit")
        enforce_max_fields(d, max_fields=8)
        require_keys(d, required={"axis", "max_value"})
        reject_unknown_keys(d, allowed={"axis", "max_value"})
        axis = d.get("axis")
        mv = d.get("max_value")
        if not isinstance(axis, str) or not axis.strip():
            raise SchemaValidationError("negative.axis must be non-empty string (fail-closed)")
        if not isinstance(mv, (int, float)) or mv < 0.0 or mv > 1.0:
            raise SchemaValidationError("negative.max_value must be in [0,1] (fail-closed)")


def validate_fl3_adapter_role_spec_v2(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 adapter role spec v2")
    enforce_max_fields(entry, max_fields=16)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_ADAPTER_ROLE_SPEC_V2_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_ADAPTER_ROLE_SPEC_V2_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "role_spec_id")
    validate_created_at_utc_z(entry.get("created_at"))

    roles = entry.get("roles")
    if not isinstance(roles, list) or len(roles) < 1:
        raise SchemaValidationError("roles must be non-empty list (fail-closed)")
    seen: Set[str] = set()
    for r in roles:
        rd = require_dict(r, name="role entry")
        enforce_max_fields(rd, max_fields=64)
        require_keys(rd, required={"role_id", "positive", "negative"})
        reject_unknown_keys(rd, allowed={"role_id", "positive", "negative"})
        role_id = rd.get("role_id")
        if not isinstance(role_id, str) or not role_id.strip():
            raise SchemaValidationError("role_id must be non-empty string (fail-closed)")
        if role_id in seen:
            raise SchemaValidationError("duplicate role_id in roles (fail-closed)")
        seen.add(role_id)
        _validate_axis_weights(rd.get("positive"))
        _validate_negative_axes(rd.get("negative"))

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("role_spec_id") != expected:
        raise SchemaValidationError("role_spec_id mismatch vs canonical hash surface (fail-closed)")

