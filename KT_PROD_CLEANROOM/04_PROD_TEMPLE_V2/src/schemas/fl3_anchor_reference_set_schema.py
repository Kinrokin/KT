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


FL3_ANCHOR_REFERENCE_SET_SCHEMA_ID = "kt.anchor_reference_set.v1"
FL3_ANCHOR_REFERENCE_SET_SCHEMA_FILE = "fl3/kt.anchor_reference_set.v1.json"
FL3_ANCHOR_REFERENCE_SET_SCHEMA_VERSION_HASH = schema_version_hash(FL3_ANCHOR_REFERENCE_SET_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "anchor_set_id",
    "baseline_model_id",
    "generation_params",
    "items",
    "set_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "anchor_set_id", "set_hash"}


def _validate_generation_params(obj: Any) -> None:
    gp = require_dict(obj, name="generation_params")
    enforce_max_fields(gp, max_fields=16)
    for k in ("temperature", "top_p", "max_tokens"):
        if k not in gp:
            raise SchemaValidationError(f"generation_params missing key (fail-closed): {k}")
    temp = gp.get("temperature")
    top_p = gp.get("top_p")
    max_tokens = gp.get("max_tokens")
    if not isinstance(temp, (int, float)) or temp < 0.0 or temp > 2.0:
        raise SchemaValidationError("generation_params.temperature must be in [0,2] (fail-closed)")
    if not isinstance(top_p, (int, float)) or top_p < 0.0 or top_p > 1.0:
        raise SchemaValidationError("generation_params.top_p must be in [0,1] (fail-closed)")
    if not isinstance(max_tokens, int) or max_tokens < 1:
        raise SchemaValidationError("generation_params.max_tokens must be >=1 int (fail-closed)")


def _compute_items_hash(items: List[Dict[str, Any]]) -> str:
    # Hash only the ordered list of prompt/baseline_response pairs (canonical JSON surface).
    payload = [{"prompt": it.get("prompt"), "baseline_response": it.get("baseline_response")} for it in items]
    return sha256_hex_of_obj({"items": payload}, drop_keys=set())


def validate_fl3_anchor_reference_set(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 anchor reference set")
    enforce_max_fields(entry, max_fields=16 + 8)  # small top-level object
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_ANCHOR_REFERENCE_SET_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_ANCHOR_REFERENCE_SET_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "anchor_set_id")
    validate_hex_64(entry, "set_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    baseline_model_id = entry.get("baseline_model_id")
    if not isinstance(baseline_model_id, str) or not baseline_model_id.strip():
        raise SchemaValidationError("baseline_model_id must be non-empty string (fail-closed)")

    _validate_generation_params(entry.get("generation_params"))

    items = entry.get("items")
    if not isinstance(items, list) or len(items) < 1:
        raise SchemaValidationError("items must be a non-empty list (fail-closed)")
    for it in items:
        d = require_dict(it, name="anchor item")
        enforce_max_fields(d, max_fields=8)
        if not isinstance(d.get("prompt"), str):
            raise SchemaValidationError("anchor item prompt must be string (fail-closed)")
        if not isinstance(d.get("baseline_response"), str):
            raise SchemaValidationError("anchor item baseline_response must be string (fail-closed)")

    expected_set_hash = _compute_items_hash(items)
    if entry.get("set_hash") != expected_set_hash:
        raise SchemaValidationError("set_hash mismatch vs canonical item hash surface (fail-closed)")

    expected_anchor_set_id = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("anchor_set_id") != expected_anchor_set_id:
        raise SchemaValidationError("anchor_set_id mismatch vs canonical hash surface (fail-closed)")

