from __future__ import annotations

from typing import Any, Dict, List, Set

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
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_ROUTER_POLICY_SCHEMA_ID = "kt.router_policy.v1"
FL3_ROUTER_POLICY_SCHEMA_FILE = "fl3/kt.router_policy.v1.json"
FL3_ROUTER_POLICY_SCHEMA_VERSION_HASH = schema_version_hash(FL3_ROUTER_POLICY_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "router_policy_id",
    "policy_name",
    "policy_version",
    "match_strategy",
    "routes",
    "default_adapter_ids",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "router_policy_id"}

_ROUTE_REQUIRED = {"domain_tag", "keywords", "adapter_ids", "required_adapter_ids"}
_ROUTE_ALLOWED = set(_ROUTE_REQUIRED) | {"notes"}


def _validate_route(row: Dict[str, Any]) -> Dict[str, Any]:
    enforce_max_fields(row, max_fields=32)
    require_keys(row, required=_ROUTE_REQUIRED)
    reject_unknown_keys(row, allowed=_ROUTE_ALLOWED)

    dom = str(row.get("domain_tag", "")).strip()
    if not dom:
        raise SchemaValidationError("domain_tag must be non-empty (fail-closed)")
    validate_short_string({"domain_tag": dom}, "domain_tag", max_len=128)
    row["domain_tag"] = dom

    keywords = ensure_sorted_str_list(row.get("keywords"), field="keywords")
    if not keywords:
        raise SchemaValidationError("keywords must be non-empty list (fail-closed)")
    row["keywords"] = keywords

    adapters = ensure_sorted_str_list(row.get("adapter_ids"), field="adapter_ids")
    if not adapters:
        raise SchemaValidationError("adapter_ids must be non-empty list (fail-closed)")
    row["adapter_ids"] = adapters

    required_adapters = ensure_sorted_str_list(row.get("required_adapter_ids"), field="required_adapter_ids")
    row["required_adapter_ids"] = required_adapters

    if "notes" in row and row["notes"] is not None:
        validate_short_string(row, "notes", max_len=2048)
    return row


def validate_fl3_router_policy(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="router_policy")
    enforce_max_fields(entry, max_fields=128)
    enforce_max_canonical_json_bytes(entry, max_bytes=512_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_ROUTER_POLICY_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_ROUTER_POLICY_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "router_policy_id")
    validate_short_string(entry, "policy_name", max_len=128)
    validate_short_string(entry, "policy_version", max_len=64)

    strat = str(entry.get("match_strategy", "")).strip().upper()
    if strat != "KEYWORD_SUBSTRING_LEXICOGRAPHIC_MIN":
        raise SchemaValidationError("match_strategy invalid (fail-closed)")
    entry["match_strategy"] = strat

    defaults = ensure_sorted_str_list(entry.get("default_adapter_ids"), field="default_adapter_ids")
    if not defaults:
        raise SchemaValidationError("default_adapter_ids must be non-empty (fail-closed)")
    entry["default_adapter_ids"] = defaults

    validate_created_at_utc_z(entry.get("created_at"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    routes_val = entry.get("routes")
    if not isinstance(routes_val, list) or not routes_val:
        raise SchemaValidationError("routes must be non-empty list (fail-closed)")

    routes: List[Dict[str, Any]] = []
    order: List[str] = []
    seen: Set[str] = set()
    for item in routes_val:
        row = require_dict(item, name="routes[]")
        row = _validate_route(row)
        dom = str(row["domain_tag"])
        if dom in seen:
            raise SchemaValidationError("duplicate domain_tag in routes (fail-closed)")
        seen.add(dom)
        routes.append(row)
        order.append(dom)
    if order != sorted(order):
        raise SchemaValidationError("routes must be sorted by domain_tag (fail-closed)")
    entry["routes"] = routes

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("router_policy_id") != expected:
        raise SchemaValidationError("router_policy_id does not match canonical hash surface (fail-closed)")

