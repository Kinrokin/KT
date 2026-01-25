from __future__ import annotations

import hashlib
import json
import re
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
from schemas.schema_files import schema_version_hash


ROUTING_RECORD_SCHEMA_ID = "kt.routing_record.v1"
ROUTING_RECORD_SCHEMA_FILE = "kt.routing.srr.v1.json"
ROUTING_RECORD_SCHEMA_VERSION_HASH = schema_version_hash(ROUTING_RECORD_SCHEMA_FILE)

ROUTING_RECORD_REQUIRED_FIELDS_ORDER = (
    "schema_id",
    "schema_version_hash",
    "routing_record_id",
    "runtime_registry_hash",
    "spine_run_hash",
    "task_context_hash",
    "task_context_ref",
    "request_hash",
    "plan_hash",
    "candidates",
    "chosen_adapter",
    "router_reason",
    "router_confidence",
    "governor_verdict",
    "parent_routing_record",
    "status",
    "created_at",
)

ROUTING_RECORD_REQUIRED_FIELDS: Set[str] = set(ROUTING_RECORD_REQUIRED_FIELDS_ORDER)
ROUTING_RECORD_ALLOWED_FIELDS: Set[str] = set(ROUTING_RECORD_REQUIRED_FIELDS_ORDER)

_UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")

_HASH_DROP_KEYS = {"created_at", "routing_record_id"}


def _canonical_json(obj: Dict[str, Any]) -> str:
    # Deterministic hash surface: strict key sorting, stable separators, ASCII-only output.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _compute_routing_record_id(record: Dict[str, Any]) -> str:
    payload = {k: v for k, v in record.items() if k not in _HASH_DROP_KEYS}
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def validate_routing_record(record: Dict[str, Any]) -> None:
    require_dict(record, name="Routing record")
    enforce_max_fields(record, max_fields=32)
    require_keys(record, required=ROUTING_RECORD_REQUIRED_FIELDS)
    reject_unknown_keys(record, allowed=ROUTING_RECORD_ALLOWED_FIELDS)

    validate_short_string(record, "schema_id", max_len=64)
    validate_hex_64(record, "schema_version_hash")
    validate_hex_64(record, "routing_record_id")
    validate_hex_64(record, "runtime_registry_hash")
    validate_hex_64(record, "spine_run_hash")
    validate_hex_64(record, "task_context_hash")
    validate_hex_64(record, "request_hash")
    validate_hex_64(record, "plan_hash")

    if record["schema_id"] != ROUTING_RECORD_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if record["schema_version_hash"] != ROUTING_RECORD_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_short_string(record, "task_context_ref", max_len=256)
    validate_short_string(record, "router_reason", max_len=256)

    if not isinstance(record.get("router_confidence"), (int, float)):
        raise SchemaValidationError("router_confidence must be numeric")
    if record["router_confidence"] < 0.0 or record["router_confidence"] > 1.0:
        raise SchemaValidationError("router_confidence out of bounds [0,1]")

    status = record.get("status")
    if status not in {"OK", "REFUSED", "DRY_RUN"}:
        raise SchemaValidationError("status must be OK, REFUSED, or DRY_RUN")

    created_at = record.get("created_at")
    if not isinstance(created_at, str) or not _UTC_Z_RE.match(created_at):
        raise SchemaValidationError("created_at must be UTC ISO-8601 with Z suffix")

    _validate_candidates(record.get("candidates"))
    _validate_chosen_adapter(record.get("chosen_adapter"))
    _validate_governor_verdict(record.get("governor_verdict"))

    parent = record.get("parent_routing_record")
    if parent is not None:
        validate_hex_64(record, "parent_routing_record")

    # Non-deniable integrity: routing_record_id must match canonical hash surface.
    expected = _compute_routing_record_id(record)
    if record.get("routing_record_id") != expected:
        raise SchemaValidationError("routing_record_id does not match canonical hash surface (fail-closed)")


def _validate_candidates(value: Any) -> None:
    if not isinstance(value, list):
        raise SchemaValidationError("candidates must be a list")
    for item in value:
        _validate_candidate(item)
    ordering = [(str(c.get("adapter_id", "")), str(c.get("adapter_version", ""))) for c in value]
    if ordering != sorted(ordering):
        raise SchemaValidationError("candidates must be sorted by adapter_id,adapter_version")


def _validate_candidate(value: Any) -> None:
    entry = require_dict(value, name="Candidate")
    required = {"adapter_id", "adapter_version"}
    allowed = {"adapter_id", "adapter_version", "capabilities", "estimated_risk"}
    require_keys(entry, required=required)
    reject_unknown_keys(entry, allowed=allowed)
    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "adapter_version", max_len=64)
    if "capabilities" in entry:
        caps = entry["capabilities"]
        if not isinstance(caps, list) or not all(isinstance(x, str) and x.strip() for x in caps):
            raise SchemaValidationError("capabilities must be list of non-empty strings")
    if "estimated_risk" in entry:
        if entry["estimated_risk"] not in {"LOW", "MEDIUM", "HIGH"}:
            raise SchemaValidationError("estimated_risk must be LOW, MEDIUM, or HIGH")


def _validate_chosen_adapter(value: Any) -> None:
    entry = require_dict(value, name="Chosen adapter")
    required = {"adapter_id", "adapter_version"}
    require_keys(entry, required=required)
    reject_unknown_keys(entry, allowed=required)
    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "adapter_version", max_len=64)


def _validate_governor_verdict(value: Any) -> None:
    entry = require_dict(value, name="Governor verdict")
    required = {"policy", "verdict", "risk_score", "verdict_hash"}
    require_keys(entry, required=required)
    reject_unknown_keys(entry, allowed=required)
    validate_short_string(entry, "policy", max_len=64)
    if entry.get("verdict") not in {"ALLOW", "DENY", "DRY_RUN"}:
        raise SchemaValidationError("verdict must be ALLOW, DENY, or DRY_RUN")
    if not isinstance(entry.get("risk_score"), (int, float)):
        raise SchemaValidationError("risk_score must be numeric")
    if entry["risk_score"] < 0.0 or entry["risk_score"] > 1.0:
        raise SchemaValidationError("risk_score out of bounds [0,1]")
    validate_hex_64(entry, "verdict_hash")
