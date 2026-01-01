from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional


STATE_VAULT_SCHEMA_ID = "kt.state_vault.v1"

# Required immutable fields for every JSONL record.
STATE_VAULT_REQUIRED_FIELDS_ORDER = (
    "receipt_id",
    "created_at",
    "event_type",
    "organ_id",
    "event_hash",
    "parent_hash",
    "payload_hash",
    "schema_id",
    "schema_version_hash",
    "constitution_version_hash",
)

# Explicitly enumerated optional payload surface (bounded; fail-closed on unknown keys).
STATE_VAULT_OPTIONAL_FIELDS_ORDER = (
    "inputs_hash",
    "outputs_hash",
    "energy_cost",
    "energy_source",
    "crisis_mode",
)

STATE_VAULT_REQUIRED_FIELDS = set(STATE_VAULT_REQUIRED_FIELDS_ORDER)
STATE_VAULT_OPTIONAL_FIELDS = set(STATE_VAULT_OPTIONAL_FIELDS_ORDER)
STATE_VAULT_ALLOWED_FIELDS = STATE_VAULT_REQUIRED_FIELDS | STATE_VAULT_OPTIONAL_FIELDS

# Payload hash is computed only from the allowed optional fields.
STATE_VAULT_PAYLOAD_FIELDS_ORDER = STATE_VAULT_OPTIONAL_FIELDS_ORDER
STATE_VAULT_PAYLOAD_FIELDS = set(STATE_VAULT_PAYLOAD_FIELDS_ORDER)

# Context poisoning defense (bounded, deterministic).
STATE_VAULT_MAX_STRING_LEN = 256
STATE_VAULT_MAX_RECORD_BYTES = 4096

ALLOWED_ENERGY_SOURCES = {"EFFICIENCY", "INEFFICIENCY"}
ALLOWED_CRISIS_MODES = {"NOMINAL", "S1_SOFT_DAMP", "S2_HARD_FREEZE", "S3_DIAGNOSTIC", "S4_REFLEX"}

GENESIS_PARENT_HASH = "0" * 64


_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def compute_state_vault_schema_version_hash() -> str:
    spec = {
        "schema_id": STATE_VAULT_SCHEMA_ID,
        "required_fields": list(STATE_VAULT_REQUIRED_FIELDS_ORDER),
        "optional_fields": list(STATE_VAULT_OPTIONAL_FIELDS_ORDER),
        "limits": {
            "max_string_len": STATE_VAULT_MAX_STRING_LEN,
            "max_record_bytes": STATE_VAULT_MAX_RECORD_BYTES,
        },
        "genesis_parent_hash": GENESIS_PARENT_HASH,
    }
    return _sha256_text(_canonical_json(spec))


STATE_VAULT_SCHEMA_VERSION_HASH = compute_state_vault_schema_version_hash()


@dataclass(frozen=True)
class StateVaultValidationError(Exception):
    message: str

    def __str__(self) -> str:
        return self.message


def utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def validate_state_vault_record(entry: Dict[str, Any]) -> None:
    if not isinstance(entry, dict):
        raise StateVaultValidationError("State-vault record must be a JSON object")

    missing = STATE_VAULT_REQUIRED_FIELDS - set(entry.keys())
    if missing:
        raise StateVaultValidationError(f"Missing required record fields: {sorted(missing)}")

    extra = set(entry.keys()) - STATE_VAULT_ALLOWED_FIELDS
    if extra:
        raise StateVaultValidationError(f"Forbidden record fields present: {sorted(extra)}")

    if entry.get("schema_id") != STATE_VAULT_SCHEMA_ID:
        raise StateVaultValidationError(f"schema_id must be {STATE_VAULT_SCHEMA_ID!r}")
    if entry.get("schema_version_hash") != STATE_VAULT_SCHEMA_VERSION_HASH:
        raise StateVaultValidationError("schema_version_hash does not match current schema")

    _validate_short_string(entry, "event_type", max_len=64)
    _validate_short_string(entry, "organ_id", max_len=64)
    _validate_short_string(entry, "created_at", max_len=64)
    if not _UTC_Z_RE.match(entry["created_at"]):
        raise StateVaultValidationError("created_at must be UTC ISO-8601 with 'Z' suffix")

    for field in ("receipt_id", "event_hash", "parent_hash", "payload_hash", "constitution_version_hash"):
        _validate_hash_hex(entry, field)

    for field in ("inputs_hash", "outputs_hash"):
        if field in entry:
            _validate_hash_hex(entry, field)

    if "energy_cost" in entry:
        if not isinstance(entry["energy_cost"], (int, float)):
            raise StateVaultValidationError("energy_cost must be a number")
        if entry["energy_cost"] < 0:
            raise StateVaultValidationError("energy_cost must be >= 0")
        if entry["energy_cost"] > 1e9:
            raise StateVaultValidationError("energy_cost exceeds maximum allowed")

    if "energy_source" in entry:
        _validate_short_string(entry, "energy_source", max_len=64)
        if entry["energy_source"] not in ALLOWED_ENERGY_SOURCES:
            raise StateVaultValidationError("energy_source is not in allowed enum set")

    if "crisis_mode" in entry:
        _validate_short_string(entry, "crisis_mode", max_len=64)
        if entry["crisis_mode"] not in ALLOWED_CRISIS_MODES:
            raise StateVaultValidationError("crisis_mode is not in allowed enum set")

    canonical = _canonical_json(entry)
    if len(canonical.encode("utf-8")) > STATE_VAULT_MAX_RECORD_BYTES:
        raise StateVaultValidationError("State-vault record exceeds max_record_bytes")


def _validate_hash_hex(entry: Dict[str, Any], field: str) -> None:
    value = entry.get(field)
    if not isinstance(value, str):
        raise StateVaultValidationError(f"{field} must be a string")
    if not _HEX_64_RE.match(value):
        raise StateVaultValidationError(f"{field} must be 64 lowercase hex chars")


def _validate_short_string(entry: Dict[str, Any], field: str, *, max_len: int) -> None:
    value = entry.get(field)
    if not isinstance(value, str):
        raise StateVaultValidationError(f"{field} must be a string")
    if len(value) > max_len:
        raise StateVaultValidationError(f"{field} exceeds max length {max_len}")


def compute_payload_hash(payload_fields: Dict[str, Any]) -> str:
    return _sha256_text(_canonical_json(payload_fields))


def compute_event_hash(
    *,
    payload_hash: str,
    event_type: str,
    organ_id: str,
    parent_hash: str,
    schema_version_hash: str,
    constitution_version_hash: str,
) -> str:
    material = {
        "payload_hash": payload_hash,
        "event_type": event_type,
        "organ_id": organ_id,
        "parent_hash": parent_hash,
        "schema_version_hash": schema_version_hash,
        "constitution_version_hash": constitution_version_hash,
    }
    return _sha256_text(_canonical_json(material))


def build_state_vault_record(
    *,
    receipt_id: str,
    created_at: str,
    event_type: str,
    organ_id: str,
    parent_hash: str,
    constitution_version_hash: str,
    inputs_hash: Optional[str] = None,
    outputs_hash: Optional[str] = None,
    energy_cost: Optional[float] = None,
    energy_source: Optional[str] = None,
    crisis_mode: Optional[str] = None,
) -> Dict[str, Any]:
    payload_fields: Dict[str, Any] = {}
    if inputs_hash is not None:
        payload_fields["inputs_hash"] = inputs_hash
    if outputs_hash is not None:
        payload_fields["outputs_hash"] = outputs_hash
    if energy_cost is not None:
        payload_fields["energy_cost"] = float(energy_cost)
    if energy_source is not None:
        payload_fields["energy_source"] = energy_source
    if crisis_mode is not None:
        payload_fields["crisis_mode"] = crisis_mode

    forbidden_payload = set(payload_fields.keys()) - STATE_VAULT_PAYLOAD_FIELDS
    if forbidden_payload:
        raise StateVaultValidationError(f"Forbidden payload keys present: {sorted(forbidden_payload)}")

    payload_hash = compute_payload_hash(payload_fields)
    event_hash = compute_event_hash(
        payload_hash=payload_hash,
        event_type=event_type,
        organ_id=organ_id,
        parent_hash=parent_hash,
        schema_version_hash=STATE_VAULT_SCHEMA_VERSION_HASH,
        constitution_version_hash=constitution_version_hash,
    )

    entry: Dict[str, Any] = {
        "receipt_id": receipt_id,
        "created_at": created_at,
        "event_type": event_type,
        "organ_id": organ_id,
        "event_hash": event_hash,
        "parent_hash": parent_hash,
        "payload_hash": payload_hash,
        "schema_id": STATE_VAULT_SCHEMA_ID,
        "schema_version_hash": STATE_VAULT_SCHEMA_VERSION_HASH,
        "constitution_version_hash": constitution_version_hash,
    }
    entry.update(payload_fields)

    validate_state_vault_record(entry)
    return entry

