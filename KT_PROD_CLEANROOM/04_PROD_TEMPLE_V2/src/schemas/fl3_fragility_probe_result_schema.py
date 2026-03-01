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
from schemas.fl3_schema_common import ensure_sorted_str_list, sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_FRAGILITY_PROBE_RESULT_SCHEMA_ID = "kt.fragility_probe_result.v1"
FL3_FRAGILITY_PROBE_RESULT_SCHEMA_FILE = "fl3/kt.fragility_probe_result.v1.json"
FL3_FRAGILITY_PROBE_RESULT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FRAGILITY_PROBE_RESULT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "fragility_probe_result_id",
    "counterpressure_plan_id",
    "status",
    "reason_codes",
    "evaluated_adapter_root_hashes",
    "probes",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "fragility_probe_result_id"}

_PROBE_REQUIRED = {"probe_id", "family", "status"}
_PROBE_ALLOWED = set(_PROBE_REQUIRED) | {"notes"}


def _validate_probes(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise SchemaValidationError("probes must be a non-empty list (fail-closed)")
    out: List[Dict[str, Any]] = []
    order: List[Tuple[str, str]] = []
    for item in value:
        d = require_dict(item, name="probes[]")
        enforce_max_fields(d, max_fields=8)
        require_keys(d, required=_PROBE_REQUIRED)
        reject_unknown_keys(d, allowed=_PROBE_ALLOWED)
        pid = str(d.get("probe_id", "")).strip()
        fam = str(d.get("family", "")).strip()
        st = str(d.get("status", "")).strip().upper()
        if not pid or not fam:
            raise SchemaValidationError("probe_id/family must be non-empty (fail-closed)")
        validate_short_string({"probe_id": pid}, "probe_id", max_len=128)
        validate_short_string({"family": fam}, "family", max_len=64)
        if st not in {"PASS", "FAIL_CLOSED"}:
            raise SchemaValidationError("probe status invalid (fail-closed)")
        record: Dict[str, Any] = {"probe_id": pid, "family": fam, "status": st}
        if "notes" in d:
            notes = d.get("notes")
            if notes is None:
                record["notes"] = None
            else:
                note_text = str(notes).strip()
                validate_short_string({"notes": note_text}, "notes", max_len=4000)
                record["notes"] = note_text
        out.append(record)
        order.append((fam, pid))
    if order != sorted(order):
        raise SchemaValidationError("probes must be sorted by (family, probe_id) (fail-closed)")
    return out


def validate_fl3_fragility_probe_result(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 fragility probe result v1")
    enforce_max_fields(entry, max_fields=96)
    enforce_max_canonical_json_bytes(entry, max_bytes=256_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FRAGILITY_PROBE_RESULT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FRAGILITY_PROBE_RESULT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "fragility_probe_result_id")
    validate_hex_64(entry, "counterpressure_plan_id")
    validate_created_at_utc_z(entry.get("created_at"))

    status = str(entry.get("status", "")).strip().upper()
    if status not in {"PASS", "FAIL_CLOSED"}:
        raise SchemaValidationError("status invalid (fail-closed)")
    entry["status"] = status

    entry["reason_codes"] = ensure_sorted_str_list(entry.get("reason_codes"), field="reason_codes")

    hashes = entry.get("evaluated_adapter_root_hashes")
    entry["evaluated_adapter_root_hashes"] = ensure_sorted_str_list(hashes, field="evaluated_adapter_root_hashes")
    for h in entry["evaluated_adapter_root_hashes"]:
        if not isinstance(h, str) or len(h) != 64:
            raise SchemaValidationError("evaluated_adapter_root_hashes must contain 64-hex strings (fail-closed)")

    entry["probes"] = _validate_probes(entry.get("probes"))

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("fragility_probe_result_id") != expected:
        raise SchemaValidationError("fragility_probe_result_id does not match canonical hash surface (fail-closed)")
