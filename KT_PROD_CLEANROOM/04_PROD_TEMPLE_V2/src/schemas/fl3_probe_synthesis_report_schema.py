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


FL3_PROBE_SYNTHESIS_REPORT_SCHEMA_ID = "kt.probe_synthesis_report.v1"
FL3_PROBE_SYNTHESIS_REPORT_SCHEMA_FILE = "fl3/kt.probe_synthesis_report.v1.json"
FL3_PROBE_SYNTHESIS_REPORT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_PROBE_SYNTHESIS_REPORT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "report_id",
    "manifest_id",
    "synthesizer_version",
    "synthesized_probes",
    "created_at",
)
_OPTIONAL_ORDER = ("notes",)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER + _OPTIONAL_ORDER)
_HASH_DROP_KEYS = {"created_at", "report_id"}


def _validate_probes(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        raise SchemaValidationError("synthesized_probes must be list (fail-closed)")
    out: List[Dict[str, Any]] = []
    for item in value:
        row = require_dict(item, name="synthesized_probes[]")
        require_keys(
            row,
            required={
                "probe_id",
                "reason_code",
                "title",
                "prompt",
                "expected_behavior",
                "requires_human_review",
                "earliest_review_timestamp",
            },
        )
        reject_unknown_keys(
            row,
            allowed={
                "probe_id",
                "reason_code",
                "title",
                "prompt",
                "expected_behavior",
                "requires_human_review",
                "earliest_review_timestamp",
            },
        )
        probe_id = str(row.get("probe_id", "")).strip()
        reason_code = str(row.get("reason_code", "")).strip()
        title = str(row.get("title", "")).strip()
        prompt = str(row.get("prompt", "")).strip()
        expected = str(row.get("expected_behavior", "")).strip()
        requires = row.get("requires_human_review")
        earliest = str(row.get("earliest_review_timestamp", "")).strip()
        if requires is not True:
            raise SchemaValidationError("requires_human_review must be true (fail-closed)")
        validate_hex_64({"probe_id": probe_id}, "probe_id")
        validate_short_string({"reason_code": reason_code}, "reason_code", max_len=128)
        validate_short_string({"title": title}, "title", max_len=256)
        validate_short_string({"prompt": prompt}, "prompt", max_len=8192)
        validate_short_string({"expected_behavior": expected}, "expected_behavior", max_len=8192)
        validate_short_string({"earliest_review_timestamp": earliest}, "earliest_review_timestamp", max_len=64)
        out.append(
            {
                "probe_id": probe_id,
                "reason_code": reason_code,
                "title": title,
                "prompt": prompt,
                "expected_behavior": expected,
                "requires_human_review": True,
                "earliest_review_timestamp": earliest,
            }
        )
    # Deterministic ordering
    keys = [(p["reason_code"], p["probe_id"]) for p in out]
    if keys != sorted(keys):
        raise SchemaValidationError("synthesized_probes must be sorted by reason_code,probe_id (fail-closed)")
    return out


def validate_fl3_probe_synthesis_report(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="probe_synthesis_report")
    enforce_max_fields(entry, max_fields=2048)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_PROBE_SYNTHESIS_REPORT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_PROBE_SYNTHESIS_REPORT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "report_id")
    validate_hex_64(entry, "manifest_id")
    validate_created_at_utc_z(entry.get("created_at"))

    validate_short_string(entry, "synthesizer_version", max_len=128)
    _ = _validate_probes(entry.get("synthesized_probes"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("report_id") != expected:
        raise SchemaValidationError("report_id does not match canonical hash surface (fail-closed)")

