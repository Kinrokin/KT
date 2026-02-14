from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

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


FL3_LAW_BUNDLE_CHANGE_RECEIPT_SCHEMA_ID = "kt.law_bundle_change_receipt.v1"
FL3_LAW_BUNDLE_CHANGE_RECEIPT_SCHEMA_FILE = "fl3/kt.law_bundle_change_receipt.v1.json"
FL3_LAW_BUNDLE_CHANGE_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(FL3_LAW_BUNDLE_CHANGE_RECEIPT_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "receipt_id",
    "bundle_id",
    "old_ref",
    "old_bundle_hash",
    "new_bundle_hash",
    "diff",
    "counts",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "receipt_id"}


def _ensure_sorted_path_list(rows: Any, *, field: str) -> List[Dict[str, str]]:
    if not isinstance(rows, list):
        raise SchemaValidationError(f"{field} must be a list (fail-closed)")
    out: List[Dict[str, str]] = []
    for item in rows:
        d = require_dict(item, name=field)
        path = str(d.get("path", "")).strip()
        sha = str(d.get("sha256", "")).strip()
        if not path:
            raise SchemaValidationError(f"{field}.path missing (fail-closed)")
        if len(sha) != 64:
            raise SchemaValidationError(f"{field}.sha256 invalid (fail-closed)")
        out.append({"path": path, "sha256": sha})
    paths = [r["path"] for r in out]
    if paths != sorted(paths):
        raise SchemaValidationError(f"{field} must be sorted by path (fail-closed)")
    if len(set(paths)) != len(paths):
        raise SchemaValidationError(f"{field} paths must be unique (fail-closed)")
    return out


def _ensure_sorted_modified_list(rows: Any, *, field: str) -> List[Dict[str, str]]:
    if not isinstance(rows, list):
        raise SchemaValidationError(f"{field} must be a list (fail-closed)")
    out: List[Dict[str, str]] = []
    for item in rows:
        d = require_dict(item, name=field)
        path = str(d.get("path", "")).strip()
        old_sha = str(d.get("old_sha256", "")).strip()
        new_sha = str(d.get("new_sha256", "")).strip()
        if not path:
            raise SchemaValidationError(f"{field}.path missing (fail-closed)")
        if len(old_sha) != 64 or len(new_sha) != 64:
            raise SchemaValidationError(f"{field} sha256 invalid (fail-closed)")
        out.append({"path": path, "old_sha256": old_sha, "new_sha256": new_sha})
    paths = [r["path"] for r in out]
    if paths != sorted(paths):
        raise SchemaValidationError(f"{field} must be sorted by path (fail-closed)")
    if len(set(paths)) != len(paths):
        raise SchemaValidationError(f"{field} paths must be unique (fail-closed)")
    return out


def validate_fl3_law_bundle_change_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="law_bundle_change_receipt")
    enforce_max_fields(entry, max_fields=512)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_LAW_BUNDLE_CHANGE_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_LAW_BUNDLE_CHANGE_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "receipt_id")
    validate_hex_64(entry, "old_bundle_hash")
    validate_hex_64(entry, "new_bundle_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    bundle_id = str(entry.get("bundle_id", "")).strip()
    if not bundle_id:
        raise SchemaValidationError("bundle_id must be non-empty string (fail-closed)")
    old_ref = str(entry.get("old_ref", "")).strip()
    if not old_ref:
        raise SchemaValidationError("old_ref must be non-empty string (fail-closed)")

    diff = require_dict(entry.get("diff"), name="diff")
    counts = require_dict(entry.get("counts"), name="counts")

    added = _ensure_sorted_path_list(diff.get("added"), field="diff.added")
    removed = _ensure_sorted_path_list(diff.get("removed"), field="diff.removed")
    modified = _ensure_sorted_modified_list(diff.get("modified"), field="diff.modified")

    # Basic count sanity.
    expected_counts: List[Tuple[str, int]] = [
        ("added", len(added)),
        ("removed", len(removed)),
        ("modified", len(modified)),
    ]
    for k, v in expected_counts:
        if counts.get(k) != v:
            raise SchemaValidationError(f"counts.{k} mismatch (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("receipt_id") != expected:
        raise SchemaValidationError("receipt_id does not match canonical hash surface (fail-closed)")

