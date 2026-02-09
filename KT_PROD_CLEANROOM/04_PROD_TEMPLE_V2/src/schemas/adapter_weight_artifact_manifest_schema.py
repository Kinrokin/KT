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
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


ADAPTER_WEIGHT_ARTIFACT_MANIFEST_SCHEMA_ID = "kt.adapter_weight_artifact_manifest.v1"
ADAPTER_WEIGHT_ARTIFACT_MANIFEST_SCHEMA_FILE = "fl3/kt.adapter_weight_artifact_manifest.v1.json"
ADAPTER_WEIGHT_ARTIFACT_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(ADAPTER_WEIGHT_ARTIFACT_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "schema_version",
    "manifest_id",
    "adapter_id",
    "adapter_version",
    "training_mode",
    "base_model_id",
    "root_hash",
    "files",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"manifest_id", "created_at"}


def _validate_clean_relpath(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SchemaValidationError(f"{field} must be a non-empty string (fail-closed)")
    norm = value.replace("\\", "/").strip()
    if norm.startswith("/"):
        raise SchemaValidationError(f"{field} must be relative (fail-closed)")
    if ".." in norm.split("/"):
        raise SchemaValidationError(f"{field} must not contain '..' (fail-closed)")
    return norm


def _compute_root_hash(files: List[Dict[str, Any]]) -> str:
    # root_hash is a deterministic sha256 over the list of file entries (sorted by path).
    import hashlib
    import json

    cleaned = [
        {"path": str(f.get("path", "")).replace("\\", "/"), "sha256": str(f.get("sha256", "")), "bytes": int(f.get("bytes", 0) or 0)}
        for f in files
    ]
    cleaned = sorted(cleaned, key=lambda e: e["path"])
    canon = json.dumps(cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def validate_adapter_weight_artifact_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="Adapter weight artifact manifest")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=512 * 1024)

    if entry.get("schema_id") != ADAPTER_WEIGHT_ARTIFACT_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != ADAPTER_WEIGHT_ARTIFACT_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    if entry.get("schema_version") != 1:
        raise SchemaValidationError("schema_version must be 1 (fail-closed)")

    validate_hex_64(entry, "manifest_id")
    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "adapter_version", max_len=64)
    if entry.get("training_mode") != "lora_mrt1":
        raise SchemaValidationError("training_mode must be lora_mrt1 (fail-closed)")
    validate_short_string(entry, "base_model_id", max_len=256)
    validate_hex_64(entry, "root_hash")

    files = entry.get("files")
    if not isinstance(files, list) or not files:
        raise SchemaValidationError("files must be non-empty list (fail-closed)")
    cleaned: List[Dict[str, Any]] = []
    for f in files:
        fo = require_dict(f, name="file entry")
        require_keys(fo, required={"path", "sha256", "bytes"})
        reject_unknown_keys(fo, allowed={"path", "sha256", "bytes"})
        p = _validate_clean_relpath(fo.get("path"), field="files[].path")
        # forbid empty / directory paths
        if p.endswith("/"):
            raise SchemaValidationError("files[].path must be a file path (fail-closed)")
        validate_hex_64(fo, "sha256")
        b = fo.get("bytes")
        if not isinstance(b, int) or b < 0:
            raise SchemaValidationError("files[].bytes must be non-negative int (fail-closed)")
        cleaned.append({"path": p, "sha256": str(fo.get("sha256")), "bytes": int(b)})

    # Deterministic ordering.
    if [c["path"] for c in cleaned] != sorted([c["path"] for c in cleaned]):
        raise SchemaValidationError("files must be sorted by path (fail-closed)")

    expected_root = _compute_root_hash(cleaned)
    if entry.get("root_hash") != expected_root:
        raise SchemaValidationError("root_hash mismatch (fail-closed)")

    validate_created_at_utc_z(entry.get("created_at"))

    expected_id = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("manifest_id") != expected_id:
        raise SchemaValidationError("manifest_id does not match canonical hash surface (fail-closed)")

