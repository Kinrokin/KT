from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64, validate_short_string
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_FACTORY_TRAIN_MANIFEST_SCHEMA_ID = "kt.factory.train_manifest.v1"
FL3_FACTORY_TRAIN_MANIFEST_SCHEMA_FILE = "fl3/kt.factory.train_manifest.v1.json"
FL3_FACTORY_TRAIN_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(FL3_FACTORY_TRAIN_MANIFEST_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "train_id",
    "job_id",
    "dataset_id",
    "base_model_id",
    "training_mode",
    "output_bundle",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "train_id"}


def validate_fl3_factory_train_manifest(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3 factory train manifest")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_FACTORY_TRAIN_MANIFEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_FACTORY_TRAIN_MANIFEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "train_id")
    validate_hex_64(entry, "job_id")
    validate_hex_64(entry, "dataset_id")
    validate_short_string(entry, "base_model_id", max_len=128)
    if entry.get("training_mode") not in {"lora", "head_only"}:
        raise SchemaValidationError("training_mode invalid (fail-closed)")
    validate_created_at_utc_z(entry.get("created_at"))

    bundle = require_dict(entry.get("output_bundle"), name="output_bundle")
    if set(bundle.keys()) != {"artifact_path", "artifact_hash"}:
        raise SchemaValidationError("output_bundle must have keys artifact_path,artifact_hash (fail-closed)")
    if not isinstance(bundle.get("artifact_path"), str) or not bundle["artifact_path"].strip():
        raise SchemaValidationError("output_bundle.artifact_path must be non-empty string (fail-closed)")
    if not isinstance(bundle.get("artifact_hash"), str) or not bundle["artifact_hash"].strip():
        raise SchemaValidationError("output_bundle.artifact_hash must be non-empty string (fail-closed)")
    if not isinstance(bundle["artifact_hash"], str) or len(bundle["artifact_hash"]) != 64:
        raise SchemaValidationError("output_bundle.artifact_hash must be 64 hex (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("train_id") != expected:
        raise SchemaValidationError("train_id does not match canonical hash surface (fail-closed)")

