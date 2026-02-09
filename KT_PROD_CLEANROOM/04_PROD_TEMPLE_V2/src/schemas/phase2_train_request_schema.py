from __future__ import annotations

import re
from typing import Any, Dict, Set

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


PHASE2_TRAIN_REQUEST_SCHEMA_ID = "kt.phase2_train_request.v1"
PHASE2_TRAIN_REQUEST_SCHEMA_FILE = "fl3/kt.phase2_train_request.v1.json"
PHASE2_TRAIN_REQUEST_SCHEMA_VERSION_HASH = schema_version_hash(PHASE2_TRAIN_REQUEST_SCHEMA_FILE)

_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "schema_version",
    "train_request_id",
    "work_order_id",
    "pinned_sha",
    "adapter_id",
    "adapter_version",
    "role_id",
    "training_mode",
    "base_model",
    "dataset_manifest_ref",
    "seed",
    "device",
    "output",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"train_request_id", "created_at"}


def _validate_hex40(value: Any, *, field: str) -> None:
    if not isinstance(value, str) or not _HEX40_RE.match(value):
        raise SchemaValidationError(f"{field} must be 40 lowercase hex chars (fail-closed)")


def validate_phase2_train_request(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="Phase2 train request")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=256 * 1024)

    if entry.get("schema_id") != PHASE2_TRAIN_REQUEST_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != PHASE2_TRAIN_REQUEST_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    if entry.get("schema_version") != 1:
        raise SchemaValidationError("schema_version must be 1 (fail-closed)")

    validate_hex_64(entry, "train_request_id")
    validate_short_string(entry, "work_order_id", max_len=256)
    _validate_hex40(entry.get("pinned_sha"), field="pinned_sha")

    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "adapter_version", max_len=64)
    validate_short_string(entry, "role_id", max_len=64)

    if entry.get("training_mode") != "lora_mrt1":
        raise SchemaValidationError("training_mode must be lora_mrt1 (fail-closed)")

    base = require_dict(entry.get("base_model"), name="base_model")
    if set(base.keys()) != {"model_id", "local_path"}:
        raise SchemaValidationError("base_model keys mismatch (fail-closed)")
    validate_short_string(base, "model_id", max_len=256)
    validate_short_string(base, "local_path", max_len=512)

    ds = require_dict(entry.get("dataset_manifest_ref"), name="dataset_manifest_ref")
    if set(ds.keys()) != {"path", "sha256"}:
        raise SchemaValidationError("dataset_manifest_ref keys mismatch (fail-closed)")
    validate_short_string(ds, "path", max_len=512)
    validate_hex_64(ds, "sha256")

    seed = entry.get("seed")
    if not isinstance(seed, int):
        raise SchemaValidationError("seed must be integer (fail-closed)")

    device = entry.get("device")
    if device not in {"auto", "cpu", "cuda"}:
        raise SchemaValidationError("device invalid (fail-closed)")

    out = require_dict(entry.get("output"), name="output")
    if set(out.keys()) != {"export_root_shadow", "export_root_promoted"}:
        raise SchemaValidationError("output keys mismatch (fail-closed)")
    shadow = out.get("export_root_shadow")
    promoted = out.get("export_root_promoted")
    if not isinstance(shadow, str) or not shadow.startswith("KT_PROD_CLEANROOM/exports/adapters_mrt1_shadow"):
        raise SchemaValidationError("output.export_root_shadow must be under exports/adapters_mrt1_shadow (fail-closed)")
    if not isinstance(promoted, str) or not promoted.startswith("KT_PROD_CLEANROOM/exports/adapters_mrt1"):
        raise SchemaValidationError("output.export_root_promoted must be under exports/adapters_mrt1 (fail-closed)")

    validate_created_at_utc_z(entry.get("created_at"))

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("train_request_id") != expected:
        raise SchemaValidationError("train_request_id does not match canonical hash surface (fail-closed)")

