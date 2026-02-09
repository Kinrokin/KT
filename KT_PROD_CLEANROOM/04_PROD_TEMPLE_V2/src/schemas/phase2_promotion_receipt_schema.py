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


PHASE2_PROMOTION_RECEIPT_SCHEMA_ID = "kt.phase2_promotion_receipt.v1"
PHASE2_PROMOTION_RECEIPT_SCHEMA_FILE = "fl3/kt.phase2_promotion_receipt.v1.json"
PHASE2_PROMOTION_RECEIPT_SCHEMA_VERSION_HASH = schema_version_hash(PHASE2_PROMOTION_RECEIPT_SCHEMA_FILE)

_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "schema_version",
    "promotion_receipt_id",
    "train_request_id",
    "pinned_sha",
    "adapter_id",
    "adapter_version",
    "training_mode",
    "status",
    "failure_reason",
    "train_receipt_ref",
    "artifact_manifest_ref",
    "output_package",
    "io_guard_receipt_glob",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"promotion_receipt_id", "created_at"}


def _validate_hex40(value: Any, *, field: str) -> None:
    if not isinstance(value, str) or not _HEX40_RE.match(value):
        raise SchemaValidationError(f"{field} must be 40 lowercase hex chars (fail-closed)")


def _validate_clean_relpath(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SchemaValidationError(f"{field} must be a non-empty string (fail-closed)")
    norm = value.replace("\\", "/").strip()
    if norm.startswith("/"):
        raise SchemaValidationError(f"{field} must be relative (fail-closed)")
    if ".." in norm.split("/"):
        raise SchemaValidationError(f"{field} must not contain '..' (fail-closed)")
    return norm


def validate_phase2_promotion_receipt(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="Phase2 promotion receipt")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    enforce_max_canonical_json_bytes(entry, max_bytes=512 * 1024)

    if entry.get("schema_id") != PHASE2_PROMOTION_RECEIPT_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != PHASE2_PROMOTION_RECEIPT_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")
    validate_hex_64(entry, "schema_version_hash")
    if entry.get("schema_version") != 1:
        raise SchemaValidationError("schema_version must be 1 (fail-closed)")

    validate_hex_64(entry, "promotion_receipt_id")
    validate_hex_64(entry, "train_request_id")
    _validate_hex40(entry.get("pinned_sha"), field="pinned_sha")

    validate_short_string(entry, "adapter_id", max_len=128)
    validate_short_string(entry, "adapter_version", max_len=64)
    if entry.get("training_mode") != "lora_mrt1":
        raise SchemaValidationError("training_mode must be lora_mrt1 (fail-closed)")

    status = entry.get("status")
    if status not in {"PASS", "FAIL"}:
        raise SchemaValidationError("status invalid (fail-closed)")
    failure_reason = entry.get("failure_reason")
    if status == "PASS":
        if failure_reason is not None:
            raise SchemaValidationError("failure_reason must be null for PASS (fail-closed)")
    else:
        if not isinstance(failure_reason, str) or not failure_reason.strip():
            raise SchemaValidationError("failure_reason must be non-empty string for FAIL (fail-closed)")

    tr = require_dict(entry.get("train_receipt_ref"), name="train_receipt_ref")
    if set(tr.keys()) != {"path", "sha256"}:
        raise SchemaValidationError("train_receipt_ref keys mismatch (fail-closed)")
    trp = _validate_clean_relpath(tr.get("path"), field="train_receipt_ref.path")
    if not trp.startswith("KT_PROD_CLEANROOM/exports/adapters_mrt1_shadow"):
        raise SchemaValidationError("train_receipt_ref.path must be under exports/adapters_mrt1_shadow (fail-closed)")
    validate_hex_64(tr, "sha256")

    am = require_dict(entry.get("artifact_manifest_ref"), name="artifact_manifest_ref")
    if set(am.keys()) != {"path", "sha256"}:
        raise SchemaValidationError("artifact_manifest_ref keys mismatch (fail-closed)")
    amp = _validate_clean_relpath(am.get("path"), field="artifact_manifest_ref.path")
    if not amp.startswith("KT_PROD_CLEANROOM/exports/adapters_mrt1_shadow"):
        raise SchemaValidationError("artifact_manifest_ref.path must be under exports/adapters_mrt1_shadow (fail-closed)")
    validate_hex_64(am, "sha256")

    out_pkg = require_dict(entry.get("output_package"), name="output_package")
    if set(out_pkg.keys()) != {"shadow_dir", "promoted_dir", "content_hash"}:
        raise SchemaValidationError("output_package keys mismatch (fail-closed)")
    shadow = _validate_clean_relpath(out_pkg.get("shadow_dir"), field="output_package.shadow_dir")
    if not shadow.startswith("KT_PROD_CLEANROOM/exports/adapters_mrt1_shadow"):
        raise SchemaValidationError("output_package.shadow_dir must be under exports/adapters_mrt1_shadow (fail-closed)")
    promoted = _validate_clean_relpath(out_pkg.get("promoted_dir"), field="output_package.promoted_dir")
    if not promoted.startswith("KT_PROD_CLEANROOM/exports/adapters_mrt1"):
        raise SchemaValidationError("output_package.promoted_dir must be under exports/adapters_mrt1 (fail-closed)")
    validate_hex_64(out_pkg, "content_hash")

    validate_short_string(entry, "io_guard_receipt_glob", max_len=256)
    validate_created_at_utc_z(entry.get("created_at"))

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("promotion_receipt_id") != expected:
        raise SchemaValidationError("promotion_receipt_id does not match canonical hash surface (fail-closed)")

