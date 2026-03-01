from __future__ import annotations

import hashlib

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


FL3_SUITE_OUTPUTS_SCHEMA_ID = "kt.suite_outputs.v1"
FL3_SUITE_OUTPUTS_SCHEMA_FILE = "fl3/kt.suite_outputs.v1.json"
FL3_SUITE_OUTPUTS_SCHEMA_VERSION_HASH = schema_version_hash(FL3_SUITE_OUTPUTS_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "suite_outputs_id",
    "base_model_id",
    "subject",
    "suite_id",
    "suite_root_hash",
    "decode_policy_id",
    "decode_cfg_hash",
    "outputs",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "suite_outputs_id"}

_SUBJECT_REQUIRED = {"subject_kind", "subject_id"}
_SUBJECT_ALLOWED = {"subject_kind", "subject_id", "adapter_root_hash"}

_OUTPUT_REQUIRED = {"case_id", "output_text", "output_sha256"}
_OUTPUT_ALLOWED = set(_OUTPUT_REQUIRED)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_fl3_suite_outputs(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="suite_outputs")
    enforce_max_fields(entry, max_fields=128)
    enforce_max_canonical_json_bytes(entry, max_bytes=2_000_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_SUITE_OUTPUTS_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_SUITE_OUTPUTS_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "suite_outputs_id")
    validate_short_string(entry, "base_model_id", max_len=128)
    validate_short_string(entry, "suite_id", max_len=128)
    validate_hex_64(entry, "suite_root_hash")
    validate_short_string(entry, "decode_policy_id", max_len=128)
    validate_hex_64(entry, "decode_cfg_hash")
    validate_created_at_utc_z(entry.get("created_at"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    subject = require_dict(entry.get("subject"), name="subject")
    enforce_max_fields(subject, max_fields=8)
    require_keys(subject, required=_SUBJECT_REQUIRED)
    reject_unknown_keys(subject, allowed=_SUBJECT_ALLOWED)
    kind = str(subject.get("subject_kind", "")).strip().upper()
    if kind not in {"BASE", "ADAPTER"}:
        raise SchemaValidationError("subject.subject_kind invalid (fail-closed)")
    subject["subject_kind"] = kind
    sid = str(subject.get("subject_id", "")).strip()
    if not sid:
        raise SchemaValidationError("subject.subject_id must be non-empty (fail-closed)")
    validate_short_string({"subject_id": sid}, "subject_id", max_len=256)
    subject["subject_id"] = sid
    arh = subject.get("adapter_root_hash", None)
    if arh is not None:
        if not isinstance(arh, str):
            raise SchemaValidationError("subject.adapter_root_hash must be string or null (fail-closed)")
        validate_hex_64({"adapter_root_hash": arh}, "adapter_root_hash")
    entry["subject"] = subject

    outs = entry.get("outputs")
    if not isinstance(outs, list) or not outs:
        raise SchemaValidationError("outputs must be non-empty list (fail-closed)")
    out_norm: List[Dict[str, Any]] = []
    order: List[str] = []
    seen: Set[str] = set()
    for item in outs:
        row = require_dict(item, name="outputs[]")
        enforce_max_fields(row, max_fields=8)
        require_keys(row, required=_OUTPUT_REQUIRED)
        reject_unknown_keys(row, allowed=_OUTPUT_ALLOWED)
        cid = str(row.get("case_id", "")).strip()
        if not cid:
            raise SchemaValidationError("outputs[].case_id must be non-empty (fail-closed)")
        validate_short_string({"case_id": cid}, "case_id", max_len=64)
        if cid in seen:
            raise SchemaValidationError("duplicate outputs[].case_id (fail-closed)")
        seen.add(cid)
        txt = row.get("output_text")
        if not isinstance(txt, str):
            raise SchemaValidationError("outputs[].output_text must be string (fail-closed)")
        sha = str(row.get("output_sha256", "")).strip()
        validate_hex_64({"output_sha256": sha}, "output_sha256")
        expected_sha = _sha256_text(txt)
        if sha != expected_sha:
            raise SchemaValidationError("outputs[].output_sha256 mismatch vs output_text (fail-closed)")
        out_norm.append({"case_id": cid, "output_text": txt, "output_sha256": sha})
        order.append(cid)
    if order != sorted(order):
        raise SchemaValidationError("outputs must be sorted by case_id (fail-closed)")
    entry["outputs"] = out_norm

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("suite_outputs_id") != expected:
        raise SchemaValidationError("suite_outputs_id does not match canonical hash surface (fail-closed)")

