from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_canonical_json_bytes,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_bounded_json_value,
    validate_hex_64,
    validate_short_string,
)
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_VALIDATOR_CATALOG_SCHEMA_ID = "kt.validator_catalog.v1"
FL3_VALIDATOR_CATALOG_SCHEMA_FILE = "fl3/kt.validator_catalog.v1.json"
FL3_VALIDATOR_CATALOG_SCHEMA_VERSION_HASH = schema_version_hash(FL3_VALIDATOR_CATALOG_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "validator_catalog_id",
    "validators",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER) | {"notes"}
_HASH_DROP_KEYS = {"created_at", "validator_catalog_id"}

_VALIDATOR_REQUIRED = {"validator_id", "kind", "params"}
_VALIDATOR_ALLOWED = set(_VALIDATOR_REQUIRED) | {"notes"}

_KINDS: Set[str] = {
    "REGEX_REQUIRED",
    "REGEX_FORBIDDEN",
    "MAX_WORDS",
    "SENTENCE_COUNT_EXACT",
    "LIST_ITEMS_EXACT",
    "JSON_PARSEABLE",
    "JSON_EXACT_OBJECT",
    "MUST_REFUSE",
}


def _validate_validator_params(*, kind: str, params: Dict[str, Any]) -> Dict[str, Any]:
    enforce_max_fields(params, max_fields=16)
    validate_bounded_json_value(params, max_depth=6, max_string_len=4096, max_list_len=128)

    k = kind.strip().upper()
    if k in {"REGEX_REQUIRED", "REGEX_FORBIDDEN"}:
        require_keys(params, required={"pattern"})
        reject_unknown_keys(params, allowed={"pattern", "flags"})
        pattern = str(params.get("pattern", "")).strip()
        if not pattern:
            raise SchemaValidationError("regex validator params.pattern must be non-empty (fail-closed)")
        validate_short_string({"pattern": pattern}, "pattern", max_len=4096)
        params["pattern"] = pattern
        flags = params.get("flags", [])
        if flags is None:
            flags = []
        if not isinstance(flags, list) or not all(isinstance(x, str) and x.strip() for x in flags):
            raise SchemaValidationError("regex validator params.flags must be list[str] (fail-closed)")
        flags_norm = sorted({x.strip().upper() for x in flags})
        for f in flags_norm:
            if f not in {"IGNORECASE", "MULTILINE", "DOTALL"}:
                raise SchemaValidationError("regex validator params.flags contains unknown flag (fail-closed)")
        params["flags"] = flags_norm
        return params

    if k == "MAX_WORDS":
        require_keys(params, required={"max_words"})
        reject_unknown_keys(params, allowed={"max_words"})
        mw = params.get("max_words")
        if not isinstance(mw, int) or mw < 0:
            raise SchemaValidationError("MAX_WORDS params.max_words must be int>=0 (fail-closed)")
        params["max_words"] = int(mw)
        return params

    if k == "SENTENCE_COUNT_EXACT":
        require_keys(params, required={"count"})
        reject_unknown_keys(params, allowed={"count"})
        n = params.get("count")
        if not isinstance(n, int) or n < 0:
            raise SchemaValidationError("SENTENCE_COUNT_EXACT params.count must be int>=0 (fail-closed)")
        params["count"] = int(n)
        return params

    if k == "LIST_ITEMS_EXACT":
        require_keys(params, required={"count", "style"})
        reject_unknown_keys(params, allowed={"count", "style"})
        n = params.get("count")
        if not isinstance(n, int) or n < 0:
            raise SchemaValidationError("LIST_ITEMS_EXACT params.count must be int>=0 (fail-closed)")
        style = str(params.get("style", "")).strip().upper()
        if style not in {"HYPHEN", "NUMBERED"}:
            raise SchemaValidationError("LIST_ITEMS_EXACT params.style invalid (fail-closed)")
        params["count"] = int(n)
        params["style"] = style
        return params

    if k == "JSON_PARSEABLE":
        reject_unknown_keys(params, allowed=set())
        return params

    if k == "JSON_EXACT_OBJECT":
        require_keys(params, required={"expected"})
        reject_unknown_keys(params, allowed={"expected"})
        expected = params.get("expected")
        validate_bounded_json_value(expected, max_depth=12, max_string_len=4096, max_list_len=256)
        params["expected"] = expected
        return params

    if k == "MUST_REFUSE":
        require_keys(params, required={"required_patterns"})
        reject_unknown_keys(params, allowed={"required_patterns", "forbidden_patterns", "max_words"})
        req = params.get("required_patterns")
        if not isinstance(req, list) or not all(isinstance(x, str) and x.strip() for x in req):
            raise SchemaValidationError("MUST_REFUSE params.required_patterns must be list[str] (fail-closed)")
        required = [x.strip() for x in req]
        if required != sorted(required):
            raise SchemaValidationError("MUST_REFUSE required_patterns must be sorted (fail-closed)")
        params["required_patterns"] = required

        forbid = params.get("forbidden_patterns", [])
        if forbid is None:
            forbid = []
        if not isinstance(forbid, list) or not all(isinstance(x, str) and x.strip() for x in forbid):
            raise SchemaValidationError("MUST_REFUSE forbidden_patterns must be list[str] (fail-closed)")
        forbidden = [x.strip() for x in forbid]
        if forbidden != sorted(forbidden):
            raise SchemaValidationError("MUST_REFUSE forbidden_patterns must be sorted (fail-closed)")
        params["forbidden_patterns"] = forbidden

        mw = params.get("max_words", None)
        if mw is not None:
            if not isinstance(mw, int) or mw < 0:
                raise SchemaValidationError("MUST_REFUSE max_words must be int>=0 or null (fail-closed)")
            params["max_words"] = int(mw)
        return params

    raise SchemaValidationError("validator kind unknown (fail-closed)")


def _validate_validators(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise SchemaValidationError("validators must be a non-empty list (fail-closed)")
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    for item in value:
        row = require_dict(item, name="validators[]")
        enforce_max_fields(row, max_fields=16)
        require_keys(row, required=_VALIDATOR_REQUIRED)
        reject_unknown_keys(row, allowed=_VALIDATOR_ALLOWED)

        vid = str(row.get("validator_id", "")).strip()
        if not vid:
            raise SchemaValidationError("validator_id must be non-empty (fail-closed)")
        validate_short_string({"validator_id": vid}, "validator_id", max_len=128)
        if vid in seen:
            raise SchemaValidationError("duplicate validator_id (fail-closed)")
        seen.add(vid)
        row["validator_id"] = vid

        kind = str(row.get("kind", "")).strip().upper()
        if kind not in _KINDS:
            raise SchemaValidationError("validator kind invalid (fail-closed)")
        row["kind"] = kind

        params = require_dict(row.get("params"), name="params")
        row["params"] = _validate_validator_params(kind=kind, params=params)

        if "notes" in row and row["notes"] is not None:
            validate_short_string(row, "notes", max_len=2048)

        out.append(row)

    ids = [r["validator_id"] for r in out]
    if ids != sorted(ids):
        raise SchemaValidationError("validators must be sorted by validator_id (fail-closed)")
    return out


def validate_fl3_validator_catalog(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="validator_catalog")
    enforce_max_fields(entry, max_fields=64)
    enforce_max_canonical_json_bytes(entry, max_bytes=256_000)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_VALIDATOR_CATALOG_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_VALIDATOR_CATALOG_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "validator_catalog_id")
    validate_created_at_utc_z(entry.get("created_at"))
    if "notes" in entry and entry["notes"] is not None:
        validate_short_string(entry, "notes", max_len=8192)

    entry["validators"] = _validate_validators(entry.get("validators"))

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("validator_catalog_id") != expected:
        raise SchemaValidationError("validator_catalog_id does not match canonical hash surface (fail-closed)")

