from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Set, Tuple

from schemas.schema_hash import canonical_json


@dataclass(frozen=True)
class SchemaValidationError(ValueError):
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class SchemaRegistryError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


def require_dict(obj: Any, *, name: str) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise SchemaValidationError(f"{name} must be a JSON object (dict)")
    return obj


def require_keys(entry: Mapping[str, Any], *, required: Set[str]) -> None:
    missing = required - set(entry.keys())
    if missing:
        raise SchemaValidationError(f"Missing required fields: {sorted(missing)}")


def reject_unknown_keys(entry: Mapping[str, Any], *, allowed: Set[str]) -> None:
    extra = set(entry.keys()) - allowed
    if extra:
        raise SchemaValidationError(f"Forbidden fields present: {sorted(extra)}")


def enforce_max_fields(entry: Mapping[str, Any], *, max_fields: int) -> None:
    if len(entry) > max_fields:
        raise SchemaValidationError("Object exceeds max field count (fail-closed)")


def validate_short_string(entry: Mapping[str, Any], field: str, *, max_len: int) -> None:
    value = entry.get(field)
    if not isinstance(value, str):
        raise SchemaValidationError(f"{field} must be a string")
    if len(value) > max_len:
        raise SchemaValidationError(f"{field} exceeds max length {max_len}")


def validate_hex_64(entry: Mapping[str, Any], field: str) -> None:
    value = entry.get(field)
    if not isinstance(value, str):
        raise SchemaValidationError(f"{field} must be a string")
    if not _HEX_64_RE.match(value):
        raise SchemaValidationError(f"{field} must be 64 lowercase hex chars")


def validate_bounded_json_value(
    value: Any,
    *,
    max_depth: int,
    max_string_len: int,
    max_list_len: int,
    _depth: int = 0,
) -> None:
    if _depth > max_depth:
        raise SchemaValidationError("Object exceeds max nesting depth (fail-closed)")

    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and len(k) > max_string_len:
                raise SchemaValidationError("Object contains an overlong key string (fail-closed)")
            validate_bounded_json_value(
                v,
                max_depth=max_depth,
                max_string_len=max_string_len,
                max_list_len=max_list_len,
                _depth=_depth + 1,
            )
    elif isinstance(value, list):
        if len(value) > max_list_len:
            raise SchemaValidationError("List exceeds max length (fail-closed)")
        for item in value:
            validate_bounded_json_value(
                item,
                max_depth=max_depth,
                max_string_len=max_string_len,
                max_list_len=max_list_len,
                _depth=_depth + 1,
            )
    elif isinstance(value, str):
        if len(value) > max_string_len:
            raise SchemaValidationError("String exceeds max length (fail-closed)")
    elif isinstance(value, (int, float, bool)) or value is None:
        return
    else:
        raise SchemaValidationError("Unsupported JSON value type (fail-closed)")


def enforce_max_canonical_json_bytes(obj: Any, *, max_bytes: int) -> None:
    try:
        encoded = canonical_json(obj).encode("utf-8")
    except Exception as exc:
        raise SchemaValidationError(f"Object is not JSON-serializable (fail-closed): {exc.__class__.__name__}")
    if len(encoded) > max_bytes:
        raise SchemaValidationError("Object exceeds max bytes (fail-closed)")

