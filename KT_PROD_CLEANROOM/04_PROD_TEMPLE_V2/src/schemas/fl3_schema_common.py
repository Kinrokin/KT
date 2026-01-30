from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Set

from schemas.base_schema import SchemaValidationError


_UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


def validate_created_at_utc_z(value: Any) -> None:
    if not isinstance(value, str) or not _UTC_Z_RE.match(value):
        raise SchemaValidationError("created_at must be UTC ISO-8601 with Z suffix")


def canonical_json(obj: Dict[str, Any]) -> str:
    # Match existing schema hash surfaces (ASCII only, stable ordering).
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex_of_obj(obj: Dict[str, Any], *, drop_keys: Set[str]) -> str:
    payload = {k: v for k, v in obj.items() if k not in drop_keys}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def ensure_sorted_str_list(values: Any, *, field: str) -> List[str]:
    if not isinstance(values, list) or not all(isinstance(x, str) and x.strip() for x in values):
        raise SchemaValidationError(f"{field} must be a list of non-empty strings")
    stripped = [x.strip() for x in values]
    if stripped != sorted(stripped):
        raise SchemaValidationError(f"{field} must be sorted (fail-closed)")
    return stripped

