from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from tools.verification.fl3_canonical import canonical_json, sha256_text
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object


def read_json_object(path: Path) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unable to read JSON (fail-closed): {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"Expected JSON object (fail-closed): {path.as_posix()}")
    return obj


def write_schema_object(*, path: Path, obj: Dict[str, Any]) -> str:
    validate_schema_bound_object(obj)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True)
    path.write_text(text + "\n", encoding="utf-8")
    # Return canonical content hash to bind into higher-level receipts.
    return sha256_text(canonical_json(obj))

