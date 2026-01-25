from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from schemas.schema_hash import sha256_json


def schema_root() -> Path:
    # .../04_PROD_TEMPLE_V2/src/schemas/schema_files.py -> .../04_PROD_TEMPLE_V2
    return Path(__file__).resolve().parents[2]


def schema_path(filename: str) -> Path:
    return schema_root() / "schemas" / filename


def load_schema(filename: str) -> Dict[str, Any]:
    path = schema_path(filename)
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Schema file missing or unreadable (fail-closed): {path.as_posix()}") from exc
    try:
        payload = json.loads(text)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Schema file is not valid JSON (fail-closed): {path.as_posix()}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Schema file must be a JSON object (fail-closed): {path.as_posix()}")
    return payload


def schema_version_hash(filename: str) -> str:
    payload = load_schema(filename)
    return sha256_json(payload)
