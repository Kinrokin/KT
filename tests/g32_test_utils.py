from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: set[str] = set()
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate JSON key: {key}")
        seen.add(key)
        out[key] = value
    return out


def load_json(rel_path: str) -> dict:
    return json.loads((ROOT / rel_path).read_text(encoding="utf-8-sig"), object_pairs_hook=reject_duplicate_keys)


def read_jsonl(rel_path: str) -> list[dict]:
    return [
        json.loads(line, object_pairs_hook=reject_duplicate_keys)
        for line in (ROOT / rel_path).read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]


def required_schema_fields(rel_path: str) -> set[str]:
    schema = load_json(rel_path)
    return set(schema.get("required", []))
