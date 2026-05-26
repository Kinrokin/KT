from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_json(rel_path: str) -> dict:
    return json.loads((ROOT / rel_path).read_text(encoding="utf-8-sig"))


def read_jsonl(rel_path: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / rel_path).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def required_schema_fields(rel_path: str) -> set[str]:
    schema = load_json(rel_path)
    return set(schema.get("required", []))
