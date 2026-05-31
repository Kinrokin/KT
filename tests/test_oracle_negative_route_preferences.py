import json
from pathlib import Path

ROOT = Path.cwd()


def read_jsonl(path: str):
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_negative_preferences_suppress_harmful_routes_without_training_authority():
    rows = read_jsonl("admission/oracle_negative_route_preferences.jsonl")
    assert rows
    assert all(row["training_authority"] == "ROUTE_VALUE_DISTILLATION_ONLY" for row in rows)
    assert all(row["adapter_training_forbidden"] is True for row in rows)
