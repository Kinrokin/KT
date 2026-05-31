import json
from pathlib import Path

ROOT = Path.cwd()


def read_jsonl(path: str):
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_base_preservation_preferences_exist_for_base_rescues():
    rows = read_jsonl("admission/base_preservation_preferences.jsonl")
    assert len(rows) >= 3
    assert all(row["preferred_route"] == "base_raw" for row in rows)
    receipt = json.loads((ROOT / "reports/base_raw_preservation_receipt.json").read_text(encoding="utf-8"))
    assert receipt["base_preservation_case_count"] == len(rows)
