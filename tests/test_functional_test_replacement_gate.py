from pathlib import Path
import json

ROOT = Path.cwd()

def read_json(path: str):
    p = ROOT / path
    assert p.exists(), f"missing required JSON: {path}"
    return json.loads(p.read_text(encoding="utf-8"))

def read_text(path: str) -> str:
    p = ROOT / path
    assert p.exists(), f"missing required file: {path}"
    return p.read_text(encoding="utf-8")

def test_functional_replacement_receipt_exists_and_passes():
    obj = read_json("reports/v14_placeholder_replacement_receipt.json")
    assert obj["schema_id"] == "kt.functional_test_replacement_receipt.v1"
    assert obj["gate_pass"] is True
    assert obj["remaining_placeholders"] == []
    assert obj["claim_ceiling_preserved"] is True
