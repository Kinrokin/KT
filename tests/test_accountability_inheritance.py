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

def test_accountability_inheritance_receipt_present():
    obj = read_json("reports/v14_accountability_inheritance_receipt.json")
    assert obj.get("claim_ceiling_preserved") is True
    text = json.dumps(obj).lower()
    assert "failure_confession" in text and "success_admissibility" in text
