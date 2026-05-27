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

def test_governed_admittance_doctrine_present():
    obj = read_json("governance/governed_admittance_doctrine.json")
    text = json.dumps(obj).lower()
    assert "admission" in text or "admittance" in text
    assert obj.get("claim_ceiling_preserved") is True
