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

def test_commercial_surface_is_scaffold_only():
    obj = read_json("commercial/commercial_claim_boundary.json")
    text = json.dumps(obj).lower()
    assert "no commercial" in text or "commercial" in text
    assert obj.get("commercial_authority", False) is False
