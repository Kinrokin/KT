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

def test_claim_casefile_blocks_high_claims():
    obj = read_json("reports/v14_claim_admissibility_casefile.json")
    text = json.dumps(obj).lower()
    for term in ["adapter promotion", "router superiority", "commercial", "s-tier", "production"]:
        assert term in text
    assert obj.get("claim_ceiling_preserved") is True
