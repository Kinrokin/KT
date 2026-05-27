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

def test_cross_domain_registry_maps_to_artifacts():
    obj = read_json("cross_domain/cross_domain_concept_registry.json")
    text = json.dumps(obj).lower()
    for word in ["medicine", "law", "ecology", "engineering"]:
        assert word in text
