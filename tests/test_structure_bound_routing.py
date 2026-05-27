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

def test_structure_bound_routing_plan_has_ood_and_blind_tests():
    obj = read_json("reports/structure_bound_routing_plan_receipt.json")
    text = json.dumps(obj).lower()
    assert "ood" in text
    assert "blind" in text or "dataset" in text
    assert "math_act" in text or "structure" in text
