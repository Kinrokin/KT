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

def test_lobe_gate_court_boundary_contract_exists():
    obj = read_json("governance/lobe_gate_court_boundary_contract.json")
    assert obj.get("claim_ceiling_preserved") is True
    assert obj.get("gates_are_lobes") is False or obj.get("gates_not_lobes") is True
