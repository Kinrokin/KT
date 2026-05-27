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

def test_specialist_atlas_has_required_lanes():
    obj = read_json("specialist_admission_atlas.json")
    text = json.dumps(obj)
    for lane in ["formal_math", "claim_boundary", "evidence_grounding", "red_assault_misdirection", "long_horizon_state", "code_tool_execution", "commercial_audit_proof", "paradox_contradiction"]:
        assert lane in text
    assert obj.get("claim_ceiling_preserved") is True
