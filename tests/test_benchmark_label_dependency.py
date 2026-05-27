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

def test_benchmark_label_dependency_classification_present():
    obj = read_json("reports/benchmark_label_dependency_scorecard.json")
    text = json.dumps(obj)
    assert any(k in text for k in ["LABEL_BOUND", "HYBRID_LABEL_AND_STRUCTURE_BOUND", "STRUCTURE_BOUND", "UNKNOWN_BLOCKED"])
    assert obj.get("claim_ceiling_preserved") is True
