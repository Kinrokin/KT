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

def test_pre_generation_route_receipt_declares_route_mode():
    obj = read_json("reports/pre_generation_route_decision_receipt.json")
    text = json.dumps(obj)
    assert any(k in text for k in ["PRE_GENERATION_ROUTE", "POST_HOC_ORACLE_STYLE_ANALYSIS_ONLY", "STATIC_DATASET_RULE", "HYBRID_RULE", "UNKNOWN_BLOCKED"])
    assert obj.get("claim_ceiling_preserved") is True
