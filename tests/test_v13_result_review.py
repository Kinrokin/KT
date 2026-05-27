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

def test_v13_result_review_preserves_no_promotion():
    obj = read_json("reports/v13_result_review_receipt.json")
    assert obj.get("promotion_eligible") is False
    assert obj.get("claim_ceiling_preserved") is True
    assert "formal_math_router_specialist" in json.dumps(obj)
