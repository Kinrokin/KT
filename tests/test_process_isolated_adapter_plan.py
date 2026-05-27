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

def test_process_isolation_plan_requires_process_per_arm():
    obj = read_json("reports/process_isolation_plan_receipt.json")
    assert obj.get("process_per_arm_required") is True or "PROCESS_ISOLATED" in json.dumps(obj)
    assert obj.get("claim_ceiling_preserved") is True
