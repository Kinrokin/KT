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

def test_v13_scores_are_reconciled_to_known_values():
    obj = read_json("reports/v13_score_reconciliation_receipt.json")
    assert obj.get("base_raw_correct") == 111
    assert obj.get("formal_math_router_specialist_correct") == 122
    assert obj.get("oracle_math_router_correct") == 135
    assert obj.get("measured_input_rows") == 200
    assert obj.get("reconciliation_status") in {"PASS", "PASS_RECONCILED", "MEASURED_RECONCILED"}
