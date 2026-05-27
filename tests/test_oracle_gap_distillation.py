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

def test_oracle_gap_rows_exist_or_receipt_blocks():
    p = ROOT / "admission/oracle_gap_analysis.jsonl"
    assert p.exists(), "missing oracle gap ledger"
    assert p.stat().st_size > 0, "oracle gap ledger must not be empty"
