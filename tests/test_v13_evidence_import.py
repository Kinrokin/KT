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

def test_v13_evidence_import_receipt_binds_hf_and_rows():
    obj = read_json("reports/v13_evidence_import_receipt.json")
    assert obj.get("measured_input_rows") == 200
    assert "hf" in " ".join(str(v).lower() for v in obj.values()) or obj.get("hf_url")
    assert obj.get("claim_ceiling_preserved") is True
