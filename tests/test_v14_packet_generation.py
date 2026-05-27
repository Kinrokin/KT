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

def test_v14_packet_generation_receipt_has_exact_name_and_sha():
    obj = read_json("reports/v14_runtime_packet_selection_receipt.json")
    assert obj.get("exact_name_required") is True
    assert obj.get("exact_sha_required") is True
    assert obj.get("claim_ceiling_preserved") is True
