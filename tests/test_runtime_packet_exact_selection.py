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

def test_runtime_packet_selection_fails_on_ambiguous_matches():
    obj = read_json("reports/v14_runtime_packet_selection_receipt.json")
    assert obj.get("fail_on_multiple_candidates") is True
    assert obj.get("broad_glob_allowed", False) is False
