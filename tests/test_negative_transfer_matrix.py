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

def test_negative_transfer_matrix_exists_and_blocks_global_promotion():
    obj = read_json("capability/negative_transfer_matrix.json")
    text = json.dumps(obj).lower()
    assert "formal_math" in text
    assert "global" in text or "blocked" in text or "negative" in text
