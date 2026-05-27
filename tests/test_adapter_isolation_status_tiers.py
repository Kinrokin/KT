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

def test_adapter_isolation_tiers_defined():
    obj = read_json("reports/adapter_isolation_status_tiers.json")
    text = json.dumps(obj)
    for tier in ["PROCESS_ISOLATED_MEASURED", "PEFT_UNLOAD_RELOAD_MEASURED", "BEST_EFFORT_PROVISIONAL", "FAILED"]:
        assert tier in text
    assert obj.get("claim_ceiling_preserved") is True
