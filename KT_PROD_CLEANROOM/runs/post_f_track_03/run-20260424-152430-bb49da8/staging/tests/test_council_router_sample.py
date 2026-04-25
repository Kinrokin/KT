from __future__ import annotations
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod

def test_after_router_executes_and_emits_receipts():
    mod = load_module(ROOT / "council/sample/council_router_after.py")
    def provider(rmr):
        return {"decision_label": "commit", "why_not": [], "reason_codes": ["RC001_CONTEXT_ALIGNMENT"]}
    router = mod.CouncilRouter({"openai_hashed": provider, "mock_local": provider}, execute_live=True)
    result = router.execute({"rmr_id":"RMR-0001","decision_label":"commit"})
    assert result["mode"] == "execute"
    assert result["provider_calls"]
    assert result["provider_calls"][0]["receipt_id"].startswith("sample-")

def test_before_router_is_dry_run():
    mod = load_module(ROOT / "council/sample/council_router_before.py")
    router = mod.CouncilRouter({"openai_hashed": lambda r: {}})
    result = router.execute({"rmr_id":"RMR-0001","decision_label":"commit"})
    assert result["mode"] == "dry-run"
