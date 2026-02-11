import json
import importlib.util
import sys
from pathlib import Path

import pytest


def _add_src_to_syspath() -> None:
    src_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

module_path = Path(__file__).resolve().parents[1] / "orchestrators" / "live_hashed_orchestrator.py"
spec = importlib.util.spec_from_file_location("live_hashed_orchestrator", module_path)
if spec is None or spec.loader is None:
    raise RuntimeError("Unable to load live_hashed_orchestrator module (fail-closed)")
_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_mod)
run_orchestrator = _mod.run_orchestrator


def test_orchestrator_commits_ledger(monkeypatch, tmp_path):
    # Stub Council router to return a fake receipt
    fake_receipt = {
        "model": "gpt-4.1-mini",
        "usage": {"total_tokens": 42},
    }
    fake_receipt_hash = "a" * 64

    def fake_execute(req):
        return {"receipt": fake_receipt, "receipt_hash": fake_receipt_hash}

    # Patch the orchestrator's local reference to the Council router
    monkeypatch.setattr(_mod, "execute_council_request", fake_execute)

    # Redirect ledger path to tmp
    ledger_dir = tmp_path / "ledgers" / "thermo"
    monkeypatch.setattr("council.thermo_ledger.LEDGER_DIR", ledger_dir)
    monkeypatch.setattr("council.thermo_ledger.LEDGER_PATH", ledger_dir / "ledger.jsonl")

    # Prepare payload file
    payload = {"mode": "LIVE_HASHED", "request_type": "healthcheck", "provider_id": "openai", "model": "gpt-4.1-mini", "prompt": "healthcheck"}
    p = tmp_path / "payload.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    rc = run_orchestrator(["--payload-file", str(p), "--commit-ledger"])
    assert rc == 0

    lines = (ledger_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["receipt_hash"] == fake_receipt_hash
    assert entry["total_tokens"] == 42
