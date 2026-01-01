import os
import json
from pathlib import Path

import pytest

from council.thermo_ledger import LEDGER_PATH, append_debit, ThermoLedgerError


def test_append_and_contents(tmp_path, monkeypatch):
    ledger_dir = tmp_path / "ledgers" / "thermo"
    monkeypatch.setattr("council.thermo_ledger.LEDGER_DIR", ledger_dir)
    monkeypatch.setattr("council.thermo_ledger.LEDGER_PATH", ledger_dir / "ledger.jsonl")

    receipt_hash = "a" * 64
    append_debit(receipt_hash=receipt_hash, total_tokens=123, model="gpt-4.1-mini")

    lines = (ledger_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert obj["receipt_hash"] == receipt_hash
    assert obj["total_tokens"] == 123
    assert obj["model"] == "gpt-4.1-mini"


def test_invalid_inputs():
    with pytest.raises(ThermoLedgerError):
        append_debit(receipt_hash="nothex", total_tokens=1, model="m")

    with pytest.raises(ThermoLedgerError):
        append_debit(receipt_hash="a" * 64, total_tokens=-1, model="m")

    with pytest.raises(ThermoLedgerError):
        append_debit(receipt_hash="a" * 64, total_tokens=1, model="")
