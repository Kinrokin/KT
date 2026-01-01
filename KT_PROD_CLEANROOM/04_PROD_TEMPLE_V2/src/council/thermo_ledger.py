from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict

from schemas.base_schema import SchemaValidationError, validate_hex_64, validate_short_string


LEDGER_DIR = Path(__file__).resolve().parents[3] / "tools" / "growth" / "ledgers" / "thermo"
LEDGER_PATH = LEDGER_DIR / "ledger.jsonl"


class ThermoLedgerError(RuntimeError):
    pass


def _validate_receipt_hash(h: str) -> None:
    if not isinstance(h, str):
        raise SchemaValidationError("receipt_hash must be a string")
    validate_hex_64({"receipt_hash": h}, "receipt_hash")


def append_debit(*, receipt_hash: str, total_tokens: int, model: str) -> None:
    # Fail-closed validations
    try:
        _validate_receipt_hash(receipt_hash)
    except Exception as e:
        raise ThermoLedgerError(f"Invalid receipt_hash: {e}")

    if not isinstance(total_tokens, int) or total_tokens < 0:
        raise ThermoLedgerError("total_tokens must be a non-negative integer (fail-closed)")

    if not isinstance(model, str) or not model:
        raise ThermoLedgerError("model must be a non-empty string (fail-closed)")

    entry: Dict = {
        "ts": int(time.time() * 1000),
        "receipt_hash": receipt_hash,
        "model": model,
        "total_tokens": int(total_tokens),
    }

    LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    with LEDGER_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=True) + "\n")
