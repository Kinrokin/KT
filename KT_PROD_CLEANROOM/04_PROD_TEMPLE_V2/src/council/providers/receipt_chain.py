from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Dict

from council.council_schemas import sha256_json


class ReceiptChainError(RuntimeError):
    pass


def read_prev_receipt_hash(receipts_path: Path) -> str:
    """Read the last non-empty line and return its `receipt_hash` or 'GENESIS'."""
    if not receipts_path.exists():
        return "GENESIS"
    try:
        with receipts_path.open("rb") as fh:
            fh.seek(0, io.SEEK_END)
            size = fh.tell()
            block_size = min(size, 16 * 1024)
            fh.seek(-block_size, io.SEEK_END)
            tail = fh.read().decode("utf-8", errors="replace")
        last_lines = [l for l in tail.splitlines() if l.strip()]
        if not last_lines:
            return "GENESIS"
        last_line = last_lines[-1]
        try:
            last_obj = json.loads(last_line)
        except Exception:
            raise ReceiptChainError("Existing receipts.jsonl last line invalid JSON (fail-closed).")
        prev = last_obj.get("receipt_hash")
        if not isinstance(prev, str) or not prev:
            raise ReceiptChainError("Existing receipts.jsonl last line missing receipt_hash (fail-closed).")
        return prev
    except ReceiptChainError:
        raise
    except Exception as e:
        raise ReceiptChainError(f"Failed reading receipts tail: {e} (fail-closed).")


def finalize_receipt(receipt_dict: Dict, receipts_path: Path) -> Dict:
    """Compute receipt_id, prev_receipt_hash, and receipt_hash and return updated dict."""
    prev_hash = read_prev_receipt_hash(receipts_path)

    # Compute receipt_id (canonical hash of body excluding chain fields)
    receipt_id = sha256_json(receipt_dict)
    receipt_dict = dict(receipt_dict)
    receipt_dict["receipt_id"] = receipt_id
    receipt_dict["prev_receipt_hash"] = prev_hash

    receipt_hash = sha256_json(receipt_dict)
    receipt_dict["receipt_hash"] = receipt_hash
    return receipt_dict
