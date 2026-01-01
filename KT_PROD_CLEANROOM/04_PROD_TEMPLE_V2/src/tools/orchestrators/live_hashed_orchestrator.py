from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from council.council_router import execute_council_request
from council.thermo_ledger import append_debit


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Non-authoritative live_hashed orchestrator (manual commit).")
    p.add_argument("--payload-file", help="JSON file containing Council LIVE_HASHED request; if omitted read stdin", default="")
    p.add_argument("--commit-ledger", action="store_true", help="If set, commit a debit to the thermodynamics ledger (explicit operator action)")
    return p.parse_args(argv)


def run_orchestrator(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    # Read payload
    if args.payload_file:
        data = Path(args.payload_file).read_text(encoding="utf-8")
    else:
        data = sys.stdin.read()
    if not data:
        print("No payload provided (stdin or --payload-file) (fail-closed).", file=sys.stderr)
        return 2

    try:
        req = json.loads(data)
    except Exception as e:
        print(f"Invalid JSON payload: {e}", file=sys.stderr)
        return 2

    # Call Council router (in-memory; Council does not persist raw text)
    out = execute_council_request(req)

    # Extract receipt and receipt_hash
    receipt = out.get("receipt")
    receipt_hash = out.get("receipt_hash")
    if not receipt or not receipt_hash:
        print("Council response missing receipt or receipt_hash (fail-closed).", file=sys.stderr)
        return 2

    # If operator did not request commit, just print summary
    if not args.commit_ledger:
        print(json.dumps({"receipt_hash": receipt_hash, "tokens": receipt.get("usage", {}).get("total_tokens"), "ledger_path": str(Path.cwd() / "tools" / "growth" / "ledgers" / "thermo" / "ledger.jsonl")}), file=sys.stderr)
        return 0

    # Commit explicit debit (fail-closed on errors)
    total_tokens = None
    try:
        usage = receipt.get("usage") or {}
        total_tokens = int(usage["total_tokens"])  # will raise if missing
    except Exception:
        print("Receipt missing usage.total_tokens (fail-closed).", file=sys.stderr)
        return 2

    model = receipt.get("model")
    try:
        append_debit(receipt_hash=receipt_hash, total_tokens=total_tokens, model=model)
    except Exception as e:
        print(f"Failed to append debit (fail-closed): {e}", file=sys.stderr)
        return 2

    # Print minimal summary
    ledger_path = Path(__file__).resolve().parents[3] / "tools" / "growth" / "ledgers" / "thermo" / "ledger.jsonl"
    summary = {"receipt_hash": receipt_hash, "tokens_debited": total_tokens, "ledger_path": str(ledger_path)}
    print(json.dumps(summary), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_orchestrator())
