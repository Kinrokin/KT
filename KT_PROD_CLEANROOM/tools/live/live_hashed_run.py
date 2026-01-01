#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from council.providers.live_provider_openai_hashed import LiveHashedOpenAIProvider
from council.providers.provider_schemas import ProviderCallReceipt
from council.providers.receipt_chain import finalize_receipt
from council.providers.receipt_store import append_receipt_chained
import io


class LiveHashedError(RuntimeError):
    pass


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="KT LIVE_HASHED runner (hash-only receipts; authoritative lane).")
    p.add_argument("--provider", default="openai", help="provider id (default: openai)")
    p.add_argument("--model", required=True, help="model id (required)")
    p.add_argument("--prompt", default="", help="prompt; if omitted read stdin")
    p.add_argument("--timeout-ms", type=int, default=20000)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--kt-node-id", default=os.getenv("KT_NODE_ID", ""), help="optional node id for deterministic key routing")
    p.add_argument("--out", default="", help="override receipts path (advanced; default cleanroom artifacts path)")
    p.add_argument("--i-understand-authoritative", action="store_true",
                   help="Required acknowledgement: LIVE_HASHED writes receipts and is authoritative.")
    return p.parse_args()


def _cleanroom_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _default_receipts_path() -> Path:
    root = _cleanroom_root()
    return root / "tools" / "growth" / "artifacts" / "live_hashed" / "openai" / "receipts.jsonl"


def _read_prompt(args: argparse.Namespace) -> str:
    if args.prompt:
        return args.prompt
    data = sys.stdin.read()
    if not data:
        raise LiveHashedError("No prompt provided (--prompt or stdin) (fail-closed).")
    return data


def main() -> int:
    sys.dont_write_bytecode = True
    args = _parse_args()

    if not args.i_understand_authoritative:
        raise SystemExit("Missing --i-understand-authoritative (fail-closed).")

    if os.getenv("KT_PROVIDERS_ENABLED") != "1":
        raise SystemExit("KT_PROVIDERS_ENABLED=1 required (fail-closed).")
    if os.getenv("KT_EXECUTION_LANE") != "LIVE_HASHED":
        raise SystemExit("KT_EXECUTION_LANE=LIVE_HASHED required (fail-closed).")

    prompt = _read_prompt(args)

    if args.provider != "openai":
        raise SystemExit("Unsupported provider (fail-closed).")

    provider = LiveHashedOpenAIProvider()
    receipt = provider.invoke_hashed(
        model=str(args.model),
        prompt=prompt,
        timeout_ms=int(args.timeout_ms),
        temperature=float(args.temperature),
        kt_node_id=str(args.kt_node_id),
    )

    out_path = Path(args.out) if args.out else _default_receipts_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Receipt dict (provider returns validated receipt body without chain fields)
    receipt_dict = receipt.to_dict()

    # Finalize chain fields and validate (shared helper)
    try:
        full_dict = finalize_receipt(receipt_dict, out_path)
    except Exception as e:
        raise SystemExit(str(e))

    full_receipt = ProviderCallReceipt.from_dict(full_dict)

    # Append-only write via shared helper
    append_receipt_chained(receipt=full_receipt, receipts_path=out_path)

    # Print receipt summary to stderr (no content)
    summary = full_receipt.to_dict()
    print(json.dumps(summary, ensure_ascii=True), file=sys.stderr)

    # Fail-closed: if provider indicated failure, abort after emitting receipt
    verdict = summary.get("verdict") or {}
    if not verdict.get("pass"):
        raise SystemExit("LIVE_HASHED provider call failed (fail-closed).")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
