#!/usr/bin/env python3
"""
Deterministic minimal lobe shim for Track 03.

CLI:
  python runtime/minimal_lobe_shim.py --input rmr.json --seed 42 --out receipt.json

The shim emits a deterministic decision and a mock signature. It is intentionally
narrow and bounded: it proves runtime receipt generation without overclaiming broader
multi-lobe capability.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_TIMESTAMP = "2026-04-24T00:00:00Z"

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def normalize_payload(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict) and "rows" in payload:
        rows = payload["rows"]
    elif isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = [payload]
    else:
        raise ValueError("Unsupported input payload structure.")
    if not rows:
        raise ValueError("Input payload contains no rows.")
    return rows

def deterministic_decision(row: Dict[str, Any], seed: int) -> Dict[str, Any]:
    mix = f'{row.get("case_id","")}|{row.get("family","")}|{row.get("variant","")}|{seed}'.encode()
    h = sha256_hex(mix)
    providers = ["openai_hashed", "openrouter_hashed", "mock_local"]
    provider = providers[int(h[0:2], 16) % len(providers)]
    confidence = round(0.55 + (int(h[2:4], 16) / 255.0) * 0.4, 3)
    margin = round(0.10 + (int(h[4:6], 16) / 255.0) * 0.5, 3)
    if row.get("beta"):
        decision = "reject"
        why_not = ["WN006_BETA_CONTAMINATED"]
    elif row.get("holdout"):
        decision = "defer"
        why_not = ["WN007_HOLDOUT_LEAKAGE"]
    elif confidence >= 0.78 and margin >= 0.24:
        decision = "commit"
        why_not = ["WN001_NO_POLICY_MATCH"]
    else:
        decision = "defer"
        why_not = ["WN002_LOW_MARGIN"]
    call = {
        "provider": provider,
        "prompt_sha256": sha256_hex(f'prompt:{row.get("rmr_id")}:{seed}'.encode()),
        "response_sha256": sha256_hex(f'response:{decision}:{row.get("rmr_id")}:{seed}'.encode()),
        "receipt_id": f'prov-{row.get("rmr_id","unknown").lower()}-{seed}'
    }
    return {
        "router_choice": provider.replace("_hashed", ""),
        "decision_label": decision,
        "confidence": confidence,
        "margin": margin,
        "provider_calls": [call],
        "why_not": why_not,
        "reason_codes": ["RC001_CONTEXT_ALIGNMENT", "RC008_EVIDENCE_COMPLETE"] if decision == "commit" else ["RC009_DEFER_REQUIRED", "RC010_RUNTIME_BOUNDED"]
    }

def build_receipt(rows: List[Dict[str, Any]], seed: int, timestamp: str) -> Dict[str, Any]:
    results = []
    for row in rows:
        result = deterministic_decision(row, seed)
        results.append({
            "rmr_id": row.get("rmr_id"),
            "case_id": row.get("case_id"),
            **result
        })
    digest_source = json.dumps(results, sort_keys=True, separators=(",", ":")).encode()
    digest = sha256_hex(digest_source)
    signature = base64.b64encode(digest.encode()).decode() + ":mock-signer:mock-key-id"
    return {
        "__generated_by_agent__": True,
        "runtime": "minimal_lobe_shim",
        "seed": seed,
        "timestamp": timestamp,
        "results": results,
        "provider_calls": [call for r in results for call in r["provider_calls"]],
        "receipt": {
            "digest_sha256": digest,
            "signature": signature,
            "signer": "mock-signer",
            "key_id": "mock-key-id"
        }
    }

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--timestamp", default=DEFAULT_TIMESTAMP)
    args = ap.parse_args()

    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    rows = normalize_payload(payload)
    receipt = build_receipt(rows, args.seed, args.timestamp)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
