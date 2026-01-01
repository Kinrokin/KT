#!/usr/bin/env python
"""Simple reconciliation tool: match LIVE_HASHED receipts to provider exports.

Usage:
  python reconcile_openai_exports.py --receipts path/to/receipts.jsonl --export path/to/openai_export.json

This is a tooling-only verifier (non-runtime). It matches receipts by request_id or request_id_hash,
checks token usage totals and models, and prints a short report. Exits non-zero if mismatches exceed threshold.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional


def load_receipts(path: Path):
    receipts = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            receipts.append(json.loads(line))
    return receipts


def load_export(path: Path):
    # Accept JSON array, line-delimited JSON, or CSV
    suf = path.suffix.lower()
    if suf == ".csv":
        out = []
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                out.append({k: (v if v != "" else None) for k, v in row.items()})
        return out

    with path.open("r", encoding="utf-8") as f:
        data = f.read().strip()
    try:
        obj = json.loads(data)
        if isinstance(obj, list):
            return obj
    except Exception:
        pass
    # fallback: try line-delimited
    out = []
    for line in data.splitlines():
        if not line.strip():
            continue
        out.append(json.loads(line))
    return out


def index_export_by_request(exp: list[Dict[str, Any]]):
    # Build multi-map for id and hash keys
    idx: Dict[str, List[Dict[str, Any]]] = {}
    for item in exp:
        keys = []
        if item.get("id"):
            keys.append(str(item.get("id")))
        if item.get("request_id"):
            keys.append(str(item.get("request_id")))
        if item.get("request_id_hash"):
            keys.append(str(item.get("request_id_hash")))
        for k in keys:
            idx.setdefault(k, []).append(item)
    return idx


def score_candidate(receipt: Dict[str, Any], candidate: Dict[str, Any], time_window_ms: int, usage_tolerance: int) -> int:
    score = 0
    att = receipt.get("provider_attestation") or {}
    req_id = att.get("request_id")
    req_hash = att.get("request_id_hash")
    # strong signals
    if req_id and str(candidate.get("id") or candidate.get("request_id")) == str(req_id):
        score += 100
    if req_hash and str(candidate.get("request_id_hash")) == str(req_hash):
        score += 80

    # model match
    r_model = receipt.get("model") or receipt.get("model_id") or receipt.get("provider_attestation", {}).get("model")
    c_model = candidate.get("model") or candidate.get("model_id")
    if r_model and c_model and str(r_model) == str(c_model):
        score += 30

    # time window overlap (best-effort)
    try:
        timing = receipt.get("timing") or {}
        r_start = int(timing.get("t_start_ms"))
        r_end = int(timing.get("t_end_ms"))
        # candidate may have 'created_at' in epoch ms or iso timestamp; try epoch first
        c_time = None
        if candidate.get("created_at"):
            try:
                c_time = int(candidate.get("created_at"))
            except Exception:
                c_time = None
        if c_time is not None:
            if (r_start - time_window_ms) <= c_time <= (r_end + time_window_ms):
                score += 20
    except Exception:
        pass

    # usage closeness
    try:
        r_usage = receipt.get("usage") or {}
        r_total = int(r_usage.get("total_tokens")) if isinstance(r_usage, dict) and r_usage.get("total_tokens") is not None else None
        p_usage = candidate.get("usage") or candidate.get("usage_summary") or {}
        p_total = int(p_usage.get("total_tokens")) if isinstance(p_usage, dict) and p_usage.get("total_tokens") is not None else None
        if r_total is not None and p_total is not None:
            diff = abs(r_total - p_total)
            if diff <= usage_tolerance:
                score += 20
            else:
                # small penalty for large mismatch
                score -= min(20, diff)
    except Exception:
        pass

    return score


def main() -> int:
    p = argparse.ArgumentParser(description="Reconcile LIVE_HASHED receipts with provider export")
    p.add_argument("--receipts", required=True, help="path to receipts.jsonl")
    p.add_argument("--export", required=True, help="path to provider export (json or jsonl)")
    p.add_argument("--time-window-ms", type=int, default=5000, help="time window tolerance in ms (default 5000)")
    p.add_argument("--usage-tolerance", type=int, default=5, help="usage total_tokens tolerance (default 5)")
    p.add_argument("--allow-unmatched", type=int, default=0, help="allowed unmatched receipts before failing (default 0)")
    args = p.parse_args()

    receipts = load_receipts(Path(args.receipts))
    export = load_export(Path(args.export))
    exp_idx = index_export_by_request(export)

    matched = 0
    unmatched_receipts = []
    unmatched_export_keys = set()
    usage_mismatches = 0
    probable_matches = []

    # Track which export rows were matched
    matched_export_ids = set()

    for r in receipts:
        att = r.get("provider_attestation") or {}
        req_id = att.get("request_id")
        req_hash = att.get("request_id_hash")

        candidates: List[Dict[str, Any]] = []
        if req_id and str(req_id) in exp_idx:
            candidates.extend(exp_idx.get(str(req_id), []))
        if req_hash and str(req_hash) in exp_idx:
            candidates.extend(exp_idx.get(str(req_hash), []))

        # If no strong key candidates, consider all export rows for fuzzy scoring
        if not candidates:
            candidates = export

        # Score candidates
        best: Optional[Dict[str, Any]] = None
        best_score = -9999
        for c in candidates:
            score = score_candidate(r, c, int(args.time_window_ms), int(args.usage_tolerance))
            if score > best_score:
                best_score = score
                best = c

        # Heuristics: consider score >= 100 as exact, >= 40 as probable
        if best is None or best_score < 40:
            unmatched_receipts.append(r.get("trace_id") or r.get("provider_attestation", {}).get("request_id") or "<unknown>")
            continue

        # Mark matched export row
        eid = str(best.get("id") or best.get("request_id") or best.get("request_id_hash") or id(best))
        matched_export_ids.add(eid)

        # Check usage mismatch
        r_usage = r.get("usage") or {}
        p_usage = best.get("usage") or best.get("usage_summary") or {}
        r_total = r_usage.get("total_tokens") if isinstance(r_usage, dict) else None
        p_total = p_usage.get("total_tokens") if isinstance(p_usage, dict) else None
        if r_total is not None and p_total is not None and abs(int(r_total) - int(p_total)) > int(args.usage_tolerance):
            usage_mismatches += 1
        else:
            matched += 1

        if 40 <= best_score < 100:
            probable_matches.append({"trace_id": r.get("trace_id"), "score": best_score})

    # Export unmatched export rows
    for c in export:
        eid = str(c.get("id") or c.get("request_id") or c.get("request_id_hash") or id(c))
        if eid not in matched_export_ids:
            unmatched_export_keys.add(eid)

    report = {
        "matched": matched,
        "probable_matches": len(probable_matches),
        "unmatched_receipts": len(unmatched_receipts),
        "unmatched_export_rows": len(unmatched_export_keys),
        "usage_mismatches": usage_mismatches,
        "verdict": "PASS" if (len(unmatched_receipts) <= int(args.allow_unmatched) and usage_mismatches == 0) else "FAIL",
    }

    # Deterministic output
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    if report["verdict"] != "PASS":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
