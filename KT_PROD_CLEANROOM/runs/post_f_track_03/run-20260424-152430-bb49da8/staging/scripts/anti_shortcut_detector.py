#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path

EXIT_OK = 0
EXIT_FAIL = 60

def load_rows(path: Path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["rows"] if isinstance(payload, dict) and "rows" in payload else payload

def measure(rows):
    base = {r["case_id"]: r for r in rows if r.get("variant") == "base"}
    mirror = {r["case_id"]: r for r in rows if r.get("variant") == "mirror"}
    masked = {r["case_id"]: r for r in rows if r.get("variant") == "masked"}
    def invariance(other):
        pairs = 0
        stable = 0
        for cid, b in base.items():
            if cid in other:
                pairs += 1
                o = other[cid]
                if b.get("router_choice") == o.get("router_choice") and b.get("decision_label") == o.get("decision_label"):
                    stable += 1
        return 1.0 if pairs == 0 else stable / pairs
    return {
        "mirror_invariance": round(invariance(mirror), 3),
        "masked_invariance": round(invariance(masked), 3),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--mirror-threshold", type=float, default=0.90)
    ap.add_argument("--masked-threshold", type=float, default=0.90)
    ap.add_argument("--json-out", required=True)
    args = ap.parse_args()
    rows = load_rows(Path(args.input))
    metrics = measure(rows)
    result = {
        **metrics,
        "mirror_threshold": args.mirror_threshold,
        "masked_threshold": args.masked_threshold,
        "passed": metrics["mirror_invariance"] >= args.mirror_threshold and metrics["masked_invariance"] >= args.masked_threshold,
    }
    Path(args.json_out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return EXIT_OK if result["passed"] else EXIT_FAIL

if __name__ == "__main__":
    raise SystemExit(main())
