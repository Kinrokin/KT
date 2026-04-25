#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--holdout-file", required=True)
    ap.add_argument("--packet", required=True)
    ap.add_argument("--json-out", required=True)
    args = ap.parse_args()

    holdout_ids = [line.strip() for line in Path(args.holdout_file).read_text(encoding="utf-8").splitlines() if line.strip()]
    packet = json.loads(Path(args.packet).read_text(encoding="utf-8"))
    rows = packet["rows"] if isinstance(packet, dict) and "rows" in packet else packet
    counted_ids = [row.get("case_id") for row in rows if row.get("counted")]
    leakage = sorted(set(holdout_ids).intersection(counted_ids))
    out = {"holdout_ids": holdout_ids, "counted_ids": counted_ids, "leakage": leakage, "clean": not leakage}
    Path(args.json_out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if not leakage else 50

if __name__ == "__main__":
    raise SystemExit(main())
