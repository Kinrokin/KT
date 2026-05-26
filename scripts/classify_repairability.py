from __future__ import annotations

import argparse
from pathlib import Path

from g32_common import build_decisions, read_jsonl, scan_corpus, write_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    rows = read_jsonl(Path(args.matrix))
    root = Path.cwd()
    scans = scan_corpus(rows, root)
    receipt = build_decisions(rows, scans, root)
    write_json(Path(args.out), receipt)
    print(f"decision_count={len(receipt['decisions'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
