from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cluster observed failures into scar groups.")
    parser.add_argument("failure_json", type=Path)
    parser.add_argument("output_json", type=Path)
    args = parser.parse_args(argv)
    failures = json.loads(args.failure_json.read_text(encoding="utf-8-sig"))
    clusters = {}
    for row in failures:
        key = row.get("failure_type", "unknown")
        clusters.setdefault(key, []).append(row.get("failure_id") or row.get("sample_id"))
    receipt = {
        "schema_id": "kt.adaptive.scar_cluster_receipt.v1",
        "source_failure_ledger": args.failure_json.as_posix(),
        "scar_clusters": [{"cluster_id": key, "failure_ids": value} for key, value in sorted(clusters.items())],
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output_json.as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
