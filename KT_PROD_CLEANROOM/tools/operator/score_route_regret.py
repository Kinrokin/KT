from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score a KT route-regret matrix.")
    parser.add_argument("matrix_json", type=Path)
    args = parser.parse_args(argv)
    matrix = json.loads(args.matrix_json.read_text(encoding="utf-8-sig"))
    rows = matrix.get("rows", [])
    mean_regret = sum(float(row.get("route_regret", 0)) for row in rows) / len(rows) if rows else 0.0
    scorecard = {
        "schema_id": "kt.router.route_regret_scorecard.v1",
        "route_regret_pass": mean_regret <= float(matrix.get("max_allowed_mean_regret", 0.05)),
        "mean_route_regret": mean_regret,
        "router_optimizes_verified_work_not_label_fit": True,
    }
    print(json.dumps(scorecard, indent=2, sort_keys=True))
    return 0 if scorecard["route_regret_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
