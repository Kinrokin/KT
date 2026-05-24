from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.compact_hat_route_regret_scar_repair_v1 import build_route_regret_matrix


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a route-regret matrix from route outcome rows.")
    parser.add_argument("input_json", type=Path)
    parser.add_argument("output_json", type=Path)
    args = parser.parse_args(argv)
    rows = json.loads(args.input_json.read_text(encoding="utf-8-sig"))
    matrix = build_route_regret_matrix(rows)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output_json.as_posix())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
