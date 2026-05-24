from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.compact_hat_route_regret_scar_repair_v1 import score_math_answers


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score normalized math answers from a JSON row list.")
    parser.add_argument("input_json", type=Path)
    args = parser.parse_args(argv)
    rows = json.loads(args.input_json.read_text(encoding="utf-8-sig"))
    print(json.dumps(score_math_answers(rows), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
