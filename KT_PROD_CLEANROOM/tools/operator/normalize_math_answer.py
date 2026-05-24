from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.compact_hat_route_regret_scar_repair_v1 import normalize_math_answer


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize a math/final-answer string for KT repair scoring.")
    parser.add_argument("text", nargs="*", help="Answer text to normalize.")
    args = parser.parse_args(argv)
    print(normalize_math_answer(" ".join(args.text)) or "")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
