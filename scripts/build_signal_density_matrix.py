from __future__ import annotations

import argparse
from pathlib import Path

from g32_common import build_signal_density


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--run-id", default="g32_signal_density")
    args = parser.parse_args()
    rows = build_signal_density(Path(args.input), Path(args.out), run_id=args.run_id)
    print(f"signal_density_rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
