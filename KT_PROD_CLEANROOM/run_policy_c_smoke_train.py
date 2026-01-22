from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser(description="Policy C smoke trainer wrapper (head-only).")
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    args = ap.parse_args()

    ds = Path(args.dataset)
    out = Path(args.output_dir)
    if not ds.exists():
        raise SystemExit(f"Missing dataset: {ds}")

    cmd = [
        sys.executable,
        "-m",
        "KT_PROD_CLEANROOM.tools.training.train_policy_c_head",
        "--dataset",
        str(ds),
        "--output-dir",
        str(out),
        "--seed",
        str(args.seed),
        "--device",
        args.device,
    ]
    raise SystemExit(subprocess.call(cmd))


if __name__ == "__main__":
    main()
