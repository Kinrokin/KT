from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path


def _core():
    path = Path(__file__).resolve().parents[1] / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("arm_rows", type=Path)
    parser.add_argument("--run-id", default="ktv1774_aggregate")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    core = _core()
    rows = core.read_jsonl(args.arm_rows)
    predictions = core.aggregate_predictions(rows, args.run_id)
    core.write_jsonl(args.out, predictions)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
