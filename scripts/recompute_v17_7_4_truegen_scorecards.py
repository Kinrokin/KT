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
    parser.add_argument("predictions", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    core = _core()
    arm_rows = core.read_jsonl(args.arm_rows)
    predictions = core.read_jsonl(args.predictions)
    scorecards = core.recompute_scorecards(arm_rows, predictions)
    mapping = {
        "benchmark": "truegen_benchmark_scorecard.json",
        "negative_transfer": "truegen_negative_transfer_by_arm.json",
        "token_efficiency": "truegen_token_efficiency_matrix.json",
        "per_band": "truegen_per_band_arm_win_matrix.json",
        "oracle_gap": "truegen_oracle_gap_update.json",
        "pfail_dgs": "truegen_pfail_dgs_update.json",
    }
    for key, name in mapping.items():
        core.write_json(args.out_dir / name, scorecards[key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
