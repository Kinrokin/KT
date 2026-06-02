from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path


def load_core():
    path = Path(__file__).resolve().parents[1] / "runtime" / "v17_7_3" / "KT_V1773_MEASURED_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1773_measured_arm_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load measured arm core: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("runtime_root", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--run-id", default="ktv1773_manual_scorecard_recompute")
    args = parser.parse_args()
    core = load_core()
    manifest = core.read_json(args.runtime_root / "runtime_inputs" / "targeted_boundary_row_manifest.json")
    arm_results = core.read_jsonl(args.output_dir / "arm_result_matrix.jsonl")
    predictions = core.read_jsonl(args.output_dir / "benchmark_predictions.jsonl")
    scorecards = core.recompute_scorecards(manifest, arm_results, predictions, args.run_id)
    for name, payload in scorecards.items():
        core.write_json(args.output_dir / name, payload)
    print(len(scorecards))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
