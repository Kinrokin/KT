from __future__ import annotations

import argparse
import importlib.util
import json
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
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    core = load_core()
    arms = core.read_jsonl(args.output_dir / "arm_result_matrix.jsonl")
    predictions = core.read_jsonl(args.output_dir / "benchmark_predictions.jsonl")
    scorecards = [
        core.read_json(args.output_dir / name)
        for name in [
            "benchmark_scorecard.json",
            "evidence_gap_closure_scorecard.json",
            "conformal_uncertainty_update.json",
            "ope_support_update.json",
            "pfail_calibration_rows.json",
            "do_nothing_counterfactual_update.json",
            "route_boundary_matrix.json",
        ]
    ]
    core.enforce_measured_rows(arms, predictions, scorecards)
    print(json.dumps({"schema_id": "kt.v17_7_3.measured_arm_enforcement_cli.v1", "status": "PASS"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
