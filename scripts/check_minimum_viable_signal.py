from __future__ import annotations

import argparse
from pathlib import Path

from g32_common import read_json, write_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    receipt = read_json(Path(args.receipt))
    rows = []
    for decision in receipt.get("decisions", []):
        checks = {
            "failure_count_pass": decision.get("failure_count", 0) >= 3,
            "human_anchor_ratio_pass": decision.get("human_anchor_ratio", 0.0) >= 0.20,
            "benchmark_leakage_scan_pass": decision.get("benchmark_leakage_scan_pass", False) is True,
            "poison_trigger_scan_pass": decision.get("poison_trigger_scan_pass", False) is True,
            "negative_transfer_scan_pass": decision.get("negative_transfer_scan_pass", False) is True,
            "repair_bid_score_pass": decision.get("repair_bid_score", 0.0) >= 0.10,
            "no_regression_plan_present": decision.get("no_regression_plan_present", False) is True,
            "failure_map_present": decision.get("failure_map_present", False) is True,
            "expected_target_metric_gain_pass": decision.get("expected_target_metric_gain", 0.0) > 0,
            "claim_ceiling_preserved": decision.get("claim_ceiling_preserved", False) is True,
        }
        rows.append(
            {
                "schema_id": "kt.minimum_viable_signal.v1",
                "cluster_id": decision.get("cluster_id"),
                "minimum_viable_signal_pass": all(checks.values()),
                "checks": checks,
            }
        )
    result = {"schema_id": "kt.minimum_viable_signal_set.v1", "rows": rows, "pass": any(row["minimum_viable_signal_pass"] for row in rows)}
    write_json(Path(args.out), result)
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
