from __future__ import annotations

import sys
import unittest
from pathlib import Path


def _add_plus_to_syspath() -> None:
    # .../tools/growth/eval_harness_plus/tests/test_eval_harness_plus.py -> .../tools/growth/eval_harness_plus
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))


_add_plus_to_syspath()

from eval_plus_schemas import (  # noqa: E402
    DriftMetricVectorSchema,
    ExtendedBenchmarkResultSchema,
    GoldenZoneSchema,
    ParadoxMetricVectorSchema,
    compute_paradox_vector,
)


class TestEvalHarnessPlus(unittest.TestCase):
    def test_deterministic_vector_hash(self) -> None:
        v1 = compute_paradox_vector(
            outcomes={"PASS": 3, "FAIL": 1},
            replay_verified=3,
            replay_total=4,
            governance_types={"GOV_POLICY_APPLY": 4},
        )
        v2 = compute_paradox_vector(
            outcomes={"PASS": 3, "FAIL": 1},
            replay_verified=3,
            replay_total=4,
            governance_types={"GOV_POLICY_APPLY": 4},
        )
        self.assertEqual(v1.vector_hash, v2.vector_hash)

    def test_bounds_enforced(self) -> None:
        with self.assertRaises(ValueError):
            ParadoxMetricVectorSchema.from_parts(
                axes={"pass_rate": 1.1, "refusal_ratio": 0.0, "replay_consistency": 0.0, "governance_entropy": 0.0},
                support={"total": 1},
            )

    def test_golden_zone_gate(self) -> None:
        golden = GoldenZoneSchema.evaluate(metric="replay_consistency", score=0.5, min_val=0.6, max_val=0.9)
        self.assertEqual(golden.verdict, "UNDER_RANGE")

        golden2 = GoldenZoneSchema.evaluate(metric="replay_consistency", score=0.7, min_val=0.6, max_val=0.9)
        self.assertEqual(golden2.verdict, "WITHIN_RANGE")

    def test_extended_result_hash_and_status(self) -> None:
        paradox = compute_paradox_vector(
            outcomes={"PASS": 1},
            replay_verified=1,
            replay_total=1,
            governance_types={"GOV_POLICY_APPLY": 1},
        )
        golden = GoldenZoneSchema.evaluate(metric="replay_consistency", score=paradox.axes["replay_consistency"], min_val=0.0, max_val=1.0)
        res = ExtendedBenchmarkResultSchema.from_parts(
            epoch_id="EPOCH-TEST",
            kernel_identity={"kernel_target": "V2_SOVEREIGN", "kernel_build_id": "unknown"},
            paradox=paradox,
            drift=None,
            golden_zone=golden,
        )
        self.assertEqual(res.status, "PASS")
        self.assertEqual(len(res.result_hash), 64)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
