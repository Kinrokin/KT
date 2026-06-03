from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core_compression", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_g2_compression_anchor_preserves_known_high_point() -> None:
    core = _core()
    receipt = core.g2_compression_anchor_receipt()
    assert receipt["status"] == "PASS"
    assert receipt["evidence_scope"] == "INTERNAL_REGRESSION_SENTINEL_ONLY"
    assert receipt["base_raw"]["correct"] == 119
    assert receipt["routed_13_lobe_kt_hat_compact"]["correct"] == 126
    assert receipt["base_raw"]["tokens_per_correct"] == 42.857143
    assert receipt["routed_13_lobe_kt_hat_compact"]["tokens_per_correct"] == 3.738095
    assert receipt["tokens_per_correct_reduction"] > 0.9
    assert receipt["learned_router_superiority_claim"] is False


def test_compression_frontier_gate_blocks_tokens_without_correctness_gain() -> None:
    core = _core()
    manifest_row = json.loads((ROOT / "admission" / "v17_7_4_truegen_row_manifest.json").read_text(encoding="utf-8"))["rows"][0]
    arm_rows = [
        core.authority(
            schema_id="kt.v17_7_4.truegen_arm_result.v1",
            sample_id=manifest_row["sample_id"],
            dataset=manifest_row["dataset"],
            task_family=manifest_row["task_family"],
            evidence_band=manifest_row["evidence_band"],
            route_boundary_class=manifest_row["route_boundary_class"],
            arm_id="base_raw",
            score=1.0,
            correct=True,
            tokens_in=10,
            tokens_out=2,
            total_tokens=12,
            route_overhead_tokens=0,
            router_tokens=0,
            hat_tokens=0,
            tribunal_tokens=0,
            repair_tokens=0,
            hat_overhead_ratio=0.0,
            latency_ms=1,
            measurement_source=core.FRESH_SOURCE,
            measurement_status=core.FRESH_STATUS,
            generation_artifacts_present=True,
        ),
        core.authority(
            schema_id="kt.v17_7_4.truegen_arm_result.v1",
            sample_id=manifest_row["sample_id"],
            dataset=manifest_row["dataset"],
            task_family=manifest_row["task_family"],
            evidence_band=manifest_row["evidence_band"],
            route_boundary_class=manifest_row["route_boundary_class"],
            arm_id="base_kt_hat_compact",
            score=1.0,
            correct=True,
            tokens_in=100,
            tokens_out=20,
            total_tokens=120,
            route_overhead_tokens=90,
            router_tokens=0,
            hat_tokens=90,
            tribunal_tokens=0,
            repair_tokens=0,
            hat_overhead_ratio=90.0,
            latency_ms=1,
            measurement_source=core.FRESH_SOURCE,
            measurement_status=core.FRESH_STATUS,
            generation_artifacts_present=True,
        ),
    ]
    predictions = core.aggregate_predictions(arm_rows, "test")
    scorecards = core.recompute_scorecards(arm_rows, predictions)
    assert scorecards["compression_frontier"]["status"] == "BLOCKED"
    assert scorecards["compression_frontier"]["outcome"] == "KT_BLOCKED__COMPRESSION_FRONTIER_REGRESSION"


def test_router_admission_defaults_to_direct_compact_until_gain_proven() -> None:
    core = _core()
    scorecards = {
        "route_regret_token_cost": {
            "matrix": {
                "base_raw": {"correct": 1, "overhead_per_correct": 0.0},
                "routed_no_hat": {"correct": 1, "overhead_per_correct": 8.0},
            }
        }
    }
    receipt = core.router_admission_receipt(scorecards)
    assert receipt["direct_compact_default"] is True
    assert receipt["decisions"]["routed_no_hat"] == "DIRECT_COMPACT_PATH_PREFERRED_UNTIL_GAIN_PROVEN"
    assert receipt["learned_router_superiority_claim"] is False
