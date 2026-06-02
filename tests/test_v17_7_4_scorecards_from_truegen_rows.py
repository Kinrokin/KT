from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _core():
    path = ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1774_truegen_core", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_scorecards_recompute_only_from_fresh_rows() -> None:
    core = _core()
    row = json.loads((ROOT / "admission" / "v17_7_4_truegen_row_manifest.json").read_text())["rows"][0]
    arm_rows = [
        core.authority(
            schema_id="kt.v17_7_4.truegen_arm_result.v1",
            sample_id=row["sample_id"],
            dataset=row["dataset"],
            task_family=row["task_family"],
            evidence_band=row["evidence_band"],
            route_boundary_class=row["route_boundary_class"],
            arm_id=arm,
            score=1.0 if arm == "base_raw" else 0.0,
            correct=arm == "base_raw",
            tokens_in=10,
            tokens_out=2,
            latency_ms=1,
            measurement_source=core.FRESH_SOURCE,
            measurement_status=core.FRESH_STATUS,
            generation_artifacts_present=True,
        )
        for arm in core.ARM_IDS
    ]
    predictions = core.aggregate_predictions(arm_rows, "test")
    scorecards = core.recompute_scorecards(arm_rows, predictions)
    assert scorecards["benchmark"]["row_level_recomputed"] is True
    assert scorecards["benchmark"]["measurement_source"] == core.FRESH_SOURCE
    assert scorecards["benchmark"]["best_static_arm"] == "base_raw"
