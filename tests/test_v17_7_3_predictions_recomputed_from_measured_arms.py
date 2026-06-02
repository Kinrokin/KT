from __future__ import annotations

import json

from tests.v17_7_3_armfix_utils import read_json, run_runtime


def test_v17_7_3_predictions_are_recomputed_from_measured_arms(tmp_path) -> None:
    _core, output_dir = run_runtime(tmp_path)
    manifest = read_json("admission/v17_7_3_targeted_boundary_row_manifest.json")
    predictions = [json.loads(line) for line in (output_dir / "benchmark_predictions.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(predictions) == manifest["row_count"]
    assert {row["measurement_status"] for row in predictions} == {"MODEL_SCORED"}
    assert all(row["available_arm_scores"] for row in predictions)
    assert all(row["best_arm"] in row["available_arm_scores"] for row in predictions)
    assert all(row["oracle_route"] == row["best_arm"] for row in predictions)
