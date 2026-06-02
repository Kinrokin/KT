from __future__ import annotations

import json

from tests.v17_7_3_armfix_utils import read_json, run_runtime


def test_v17_7_3_arm_matrix_has_every_planned_arm_for_every_row(tmp_path) -> None:
    _core, output_dir = run_runtime(tmp_path)
    manifest = read_json("admission/v17_7_3_targeted_boundary_row_manifest.json")
    arm_plan = read_json("admission/v17_7_3_arm_execution_plan.json")
    arm_rows = [json.loads(line) for line in (output_dir / "arm_result_matrix.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(arm_rows) == manifest["row_count"] * len(arm_plan["arms"])
    by_sample = {}
    for row in arm_rows:
        by_sample.setdefault(row["sample_id"], set()).add(row["arm_id"])
    assert len(by_sample) == manifest["row_count"]
    assert all(arms == set(arm_plan["arms"]) for arms in by_sample.values())
