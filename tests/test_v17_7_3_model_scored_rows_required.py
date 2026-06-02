from __future__ import annotations

import json

from tests.v17_7_3_armfix_utils import read_jsonl, run_runtime


def test_v17_7_3_runtime_emits_only_model_scored_arm_rows(tmp_path) -> None:
    _core, output_dir = run_runtime(tmp_path)
    arm_rows = [
        row
        for line in (output_dir / "arm_result_matrix.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
        for row in [json.loads(line)]
    ]
    assert arm_rows
    assert {row["measurement_status"] for row in arm_rows} == {"MODEL_SCORED"}
    assert all(row["model_id"] for row in arm_rows)
    assert all(row["prompt_hash"] and row["output_hash"] for row in arm_rows)


def test_v17_7_3_packet_sources_cover_target_manifest() -> None:
    target = read_jsonl("admission/v17_7_route_outcome_table.jsonl")
    source_ids = {row["sample_id"] for row in target}
    assert source_ids
