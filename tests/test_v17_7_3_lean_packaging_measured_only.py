from __future__ import annotations

import zipfile

from tests.v17_7_3_armfix_utils import packet_names, run_runtime


def test_v17_7_3_runtime_packet_is_lean_and_measured() -> None:
    names = packet_names("packets/ktv1773_measured_arm_v1.zip")
    assert "KTV1773_MEASURED_ARM_MASTER_RUNNER.py" in names
    assert "KT_V1773_MEASURED_ARM_CORE.py" in names
    assert "runtime_inputs/targeted_boundary_row_manifest.json" in names
    assert "runtime_inputs/source_route_outcome_table.jsonl" in names
    assert not any(name.startswith(("models/", "adapter_weights/", ".git/", "debug_logs/")) for name in names)


def test_v17_7_3_assessment_zip_is_review_only(tmp_path) -> None:
    core, output_dir = run_runtime(tmp_path)
    summary = core.read_json(output_dir / "final_summary.json")
    with zipfile.ZipFile(summary["assessment_zip"]) as archive:
        names = set(archive.namelist())
    assert "benchmark_predictions.jsonl" in names
    assert "arm_result_matrix.jsonl" in names
    assert "final_summary.json" in names
    assert not any(name.startswith(("models/", "adapter_weights/", ".git/", "debug_logs/")) for name in names)
