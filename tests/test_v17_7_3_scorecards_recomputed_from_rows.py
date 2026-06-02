from __future__ import annotations

from tests.v17_7_3_armfix_utils import run_runtime


def test_v17_7_3_scorecards_are_row_level_recomputed(tmp_path) -> None:
    core, output_dir = run_runtime(tmp_path)
    benchmark = core.read_json(output_dir / "benchmark_scorecard.json")
    closure = core.read_json(output_dir / "evidence_gap_closure_scorecard.json")
    scorecards = [
        core.read_json(output_dir / "benchmark_scorecard.json"),
        core.read_json(output_dir / "evidence_gap_closure_scorecard.json"),
        core.read_json(output_dir / "conformal_uncertainty_update.json"),
        core.read_json(output_dir / "ope_support_update.json"),
        core.read_json(output_dir / "route_boundary_matrix.json"),
    ]
    assert benchmark["row_level_recomputed"] is True
    assert benchmark["measurement_status"] == "MODEL_SCORED"
    assert closure["all_required_rows_model_scored"] is True
    assert all(row["measurement_status"] == "MODEL_SCORED" for row in scorecards)
