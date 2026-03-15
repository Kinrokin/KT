from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.operator_greenline_validate import build_lane_delta_row


def test_ci_sim_lane_row_requires_expected_meta_ci_sim_fragment() -> None:
    row = build_lane_delta_row(
        row_id="lane.ci_sim",
        lane_name="certify.ci_sim",
        baseline_lane={"rc": 2, "run_dir": "baseline/ci", "verdict": "KT_CERTIFY_FAIL_CLOSED"},
        current_lane={"rc": 0, "verdict": "KT_CERTIFY_PASS cmd=certify lane=ci_sim"},
        current_direct_report={"status": "PASS"},
        current_direct_verdict="KT_CERTIFY_PASS cmd=certify lane=ci_sim",
        current_direct_run_ref="current/ci",
        expected_verdict_prefix="KT_CERTIFY_PASS",
        required_verdict_fragments=("meta_ci_sim=EXPECTED_FAIL",),
    )

    assert row["mismatch_count"] == 1
    assert row["checks"]["current_direct_required_fragments_present"] is False
    assert row["resolution_or_blocker"] == "lane remains unrecovered"
