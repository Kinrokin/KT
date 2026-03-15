from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.operator_greenline_validate import build_lane_delta_row


def test_status_lane_row_fails_when_direct_verdict_is_not_pass() -> None:
    row = build_lane_delta_row(
        row_id="lane.status",
        lane_name="status",
        baseline_lane={"rc": 2, "run_dir": "baseline/status", "verdict": "KT_STATUS_FAIL_CLOSED"},
        current_lane={"rc": 0, "verdict": "KT_STATUS_PASS cmd=status"},
        current_direct_report={"status": "PASS"},
        current_direct_verdict="KT_STATUS_FAIL_CLOSED cmd=status",
        current_direct_run_ref="current/status",
        expected_verdict_prefix="KT_STATUS_PASS",
    )

    assert row["mismatch_count"] == 1
    assert row["checks"]["current_direct_verdict_pass"] is False
    assert row["resolution_or_blocker"] == "lane remains unrecovered"
