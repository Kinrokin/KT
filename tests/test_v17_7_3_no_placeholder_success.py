from __future__ import annotations

import pytest

from tests.v17_7_3_armfix_utils import load_core


def test_v17_7_3_rejects_placeholder_success_statuses() -> None:
    core = load_core()
    rows = [
        {
            "schema_id": "kt.v17_7_3.measured_arm_result_row.v1",
            "sample_id": "row-1",
            "measurement_status": "PENDING_KAGGLE_ARM_EXECUTION",
        }
    ]
    with pytest.raises(RuntimeError):
        core.enforce_measured_rows(rows)


def test_v17_7_3_accepts_model_scored_rows() -> None:
    core = load_core()
    rows = [
        {
            "schema_id": "kt.v17_7_3.measured_arm_result_row.v1",
            "sample_id": "row-1",
            "measurement_status": "MODEL_SCORED",
        }
    ]
    core.enforce_measured_rows(rows)
