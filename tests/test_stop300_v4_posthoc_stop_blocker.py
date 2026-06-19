import json
from pathlib import Path


def test_v4_posthoc_stop_blocker_receipt():
    receipt = json.loads(Path("reports/stop300_v4_generation_time_execution_audit.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "BLOCKED_POSTHOC_STOP_NOT_PHYSICAL_TERMINATION"
    assert receipt["v4_gpu_run_status"] == "NOT_RUN"
    assert receipt["posthoc_evidence"]["detector_iterates_over_completed_raw_ids"] is True
    assert receipt["posthoc_evidence"]["transformers_stopping_criteria_absent"] is True
