import json
from pathlib import Path


def test_v3_postmerge_audit_binds_unresolved_defects():
    receipt = json.loads(Path("reports/stop300_v3_postmerge_execution_audit.json").read_text(encoding="utf-8-sig"))
    assert receipt["status"] == "BLOCKED_GPU_RUN_UNRESOLVED_POSTMERGE_DEFECTS"
    assert receipt["v3_gpu_run_status"] == "NOT_RUN"
    assert len(receipt["unresolved_review_threads"]) == 5
    assert "v3_court_can_pass_without_independent_derived_predicates" in receipt["defects"]
