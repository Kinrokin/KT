import json
from pathlib import Path


def test_v2_postmerge_audit_blocks_gpu_run():
    receipt = json.loads(Path("reports/stop300_v2_postmerge_semantic_audit.json").read_text(encoding="utf-8-sig"))
    supersession = json.loads(Path("reports/stop300_v2_supersession_receipt.json").read_text(encoding="utf-8-sig"))
    assert receipt["status"] == "BLOCKED_GPU_RUN_POSTMERGE_SEMANTIC_DEFECTS"
    assert receipt["v2_gpu_run_status"] == "NOT_RUN"
    assert "result_court_can_pass_correctness_damage" in receipt["defects"]
    assert supersession["status"] == "SUPERSEDED_BEFORE_GPU_EXECUTION"
