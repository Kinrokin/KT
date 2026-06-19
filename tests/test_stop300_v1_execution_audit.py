import json
from pathlib import Path


def test_v1_execution_audit_blocks_pre_gpu_contract_mismatch():
    receipt = json.loads(Path("reports/stop300_v1_pre_gpu_execution_audit.json").read_text(encoding="utf-8-sig"))
    assert receipt["status"] == "BLOCKED_PRE_GPU_EXECUTION_CONTRACT_MISMATCH"
    assert receipt["v1_gpu_run_status"] == "NOT_RUN"
    assert receipt["overlap_count"] > 0
    assert "freshness_depends_on_repo_text_search_not_authority_registry" in receipt["defects"]
