import json
from pathlib import Path

ROOT = Path.cwd()


def test_truth_integrity_loop_blocks_strong_claims_when_receipts_conflict():
    receipt = json.loads((ROOT / "reports/v14_truth_integrity_audit_receipt.json").read_text(encoding="utf-8"))
    assert receipt["truth_integrity_status"] == "REPAIR_REQUIRED_STRONG_CLAIMS_BLOCKED"
    assert receipt["release_authority"] == "BLOCK_STRONG_CLAIMS"
    assert "adapter_identity_mismatch" in receipt["defects"]
    assert "structure_bound_overclaim" in receipt["defects"]
    assert "isolation_receipt_contradiction" in receipt["defects"]
    assert receipt["claim_ceiling_preserved"] is True
