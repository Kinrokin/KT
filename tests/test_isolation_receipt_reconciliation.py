import json
from pathlib import Path

ROOT = Path.cwd()


def test_isolation_contradiction_is_reconciled_to_provisional_not_process_claim():
    receipt = json.loads((ROOT / "reports/v14_isolation_receipt_reconciliation.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "CONTRADICTION_RECONCILED_TO_PROVISIONAL_ISOLATION"
    assert receipt["outer_receipt_claim"] == "PROCESS_ISOLATED_MEASURED"
    assert receipt["inner_receipt_claim"] == "BEST_EFFORT_PEFT_UNLOAD_WITH_DERIVED_SPECIALIST_ROUTE"
    assert receipt["resolved_isolation_tier"] == "BEST_EFFORT_PROVISIONAL"
    assert receipt["process_isolated_claim_authorized"] is False
    assert receipt["adapter_promotion_authorized"] is False
