import json
from pathlib import Path
import subprocess
import sys

ROOT = Path.cwd()


def test_v14_score_reconciliation_records_v13_to_v14_delta():
    result = subprocess.run([sys.executable, "scripts/reconcile_v14_scores.py"], cwd=ROOT, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr + result.stdout
    receipt = json.loads((ROOT / "reports/v14_score_reconciliation_receipt.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS_RECONCILED"
    assert receipt["conflicts_detected"] == []
    assert receipt["v13_formal_math_router_specialist_correct"] == 122
    assert receipt["v14_formal_math_router_specialist_correct"] == 117
    assert receipt["v13_to_v14_delta_correct"] == -5
