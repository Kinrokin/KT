import json
from pathlib import Path
import subprocess
import sys

ROOT = Path.cwd()


def test_adapter_identity_defect_is_bound_and_blocks_named_success_claims():
    result = subprocess.run([sys.executable, "scripts/adjudicate_adapter_identity.py"], cwd=ROOT, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr + result.stdout
    bindings = json.loads((ROOT / "admission/adapter_identity_expected_bindings.json").read_text(encoding="utf-8"))
    expected = {row["arm"]: row["expected_adapter_id"] for row in bindings["bindings"]}
    assert expected["formal_math_repair_adapter_global"] == "g3_formal_math_repair_adapter"
    receipt = json.loads((ROOT / "reports/v14_adapter_identity_adjudication_receipt.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "DEFECT_CONFIRMED_STRONG_ADAPTER_CLAIMS_BLOCKED"
    assert receipt["formal_math_adapter_success_claim_authorized"] is False
    assert receipt["adapter_promotion_authorized"] is False
    assert any(item["arm"] == "formal_math_repair_adapter_global" for item in receipt["defects"])
