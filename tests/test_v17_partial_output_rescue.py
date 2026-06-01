from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_partial_output_rescue_contract_preserves_measured_artifacts():
    receipt = json.loads((ROOT / "reports/v17_1_partial_output_rescue_receipt.json").read_text(encoding="utf-8"))
    contract = json.loads((ROOT / "reports/v17_1_finalization_failure_contract.json").read_text(encoding="utf-8"))
    assert receipt["partial_measured_outputs_zip_on_finalization_failure"] is True
    assert receipt["assessment_zip_when_measured_rows_exist"] is True
    assert contract["emit_blocker_receipt"] is True
    assert contract["preserve_measured_artifacts"] is True
