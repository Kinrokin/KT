from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_6_functional_implementation_gate_passes_with_real_scripts_and_tests():
    receipt = json.loads((ROOT / "reports/v17_6_functional_implementation_receipt.json").read_text(encoding="utf-8"))
    assert receipt["validation_status"] == "PASS"
    assert receipt["placeholder_tests_remaining"] == 0
    assert receipt["real_scripts_added"] >= 10
    assert receipt["real_tests_added"] >= 10
    assert receipt["oracle_gap_rows_generated"] == 26
    assert receipt["policy_patch_emitted"] is True
    assert receipt["lean_packaging_wired"] is True
    assert receipt["runtime_packet_generated"] is True
    assert (ROOT / "scripts/v17_6_oracle_autopsy_common.py").exists()
    assert (ROOT / "scripts/generate_ktv176_e2e_v1.py").exists()
