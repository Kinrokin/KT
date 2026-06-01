from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v17_1_functional_gate_counts_real_scripts_tests_and_packet():
    receipt = json.loads((ROOT / "reports/v17_1_functional_implementation_receipt.json").read_text(encoding="utf-8"))
    assert receipt["validation_status"] == "PASS"
    assert receipt["spec_files_implemented"] == receipt["spec_files_found"]
    assert receipt["real_scripts_added"] >= 14
    assert receipt["real_tests_added"] >= 17
    assert receipt["placeholder_tests_remaining"] == 0
    assert receipt["runtime_packet_generated"] is True
