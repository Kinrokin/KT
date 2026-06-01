from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_assessment_only_output_mode_is_wired():
    receipt = json.loads((ROOT / "reports/v17_1_output_mode_receipt.json").read_text(encoding="utf-8"))
    manifest = json.loads((ROOT / "reports/v17_1_assessment_only_manifest.json").read_text(encoding="utf-8"))
    assert receipt["KT_OUTPUT_MODE"] == "ASSESSMENT_ONLY"
    assert receipt["KT_PRINT_JSON_EVENTS_ONLY"] == "1"
    assert "aggregated_measured_rows/benchmark_predictions.jsonl" in manifest["included"]
    assert manifest["status"] == "PASS"
