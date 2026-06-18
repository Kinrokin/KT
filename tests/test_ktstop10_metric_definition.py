from __future__ import annotations

import json
import subprocess
from pathlib import Path


def test_semantic_trailer_recompute_matches_hardened_contract() -> None:
    subprocess.run(["python", "scripts/reconcile_ktstop10_metrics.py"], check=True)
    receipt = json.loads(Path("reports/ktstop10_semantic_trailer_recompute.json").read_text())
    assert receipt["expectation_status"] == "PASS"
    assert receipt["by_arm"]["A0_CURRENT_PROMPT"]["semantic_trailer_rows"] == 8
    assert receipt["by_arm"]["A1_STOP_AFTER_FINAL_ANSWER"]["semantic_trailer_rows"] == 7
    metric = json.loads(Path("reports/ktstop10_metric_definition_audit.json").read_text())
    assert "answer_line_text" in metric["corrected_fields_added"]
