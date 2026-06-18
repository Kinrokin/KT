from __future__ import annotations

import json
import subprocess
from pathlib import Path


def test_first_answer_lock_gate_allows_exact_sandbox_only() -> None:
    subprocess.run(["python", "scripts/audit_first_last_final_answers.py"], check=True)
    gate = json.loads(Path("reports/ktstop10_first_answer_lock_gate.json").read_text())
    assert gate["status"] == "PASS_ZERO_FIRST_WRONG_LATER_CORRECTED_ON_STOP10"
    assert gate["first_final_wrong_later_corrected"] == 0
    assert gate["first_final_correct_later_damaged"] == 2
    assert gate["shadow_canary_default_authority"] is False
