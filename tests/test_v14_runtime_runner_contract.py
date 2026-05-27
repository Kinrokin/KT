from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path.cwd()
RUNNER = ROOT / "packets/ktg3full_v14_atlas/KTG3FULL_V14_ATLAS_RUNNER.py"


def test_v14_runner_fails_closed_without_measured_rows(tmp_path: Path) -> None:
    env = os.environ.copy()
    env.pop("KT_V14_PREDICTIONS_JSONL", None)
    env["KT_V14_INPUT_DIR"] = str(tmp_path / "missing_input")
    env["KT_OUTPUT_DIR"] = str(tmp_path / "out")

    result = subprocess.run([sys.executable, str(RUNNER)], cwd=ROOT, env=env, text=True, capture_output=True)

    assert result.returncode == 2
    blocker = json.loads((tmp_path / "out/BLOCKER_RECEIPT.json").read_text(encoding="utf-8"))
    assert blocker["outcome"] == "KTG3FULL_V14_BLOCKED__MISSING_MEASURED_BENCHMARK_ROWS_OR_PREGEN_DECISIONS"
    assert blocker["status"] == "SCAFFOLD_EMITTED_NOT_EARNED"
    assert blocker["claim_ceiling_preserved"] is True


def test_v14_runner_passes_with_measured_rows(tmp_path: Path) -> None:
    rows = [
        {"sample_id": "gsm8k-1", "dataset": "GSM8K", "task_family": "formal_math", "base_raw_correct": False, "formal_math_adapter_correct": True},
        {"sample_id": "arc-1", "dataset": "ARC", "task_family": "reasoning", "base_raw_correct": True, "formal_math_adapter_correct": False},
    ]
    input_path = tmp_path / "benchmark_predictions.jsonl"
    input_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    env = os.environ.copy()
    env["KT_V14_PREDICTIONS_JSONL"] = str(input_path)
    env["KT_OUTPUT_DIR"] = str(tmp_path / "out")

    result = subprocess.run([sys.executable, str(RUNNER)], cwd=ROOT, env=env, text=True, capture_output=True)

    assert result.returncode == 0
    summary = json.loads((tmp_path / "out/assessment_summary.json").read_text(encoding="utf-8"))
    scorecard = json.loads((tmp_path / "out/benchmark_scorecard.json").read_text(encoding="utf-8"))
    assert summary["status"] == "MEASURED_RUNTIME_GATE_PASS"
    assert scorecard["formal_math_router_specialist_correct"] == 2
    assert scorecard["promotion_eligible"] is False
    assert scorecard["claim_ceiling_preserved"] is True
