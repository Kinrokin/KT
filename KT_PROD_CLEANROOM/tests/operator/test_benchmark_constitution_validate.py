from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_benchmark_constitution_cli_emits_receipt_and_negative_ledger(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    negative_path = tmp_path / "negative.json"
    receipt_path = tmp_path / "receipt.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.benchmark_constitution_validate",
            "--negative-ledger-output",
            str(negative_path),
            "--receipt-output",
            str(receipt_path),
        ],
        cwd=str(root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["actual_category"] == "GOVERNED_RECEIPT_BACKED_FAIL_CLOSED_AI_EXECUTION_WITH_ADAPTIVE_IMPROVEMENT_UNDER_LAW"
    assert payload["negative_result_row_count"] >= 5

    negative = json.loads(negative_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert negative["status"] == "PASS"
    assert len(negative["rows"]) >= 5
    assert receipt["status"] == "PASS"
    assert receipt["negative_result_row_count"] >= 5
