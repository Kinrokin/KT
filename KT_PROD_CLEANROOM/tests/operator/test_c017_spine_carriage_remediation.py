from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.c017_spine_carriage_validate import build_c017_receipt  # noqa: E402
from tools.operator.titanium_common import repo_root  # noqa: E402


def test_c017_receipt_closes_spine_carriage_only() -> None:
    root = repo_root()
    telemetry_path = root / "KT_PROD_CLEANROOM" / "reports" / ".tmp_c017_spine_carriage_telemetry.jsonl"
    export_root = root / "KT_PROD_CLEANROOM" / "exports" / ".tmp_c017_spine_carriage"
    receipt = build_c017_receipt(root=root, telemetry_path=telemetry_path, export_root=export_root)

    assert receipt["status"] == "PASS"
    assert receipt["wave3_unlock_assessment"]["c017_closed"] is True
    assert receipt["wave3_unlock_assessment"]["wave3_unlocked"] is True
    assert receipt["wave3_unlock_assessment"]["wave3_auto_opened"] is False
    assert "minimum_viable_civilization_run_executed" in receipt["stronger_claim_not_made"]
    assert "C005_ROUTER_AMBITION_EXCEEDS_IMPLEMENTATION" in receipt["remaining_open_truths"]
    assert "C016_REMOTE_PROVIDER_AUTH_ONLY_FAIL_CLOSED_OUTCOMES_VISIBLE" in receipt["remaining_open_truths"]

    rows = receipt["carriage_matrix"]
    assert rows
    assert all(row["status"] == "PASS" for row in rows)
    assert all(row["comparison_pass"] is True for row in rows)
    assert all(row["input_string_length"] > receipt["exact_ceiling"]["legacy_general_string_limit"] for row in rows)
    assert receipt["oversize_guard"]["status"] == "PASS"
    assert receipt["oversize_guard"]["message_match"] is True


def test_c017_cli_writes_receipt(tmp_path: Path) -> None:
    root = repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    receipt_path = tmp_path / "receipt.json"
    telemetry_path = tmp_path / "telemetry.jsonl"
    export_root = tmp_path / "exports"

    proc = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.c017_spine_carriage_validate",
            "--receipt-output",
            str(receipt_path),
            "--telemetry-output",
            str(telemetry_path),
            "--export-root",
            str(export_root),
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
    assert payload["wave3_unlocked"] is True
    assert receipt_path.exists()
