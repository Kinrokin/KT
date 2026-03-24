from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_wave3_cli_emits_bounded_receipts(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    receipt_path = tmp_path / "wave3_receipt.json"
    detached_receipt_path = tmp_path / "wave3_detached_receipt.json"
    compiler_path = tmp_path / "wave3_claim_compiler.json"
    matrix_path = tmp_path / "wave3_claim_matrix.json"
    bounded_output_path = tmp_path / "wave3_bounded_output.json"
    telemetry_path = tmp_path / "wave3_telemetry.jsonl"
    export_root = tmp_path / "exports"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.wave3_minimum_viable_civilization_validate",
            "--receipt-output",
            str(receipt_path),
            "--detached-receipt-output",
            str(detached_receipt_path),
            "--claim-compiler-output",
            str(compiler_path),
            "--claim-class-matrix-output",
            str(matrix_path),
            "--bounded-output",
            str(bounded_output_path),
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

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    detached = json.loads(detached_receipt_path.read_text(encoding="utf-8"))
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    bounded = json.loads(bounded_output_path.read_text(encoding="utf-8"))

    assert receipt["status"] == "PASS"
    assert receipt["canonical_run"]["status"] == "PASS"
    assert receipt["canonical_run"]["state_vault_delta_records"] > 0
    assert any(step["path_role"] == "adapter_or_provider" for step in receipt["exact_end_to_end_path_exercised"])
    assert detached["status"] == "PASS"
    assert detached["externality_class"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert matrix["status"] == "PASS"
    assert bounded["status"] == "PASS"
    assert "C016_REMOTE_PROVIDER_AUTH_ONLY_FAIL_CLOSED_OUTCOMES_VISIBLE" in receipt["remaining_open_contradictions"]
