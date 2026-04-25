from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tools.operator.b02_runtime_unify_t3_validate import build_b02_runtime_unify_t3_outputs
from tools.operator.titanium_common import repo_root


def test_build_b02_runtime_unify_t3_outputs_passes_on_live_repo(tmp_path: Path) -> None:
    root = repo_root()
    outputs = build_b02_runtime_unify_t3_outputs(
        root=root,
        export_root=tmp_path / "exports",
        c017_telemetry_path=tmp_path / "c017_telemetry.jsonl",
        w1_telemetry_path=tmp_path / "w1_telemetry.jsonl",
    )

    assert outputs["b02_runtime_unify_t3_receipt"]["status"] == "PASS"
    assert outputs["b02_state_vault_lawfulness_receipt"]["status"] == "PASS"
    assert outputs["b02_residual_organ_truth_receipt"]["status"] == "PASS"
    assert outputs["b02_exit_gap_receipt"]["status"] == "PASS"
    assert outputs["b02_runtime_unify_t3_receipt"]["entry_gate_status"] is True
    assert outputs["b02_runtime_unify_t3_receipt"]["exit_gate_status"] is False
    assert outputs["b02_runtime_unify_t3_receipt"]["next_lawful_move"] == "CONTINUE_B02_RUNTIME_UNIFICATION_BEFORE_GATE_C"


def test_b02_runtime_unify_t3_cli_writes_requested_receipts(tmp_path: Path) -> None:
    root = repo_root()
    cleanroom_root = root / "KT_PROD_CLEANROOM"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(cleanroom_root) + os.pathsep + str(cleanroom_root / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    state_vault_output = tmp_path / "b02_state_vault_lawfulness_receipt.json"
    residual_output = tmp_path / "b02_residual_organ_truth_receipt.json"
    exit_gap_output = tmp_path / "b02_exit_gap_receipt.json"
    receipt_output = tmp_path / "b02_runtime_unify_t3_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.b02_runtime_unify_t3_validate",
            "--c017-telemetry-output",
            str(tmp_path / "c017_telemetry.jsonl"),
            "--w1-telemetry-output",
            str(tmp_path / "w1_telemetry.jsonl"),
            "--state-vault-lawfulness-output",
            str(state_vault_output),
            "--residual-organ-truth-output",
            str(residual_output),
            "--exit-gap-output",
            str(exit_gap_output),
            "--receipt-output",
            str(receipt_output),
            "--export-root",
            str(tmp_path / "exports"),
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
    assert payload["entry_gate_status"] is True
    assert payload["exit_gate_status"] is False
    assert payload["next_lawful_move"] == "CONTINUE_B02_RUNTIME_UNIFICATION_BEFORE_GATE_C"

    for path in (
        state_vault_output,
        residual_output,
        exit_gap_output,
        receipt_output,
    ):
        assert path.exists(), path
