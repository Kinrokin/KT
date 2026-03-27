from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tools.operator.b02_runtime_unify_t4_validate import build_b02_runtime_unify_t4_outputs
from tools.operator.titanium_common import repo_root


def test_build_b02_runtime_unify_t4_outputs_passes_on_live_repo(tmp_path: Path) -> None:
    root = repo_root()
    outputs = build_b02_runtime_unify_t4_outputs(
        root=root,
        export_root=tmp_path / "exports",
        c017_telemetry_path=tmp_path / "c017_telemetry.jsonl",
        w1_telemetry_path=tmp_path / "w1_telemetry.jsonl",
    )

    assert outputs["b02_runtime_unify_t4_receipt"]["status"] == "PASS"
    assert outputs["b02_adapter_runtime_boundary_receipt"]["status"] == "PASS"
    assert outputs["b02_router_boundary_truth_receipt"]["status"] == "PASS"
    assert outputs["b02_promotion_boundary_truth_receipt"]["status"] == "PASS"
    assert outputs["b02_exit_gap_reduction_receipt"]["status"] == "PASS"
    assert outputs["b02_runtime_unify_t4_receipt"]["entry_gate_status"] is True
    assert outputs["b02_runtime_unify_t4_receipt"]["exit_gate_status"] is False
    assert outputs["b02_runtime_unify_t4_receipt"]["next_lawful_move"] == "CONTINUE_B02_RUNTIME_UNIFICATION_BEFORE_GATE_C"
    assert len(outputs["b02_exit_gap_reduction_receipt"]["remaining_exit_blockers"]) == 1
    assert outputs["b02_exit_gap_reduction_receipt"]["remaining_exit_blockers"][0]["blocker_id"] == "PROMOTION_CIVILIZATION_RATIFIED_FALSE"


def test_b02_runtime_unify_t4_cli_writes_requested_receipts(tmp_path: Path) -> None:
    root = repo_root()
    cleanroom_root = root / "KT_PROD_CLEANROOM"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(cleanroom_root) + os.pathsep + str(cleanroom_root / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    adapter_boundary_output = tmp_path / "b02_adapter_runtime_boundary_receipt.json"
    router_boundary_output = tmp_path / "b02_router_boundary_truth_receipt.json"
    promotion_boundary_output = tmp_path / "b02_promotion_boundary_truth_receipt.json"
    exit_gap_reduction_output = tmp_path / "b02_exit_gap_reduction_receipt.json"
    receipt_output = tmp_path / "b02_runtime_unify_t4_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.b02_runtime_unify_t4_validate",
            "--c017-telemetry-output",
            str(tmp_path / "c017_telemetry.jsonl"),
            "--w1-telemetry-output",
            str(tmp_path / "w1_telemetry.jsonl"),
            "--adapter-boundary-output",
            str(adapter_boundary_output),
            "--router-boundary-output",
            str(router_boundary_output),
            "--promotion-boundary-output",
            str(promotion_boundary_output),
            "--exit-gap-reduction-output",
            str(exit_gap_reduction_output),
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
    assert payload["remaining_exit_blocker_count"] == 1

    for path in (
        adapter_boundary_output,
        router_boundary_output,
        promotion_boundary_output,
        exit_gap_reduction_output,
        receipt_output,
    ):
        assert path.exists(), path
