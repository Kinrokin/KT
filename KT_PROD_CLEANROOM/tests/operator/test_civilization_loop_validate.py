from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from tools.operator.civilization_loop_validate import build_civilization_loop_outputs  # noqa: E402
from tools.operator.titanium_common import repo_root  # noqa: E402


def test_civilization_loop_outputs_prove_bounded_mutation_cycle() -> None:
    root = repo_root()
    outputs = build_civilization_loop_outputs(root=root)

    contract = outputs["contract"]
    rollback_receipt = outputs["rollback_receipt"]
    learning_response_receipt = outputs["learning_response_receipt"]
    civilization_loop_receipt = outputs["civilization_loop_receipt"]

    assert contract["status"] == "ACTIVE"
    assert rollback_receipt["status"] == "PASS"
    assert learning_response_receipt["status"] == "PASS"
    assert civilization_loop_receipt["status"] == "PASS"
    assert civilization_loop_receipt["promotion_decision"] == "PROMOTE"
    assert learning_response_receipt["learning_response_status"] == "BOUNDED_SAFE_IMPROVEMENT_PROVED"


def test_civilization_loop_cli_writes_outputs(tmp_path: Path) -> None:
    root = repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    contract_path = tmp_path / "civilization_contract.json"
    receipt_path = tmp_path / "civilization_receipt.json"
    rollback_path = tmp_path / "rollback_receipt.json"
    learning_path = tmp_path / "learning_response.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.civilization_loop_validate",
            "--contract-output",
            str(contract_path),
            "--receipt-output",
            str(receipt_path),
            "--rollback-output",
            str(rollback_path),
            "--learning-output",
            str(learning_path),
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
    assert payload["promotion_decision"] == "PROMOTE"
    for path in (contract_path, receipt_path, rollback_path, learning_path):
        assert path.exists()
