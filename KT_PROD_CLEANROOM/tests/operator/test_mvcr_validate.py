from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from tools.operator.mvcr_validate import build_mvcr_receipt  # noqa: E402
from tools.operator.titanium_common import repo_root  # noqa: E402


def test_mvcr_receipt_proves_bounded_sacred_path(tmp_path: Path) -> None:
    root = repo_root()
    receipt = build_mvcr_receipt(root=root, export_root=tmp_path / "exports")

    assert receipt["status"] == "PASS"
    assert receipt["canonical_run_status"] == "PASS"
    assert receipt["state_vault_delta_records"] > 0
    assert receipt["verifier_pack_status"] == "PASS"
    assert receipt["runtime_claim_compilation"]["status"] == "PASS"
    assert receipt["runtime_claim_compilation"]["externality_class_max"] == "E1_SAME_HOST_DETACHED_REPLAY"

    path_roles = {row["path_role"] for row in receipt["exact_end_to_end_path_exercised"]}
    assert {
        "ingress",
        "planner",
        "router",
        "adapter_or_provider",
        "organ_stack",
        "memory_or_state_vault",
        "verifier_pack",
        "claim_compiler",
        "bounded_output",
    } <= path_roles


def test_mvcr_cli_writes_receipt(tmp_path: Path) -> None:
    root = repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    receipt_path = tmp_path / "mvcr.json"
    export_root = tmp_path / "exports"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.mvcr_validate",
            "--receipt-output",
            str(receipt_path),
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
    assert payload["canonical_run_status"] == "PASS"
    assert payload["state_vault_delta_records"] > 0
    assert receipt_path.exists()
