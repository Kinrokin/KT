from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from tools.operator.titanium_common import repo_root  # noqa: E402
from tools.operator.universal_adapter_validate import build_universal_adapter_outputs  # noqa: E402


def test_universal_adapter_outputs_bind_live_and_generated_surfaces() -> None:
    root = repo_root()
    outputs = build_universal_adapter_outputs(root=root)

    abi_v2 = outputs["abi_v2"]
    universal = outputs["universal_adapter_receipt"]
    inventory = outputs["provider_inventory_receipt"]

    assert abi_v2["status"] == "ACTIVE"
    assert universal["status"] == "PASS"
    assert inventory["status"] == "PASS"
    assert universal["live_adapter_count"] == 2
    assert universal["generated_candidate"]["status"] == "GENERATED_PROMOTABLE_CANDIDATE"
    assert universal["generated_candidate"]["adapter_class"] == "GENERATED_MUTATION_CANDIDATE"
    assert inventory["live_runtime_adapter_ids"] == [
        "council.openai.live_hashed.v1",
        "council.openrouter.live_hashed.v1",
    ]


def test_universal_adapter_cli_writes_outputs(tmp_path: Path) -> None:
    root = repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    abi_path = tmp_path / "abi_v2.json"
    receipt_path = tmp_path / "universal_adapter.json"
    inventory_path = tmp_path / "provider_inventory.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.universal_adapter_validate",
            "--abi-output",
            str(abi_path),
            "--receipt-output",
            str(receipt_path),
            "--inventory-output",
            str(inventory_path),
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
    assert payload["live_adapter_count"] == 2
    for path in (abi_path, receipt_path, inventory_path):
        assert path.exists()
