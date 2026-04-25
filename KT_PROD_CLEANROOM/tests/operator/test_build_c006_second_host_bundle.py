from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_build_c006_second_host_bundle_cli_stages_bundle(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    output_dir = tmp_path / "bundle"
    receipt_path = tmp_path / "second_host_kit_hardening_receipt.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.build_c006_second_host_bundle",
            "--output-dir",
            str(output_dir),
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
    assert payload["receipt_status"] == "PASS"
    assert payload["bundle_file_count"] >= 10

    manifest_path = output_dir / "KT_PROD_CLEANROOM" / "reports" / "c006_second_host_bundle_manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "PASS"
    assert manifest["bundle_class"] == "READY_PENDING_HARDWARE"
    assert any(row["source_ref"].endswith("post_wave5_c006_friendly_host_handoff_pack.json") for row in manifest["bundle_rows"])

    assert receipt_path.exists()
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["kit_status"] == "READY_STAGED_PENDING_HARDWARE"
    assert receipt["blocker_id"] == "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"
    assert receipt["bundle_file_count"] == len(manifest["bundle_rows"])
