from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_capability_atlas_cli_emits_mapped_rows(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    atlas_path = tmp_path / "atlas.json"
    receipt_path = tmp_path / "receipt.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.capability_atlas_validate",
            "--atlas-output",
            str(atlas_path),
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
    assert payload["surface_count"] >= 10

    atlas = json.loads(atlas_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    by_surface = {row["surface_id"]: row for row in atlas["topology"]}
    assert atlas["schema_id"] == "kt.capability_atlas.v1"
    assert "adapter_layer" in by_surface
    assert by_surface["adapter_layer"]["governing_law_ref"].endswith("kt_adapter_abi_v2.json")
    assert by_surface["tournament_promotion"]["challenge_pack_ref"].endswith("civilization_loop_receipt.json")
    assert by_surface["detached_verifier_externality_lane"]["economic_profile_id"] == "c006_cross_host_reentry_lane"
    assert receipt["status"] == "PASS"
    assert receipt["surface_count"] == len(atlas["topology"])
