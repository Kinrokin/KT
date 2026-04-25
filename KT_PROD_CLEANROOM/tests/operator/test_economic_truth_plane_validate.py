from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_economic_truth_plane_cli_emits_profile_coverage(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    plane_path = tmp_path / "plane.json"
    receipt_path = tmp_path / "receipt.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.economic_truth_plane_validate",
            "--plane-output",
            str(plane_path),
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
    assert payload["profile_count"] >= 4

    plane = json.loads(plane_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    profile_ids = {profile["profile_id"] for profile in plane["profiles"]}
    assert plane["schema_id"] == "kt.economic_truth_plane.v1"
    assert "canonical_same_host_runtime_lane" in profile_ids
    assert "bounded_verifier_handoff_lane" in profile_ids
    assert "bounded_mutation_civilization_lane" in profile_ids
    assert "c006_cross_host_reentry_lane" in profile_ids
    assert receipt["status"] == "PASS"
