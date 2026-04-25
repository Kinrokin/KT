from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tools.operator.single_spine_path_validate import build_single_spine_receipts
from tools.operator.titanium_common import repo_root


def test_build_single_spine_receipts_passes_on_live_repo(tmp_path: Path) -> None:
    root = repo_root()
    receipts = build_single_spine_receipts(
        root=root,
        report_root_rel="KT_PROD_CLEANROOM/reports",
        export_root=tmp_path / "exports",
    )

    canonical_scope = receipts["canonical_scope_manifest_receipt"]
    runtime_boundary = receipts["runtime_boundary_receipt"]
    single_spine = receipts["single_spine_path_receipt"]

    assert canonical_scope["status"] == "PASS", canonical_scope
    assert runtime_boundary["status"] == "PASS", runtime_boundary
    assert single_spine["status"] == "PASS", single_spine
    assert single_spine["canonical_entry_callable"] == "kt.entrypoint.invoke"
    assert single_spine["canonical_spine_callable"] == "core.spine.run"
    assert single_spine["next_lawful_move"] == "W2_RUNTIME_ORGAN_REALIZATION_AND_MVCR"
    assert len(single_spine["probe_matrix"]) == 2
    assert {row["probe_id"] for row in single_spine["probe_matrix"]} == {"cognition_request", "council_request"}
    assert all(row["status"] == "PASS" for row in single_spine["probe_matrix"])


def test_single_spine_cli_writes_requested_receipts(tmp_path: Path) -> None:
    root = repo_root()
    cleanroom_root = root / "KT_PROD_CLEANROOM"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(cleanroom_root) + os.pathsep + str(cleanroom_root / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    canonical_scope_output = tmp_path / "canonical_scope_manifest_receipt.json"
    runtime_boundary_output = tmp_path / "runtime_boundary_receipt.json"
    single_spine_output = tmp_path / "single_spine_path_receipt.json"
    export_root = tmp_path / "exports"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.single_spine_path_validate",
            "--canonical-scope-output",
            str(canonical_scope_output),
            "--runtime-boundary-output",
            str(runtime_boundary_output),
            "--single-spine-output",
            str(single_spine_output),
            "--export-root",
            str(export_root),
        ],
        cwd=str(cleanroom_root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["canonical_scope_status"] == "PASS"
    assert payload["runtime_boundary_status"] == "PASS"
    assert payload["single_spine_status"] == "PASS"
    assert canonical_scope_output.exists()
    assert runtime_boundary_output.exists()
    assert single_spine_output.exists()
