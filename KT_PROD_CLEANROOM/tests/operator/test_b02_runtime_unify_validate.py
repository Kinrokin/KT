from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tools.operator.b02_runtime_unify_validate import build_b02_runtime_unify_outputs
from tools.operator.titanium_common import repo_root


def test_build_b02_runtime_unify_outputs_passes_on_live_repo(tmp_path: Path) -> None:
    root = repo_root()
    outputs = build_b02_runtime_unify_outputs(
        root=root,
        export_root=tmp_path / "exports",
        c017_telemetry_path=tmp_path / "c017_telemetry.jsonl",
        w1_telemetry_path=tmp_path / "w1_telemetry.jsonl",
    )

    assert outputs["b02_runtime_unify_receipt"]["status"] == "PASS"
    assert outputs["b02_runtime_path_agreement_receipt"]["status"] == "PASS"
    assert outputs["b02_organ_honesty_receipt"]["status"] == "PASS"
    assert outputs["b02_runtime_unify_receipt"]["entry_gate_status"] is True
    assert outputs["b02_runtime_unify_receipt"]["exit_gate_status"] is False
    assert outputs["b02_runtime_unify_receipt"]["next_lawful_move"] == "CONTINUE_B02_RUNTIME_UNIFICATION_BEFORE_GATE_C"
    assert "kt.entrypoint.invoke -> core.spine.run" in outputs["b02_runtime_unify_receipt"]["earned_current_head_claims"][0]


def test_b02_runtime_unify_cli_writes_requested_receipts(tmp_path: Path) -> None:
    root = repo_root()
    cleanroom_root = root / "KT_PROD_CLEANROOM"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(cleanroom_root) + os.pathsep + str(cleanroom_root / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    canonical_scope_output = tmp_path / "canonical_scope_manifest_receipt.json"
    runtime_boundary_output = tmp_path / "runtime_boundary_receipt.json"
    single_spine_output = tmp_path / "single_spine_path_receipt.json"
    toolchain_firewall_output = tmp_path / "toolchain_runtime_firewall_receipt.json"
    c017_output = tmp_path / "c017_spine_carriage_receipt.json"
    useful_output_path = tmp_path / "useful_output_benchmark.json"
    provider_path_output = tmp_path / "provider_path_integrity_receipt.json"
    organ_register_output = tmp_path / "organ_disposition_register.json"
    organ_dependency_output = tmp_path / "organ_dependency_resolution_receipt.json"
    mvcr_output = tmp_path / "mvcr_live_execution_receipt.json"
    path_agreement_output = tmp_path / "b02_runtime_path_agreement_receipt.json"
    organ_honesty_output = tmp_path / "b02_organ_honesty_receipt.json"
    receipt_output = tmp_path / "b02_runtime_unify_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.b02_runtime_unify_validate",
            "--canonical-scope-output",
            str(canonical_scope_output),
            "--runtime-boundary-output",
            str(runtime_boundary_output),
            "--single-spine-output",
            str(single_spine_output),
            "--toolchain-firewall-output",
            str(toolchain_firewall_output),
            "--c017-output",
            str(c017_output),
            "--c017-telemetry-output",
            str(tmp_path / "c017_telemetry.jsonl"),
            "--useful-output-output",
            str(useful_output_path),
            "--provider-path-output",
            str(provider_path_output),
            "--organ-register-output",
            str(organ_register_output),
            "--organ-dependency-output",
            str(organ_dependency_output),
            "--mvcr-output",
            str(mvcr_output),
            "--w1-telemetry-output",
            str(tmp_path / "w1_telemetry.jsonl"),
            "--path-agreement-output",
            str(path_agreement_output),
            "--organ-honesty-output",
            str(organ_honesty_output),
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
        canonical_scope_output,
        runtime_boundary_output,
        single_spine_output,
        toolchain_firewall_output,
        c017_output,
        useful_output_path,
        provider_path_output,
        organ_register_output,
        organ_dependency_output,
        mvcr_output,
        path_agreement_output,
        organ_honesty_output,
        receipt_output,
    ):
        assert path.exists(), path
