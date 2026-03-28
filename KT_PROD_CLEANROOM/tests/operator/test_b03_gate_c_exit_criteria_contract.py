from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tools.operator import w3_externality_and_comparative_proof_validate as w3
from tools.operator.benchmark_constitution_validate import (
    DEFAULT_GATE_C_EXIT_CRITERIA_CONTRACT_REL,
    DEFAULT_GATE_C_EXIT_TERMINAL_STATE_REL,
)

OVERLAY_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
    DEFAULT_GATE_C_EXIT_CRITERIA_CONTRACT_REL,
    DEFAULT_GATE_C_EXIT_TERMINAL_STATE_REL,
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _clean_clone(tmp_path: Path) -> Path:
    root = _repo_root()
    clone_root = tmp_path / "repo"
    subprocess.run(
        ["git", "clone", "--quiet", str(root), str(clone_root)],
        cwd=str(tmp_path),
        check=True,
    )
    for ref in OVERLAY_REFS:
        src = root / ref
        dst = clone_root / ref
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return clone_root


def test_gate_c_exit_criteria_contract_receipt_passes_on_current_repo() -> None:
    root = _repo_root()
    result = w3.build_gate_c_exit_criteria_contract_receipt(root=root)

    assert result["status"] == "PASS"
    assert result["contract_mode"] == "DEFINITION_ONLY_NO_OUTCOME_CLAIM"
    assert result["terminal_state"]["current_state"] == "EXIT_CRITERIA_BOUND_NOT_ADJUDICATED"
    assert result["terminal_state"]["gate_c_exit_claim_allowed"] is False
    assert result["terminal_state"]["live_beats_baseline_claim_allowed"] is False
    assert "KT_PROD_CLEANROOM/reports/baseline_vs_live_scorecard.json" in result["required_same_head_evidence_surface_refs"]
    assert "KT_PROD_CLEANROOM/reports/tracked_counted_receipt_class_authority_closure_receipt.json" in result["required_same_head_authority_contract_receipt_refs"]
    assert all(item["authority_shape_complete"] is False for item in result["documentary_surface_classification"])
    assert result["tracked_counted_receipt_class_authority_closure_regression"]["status"] == "PASS"


def test_w3_cli_emits_gate_c_exit_criteria_contract_receipt_with_explicit_output(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    e2_path = tmp_path / "e2.json"
    atlas_path = tmp_path / "atlas.json"
    canonical_delta_path = tmp_path / "canonical_delta.json"
    advancement_delta_path = tmp_path / "advancement_delta.json"
    receipt_path = tmp_path / "gate_c_exit_criteria_contract_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.w3_externality_and_comparative_proof_validate",
            "--e2-output",
            str(e2_path),
            "--capability-atlas-output",
            str(atlas_path),
            "--canonical-delta-output",
            str(canonical_delta_path),
            "--advancement-delta-output",
            str(advancement_delta_path),
            "--emit-gate-c-exit-criteria-contract-receipt",
            "--gate-c-exit-criteria-contract-output",
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
    assert payload["gate_c_exit_criteria_contract_status"] == "PASS"

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_GATE_C_EXIT_CRITERIA_CONTRACT_ARTIFACT_ONLY"
    assert receipt["contract_mode"] == "DEFINITION_ONLY_NO_OUTCOME_CLAIM"
    assert receipt["terminal_state"]["gate_c_exit_claim_allowed"] is False
    assert receipt["terminal_state"]["live_beats_baseline_claim_allowed"] is False
