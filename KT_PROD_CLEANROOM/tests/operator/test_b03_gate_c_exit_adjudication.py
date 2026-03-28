from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tools.operator import w3_externality_and_comparative_proof_validate as w3

OVERLAY_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
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


def test_gate_c_exit_adjudication_receipt_passes_on_current_repo() -> None:
    root = _repo_root()
    result = w3.build_gate_c_exit_adjudication_receipt(root=root)

    assert result["status"] == "PASS"
    assert result["receipt_role"] == "COUNTED_GATE_C_EXIT_ADJUDICATION_ARTIFACT_ONLY"
    assert result["gate_c_exit_earned"] is True
    assert result["live_beats_baseline_adjudicated"] is True
    assert all(item["pass"] is True and item["blocked"] is False for item in result["same_head_evidence_surface_contracts"])
    assert all(item["pass"] is True and item["blocked"] is False for item in result["same_head_authority_contract_receipts"])
    assert result["final_current_head_adjudication_authority_binding_regression"]["status"] == "PASS"
    tracked_final = next(
        item for item in result["forbidden_surface_classification"]
        if item["surface_ref"] == "KT_PROD_CLEANROOM/reports/final_current_head_adjudication_receipt.json"
    )
    assert tracked_final["tracked_authority_class"] == "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH"
    assert tracked_final["tracked_contract"]["blocked"] is True
    assert tracked_final["tracked_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH"
    assert result["gate_d_authorized"] is False
    assert result["next_lawful_move"] == "REANCHOR_CURRENT_STATE_FOR_GATE_D_DECISION"


def test_w3_cli_emits_gate_c_exit_adjudication_receipt_with_explicit_output(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    e2_path = tmp_path / "e2.json"
    atlas_path = tmp_path / "atlas.json"
    canonical_delta_path = tmp_path / "canonical_delta.json"
    advancement_delta_path = tmp_path / "advancement_delta.json"
    receipt_path = tmp_path / "gate_c_exit_adjudication_receipt.json"

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
            "--emit-gate-c-exit-adjudication-receipt",
            "--gate-c-exit-adjudication-output",
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
    assert payload["gate_c_exit_adjudication_status"] == "PASS"

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_GATE_C_EXIT_ADJUDICATION_ARTIFACT_ONLY"
    assert receipt["gate_c_exit_earned"] is True
    assert receipt["live_beats_baseline_adjudicated"] is True
    assert receipt["gate_d_authorized"] is False
    assert receipt["next_lawful_move"] == "REANCHOR_CURRENT_STATE_FOR_GATE_D_DECISION"
    assert all(item["pass"] is True and item["blocked"] is False for item in receipt["same_head_evidence_surface_contracts"])
    assert all(item["pass"] is True and item["blocked"] is False for item in receipt["same_head_authority_contract_receipts"])
    tracked_final = next(
        item for item in receipt["forbidden_surface_classification"]
        if item["surface_ref"] == "KT_PROD_CLEANROOM/reports/final_current_head_adjudication_receipt.json"
    )
    assert tracked_final["tracked_authority_class"] == "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH"
    assert tracked_final["tracked_contract"]["blocked"] is True
    assert tracked_final["tracked_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH"
