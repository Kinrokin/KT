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
    "KT_PROD_CLEANROOM/tools/operator/final_current_head_adjudication_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
    "KT_PROD_CLEANROOM/governance/counted_consumer_allowlist_contract.json",
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


def test_t15_receipt_final_head_authority_alignment_passes_on_current_repo() -> None:
    root = _repo_root()
    result = w3.build_t15_receipt_final_head_authority_alignment_receipt(root=root)

    assert result["status"] == "PASS"
    assert result["tracked_t15_authority_class"] == "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH"
    assert result["tracked_t15_contract"]["blocked"] is True
    assert result["tracked_t15_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH"
    assert result["authoritative_current_head_t15_candidate_contract"]["pass"] is True
    assert result["authoritative_current_head_t15_candidate_contract"]["subject_head"] == result["current_git_head"]


def test_w3_cli_emits_t16_receipt_with_explicit_output(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    e2_path = tmp_path / "e2.json"
    atlas_path = tmp_path / "atlas.json"
    canonical_delta_path = tmp_path / "canonical_delta.json"
    advancement_delta_path = tmp_path / "advancement_delta.json"
    t16_receipt_path = tmp_path / "t15_receipt_final_head_authority_alignment_receipt.json"

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
            "--emit-t15-receipt-final-head-authority-alignment-receipt",
            "--t15-receipt-final-head-authority-alignment-output",
            str(t16_receipt_path),
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
    assert payload["documentary_carrier_consumer_status"] == "PASS"
    assert payload["t15_receipt_final_head_authority_alignment_status"] == "PASS"

    receipt = json.loads(t16_receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_T16_T15_FINAL_HEAD_AUTHORITY_ALIGNMENT_ARTIFACT_ONLY"
    assert receipt["tracked_t15_authority_class"] == "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH"
    assert receipt["tracked_t15_contract"]["blocked"] is True
    assert receipt["tracked_t15_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH"
    assert receipt["authoritative_current_head_t15_candidate_contract"]["pass"] is True
