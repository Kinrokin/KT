from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tools.operator import w3_externality_and_comparative_proof_validate as w3
from tools.operator.benchmark_constitution_validate import (
    COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF,
    COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF,
    DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH,
)

OVERLAY_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/e1_bounded_campaign_validate.py",
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


def test_t17_receipt_passes_on_current_repo() -> None:
    root = _repo_root()
    result = w3.build_counted_receipt_family_same_head_authority_contract_receipt(root=root)

    assert result["status"] == "PASS"
    assert result["same_head_authority_contract_ref"] == COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF
    assert result["same_head_authority_contract_owner_ref"] == COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF

    checks = {check["check_id"]: check["pass"] for check in result["checks"]}
    assert checks["t10_family_source_adopts_shared_same_head_authority_contract"] is True
    assert checks["t15_family_source_adopts_shared_same_head_authority_contract"] is True
    assert checks["generic_family_cross_head_receipt_is_carrier_only"] is True
    assert checks["generic_family_same_head_candidate_is_authoritative"] is True

    generic_probe = result["generic_same_head_authority_probe"]
    assert generic_probe["tracked_authority_class"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
    assert generic_probe["authoritative_current_head_candidate_contract"]["pass"] is True


def test_w3_cli_emits_t17_receipt_with_explicit_output(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    e2_path = tmp_path / "e2.json"
    atlas_path = tmp_path / "atlas.json"
    canonical_delta_path = tmp_path / "canonical_delta.json"
    advancement_delta_path = tmp_path / "advancement_delta.json"
    t17_receipt_path = tmp_path / "counted_receipt_family_same_head_authority_contract_receipt.json"

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
            "--emit-counted-receipt-family-same-head-authority-contract-receipt",
            "--counted-receipt-family-same-head-authority-contract-output",
            str(t17_receipt_path),
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
    assert payload["counted_receipt_family_same_head_authority_contract_status"] == "PASS"

    receipt = json.loads(t17_receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_T17_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_ARTIFACT_ONLY"
    checks = {check["check_id"]: check["pass"] for check in receipt["checks"]}
    assert checks["t10_family_source_adopts_shared_same_head_authority_contract"] is True
    assert checks["t15_family_source_adopts_shared_same_head_authority_contract"] is True
    adopted = {row["receipt_family_id"]: row["tracked_receipt_ref"] for row in receipt["adopted_receipt_families"]}
    assert adopted["T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_FAMILY"] == "KT_PROD_CLEANROOM/reports/t10_receipt_final_head_authority_alignment_receipt.json"
    assert adopted["T15_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_FAMILY"] == "KT_PROD_CLEANROOM/reports/t15_receipt_final_head_authority_alignment_receipt.json"
