from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_contract_enforcement_receipt_fails_closed_on_missing_or_mismatched_fields(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    write_scope_path = tmp_path / "validator_write_scope_enforcement_receipt.json"
    subject_boundary_path = tmp_path / "comparator_receipt_subject_boundary_receipt.json"
    contract_enforcement_path = tmp_path / "comparator_receipt_contract_enforcement_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.benchmark_constitution_validate",
            "--write-scope-receipt-output",
            str(write_scope_path),
            "--subject-boundary-receipt-output",
            str(subject_boundary_path),
            "--contract-enforcement-receipt-output",
            str(contract_enforcement_path),
        ],
        cwd=str(root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    receipt = json.loads(contract_enforcement_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["tranche_id"] == "B03_T6_COMPARATOR_RECEIPT_CONTRACT_ENFORCEMENT"

    checks = {check["check_id"]: check["pass"] for check in receipt["checks"]}
    assert checks["generated_baseline_scorecard_declares_receipt_role"] is True
    assert checks["generated_baseline_scorecard_declares_subject_head"] is True
    assert checks["well_formed_generated_receipts_consume_successfully"] is True

    attempts = {attempt["attempt_id"]: attempt for attempt in receipt["malformed_consumption_attempts"]}
    assert attempts["missing_receipt_role_rejected"]["failure_reason"] == "RECEIPT_ROLE_MISSING"
    assert attempts["missing_subject_head_rejected"]["failure_reason"] == "SUBJECT_HEAD_MISSING"
    assert attempts["wrong_receipt_role_rejected"]["failure_reason"] == "RECEIPT_ROLE_MISMATCH"
    assert attempts["wrong_subject_head_rejected"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH"
    assert attempts["subject_boundary_missing_role_rejected"]["failure_reason"] == "RECEIPT_ROLE_MISSING"
