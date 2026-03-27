from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_subject_boundary_receipt_blocks_stale_receipt_misread(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    subject_boundary_path = tmp_path / "comparator_receipt_subject_boundary_receipt.json"
    write_scope_path = tmp_path / "validator_write_scope_enforcement_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.benchmark_constitution_validate",
            "--write-scope-receipt-output",
            str(write_scope_path),
            "--subject-boundary-receipt-output",
            str(subject_boundary_path),
        ],
        cwd=str(root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    receipt = json.loads(subject_boundary_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["tranche_id"] == "B03_T5_COMPARATOR_RECEIPT_SUBJECT_BOUNDARY"

    attempts = {attempt["attempt_id"]: attempt for attempt in receipt["misread_attempts"]}

    t3_attempt = attempts["t3_benchmark_receipt_as_current_head_capability_proof"]
    assert t3_attempt["pass"] is False
    assert t3_attempt["blocked"] is True
    assert t3_attempt["failure_reason"] == "SUBJECT_HEAD_MISMATCH"

    t4_attempt = attempts["t4_write_scope_receipt_as_current_head_capability_proof"]
    assert t4_attempt["pass"] is False
    assert t4_attempt["blocked"] is True
    assert t4_attempt["failure_reason"] == "RECEIPT_ROLE_MISMATCH"

    roles = {binding["receipt_ref"]: binding for binding in receipt["receipt_role_bindings"]}
    assert roles["KT_PROD_CLEANROOM/reports/benchmark_constitution_receipt.json"]["receipt_role"] == "RETAINED_T3_SUBJECT_PROOF_ONLY"
    assert roles["KT_PROD_CLEANROOM/reports/validator_write_scope_enforcement_receipt.json"]["receipt_role"] == "COUNTED_T4_HARDENING_ARTIFACT_ONLY"
