from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tools.operator import final_current_head_adjudication_validate as final_current
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


def test_documentary_carrier_guard_is_centralized_in_both_consumers() -> None:
    root = _repo_root()
    final_guard = final_current.evaluate_documentary_carrier_fail_closed_consumer_guard(root=root)
    w3_guard = w3.evaluate_documentary_carrier_fail_closed_consumer_guard(root=root)
    receipt = w3.build_documentary_carrier_guard_centralization_receipt(root=root)

    assert final_guard["status"] == "PASS"
    assert w3_guard["status"] == "PASS"
    assert final_guard["shared_guard_helper_ref"] == "tools.operator.benchmark_constitution_validate.evaluate_documentary_carrier_fail_closed_consumer_guard"
    assert w3_guard["shared_guard_helper_ref"] == "tools.operator.benchmark_constitution_validate.evaluate_documentary_carrier_fail_closed_consumer_guard"
    assert receipt["status"] == "PASS"
    assert all(check["pass"] for check in receipt["source_checks"])
    assert receipt["final_current_head_consumer_guard"]["documentary_carrier_attempt"]["failure_reason"] == "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH"
    assert receipt["w3_consumer_guard"]["documentary_carrier_attempt"]["failure_reason"] == "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH"


def test_w3_cli_emits_t13_receipt_with_explicit_opt_in_only(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    e2_path = tmp_path / "e2.json"
    atlas_path = tmp_path / "atlas.json"
    canonical_delta_path = tmp_path / "canonical_delta.json"
    advancement_delta_path = tmp_path / "advancement_delta.json"
    t13_receipt_path = tmp_path / "documentary_carrier_guard_centralization_receipt.json"

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
            "--emit-documentary-carrier-guard-centralization-receipt",
            "--documentary-carrier-guard-centralization-output",
            str(t13_receipt_path),
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

    receipt = json.loads(t13_receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_T13_DOCUMENTARY_CARRIER_GUARD_CENTRALIZATION_ARTIFACT_ONLY"
    assert receipt["shared_guard_helper_ref"] == "tools.operator.benchmark_constitution_validate.evaluate_documentary_carrier_fail_closed_consumer_guard"
    assert all(check["pass"] for check in receipt["source_checks"])
