from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.post_wave5_c006_second_host_execute_validate import (  # noqa: E402
    build_post_wave5_c006_second_host_execution_receipt,
    build_second_host_submission_template,
)
from tools.operator.titanium_common import repo_root  # noqa: E402


def test_second_host_execution_receipt_holds_without_return() -> None:
    receipt = build_post_wave5_c006_second_host_execution_receipt(root=repo_root())

    assert receipt["status"] == "PASS"
    assert receipt["c006_status"] == "OPEN_SECOND_HOST_EXECUTION_PENDING"
    assert receipt["blocker_delta"] == "C006_EXECUTION_ATTEMPTED_AWAITING_SECOND_HOST_RETURN"
    assert receipt["exact_externality_class_earned"] == "NOT_EARNED"
    assert receipt["environment_declaration"]["second_host_return_present"] is False


def test_second_host_submission_template_binds_current_head() -> None:
    root = repo_root()
    head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    template = build_second_host_submission_template(current_head=head)

    assert template["status"] == "PENDING_RETURN"
    assert template["current_head_commit"] == head
    assert template["required_environment_class"] == "E_CROSS_HOST_FRIENDLY"


def test_second_host_execution_cli_writes_receipt_and_template(tmp_path: Path) -> None:
    root = repo_root()
    output_path = tmp_path / "c006_second_host_execution.json"
    template_path = tmp_path / "c006_second_host_template.json"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")

    proc = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.post_wave5_c006_second_host_execute_validate",
            "--output",
            str(output_path),
            "--template-output",
            str(template_path),
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
    assert payload["blocker_delta"] == "C006_EXECUTION_ATTEMPTED_AWAITING_SECOND_HOST_RETURN"
    assert payload["exact_externality_class_earned"] == "NOT_EARNED"
    assert output_path.exists()
    assert template_path.exists()
