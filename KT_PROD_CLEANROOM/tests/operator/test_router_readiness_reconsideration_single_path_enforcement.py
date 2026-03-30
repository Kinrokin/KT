from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.operator import router_readiness_reconsideration_input_validate as validate


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_single_path_enforcement_receipt_passes_on_current_repo() -> None:
    receipt = validate.build_router_readiness_reconsideration_single_path_enforcement_receipt(root=_repo_root())

    assert receipt["status"] == "PASS"
    assert receipt["sanctioned_paths"]["emitter"] == "KT_PROD_CLEANROOM/tools/router/run_router_readiness_reconsideration_input.py"
    assert (
        receipt["sanctioned_paths"]["consumer_validator"]
        == "KT_PROD_CLEANROOM/tools/operator/router_readiness_reconsideration_input_validate.py"
    )
    assert receipt["detected_schema_emitters"] == [receipt["sanctioned_paths"]["emitter"]]
    assert receipt["detected_schema_touchers"] == [
        receipt["sanctioned_paths"]["consumer_validator"],
        receipt["sanctioned_paths"]["emitter"],
    ]


def test_single_path_enforcement_cli_emits_pass_receipt(tmp_path: Path) -> None:
    output_path = tmp_path / "single_path_enforcement_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.router_readiness_reconsideration_input_validate",
            "--emit-single-path-enforcement-receipt",
            "--output",
            str(output_path),
        ],
        cwd=str(_repo_root() / "KT_PROD_CLEANROOM"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["detected_schema_emitters"] == ["KT_PROD_CLEANROOM/tools/router/run_router_readiness_reconsideration_input.py"]
