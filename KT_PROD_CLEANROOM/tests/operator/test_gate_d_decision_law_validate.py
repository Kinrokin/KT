from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tools.operator import gate_d_decision_law_validate as gate_d

OVERLAY_REFS = [
    "KT_PROD_CLEANROOM/governance/gate_d_decision_law.json",
    "KT_PROD_CLEANROOM/governance/gate_d_decision_terminal_state.json",
    "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json",
    "KT_PROD_CLEANROOM/tools/operator/gate_d_decision_law_validate.py",
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


def test_gate_d_decision_law_receipt_passes_on_current_repo() -> None:
    root = _repo_root()
    result = gate_d.build_gate_d_decision_law_receipt(root=root)

    assert result["status"] == "PASS"
    assert result["law_type"] == "GATE_D_DECISION_BALLOT"
    assert result["mode"] == "DEFINITION_ONLY_NO_POSTURE_SELECTED"
    assert result["gate_c_exit_head"] == "71268f2f7489aadec338d5e71bb5b70f8a7fe9dc"
    assert result["reanchor_head"] == "ee752460e34ad2411adc3d228704f20c421f33be"
    assert result["postures_selected"] is False
    assert result["b04_activation_allowed"] is False
    assert result["next_lawful_move"] == "B04_GATE_D_POSTURE_SELECTION_ONLY"
    assert all(row["allowed_postures_exact"] for row in result["domain_rows"])
    assert all(row["default_is_restrictive"] for row in result["domain_rows"])
    assert all(row["selected_posture_is_unset"] for row in result["domain_rows"])


def test_gate_d_decision_law_cli_emits_receipt_with_explicit_output(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    receipt_path = tmp_path / "gate_d_decision_law_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.gate_d_decision_law_validate",
            "--output",
            str(receipt_path),
        ],
        cwd=str(root / "KT_PROD_CLEANROOM"),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["gate_d_decision_law_status"] == "PASS"
    assert payload["next_lawful_move"] == "B04_GATE_D_POSTURE_SELECTION_ONLY"

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_GATE_D_DECISION_LAW_ARTIFACT_ONLY"
    assert receipt["mode"] == "DEFINITION_ONLY_NO_POSTURE_SELECTED"
    assert receipt["postures_selected"] is False
    assert receipt["b04_activation_allowed"] is False
    assert receipt["next_lawful_move"] == "B04_GATE_D_POSTURE_SELECTION_ONLY"
