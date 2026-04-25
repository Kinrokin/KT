from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tools.operator import gate_d_decision_receipt_validate as gate_d


OVERLAY_REFS = [
    "KT_PROD_CLEANROOM/governance/b04_civilization_activation_launch_contract.json",
    "KT_PROD_CLEANROOM/tools/operator/gate_d_decision_receipt_validate.py",
    "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json",
    "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json",
    "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json",
    "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _clean_clone(tmp_path: Path) -> Path:
    root = _repo_root()
    clone_root = tmp_path / "repo"
    subprocess.run(["git", "clone", "--quiet", str(root), str(clone_root)], cwd=str(tmp_path), check=True)
    for ref in OVERLAY_REFS:
        src = root / ref
        dst = clone_root / ref
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return clone_root


def test_gate_d_decision_receipt_passes_on_current_repo() -> None:
    root = _repo_root()
    receipt = gate_d.build_gate_d_decision_receipt(root=root)

    assert receipt["status"] == "PASS"
    assert receipt["decision_mode"] == "POSTURE_SELECTION_ONLY_NO_IMPLEMENTATION"
    assert receipt["implementation_activation"]["b04_activation_allowed"] is False
    assert receipt["implementation_activation"]["separate_launch_surface_required"] is True
    assert receipt["next_lawful_move"] == "B04_GATE_D_CIVILIZATION_ACTIVATE__SEPARATE_LAUNCH_SURFACE_REQUIRED"

    selected = {row["domain_id"]: row["selected_posture"] for row in receipt["selected_postures"]}
    assert selected == gate_d.EXPECTED_SELECTIONS

    bindings = {row["domain_id"]: row for row in receipt["non_default_posture_bindings"]}
    assert sorted(bindings) == ["D2_NEW_COUNTED_DOMAINS", "D3_ADAPTIVE_EVOLUTION_AUTHORIZATION"]
    assert bindings["D2_NEW_COUNTED_DOMAINS"]["validator_chain"] == gate_d.EXPECTED_B04_VALIDATORS
    assert bindings["D2_NEW_COUNTED_DOMAINS"]["proof_required"] == gate_d.EXPECTED_B04_EMIT_ARTIFACTS
    assert "learned-router cutover and multi-lobe promotion remain blocked" in bindings["D3_ADAPTIVE_EVOLUTION_AUTHORIZATION"]["scope_boundary"].lower()


def test_gate_d_decision_receipt_cli_emits_receipt_with_explicit_output(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    receipt_path = tmp_path / "gate_d_decision_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.gate_d_decision_receipt_validate",
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
    assert payload["gate_d_posture_selection_status"] == "PASS"
    assert payload["next_lawful_move"] == "B04_GATE_D_CIVILIZATION_ACTIVATE__SEPARATE_LAUNCH_SURFACE_REQUIRED"

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_GATE_D_POSTURE_SELECTION_ARTIFACT_ONLY"
    assert receipt["implementation_activation"]["b04_activation_allowed"] is False
    assert receipt["implementation_activation"]["separate_launch_surface_required"] is True
