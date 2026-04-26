from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tools.operator import router_shadow_evaluation_ratification_validate as r4
from tools.operator.wave2b_router_shadow_validate import build_wave2b_shadow_reports


OVERLAY_REFS = [
    "KT_PROD_CLEANROOM/governance/router_promotion_law.json",
    "KT_PROD_CLEANROOM/governance/b04_r4_router_shadow_evaluation_law_contract.json",
    "KT_PROD_CLEANROOM/governance/b04_r4_router_shadow_terminal_state.json",
    "KT_PROD_CLEANROOM/tools/operator/cohort0_router_shadow_state_binding_tranche.py",
    "KT_PROD_CLEANROOM/tools/operator/router_shadow_evaluation_ratification_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/wave2b_router_shadow_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b04_r4_router_shadow_evaluation_ratification_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_wave2b_router_shadow.py",
    "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json",
    "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json",
    "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json",
    "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"
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


def test_router_shadow_evaluation_ratification_receipt_passes_on_bound_clone(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    telemetry_path = tmp_path / "telemetry.jsonl"
    reports = build_wave2b_shadow_reports(root=root, telemetry_path=telemetry_path)
    receipt = r4.build_router_shadow_evaluation_ratification_receipt(
        root=root,
        selection_report=reports["selection_report"],
        matrix_report=reports["matrix_report"],
        health_report=reports["health_report"],
    )

    assert receipt["status"] == "PASS"
    assert receipt["workstream_id"] == "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"
    assert receipt["next_lawful_move"] == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
    assert receipt["static_router_summary"]["canonical_router_status"] == "STATIC_CANONICAL_BASELINE_ONLY"
    assert receipt["shadow_evaluation_summary"]["route_distribution_delta_count"] == 0
    assert receipt["router_cutover_summary"]["learned_router_cutover_allowed"] is False


def test_router_shadow_evaluation_ratification_cli_emits_receipt_with_explicit_output(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    selection_path = tmp_path / "selection.json"
    matrix_path = tmp_path / "matrix.json"
    health_path = tmp_path / "health.json"
    telemetry_path = tmp_path / "telemetry.jsonl"
    receipt_path = tmp_path / "router_shadow_evaluation_ratification_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.router_shadow_evaluation_ratification_validate",
            "--selection-output",
            str(selection_path),
            "--matrix-output",
            str(matrix_path),
            "--health-output",
            str(health_path),
            "--telemetry-output",
            str(telemetry_path),
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
    assert payload["router_shadow_evaluation_ratification_status"] == "PASS"
    assert payload["next_lawful_move"] == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_B04_R4_ROUTER_SHADOW_EVALUATION_ARTIFACT_ONLY"
    assert receipt["next_lawful_move"] == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
    assert json.loads(selection_path.read_text(encoding="utf-8"))["current_git_head"] == receipt["current_git_head"]
    assert json.loads(matrix_path.read_text(encoding="utf-8"))["current_git_head"] == receipt["current_git_head"]
    assert json.loads(health_path.read_text(encoding="utf-8"))["current_git_head"] == receipt["current_git_head"]
