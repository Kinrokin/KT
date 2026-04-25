from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tools.operator import router_ordered_proof_validate as ordered
from tools.operator import router_vs_best_adapter_proof_ratification_validate as r5


COPY_REFS = [
    "KT_PROD_CLEANROOM/governance/router_policy_registry.json",
    "KT_PROD_CLEANROOM/governance/b04_r5_router_vs_best_adapter_proof_contract.json",
    "KT_PROD_CLEANROOM/governance/b04_r5_router_vs_best_adapter_terminal_state.json",
    "KT_PROD_CLEANROOM/governance/b04_r5_fourth_same_head_rerun_terminal_state.json",
    "KT_PROD_CLEANROOM/tools/operator/cohort0_router_shadow_state_binding_tranche.py",
    "KT_PROD_CLEANROOM/tools/operator/router_ordered_proof_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/router_vs_best_adapter_proof_ratification_validate.py",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _clean_clone(tmp_path: Path) -> Path:
    root = _repo_root()
    clone_root = tmp_path / "repo"
    subprocess.run(["git", "clone", "--quiet", str(root), str(clone_root)], cwd=str(tmp_path), check=True)
    for ref in COPY_REFS:
        src = root / ref
        dst = clone_root / ref
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(clone_root / "KT_PROD_CLEANROOM") + os.pathsep + str(clone_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    subprocess.run(
        [sys.executable, "-m", "tools.operator.cohort0_router_shadow_state_binding_tranche"],
        cwd=str(clone_root / "KT_PROD_CLEANROOM"),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    return clone_root


def test_router_vs_best_adapter_proof_ratification_receipt_holds_honestly_on_bound_clone(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    base = ordered._build_base_reports(root=root)
    shadow_matrix = ordered.build_router_shadow_eval_matrix(root=root, base=base)
    health_report = ordered.build_route_distribution_health(root=root, base=base, shadow_matrix=shadow_matrix)
    scorecard = ordered.build_router_superiority_scorecard(root=root, base=base, health_report=health_report)
    ordered_receipt = ordered.build_router_ordered_proof_receipt(
        root=root,
        base=base,
        shadow_matrix=shadow_matrix,
        health_report=health_report,
        scorecard=scorecard,
    )

    receipt = r5.build_router_vs_best_adapter_proof_ratification_receipt(
        root=root,
        shadow_matrix=shadow_matrix,
        health_report=health_report,
        scorecard=scorecard,
        ordered_receipt=ordered_receipt,
    )

    assert receipt["status"] == "PASS"
    assert receipt["workstream_id"] == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
    assert receipt["router_proof_summary"]["router_superiority_earned"] is False
    assert receipt["router_proof_summary"]["exact_superiority_outcome"] == "NOT_EARNED_STATIC_BASELINE_RETAINS_CANONICAL_STATUS"
    assert receipt["next_lawful_move"] == "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"


def test_router_vs_best_adapter_proof_cli_emits_same_head_hold_receipt(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    shadow_matrix_path = tmp_path / "router_shadow_eval_matrix.json"
    health_path = tmp_path / "route_distribution_health.json"
    scorecard_path = tmp_path / "router_superiority_scorecard.json"
    ordered_proof_path = tmp_path / "router_ordered_proof_receipt.json"
    receipt_path = tmp_path / "router_vs_best_adapter_proof_ratification_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.router_vs_best_adapter_proof_ratification_validate",
            "--shadow-matrix-output",
            str(shadow_matrix_path),
            "--health-output",
            str(health_path),
            "--scorecard-output",
            str(scorecard_path),
            "--ordered-proof-output",
            str(ordered_proof_path),
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
    assert payload["router_superiority_earned"] is False
    assert payload["next_lawful_move"] == "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"

    shadow_matrix = json.loads(shadow_matrix_path.read_text(encoding="utf-8"))
    health = json.loads(health_path.read_text(encoding="utf-8"))
    scorecard = json.loads(scorecard_path.read_text(encoding="utf-8"))
    ordered_receipt = json.loads(ordered_proof_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    assert shadow_matrix["current_git_head"] == receipt["current_git_head"]
    assert shadow_matrix["subject_head"] == receipt["subject_head"]
    assert health["current_git_head"] == receipt["current_git_head"]
    assert scorecard["subject_head"] == receipt["subject_head"]
    assert ordered_receipt["subject_head"] == receipt["subject_head"]
    assert receipt["router_proof_summary"]["router_superiority_earned"] is False
    assert receipt["next_lawful_move"] == "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"


def test_r5_execution_context_recognizes_second_same_head_rerun_launch_surface() -> None:
    overlay = {
        "next_counted_workstream_id": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__SECOND_SAME_HEAD_RERUN",
        "current_lawful_gate_standing": {
            "current_counted_batch": "B04_R5_SECOND_SAME_HEAD_RERUN_LAUNCH_SURFACE",
        },
        "workstream_id": "B04_R5_SECOND_SAME_HEAD_RERUN_LAUNCH_SURFACE",
    }
    next_contract = {
        "source_workstream_id": "B04_R5_SECOND_SAME_HEAD_RERUN_LAUNCH_SURFACE",
        "exact_next_counted_workstream_id": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__SECOND_SAME_HEAD_RERUN",
        "execution_mode": "SECOND_R5_RERUN_AUTHORIZED_ONLY__R6_STILL_BLOCKED_UNTIL_EARNED_SUPERIORITY",
        "repo_state_executable_now": True,
    }
    resume = {
        "exact_next_counted_workstream_id": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__SECOND_SAME_HEAD_RERUN",
        "workstream_id": "B04_R5_SECOND_SAME_HEAD_RERUN_LAUNCH_SURFACE",
        "repo_state_executable_now": True,
    }
    reanchor = {
        "next_lawful_move": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__SECOND_SAME_HEAD_RERUN",
        "workstream_id": "B04_R5_SECOND_SAME_HEAD_RERUN_LAUNCH_SURFACE",
    }

    assert (
        r5._r5_execution_context(
            overlay=overlay,
            next_contract=next_contract,
            resume=resume,
            reanchor=reanchor,
        )
        == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__SECOND_SAME_HEAD_RERUN"
    )


def test_r5_execution_context_recognizes_third_same_head_rerun_launch_surface() -> None:
    overlay = {
        "next_counted_workstream_id": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__THIRD_SAME_HEAD_RERUN",
        "current_lawful_gate_standing": {
            "current_counted_batch": "B04_R5_THIRD_SAME_HEAD_RERUN_LAUNCH_SURFACE",
        },
        "workstream_id": "B04_R5_THIRD_SAME_HEAD_RERUN_LAUNCH_SURFACE",
    }
    next_contract = {
        "source_workstream_id": "B04_R5_THIRD_SAME_HEAD_RERUN_LAUNCH_SURFACE",
        "exact_next_counted_workstream_id": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__THIRD_SAME_HEAD_RERUN",
        "execution_mode": "THIRD_R5_RERUN_AUTHORIZED_ONLY__R6_STILL_BLOCKED_UNTIL_EARNED_SUPERIORITY",
        "repo_state_executable_now": True,
    }
    resume = {
        "exact_next_counted_workstream_id": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__THIRD_SAME_HEAD_RERUN",
        "workstream_id": "B04_R5_THIRD_SAME_HEAD_RERUN_LAUNCH_SURFACE",
        "repo_state_executable_now": True,
    }
    reanchor = {
        "next_lawful_move": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__THIRD_SAME_HEAD_RERUN",
        "workstream_id": "B04_R5_THIRD_SAME_HEAD_RERUN_LAUNCH_SURFACE",
    }

    assert (
        r5._r5_execution_context(
            overlay=overlay,
            next_contract=next_contract,
            resume=resume,
            reanchor=reanchor,
        )
        == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__THIRD_SAME_HEAD_RERUN"
    )


def test_r5_execution_context_recognizes_fourth_same_head_rerun_launch_surface() -> None:
    overlay = {
        "next_counted_workstream_id": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__FOURTH_SAME_HEAD_RERUN",
        "current_lawful_gate_standing": {
            "current_counted_batch": "B04_R5_FOURTH_SAME_HEAD_RERUN_LAUNCH_SURFACE",
        },
        "workstream_id": "B04_R5_FOURTH_SAME_HEAD_RERUN_LAUNCH_SURFACE",
    }
    next_contract = {
        "source_workstream_id": "B04_R5_FOURTH_SAME_HEAD_RERUN_LAUNCH_SURFACE",
        "exact_next_counted_workstream_id": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__FOURTH_SAME_HEAD_RERUN",
        "execution_mode": "FOURTH_R5_RERUN_AUTHORIZED_ONLY__R6_STILL_BLOCKED_UNTIL_EARNED_SUPERIORITY",
        "repo_state_executable_now": True,
    }
    resume = {
        "exact_next_counted_workstream_id": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__FOURTH_SAME_HEAD_RERUN",
        "workstream_id": "B04_R5_FOURTH_SAME_HEAD_RERUN_LAUNCH_SURFACE",
        "repo_state_executable_now": True,
    }
    reanchor = {
        "next_lawful_move": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__FOURTH_SAME_HEAD_RERUN",
        "workstream_id": "B04_R5_FOURTH_SAME_HEAD_RERUN_LAUNCH_SURFACE",
    }

    assert (
        r5._r5_execution_context(
            overlay=overlay,
            next_contract=next_contract,
            resume=resume,
            reanchor=reanchor,
        )
        == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__FOURTH_SAME_HEAD_RERUN"
    )
