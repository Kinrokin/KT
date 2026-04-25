from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.operator import hold_state_surface_basis_validate as validate


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _repo_head() -> str:
    return subprocess.check_output(["git", "-C", str(_repo_root()), "rev-parse", "HEAD"], text=True).strip()


def _overlay(basis_head: str) -> dict:
    return {
        "repo_state": {"current_git_head": basis_head},
        "repo_state_executable_now": False,
        "next_counted_workstream_id": "B04_R6_LEARNED_ROUTER_AUTHORIZATION",
        "next_counted_workstream_scope": (
            "No later router-readiness reconsideration input may be prepared unless a future gate packet earns "
            "material_change_earned = true, and the single-path enforcement receipt must be freshly re-emitted and "
            "remain PASS on the actual candidate head. Static baseline stays canonical."
        ),
        "executable_now_why": (
            "Static baseline remains canonical and any future counted reopening requires a fresh same-head guard on the "
            "actual candidate head."
        ),
    }


def _next_contract() -> dict:
    return {
        "repo_state_executable_now": False,
        "exact_next_counted_workstream_id": "B04_R6_LEARNED_ROUTER_AUTHORIZATION",
        "workstream_objective": (
            "Counted lane stays closed. Static baseline remains canonical. Any future consumer must accept the input "
            "only after the single-path enforcement receipt is freshly re-emitted and PASS on the actual candidate head."
        ),
    }


def _resume(basis_head: str) -> dict:
    return {
        "current_git_head": basis_head,
        "why_not_executable_now": (
            "Static baseline remains canonical. Any future counted reopening requires a fresh same-head single-path "
            "enforcement receipt on the actual candidate head."
        ),
    }


def _reanchor(basis_head: str) -> dict:
    return {
        "current_repo_state": {"current_git_head": basis_head},
        "current_bounded_limitations": {
            "note": (
                "The standing single-path enforcement receipt is preserved as lab-only basis, and any future "
                "reconsideration attempt must re-emit that guard on the actual candidate head."
            )
        },
    }


def test_hold_state_basis_validation_receipt_passes_for_preseal_basis_split() -> None:
    receipt = validate.build_hold_state_surface_basis_validation_receipt(
        root=_repo_root(),
        actual_repo_head="ACTUAL_HEAD",
        overlay=_overlay("BASIS_HEAD"),
        next_workstream=_next_contract(),
        resume_blockers=_resume("BASIS_HEAD"),
        reanchor=_reanchor("BASIS_HEAD"),
        overlay_ref="overlay.json",
        next_workstream_ref="next.json",
        resume_blockers_ref="resume.json",
        reanchor_ref="reanchor.json",
    )

    assert receipt["status"] == "PASS"
    assert receipt["tracked_surface_basis_head"] == "BASIS_HEAD"
    assert receipt["actual_repo_head"] == "ACTUAL_HEAD"
    assert receipt["head_alignment_posture"] == "PRE_SEAL_HOLD_STATE_BASIS_CONFIRMED"


def test_hold_state_basis_validation_receipt_fails_when_basis_heads_disagree() -> None:
    receipt = validate.build_hold_state_surface_basis_validation_receipt(
        root=_repo_root(),
        actual_repo_head="ACTUAL_HEAD",
        overlay=_overlay("BASIS_HEAD_A"),
        next_workstream=_next_contract(),
        resume_blockers=_resume("BASIS_HEAD_B"),
        reanchor=_reanchor("BASIS_HEAD_A"),
        overlay_ref="overlay.json",
        next_workstream_ref="next.json",
        resume_blockers_ref="resume.json",
        reanchor_ref="reanchor.json",
    )

    assert receipt["status"] == "FAIL"
    failed = {item["check_id"] for item in receipt["checks"] if not item["pass"]}
    assert "tracked_hold_surfaces_share_single_basis_head" in failed


def test_hold_state_basis_validator_cli_emits_pass_receipt_on_real_surfaces(tmp_path: Path) -> None:
    receipt_path = tmp_path / "hold_state_basis_validation_receipt.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.hold_state_surface_basis_validate",
            "--output",
            str(receipt_path),
        ],
        cwd=str(_repo_root() / "KT_PROD_CLEANROOM"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["actual_repo_head"] == _repo_head()
    assert payload["tracked_surface_basis_head"] != payload["actual_repo_head"]
