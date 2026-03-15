from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.operator_greenline_validate import build_greenline_outputs_from_artifacts


def _baseline_report() -> dict:
    return {
        "allow_dirty": True,
        "blockers": [
            "STATUS_LANE_NOT_PASS",
            "LANE_NOT_OK:status",
            "LANE_NOT_OK:certify.ci_sim",
            "CANONICAL_HMAC_NOT_RUNNABLE_CLEAN",
        ],
        "grade": "D",
        "head": "old-head",
        "lanes": [
            {
                "lane": "status",
                "rc": 2,
                "run_dir": "baseline/status",
                "verdict": "KT_STATUS_FAIL_CLOSED cmd=status profile=v1 allow_dirty=1",
            },
            {
                "lane": "certify.ci_sim",
                "rc": 2,
                "run_dir": "baseline/ci_sim",
                "verdict": "KT_CERTIFY_FAIL_CLOSED cmd=certify profile=v1 allow_dirty=1",
            },
        ],
        "overall_status": "HOLD",
        "run_dir": "baseline/readiness",
        "score": 60,
        "worktree_clean": False,
    }


def _current_status_report(head: str) -> dict:
    return {
        "head": head,
        "profile": "v1",
        "schema_id": "kt.operator.status_report.unbound.v1",
        "status": "PASS",
    }


def _current_ci_sim_report(head: str) -> dict:
    return {
        "head": head,
        "lane": "ci_sim",
        "profile": "v1",
        "schema_id": "kt.operator.certify_report.unbound.v1",
        "status": "PASS",
    }


def _current_readiness_report(head: str) -> dict:
    return {
        "allow_dirty": False,
        "blockers": [],
        "grade": "A",
        "head": head,
        "lanes": [
            {
                "lane": "status",
                "rc": 0,
                "run_dir": "current/status",
                "verdict": "KT_STATUS_PASS cmd=status profile=v1 allow_dirty=0",
            },
            {
                "lane": "certify.ci_sim",
                "rc": 0,
                "run_dir": "current/ci_sim",
                "verdict": "KT_CERTIFY_PASS cmd=certify lane=ci_sim profile=v1 allow_dirty=0 meta_ci_sim=EXPECTED_FAIL",
            },
        ],
        "overall_status": "PASS",
        "run_dir": "current/readiness",
        "score": 100,
        "worktree_clean": True,
    }


def test_operator_greenline_validate_passes_for_cleared_baseline_blockers() -> None:
    head = "new-head"
    outputs = build_greenline_outputs_from_artifacts(
        baseline_report=_baseline_report(),
        current_status_report=_current_status_report(head),
        current_status_verdict="KT_STATUS_PASS cmd=status profile=v1 allow_dirty=0",
        current_ci_sim_report=_current_ci_sim_report(head),
        current_ci_sim_verdict="KT_CERTIFY_PASS cmd=certify lane=ci_sim profile=v1 allow_dirty=0 meta_ci_sim=EXPECTED_FAIL",
        current_readiness_report=_current_readiness_report(head),
        subject_head=head,
        changed_files=[
            "KT_PROD_CLEANROOM/tools/operator/kt_cli.py",
            "KT_PROD_CLEANROOM/tools/operator/operator_greenline_validate.py",
            "KT_PROD_CLEANROOM/tests/operator/test_operator_greenline_validate.py",
        ],
        prewrite_git_clean=True,
        baseline_readiness_ref="baseline.json",
        current_status_run_ref="status_run",
        current_ci_sim_run_ref="ci_run",
        current_readiness_ref="current.json",
    )

    assert outputs["repair_matrix"]["status"] == "PASS"
    assert outputs["repair_matrix"]["mismatch_count"] == 0
    assert outputs["post_repair_readiness"]["status"] == "PASS"
    assert outputs["post_repair_readiness"]["pass_verdict"] == "READINESS_GRADE_RECOVERED"
    assert outputs["receipt"]["status"] == "PASS"
    assert outputs["receipt"]["pass_verdict"] == "OPERATOR_FACTORY_GREENLINE_RECOVERED"
