from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


WORK_ORDER_ID = "WORK_ORDER_KT_FRONTIER_ELEVATION_AND_PUBLIC_DEFENSIBILITY"
WORK_ORDER_SCHEMA_ID = "kt.work_order.frontier_elevation_and_public_defensibility.v2"
WORKSTREAM_ID = "WS14_OPERATOR_FACTORY_GREENLINE_RECOVERY"
STEP_ID = "WS14_STEP_1_REPAIR_OPERATOR_GREENLINES"
PASS_VERDICT = "OPERATOR_FACTORY_GREENLINE_RECOVERED"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GREENLINE_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_operator_greenline_receipt.json"
REPAIR_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_ci_sim_repair_matrix.json"
POST_REPAIR_READINESS_REL = f"{REPORT_ROOT_REL}/kt_readiness_grade_post_repair.json"

WS13_EVIDENCE_HEAD = "23fdf42ef7be7f1e3663e3813e2b5b2fcf106a01"
BASELINE_READINESS_REPORT_REL = (
    "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/20260315T134212812305Z_readiness-grade/reports/readiness_grade.json"
)
DEFAULT_STATUS_RUN_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS14_status_final"
DEFAULT_CI_SIM_RUN_REL = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS14_ci_sim_final"
DEFAULT_CURRENT_READINESS_REPORT_REL = (
    "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS14_readiness_post_repair_final/reports/readiness_grade.json"
)

STATUS_REPORT_NAME = "status_report.json"
CERTIFY_REPORT_NAME = "certify_report.json"
VERDICT_NAME = "verdict.txt"

TARGETED_BLOCKERS = [
    "STATUS_LANE_NOT_PASS",
    "LANE_NOT_OK:status",
    "LANE_NOT_OK:certify.ci_sim",
    "CANONICAL_HMAC_NOT_RUNNABLE_CLEAN",
]
MINIMUM_POST_REPAIR_GRADE = "B+"
PROTECTED_PATTERNS = ("KT_ARCHIVE/**", "**/archive/**", "**/historical/**")
VOLATILE_JSON_KEYS = ("generated_utc", "timestamp")

VALIDATORS_RUN = [
    "python -m tools.operator.operator_greenline_validate",
    "python -m tools.operator.readiness_grade",
]
TESTS_RUN = [
    "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_operator_greenline_validate.py -q",
    "python -m pytest KT_PROD_CLEANROOM/tests/operator/test_status_lane.py KT_PROD_CLEANROOM/tests/operator/test_ci_sim_lane.py -q",
]

SUBJECT_TOUCH_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/kt_cli.py",
    "KT_PROD_CLEANROOM/tests/fl3/test_operator_cli.py",
    "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256",
    "KT_PROD_CLEANROOM/AUDITS/LAW_AMENDMENT_FL3_20260315T154138Z.json",
    "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_CHANGE_RECEIPT_FL3_20260315T154157Z.json",
    "KT_PROD_CLEANROOM/tests/fl3/test_fl3_receipts_no_secrets.py",
    "KT_PROD_CLEANROOM/tests/operator/test_truth_publication.py",
    "KT_PROD_CLEANROOM/governance/pin_registry.json",
    "KT_PROD_CLEANROOM/governance/governance_manifest.json",
    "KT_PROD_CLEANROOM/tools/operator/operator_greenline_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_operator_greenline_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_status_lane.py",
    "KT_PROD_CLEANROOM/tests/operator/test_ci_sim_lane.py",
]
GENERATED_ARTIFACT_REFS = [
    GREENLINE_RECEIPT_REL,
    REPAIR_MATRIX_REL,
    POST_REPAIR_READINESS_REL,
]
CREATED_FILES = [
    "KT_PROD_CLEANROOM/AUDITS/LAW_AMENDMENT_FL3_20260315T154138Z.json",
    "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_CHANGE_RECEIPT_FL3_20260315T154157Z.json",
    "KT_PROD_CLEANROOM/tools/operator/operator_greenline_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_operator_greenline_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_status_lane.py",
    "KT_PROD_CLEANROOM/tests/operator/test_ci_sim_lane.py",
    GREENLINE_RECEIPT_REL,
    REPAIR_MATRIX_REL,
    POST_REPAIR_READINESS_REL,
]
WORKSTREAM_FILES_TOUCHED = SUBJECT_TOUCH_REFS + GENERATED_ARTIFACT_REFS
SURFACE_CLASSIFICATIONS = {
    "KT_PROD_CLEANROOM/tools/operator/kt_cli.py": "canonical active file",
    "KT_PROD_CLEANROOM/tests/fl3/test_operator_cli.py": "validator/test file",
    "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256": "canonical active file",
    "KT_PROD_CLEANROOM/AUDITS/LAW_AMENDMENT_FL3_20260315T154138Z.json": "documentary evidence",
    "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_CHANGE_RECEIPT_FL3_20260315T154157Z.json": "documentary evidence",
    "KT_PROD_CLEANROOM/tests/fl3/test_fl3_receipts_no_secrets.py": "validator/test file",
    "KT_PROD_CLEANROOM/tests/operator/test_truth_publication.py": "validator/test file",
    "KT_PROD_CLEANROOM/governance/pin_registry.json": "canonical active file",
    "KT_PROD_CLEANROOM/governance/governance_manifest.json": "canonical active file",
    "KT_PROD_CLEANROOM/tools/operator/operator_greenline_validate.py": "canonical active file",
    "KT_PROD_CLEANROOM/tests/operator/test_operator_greenline_validate.py": "validator/test file",
    "KT_PROD_CLEANROOM/tests/operator/test_status_lane.py": "validator/test file",
    "KT_PROD_CLEANROOM/tests/operator/test_ci_sim_lane.py": "validator/test file",
    GREENLINE_RECEIPT_REL: "generated artifact",
    REPAIR_MATRIX_REL: "generated artifact",
    POST_REPAIR_READINESS_REL: "generated artifact",
}

GRADE_ORDER = {
    "A+": 8,
    "A": 7,
    "A-": 6,
    "B+": 5,
    "B": 4,
    "B-": 3,
    "C+": 2,
    "C": 1,
    "C-": 0,
    "D": -1,
    "F": -2,
}


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_porcelain(root: Path) -> List[str]:
    output = subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain=v1"],
        text=True,
        encoding="utf-8",
    )
    return [line.rstrip() for line in output.splitlines() if line.strip()]


def _git_changed_since(root: Path, base_ref: str) -> List[str]:
    output = _git(root, "diff", "--name-only", f"{base_ref}..HEAD")
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _load_required_text(root: Path, rel: str) -> str:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required text artifact: {rel}")
    return path.read_text(encoding="utf-8").strip()


def _lane_entry(report: Dict[str, Any], lane_name: str) -> Dict[str, Any]:
    lanes = report.get("lanes")
    if not isinstance(lanes, list):
        raise RuntimeError("FAIL_CLOSED: readiness report missing lanes")
    for lane in lanes:
        if isinstance(lane, dict) and str(lane.get("lane", "")).strip() == lane_name:
            return lane
    raise RuntimeError(f"FAIL_CLOSED: readiness report missing lane={lane_name}")


def _grade_at_least(current: str, minimum: str) -> bool:
    return GRADE_ORDER.get(str(current).strip().upper(), -99) >= GRADE_ORDER.get(str(minimum).strip().upper(), -99)


def _is_protected(path: str) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in PROTECTED_PATTERNS)


def build_lane_delta_row(
    *,
    row_id: str,
    lane_name: str,
    baseline_lane: Dict[str, Any],
    current_lane: Dict[str, Any],
    current_direct_report: Dict[str, Any],
    current_direct_verdict: str,
    current_direct_run_ref: str,
    expected_verdict_prefix: str,
    required_verdict_fragments: Sequence[str] = (),
) -> Dict[str, Any]:
    verdict_ok = str(current_direct_verdict).startswith(expected_verdict_prefix)
    fragments_ok = all(fragment in str(current_direct_verdict) for fragment in required_verdict_fragments)
    report_status_ok = str(current_direct_report.get("status", "")).strip() == "PASS"
    current_lane_rc_ok = int(current_lane.get("rc", 1)) == 0
    current_lane_verdict_ok = str(current_lane.get("verdict", "")).startswith(expected_verdict_prefix)
    baseline_failed = int(baseline_lane.get("rc", 0)) != 0

    checks = {
        "baseline_failed": baseline_failed,
        "current_direct_verdict_pass": verdict_ok,
        "current_direct_required_fragments_present": fragments_ok,
        "current_direct_report_status_pass": report_status_ok,
        "current_readiness_lane_rc_zero": current_lane_rc_ok,
        "current_readiness_lane_verdict_pass": current_lane_verdict_ok,
    }
    mismatch_count = len([name for name, ok in checks.items() if not ok])
    return {
        "row_id": row_id,
        "lane": lane_name,
        "environment_metadata": {
            "baseline_run_dir": baseline_lane.get("run_dir", ""),
            "current_run_dir": current_direct_run_ref,
        },
        "expected_result": {
            "baseline_rc_nonzero": True,
            "current_direct_report_status": "PASS",
            "current_direct_verdict_prefix": expected_verdict_prefix,
            "current_readiness_lane_rc": 0,
        },
        "actual_result": {
            "baseline_rc": int(baseline_lane.get("rc", 0)),
            "baseline_verdict": str(baseline_lane.get("verdict", "")),
            "current_direct_report_status": str(current_direct_report.get("status", "")),
            "current_direct_verdict": str(current_direct_verdict),
            "current_readiness_lane_rc": int(current_lane.get("rc", 0)),
            "current_readiness_lane_verdict": str(current_lane.get("verdict", "")),
        },
        "mismatch_count": mismatch_count,
        "resolution_or_blocker": "cleared" if mismatch_count == 0 else "lane remains unrecovered",
        "checks": checks,
    }


def _build_common_fields(*, subject_head: str, status: str, pass_verdict: str) -> Dict[str, Any]:
    return {
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": subject_head,
        "compiled_head_commit": subject_head,
        "evidence_head_commit": subject_head,
        "status": status,
        "pass_verdict": pass_verdict,
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": list(VALIDATORS_RUN),
        "tests_run": list(TESTS_RUN),
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "workstream_id": WORKSTREAM_ID,
        "created_files": list(CREATED_FILES),
        "deleted_files": [],
        "retained_new_files": list(CREATED_FILES),
        "temporary_files_removed": [],
        "superseded_files_removed_or_demoted": [],
        "waste_control": {
            "created_files_count": len(CREATED_FILES),
            "deleted_files_count": 0,
            "temporary_files_removed_count": 0,
            "superseded_files_removed_count": 0,
            "net_artifact_delta": len(CREATED_FILES),
            "retention_justifications": [
                {
                    "path": BASELINE_READINESS_REPORT_REL,
                    "reason": "retained as documentary historical baseline for the WS14 repair delta",
                },
                {
                    "path": "KT_PROD_CLEANROOM/AUDITS/LAW_AMENDMENT_FL3_20260315T154138Z.json",
                    "reason": "retained as documentary evidence for the refreshed law bundle pinset",
                },
                {
                    "path": "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_CHANGE_RECEIPT_FL3_20260315T154157Z.json",
                    "reason": "retained as documentary evidence for the WS14 law bundle change",
                },
                {
                    "path": "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS14_*",
                    "reason": "retained under the approved operator run root as validator evidence, not as canonical active files",
                },
            ],
        },
        "surface_classifications": dict(SURFACE_CLASSIFICATIONS),
    }


def build_greenline_outputs_from_artifacts(
    *,
    baseline_report: Dict[str, Any],
    current_status_report: Dict[str, Any],
    current_status_verdict: str,
    current_ci_sim_report: Dict[str, Any],
    current_ci_sim_verdict: str,
    current_readiness_report: Dict[str, Any],
    subject_head: str,
    changed_files: Sequence[str],
    prewrite_git_clean: bool,
    baseline_readiness_ref: str,
    current_status_run_ref: str,
    current_ci_sim_run_ref: str,
    current_readiness_ref: str,
) -> Dict[str, Dict[str, Any]]:
    baseline_status_lane = _lane_entry(baseline_report, "status")
    baseline_ci_sim_lane = _lane_entry(baseline_report, "certify.ci_sim")
    current_status_lane = _lane_entry(current_readiness_report, "status")
    current_ci_sim_lane = _lane_entry(current_readiness_report, "certify.ci_sim")

    current_blockers = [str(item) for item in current_readiness_report.get("blockers", [])]
    baseline_blockers = [str(item) for item in baseline_report.get("blockers", [])]

    unexpected = sorted(path for path in changed_files if path not in WORKSTREAM_FILES_TOUCHED)
    protected = sorted(path for path in changed_files if _is_protected(path))
    if unexpected or protected:
        raise RuntimeError(
            "FAIL_CLOSED: unexpected subject touches detected: "
            + ", ".join(unexpected + protected)
        )

    heads = {
        str(current_status_report.get("head", "")).strip(),
        str(current_ci_sim_report.get("head", "")).strip(),
        str(current_readiness_report.get("head", "")).strip(),
    }
    if heads != {subject_head}:
        raise RuntimeError("FAIL_CLOSED: current WS14 run heads do not converge on the subject head")

    status_row = build_lane_delta_row(
        row_id="lane.status",
        lane_name="status",
        baseline_lane=baseline_status_lane,
        current_lane=current_status_lane,
        current_direct_report=current_status_report,
        current_direct_verdict=current_status_verdict,
        current_direct_run_ref=current_status_run_ref,
        expected_verdict_prefix="KT_STATUS_PASS",
    )
    ci_sim_row = build_lane_delta_row(
        row_id="lane.ci_sim",
        lane_name="certify.ci_sim",
        baseline_lane=baseline_ci_sim_lane,
        current_lane=current_ci_sim_lane,
        current_direct_report=current_ci_sim_report,
        current_direct_verdict=current_ci_sim_verdict,
        current_direct_run_ref=current_ci_sim_run_ref,
        expected_verdict_prefix="KT_CERTIFY_PASS",
        required_verdict_fragments=("meta_ci_sim=EXPECTED_FAIL",),
    )

    targeted_blocker_rows: List[Dict[str, Any]] = []
    for blocker in TARGETED_BLOCKERS:
        baseline_present = blocker in baseline_blockers
        current_present = blocker in current_blockers
        mismatch_count = 0 if baseline_present and not current_present else 1
        targeted_blocker_rows.append(
            {
                "row_id": f"blocker.{blocker}",
                "environment_metadata": {
                    "baseline_head": baseline_report.get("head", ""),
                    "current_head": current_readiness_report.get("head", ""),
                },
                "expected_result": {
                    "baseline_present": True,
                    "current_present": False,
                },
                "actual_result": {
                    "baseline_present": baseline_present,
                    "current_present": current_present,
                },
                "mismatch_count": mismatch_count,
                "resolution_or_blocker": "cleared" if mismatch_count == 0 else "targeted blocker still active",
            }
        )

    baseline_score = int(baseline_report.get("score", 0))
    current_score = int(current_readiness_report.get("score", 0))
    current_grade = str(current_readiness_report.get("grade", "")).strip()
    current_status = str(current_readiness_report.get("overall_status", "")).strip()
    grade_floor_met = _grade_at_least(current_grade, MINIMUM_POST_REPAIR_GRADE)
    readiness_row = {
        "row_id": "readiness.overall",
        "environment_metadata": {
            "baseline_run_dir": baseline_report.get("run_dir", ""),
            "current_run_dir": current_readiness_report.get("run_dir", ""),
        },
        "expected_result": {
            "overall_status": "PASS",
            "minimum_grade": MINIMUM_POST_REPAIR_GRADE,
            "blockers": [],
            "worktree_clean": True,
        },
        "actual_result": {
            "baseline_status": baseline_report.get("overall_status", ""),
            "baseline_grade": baseline_report.get("grade", ""),
            "baseline_score": baseline_score,
            "current_status": current_status,
            "current_grade": current_grade,
            "current_score": current_score,
            "delta_score": current_score - baseline_score,
            "current_blockers": current_blockers,
            "worktree_clean": bool(current_readiness_report.get("worktree_clean")),
        },
        "mismatch_count": len(
            [
                name
                for name, ok in {
                    "overall_status_pass": current_status == "PASS",
                    "grade_floor_met": grade_floor_met,
                    "blockers_cleared": not current_blockers,
                    "worktree_clean": bool(current_readiness_report.get("worktree_clean")),
                }.items()
                if not ok
            ]
        ),
        "resolution_or_blocker": (
            "cleared"
            if current_status == "PASS" and grade_floor_met and not current_blockers and bool(current_readiness_report.get("worktree_clean"))
            else "readiness grade still held"
        ),
    }

    rows = [status_row, ci_sim_row, *targeted_blocker_rows, readiness_row]
    mismatch_count = sum(int(row.get("mismatch_count", 0)) for row in rows)
    matrix_status = "PASS" if mismatch_count == 0 else "BLOCKED"
    targeted_blockers_cleared = [blocker for blocker in TARGETED_BLOCKERS if blocker in baseline_blockers and blocker not in current_blockers]
    targeted_blockers_remaining = [blocker for blocker in TARGETED_BLOCKERS if blocker in current_blockers]

    repair_matrix = _build_common_fields(
        subject_head=subject_head,
        status=matrix_status,
        pass_verdict="CI_SIM_REPAIR_MATRIX_COMPLETE" if matrix_status == "PASS" else "CI_SIM_REPAIR_MATRIX_BLOCKED",
    )
    repair_matrix.update(
        {
            "schema_id": "kt.operator.ci_sim_repair_matrix.v1",
            "artifact_id": Path(REPAIR_MATRIX_REL).name,
            "input_refs": [
                baseline_readiness_ref,
                f"{current_status_run_ref}/{STATUS_REPORT_NAME}",
                f"{current_status_run_ref}/{VERDICT_NAME}",
                f"{current_ci_sim_run_ref}/{CERTIFY_REPORT_NAME}",
                f"{current_ci_sim_run_ref}/{VERDICT_NAME}",
                current_readiness_ref,
            ],
            "next_lawful_step": {
                "status_after_workstream": "UNLOCKED" if matrix_status == "PASS" else "BLOCKED",
                "workstream_id": "WS15_DELIVERY_INTEGRITY_RESTORATION",
            },
            "rows": rows,
            "environment_metadata": {
                "baseline_head": baseline_report.get("head", ""),
                "current_head": subject_head,
                "baseline_allow_dirty": baseline_report.get("allow_dirty"),
                "current_allow_dirty": current_readiness_report.get("allow_dirty"),
            },
            "expected_result": {
                "status_lane_pass": True,
                "ci_sim_lane_pass": True,
                "targeted_blockers_cleared": list(TARGETED_BLOCKERS),
                "minimum_post_repair_grade": MINIMUM_POST_REPAIR_GRADE,
            },
            "actual_result": {
                "baseline_grade": baseline_report.get("grade", ""),
                "baseline_score": baseline_score,
                "current_grade": current_grade,
                "current_score": current_score,
                "delta_score": current_score - baseline_score,
                "targeted_blockers_cleared": targeted_blockers_cleared,
                "targeted_blockers_remaining": targeted_blockers_remaining,
            },
            "mismatch_count": mismatch_count,
            "resolution_or_blocker": (
                "targeted operator greenline defect classes are cleared"
                if matrix_status == "PASS"
                else "one or more targeted greenline defect classes remain unresolved"
            ),
        }
    )

    readiness_status = (
        "PASS"
        if current_status == "PASS"
        and grade_floor_met
        and not current_blockers
        and status_row["mismatch_count"] == 0
        and ci_sim_row["mismatch_count"] == 0
        else "BLOCKED"
    )
    post_repair_readiness = _build_common_fields(
        subject_head=subject_head,
        status=readiness_status,
        pass_verdict="READINESS_GRADE_RECOVERED" if readiness_status == "PASS" else "READINESS_GRADE_STILL_HELD",
    )
    post_repair_readiness.update(
        {
            "schema_id": "kt.operator.readiness_grade_post_repair.v1",
            "artifact_id": Path(POST_REPAIR_READINESS_REL).name,
            "input_refs": [
                baseline_readiness_ref,
                current_readiness_ref,
                f"{current_status_run_ref}/{STATUS_REPORT_NAME}",
                f"{current_ci_sim_run_ref}/{CERTIFY_REPORT_NAME}",
            ],
            "next_lawful_step": {
                "status_after_workstream": "UNLOCKED" if readiness_status == "PASS" else "BLOCKED",
                "workstream_id": "WS15_DELIVERY_INTEGRITY_RESTORATION",
            },
            "baseline_readiness_ref": baseline_readiness_ref,
            "current_readiness_ref": current_readiness_ref,
            "summary": {
                "baseline_overall_status": baseline_report.get("overall_status", ""),
                "baseline_grade": baseline_report.get("grade", ""),
                "baseline_score": baseline_score,
                "current_overall_status": current_status,
                "current_grade": current_grade,
                "current_score": current_score,
                "delta_score": current_score - baseline_score,
                "grade_floor_met": grade_floor_met,
                "targeted_blockers_cleared_count": len(targeted_blockers_cleared),
                "targeted_blockers_remaining_count": len(targeted_blockers_remaining),
            },
            "lane_health": {
                "status": {
                    "direct_run_ref": current_status_run_ref,
                    "report_status": current_status_report.get("status", ""),
                    "verdict": current_status_verdict,
                },
                "certify.ci_sim": {
                    "direct_run_ref": current_ci_sim_run_ref,
                    "report_status": current_ci_sim_report.get("status", ""),
                    "verdict": current_ci_sim_verdict,
                },
            },
            "targeted_blockers_cleared": targeted_blockers_cleared,
            "targeted_blockers_remaining": targeted_blockers_remaining,
        }
    )

    receipt_checks = [
        {
            "check": "prewrite_git_status_clean",
            "status": "PASS" if prewrite_git_clean else "FAIL",
            "refs": [current_readiness_ref],
        },
        {
            "check": "workstream_touches_remain_in_scope",
            "status": "PASS" if not unexpected and not protected else "FAIL",
            "refs": list(WORKSTREAM_FILES_TOUCHED),
        },
        {
            "check": "status_lane_recovers",
            "status": "PASS" if status_row["mismatch_count"] == 0 else "FAIL",
            "refs": [f"{current_status_run_ref}/{STATUS_REPORT_NAME}", f"{current_status_run_ref}/{VERDICT_NAME}"],
        },
        {
            "check": "ci_sim_lane_recovers",
            "status": "PASS" if ci_sim_row["mismatch_count"] == 0 else "FAIL",
            "refs": [f"{current_ci_sim_run_ref}/{CERTIFY_REPORT_NAME}", f"{current_ci_sim_run_ref}/{VERDICT_NAME}"],
        },
        {
            "check": "targeted_blockers_cleared",
            "status": "PASS" if not targeted_blockers_remaining and len(targeted_blockers_cleared) == len(TARGETED_BLOCKERS) else "FAIL",
            "refs": [baseline_readiness_ref, current_readiness_ref, REPAIR_MATRIX_REL],
        },
        {
            "check": "post_repair_readiness_meets_floor",
            "status": "PASS" if readiness_status == "PASS" else "FAIL",
            "refs": [current_readiness_ref, POST_REPAIR_READINESS_REL],
        },
    ]
    receipt_status = "PASS" if all(row["status"] == "PASS" for row in receipt_checks) else "BLOCKED"
    receipt = _build_common_fields(
        subject_head=subject_head,
        status=receipt_status,
        pass_verdict=PASS_VERDICT if receipt_status == "PASS" else "OPERATOR_FACTORY_GREENLINE_BLOCKED",
    )
    receipt.update(
        {
            "schema_id": "kt.operator.operator_greenline_receipt.v1",
            "artifact_id": Path(GREENLINE_RECEIPT_REL).name,
            "input_refs": [
                baseline_readiness_ref,
                current_readiness_ref,
                f"{current_status_run_ref}/{STATUS_REPORT_NAME}",
                f"{current_status_run_ref}/{VERDICT_NAME}",
                f"{current_ci_sim_run_ref}/{CERTIFY_REPORT_NAME}",
                f"{current_ci_sim_run_ref}/{VERDICT_NAME}",
                *SUBJECT_TOUCH_REFS,
            ],
            "next_lawful_step": {
                "status_after_workstream": "UNLOCKED" if receipt_status == "PASS" else "BLOCKED",
                "workstream_id": "WS15_DELIVERY_INTEGRITY_RESTORATION",
            },
            "baseline_readiness_ref": baseline_readiness_ref,
            "current_status_run_ref": current_status_run_ref,
            "current_ci_sim_run_ref": current_ci_sim_run_ref,
            "current_readiness_ref": current_readiness_ref,
            "checks": receipt_checks,
            "summary": {
                "baseline_grade": baseline_report.get("grade", ""),
                "baseline_score": baseline_score,
                "current_grade": current_grade,
                "current_score": current_score,
                "delta_score": current_score - baseline_score,
                "targeted_blockers_cleared": targeted_blockers_cleared,
                "targeted_blockers_remaining": targeted_blockers_remaining,
            },
            "step_report": {
                "timestamp": utc_now_iso_z(),
                "workstream_id": WORKSTREAM_ID,
                "step_id": STEP_ID,
                "actions_taken": [
                    "repaired the operator CLI bootstrap so status and ci_sim no longer depend on external PYTHONPATH",
                    "refreshed the law bundle pinset and generated the canonical law change evidence",
                    "repaired ci_sim validation and hashpin drift, then reran status, ci_sim, and readiness on a clean subject head",
                ],
                "files_touched": list(WORKSTREAM_FILES_TOUCHED),
                "tests_run": list(TESTS_RUN),
                "validators_run": list(VALIDATORS_RUN),
                "issues_found": list(TARGETED_BLOCKERS),
                "resolution": (
                    "WS14 clears the red status and ci_sim defect classes and raises the live readiness grade above the B+ floor."
                    if receipt_status == "PASS"
                    else "WS14 remains blocked until the targeted operator greenline defects and readiness floor are all cleared."
                ),
                "pass_fail_status": receipt_status,
                "unexpected_touches": [],
                "protected_touch_violations": [],
            },
        }
    )

    return {
        "repair_matrix": repair_matrix,
        "post_repair_readiness": post_repair_readiness,
        "receipt": receipt,
    }


def build_ws14_outputs(
    root: Path,
    *,
    baseline_readiness_rel: str = BASELINE_READINESS_REPORT_REL,
    current_status_run_rel: str = DEFAULT_STATUS_RUN_REL,
    current_ci_sim_run_rel: str = DEFAULT_CI_SIM_RUN_REL,
    current_readiness_rel: str = DEFAULT_CURRENT_READINESS_REPORT_REL,
    subject_head_override: Optional[str] = None,
    changed_files_override: Optional[Sequence[str]] = None,
    prewrite_git_clean_override: Optional[bool] = None,
) -> Dict[str, Dict[str, Any]]:
    baseline_report = _load_required_json(root, baseline_readiness_rel)
    current_status_report = _load_required_json(root, f"{current_status_run_rel}/{STATUS_REPORT_NAME}")
    current_status_verdict = _load_required_text(root, f"{current_status_run_rel}/{VERDICT_NAME}")
    current_ci_sim_report = _load_required_json(root, f"{current_ci_sim_run_rel}/{CERTIFY_REPORT_NAME}")
    current_ci_sim_verdict = _load_required_text(root, f"{current_ci_sim_run_rel}/{VERDICT_NAME}")
    current_readiness_report = _load_required_json(root, current_readiness_rel)

    subject_head = subject_head_override or _git_head(root)
    changed_files = list(changed_files_override) if changed_files_override is not None else _git_changed_since(root, WS13_EVIDENCE_HEAD)
    prewrite_git_clean = (
        bool(prewrite_git_clean_override)
        if prewrite_git_clean_override is not None
        else not _git_status_porcelain(root)
    )

    return build_greenline_outputs_from_artifacts(
        baseline_report=baseline_report,
        current_status_report=current_status_report,
        current_status_verdict=current_status_verdict,
        current_ci_sim_report=current_ci_sim_report,
        current_ci_sim_verdict=current_ci_sim_verdict,
        current_readiness_report=current_readiness_report,
        subject_head=subject_head,
        changed_files=changed_files,
        prewrite_git_clean=prewrite_git_clean,
        baseline_readiness_ref=baseline_readiness_rel,
        current_status_run_ref=current_status_run_rel,
        current_ci_sim_run_ref=current_ci_sim_run_rel,
        current_readiness_ref=current_readiness_rel,
    )


def _write_outputs(
    root: Path,
    *,
    baseline_readiness_rel: str,
    current_status_run_rel: str,
    current_ci_sim_run_rel: str,
    current_readiness_rel: str,
) -> List[str]:
    outputs = build_ws14_outputs(
        root,
        baseline_readiness_rel=baseline_readiness_rel,
        current_status_run_rel=current_status_run_rel,
        current_ci_sim_run_rel=current_ci_sim_run_rel,
        current_readiness_rel=current_readiness_rel,
    )
    changed: List[str] = []
    mapping = {
        REPAIR_MATRIX_REL: outputs["repair_matrix"],
        POST_REPAIR_READINESS_REL: outputs["post_repair_readiness"],
        GREENLINE_RECEIPT_REL: outputs["receipt"],
    }
    for rel, payload in mapping.items():
        if write_json_stable((root / Path(rel)).resolve(), payload, volatile_keys=VOLATILE_JSON_KEYS):
            changed.append(rel)
    return changed


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate WS14 operator greenline recovery and emit sealed reports.")
    parser.add_argument("--baseline-readiness-report", default=BASELINE_READINESS_REPORT_REL)
    parser.add_argument("--status-run-dir", default=DEFAULT_STATUS_RUN_REL)
    parser.add_argument("--ci-sim-run-dir", default=DEFAULT_CI_SIM_RUN_REL)
    parser.add_argument("--current-readiness-report", default=DEFAULT_CURRENT_READINESS_REPORT_REL)
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    changed = _write_outputs(
        root,
        baseline_readiness_rel=str(args.baseline_readiness_report),
        current_status_run_rel=str(args.status_run_dir),
        current_ci_sim_run_rel=str(args.ci_sim_run_dir),
        current_readiness_rel=str(args.current_readiness_report),
    )
    receipt = load_json((root / Path(GREENLINE_RECEIPT_REL)).resolve())
    print(
        json.dumps(
            {
                "artifact_id": receipt["artifact_id"],
                "status": receipt["status"],
                "pass_verdict": receipt["pass_verdict"],
                "subject_head_commit": receipt["subject_head_commit"],
                "evidence_head_commit": receipt["evidence_head_commit"],
                "unexpected_touches": receipt["unexpected_touches"],
                "protected_touch_violations": receipt["protected_touch_violations"],
                "changed": sorted(changed),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
