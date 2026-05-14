from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


DEFAULT_SHARED_OUTPUTS = (
    "KT_PROD_CLEANROOM/reports/b04_r6_next_lawful_move_receipt.json",
    "KT_PROD_CLEANROOM/reports/b04_r6_pipeline_board.json",
    "KT_PROD_CLEANROOM/reports/kt_claim_ceiling_current_state.json",
    "KT_PROD_CLEANROOM/reports/kt_future_blocker_register.json",
)

KNOWN_LONG_TEST_PATHS = (
    "KT_PROD_CLEANROOM/tests/operator",
    "tests/operator",
)


def _is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(["git", "merge-base", "--is-ancestor", ancestor, descendant], cwd=root)
    return result.returncode == 0


def _bool_status(condition: bool) -> str:
    return "PASS" if condition else "FAIL"


def _check_branch(root: Path, *, expected_branch: str) -> dict[str, Any]:
    try:
        branch = common.git_current_branch_name(root)
        head = common.git_rev_parse(root, "HEAD")
    except subprocess.CalledProcessError as exc:
        return {
            "check": "branch_context",
            "status": "FAIL",
            "branch": "UNKNOWN_BRANCH",
            "head": "",
            "origin_main": "",
            "reason": f"unable to read local branch context: {exc}",
        }
    try:
        origin_main = common.git_rev_parse(root, "origin/main")
    except subprocess.CalledProcessError as exc:
        return {
            "check": "branch_context",
            "status": "FAIL",
            "branch": branch,
            "head": head,
            "origin_main": "",
            "reason": f"missing or unreadable origin/main: {exc}",
        }
    branch_ok = True
    reason = "branch accepted"
    if expected_branch and branch != expected_branch:
        branch_ok = False
        reason = f"expected {expected_branch!r}, got {branch!r}"
    if branch == "main" and head != origin_main:
        branch_ok = False
        reason = "main preflight requires HEAD to equal origin/main"
    if branch != "main" and not _is_ancestor(root, origin_main, head):
        branch_ok = False
        reason = "branch does not descend from origin/main"
    return {
        "check": "branch_context",
        "status": _bool_status(branch_ok),
        "branch": branch,
        "head": head,
        "origin_main": origin_main,
        "reason": reason,
    }


def _check_clean(root: Path) -> dict[str, Any]:
    status = common.git_status_porcelain(root).strip()
    return {
        "check": "worktree_clean",
        "status": _bool_status(not status),
        "dirty_paths": status.splitlines() if status else [],
    }


def _check_source_outputs(root: Path, sources: Sequence[str]) -> dict[str, Any]:
    missing = [raw for raw in sources if raw and not common.resolve_path(root, raw).is_file()]
    return {
        "check": "required_source_outputs_present",
        "status": _bool_status(not missing),
        "missing": missing,
    }


def _check_overwrites(root: Path, overwrites: Sequence[str]) -> dict[str, Any]:
    present = [raw for raw in overwrites if common.resolve_path(root, raw).exists()]
    return {
        "check": "pre_overwrite_binding_notice",
        "status": "PASS",
        "gating": "informational",
        "targets": list(overwrites),
        "shared_outputs": present,
        "requirement": "bind git object before generation when these shared files will be overwritten",
    }


def _test_plan_hint(test_paths: Sequence[str]) -> dict[str, Any]:
    long_paths = [
        raw
        for raw in test_paths
        if raw.replace("\\", "/").rstrip("/") in KNOWN_LONG_TEST_PATHS
    ]
    return {
        "check": "timeout_safe_test_plan",
        "status": "PASS",
        "known_long_paths": long_paths,
        "recommendation": (
            "run focused lane tests plus adjacent compiler/claim tests; shard broad operator suites"
            if long_paths
            else "focused suite is acceptable"
        ),
    }


def build_receipt(
    *,
    lane: str,
    expected_branch: str,
    source_outputs: Sequence[str],
    overwrites: Optional[Sequence[str]],
    test_paths: Sequence[str],
) -> dict[str, Any]:
    root = repo_root()
    overwrite_targets = DEFAULT_SHARED_OUTPUTS if overwrites is None else overwrites
    checks = [
        _check_branch(root, expected_branch=expected_branch),
        _check_clean(root),
        _check_source_outputs(root, source_outputs),
        _check_overwrites(root, overwrite_targets),
        _test_plan_hint(test_paths),
        {
            "check": "json_parser_mode",
            "status": "PASS",
            "recommendation": "use utf-8-sig for broad report JSON sweeps; strict parse changed JSON when needed",
        },
        {
            "check": "claim_token_scan_required",
            "status": "PASS",
            "scope": "recursive claim-bearing JSON strings, arrays, nested objects, and markdown reports",
        },
        {
            "check": "claim_scanner_field_classification",
            "status": "PASS",
            "requirement": "machine routing IDs are not human claim-bearing prose fields",
        },
        {
            "check": "reason_code_uniqueness_required",
            "status": "PASS",
            "requirement": "every lane validator must prove reason-code uniqueness",
        },
        {
            "check": "self_replay_expectations_declared",
            "status": "PASS",
            "requirement": "self-replay lanes must declare exact lane, predecessor outcome, and next-move expectations",
        },
        {
            "check": "shared_output_schema_preservation_required",
            "status": "PASS",
            "requirement": "shared canonical boards/registers must preserve canonical schema",
        },
        {
            "check": "review_threads_clean_before_merge",
            "status": "PASS",
            "gating": "external",
            "requirement": "query PR review threads before merge and resolve only after proof",
        },
        {
            "check": "head_fields_required",
            "status": "PASS",
            "requirement": "split current_git_head, current_branch_head, and current_main_head",
        },
    ]
    failures = [check for check in checks if check.get("status") != "PASS"]
    return {
        "schema_id": "kt.lane_preflight.receipt.v1",
        "artifact_id": "KT_LANE_PREFLIGHT_RECEIPT",
        "generated_utc": utc_now_iso_z(),
        "lane": lane,
        "status": "PASS" if not failures else "FAIL",
        "checks": checks,
        "failures": failures,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="KT lane preflight")
    parser.add_argument("--lane", required=True)
    parser.add_argument("--expected-branch", default="")
    parser.add_argument("--source-output", action="append", default=[])
    parser.add_argument("--overwrite", action="append", default=[])
    parser.add_argument("--no-default-overwrites", action="store_true")
    parser.add_argument("--test-path", action="append", default=[])
    args = parser.parse_args(argv)
    overwrites: Optional[Sequence[str]]
    if args.no_default_overwrites:
        overwrites = args.overwrite
    else:
        overwrites = args.overwrite or None
    receipt = build_receipt(
        lane=args.lane,
        expected_branch=args.expected_branch,
        source_outputs=args.source_output,
        overwrites=overwrites,
        test_paths=args.test_path,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
