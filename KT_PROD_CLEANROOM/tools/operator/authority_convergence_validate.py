from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import make_run_dir, repo_root, utc_now_iso_z, write_failure_artifacts, write_json_worm
from tools.operator.truth_authority import CURRENT_POINTER_REL


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPECTED_POINTER_REF = CURRENT_POINTER_REL


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return json.loads(path.read_text(encoding="utf-8"))


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _head_from(payload: Dict[str, Any]) -> str:
    if "validated_head_sha" in payload:
        return str(payload.get("validated_head_sha", "")).strip()
    if "pinned_head_sha" in payload:
        return str(payload.get("pinned_head_sha", "")).strip()
    if "truth_subject_commit" in payload:
        return str(payload.get("truth_subject_commit", "")).strip()
    worktree = payload.get("worktree")
    if isinstance(worktree, dict):
        return str(worktree.get("head_sha", "")).strip()
    return ""


def _status_from(payload: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(payload.get(key, "")).strip()
        if value:
            return value
    return ""


def _nested_verdict_head(payload: Dict[str, Any]) -> str:
    production = payload.get("production_run")
    if not isinstance(production, dict):
        return ""
    explicit = str(production.get("nested_verdict_head_sha", "")).strip()
    if explicit:
        return explicit
    verdict = str(production.get("nested_verdict", "")).strip()
    match = re.search(r"\bhead=([0-9a-f]{7,64})\b", verdict)
    return str(match.group(1)).strip() if match else ""


def build_authority_convergence_report(*, root: Path) -> Dict[str, Any]:
    report_root = (root / DEFAULT_REPORT_ROOT_REL).resolve()
    board = _load_json(root / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json")
    readiness = _load_json(root / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json")
    current_pointer = _load_json(root / CURRENT_POINTER_REL)
    current_state = _load_json(report_root / "current_state_receipt.json")
    runtime_audit = _load_json(report_root / "runtime_closure_audit.json")
    settled_truth = _load_json(report_root / "settled_truth_source_receipt.json")
    live_index = _load_json(report_root / "live_validation_index.json")
    preflight = _load_json(report_root / "one_button_preflight_receipt.json")
    production = _load_json(report_root / "one_button_production_receipt.json")

    try:
        git_head = _git(root, "rev-parse", "HEAD")
    except Exception:  # noqa: BLE001
        git_head = _head_from(live_index)
    try:
        git_branch = _git(root, "rev-parse", "--abbrev-ref", "HEAD")
    except Exception:  # noqa: BLE001
        git_branch = str(live_index.get("branch_ref", "")).strip()

    observed = {
        "git_head": git_head,
        "git_branch": git_branch,
        "live_validation_head": _head_from(live_index),
        "board_head": str(board.get("last_synced_head_sha", "")).strip(),
        "pointer_head": _head_from(current_pointer),
        "current_state_head": _head_from(current_state),
        "runtime_audit_head": _head_from(runtime_audit),
        "settled_truth_head": _head_from(settled_truth),
        "preflight_head": _head_from(preflight),
        "production_head": _head_from(production),
        "production_nested_verdict_head": _nested_verdict_head(production),
        "board_truth_source": str(board.get("authoritative_current_head_truth_source", "")).strip(),
        "readiness_truth_source": str(readiness.get("authoritative_truth_source", "")).strip(),
        "board_authority_mode": str(board.get("authority_mode", "")).strip(),
        "settled_authority_mode": str(settled_truth.get("status", "")).strip(),
        "board_posture_state": _status_from(board, "current_posture_state"),
        "pointer_posture_state": _status_from(current_pointer, "posture_enum"),
        "current_state_posture_state": _status_from(current_state, "posture_state", "current_p0_state"),
        "runtime_audit_posture_state": _status_from(runtime_audit, "posture_state", "current_state"),
        "settled_truth_posture_state": _status_from(settled_truth, "derived_posture_state"),
        "preflight_status": _status_from(preflight, "status"),
        "production_status": _status_from(production, "status"),
        "preflight_head_lineage_match": bool(preflight.get("head_lineage_match")),
        "production_head_lineage_match": bool((production.get("production_run") or {}).get("head_lineage_match")),
        "worktree_dirty": bool((live_index.get("worktree") or {}).get("git_dirty")),
    }

    failures: List[str] = []
    checks: List[Dict[str, Any]] = []

    def expect_equal(check_id: str, actual: str, expected: str) -> None:
        ok = bool(actual) and actual == expected
        checks.append({"check": check_id, "actual": actual, "expected": expected, "status": "PASS" if ok else "FAIL"})
        if not ok:
            failures.append(check_id)

    def expect_true(check_id: str, actual: bool) -> None:
        checks.append({"check": check_id, "actual": bool(actual), "status": "PASS" if actual else "FAIL"})
        if not actual:
            failures.append(check_id)

    expect_equal("live_validation_matches_git_head", observed["live_validation_head"], git_head)
    expect_equal("execution_board_matches_git_head", observed["board_head"], git_head)
    expect_equal("current_pointer_matches_git_head", observed["pointer_head"], git_head)
    expect_equal("current_state_receipt_matches_git_head", observed["current_state_head"], git_head)
    expect_equal("runtime_closure_audit_matches_git_head", observed["runtime_audit_head"], git_head)
    expect_equal("settled_truth_source_matches_git_head", observed["settled_truth_head"], git_head)
    expect_equal("one_button_preflight_matches_git_head", observed["preflight_head"], git_head)
    expect_equal("one_button_production_matches_git_head", observed["production_head"], git_head)
    expect_equal("one_button_nested_verdict_matches_git_head", observed["production_nested_verdict_head"], git_head)
    expect_equal("execution_board_points_to_current_pointer", observed["board_truth_source"], EXPECTED_POINTER_REF)
    expect_equal("readiness_scope_points_to_current_pointer", observed["readiness_truth_source"], EXPECTED_POINTER_REF)
    expect_equal("authority_mode_converged", observed["board_authority_mode"], observed["settled_authority_mode"])
    expect_equal("board_posture_matches_pointer", observed["board_posture_state"], observed["pointer_posture_state"])
    expect_equal("board_posture_matches_current_state", observed["board_posture_state"], observed["current_state_posture_state"])
    expect_equal("board_posture_matches_runtime_audit", observed["board_posture_state"], observed["runtime_audit_posture_state"])
    expect_equal("board_posture_matches_settled_truth", observed["board_posture_state"], observed["settled_truth_posture_state"])
    expect_equal("current_branch_matches_git_branch", str(current_state.get("branch_ref", "")).strip(), git_branch)
    expect_equal("runtime_audit_branch_matches_git_branch", str(runtime_audit.get("branch_ref", "")).strip(), git_branch)
    expect_equal("live_validation_branch_matches_git_branch", str(live_index.get("branch_ref", "")).strip(), git_branch)

    truthful_green = observed["board_posture_state"] == "TRUTHFUL_GREEN"
    if truthful_green:
        expect_true("truthful_green_requires_clean_worktree", not observed["worktree_dirty"])
        expect_equal("truthful_green_requires_settled_authority", observed["board_authority_mode"], "SETTLED_AUTHORITATIVE")
        expect_equal("truthful_green_requires_preflight_pass", observed["preflight_status"], "PASS")
        expect_equal("truthful_green_requires_production_pass", observed["production_status"], "PASS")
        expect_true("truthful_green_requires_preflight_lineage_match", observed["preflight_head_lineage_match"])
        expect_true("truthful_green_requires_production_lineage_match", observed["production_head_lineage_match"])

    return {
        "schema_id": "kt.operator.authority_convergence_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "checks": checks,
        "observed": observed,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate that all active authority surfaces converge on one current-head truth story.")
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="authority-convergence-validate", requested_run_root=str(args.run_root))
    try:
        report = build_authority_convergence_report(root=repo_root())
        write_json_worm(run_dir / "reports" / "authority_convergence_receipt.json", report, label="authority_convergence_receipt.json")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.authority.convergence_validate",
                failure_name="AUTHORITY_CONVERGENCE_FAIL",
                message="; ".join(report.get("failures", [])),
                next_actions=[
                    "Regenerate current-head truth receipts from the current head.",
                    "Resync execution_board.json and readiness_scope_manifest.json to the authoritative current pointer.",
                    "Do not claim TRUTHFUL_GREEN until all authority convergence checks pass.",
                ],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.authority.convergence_validate",
            failure_name="AUTHORITY_CONVERGENCE_FAIL",
            message=str(exc),
            next_actions=["Inspect KT_PROD_CLEANROOM/governance and KT_PROD_CLEANROOM/reports authority surfaces."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
