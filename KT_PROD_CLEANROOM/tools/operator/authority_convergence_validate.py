from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import make_run_dir, repo_root, utc_now_iso_z, write_failure_artifacts, write_json_worm
from tools.operator.truth_authority import CURRENT_POINTER_REL, active_supporting_truth_surfaces, active_truth_source_ref, load_json_ref


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DEFAULT_CURRENT_STATE_REL = f"{DEFAULT_REPORT_ROOT_REL}/current_state_receipt.json"
DEFAULT_RUNTIME_AUDIT_REL = f"{DEFAULT_REPORT_ROOT_REL}/runtime_closure_audit.json"
LEDGER_BRANCH = "kt_truth_ledger"
PROOF_CLASS_FAIL_CLOSED = "FAIL_CLOSED"
PROOF_CLASS_LOCAL_LEDGER_ONLY = "LOCAL_LEDGER_SELF_CONVERGENCE_ONLY"
PROOF_CLASS_PUBLISHED_HEAD = "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _remote_branch_exists(root: Path, *, remote: str, branch: str) -> bool:
    try:
        output = _git(root, "ls-remote", "--heads", remote, branch)
    except Exception:  # noqa: BLE001
        return False
    return bool(output.strip())


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


def _find_supporting_ref(surfaces: Sequence[str], suffix: str) -> str:
    for surface in surfaces:
        if str(surface).strip().endswith(suffix):
            return str(surface).strip()
    return ""


def _documentary_only(payload: Dict[str, Any]) -> bool:
    if bool(payload.get("documentary_only")):
        return True
    if "live_authority" in payload and payload.get("live_authority") is False:
        return True
    status = str(payload.get("status", "")).strip().upper()
    authority_role = str(payload.get("authority_role", "")).strip().upper()
    return "DOCUMENTARY" in status or "SUPERSEDED" in status or authority_role == "DOCUMENTARY_ONLY"


def build_authority_convergence_report(*, root: Path) -> Dict[str, Any]:
    report_root = (root / DEFAULT_REPORT_ROOT_REL).resolve()
    active_source = active_truth_source_ref(root=root)
    active_supporting = active_supporting_truth_surfaces(root=root)
    board = _load_json(root / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json")
    readiness = _load_json(root / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json")
    current_pointer = load_json_ref(root=root, ref=active_source)
    current_state_ref = _find_supporting_ref(active_supporting, "current_state_receipt.json") or DEFAULT_CURRENT_STATE_REL
    runtime_audit_ref = _find_supporting_ref(active_supporting, "runtime_closure_audit.json") or DEFAULT_RUNTIME_AUDIT_REL
    current_state = load_json_ref(root=root, ref=current_state_ref)
    runtime_audit = load_json_ref(root=root, ref=runtime_audit_ref)
    settled_truth = _load_json(report_root / "settled_truth_source_receipt.json")
    live_index_path = report_root / "live_validation_index.json"
    live_index = _load_json(live_index_path) if live_index_path.exists() else {}
    preflight_path = report_root / "one_button_preflight_receipt.json"
    preflight = _load_json(preflight_path) if preflight_path.exists() else {}
    production_path = report_root / "one_button_production_receipt.json"
    production = _load_json(production_path) if production_path.exists() else {}
    main_current_pointer = _load_json(root / CURRENT_POINTER_REL)
    main_current_state = _load_json(report_root / "current_state_receipt.json")
    main_runtime_audit = _load_json(report_root / "runtime_closure_audit.json")
    ledger_active = active_source != CURRENT_POINTER_REL

    try:
        git_head = _git(root, "rev-parse", "HEAD")
    except Exception:  # noqa: BLE001
        git_head = _head_from(current_pointer) or _head_from(live_index)
    try:
        git_branch = _git(root, "rev-parse", "--abbrev-ref", "HEAD")
    except Exception:  # noqa: BLE001
        git_branch = str(current_state.get("branch_ref", "")).strip() or str(live_index.get("branch_ref", "")).strip()

    ledger_remote_exists = _remote_branch_exists(root, remote="origin", branch=LEDGER_BRANCH)
    # WS2 guardrail: do not treat remote branch reachability as published-head admissibility proof.
    proof_class = PROOF_CLASS_LOCAL_LEDGER_ONLY if ledger_active else PROOF_CLASS_PUBLISHED_HEAD

    observed = {
        "git_head": git_head,
        "git_branch": git_branch,
        "board_head": str(board.get("last_synced_head_sha", "")).strip(),
        "active_truth_source": active_source,
        "active_supporting_truth_surfaces": active_supporting,
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
        "proof_class": proof_class,
        "ledger_branch_published": ledger_remote_exists,
        "active_current_pointer_documentary_only": _documentary_only(current_pointer),
        "main_current_pointer_documentary_only": _documentary_only(main_current_pointer),
        "main_current_state_documentary_only": _documentary_only(main_current_state),
        "main_runtime_audit_documentary_only": _documentary_only(main_runtime_audit),
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

    expect_equal("execution_board_matches_git_head", observed["board_head"], git_head)
    expect_equal("current_pointer_matches_git_head", observed["pointer_head"], git_head)
    expect_equal("current_state_receipt_matches_git_head", observed["current_state_head"], git_head)
    expect_equal("runtime_closure_audit_matches_git_head", observed["runtime_audit_head"], git_head)
    expect_equal("settled_truth_source_matches_git_head", observed["settled_truth_head"], git_head)
    expect_equal("execution_board_points_to_active_truth_source", observed["board_truth_source"], active_source)
    expect_equal("readiness_scope_points_to_active_truth_source", observed["readiness_truth_source"], active_source)
    expect_equal("authority_mode_converged", observed["board_authority_mode"], observed["settled_authority_mode"])
    expect_equal("board_posture_matches_pointer", observed["board_posture_state"], observed["pointer_posture_state"])
    expect_equal("board_posture_matches_current_state", observed["board_posture_state"], observed["current_state_posture_state"])
    expect_equal("board_posture_matches_runtime_audit", observed["board_posture_state"], observed["runtime_audit_posture_state"])
    expect_equal("board_posture_matches_settled_truth", observed["board_posture_state"], observed["settled_truth_posture_state"])
    expect_equal("current_branch_matches_git_branch", str(current_state.get("branch_ref", "")).strip(), git_branch)
    expect_equal("runtime_audit_branch_matches_git_branch", str(runtime_audit.get("branch_ref", "")).strip(), git_branch)
    expect_true("active_current_pointer_not_documentary_only", not observed["active_current_pointer_documentary_only"])

    truthful_green = observed["board_posture_state"] == "TRUTHFUL_GREEN"
    if ledger_active:
        expect_equal("local_ledger_requires_transitional_authority", observed["board_authority_mode"], "TRANSITIONAL_AUTHORITATIVE")
        expect_true("main_current_pointer_documentary_only", observed["main_current_pointer_documentary_only"])
        expect_true("main_current_state_documentary_only", observed["main_current_state_documentary_only"])
        expect_true("main_runtime_audit_documentary_only", observed["main_runtime_audit_documentary_only"])
        h1_gate = bool((board.get("program_gates") or {}).get("H1_ACTIVATION_ALLOWED"))
        expect_true("local_ledger_requires_h1_blocked", not h1_gate)
        if proof_class == PROOF_CLASS_PUBLISHED_HEAD:
            expect_true("published_ledger_branch_required", observed["ledger_branch_published"])
        else:
            checks.append(
                {
                    "check": "proof_class_is_local_ledger_only",
                    "status": "PASS",
                    "proof_class": proof_class,
                    "ledger_branch_published": observed["ledger_branch_published"],
                }
            )
    elif truthful_green:
        expect_true("truthful_green_requires_clean_worktree", not observed["worktree_dirty"])
        expect_equal("truthful_green_requires_settled_authority", observed["board_authority_mode"], "SETTLED_AUTHORITATIVE")
        expect_equal("truthful_green_requires_preflight_pass", observed["preflight_status"], "PASS")
        expect_equal("truthful_green_requires_production_pass", observed["production_status"], "PASS")
        expect_equal("one_button_preflight_matches_git_head", observed["preflight_head"], git_head)
        expect_equal("one_button_production_matches_git_head", observed["production_head"], git_head)
        expect_equal("one_button_nested_verdict_matches_git_head", observed["production_nested_verdict_head"], git_head)
        expect_true("truthful_green_requires_preflight_lineage_match", observed["preflight_head_lineage_match"])
        expect_true("truthful_green_requires_production_lineage_match", observed["production_head_lineage_match"])

    return {
        "schema_id": "kt.operator.authority_convergence_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not failures and proof_class != PROOF_CLASS_FAIL_CLOSED else "FAIL",
        "proof_class": proof_class if not failures else PROOF_CLASS_FAIL_CLOSED,
        "published_head_authority_claimed": proof_class == PROOF_CLASS_PUBLISHED_HEAD and not failures,
        "h1_admissible": proof_class == PROOF_CLASS_PUBLISHED_HEAD and not failures,
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
