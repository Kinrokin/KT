from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.github_ruleset import DEFAULT_RULESET_PATH, _api_request, _github_token, _repo_slug
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/ci_gate_promotion_receipt.json"
DEFAULT_BRANCH_PROTECTION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json"
HISTORICAL_ACTIVE_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/main_branch_protection_active_receipt.json"
FAIL_CLOSED_MAIN_WORKFLOW_PATH = ".github/workflows/ci_p0_fail_closed_main.yml"
WARN_ONLY_WORKFLOW_PATH = ".github/workflows/ci_p0_warn_only_closure.yml"


def _resolve_path(rel_or_abs: str) -> Path:
    path = Path(str(rel_or_abs)).expanduser()
    if not path.is_absolute():
        path = (repo_root() / path).resolve()
    return path


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=str(repo_root()), text=True).strip()


def _run_summary(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "databaseId": row.get("id"),
        "workflowName": str(row.get("name", "")).strip(),
        "headSha": str(row.get("head_sha", "")).strip(),
        "status": str(row.get("status", "")).strip(),
        "conclusion": str(row.get("conclusion", "")).strip(),
        "event": str(row.get("event", "")).strip(),
        "url": str(row.get("html_url", "")).strip(),
        "displayTitle": str(row.get("display_title", "")).strip(),
    }


def _job_summaries(jobs: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in jobs:
        if not isinstance(row, dict):
            continue
        out.append(
            {
                "name": str(row.get("name", "")).strip(),
                "conclusion": str(row.get("conclusion", "")).strip(),
                "url": str(row.get("html_url", "")).strip(),
            }
        )
    return out


def _workflow_by_path(workflows: Sequence[Dict[str, Any]], workflow_path: str) -> Optional[Dict[str, Any]]:
    target = str(workflow_path).strip()
    for row in workflows:
        if not isinstance(row, dict):
            continue
        if str(row.get("path", "")).strip() == target:
            return row
    return None


def _latest_run_for_workflow(
    runs: Sequence[Dict[str, Any]],
    *,
    workflow_id: Any,
    head_sha: str = "",
    event: str = "",
) -> Optional[Dict[str, Any]]:
    for row in runs:
        if not isinstance(row, dict):
            continue
        if row.get("workflow_id") != workflow_id:
            continue
        if head_sha and str(row.get("head_sha", "")).strip() != str(head_sha).strip():
            continue
        if event and str(row.get("event", "")).strip() != str(event).strip():
            continue
        return row
    return None


def _build_ci_gate_receipt(
    *,
    repo_slug: str,
    branch_ref: str,
    head_sha: str,
    fail_workflow: Optional[Dict[str, Any]],
    warn_workflow: Optional[Dict[str, Any]],
    fail_run: Optional[Dict[str, Any]],
    warn_run: Optional[Dict[str, Any]],
    fail_jobs: Sequence[Dict[str, Any]],
    branch_receipt: Dict[str, Any],
    desired_ruleset_artifact: str,
    desired_ruleset_sha256: str,
    historical_active_status: str,
) -> Dict[str, Any]:
    fail_declared = fail_workflow is not None
    warn_declared = warn_workflow is not None
    fail_active = bool(fail_workflow) and str(fail_workflow.get("state", "")).strip() == "active"
    warn_active = bool(warn_workflow) and str(warn_workflow.get("state", "")).strip() == "active"
    fail_run_ok = bool(fail_run) and str((fail_run or {}).get("status", "")).strip() == "completed" and str((fail_run or {}).get("conclusion", "")).strip() == "success"
    branch_status = str(branch_receipt.get("status", "")).strip() or "UNKNOWN"
    branch_claim_admissible = bool(branch_receipt.get("claim_admissible"))

    if fail_run_ok:
        if branch_status == "PASS" and branch_claim_admissible:
            receipt_status = "PASS"
        elif branch_status == "BLOCKED":
            receipt_status = "PASS_WITH_PLATFORM_BLOCK"
        else:
            receipt_status = "PASS_WITH_WARNINGS"
    else:
        receipt_status = "FAIL"

    promotion_status = "CURRENT_HEAD_PASS" if fail_run_ok else "CURRENT_HEAD_FAIL"
    current_head_admissible = fail_run_ok and branch_status == "PASS" and branch_claim_admissible

    next_actions: List[str] = []
    if not fail_run_ok:
        next_actions.append("Repair the current-head fail-closed main workflow and rerun CI governance verification.")
    elif branch_status == "BLOCKED":
        next_actions.extend(
            [
                "Treat fail-closed workflow as live current-head workflow evidence only.",
                "Do not claim platform-enforced governance on main while ruleset verification remains blocked.",
                "Enable GitHub branch protection capability or make the repository public, then rerun program.github.ruleset.verify.",
            ]
        )
    elif current_head_admissible:
        next_actions.append("Platform-enforced governance is proven on the current head.")
    else:
        next_actions.append("Refresh branch protection verification and current-head workflow evidence together before making governance claims.")

    return {
        "schema_id": "kt.sovereign.ci_gate_promotion_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "branch": branch_ref,
        "head_sha": head_sha,
        "promotion_scope": "ci_execution_governance_only",
        "published_head_authority_claimed": False,
        "status": receipt_status,
        "warn_only_workflow": {
            "name": str((warn_workflow or {}).get("name", "")).strip(),
            "declared": warn_declared,
            "workflow_active_on_repo": warn_active,
            "path": str((warn_workflow or {}).get("path", "")).strip(),
            "path_sha256": file_sha256(_resolve_path(str((warn_workflow or {}).get("path", "")).strip())) if warn_declared else "",
            "latest_observed_run": _run_summary(warn_run) if warn_run else None,
            "live_on_repo": warn_active,
            "note": "warn-only remains active on the repository, but no current-head push run is expected for this workflow trigger model",
        },
        "fail_closed_main_workflow": {
            "name": str((fail_workflow or {}).get("name", "")).strip(),
            "declared": fail_declared,
            "workflow_active_on_repo": fail_active,
            "path": str((fail_workflow or {}).get("path", "")).strip(),
            "path_sha256": file_sha256(_resolve_path(str((fail_workflow or {}).get("path", "")).strip())) if fail_declared else "",
            "live_on_main": fail_active,
            "current_head_run": ({**_run_summary(fail_run), "jobs": _job_summaries(fail_jobs)} if fail_run else None),
            "promotion_status": promotion_status,
        },
        "branch_protection_ruleset": {
            "desired_state_artifact": desired_ruleset_artifact,
            "desired_state_sha256": desired_ruleset_sha256,
            "fresh_verify_status": branch_status,
            "fresh_verify_claim_admissible": branch_claim_admissible,
            "fresh_verify_platform_block": branch_receipt.get("platform_block"),
            "fresh_verify_next_action": str(branch_receipt.get("next_action", "")).strip(),
            "historical_active_receipt_ref": HISTORICAL_ACTIVE_RECEIPT_REL,
            "historical_active_receipt_status": historical_active_status,
            "current_head_admissible": current_head_admissible,
        },
        "local_ci_artifacts": {
            "cidelivery_manifest": "ci/delivery/cidelivery_manifest.json",
            "cireplay_receipt": "ci/evidence/cireplay_receipt.json",
        },
        "next_actions": next_actions,
    }


def build_ci_gate_promotion_receipt(
    *,
    repo_slug: str = "",
    ruleset_path: str = DEFAULT_RULESET_PATH,
    branch_protection_receipt_path: str = DEFAULT_BRANCH_PROTECTION_RECEIPT_REL,
) -> Dict[str, Any]:
    root = repo_root()
    repo = _repo_slug(repo_slug)
    owner, repo_name = repo.split("/", 1)
    token = _github_token()
    workflows_payload = _api_request(method="GET", path=f"/repos/{owner}/{repo_name}/actions/workflows", token=token)
    runs_payload = _api_request(method="GET", path=f"/repos/{owner}/{repo_name}/actions/runs?branch=main&per_page=100", token=token)
    workflows = workflows_payload.get("workflows") if isinstance(workflows_payload, dict) else []
    runs = runs_payload.get("workflow_runs") if isinstance(runs_payload, dict) else []
    workflows = workflows if isinstance(workflows, list) else []
    runs = runs if isinstance(runs, list) else []

    fail_workflow = _workflow_by_path(workflows, FAIL_CLOSED_MAIN_WORKFLOW_PATH)
    warn_workflow = _workflow_by_path(workflows, WARN_ONLY_WORKFLOW_PATH)
    head_sha = _git("rev-parse", "HEAD")
    branch_ref = _git("rev-parse", "--abbrev-ref", "HEAD")
    fail_run = _latest_run_for_workflow(runs, workflow_id=(fail_workflow or {}).get("id"), head_sha=head_sha, event="push") if fail_workflow else None
    warn_run = _latest_run_for_workflow(runs, workflow_id=(warn_workflow or {}).get("id")) if warn_workflow else None
    fail_jobs_payload = (
        _api_request(method="GET", path=f"/repos/{owner}/{repo_name}/actions/runs/{fail_run.get('id')}/jobs?per_page=100", token=token)
        if fail_run
        else {}
    )
    fail_jobs = fail_jobs_payload.get("jobs") if isinstance(fail_jobs_payload, dict) else []
    fail_jobs = fail_jobs if isinstance(fail_jobs, list) else []

    branch_receipt = load_json(_resolve_path(branch_protection_receipt_path))
    historical_active_path = _resolve_path(HISTORICAL_ACTIVE_RECEIPT_REL)
    historical_active_status = "MISSING"
    if historical_active_path.exists():
        historical_active_status = str(load_json(historical_active_path).get("status", "")).strip() or "UNKNOWN"

    desired_ruleset_path = _resolve_path(ruleset_path)
    desired_ruleset_artifact = str(desired_ruleset_path.relative_to(root)).replace("\\", "/")
    desired_ruleset_sha256 = file_sha256(desired_ruleset_path)
    return _build_ci_gate_receipt(
        repo_slug=repo,
        branch_ref=branch_ref,
        head_sha=head_sha,
        fail_workflow=fail_workflow,
        warn_workflow=warn_workflow,
        fail_run=fail_run,
        warn_run=warn_run,
        fail_jobs=fail_jobs,
        branch_receipt=branch_receipt,
        desired_ruleset_artifact=desired_ruleset_artifact,
        desired_ruleset_sha256=desired_ruleset_sha256,
        historical_active_status=historical_active_status,
    )


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mint the current-head CI execution governance receipt.")
    parser.add_argument("--repo-slug", default="")
    parser.add_argument("--ruleset", default=DEFAULT_RULESET_PATH)
    parser.add_argument("--branch-protection-receipt", default=DEFAULT_BRANCH_PROTECTION_RECEIPT_REL)
    parser.add_argument("--out", default=DEFAULT_RECEIPT_PATH)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    receipt = build_ci_gate_promotion_receipt(
        repo_slug=str(args.repo_slug),
        ruleset_path=str(args.ruleset),
        branch_protection_receipt_path=str(args.branch_protection_receipt),
    )
    out_path = _resolve_path(str(args.out))
    write_json_stable(out_path, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(receipt.get("status", "")).strip() in {"PASS", "PASS_WITH_PLATFORM_BLOCK", "PASS_WITH_WARNINGS"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
