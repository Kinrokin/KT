from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, make_run_dir, repo_root, write_failure_artifacts, write_json_worm


def _age_days(path: Path) -> float:
    ts = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds() / 86400.0


def _git(repo_root_path: Path, args: Sequence[str]) -> str:
    p = subprocess.run(
        ["git", *args],
        cwd=str(repo_root_path),
        text=True,
        capture_output=True,
        check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(f"FAIL_CLOSED: git {' '.join(args)} failed: {(p.stderr or p.stdout).strip()}")
    return (p.stdout or "").strip()


def _load_json_bom_tolerant(path: Path) -> Dict[str, object]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        obj = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(obj, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return obj


def compute_god_status() -> Dict[str, object]:
    root = repo_root()
    manifest = (root / "KT_PROD_CLEANROOM" / "governance" / "governance_manifest.json").resolve()
    runs_root = (root / "KT_PROD_CLEANROOM" / "exports" / "_runs" / "KT_OPERATOR").resolve()
    ci_gate_receipt_path = (root / "KT_PROD_CLEANROOM" / "reports" / "ci_gate_promotion_receipt.json").resolve()
    twocc = []
    for report_path in sorted(runs_root.glob("*/reports/twocleanclone_proof.json")):
        try:
            report = load_json(report_path)
        except Exception:  # noqa: BLE001
            continue
        if str(report.get("status", "")).strip() == "PASS":
            twocc.append(report_path.parent.parent)
    warnings = []
    if not manifest.exists():
        warnings.append("governance_manifest_missing")
    elif _age_days(manifest) > 30:
        warnings.append("governance_manifest_stale")
    if not twocc:
        warnings.append("twocleanclone_missing")
    ci_gate_status = "MISSING"
    if ci_gate_receipt_path.exists():
        ci_gate_receipt = _load_json_bom_tolerant(ci_gate_receipt_path)
        ci_gate_status = str(ci_gate_receipt.get("status", "")).strip() or "UNKNOWN"
        if ci_gate_status == "PASS_WITH_PLATFORM_BLOCK":
            warnings.append("ci_execution_governance_platform_block")
    status = "PASS_WITH_WARNINGS" if warnings else "PASS"
    return {
        "schema_id": "kt.operator.god_status.v1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "branch_ref": _git(root, ["rev-parse", "--abbrev-ref", "HEAD"]),
        "validated_head_sha": _git(root, ["rev-parse", "HEAD"]),
        "scope": "candidate_tracked_worktree_governance_and_reproducibility_only",
        "ci_gate_promotion_status": ci_gate_status,
        "status": status,
        "warnings": warnings,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Compute Titanium God-Status.")
    ap.add_argument("--profile", default="v1")
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="god-status", requested_run_root=str(args.run_root))
    try:
        report = compute_god_status()
        write_json_worm(run_dir / "reports" / "godstatus_verdict.json", report, label="godstatus_verdict.json")
        write_json_worm(
            run_dir / "reports" / "godstatus_cooldown_state.json",
            {
                "generated_utc": report["generated_utc"],
                "branch_ref": report["branch_ref"],
                "validated_head_sha": report["validated_head_sha"],
                "cooldown_active": False,
            },
            label="godstatus_cooldown_state.json",
        )
        verdict = f"KT_GOD_STATUS_{str(report['status'])}"
        (run_dir / "reports" / "one_line_verdict.txt").write_text(verdict + "\n", encoding="utf-8")
        print(verdict)
        return 0 if report["status"] != "HOLD" else 70
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.authority.god_status",
            failure_name="GOD_STATUS_HOLD",
            message=str(exc),
            next_actions=["Repair governance freshness gaps and rerun god_status."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
