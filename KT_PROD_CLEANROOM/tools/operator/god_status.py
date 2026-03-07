from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, make_run_dir, repo_root, write_failure_artifacts, write_json_worm


def _age_days(path: Path) -> float:
    ts = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds() / 86400.0


def compute_god_status() -> Dict[str, object]:
    root = repo_root()
    manifest = (root / "KT_PROD_CLEANROOM" / "governance" / "governance_manifest.json").resolve()
    twocc = sorted((root / "KT_PROD_CLEANROOM" / "exports" / "_runs" / "KT_OPERATOR").glob("*_twocleanclone-proof"))
    warnings = []
    if not manifest.exists():
        warnings.append("governance_manifest_missing")
    elif _age_days(manifest) > 30:
        warnings.append("governance_manifest_stale")
    if not twocc:
        warnings.append("twocleanclone_missing")
    status = "PASS_WITH_WARNINGS" if warnings else "PASS"
    return {"schema_id": "kt.operator.god_status.v1", "status": status, "warnings": warnings}


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
        write_json_worm(run_dir / "reports" / "godstatus_cooldown_state.json", {"cooldown_active": False}, label="godstatus_cooldown_state.json")
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
