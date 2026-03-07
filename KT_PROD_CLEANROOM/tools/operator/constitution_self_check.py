from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, make_run_dir, repo_root, write_failure_artifacts, write_json_worm


def self_check() -> Dict[str, object]:
    root = repo_root()
    manifest = load_json((root / "KT_PROD_CLEANROOM" / "governance" / "governance_manifest.json").resolve())
    expected_epoch = int(manifest.get("constitution_epoch", 0))
    locator_dir = (root / "KT_PROD_CLEANROOM" / "governance" / "tier_locators").resolve()
    locators = sorted(locator_dir.glob("tier*_files.json"))
    failures = []
    checked = []
    for locator in locators:
        obj = load_json(locator)
        epoch = int(obj.get("constitution_epoch", -1))
        status = "PASS" if epoch == expected_epoch else "FAIL"
        if status != "PASS":
            failures.append(locator.name)
        checked.append({"path": locator.as_posix(), "status": status, "constitution_epoch": epoch})
    return {"checked": checked, "schema_id": "kt.operator.constitution_self_check.v1", "status": "PASS" if not failures else "FAIL", "violations": failures}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Constitution epoch self-check.")
    ap.add_argument("--mode", default="internal")
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="constitution-self-check", requested_run_root=str(args.run_root))
    try:
        report = self_check()
        write_json_worm(run_dir / "reports" / "constitution_self_check.json", report, label="constitution_self_check.json")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.constitution.self_check",
                failure_name="CONSTITUTION_EPOCH_MISMATCH",
                message="; ".join(str(x) for x in report.get("violations", [])),
                next_actions=["Align all tier locator constitution_epoch values to the governance manifest epoch."],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.constitution.self_check",
            failure_name="CONSTITUTION_EPOCH_MISMATCH",
            message=str(exc),
            next_actions=["Inspect governance/tier_locators and governance_manifest.json."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
