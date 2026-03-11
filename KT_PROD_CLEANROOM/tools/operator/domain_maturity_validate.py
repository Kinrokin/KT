from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import make_run_dir, repo_root, write_failure_artifacts, write_json_worm


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return json.loads(path.read_text(encoding="utf-8"))


def build_domain_maturity_report(*, root: Path) -> Dict[str, Any]:
    board = _load_json(root / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json")
    taxonomy = _load_json(root / "KT_PROD_CLEANROOM" / "governance" / "status_taxonomy.json")
    allowed = {str(item).strip() for item in taxonomy.get("maturity_ladder", []) if str(item).strip()}
    domains = board.get("constitutional_domains") if isinstance(board.get("constitutional_domains"), list) else []
    checks = []
    failures = []
    for row in domains:
        if not isinstance(row, dict):
            continue
        domain_id = str(row.get("domain_id", "")).strip()
        maturity_state = str(row.get("maturity_state", "")).strip()
        status = str(row.get("status", "")).strip()
        gate_state = str(row.get("gate_state", "")).strip()
        ok = bool(maturity_state) and maturity_state in allowed
        checks.append(
            {
                "domain_id": domain_id,
                "maturity_state": maturity_state,
                "status": status,
                "gate_state": gate_state,
                "status_check": "PASS" if ok else "FAIL",
            }
        )
        if not ok:
            failures.append(f"{domain_id}:invalid_maturity_state")
    return {
        "schema_id": "kt.operator.domain_maturity_validation_receipt.v1",
        "status": "PASS" if not failures else "FAIL",
        "checks": checks,
        "failures": failures,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate that constitutional domain maturity states use the tracked status taxonomy.")
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="domain-maturity-validate", requested_run_root=str(args.run_root))
    try:
        report = build_domain_maturity_report(root=repo_root())
        write_json_worm(run_dir / "reports" / "domain_maturity_validation_receipt.json", report, label="domain_maturity_validation_receipt.json")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.domain.maturity.validate",
                failure_name="DOMAIN_MATURITY_INVALID",
                message="; ".join(report.get("failures", [])),
                next_actions=["Regenerate execution_board.json so every domain carries a valid maturity state from status_taxonomy.json."],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.domain.maturity.validate",
            failure_name="DOMAIN_MATURITY_INVALID",
            message=str(exc),
            next_actions=["Inspect KT_PROD_CLEANROOM/governance/execution_board.json and KT_PROD_CLEANROOM/governance/status_taxonomy.json."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
