from __future__ import annotations

import argparse
import json
from typing import Optional, Sequence

from tools.operator.titanium_common import make_run_dir, repo_root, write_failure_artifacts, write_json_worm
from tools.operator.truth_publication import validate_truth_publication


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate Domain 1 truth publication architecture.")
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="truth-publication-validate", requested_run_root=str(args.run_root))
    try:
        report = validate_truth_publication(root=repo_root())
        write_json_worm(run_dir / "reports" / "truth_publication_validation_receipt.json", report, label="truth_publication_validation_receipt.json")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.truth.publication_validate",
                failure_name="STOP_GATE_BLOCKED",
                message="; ".join(report.get("failures", [])),
                next_actions=["Repair Domain 1 publication law surfaces, pointer state, or execution-board authority and rerun truth_publication_validate."],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.truth.publication_validate",
            failure_name="STOP_GATE_BLOCKED",
            message=str(exc),
            next_actions=["Inspect KT_PROD_CLEANROOM/tools/operator/truth_publication.py and Domain 1 governance contracts."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
