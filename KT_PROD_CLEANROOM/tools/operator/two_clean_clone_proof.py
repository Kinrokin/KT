from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Optional, Sequence

from tools.operator.titanium_common import file_sha256, make_run_dir, write_failure_artifacts, write_json_worm


def compare_runs(run_a: Path, run_b: Path) -> Dict[str, object]:
    keys = {
        "delivery_root_hash": "delivery/delivery_manifest.json",
        "bindingloop_check_hash": "reports/bindingloop_check.json",
        "evidence_core_merkle_root_sha256": "evidence/evidence_core_merkle.json",
        "replay_receipt_hash": "evidence/replay_receipt.json",
    }
    comparisons = []
    violations = []
    for name, rel in keys.items():
        a = (run_a / rel).resolve()
        b = (run_b / rel).resolve()
        if not a.exists() or not b.exists():
            violations.append(f"{name}:missing")
            continue
        a_sha = file_sha256(a)
        b_sha = file_sha256(b)
        status = "PASS" if a_sha == b_sha else "FAIL"
        if status != "PASS":
            violations.append(name)
        comparisons.append({"a_sha256": a_sha, "b_sha256": b_sha, "key": name, "status": status})
    return {"comparisons": comparisons, "schema_id": "kt.operator.twocleanclone_proof.v1", "status": "PASS" if not violations else "FAIL", "violations": violations}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Compare two clean-clone runs.")
    ap.add_argument("--run-a", required=True)
    ap.add_argument("--run-b", required=True)
    ap.add_argument("--programs", default="")
    ap.add_argument("--output", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="twocleanclone-proof", requested_run_root=str(args.output))
    try:
        report = compare_runs(Path(args.run_a), Path(args.run_b))
        write_json_worm(run_dir / "reports" / "twocleanclone_proof.json", report, label="twocleanclone_proof.json")
        write_json_worm(
            run_dir / "reports" / "proofrunbundle_index.json",
            {"programs": str(args.programs), "run_a": str(args.run_a), "run_b": str(args.run_b)},
            label="proofrunbundle_index.json",
        )
        summary = "\n".join(str(x) for x in report.get("violations", [])) + ("\n" if report.get("violations") else "PASS\n")
        (run_dir / "reports" / "twocleanclone_diff_summary.txt").write_text(summary, encoding="utf-8")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.proof.twocleanclone",
                failure_name="REPLAY_NONDETERMINISTIC",
                message="; ".join(str(x) for x in report.get("violations", [])),
                next_actions=["Rerun both programs from clean clones and compare the missing or mismatched proof artifacts."],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.proof.twocleanclone",
            failure_name="REPLAY_NONDETERMINISTIC",
            message=str(exc),
            next_actions=["Provide two run directories with the required proof artifacts."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
