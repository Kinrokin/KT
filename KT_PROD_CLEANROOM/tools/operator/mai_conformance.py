from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Optional, Sequence

from tools.operator.titanium_common import make_run_dir, write_failure_artifacts, write_json_worm


def check_mai(target: Path) -> dict:
    target = target.resolve()
    provenance = (target / "reports" / "model_plane_provenance.json").resolve()
    if not provenance.exists():
        raise RuntimeError("FAIL_CLOSED: missing reports/model_plane_provenance.json")
    obj = json.loads(provenance.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError("FAIL_CLOSED: model_plane_provenance must be a JSON object")
    missing: List[str] = []
    for field in ("engine_name", "engine_version", "tokenizer_hash_or_id", "model_snapshot_hash_or_file_hashes"):
        if not obj.get(field):
            missing.append(field)
    probe_results = (target / "reports" / "probe_results.jsonl").resolve()
    if probe_results.exists():
        for line in probe_results.read_text(encoding="utf-8").splitlines():
            if "payload" in line.lower():
                missing.append("probe_payload_leak")
                break
    return {"missing": missing, "schema_id": "kt.operator.mai_conformance.v1", "status": "PASS" if not missing else "FAIL"}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Minimal MAI conformance validator.")
    ap.add_argument("--target", required=True)
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="mai-conformance", requested_run_root=str(args.run_root))
    try:
        report = check_mai(Path(args.target))
        write_json_worm(run_dir / "reports" / "conformance_report.json", report, label="conformance_report.json")
        (run_dir / "reports" / "conformance_report.md").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.mai.conformance",
                failure_name="MAI_CONFORMANCE_FAIL",
                message="; ".join(str(x) for x in report.get("missing", [])),
                next_actions=["Emit complete model_plane_provenance.json and ensure probe outputs remain hash-ref-only."],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.mai.conformance",
            failure_name="MAI_CONFORMANCE_FAIL",
            message=str(exc),
            next_actions=["Point --target at a run directory with reports/model_plane_provenance.json."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
