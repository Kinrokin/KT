from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes
from tools.operator.titanium_common import make_run_dir, write_failure_artifacts, write_json_worm


def _entry_hash(obj: Dict[str, object]) -> str:
    payload = {k: v for k, v in obj.items() if k != "entry_hash"}
    return hashlib.sha256(canonicalize_bytes(payload)).hexdigest()


def verify_ledger(ledger_path: Path) -> Dict[str, object]:
    previous = ""
    violations: List[str] = []
    count = 0
    for line_no, line in enumerate(ledger_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        count += 1
        obj = json.loads(line)
        actual_prev = str(obj.get("previous_entry_hash", "")).strip()
        actual_hash = str(obj.get("entry_hash", "")).strip()
        expected_hash = _entry_hash(obj)
        if actual_prev != previous:
            violations.append(f"line{line_no}:previous_entry_hash")
        if actual_hash != expected_hash:
            violations.append(f"line{line_no}:entry_hash")
        previous = actual_hash
    return {"entries": count, "schema_id": "kt.operator.ledger_verify_chain.v1", "status": "PASS" if not violations else "FAIL", "violations": violations}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Verify append-only ledger chain.")
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="ledger-verify-chain", requested_run_root=str(args.run_root))
    try:
        report = verify_ledger(Path(args.ledger))
        write_json_worm(run_dir / "reports" / "ledger_verify_chain.json", report, label="ledger_verify_chain.json")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.ledger.verify_chain",
                failure_name="LEDGER_CHAIN_INVALID",
                message="; ".join(str(x) for x in report.get("violations", [])),
                next_actions=["Repair the ledger chain or roll forward with a valid append-only entry."],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.ledger.verify_chain",
            failure_name="LEDGER_CHAIN_INVALID",
            message=str(exc),
            next_actions=["Inspect the target ledger JSONL for malformed or reordered entries."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
