from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v15_oracle_harvest_common import current_checked_portfolio, oracle_gap_matrix, write_jsonl


def current_main(argv):
    import argparse
    repo = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src"))
    from memory.lab_effect import write_record
    from schemas.trusted_local_path import assert_no_link_or_reparse_path

    parser = argparse.ArgumentParser(description="Read verified current laboratory evidence; historical V15 mode is unchanged.")
    parser.add_argument("--current-checked-run", required=True, type=Path)
    parser.add_argument("--freeze-sha256", required=True)
    parser.add_argument("--baseline-route", default="base/direct")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    output = args.output
    assert_no_link_or_reparse_path(output, label="current oracle output")
    if (output.resolve() != output or output.is_relative_to(repo) or
            output.is_relative_to(args.current_checked_run.resolve()) or output.exists()):
        raise ValueError("CURRENT_ORACLE_OUTPUT_MUST_BE_NEW_AND_EXTERNAL")
    report = current_checked_portfolio(args.current_checked_run, freeze_sha256=args.freeze_sha256,
                                       baseline_route=args.baseline_route)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_record(output, report)
    print(json.dumps({"status": report["status"], "assigned": report["assigned_operations"],
                      "completed": report["completed_operations"], "output": str(output)}, sort_keys=True))


if __name__ == "__main__":
    if "--current-checked-run" in sys.argv:
        current_main(sys.argv[1:])
        raise SystemExit(0)
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("admission/oracle_gap_matrix.jsonl")
    rows = write_jsonl(out, oracle_gap_matrix())
    print(json.dumps({"rows": len(rows), "out": out.as_posix()}, sort_keys=True))
