from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import write_text_worm


def _read_json_dict(path: Path) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable JSON: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: receipt must be a JSON object: {path.as_posix()}")
    return obj


def validate_receipts_dir(*, receipts_dir: Path) -> Dict[str, Any]:
    receipts_dir = receipts_dir.resolve()
    if not receipts_dir.exists() or not receipts_dir.is_dir():
        raise FL3ValidationError(f"FAIL_CLOSED: receipts_dir missing: {receipts_dir.as_posix()}")

    results: List[Dict[str, Any]] = []
    ok = True
    for p in sorted(receipts_dir.glob("*.json"), key=lambda x: x.name):
        try:
            obj = _read_json_dict(p)
            validate_schema_bound_object(obj)
            results.append({"path": p.as_posix(), "status": "PASS"})
        except Exception as exc:  # noqa: BLE001
            ok = False
            results.append({"path": p.as_posix(), "status": "FAIL", "error": str(exc)[:400]})

    report: Dict[str, Any] = {
        "status": "PASS" if ok else "FAIL",
        "counts": {
            "total": len(results),
            "pass": sum(1 for r in results if r["status"] == "PASS"),
            "fail": sum(1 for r in results if r["status"] == "FAIL"),
        },
        "results": results,
    }
    return report


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Fail-closed validation of all change receipts in the archive vault.")
    ap.add_argument(
        "--receipts-dir",
        default="KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/receipts",
        help="Path to receipts directory (repo-relative by default).",
    )
    ap.add_argument("--out-dir", required=True, help="Write receipts_validation_report.json under this directory (WORM).")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = repo_root_from(Path(__file__))

    receipts_dir = Path(str(args.receipts_dir))
    if not receipts_dir.is_absolute():
        receipts_dir = (repo_root / receipts_dir).resolve()

    out_dir = Path(str(args.out_dir))
    if not out_dir.is_absolute():
        out_dir = (repo_root / out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report = validate_receipts_dir(receipts_dir=receipts_dir)
    out_path = out_dir / "receipts_validation_report.json"
    write_text_worm(
        path=out_path,
        text=json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="receipts_validation_report.json",
    )
    if report.get("status") != "PASS":
        raise SystemExit("FAIL_CLOSED: one or more receipts failed validation")
    print(out_path.as_posix())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc

