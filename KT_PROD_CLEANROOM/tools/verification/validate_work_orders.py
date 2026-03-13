from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.schema_registry import validate_object_with_binding
from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_validators import FL3ValidationError
from tools.verification.worm_write import write_text_worm


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate work orders (schema-bound) under exports/ and write a WORM report.")
    ap.add_argument("--run-root", default=None, help="Run root for WORM outputs. Default: KT_PROD_CLEANROOM/exports/_runs/KT_V1_CLOSURE/<ts>/")
    ap.add_argument("--exports-root", default="KT_PROD_CLEANROOM/exports", help="Exports root to scan.")
    ap.add_argument("--max-files", type=int, default=2000, help="Fail-closed if more matching files are found.")
    return ap.parse_args(argv)


def _default_run_root(*, repo_root: Path) -> Path:
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs" / "KT_V1_CLOSURE" / ts


def _iter_work_order_files(*, root: Path) -> List[Path]:
    # Deliberately narrow: only WORK_ORDER_*.json, to avoid scanning arbitrary JSON payloads.
    # Use an underscore to avoid self-matching this tool's own report outputs.
    #
    # IMPORTANT: exports/_runs/** contains ephemeral operator artifacts (including clean clones of
    # the repo) and must not be treated as "authoritative exports". Those run directories may
    # contain draft/proposed work orders or partial snapshots that are intentionally not schema
    # valid. Scanning them would make canonical verification non-deterministically fail based on
    # local run history.
    runs_root = (root / "_runs").resolve()
    files: List[Path] = []
    for p in root.rglob("WORK_ORDER_*.json"):
        if not p.is_file():
            continue
        try:
            if p.resolve().is_relative_to(runs_root):
                continue
        except Exception:
            # Conservative fallback: if we cannot resolve/is_relative_to, keep scanning.
            pass
        files.append(p)
    return sorted(files)


def _read_json_obj(path: Path) -> Dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8-sig")
        obj = json.loads(text)
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unable to read JSON (fail-closed): {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"Expected JSON object (fail-closed): {path.as_posix()}")
    return obj


def validate_work_orders(*, repo_root: Path, exports_root: Path, max_files: int) -> Tuple[List[str], List[Dict[str, str]]]:
    files = _iter_work_order_files(root=exports_root)
    if len(files) > max_files:
        raise FL3ValidationError(f"Too many WORK_ORDER*.json files ({len(files)}) under {exports_root.as_posix()} (fail-closed)")

    ok: List[str] = []
    failures: List[Dict[str, str]] = []
    for p in files:
        rel = None
        try:
            rel = p.resolve().relative_to(repo_root.resolve()).as_posix()
        except Exception:
            rel = p.as_posix()
        try:
            obj = _read_json_obj(p)
            validate_object_with_binding(obj)
            ok.append(rel)
        except Exception as exc:  # noqa: BLE001
            failures.append(
                {
                    "path": rel,
                    "error": str(exc),
                }
            )
    return ok, failures


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = repo_root_from(Path(__file__))
    exports_root = (repo_root / str(args.exports_root)).resolve()
    if not exports_root.exists() or not exports_root.is_dir():
        raise FL3ValidationError(f"exports_root missing/not-a-dir (fail-closed): {exports_root.as_posix()}")

    run_root = Path(args.run_root).resolve() if args.run_root else _default_run_root(repo_root=repo_root).resolve()

    ok, failures = validate_work_orders(repo_root=repo_root, exports_root=exports_root, max_files=int(args.max_files))
    report = {
        "schema_id": "kt.work_order_validation_report.v1",
        "exports_root": str(exports_root.as_posix()),
        "counts": {"ok": len(ok), "failures": len(failures)},
        "ok": ok,
        "failures": failures,
    }
    out_path = run_root / "work_orders_validation_report.json"
    write_text_worm(
        path=out_path,
        text=json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="work_orders_validation_report.json",
    )
    print(out_path.as_posix())

    if failures:
        raise SystemExit("FAIL_CLOSED: one or more work orders failed schema validation")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc
