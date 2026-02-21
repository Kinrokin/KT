from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from tools.verification.worm_write import write_text_worm


def _fail_closed(msg: str) -> int:
    raise SystemExit(f"FAIL_CLOSED: {msg}")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json_worm(path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(path=path, text=json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", label=label)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="MVE admission gate (consumes MVE artifacts; fail-closed).")
    ap.add_argument("--mve-dir", required=True, help="Directory containing MVE artifacts (run_root/.../mve).")
    ap.add_argument("--out-dir", required=True, help="Output directory for admission record (WORM).")
    args = ap.parse_args(argv)

    mve_dir = Path(args.mve_dir)
    if not mve_dir.is_dir():
        _fail_closed("mve_dir missing")

    required = [
        "world_set.json",
        "multiversal_results.jsonl",
        "multiversal_conflicts.jsonl",
        "multiversal_fitness.json",
        "mve_summary.json",
        "mve_sha256_manifest.json",
    ]
    missing = [name for name in required if not (mve_dir / name).is_file()]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if any(out_dir.iterdir()):
        _fail_closed("out_dir is not empty (WORM directory reuse forbidden)")

    rec = {
        "schema_id": "kt.mve_admission_record.v1",
        "mve_dir": str(mve_dir.as_posix()),
        "status": "PASS" if not missing else "REJECTED_AT_ADMISSION",
        "missing": missing,
        "reason_codes": (["MVE_ARTIFACTS_MISSING"] if missing else []),
    }
    _write_json_worm(path=out_dir / "mve_admission_record.json", obj=rec, label="mve_admission_record.json")
    return 0 if not missing else 2


if __name__ == "__main__":
    raise SystemExit(main())

