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
    ap.add_argument("--mode", choices=["mve0", "mve1"], default="mve0", help="Admission mode (default: mve0).")
    ap.add_argument("--mve-dir", required=True, help="Directory containing MVE artifacts (run_root/.../mve).")
    ap.add_argument("--titan-gate", default="", help="Path to titan_promotion_gate.json (required for mve1).")
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
    if str(args.mode) == "mve1":
        required += [
            "multiversal_output_stubs.jsonl",
            "mve_drift_report.json",
            "mve_capture_resistance_report.json",
        ]
    missing = [name for name in required if not (mve_dir / name).is_file()]

    titan_gate_path = Path(str(args.titan_gate)).resolve() if str(args.titan_gate).strip() else None
    titan_gate_missing = False
    titan_gate_blocked = False
    if str(args.mode) == "mve1":
        if titan_gate_path is None:
            titan_gate_missing = True
        elif not titan_gate_path.is_file():
            titan_gate_missing = True
        else:
            tg = _read_json(titan_gate_path)
            if not isinstance(tg, dict) or tg.get("schema_id") != "kt.titan_promotion_gate.v1":
                _fail_closed("titan_gate schema_id mismatch")
            titan_gate_blocked = bool(tg.get("promotion_blocked", False))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if any(out_dir.iterdir()):
        _fail_closed("out_dir is not empty (WORM directory reuse forbidden)")

    reason_codes: List[str] = []
    if missing:
        reason_codes.append("MVE_ARTIFACTS_MISSING")
    if titan_gate_missing:
        reason_codes.append("TITAN_GATE_MISSING")
    if titan_gate_blocked:
        reason_codes.append("TITAN_GATE_BLOCKED")

    rec = {
        "schema_id": "kt.mve_admission_record.v1",
        "mode": str(args.mode),
        "mve_dir": str(mve_dir.as_posix()),
        "status": ("PASS" if (not missing and not titan_gate_missing and not titan_gate_blocked) else "REJECTED_AT_ADMISSION"),
        "missing": missing,
        "titan_gate_path": (titan_gate_path.as_posix() if titan_gate_path is not None else ""),
        "reason_codes": reason_codes,
    }
    _write_json_worm(path=out_dir / "mve_admission_record.json", obj=rec, label="mve_admission_record.json")
    return 0 if rec["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
