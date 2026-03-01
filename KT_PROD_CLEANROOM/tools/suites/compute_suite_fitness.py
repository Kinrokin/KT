from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

from tools.verification.worm_write import write_text_worm


def _fail_closed(msg: str) -> int:
    raise SystemExit(f"FAIL_CLOSED: {msg}")


def _read_json_dict(path: Path, *, label: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"FAIL_CLOSED: unreadable JSON {label}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        _fail_closed(f"{label} must be a JSON object: {path.as_posix()}")
    return obj


def _write_json_worm(path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(path=path, text=json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", label=label)


def _region_for_pass_rate(pass_rate: float) -> str:
    # Suite fitness is about pressure: too-easy suites are low pressure and must evolve.
    if pass_rate > 0.97 or pass_rate < 0.30:
        return "C"
    if pass_rate > 0.90 or pass_rate < 0.50:
        return "B"
    return "A"


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Compute suite-level fitness (pressure) region from a suite_eval_report (deterministic; WORM).")
    ap.add_argument("--suite-eval-report", required=True, help="Path to kt.suite_eval_report.v1 JSON.")
    ap.add_argument("--out-dir", required=True, help="Output directory (WORM; must be empty).")
    args = ap.parse_args(argv)

    report_path = Path(args.suite_eval_report).resolve()
    if not report_path.is_file():
        _fail_closed("suite_eval_report missing")
    rep = _read_json_dict(report_path, label="suite_eval_report")
    if str(rep.get("schema_id", "")).strip() != "kt.suite_eval_report.v1":
        _fail_closed("suite_eval_report schema_id mismatch")

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    if any(out_dir.iterdir()):
        _fail_closed("out_dir is not empty (WORM directory reuse forbidden)")

    case_results = rep.get("case_results") if isinstance(rep.get("case_results"), list) else []
    if not case_results:
        _fail_closed("suite_eval_report.case_results missing/invalid")
    passed = sum(1 for r in case_results if isinstance(r, dict) and bool(r.get("passed", False)))
    total = len([r for r in case_results if isinstance(r, dict)])
    if total <= 0:
        _fail_closed("suite_eval_report.case_results empty")

    pass_rate = float(passed) / float(total)
    region = _region_for_pass_rate(pass_rate)

    if pass_rate > 0.97:
        action = "ESCALATE_OR_MUTATE"
    elif pass_rate < 0.30:
        action = "REVIEW_CASES_OR_THRESHOLDS"
    else:
        action = "OK"

    payload = {
        "schema_id": "kt.suite_fitness_record.v1",
        "suite_eval_report_id": str(rep.get("suite_eval_report_id", "")).strip(),
        "suite_definition_id": str(rep.get("suite_definition_id", "")).strip(),
        "case_count": int(total),
        "passed": int(passed),
        "pass_rate": pass_rate,
        "region": region,
        "recommended_action": action,
        "determinism_fingerprint": hashlib.sha256((str(total) + "\n" + str(passed)).encode("utf-8")).hexdigest(),
    }
    _write_json_worm(path=out_dir / "suite_fitness_record.json", obj=payload, label="suite_fitness_record.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

