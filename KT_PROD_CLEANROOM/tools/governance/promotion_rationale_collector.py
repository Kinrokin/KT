from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import write_text_worm


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"Unable to read JSON (fail-closed): {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"Expected JSON object (fail-closed): {path.as_posix()}")
    return obj


def build_promotion_rationale(
    *, job_id: str, lane_id: str, decision: str, summary: str, evidence_paths: List[str], created_at: str
) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "schema_id": "kt.promotion_rationale.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.promotion_rationale.v1.json"),
        "rationale_id": "",
        "job_id": str(job_id),
        "lane_id": str(lane_id),
        "decision": str(decision).upper(),
        "summary": str(summary),
        "evidence_paths": sorted({p.strip() for p in evidence_paths if isinstance(p, str) and p.strip()}),
        "created_at": created_at,
        "notes": None,
    }
    obj["rationale_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "rationale_id"})
    validate_schema_bound_object(obj)
    return obj


def ensure_promotion_rationale_for_job_dir(*, job_dir: Path, lane_id: str = "FL4_SEAL") -> Dict[str, Any]:
    job_dir = job_dir.resolve()
    job = _read_json(job_dir / "job.json")
    promotion = _read_json(job_dir / "promotion.json") if (job_dir / "promotion.json").exists() else {}
    eval_report = _read_json(job_dir / "eval_report.json") if (job_dir / "eval_report.json").exists() else {}

    job_id = str(job.get("job_id", "")).strip()
    decision = str(promotion.get("decision", "UNKNOWN")).strip().upper() or "UNKNOWN"
    verdict = str(eval_report.get("final_verdict", "UNKNOWN")).strip()
    utility_floor_pass = eval_report.get("utility_floor_pass")
    summary = f"promotion_decision={decision}; final_verdict={verdict}; utility_floor_pass={utility_floor_pass}"

    created_at = _utc_now_z()
    evidence_paths = [
        "job.json",
        "promotion.json",
        "eval_report.json",
        "judgement.json",
        "hash_manifest.json",
        "job_dir_manifest.json",
    ]
    obj = build_promotion_rationale(
        job_id=job_id,
        lane_id=lane_id,
        decision=decision,
        summary=summary,
        evidence_paths=evidence_paths,
        created_at=created_at,
    )
    out_path = job_dir / "promotion_rationale.json"
    write_text_worm(
        path=out_path,
        text=json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="promotion_rationale.json",
    )
    return obj


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Emit a schema-bound promotion rationale manifest for a job_dir.")
    ap.add_argument("--job-dir", required=True)
    ap.add_argument("--lane-id", default="FL4_SEAL")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    obj = ensure_promotion_rationale_for_job_dir(job_dir=Path(args.job_dir), lane_id=str(args.lane_id))
    print(json.dumps({"status": "PASS", "rationale_id": obj.get("rationale_id")}, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc

