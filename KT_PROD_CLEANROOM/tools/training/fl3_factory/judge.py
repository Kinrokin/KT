from __future__ import annotations

from typing import Any, Dict, List

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_json


def _schema_hash(schema_file: str) -> str:
    from schemas.schema_files import schema_version_hash  # type: ignore

    return schema_version_hash(schema_file)


def build_judgement(*, job: Dict[str, Any], dataset: Dict[str, Any]) -> Dict[str, Any]:
    """
    Minimal real judge:
    - STANDARD: accept all rows (deterministic)
    - TOURNAMENT: accept the first row only (deterministic, blind)
    """
    rows = dataset.get("rows") if isinstance(dataset.get("rows"), list) else []
    run_kind = str(job.get("run_kind", "STANDARD"))

    accepted: List[str] = []
    rejected: List[str] = []
    if run_kind == "TOURNAMENT":
        if len(rows) > 0:
            rid0 = rows[0].get("row_id") if isinstance(rows[0], dict) else None
            if not isinstance(rid0, str):
                rid0 = "0000"
            accepted = [rid0]
            rejected = []
            for row in rows[1:]:
                rid = row.get("row_id") if isinstance(row, dict) else None
                if isinstance(rid, str):
                    rejected.append(rid)
    else:
        for row in rows:
            rid = row.get("row_id") if isinstance(row, dict) else None
            if isinstance(rid, str):
                accepted.append(rid)
        rejected = []

    # Canonical ordering: tests enforce that accepted_row_ids are sorted.
    accepted = sorted(accepted)
    rejected = sorted(rejected)

    record = {
        "schema_id": "kt.factory.judgement.v1",
        "schema_version_hash": _schema_hash("fl3/kt.factory.judgement.v1.json"),
        "judgement_id": "",
        "job_id": job["job_id"],
        "dataset_id": dataset["dataset_id"],
        "accepted_row_ids": accepted,
        "rejected_row_ids": rejected,
        "judge_ref": "kt.judge.min_real.v1",
        "created_at": utc_now_z(),
    }
    record["judgement_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "judgement_id"}})
    return record
