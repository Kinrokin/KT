from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_json


def _schema_hash(schema_file: str) -> str:
    from schemas.schema_files import schema_version_hash  # type: ignore

    return schema_version_hash(schema_file)


def _row_text(*, job: Dict[str, Any], index: int) -> str:
    role = str(job.get("role", "UNKNOWN"))
    adapter_id = str(job.get("adapter_id", "unknown"))
    seed = int(job.get("seed", 0))
    return f"{role}|{adapter_id}|seed={seed}|i={index}"


def _row_label(text: str) -> int:
    # Deterministic label derived from content (no RNG).
    b = hashlib.sha256(text.encode("utf-8")).digest()
    return int(b[0] % 2)


def build_dataset(*, job: Dict[str, Any]) -> Dict[str, Any]:
    """
    Minimal real harvest (MRT-0/1 compatible):
    - deterministic rows (no network, no providers)
    - enough rows to support tiny training/eval in SMOKE mode

    For TOURNAMENT, emit blindable rows (hash-only) to preserve blindness discipline.
    """
    run_kind = str(job.get("run_kind", "STANDARD"))

    rows: List[dict] = []
    if run_kind == "TOURNAMENT":
        # Tournament judge must never see identity. Use hashes only.
        for i in range(8):
            row_id = f"{i:04d}"
            prompt_hash = sha256_json({"p": f"prompt_{i}", "seed": int(job.get("seed", 0))})
            candidate_hash = sha256_json({"prompt_hash": prompt_hash, "c": f"candidate_{i}"})
            # Provide deterministic "text/label" derived only from hashes so train/eval can run without identity leakage.
            derived_text = f"{prompt_hash}:{candidate_hash}"
            rows.append(
                {
                    "row_id": row_id,
                    "prompt_hash": prompt_hash,
                    "candidate_hash": candidate_hash,
                    "text": derived_text,
                    "label": _row_label(derived_text),
                }
            )
    else:
        # Use more than 1 row to make training/eval non-trivial but still cheap.
        mode = str(job.get("mode", "SMOKE"))
        n = 32 if mode == "SMOKE" else 128
        for i in range(n):
            text = _row_text(job=job, index=i)
            rows.append(
                {
                    "row_id": f"{i:04d}",
                    "text": text,
                    "label": _row_label(text),
                }
            )

    record = {
        "schema_id": "kt.factory.dataset.v1",
        "schema_version_hash": _schema_hash("fl3/kt.factory.dataset.v1.json"),
        "dataset_id": "",
        "job_id": job["job_id"],
        "rows": rows,
        "created_at": utc_now_z(),
    }
    record["dataset_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "dataset_id"}})
    return record
