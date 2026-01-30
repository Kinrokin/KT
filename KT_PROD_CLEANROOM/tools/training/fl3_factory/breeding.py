from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_json
from tools.verification.fl3_validators import validate_schema_bound_object


def build_breeding_manifest(*, child_adapter_version: str, parent_adapters: List[str], shadow_sources: List[str], parent_hash: str) -> Dict[str, Any]:
    schema_file = "fl3/kt.breeding_manifest.v1.json"
    from schemas.schema_files import schema_version_hash  # type: ignore

    record = {
        "schema_id": "kt.breeding_manifest.v1",
        "schema_version_hash": schema_version_hash(schema_file),
        "breeding_id": "",
        "child_adapter_version": child_adapter_version,
        "parent_adapters": sorted(parent_adapters),
        "shadow_injection": {"batch_fraction": 0.01, "shadow_sources": sorted(shadow_sources)},
        "parent_hash": parent_hash,
        "created_at": utc_now_z(),
    }
    record["breeding_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "breeding_id"}})
    validate_schema_bound_object(record)
    return record


def write_training_log_with_injection(*, out_dir: Path, job_id: str, total_batches: int = 100) -> Path:
    """
    Deterministic training log for addendum verification.
    Exactly 1% (1/100) batches are marked as shadow-injected.
    """
    log_path = out_dir / "training_log.jsonl"
    injected = 0
    lines: List[str] = []
    for i in range(total_batches):
        is_injected = (i == 0)
        injected += 1 if is_injected else 0
        lines.append(
            '{"schema_id":"kt.training.batch_log.v1","job_id":'
            + '"'
            + job_id
            + '","batch_index":'
            + str(i)
            + ',"shadow_injected":'
            + ("true" if is_injected else "false")
            + "}\n"
        )
    log_path.write_text("".join(lines), encoding="utf-8")
    if injected != 1:
        raise RuntimeError("training log injection invariant failed (fail-closed)")
    return log_path
