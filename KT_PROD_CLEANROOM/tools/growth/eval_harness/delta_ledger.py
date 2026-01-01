from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Optional, Tuple

from eval_schemas import LearningDeltaSchema, sha256_json


def _read_last_jsonl_record(path: Path) -> Optional[Dict[str, object]]:
    if not path.exists() or path.stat().st_size == 0:
        return None
    with path.open("rb") as handle:
        handle.seek(0, 2)
        end = handle.tell()
        # Read up to last 64KB; records are small and bounded.
        window = min(end, 64 * 1024)
        handle.seek(end - window, 0)
        chunk = handle.read(window)
    # Split lines safely; tolerate trailing newline.
    lines = [ln for ln in chunk.splitlines() if ln.strip()]
    if not lines:
        return None
    last = lines[-1].decode("utf-8", errors="strict")
    obj = json.loads(last)
    if not isinstance(obj, dict):
        raise ValueError("Delta ledger last record is not an object (fail-closed)")
    return obj


def append_delta(*, ledger_path: Path, delta: LearningDeltaSchema) -> Dict[str, object]:
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    prev = _read_last_jsonl_record(ledger_path)
    prev_hash = prev.get("record_hash") if isinstance(prev, dict) else None
    if prev is not None and not isinstance(prev_hash, str):
        raise ValueError("Delta ledger missing record_hash in last record (fail-closed)")

    record = {
        "prev_record_hash": prev_hash,
        "delta_id": delta.delta_id,
        "baseline_run_id": delta.baseline_run_id,
        "candidate_run_id": delta.candidate_run_id,
        "per_metric_deltas": delta.per_metric_deltas,
        "confidence": delta.confidence,
        "suite_hash": delta.suite_hash,
        "provenance_refs": list(delta.provenance_refs),
    }
    record_hash = sha256_json(record)
    record["record_hash"] = record_hash
    with ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
    return record
