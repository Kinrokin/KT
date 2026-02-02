from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Set


@dataclass(frozen=True)
class CheckpointRecord:
    crucible_id: str
    run_id: str
    outcome: str
    status: str

    def to_dict(self) -> Dict[str, str]:
        return {"crucible_id": self.crucible_id, "run_id": self.run_id, "outcome": self.outcome, "status": self.status}


def append_checkpoint(path: Path, record: CheckpointRecord) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")


def _iter_records(path: Path) -> Iterable[Dict[str, str]]:
    if not path.exists():
        return []
    records: List[Dict[str, str]] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            if isinstance(obj, dict):
                records.append(obj)
    return records


def completed_crucible_ids(path: Path) -> Set[str]:
    completed: Set[str] = set()
    for rec in _iter_records(path):
        if rec.get("status") == "DONE" and isinstance(rec.get("crucible_id"), str):
            completed.add(rec["crucible_id"])
    return completed


def completed_crucible_run_ids(path: Path) -> Dict[str, str]:
    completed: Dict[str, str] = {}
    for rec in _iter_records(path):
        cid = rec.get("crucible_id")
        rid = rec.get("run_id")
        if rec.get("status") == "DONE" and isinstance(cid, str) and isinstance(rid, str):
            completed[cid] = rid
    return completed
