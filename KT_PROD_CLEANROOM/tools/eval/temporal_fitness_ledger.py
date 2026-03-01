from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical
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


def _safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(s).strip())[:128].strip("_") or "UNKNOWN"


def _default_ledger_root(*, repo_root: Path) -> Path:
    if os.environ.get("KT_SEAL_MODE") == "1":
        return (repo_root / "KT_PROD_CLEANROOM" / "exports" / "adapters_shadow" / "_fitness_ledger").resolve()
    return (repo_root / "KT_PROD_CLEANROOM" / "exports" / "adapters" / "_fitness_ledger").resolve()


def _region_rank(code: str) -> int:
    c = str(code).strip().upper()
    if c == "A":
        return 3
    if c == "B":
        return 2
    return 1


def _extract_world_regions(fitness: Dict[str, Any]) -> Dict[str, str]:
    wf = fitness.get("world_fitness") if isinstance(fitness.get("world_fitness"), list) else []
    out: Dict[str, str] = {}
    for row in wf:
        if not isinstance(row, dict):
            continue
        wid = str(row.get("world_id", "")).strip()
        reg = str(row.get("region", "")).strip().upper()
        if wid and reg in {"A", "B", "C"}:
            out[wid] = reg
    if not out:
        _fail_closed("multiversal_fitness.world_fitness missing/invalid")
    return out


def _load_existing_entries(*, ledger_dir: Path) -> List[Tuple[Path, Dict[str, Any]]]:
    if not ledger_dir.exists():
        return []
    if not ledger_dir.is_dir():
        _fail_closed("ledger_dir exists but is not a directory")
    entries: List[Tuple[Path, Dict[str, Any]]] = []
    for p in sorted(ledger_dir.glob("*.json")):
        if not p.is_file():
            continue
        obj = _read_json_dict(p, label="ledger_entry")
        entries.append((p, obj))
    return entries


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Temporal fitness ledger (WORM, cross-run memory, promotion-blocking on regression).")
    ap.add_argument("--fitness-record", required=True, help="Path to multiversal_fitness.json.")
    ap.add_argument("--run-id", required=True, help="Run identifier (stable string; used for WORM ledger entry naming).")
    ap.add_argument("--out-dir", required=True, help="Output directory for gate artifacts (WORM; must be empty).")
    ap.add_argument("--ledger-root", default="", help="Override ledger root (default: exports/adapters(_shadow)/_fitness_ledger).")
    ap.add_argument("--no-write-ledger", action="store_true", help="Do not append to the ledger; compute gate only.")
    args = ap.parse_args(argv)

    repo_root = Path.cwd().resolve()
    fitness_path = Path(args.fitness_record).resolve()
    if not fitness_path.is_file():
        _fail_closed("fitness_record missing")
    fitness = _read_json_dict(fitness_path, label="multiversal_fitness")
    if str(fitness.get("schema_id", "")).strip() != "kt.multiversal_fitness_record.v1":
        _fail_closed("multiversal_fitness schema_id mismatch")

    adapter_id = str(fitness.get("artifact_id", "")).strip()
    if not adapter_id:
        _fail_closed("multiversal_fitness.artifact_id missing")

    run_id = str(args.run_id).strip()
    if not run_id:
        _fail_closed("run_id missing")

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    if any(out_dir.iterdir()):
        _fail_closed("out_dir is not empty (WORM directory reuse forbidden)")

    ledger_root = Path(args.ledger_root).resolve() if str(args.ledger_root).strip() else _default_ledger_root(repo_root=repo_root)
    ledger_dir = (ledger_root / _safe_name(adapter_id)).resolve()
    ledger_dir.mkdir(parents=True, exist_ok=True)

    existing = _load_existing_entries(ledger_dir=ledger_dir)

    # Snapshot existing ledger inputs for replay.
    snapshot: List[Dict[str, str]] = []
    for p, _obj in existing:
        snapshot.append({"path": p.as_posix(), "sha256": sha256_file_canonical(p)})

    current = _extract_world_regions(fitness)

    # Historical best (prior entries only).
    best: Dict[str, str] = {}
    by_world_series: Dict[str, List[str]] = {}
    for _p, obj in existing:
        try:
            regions = _extract_world_regions(obj.get("fitness_record", obj))
        except SystemExit:
            # Ignore malformed historical entry (fail-closed via admission gate later).
            continue
        for wid, reg in regions.items():
            by_world_series.setdefault(wid, []).append(reg)
            prev = best.get(wid)
            if prev is None or _region_rank(reg) > _region_rank(prev):
                best[wid] = reg

    regressed_worlds = sorted([wid for wid, reg in current.items() if wid in best and _region_rank(reg) < _region_rank(best[wid])])

    b_to_c = 0
    for wid, series in by_world_series.items():
        prev: Optional[str] = None
        for r in series:
            if prev == "B" and r == "C":
                b_to_c += 1
            prev = r

    promotion_blocked = bool(regressed_worlds)
    reason_codes = ["RC_TEMPORAL_FITNESS_REGRESSION"] if regressed_worlds else []

    gate = {
        "schema_id": "kt.temporal_fitness_gate.v1",
        "adapter_id": adapter_id,
        "run_id": run_id,
        "ledger_root": ledger_root.as_posix(),
        "ledger_snapshot": snapshot,
        "historical_best_by_world": best,
        "current_by_world": current,
        "regressed_world_ids": regressed_worlds,
        "b_to_c_transition_count": int(b_to_c),
        "promotion_blocked": bool(promotion_blocked),
        "reason_codes": reason_codes,
        "determinism_fingerprint": hashlib.sha256((adapter_id + "\n" + run_id + "\n" + str(len(snapshot))).encode("utf-8")).hexdigest(),
    }

    write_text_worm(
        path=out_dir / "temporal_fitness_gate.json",
        text=json.dumps(gate, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="temporal_fitness_gate.json",
    )

    # Append WORM ledger entry after gate is computed.
    if not bool(args.no_write_ledger):
        entry = {
            "schema_id": "kt.temporal_fitness_ledger_entry.v1",
            "adapter_id": adapter_id,
            "run_id": run_id,
            "fitness_record": fitness,
            "fitness_record_sha256": sha256_file_canonical(fitness_path),
            "determinism_fingerprint": hashlib.sha256((adapter_id + "\n" + run_id).encode("utf-8")).hexdigest(),
        }
        entry_bytes = (json.dumps(entry, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
        entry_sha = hashlib.sha256(entry_bytes).hexdigest()
        entry_name = f"{_safe_name(run_id)}__{entry_sha}.json"
        write_text_worm(
            path=ledger_dir / entry_name,
            text=entry_bytes.decode("utf-8"),
            label="temporal_fitness_ledger_entry.json",
        )

    return 0 if not promotion_blocked else 2


if __name__ == "__main__":
    raise SystemExit(main())

