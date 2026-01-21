from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from core.runtime_registry import load_runtime_registry
from policy_c.static_safety_check import assert_export_root_allowed, policy_c_module_paths, run_static_safety_check


DATASET_RECORD_SCHEMA_ID = "kt.policy_c.dataset_record.v1"
DATASET_MANIFEST_SCHEMA_ID = "kt.policy_c.dataset_manifest.v1"


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _hashable_record(record: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(record)
    data.pop("timestamp", None)
    return data


def _hashable_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(manifest)
    data.pop("created_at", None)
    data.pop("manifest_hash", None)
    return data


def export_dataset(*, sweep_result_path: Path, out_root: Path) -> Dict[str, Any]:
    registry = load_runtime_registry()
    assert_export_root_allowed(out_root, registry.policy_c.sweep.allowed_export_roots)
    safety = run_static_safety_check(
        registry=registry,
        module_paths=policy_c_module_paths(),
        schema_paths=[
            Path(__file__).resolve().parent / "policy_c_dataset_record_schema_v1.json",
            Path(__file__).resolve().parent / "policy_c_dataset_manifest_schema_v1.json",
        ],
    )
    if not safety.ok:
        raise RuntimeError(f"Static safety check failed (fail-closed): {safety.errors}")

    sweep = _load_json(sweep_result_path)
    run_results = sweep.get("run_results") or []
    records: List[Dict[str, Any]] = []

    for entry in run_results:
        epoch_summary = _load_json(Path(entry["paths"]["epoch_summary"]))
        drift_report = _load_json(Path(entry["paths"]["drift_report"]))
        pressure_tensor = _load_json(Path(entry["paths"]["pressure_tensor"]))

        record = {
            "schema_id": DATASET_RECORD_SCHEMA_ID,
            "sweep_id": sweep["sweep_id"],
            "run_id": entry["run_id"],
            "epoch_id": entry["epoch_id"],
            "timestamp": epoch_summary["timestamp_utc"],
            "pressure_tensor_ref": {
                "path": entry["paths"]["pressure_tensor"],
                "hash": entry["hashes"]["pressure_tensor_hash"],
            },
            "epoch_summary_ref": {
                "path": entry["paths"]["epoch_summary"],
                "hash": entry["hashes"]["summary_hash"],
            },
            "drift_report_ref": {
                "path": entry["paths"]["drift_report"],
                "hash": entry["hashes"]["drift_report_hash"],
            },
            "labels": {
                "status": entry["status"],
                "reason_codes": entry.get("reason_codes", []),
            },
        }
        records.append(record)

    out_root.mkdir(parents=True, exist_ok=True)
    records_path = out_root / "kt_policy_c_dataset_v1.jsonl"
    with records_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    records_hash = _sha256_text(_canonical_json([_hashable_record(r) for r in records]))

    # Use sweep finished_at for deterministic manifests; timestamps are non-hash fields.
    created_at = sweep.get("finished_at") or _timestamp()
    manifest = {
        "schema_id": DATASET_MANIFEST_SCHEMA_ID,
        "dataset_id": f"{sweep['sweep_id']}.policy_c.v1",
        "created_at": created_at,
        "sweep_id": sweep["sweep_id"],
        "record_schema_id": DATASET_RECORD_SCHEMA_ID,
        "manifest_schema_id": DATASET_MANIFEST_SCHEMA_ID,
        "counts": {
            "records": len(records),
        },
        "records_path": records_path.as_posix(),
        "records_hash": records_hash,
        "export_root": out_root.as_posix(),
    }
    manifest_hash = _sha256_text(_canonical_json(_hashable_manifest(manifest)))
    manifest["manifest_hash"] = manifest_hash

    manifest_path = out_root / "kt_policy_c_dataset_manifest_v1.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True), encoding="utf-8")
    return manifest


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Policy C dataset export (deterministic; no network).")
    p.add_argument("--sweep-result", type=Path, required=True, help="Sweep result JSON path.")
    p.add_argument("--out-root", type=Path, required=True, help="Export root (allowlisted).")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    export_dataset(sweep_result_path=args.sweep_result, out_root=args.out_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
