from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from distill_schemas import DistillationConfigSchema, ModelArtifactSchema, TrainingRunManifestSchema, sha256_json


MAX_JSON_BYTES = 512_000
MAX_JSONL_BYTES = 5_000_000


def _read_json_object(path: Path) -> Dict[str, Any]:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("json_too_large (fail-closed)")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("json_not_object (fail-closed)")
    return dict(data)


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if path.stat().st_size > MAX_JSONL_BYTES:
        raise ValueError("jsonl_too_large (fail-closed)")
    lines = path.read_text(encoding="utf-8").splitlines()
    out: List[Dict[str, Any]] = []
    for ln in lines:
        if not ln.strip():
            continue
        obj = json.loads(ln)
        if not isinstance(obj, dict):
            raise ValueError("jsonl_not_object (fail-closed)")
        out.append(dict(obj))
    return out


def _ensure_under_root(*, path: Path, root: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except Exception:
        raise ValueError(f"{label}_not_under_root (fail-closed)")


def _read_last_jsonl_line(path: Path, *, max_bytes: int = 64_000) -> str | None:
    if not path.exists():
        return None
    size = path.stat().st_size
    read_size = min(size, max_bytes)
    with path.open("rb") as f:
        f.seek(size - read_size)
        chunk = f.read(read_size).decode("utf-8", errors="strict")
    lines = [ln for ln in chunk.splitlines() if ln.strip()]
    return lines[-1] if lines else None


def _append_chained_ledger(*, ledger_path: Path, payload: Dict[str, Any]) -> None:
    last = _read_last_jsonl_line(ledger_path)
    prev_hash = "0" * 64
    if last is not None:
        obj = json.loads(last)
        if not isinstance(obj, dict) or "record_hash" not in obj:
            raise ValueError("ledger_tail_malformed (fail-closed)")
        prev_hash = str(obj.get("record_hash"))
    record = dict(payload)
    record["prev_record_hash"] = prev_hash
    record["record_hash"] = sha256_json(record)
    line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(line + "\n")
        handle.flush()


def main() -> int:
    ap = argparse.ArgumentParser(description="C025 distillation (tooling-only; deterministic; no training execution)")
    ap.add_argument("--warehouse-manifest", required=True, help="Path to C024 warehouse_manifest.jsonl")
    ap.add_argument("--out-dir", required=True, help="Output directory under tools/growth/artifacts/distillation/")
    ap.add_argument("--config-id", default="DISTILL-0001", help="Distillation config ID")
    ap.add_argument("--max-exemplars", type=int, default=1000, help="Max exemplars to include")
    ap.add_argument("--allow-existing", action="store_true", help="If output dir exists, validate contents match computed hashes and exit 0")
    args = ap.parse_args()

    warehouse_manifest = Path(args.warehouse_manifest).resolve()
    out_dir = Path(args.out_dir).resolve()
    _ensure_under_root(
        path=warehouse_manifest,
        root=Path("KT_PROD_CLEANROOM/tools/growth/artifacts/training_warehouse").resolve(),
        label="warehouse_manifest",
    )
    _ensure_under_root(
        path=out_dir,
        root=Path("KT_PROD_CLEANROOM/tools/growth/artifacts/distillation").resolve(),
        label="out_dir",
    )

    config = DistillationConfigSchema.make(
        config_id=str(args.config_id),
        max_exemplars=int(args.max_exemplars),
        toolchain={"name": "C025_METADATA_ONLY", "version": "1", "notes": "No training executed; artifact is provenance+hash bundle."},
    )

    records = _read_jsonl(warehouse_manifest)
    exemplar_ids: List[str] = []
    exemplar_hashes: List[str] = []
    for rec in records[: config.max_exemplars]:
        exemplar_ids.append(str(rec.get("exemplar_id")))
        exemplar_hashes.append(str(rec.get("exemplar_hash")))

    run_id = sha256_json({"config_hash": config.config_hash, "warehouse_manifest": warehouse_manifest.as_posix(), "exemplar_ids": exemplar_ids})
    run_manifest = TrainingRunManifestSchema.make(
        run_id=run_id,
        config=config,
        warehouse_manifest_path=warehouse_manifest.as_posix(),
        exemplar_ids=exemplar_ids,
        exemplar_hashes=exemplar_hashes,
    )
    artifact = ModelArtifactSchema.make(run_manifest=run_manifest)

    # Append-only discipline: refuse to overwrite.
    if out_dir.exists():
        if not args.allow_existing:
            raise SystemExit("refuse_overwrite (fail-closed)")
        existing_run = TrainingRunManifestSchema.from_dict(_read_json_object(out_dir / "run_manifest.json"))
        existing_art = ModelArtifactSchema.from_dict(_read_json_object(out_dir / "model_artifact.json"))
        existing_cfg = DistillationConfigSchema.from_dict(_read_json_object(out_dir / "distill_config.json"))
        if existing_cfg.config_hash != config.config_hash:
            raise SystemExit("existing_config_mismatch (fail-closed)")
        if existing_run.run_id != run_manifest.run_id or existing_run.run_hash != run_manifest.run_hash:
            raise SystemExit("existing_run_manifest_mismatch (fail-closed)")
        if existing_art.artifact_hash != artifact.artifact_hash:
            raise SystemExit("existing_artifact_mismatch (fail-closed)")
        return 0
    out_dir.mkdir(parents=True, exist_ok=False)

    (out_dir / "distill_config.json").write_text(json.dumps(config.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True), encoding="utf-8")
    (out_dir / "run_manifest.json").write_text(json.dumps(run_manifest.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True), encoding="utf-8")
    (out_dir / "model_artifact.json").write_text(json.dumps(artifact.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True), encoding="utf-8")

    # Append chained ledger (tooling-side only).
    ledger_path = Path("KT_PROD_CLEANROOM/tools/growth/artifacts/distillation/distillation_ledger_chained.jsonl").resolve()
    _append_chained_ledger(
        ledger_path=ledger_path,
        payload={
            "schema": "kt.distill.ledger_record",
            "schema_version": 1,
            "run_dir": out_dir.as_posix(),
            "run_hash": run_manifest.run_hash,
            "artifact_hash": artifact.artifact_hash,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
