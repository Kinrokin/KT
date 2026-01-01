from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from warehouse_schemas import TrainingExemplarSchema, WarehouseManifestSchema, sha256_json


MAX_JSON_BYTES = 512_000
MAX_YAML_BYTES = 512_000


def _read_json_object(path: Path) -> Dict[str, Any]:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("json_too_large (fail-closed)")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("json_not_object (fail-closed)")
    return dict(data)


def _extract_prompt_from_crucible_yaml(path: Path) -> str:
    # Minimal, deterministic extractor for the prompt block:
    # input:
    #   prompt: |
    #     ...
    if path.stat().st_size > MAX_YAML_BYTES:
        raise ValueError("crucible_yaml_too_large (fail-closed)")
    text = path.read_text(encoding="utf-8", errors="strict")
    lines = text.splitlines()
    in_prompt = False
    prompt_lines: list[str] = []
    prompt_indent: Optional[int] = None
    for line in lines:
        if not in_prompt:
            if line.rstrip() == "prompt: |" or line.strip() == "prompt: |":
                in_prompt = True
                prompt_indent = None
                continue
            continue
        # After prompt: |, capture indented block until indentation ends.
        if prompt_indent is None:
            if not line.strip():
                prompt_lines.append("")
                continue
            prompt_indent = len(line) - len(line.lstrip(" "))
        if line.strip() and (len(line) - len(line.lstrip(" "))) < (prompt_indent or 0):
            break
        prompt_lines.append(line[(prompt_indent or 0) :])
    return "\n".join(prompt_lines).strip("\n")


def _ensure_under_root(*, path: Path, root: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except Exception:
        raise ValueError(f"{label}_not_under_root (fail-closed)")


def _read_last_jsonl_line(path: Path, *, max_bytes: int = 64_000) -> Optional[str]:
    if not path.exists():
        return None
    size = path.stat().st_size
    read_size = min(size, max_bytes)
    with path.open("rb") as f:
        f.seek(size - read_size)
        chunk = f.read(read_size).decode("utf-8", errors="strict")
    lines = [ln for ln in chunk.splitlines() if ln.strip()]
    return lines[-1] if lines else None


def create_exemplar_from_c019_run(
    *,
    artifacts_root: Path,
    kernel_target: str,
    epoch_id: str,
    crucible_id: str,
    run_id: str,
    crucible_spec_path: Path,
    c019_run_dir: Path,
    license: str = "INTERNAL_ONLY",
) -> Tuple[TrainingExemplarSchema, Path]:
    # Path discipline: bind to expected roots (no traversal / no surprises).
    _ensure_under_root(path=crucible_spec_path.resolve(), root=Path("KT_PROD_CLEANROOM/tools/growth/crucibles").resolve(), label="crucible_spec_path")
    _ensure_under_root(path=c019_run_dir.resolve(), root=Path("KT_PROD_CLEANROOM/tools/growth/artifacts/c019_runs").resolve(), label="c019_run_dir")
    _ensure_under_root(path=artifacts_root.resolve(), root=Path("KT_PROD_CLEANROOM/tools/growth/artifacts/training_warehouse").resolve(), label="warehouse_artifacts_root")

    # Read metadata-only evidence from C019 run directory.
    replay = _read_json_object(c019_run_dir / "replay_report.json")
    gov = _read_json_object(c019_run_dir / "governance_report.json")

    prompt = _extract_prompt_from_crucible_yaml(crucible_spec_path)
    exemplar = TrainingExemplarSchema.make(
        kernel_target=kernel_target,
        epoch_id=epoch_id,
        crucible_id=crucible_id,
        run_id=run_id,
        provenance={
            "artifacts_dir": c019_run_dir.as_posix(),
            "replay_head_hash": str(replay.get("head_hash", "")),
            "record_count": int(replay.get("record_count", 0)),
            "governance_types": ",".join(str(t) for t in (gov.get("types") or [])),
        },
        extraction_justification="C024 bootstrap exemplar: warehouse format + provenance binding (no kernel output text stored).",
        license=license,
        usage_flags={"allow_training": True, "allow_distillation": True},
        content={
            "prompt": prompt,
            "expected_outcome": "PASS",
            "notes": "Governance honesty prompt (safe).",
        },
    )

    # Write exemplar JSON (append-only: do not overwrite).
    exemplar_dir = artifacts_root / "exemplars"
    exemplar_dir.mkdir(parents=True, exist_ok=True)
    out_path = exemplar_dir / f"{exemplar.exemplar_id}.json"
    if out_path.exists():
        # Idempotence: validate existing exemplar matches the computed ID/hash.
        existing = _read_json_object(out_path)
        ex2 = TrainingExemplarSchema.from_dict(existing)
        if ex2.exemplar_id != exemplar.exemplar_id or ex2.exemplar_hash != exemplar.exemplar_hash:
            raise ValueError("existing_exemplar_mismatch (fail-closed)")
        return ex2, out_path
    out_path.write_text(json.dumps(exemplar.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True), encoding="utf-8")
    return exemplar, out_path


def append_manifest_record(*, manifest_path: Path, record: Mapping[str, Any]) -> None:
    # Append-only JSONL.
    line = json.dumps(dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(line + "\n")
        handle.flush()


def append_chained_ledger(*, ledger_path: Path, payload: Mapping[str, Any]) -> None:
    # Minimal chaining for tamper-evidence: each record includes prev_record_hash + record_hash.
    last = _read_last_jsonl_line(ledger_path)
    prev_hash = "0" * 64
    if last is not None:
        obj = json.loads(last)
        if not isinstance(obj, dict) or "record_hash" not in obj:
            raise ValueError("ledger_tail_malformed (fail-closed)")
        prev_hash = str(obj.get("record_hash"))
    record = dict(payload)
    record["prev_record_hash"] = prev_hash
    record_hash = sha256_json(record)
    record["record_hash"] = record_hash
    line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(line + "\n")
        handle.flush()


def append_exemplar_to_warehouse(*, artifacts_root: Path, exemplar_path: Path) -> bool:
    exemplar_obj = _read_json_object(exemplar_path)
    exemplar = TrainingExemplarSchema.from_dict(exemplar_obj)
    bytes_len = exemplar_path.stat().st_size
    record = WarehouseManifestSchema.from_exemplar(exemplar=exemplar, bytes_len=bytes_len).to_dict()

    manifest_path = artifacts_root / "warehouse_manifest.jsonl"
    # Idempotence: refuse duplicate exemplar IDs in the manifest.
    if manifest_path.exists():
        for ln in manifest_path.read_text(encoding="utf-8").splitlines():
            if not ln.strip():
                continue
            obj = json.loads(ln)
            if isinstance(obj, dict) and obj.get("exemplar_id") == exemplar.exemplar_id:
                return False
    append_manifest_record(manifest_path=manifest_path, record=record)
    # Also append chained ledger record.
    ledger_path = artifacts_root / "warehouse_ledger_chained.jsonl"
    append_chained_ledger(
        ledger_path=ledger_path,
        payload={
            "schema": "kt.training.warehouse.ledger_record",
            "schema_version": 1,
            "manifest_record": record,
        },
    )
    return True
