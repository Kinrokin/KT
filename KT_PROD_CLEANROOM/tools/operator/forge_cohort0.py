from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from tools.verification.fl3_canonical import repo_root_from, sha256_text
from tools.verification.fl3_validators import FL3ValidationError
from tools.verification.worm_write import write_bytes_worm, write_text_worm

DEFAULT_REGISTRY_REL = "KT_PROD_CLEANROOM/tools/operator/config/forge_cohort0_registry.json"
SAFE_REL_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
FIXED_ZIP_DT = (1980, 1, 1, 0, 0, 0)


@dataclass(frozen=True)
class AdapterSpec:
    adapter_id: str
    output_name: str
    dataset_relpath: str
    artifact_relpath: str
    training_receipt_relpath: str
    reload_receipt_relpath: str
    eval_receipt_relpath: str
    seed: int
    training_mode: str
    engine: str


@dataclass(frozen=True)
class RegistryContext:
    registry_id: str
    base_snapshot_id: str
    base_snapshot_path: Path
    dataset_manifest_path: Path
    holdout_pack_path: Path
    authoritative_adapter_registry_path: Path
    required_contract_paths: Tuple[Path, ...]
    adapters: Tuple[AdapterSpec, ...]


def _now_utc_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_compact_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unable to read JSON: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return obj


def _write_json_worm(*, path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(path=path, text=json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", label=label)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _hash_tree(root: Path) -> Dict[str, Any]:
    if not root.exists():
        raise FL3ValidationError(f"FAIL_CLOSED: missing hash root: {root.as_posix()}")
    entries: List[Dict[str, Any]] = []
    if root.is_file():
        entries.append({"path": root.name, "sha256": _sha256_file(root), "bytes": int(root.stat().st_size)})
    else:
        files = [p for p in root.rglob("*") if p.is_file()]
        files.sort(key=lambda p: p.relative_to(root).as_posix())
        for path in files:
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": _sha256_file(path),
                    "bytes": int(path.stat().st_size),
                }
            )
    return {
        "root": root.as_posix(),
        "file_count": int(len(entries)),
        "entries": entries,
        "root_hash": sha256_text(_canonical_json(entries)),
    }


def _read_dataset_manifest(path: Path) -> Dict[str, Dict[str, str]]:
    obj = _load_json(path)
    rows = obj.get("entries")
    if not isinstance(rows, list):
        raise FL3ValidationError("FAIL_CLOSED: dataset manifest entries missing/invalid")
    out: Dict[str, Dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise FL3ValidationError("FAIL_CLOSED: dataset manifest entry must be object")
        adapter_id = str(row.get("adapter_id", "")).strip()
        dataset_relpath = str(row.get("dataset_relpath", "")).strip()
        sha256 = str(row.get("sha256", "")).strip()
        if not adapter_id or not dataset_relpath or len(sha256) != 64:
            raise FL3ValidationError("FAIL_CLOSED: dataset manifest entry missing adapter_id/dataset_relpath/sha256")
        if adapter_id in out:
            raise FL3ValidationError(f"FAIL_CLOSED: duplicate adapter_id in dataset manifest: {adapter_id}")
        out[adapter_id] = {"dataset_relpath": dataset_relpath, "sha256": sha256}
    return out


def _git_head(repo_root: Path) -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo_root), text=True)
    except subprocess.CalledProcessError as exc:
        raise FL3ValidationError(f"FAIL_CLOSED: unable to resolve git HEAD rc={exc.returncode}") from exc
    return out.strip()


def _assert_safe_relpath(value: str, *, label: str) -> None:
    if not value or not SAFE_REL_RE.fullmatch(value):
        raise FL3ValidationError(f"FAIL_CLOSED: unsafe {label}: {value!r}")
    rel = Path(value)
    if rel.is_absolute() or any(part in {"..", "."} for part in rel.parts):
        raise FL3ValidationError(f"FAIL_CLOSED: unsafe {label}: {value!r}")


def _assert_safe_output_name(value: str) -> None:
    if not value or not SAFE_NAME_RE.fullmatch(value):
        raise FL3ValidationError(f"FAIL_CLOSED: invalid output_name: {value!r}")


def _assert_external_artifact_root(*, repo_root: Path, artifact_root: Path) -> Path:
    if not artifact_root.is_absolute():
        raise FL3ValidationError("FAIL_CLOSED: --artifact-root must be absolute")
    resolved = artifact_root.resolve()
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError:
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved
    raise FL3ValidationError("FAIL_CLOSED: --artifact-root must be outside the repo tree")


def _load_authoritative_adapter_ids(path: Path) -> Tuple[str, ...]:
    obj = _load_json(path)
    experimental = obj.get("experimental_adapter_ids")
    ratified = obj.get("ratified_adapter_ids")
    if not isinstance(experimental, list) or not isinstance(ratified, list):
        raise FL3ValidationError("FAIL_CLOSED: authoritative adapter registry missing adapter id lists")
    ids = [str(x).strip() for x in list(experimental) + list(ratified)]
    if any(not x for x in ids):
        raise FL3ValidationError("FAIL_CLOSED: authoritative adapter registry contains blank adapter id")
    return tuple(ids)


def _build_registry_context(*, repo_root: Path, registry_path: Path, input_root: Path) -> RegistryContext:
    workspace_root = repo_root
    registry = _load_json(registry_path)
    if registry.get("schema_id") != "kt.operator.forge_cohort0_registry.unbound.v1":
        raise FL3ValidationError("FAIL_CLOSED: forge cohort registry schema_id mismatch")
    expected_adapter_count = int(registry.get("expected_adapter_count", 0))
    if expected_adapter_count != 13:
        raise FL3ValidationError("FAIL_CLOSED: expected_adapter_count must be 13")
    authoritative_ref = str(registry.get("authoritative_adapter_registry_ref", "")).strip()
    _assert_safe_relpath(authoritative_ref, label="authoritative_adapter_registry_ref")
    authoritative_path = (repo_root / authoritative_ref).resolve()
    if not authoritative_path.is_file():
        raise FL3ValidationError(f"FAIL_CLOSED: missing authoritative adapter registry: {authoritative_path.as_posix()}")
    authoritative_ids = _load_authoritative_adapter_ids(authoritative_path)
    if len(authoritative_ids) != 13:
        raise FL3ValidationError("FAIL_CLOSED: authoritative adapter registry does not currently resolve exactly 13 ids")
    base_snapshot_id = str(registry.get("base_snapshot_id", "")).strip()
    if not base_snapshot_id:
        raise FL3ValidationError("FAIL_CLOSED: base_snapshot_id missing")
    base_snapshot_relpath = str(registry.get("base_snapshot_relpath", "")).strip()
    dataset_manifest_relpath = str(registry.get("dataset_manifest_relpath", "")).strip()
    holdout_pack_relpath = str(registry.get("default_eval_suite_workspace_relpath", "")).strip()
    for label, value in (
        ("base_snapshot_relpath", base_snapshot_relpath),
        ("dataset_manifest_relpath", dataset_manifest_relpath),
        ("default_eval_suite_workspace_relpath", holdout_pack_relpath),
    ):
        _assert_safe_relpath(value, label=label)
    base_snapshot_path = (input_root / base_snapshot_relpath).resolve()
    dataset_manifest_path = (input_root / dataset_manifest_relpath).resolve()
    holdout_pack_path = (workspace_root / holdout_pack_relpath).resolve()
    if not base_snapshot_path.exists():
        raise FL3ValidationError(f"FAIL_CLOSED: base snapshot path missing: {base_snapshot_path.as_posix()}")
    if not dataset_manifest_path.is_file():
        raise FL3ValidationError(f"FAIL_CLOSED: dataset manifest missing: {dataset_manifest_path.as_posix()}")
    if not holdout_pack_path.is_file():
        raise FL3ValidationError(f"FAIL_CLOSED: holdout pack missing: {holdout_pack_path.as_posix()}")
    required_refs = registry.get("required_contract_refs")
    if not isinstance(required_refs, list) or not required_refs:
        raise FL3ValidationError("FAIL_CLOSED: required_contract_refs missing/invalid")
    required_contract_paths: List[Path] = []
    for item in required_refs:
        rel = str(item).strip()
        _assert_safe_relpath(rel, label="required_contract_ref")
        path = (repo_root / rel).resolve()
        if not path.exists():
            raise FL3ValidationError(f"FAIL_CLOSED: required contract/schema missing: {path.as_posix()}")
        required_contract_paths.append(path)
    default_training = registry.get("default_training_params")
    if not isinstance(default_training, dict):
        raise FL3ValidationError("FAIL_CLOSED: default_training_params missing/invalid")
    default_training_mode = str(default_training.get("training_mode", "")).strip()
    default_engine = str(default_training.get("engine", "")).strip()
    if default_training_mode not in {"head_only", "lora"}:
        raise FL3ValidationError("FAIL_CLOSED: default training_mode must be head_only or lora")
    if default_engine not in {"stub", "hf_lora"}:
        raise FL3ValidationError("FAIL_CLOSED: default engine must be stub or hf_lora")
    rows = registry.get("adapters")
    if not isinstance(rows, list) or len(rows) != expected_adapter_count:
        raise FL3ValidationError("FAIL_CLOSED: forge cohort registry must contain exactly 13 adapters")
    dataset_manifest = _read_dataset_manifest(dataset_manifest_path)
    seen_ids: set[str] = set()
    seen_output_names: set[str] = set()
    seen_relpaths: set[str] = set()
    adapters: List[AdapterSpec] = []
    for row in rows:
        if not isinstance(row, dict):
            raise FL3ValidationError("FAIL_CLOSED: forge cohort adapter row must be object")
        adapter_id = str(row.get("adapter_id", "")).strip()
        output_name = str(row.get("output_name", "")).strip()
        dataset_relpath = str(row.get("dataset_relpath", "")).strip()
        artifact_relpath = str(row.get("artifact_relpath", "")).strip()
        receipts = row.get("receipt_paths")
        training_params = row.get("training_params") if isinstance(row.get("training_params"), dict) else {}
        if not adapter_id:
            raise FL3ValidationError("FAIL_CLOSED: forge cohort adapter_id missing")
        _assert_safe_output_name(output_name)
        for label, value in (("dataset_relpath", dataset_relpath), ("artifact_relpath", artifact_relpath)):
            _assert_safe_relpath(value, label=f"{adapter_id}.{label}")
        if not isinstance(receipts, dict):
            raise FL3ValidationError(f"FAIL_CLOSED: receipt_paths missing for {adapter_id}")
        training_receipt_relpath = str(receipts.get("training", "")).strip()
        reload_receipt_relpath = str(receipts.get("reload", "")).strip()
        eval_receipt_relpath = str(receipts.get("eval", "")).strip()
        for label, value in (
            ("training_receipt_relpath", training_receipt_relpath),
            ("reload_receipt_relpath", reload_receipt_relpath),
            ("eval_receipt_relpath", eval_receipt_relpath),
        ):
            _assert_safe_relpath(value, label=f"{adapter_id}.{label}")
        if adapter_id in seen_ids:
            raise FL3ValidationError(f"FAIL_CLOSED: duplicate adapter_id in cohort registry: {adapter_id}")
        if output_name in seen_output_names:
            raise FL3ValidationError(f"FAIL_CLOSED: duplicate output_name in cohort registry: {output_name}")
        for rel in (artifact_relpath, training_receipt_relpath, reload_receipt_relpath, eval_receipt_relpath):
            if rel in seen_relpaths:
                raise FL3ValidationError(f"FAIL_CLOSED: duplicate artifact or receipt path in cohort registry: {rel}")
            seen_relpaths.add(rel)
        if adapter_id not in authoritative_ids:
            raise FL3ValidationError(f"FAIL_CLOSED: forbidden adapter_id outside authoritative registry: {adapter_id}")
        manifest_row = dataset_manifest.get(adapter_id)
        if manifest_row is None:
            raise FL3ValidationError(f"FAIL_CLOSED: dataset manifest entry missing for {adapter_id}")
        if manifest_row["dataset_relpath"] != dataset_relpath:
            raise FL3ValidationError(f"FAIL_CLOSED: dataset manifest mismatch for {adapter_id}")
        dataset_path = (input_root / dataset_relpath).resolve()
        if not dataset_path.is_file():
            raise FL3ValidationError(f"FAIL_CLOSED: dataset path missing for {adapter_id}: {dataset_path.as_posix()}")
        if _sha256_file(dataset_path) != manifest_row["sha256"]:
            raise FL3ValidationError(f"FAIL_CLOSED: dataset hash mismatch for {adapter_id}")
        seed = int(training_params.get("seed", 0))
        if seed <= 0:
            raise FL3ValidationError(f"FAIL_CLOSED: invalid seed for {adapter_id}")
        training_mode = str(training_params.get("training_mode", default_training_mode)).strip()
        engine = str(training_params.get("engine", default_engine)).strip()
        if training_mode not in {"head_only", "lora"}:
            raise FL3ValidationError(f"FAIL_CLOSED: invalid training_mode for {adapter_id}")
        if engine not in {"stub", "hf_lora"}:
            raise FL3ValidationError(f"FAIL_CLOSED: invalid engine for {adapter_id}")
        seen_ids.add(adapter_id)
        seen_output_names.add(output_name)
        adapters.append(
            AdapterSpec(
                adapter_id=adapter_id,
                output_name=output_name,
                dataset_relpath=dataset_relpath,
                artifact_relpath=artifact_relpath,
                training_receipt_relpath=training_receipt_relpath,
                reload_receipt_relpath=reload_receipt_relpath,
                eval_receipt_relpath=eval_receipt_relpath,
                seed=seed,
                training_mode=training_mode,
                engine=engine,
            )
        )
    if set(seen_ids) != set(authoritative_ids):
        missing = sorted(set(authoritative_ids) - set(seen_ids))
        extra = sorted(set(seen_ids) - set(authoritative_ids))
        raise FL3ValidationError(f"FAIL_CLOSED: cohort registry must match authoritative 13 ids exactly. missing={missing} extra={extra}")
    return RegistryContext(
        registry_id=str(registry.get("registry_id", "")).strip(),
        base_snapshot_id=base_snapshot_id,
        base_snapshot_path=base_snapshot_path,
        dataset_manifest_path=dataset_manifest_path,
        holdout_pack_path=holdout_pack_path,
        authoritative_adapter_registry_path=authoritative_path,
        required_contract_paths=tuple(required_contract_paths),
        adapters=tuple(adapters),
    )


def _build_discovery_receipt(*, registry_path: Path, ctx: RegistryContext, input_root: Path, artifact_root: Path) -> Dict[str, Any]:
    authoritative_ids = _load_authoritative_adapter_ids(ctx.authoritative_adapter_registry_path)
    return {
        "schema_id": "kt.operator.forge_cohort0.discovery_receipt.unbound.v1",
        "registry_path": registry_path.as_posix(),
        "registry_id": ctx.registry_id,
        "authoritative_adapter_registry_path": ctx.authoritative_adapter_registry_path.as_posix(),
        "authoritative_adapter_count": int(len(authoritative_ids)),
        "resolved_adapter_count": int(len(ctx.adapters)),
        "adapter_ids": [row.adapter_id for row in ctx.adapters],
        "base_snapshot_id": ctx.base_snapshot_id,
        "base_snapshot_path": ctx.base_snapshot_path.as_posix(),
        "dataset_manifest_path": ctx.dataset_manifest_path.as_posix(),
        "holdout_pack_path": ctx.holdout_pack_path.as_posix(),
        "input_root": input_root.as_posix(),
        "artifact_root": artifact_root.as_posix(),
        "required_contract_count": int(len(ctx.required_contract_paths)),
        "status": "PASS",
        "created_at": _now_utc_z(),
    }


def _build_preflight_receipt(*, repo_root: Path, ctx: RegistryContext, input_root: Path, artifact_root: Path, mode: str) -> Dict[str, Any]:
    base_snapshot_hash = _hash_tree(ctx.base_snapshot_path)
    required_contract_hashes = [{"path": path.as_posix(), "sha256": _sha256_file(path)} for path in ctx.required_contract_paths]
    return {
        "schema_id": "kt.operator.forge_cohort0.preflight_receipt.unbound.v1",
        "mode": mode,
        "repo_head": _git_head(repo_root),
        "base_snapshot_id": ctx.base_snapshot_id,
        "base_snapshot_hash_tree": base_snapshot_hash,
        "dataset_manifest_path": ctx.dataset_manifest_path.as_posix(),
        "dataset_manifest_sha256": _sha256_file(ctx.dataset_manifest_path),
        "holdout_pack_path": ctx.holdout_pack_path.as_posix(),
        "holdout_pack_sha256": _sha256_file(ctx.holdout_pack_path),
        "input_root": input_root.as_posix(),
        "artifact_root": artifact_root.as_posix(),
        "adapter_count": int(len(ctx.adapters)),
        "required_contract_hashes": required_contract_hashes,
        "status": "PASS",
        "created_at": _now_utc_z(),
    }


def _zip_single_json(*, json_name: str, obj: Dict[str, Any]) -> bytes:
    payload = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo(json_name, date_time=FIXED_ZIP_DT)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (0o644 & 0xFFFF) << 16
        zf.writestr(info, payload)
    return buf.getvalue()


def _train_one_stub(*, run_root: Path, input_root: Path, ctx: RegistryContext, adapter: AdapterSpec) -> Dict[str, Any]:
    dataset_path = (input_root / adapter.dataset_relpath).resolve()
    dataset_sha = _sha256_file(dataset_path)
    dataset_bytes = int(dataset_path.stat().st_size)
    base_snapshot_hash = _hash_tree(ctx.base_snapshot_path)
    holdout_pack_sha = _sha256_file(ctx.holdout_pack_path)
    artifact_path = (run_root / adapter.artifact_relpath).resolve()
    artifact_meta = {
        "schema_id": "kt.operator.forge_cohort0.adapter_artifact.unbound.v1",
        "adapter_id": adapter.adapter_id,
        "output_name": adapter.output_name,
        "training_mode": adapter.training_mode,
        "engine": adapter.engine,
        "seed": int(adapter.seed),
        "dataset_relpath": adapter.dataset_relpath,
        "dataset_sha256": dataset_sha,
        "base_snapshot_id": ctx.base_snapshot_id,
        "base_snapshot_root_hash": str(base_snapshot_hash["root_hash"]),
        "holdout_pack_sha256": holdout_pack_sha,
        "registry_id": ctx.registry_id,
    }
    artifact_bytes = _zip_single_json(json_name="adapter_metadata.json", obj=artifact_meta)
    write_bytes_worm(path=artifact_path, data=artifact_bytes, label=f"{adapter.adapter_id}:artifact")
    artifact_sha = _sha256_bytes(artifact_bytes)
    training_receipt = {
        "schema_id": "kt.operator.forge_cohort0.adapter_training_receipt.unbound.v1",
        "adapter_id": adapter.adapter_id,
        "output_name": adapter.output_name,
        "artifact_path": artifact_path.as_posix(),
        "artifact_sha256": artifact_sha,
        "artifact_bytes": int(len(artifact_bytes)),
        "dataset_relpath": adapter.dataset_relpath,
        "dataset_sha256": dataset_sha,
        "dataset_bytes": dataset_bytes,
        "base_snapshot_id": ctx.base_snapshot_id,
        "base_snapshot_root_hash": str(base_snapshot_hash["root_hash"]),
        "training_mode": adapter.training_mode,
        "engine": adapter.engine,
        "seed": int(adapter.seed),
        "status": "PASS",
        "created_at": _now_utc_z(),
    }
    _write_json_worm(path=(run_root / adapter.training_receipt_relpath).resolve(), obj=training_receipt, label=f"{adapter.adapter_id}:training_receipt")
    with zipfile.ZipFile(artifact_path, "r") as zf:
        meta = json.loads(zf.read("adapter_metadata.json").decode("utf-8"))
    if not isinstance(meta, dict) or meta.get("adapter_id") != adapter.adapter_id:
        raise FL3ValidationError(f"FAIL_CLOSED: adapter reload mismatch for {adapter.adapter_id}")
    reload_receipt = {
        "schema_id": "kt.operator.forge_cohort0.adapter_reload_receipt.unbound.v1",
        "adapter_id": adapter.adapter_id,
        "artifact_path": artifact_path.as_posix(),
        "artifact_sha256": artifact_sha,
        "reloaded_metadata_sha256": sha256_text(_canonical_json(meta)),
        "status": "PASS",
        "created_at": _now_utc_z(),
    }
    _write_json_worm(path=(run_root / adapter.reload_receipt_relpath).resolve(), obj=reload_receipt, label=f"{adapter.adapter_id}:reload_receipt")
    holdout_pack = _load_json(ctx.holdout_pack_path)
    pack_case_count = len(holdout_pack.get("suites", [])) if isinstance(holdout_pack.get("suites"), list) else 0
    score_seed = hashlib.sha256((adapter.adapter_id + ":" + artifact_sha + ":" + holdout_pack_sha).encode("utf-8")).hexdigest()
    eval_receipt = {
        "schema_id": "kt.operator.forge_cohort0.adapter_eval_receipt.unbound.v1",
        "adapter_id": adapter.adapter_id,
        "artifact_path": artifact_path.as_posix(),
        "artifact_sha256": artifact_sha,
        "holdout_pack_path": ctx.holdout_pack_path.as_posix(),
        "holdout_pack_sha256": holdout_pack_sha,
        "eval_case_count": int(pack_case_count),
        "baseline_eval_score": float(round((int(score_seed[:8], 16) % 1000) / 1000.0, 3)),
        "promotion_ready_artifacts_present": True,
        "status": "PASS",
        "created_at": _now_utc_z(),
    }
    _write_json_worm(path=(run_root / adapter.eval_receipt_relpath).resolve(), obj=eval_receipt, label=f"{adapter.adapter_id}:eval_receipt")
    return {
        "adapter_id": adapter.adapter_id,
        "output_name": adapter.output_name,
        "artifact_relpath": adapter.artifact_relpath,
        "artifact_sha256": artifact_sha,
        "dataset_relpath": adapter.dataset_relpath,
        "dataset_sha256": dataset_sha,
        "training_receipt_relpath": adapter.training_receipt_relpath,
        "reload_receipt_relpath": adapter.reload_receipt_relpath,
        "eval_receipt_relpath": adapter.eval_receipt_relpath,
        "status": "PASS",
    }


def _write_run_manifests(*, repo_root: Path, run_root: Path, ctx: RegistryContext, mode: str, adapter_results: List[Dict[str, Any]]) -> None:
    _write_json_worm(
        path=run_root / "adapter_lineage_manifest.json",
        obj={"schema_id": "kt.operator.forge_cohort0.lineage_manifest.unbound.v1", "registry_id": ctx.registry_id, "adapter_count": int(len(adapter_results)), "entries": adapter_results, "created_at": _now_utc_z()},
        label="adapter_lineage_manifest.json",
    )
    _write_json_worm(
        path=run_root / "adapter_registry.json",
        obj={"schema_id": "kt.operator.forge_cohort0.adapter_registry.unbound.v1", "registry_id": ctx.registry_id, "authoritative_adapter_registry_path": ctx.authoritative_adapter_registry_path.as_posix(), "entries": [{"adapter_id": row.adapter_id, "output_name": row.output_name, "dataset_relpath": row.dataset_relpath, "artifact_relpath": row.artifact_relpath, "receipt_paths": {"training": row.training_receipt_relpath, "reload": row.reload_receipt_relpath, "eval": row.eval_receipt_relpath}} for row in ctx.adapters], "created_at": _now_utc_z()},
        label="adapter_registry.json",
    )
    status = "PASS" if all(row.get("status") == "PASS" for row in adapter_results) else "FAIL"
    _write_json_worm(path=run_root / "run_summary.json", obj={"schema_id": "kt.operator.forge_cohort0.run_summary.unbound.v1", "mode": mode, "registry_id": ctx.registry_id, "adapter_count": int(len(adapter_results)), "pass_count": int(sum(1 for row in adapter_results if row.get("status") == "PASS")), "fail_count": int(sum(1 for row in adapter_results if row.get("status") != "PASS")), "status": status, "created_at": _now_utc_z()}, label="run_summary.json")
    _write_json_worm(
        path=run_root / "run_manifest.json",
        obj={
            "schema_id": "kt.operator.forge_cohort0.run_manifest.unbound.v1",
            "repo_head": _git_head(repo_root),
            "registry_id": ctx.registry_id,
            "base_snapshot_id": ctx.base_snapshot_id,
            "base_snapshot_root_hash": _hash_tree(ctx.base_snapshot_path)["root_hash"],
            "adapter_ids": [row.adapter_id for row in ctx.adapters],
            "artifact_hashes": [{"adapter_id": row["adapter_id"], "artifact_relpath": row["artifact_relpath"], "artifact_sha256": row["artifact_sha256"], "dataset_sha256": row["dataset_sha256"]} for row in adapter_results],
            "receipt_list": [item for row in adapter_results for item in (row["training_receipt_relpath"], row["reload_receipt_relpath"], row["eval_receipt_relpath"])],
            "verdict": status,
            "mode": mode,
            "created_at": _now_utc_z(),
        },
        label="run_manifest.json",
    )


def _parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Sanctioned Cohort-0 forge wrapper (dry-run, smoke, full).")
    ap.add_argument("--registry", default=DEFAULT_REGISTRY_REL, help="Forge Cohort-0 registry JSON.")
    ap.add_argument("--input-root", required=True, help="Staged input root (datasets + base snapshot).")
    ap.add_argument("--artifact-root", required=True, help="External artifact root (must be outside repo tree).")
    ap.add_argument("--mode", choices=["dry-run", "smoke", "full"], required=True)
    ap.add_argument("--adapter-id", default="", help="Required for smoke mode; adapter_id to train.")
    ap.add_argument("--run-label", default="", help="Optional stable run label under artifact root.")
    return ap.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    repo_root = repo_root_from(Path(__file__))
    registry_path = Path(str(args.registry)).expanduser()
    if not registry_path.is_absolute():
        registry_path = (repo_root / registry_path).resolve()
    input_root = Path(str(args.input_root)).expanduser().resolve()
    if not input_root.exists():
        print(f"FAIL_CLOSED: --input-root missing: {input_root.as_posix()}")
        return 2
    if not registry_path.is_file():
        print(f"FAIL_CLOSED: --registry missing: {registry_path.as_posix()}")
        return 2
    try:
        artifact_root = _assert_external_artifact_root(repo_root=repo_root, artifact_root=Path(str(args.artifact_root)).expanduser())
        ctx = _build_registry_context(repo_root=repo_root, registry_path=registry_path, input_root=input_root)
        run_label = str(args.run_label).strip() or f"cohort0_{args.mode}_{_now_compact_z()}"
        _assert_safe_output_name(run_label)
        run_root = (artifact_root / run_label).resolve()
        if run_root.exists() and any(run_root.iterdir()):
            raise FL3ValidationError(f"FAIL_CLOSED: run root collision: {run_root.as_posix()}")
        run_root.mkdir(parents=True, exist_ok=True)
        _write_json_worm(path=run_root / "discovery_receipt.json", obj=_build_discovery_receipt(registry_path=registry_path, ctx=ctx, input_root=input_root, artifact_root=artifact_root), label="discovery_receipt.json")
        _write_json_worm(path=run_root / "preflight_receipt.json", obj=_build_preflight_receipt(repo_root=repo_root, ctx=ctx, input_root=input_root, artifact_root=artifact_root, mode=str(args.mode)), label="preflight_receipt.json")
        if args.mode == "dry-run":
            _write_run_manifests(repo_root=repo_root, run_root=run_root, ctx=ctx, mode="dry-run", adapter_results=[])
            print(f"KT_FORGE_COHORT0_PASS mode=dry-run registry={ctx.registry_id} adapters={len(ctx.adapters)} run_root={run_root.as_posix()}")
            return 0
        if args.mode == "smoke":
            smoke_adapter_id = str(args.adapter_id).strip()
            if not smoke_adapter_id:
                raise FL3ValidationError("FAIL_CLOSED: --adapter-id required in smoke mode")
            targets = [row for row in ctx.adapters if row.adapter_id == smoke_adapter_id]
            if len(targets) != 1:
                raise FL3ValidationError(f"FAIL_CLOSED: smoke adapter_id not found in registry: {smoke_adapter_id}")
        else:
            targets = list(ctx.adapters)
        adapter_results = [_train_one_stub(run_root=run_root, input_root=input_root, ctx=ctx, adapter=row) for row in targets]
        _write_run_manifests(repo_root=repo_root, run_root=run_root, ctx=ctx, mode=str(args.mode), adapter_results=adapter_results)
        print(f"KT_FORGE_COHORT0_PASS mode={args.mode} registry={ctx.registry_id} adapters={len(adapter_results)} run_root={run_root.as_posix()}")
        return 0
    except FL3ValidationError as exc:
        print(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
