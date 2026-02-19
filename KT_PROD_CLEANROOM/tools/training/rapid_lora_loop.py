from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.schema_hash import canonical_json
from tools.training.fl3_factory.eval_stub import build_eval_report
from tools.training.fl3_factory.trace import build_reasoning_trace
from tools.training.fl3_factory.train_stub import build_train_manifest
from tools.verification.fl3_canonical import sha256_text
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import write_text_worm


class FailClosedError(RuntimeError):
    pass


def _now_utc_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_json_worm(*, path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(path=path, text=canonical_json(obj) + "\n", label=label)


def _assert_out_dir_under_exports_runs(*, repo_root: Path, out_dir: Path) -> Path:
    out_dir = out_dir.resolve()
    allowed_root = (repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs").resolve()
    try:
        out_dir.relative_to(allowed_root)
    except ValueError as exc:
        raise FailClosedError(f"FAIL_CLOSED: out_dir must be under {allowed_root}") from exc
    return out_dir


def _dep_versions() -> Dict[str, Dict[str, Any]]:
    deps = {"torch": None, "transformers": None, "peft": None}
    out: Dict[str, Dict[str, Any]] = {}
    for name in deps:
        try:
            mod = __import__(name)  # noqa: S404
            ver = getattr(mod, "__version__", "UNKNOWN")
            out[name] = {"present": True, "version": str(ver)}
        except Exception:  # noqa: BLE001
            out[name] = {"present": False, "version": None}
    return out


def _hash_dataset(*, dataset_path: Path, out_dir: Path) -> Tuple[str, Optional[str]]:
    """
    Returns: (dataset_root_hash, manifest_path_or_none)
    """
    if dataset_path.is_file():
        return _sha256_file(dataset_path), None
    if not dataset_path.is_dir():
        raise FailClosedError("FAIL_CLOSED: dataset_path must be a file or directory")

    entries: List[Dict[str, str]] = []
    for p in sorted(dataset_path.rglob("*")):
        if p.is_file():
            rel = p.relative_to(dataset_path).as_posix()
            entries.append({"path": rel, "sha256": _sha256_file(p)})
    manifest = {
        "schema_id": "kt.dataset_hash_manifest.unbound.v1",
        "dataset_path": str(dataset_path),
        "file_count": len(entries),
        "files": entries,
    }
    manifest_path = out_dir / "dataset_hash_manifest.json"
    _write_json_worm(path=manifest_path, obj=manifest, label=manifest_path.name)
    root_hash = sha256_text(canonical_json(manifest))
    return root_hash, str(manifest_path)


@dataclass(frozen=True)
class RapidConfig:
    job_id: str
    job_label: str
    adapter_id: str
    adapter_version: str
    training_mode: str
    seed: int


def _load_config(path: Path) -> RapidConfig:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise FailClosedError("FAIL_CLOSED: config must be JSON object")
    job_label = str(obj.get("job_id", "")).strip()
    # Schema-bound factory artifacts require a 64-hex job_id. Derive deterministically from config.
    job_id = sha256_text(canonical_json(obj))
    adapter_id = str(obj.get("adapter_id", "")).strip() or f"adapter.{job_id[:16]}"
    adapter_version = str(obj.get("adapter_version", "")).strip() or "v0"
    training_mode = str(obj.get("training_mode", "")).strip().lower() or "lora"
    if training_mode not in {"lora", "head_only"}:
        raise FailClosedError("FAIL_CLOSED: training_mode must be one of: lora, head_only")
    seed = int(obj.get("seed", 1337))
    return RapidConfig(
        job_id=job_id,
        job_label=job_label,
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        training_mode=training_mode,
        seed=seed,
    )


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Rapid adapter loop (offline; WORM; fail-closed).")
    p.add_argument("--dataset", required=True, help="Local dataset file/dir (no network).")
    p.add_argument("--config", required=True, help="Local JSON config (seeded).")
    p.add_argument("--base-model-dir", default="", help="Local model dir (required for hf_lora engine).")
    p.add_argument("--engine", default="hf_lora", choices=["hf_lora", "stub"], help="Training engine.")
    p.add_argument(
        "--out-dir",
        default="",
        help="Output directory under KT_PROD_CLEANROOM/exports/_runs (default: create new).",
    )
    return p.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = Path.cwd().resolve()

    dataset_path = Path(args.dataset).resolve()
    config_path = Path(args.config).resolve()
    if not dataset_path.exists():
        raise FailClosedError("FAIL_CLOSED: dataset path missing")
    if not config_path.exists():
        raise FailClosedError("FAIL_CLOSED: config path missing")

    cfg = _load_config(config_path)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.out_dir:
        out_dir = _assert_out_dir_under_exports_runs(repo_root=repo_root, out_dir=Path(args.out_dir))
    else:
        out_dir = _assert_out_dir_under_exports_runs(
            repo_root=repo_root,
            out_dir=repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs" / "KT_RAPID_LORA" / f"{ts}_{cfg.job_id}",
        )
    if out_dir.exists():
        raise FailClosedError("FAIL_CLOSED: out_dir already exists (WORM collision)")
    out_dir.mkdir(parents=True, exist_ok=False)

    deps = _dep_versions()
    dataset_hash, dataset_manifest_path = _hash_dataset(dataset_path=dataset_path, out_dir=out_dir)
    config_sha = _sha256_file(config_path)
    base_model_dir = str(args.base_model_dir).strip()

    manifest: Dict[str, Any] = {
        "schema_id": "kt.rapid_lora_run_manifest.unbound.v1",
        "created_at": _now_utc_z(),
        "engine": str(args.engine),
        "job_id": cfg.job_id,
        "job_label": cfg.job_label,
        "adapter_id": cfg.adapter_id,
        "adapter_version": cfg.adapter_version,
        "training_mode": cfg.training_mode,
        "seed": cfg.seed,
        "dataset_path": str(dataset_path),
        "dataset_root_hash": dataset_hash,
        "dataset_manifest_path": dataset_manifest_path,
        "config_path": str(config_path),
        "config_sha256": config_sha,
        "base_model_dir": base_model_dir,
        "deps": deps,
        "status": "UNKNOWN",
        "produced": {},
    }
    _write_json_worm(path=out_dir / "training_run_manifest.json", obj=manifest, label="training_run_manifest.json")

    try:
        if str(args.engine) == "hf_lora":
            missing = [k for k, v in deps.items() if not v.get("present")]
            if missing:
                raise FailClosedError(
                    "FAIL_CLOSED: missing deps for hf_lora engine: "
                    + ",".join(missing)
                    + " (next_action=install offline wheelhouse)"
                )
            if not base_model_dir:
                raise FailClosedError("FAIL_CLOSED: --base-model-dir required for hf_lora engine")
            bdir = Path(base_model_dir).resolve()
            if not bdir.exists():
                raise FailClosedError("FAIL_CLOSED: base model dir missing")
            # Intentionally do not implement training here; this tool is a governed wrapper.
            # Next action is explicit: provide offline model weights and enable a dedicated training EPIC.
            raise FailClosedError(
                "FAIL_CLOSED: hf_lora engine is gated (next_action=provide offline model dir + training EPIC to enable execution)"
            )

        # Stub engine: produces schema-bound artifacts deterministically without external ML deps.
        job = {
            "job_id": cfg.job_id,
            "base_model_id": "stub.local.model",
            "training_mode": cfg.training_mode,
            "adapter_id": cfg.adapter_id,
            "adapter_version": cfg.adapter_version,
        }
        dataset_obj = {"dataset_id": dataset_hash}

        train_manifest = build_train_manifest(job=job, dataset=dataset_obj, out_dir=out_dir / "train")
        validate_schema_bound_object(train_manifest)
        _write_json_worm(path=out_dir / "train_manifest.json", obj=train_manifest, label="train_manifest.json")
        manifest["produced"]["train_manifest_id"] = train_manifest.get("train_id")

        trace = build_reasoning_trace(job_id=cfg.job_id, final_output_hash=train_manifest["output_bundle"]["artifact_hash"])
        validate_schema_bound_object(trace)
        _write_json_worm(path=out_dir / "reasoning_trace.json", obj=trace, label="reasoning_trace.json")
        manifest["produced"]["trace_id"] = trace.get("trace_id")

        eval_report = build_eval_report(job=job, trace=trace)
        validate_schema_bound_object(eval_report)
        _write_json_worm(path=out_dir / "eval_report.json", obj=eval_report, label="eval_report.json")
        manifest["produced"]["eval_id"] = eval_report.get("eval_id")

        manifest["status"] = "PASS"
        _write_json_worm(path=out_dir / "training_run_manifest.PASS.json", obj=manifest, label="training_run_manifest.PASS.json")
        verdict = f"KT_RAPID_LORA_PASS engine=stub job_id={cfg.job_id} out_dir={out_dir.as_posix()}"
        write_text_worm(path=out_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
        print(verdict)
        return 0

    except FailClosedError as exc:
        manifest["status"] = "FAIL_CLOSED"
        manifest["error"] = str(exc)
        _write_json_worm(path=out_dir / "training_run_manifest.FAIL_CLOSED.json", obj=manifest, label="training_run_manifest.FAIL_CLOSED.json")
        verdict = f"KT_RAPID_LORA_FAIL_CLOSED engine={args.engine} job_id={cfg.job_id} out_dir={out_dir.as_posix()}"
        write_text_worm(path=out_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
        print(str(exc))
        print(verdict)
        return 2
    except FL3ValidationError as exc:
        manifest["status"] = "FAIL_CLOSED"
        manifest["error"] = f"schema_validation:{str(exc)}"
        _write_json_worm(path=out_dir / "training_run_manifest.FAIL_CLOSED.json", obj=manifest, label="training_run_manifest.FAIL_CLOSED.json")
        verdict = f"KT_RAPID_LORA_FAIL_CLOSED engine={args.engine} job_id={cfg.job_id} out_dir={out_dir.as_posix()}"
        write_text_worm(path=out_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
        print(str(exc))
        print(verdict)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
