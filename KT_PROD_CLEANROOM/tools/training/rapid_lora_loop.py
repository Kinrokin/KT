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
    allowed_roots = [(repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs").resolve()]
    if os.environ.get("KT_SEAL_MODE") == "1":
        allowed_roots.append((repo_root / "KT_PROD_CLEANROOM" / "exports" / "adapters_shadow" / "_tmp" / "tests").resolve())
    for r in allowed_roots:
        try:
            out_dir.relative_to(r)
            return out_dir
        except ValueError:
            continue
    allowed_s = ", ".join(r.as_posix() for r in allowed_roots)
    raise FailClosedError(f"FAIL_CLOSED: out_dir must be under one of: {allowed_s}")


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


def _build_dataset_hash_manifest(*, dataset_path: Path) -> Dict[str, Any]:
    if not dataset_path.is_dir():
        if not dataset_path.is_file():
            raise FailClosedError("FAIL_CLOSED: dataset_path must be a file or directory")

    entries: List[Dict[str, str]] = []
    if dataset_path.is_file():
        entries.append({"path": dataset_path.name, "sha256": _sha256_file(dataset_path)})
    else:
        for p in sorted(dataset_path.rglob("*")):
            if p.is_file():
                rel = p.relative_to(dataset_path).as_posix()
                entries.append({"path": rel, "sha256": _sha256_file(p)})
    return {
        "schema_id": "kt.dataset_hash_manifest.unbound.v1",
        "dataset_path": str(dataset_path),
        "file_count": len(entries),
        "files": entries,
    }


def _dataset_root_hash(*, manifest: Dict[str, Any]) -> str:
    return sha256_text(canonical_json(manifest))


def _write_dataset_manifest_worm(*, out_dir: Path, manifest: Dict[str, Any]) -> str:
    manifest_path = out_dir / "dataset_hash_manifest.json"
    _write_json_worm(path=manifest_path, obj=manifest, label=manifest_path.name)
    return str(manifest_path)


@dataclass(frozen=True)
class RapidConfig:
    job_id: str
    job_label: str
    adapter_id: str
    adapter_version: str
    training_mode: str
    seed: int


def _load_config(path: Path) -> RapidConfig:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FailClosedError("FAIL_CLOSED: config must be valid JSON") from exc
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
    p.add_argument("--engine", default="stub", choices=["hf_lora", "stub"], help="Training engine.")
    p.add_argument(
        "--enable-real-engine",
        action="store_true",
        help="Allow non-stub engines (default: disabled; fail-closed).",
    )
    p.add_argument(
        "--out-dir",
        default="",
        help="Output directory under KT_PROD_CLEANROOM/exports/_runs (default: create new).",
    )
    return p.parse_args(list(argv) if argv is not None else None)


def _parse_hashes_txt(*, text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 3:
            raise FailClosedError("FAIL_CLOSED: invalid hashes.txt line")
        algo, h, name = parts
        if algo != "sha256":
            raise FailClosedError("FAIL_CLOSED: hashes.txt algo must be sha256")
        out[name] = h
    return out


def _verify_existing_stub_run(
    *, out_dir: Path, dataset_hash: str, dataset_manifest_path: Optional[str], config_sha: str, derived_job_id: str
) -> None:
    """
    Verify existing artifacts in-place without writing anything.
    """
    # Prefer PASS manifest if present.
    manifest_path = out_dir / "training_run_manifest.PASS.json"
    if not manifest_path.exists():
        manifest_path = out_dir / "training_run_manifest.json"
    if not manifest_path.exists():
        raise FailClosedError("FAIL_CLOSED: missing training_run_manifest.json for verification")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise FailClosedError("FAIL_CLOSED: invalid training_run_manifest.json (not object)")

    if str(manifest.get("engine", "")).strip() != "stub":
        raise FailClosedError("FAIL_CLOSED: existing run engine mismatch (expected stub)")
    if str(manifest.get("job_id", "")).strip() != derived_job_id:
        raise FailClosedError("FAIL_CLOSED: existing job_id mismatch")
    if str(manifest.get("dataset_root_hash", "")).strip() != dataset_hash:
        raise FailClosedError("FAIL_CLOSED: dataset_root_hash mismatch")
    if str(manifest.get("config_sha256", "")).strip() != config_sha:
        raise FailClosedError("FAIL_CLOSED: config_sha256 mismatch")

    if dataset_manifest_path:
        got = str(manifest.get("dataset_manifest_path") or "").replace("\\", "/")
        if got and got != dataset_manifest_path.replace("\\", "/"):
            raise FailClosedError("FAIL_CLOSED: dataset_manifest_path mismatch")

    train_manifest_path = out_dir / "train_manifest.json"
    trace_path = out_dir / "reasoning_trace.json"
    eval_path = out_dir / "eval_report.json"
    for p in (train_manifest_path, trace_path, eval_path):
        if not p.exists():
            raise FailClosedError(f"FAIL_CLOSED: missing artifact for verification: {p.name}")

    train_manifest = json.loads(train_manifest_path.read_text(encoding="utf-8"))
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    eval_report = json.loads(eval_path.read_text(encoding="utf-8"))
    if not isinstance(train_manifest, dict) or not isinstance(trace, dict) or not isinstance(eval_report, dict):
        raise FailClosedError("FAIL_CLOSED: invalid schema artifacts for verification (not objects)")
    validate_schema_bound_object(train_manifest)
    validate_schema_bound_object(trace)
    validate_schema_bound_object(eval_report)

    bundle = train_manifest.get("output_bundle")
    if not isinstance(bundle, dict):
        raise FailClosedError("FAIL_CLOSED: train_manifest output_bundle missing/invalid")
    artifact_path = Path(str(bundle.get("artifact_path", ""))).expanduser()
    if not artifact_path.is_absolute():
        artifact_path = (out_dir / artifact_path).resolve()
    if not artifact_path.exists():
        raise FailClosedError("FAIL_CLOSED: missing adapter artifact file for verification")
    got_hash = _sha256_file(artifact_path)
    if got_hash != str(bundle.get("artifact_hash", "")).strip():
        raise FailClosedError("FAIL_CLOSED: adapter artifact hash mismatch")

    # Verify verdict + hash ledger (operator contract).
    verdict_path = out_dir / "verdict.txt"
    if not verdict_path.exists():
        raise FailClosedError("FAIL_CLOSED: missing verdict.txt for verification")
    expected_verdict = f"KT_RAPID_LORA_PASS cmd=train engine=stub job_id={derived_job_id} out_dir={out_dir.as_posix()}"
    got_verdict = verdict_path.read_text(encoding="utf-8").strip()
    if got_verdict != expected_verdict:
        raise FailClosedError("FAIL_CLOSED: verdict.txt mismatch for verification")

    hashes_path = out_dir / "hashes.txt"
    if not hashes_path.exists():
        raise FailClosedError("FAIL_CLOSED: missing hashes.txt for verification")
    hashes = _parse_hashes_txt(text=hashes_path.read_text(encoding="utf-8"))

    expected_hashes: Dict[str, str] = {
        "dataset_root_hash": dataset_hash,
        "dataset_hash_manifest.json": _sha256_file(out_dir / "dataset_hash_manifest.json"),
        "config_sha256": config_sha,
        "training_run_manifest.PASS.json": _sha256_file(out_dir / "training_run_manifest.PASS.json"),
        "train_manifest.json": _sha256_file(train_manifest_path),
        "reasoning_trace.json": _sha256_file(trace_path),
        "eval_report.json": _sha256_file(eval_path),
        "adapter_artifact": got_hash,
        "verdict.txt": _sha256_file(verdict_path),
    }
    for name, expected in expected_hashes.items():
        got = hashes.get(name)
        if got != expected:
            raise FailClosedError(f"FAIL_CLOSED: hashes.txt mismatch for {name}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = Path.cwd().resolve()

    try:
        dataset_path = Path(args.dataset).resolve()
        config_path = Path(args.config).resolve()
        if not dataset_path.exists():
            raise FailClosedError("FAIL_CLOSED: dataset path missing")
        if not config_path.exists():
            raise FailClosedError("FAIL_CLOSED: config path missing")
        cfg = _load_config(config_path)
    except FailClosedError as exc:
        print(str(exc))
        return 2

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        if args.out_dir:
            out_dir = _assert_out_dir_under_exports_runs(repo_root=repo_root, out_dir=Path(args.out_dir))
        else:
            out_dir = _assert_out_dir_under_exports_runs(
                repo_root=repo_root,
                out_dir=repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs" / "KT_RAPID_LORA" / f"{ts}_{cfg.job_id}",
            )
    except FailClosedError as exc:
        print(str(exc))
        return 2

    deps = _dep_versions()
    config_sha = _sha256_file(config_path)
    base_model_dir = str(args.base_model_dir).strip()

    # WORM semantics: if out_dir already exists, verify in-place and treat as a byte-identical no-op if consistent.
    if out_dir.exists():
        try:
            expected_manifest = _build_dataset_hash_manifest(dataset_path=dataset_path)
            dataset_hash = _dataset_root_hash(manifest=expected_manifest)
            manifest_path = out_dir / "dataset_hash_manifest.json"
            if not manifest_path.exists():
                raise FailClosedError("FAIL_CLOSED: missing dataset_hash_manifest.json for verification")
            got_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(got_manifest, dict):
                raise FailClosedError("FAIL_CLOSED: invalid dataset_hash_manifest.json for verification")
            if canonical_json(got_manifest) != canonical_json(expected_manifest):
                raise FailClosedError("FAIL_CLOSED: dataset_hash_manifest.json mismatch for verification")
            dataset_manifest_path = str(manifest_path.as_posix())
            if str(args.engine) == "stub":
                _verify_existing_stub_run(
                    out_dir=out_dir,
                    dataset_hash=dataset_hash,
                    dataset_manifest_path=dataset_manifest_path,
                    config_sha=config_sha,
                    derived_job_id=cfg.job_id,
                )
                verdict = f"KT_RAPID_LORA_PASS cmd=verify engine=stub job_id={cfg.job_id} noop=1 out_dir={out_dir.as_posix()}"
                print(verdict)
                return 0
            raise FailClosedError("FAIL_CLOSED: verify-only mode only supported for stub engine")
        except (FailClosedError, FL3ValidationError) as exc:  # noqa: BLE001
            msg = str(exc)
            print(msg)
            print(f"KT_RAPID_LORA_FAIL_CLOSED cmd=verify engine={args.engine} job_id={cfg.job_id} out_dir={out_dir.as_posix()}")
            return 2

    out_dir.mkdir(parents=True, exist_ok=False)
    dataset_manifest = _build_dataset_hash_manifest(dataset_path=dataset_path)
    dataset_hash = _dataset_root_hash(manifest=dataset_manifest)
    dataset_manifest_path = _write_dataset_manifest_worm(out_dir=out_dir, manifest=dataset_manifest)

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
            if not bool(getattr(args, "enable_real_engine", False)):
                raise FailClosedError("FAIL_CLOSED: real engines are disabled by default (use --enable-real-engine)")
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
            # Offline + no-surprises cache confinement.
            cache_root = (out_dir / "_hf_cache").resolve()
            cache_root.mkdir(parents=True, exist_ok=True)
            os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
            os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
            os.environ.setdefault("HF_HOME", str(cache_root))
            os.environ.setdefault("TRANSFORMERS_CACHE", str((cache_root / "transformers").resolve()))
            os.environ.setdefault("HF_DATASETS_CACHE", str((cache_root / "datasets").resolve()))

            # Hash the base model snapshot for auditability (full file-hash manifest; may be expensive).
            base_entries: List[Dict[str, Any]] = []
            for p in sorted(bdir.rglob("*")):
                if not p.is_file():
                    continue
                rel = p.relative_to(bdir).as_posix()
                base_entries.append({"path": rel, "bytes": int(p.stat().st_size), "sha256": _sha256_file(p)})
            base_model_manifest = {
                "schema_id": "kt.base_model_hash_manifest.unbound.v1",
                "base_model_dir": bdir.as_posix(),
                "file_count": int(len(base_entries)),
                "files": base_entries,
            }
            base_model_root_hash = sha256_text(canonical_json(base_model_manifest))
            _write_json_worm(
                path=(out_dir / "base_model_hash_manifest.json").resolve(),
                obj=base_model_manifest,
                label="base_model_hash_manifest.json",
            )
            manifest["produced"]["base_model_root_hash"] = base_model_root_hash
            manifest["produced"]["base_model_manifest_path"] = (out_dir / "base_model_hash_manifest.json").as_posix()

            # Training knobs (kept minimal; derived deterministically from config if present).
            try:
                raw_cfg = json.loads(config_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                raw_cfg = {}
            if not isinstance(raw_cfg, dict):
                raw_cfg = {}
            max_steps = int(raw_cfg.get("max_steps", 1))
            if max_steps < 1:
                raise FailClosedError("FAIL_CLOSED: max_steps must be >= 1")
            batch_size = int(raw_cfg.get("batch_size", raw_cfg.get("batch", 1)))
            if batch_size < 1:
                raise FailClosedError("FAIL_CLOSED: batch_size must be >= 1")
            seq_len = int(raw_cfg.get("seq_len", 32))
            if seq_len < 4:
                raise FailClosedError("FAIL_CLOSED: seq_len must be >= 4")
            lr = float(raw_cfg.get("lr", 1e-4))
            lora_r = int(raw_cfg.get("lora_rank", raw_cfg.get("lora_r", 8)))
            if lora_r < 1:
                raise FailClosedError("FAIL_CLOSED: lora_rank must be >= 1")
            lora_alpha = int(raw_cfg.get("lora_alpha", max(16, lora_r * 2)))
            lora_dropout = float(raw_cfg.get("lora_dropout", 0.0))
            target_modules_cfg = raw_cfg.get("target_modules")
            target_modules_override = (
                [str(x).strip() for x in target_modules_cfg if isinstance(x, str) and str(x).strip()]
                if isinstance(target_modules_cfg, list)
                else []
            )

            # Real engine: minimal deterministic LoRA update on synthetic token ids (no tokenizer; no network).
            import random
            import zipfile

            import torch
            from peft import LoraConfig, TaskType, get_peft_model
            from transformers import AutoModelForCausalLM

            os.environ.setdefault("PYTHONHASHSEED", str(cfg.seed))
            random.seed(int(cfg.seed))
            torch.manual_seed(int(cfg.seed))
            try:
                torch.use_deterministic_algorithms(True)
            except Exception:  # noqa: BLE001
                pass
            try:
                torch.set_num_threads(1)
            except Exception:  # noqa: BLE001
                pass

            model = AutoModelForCausalLM.from_pretrained(bdir, local_files_only=True)

            # Reduce randomness where possible.
            for attr in ("attn_pdrop", "embd_pdrop", "resid_pdrop", "dropout"):
                if hasattr(model.config, attr):
                    setattr(model.config, attr, 0.0)

            # Determine LoRA target modules deterministically.
            candidate = [
                "q_proj",
                "k_proj",
                "v_proj",
                "o_proj",
                "c_attn",
                "c_proj",
                "c_fc",
                "out_proj",
                "fc1",
                "fc2",
                "gate_proj",
                "up_proj",
                "down_proj",
            ]
            present: List[str] = []
            for name, module in model.named_modules():
                last = name.split(".")[-1]
                if isinstance(module, torch.nn.Linear) or module.__class__.__name__ == "Conv1D":
                    present.append(last)
            present_unique = sorted(set(present))
            target_modules = target_modules_override or [m for m in candidate if m in present_unique]
            if not target_modules:
                target_modules = present_unique[:4]
            if not target_modules:
                raise FailClosedError(
                    "FAIL_CLOSED: unable to infer target_modules for LoRA (next_action=provide target_modules list in config)"
                )

            lora_cfg = LoraConfig(
                r=int(lora_r),
                lora_alpha=int(lora_alpha),
                lora_dropout=float(lora_dropout),
                bias="none",
                target_modules=target_modules,
                task_type=TaskType.CAUSAL_LM,
            )
            peft_model = get_peft_model(model, lora_cfg)
            # Make adapter config stable across machines (avoid absolute base_model_dir path leakage).
            for pcfg in getattr(peft_model, "peft_config", {}).values():
                try:
                    pcfg.base_model_name_or_path = f"sha256:{base_model_root_hash}"
                except Exception:  # noqa: BLE001
                    continue

            peft_model.train()
            params = [p for p in peft_model.parameters() if bool(getattr(p, "requires_grad", False))]
            if not params:
                raise FailClosedError("FAIL_CLOSED: no trainable parameters for hf_lora engine (unexpected)")
            opt = torch.optim.AdamW(params, lr=float(lr))

            vocab_size = int(getattr(peft_model.config, "vocab_size", 0) or 0)
            if vocab_size <= 0:
                raise FailClosedError("FAIL_CLOSED: model vocab_size missing/invalid")
            data_seed = (int(cfg.seed) ^ int(dataset_hash[:16], 16)) & 0xFFFFFFFF
            g = torch.Generator(device="cpu").manual_seed(int(data_seed))
            input_ids = torch.randint(0, vocab_size, (int(batch_size), int(seq_len)), generator=g, dtype=torch.long)

            loss_last: float = 0.0
            for _step in range(int(max_steps)):
                out = peft_model(input_ids=input_ids, labels=input_ids)
                loss = getattr(out, "loss", None)
                if loss is None:
                    raise FailClosedError("FAIL_CLOSED: model did not produce loss")
                loss_last = float(loss.detach().cpu().item())
                loss.backward()
                opt.step()
                opt.zero_grad(set_to_none=True)

            adapter_dir = (out_dir / "adapter").resolve()
            adapter_dir.mkdir(parents=True, exist_ok=False)
            peft_model.save_pretrained(adapter_dir, safe_serialization=True)

            artifact_path = (out_dir / "adapter_artifact.zip").resolve()
            fixed_dt = (1980, 1, 1, 0, 0, 0)
            files = [p for p in adapter_dir.rglob("*") if p.is_file()]
            files.sort(key=lambda p: p.relative_to(adapter_dir).as_posix())
            with artifact_path.open("xb") as handle:
                with zipfile.ZipFile(handle, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for p in files:
                        rel = p.relative_to(adapter_dir).as_posix()
                        data = p.read_bytes()
                        zi = zipfile.ZipInfo(rel, date_time=fixed_dt)
                        zi.compress_type = zipfile.ZIP_DEFLATED
                        zi.external_attr = (0o644 & 0xFFFF) << 16
                        zf.writestr(zi, data)
            artifact_hash = _sha256_file(artifact_path)

            manifest["produced"]["output_adapter_hash"] = artifact_hash
            manifest["produced"]["output_adapter_path"] = artifact_path.as_posix()
            manifest["produced"]["hf_lora"] = {
                "steps": int(max_steps),
                "batch_size": int(batch_size),
                "seq_len": int(seq_len),
                "lr": float(lr),
                "lora_rank": int(lora_r),
                "lora_alpha": int(lora_alpha),
                "lora_dropout": float(lora_dropout),
                "target_modules": list(target_modules),
                "loss_last": loss_last,
            }

            # Emit schema-bound factory artifacts for parity with stub engine.
            from schemas.schema_files import schema_version_hash  # type: ignore
            from tools.training.fl3_factory.timeutil import utc_now_z
            from tools.verification.fl3_canonical import sha256_json

            base_model_id = f"sha256:{base_model_root_hash}"
            job = {
                "job_id": cfg.job_id,
                "base_model_id": base_model_id,
                "training_mode": cfg.training_mode,
                "adapter_id": cfg.adapter_id,
                "adapter_version": cfg.adapter_version,
            }
            dataset_obj = {"dataset_id": dataset_hash}

            train_manifest = {
                "schema_id": "kt.factory.train_manifest.v1",
                "schema_version_hash": schema_version_hash("fl3/kt.factory.train_manifest.v1.json"),
                "train_id": "",
                "job_id": job["job_id"],
                "dataset_id": dataset_obj["dataset_id"],
                "base_model_id": job["base_model_id"],
                "training_mode": job["training_mode"],
                "output_bundle": {"artifact_path": artifact_path.as_posix(), "artifact_hash": artifact_hash},
                "created_at": utc_now_z(),
            }
            train_manifest["train_id"] = sha256_json({k: v for k, v in train_manifest.items() if k not in {"created_at", "train_id"}})
            validate_schema_bound_object(train_manifest)
            _write_json_worm(path=out_dir / "train_manifest.json", obj=train_manifest, label="train_manifest.json")
            manifest["produced"]["train_manifest_id"] = train_manifest.get("train_id")

            trace = build_reasoning_trace(job_id=cfg.job_id, final_output_hash=artifact_hash)
            validate_schema_bound_object(trace)
            _write_json_worm(path=out_dir / "reasoning_trace.json", obj=trace, label="reasoning_trace.json")
            manifest["produced"]["trace_id"] = trace.get("trace_id")

            eval_report = build_eval_report(job=job, trace=trace)
            validate_schema_bound_object(eval_report)
            _write_json_worm(path=out_dir / "eval_report.json", obj=eval_report, label="eval_report.json")
            manifest["produced"]["eval_id"] = eval_report.get("eval_id")

            manifest["status"] = "PASS"
            _write_json_worm(path=out_dir / "training_run_manifest.PASS.json", obj=manifest, label="training_run_manifest.PASS.json")
            verdict = f"KT_RAPID_LORA_PASS cmd=train engine=hf_lora job_id={cfg.job_id} out_dir={out_dir.as_posix()}"
            write_text_worm(path=out_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")

            hashes: List[Tuple[str, str, str]] = []
            hashes.append(("sha256", dataset_hash, "dataset_root_hash"))
            hashes.append(("sha256", _sha256_file(Path(dataset_manifest_path)), "dataset_hash_manifest.json"))
            hashes.append(("sha256", config_sha, "config_sha256"))
            hashes.append(("sha256", base_model_root_hash, "base_model_root_hash"))
            hashes.append(("sha256", _sha256_file(out_dir / "base_model_hash_manifest.json"), "base_model_hash_manifest.json"))
            hashes.append(("sha256", _sha256_file(out_dir / "training_run_manifest.PASS.json"), "training_run_manifest.PASS.json"))
            hashes.append(("sha256", _sha256_file(out_dir / "train_manifest.json"), "train_manifest.json"))
            hashes.append(("sha256", _sha256_file(out_dir / "reasoning_trace.json"), "reasoning_trace.json"))
            hashes.append(("sha256", _sha256_file(out_dir / "eval_report.json"), "eval_report.json"))
            hashes.append(("sha256", artifact_hash, "adapter_artifact"))
            hashes.append(("sha256", _sha256_file(out_dir / "verdict.txt"), "verdict.txt"))
            hashes_txt = "\n".join([f"{algo} {h}  {name}" for (algo, h, name) in hashes]) + "\n"
            write_text_worm(path=out_dir / "hashes.txt", text=hashes_txt, label="hashes.txt")

            print(verdict)
            return 0

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
        manifest["produced"]["output_adapter_hash"] = train_manifest.get("output_bundle", {}).get("artifact_hash")
        manifest["produced"]["output_adapter_path"] = train_manifest.get("output_bundle", {}).get("artifact_path")

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
        verdict = f"KT_RAPID_LORA_PASS cmd=train engine=stub job_id={cfg.job_id} out_dir={out_dir.as_posix()}"
        write_text_worm(path=out_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")

        # Hash list (WORM): stable pointers for operators.
        hashes: List[Tuple[str, str, str]] = []
        hashes.append(("sha256", dataset_hash, "dataset_root_hash"))
        if dataset_manifest_path:
            hashes.append(("sha256", _sha256_file(Path(dataset_manifest_path)), "dataset_hash_manifest.json"))
        hashes.append(("sha256", config_sha, "config_sha256"))
        hashes.append(("sha256", _sha256_file(out_dir / "training_run_manifest.PASS.json"), "training_run_manifest.PASS.json"))
        hashes.append(("sha256", _sha256_file(out_dir / "train_manifest.json"), "train_manifest.json"))
        hashes.append(("sha256", _sha256_file(out_dir / "reasoning_trace.json"), "reasoning_trace.json"))
        hashes.append(("sha256", _sha256_file(out_dir / "eval_report.json"), "eval_report.json"))
        if isinstance(manifest["produced"].get("output_adapter_path"), str) and manifest["produced"]["output_adapter_path"]:
            ap = Path(str(manifest["produced"]["output_adapter_path"]))
            if not ap.is_absolute():
                ap = (out_dir / ap).resolve()
            if ap.exists():
                hashes.append(("sha256", _sha256_file(ap), "adapter_artifact"))
        hashes.append(("sha256", _sha256_file(out_dir / "verdict.txt"), "verdict.txt"))
        hashes_txt = "\n".join([f"{algo} {h}  {name}" for (algo, h, name) in hashes]) + "\n"
        write_text_worm(path=out_dir / "hashes.txt", text=hashes_txt, label="hashes.txt")

        print(verdict)
        return 0

    except FailClosedError as exc:
        manifest["status"] = "FAIL_CLOSED"
        manifest["error"] = str(exc)
        _write_json_worm(path=out_dir / "training_run_manifest.FAIL_CLOSED.json", obj=manifest, label="training_run_manifest.FAIL_CLOSED.json")
        verdict = f"KT_RAPID_LORA_FAIL_CLOSED cmd=train engine={args.engine} job_id={cfg.job_id} out_dir={out_dir.as_posix()}"
        write_text_worm(path=out_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
        print(str(exc))
        print(verdict)
        return 2
    except FL3ValidationError as exc:
        manifest["status"] = "FAIL_CLOSED"
        manifest["error"] = f"schema_validation:{str(exc)}"
        _write_json_worm(path=out_dir / "training_run_manifest.FAIL_CLOSED.json", obj=manifest, label="training_run_manifest.FAIL_CLOSED.json")
        verdict = f"KT_RAPID_LORA_FAIL_CLOSED cmd=train engine={args.engine} job_id={cfg.job_id} out_dir={out_dir.as_posix()}"
        write_text_worm(path=out_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
        print(str(exc))
        print(verdict)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
