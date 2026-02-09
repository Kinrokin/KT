from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tools.verification.strict_json import load_no_dupes


class Phase2TrainError(RuntimeError):
    pass


def _repo_root_from(this_file: Path) -> Path:
    p = this_file.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").exists():
            return parent
    raise Phase2TrainError("FAIL_CLOSED: unable to locate repo root (missing KT_PROD_CLEANROOM/)")


def _bootstrap_syspath(*, repo_root: Path) -> None:
    """
    Must be runnable via `python -m tools.training.phase2_train` without relying on PYTHONPATH.

    NOTE: This does not (and cannot) retroactively enforce sitecustomize at interpreter startup.
    We explicitly import sitecustomize after sys.path bootstrapping so KT_IO_GUARD can be installed
    even when callers didn't preconfigure PYTHONPATH.
    """
    import sys

    src_root = (repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()
    cleanroom_root = (repo_root / "KT_PROD_CLEANROOM").resolve()
    for p in (str(src_root), str(cleanroom_root)):
        if p not in sys.path:
            sys.path.insert(0, p)


def _canonical_json(obj: object) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical_json(obj), encoding="utf-8", newline="\n")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git_sha(repo_root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo_root), text=True).strip()
    except Exception as exc:  # noqa: BLE001
        raise Phase2TrainError(f"FAIL_CLOSED: unable to resolve git sha: {exc.__class__.__name__}")


def _enforce_offline_and_guard() -> None:
    if os.environ.get("KT_LIVE") != "0":
        raise Phase2TrainError("FAIL_CLOSED: MRT-1 requires offline mode: KT_LIVE must be 0")
    if os.environ.get("KT_IO_GUARD") != "1":
        raise Phase2TrainError("FAIL_CLOSED: MRT-1 requires IO guard: KT_IO_GUARD must be 1")
    if os.environ.get("KT_IO_GUARD_DENY_NETWORK", "1") != "1":
        raise Phase2TrainError("FAIL_CLOSED: MRT-1 requires deny-network: KT_IO_GUARD_DENY_NETWORK must be 1")
    if not os.environ.get("KT_IO_GUARD_ALLOWED_WRITE_ROOTS", "").strip():
        raise Phase2TrainError("FAIL_CLOSED: MRT-1 requires KT_IO_GUARD_ALLOWED_WRITE_ROOTS (JSON list) to be set")


def _require_io_guard_installed() -> None:
    # Ensure sitecustomize runs (installs kt_io_guard) once sys.path includes KT_PROD_CLEANROOM.
    import importlib

    importlib.import_module("sitecustomize")
    try:
        import kt_io_guard  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise Phase2TrainError(f"FAIL_CLOSED: IO guard not importable as kt_io_guard: {exc.__class__.__name__}")
    guard = getattr(kt_io_guard, "_GLOBAL_GUARD", None)
    if guard is None:
        raise Phase2TrainError("FAIL_CLOSED: IO guard not installed (_GLOBAL_GUARD is None)")


def _validate_clean_relative_path(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise Phase2TrainError(f"FAIL_CLOSED: {field} must be a non-empty string")
    norm = value.replace("\\", "/").strip()
    p = Path(norm)
    if p.is_absolute():
        raise Phase2TrainError(f"FAIL_CLOSED: {field} must be a relative path")
    if any(part in {".", ".."} for part in p.parts):
        raise Phase2TrainError(f"FAIL_CLOSED: {field} must not contain '.' or '..' segments")
    return norm


@dataclass(frozen=True)
class TrainPaths:
    export_shadow_root_rel: str
    export_shadow_root_abs: Path
    export_promoted_root_rel: str
    export_promoted_root_abs: Path
    run_dir_rel: str
    run_dir_abs: Path


def _resolve_export_roots(
    *, repo_root: Path, export_shadow_root: str, export_promoted_root: str, adapter_id: str, adapter_version: str, request_id: str
) -> TrainPaths:
    from tools.verification.fl3_validators import assert_relpath_under_exports_mrt1  # type: ignore

    shadow_rel = _validate_clean_relative_path(export_shadow_root, field="output.export_root_shadow")
    promoted_rel = _validate_clean_relative_path(export_promoted_root, field="output.export_root_promoted")

    if not shadow_rel.startswith("KT_PROD_CLEANROOM/exports/adapters_mrt1_shadow"):
        raise Phase2TrainError("FAIL_CLOSED: export_root_shadow must be under KT_PROD_CLEANROOM/exports/adapters_mrt1_shadow")
    if not promoted_rel.startswith("KT_PROD_CLEANROOM/exports/adapters_mrt1"):
        raise Phase2TrainError("FAIL_CLOSED: export_root_promoted must be under KT_PROD_CLEANROOM/exports/adapters_mrt1")

    shadow_abs = assert_relpath_under_exports_mrt1(repo_root=repo_root, relpath=shadow_rel, allow_promoted=False)
    promoted_abs = assert_relpath_under_exports_mrt1(repo_root=repo_root, relpath=promoted_rel, allow_promoted=True)

    run_dir_rel = f"{shadow_rel}/{adapter_id}/{adapter_version}/{request_id}".replace("\\", "/")
    run_dir_abs = (repo_root / run_dir_rel).resolve()
    # Must still be under MRT-1 shadow roots.
    _ = assert_relpath_under_exports_mrt1(repo_root=repo_root, relpath=run_dir_rel, allow_promoted=False)

    return TrainPaths(
        export_shadow_root_rel=shadow_rel,
        export_shadow_root_abs=shadow_abs,
        export_promoted_root_rel=promoted_rel,
        export_promoted_root_abs=promoted_abs,
        run_dir_rel=run_dir_rel,
        run_dir_abs=run_dir_abs,
    )


def _derive_role_id_from_adapter_id(*, repo_root: Path, adapter_id: str) -> str:
    # Doctrine-bound: ROLE_FITNESS_WEIGHTS.json is the canonical role list.
    weights_path = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "ROLE_FITNESS_WEIGHTS.json"
    obj = load_no_dupes(weights_path)
    if not isinstance(obj, dict):
        raise Phase2TrainError("FAIL_CLOSED: ROLE_FITNESS_WEIGHTS.json must be object")
    roles = obj.get("roles")
    if not isinstance(roles, list):
        raise Phase2TrainError("FAIL_CLOSED: ROLE_FITNESS_WEIGHTS.roles must be list")
    role_ids = []
    for r in roles:
        if isinstance(r, dict) and isinstance(r.get("role_id"), str):
            role_ids.append(r["role_id"].strip())
    if "ARBITER" not in set(role_ids) or len(set(role_ids)) != 14:
        raise Phase2TrainError("FAIL_CLOSED: doctrine drift detected (expected 14 roles incl ARBITER)")

    # Expected canonical mapping: lobe.<role_id.lower()>.v1 (ARBITER excluded from lobes).
    if not adapter_id.startswith("lobe.") or not adapter_id.endswith(".v1"):
        raise Phase2TrainError("FAIL_CLOSED: adapter_id must match lobe.<role>.v1 for MRT-1 training")
    role_lower = adapter_id[len("lobe.") : -len(".v1")]
    if not role_lower or any(ch for ch in role_lower if not (ch.islower() or ch == "_")):
        raise Phase2TrainError("FAIL_CLOSED: adapter_id role segment must be lowercase letters/underscore")
    role_id = role_lower.upper()
    if role_id == "ARBITER":
        raise Phase2TrainError("FAIL_CLOSED: ARBITER is not a trainable lobe (exclude by doctrine)")
    if role_id not in set(role_ids):
        raise Phase2TrainError(f"FAIL_CLOSED: adapter_id role_id {role_id!r} not present in doctrine")
    return role_id


def _build_train_request(
    *,
    repo_root: Path,
    work_order_id: str,
    pinned_sha: str,
    adapter_id: str,
    adapter_version: str,
    role_id: str,
    base_model_id: str,
    base_model_path: str,
    dataset_path: str,
    dataset_sha256: str,
    seed: int,
    device: str,
    export_shadow_root: str,
    export_promoted_root: str,
) -> Dict[str, Any]:
    from schemas.fl3_schema_common import sha256_hex_of_obj  # type: ignore
    from schemas.schema_files import schema_version_hash  # type: ignore
    from tools.verification.fl3_validators import validate_schema_bound_object  # type: ignore

    req: Dict[str, Any] = {
        "schema_id": "kt.phase2_train_request.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.phase2_train_request.v1.json"),
        "schema_version": 1,
        "train_request_id": "",
        "work_order_id": work_order_id,
        "pinned_sha": pinned_sha,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "role_id": role_id,
        "training_mode": "lora_mrt1",
        "base_model": {"model_id": base_model_id, "local_path": base_model_path},
        "dataset_manifest_ref": {"path": dataset_path, "sha256": dataset_sha256},
        "seed": int(seed),
        "device": device,
        "output": {"export_root_shadow": export_shadow_root, "export_root_promoted": export_promoted_root},
        "created_at": _utc_now_z(),
    }
    req["train_request_id"] = sha256_hex_of_obj(req, drop_keys={"train_request_id", "created_at"})
    validate_schema_bound_object(req)
    return req


def _iter_text_samples(dataset_jsonl: Path) -> Iterable[str]:
    for line in dataset_jsonl.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except Exception:
            # Treat raw lines as text samples (fallback).
            yield line
            continue
        if isinstance(obj, str):
            yield obj
            continue
        if isinstance(obj, dict):
            for k in ("text", "prompt", "input"):
                if isinstance(obj.get(k), str) and obj[k].strip():
                    # Common patterns: prompt+completion, input+output.
                    if k in {"prompt", "input"}:
                        tail = obj.get("completion") or obj.get("output") or obj.get("response") or ""
                        if isinstance(tail, str) and tail.strip():
                            yield obj[k] + "\n" + tail
                        else:
                            yield obj[k]
                    else:
                        yield obj[k]
                    break


def _safe_write_failure_evidence(run_dir_abs: Path, *, failure_reason: str) -> None:
    (run_dir_abs / "error.txt").write_text(failure_reason.strip() + "\n", encoding="utf-8", newline="\n")


def _build_weight_manifest(
    *, adapter_id: str, adapter_version: str, base_model_id: str, run_dir_abs: Path, created_at: str
) -> Dict[str, Any]:
    from schemas.fl3_schema_common import sha256_hex_of_obj  # type: ignore
    from schemas.schema_files import schema_version_hash  # type: ignore
    from tools.verification.fl3_validators import validate_schema_bound_object  # type: ignore

    # The manifest/root_hash is the content-addressed surface used for promotion (content_hash).
    # It MUST NOT include wall-clock dependent files (e.g. train_request.json created_at, receipts)
    # or circular self-references (the manifest itself).
    excluded_names = {
        "train_request.json",  # contains created_at; request_id is deterministic but file bytes are not
        "train_receipt.json",  # contains created_at and references content_hash; would be circular
        "adapter_weight_manifest.json",  # circular/self-reference
    }

    files: List[Dict[str, Any]] = []
    for p in sorted([x for x in run_dir_abs.rglob("*") if x.is_file()], key=lambda x: x.as_posix()):
        if p.name in excluded_names:
            continue
        rel = p.relative_to(run_dir_abs).as_posix()
        files.append({"path": rel, "sha256": _sha256_file(p), "bytes": int(p.stat().st_size)})
    if not files:
        raise Phase2TrainError("FAIL_CLOSED: no files present to manifest")

    root_hash = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    manifest: Dict[str, Any] = {
        "schema_id": "kt.adapter_weight_artifact_manifest.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.adapter_weight_artifact_manifest.v1.json"),
        "schema_version": 1,
        "manifest_id": "",
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "training_mode": "lora_mrt1",
        "base_model_id": base_model_id,
        "root_hash": root_hash,
        "files": files,
        "created_at": created_at,
    }
    manifest["manifest_id"] = sha256_hex_of_obj(manifest, drop_keys={"manifest_id", "created_at"})
    validate_schema_bound_object(manifest)
    return manifest


def _build_train_receipt(
    *,
    pinned_sha: str,
    adapter_id: str,
    adapter_version: str,
    status: str,
    failure_reason: Optional[str],
    base_model_id: str,
    base_model_path: str,
    dataset_path: str,
    dataset_sha256: str,
    train_request_id: str,
    shadow_dir_rel: str,
    content_hash: str,
    artifact_manifest_path_rel: str,
    artifact_manifest_sha256: str,
    created_at: str,
) -> Dict[str, Any]:
    from schemas.fl3_schema_common import sha256_hex_of_obj  # type: ignore
    from schemas.schema_files import schema_version_hash  # type: ignore
    from tools.verification.fl3_validators import validate_schema_bound_object  # type: ignore

    receipt: Dict[str, Any] = {
        "schema_id": "kt.phase2_train_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.phase2_train_receipt.v1.json"),
        "schema_version": 1,
        "train_receipt_id": "",
        "train_request_id": train_request_id,
        "pinned_sha": pinned_sha,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "training_mode": "lora_mrt1",
        "status": status,
        "failure_reason": failure_reason,
        "base_model": {"model_id": base_model_id, "local_path": base_model_path},
        "dataset_manifest_ref": {"path": dataset_path, "sha256": dataset_sha256},
        "output_package": {
            "shadow_dir": shadow_dir_rel,
            "promoted_dir": None,
            "content_hash": content_hash,
        },
        "artifact_manifest_ref": {
            "path": artifact_manifest_path_rel,
            "sha256": artifact_manifest_sha256,
        },
        "io_guard_receipt_glob": "io_guard_receipt*.json",
        "created_at": created_at,
    }
    receipt["train_receipt_id"] = sha256_hex_of_obj(receipt, drop_keys={"train_receipt_id", "created_at"})
    validate_schema_bound_object(receipt)
    return receipt


def _run_lora_training(*, req: Dict[str, Any], run_dir_abs: Path, trainer_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes a minimal LoRA training loop.

    Fail-closed guarantees:
    - No network (IO guard).
    - No base model download (must exist at local_path).
    - Only LoRA params trainable; base frozen.

    This function intentionally imports heavy deps lazily so CI remains lightweight.
    """
    try:
        import random

        import torch  # type: ignore
        from peft import LoraConfig, get_peft_model  # type: ignore
        import safetensors  # noqa: F401  # type: ignore
        from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise Phase2TrainError(
            f"FAIL_CLOSED: missing training dependencies (torch/transformers/peft/safetensors): {exc.__class__.__name__}"
        )

    seed = int(req["seed"])
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)

    device_req = str(req.get("device", "auto"))
    if device_req == "cpu":
        device = torch.device("cpu")
    elif device_req == "cuda":
        device = torch.device("cuda")
    else:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    base_model_path = Path(req["base_model"]["local_path"]).expanduser()
    if not base_model_path.exists():
        raise Phase2TrainError("FAIL_CLOSED: base_model.local_path does not exist (offline required)")

    # Load base model/tokenizer strictly from local path.
    tokenizer = AutoTokenizer.from_pretrained(str(base_model_path), local_files_only=True, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Memory-safety: on GPU, load weights in fp16 to avoid fp32 OOM on 7B-class models.
    # Optional QLoRA path is supported via bitsandbytes 4-bit quantization.
    model_kwargs: Dict[str, Any] = {"local_files_only": True, "low_cpu_mem_usage": True}
    if device.type == "cuda":
        model_kwargs["torch_dtype"] = torch.float16

    load_in_4bit = bool(trainer_cfg.get("load_in_4bit", False))
    if load_in_4bit:
        try:
            from transformers import BitsAndBytesConfig  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise Phase2TrainError(
                f"FAIL_CLOSED: --load-in-4bit requested but BitsAndBytesConfig unavailable: {exc.__class__.__name__}"
            )
        try:
            import bitsandbytes  # noqa: F401  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise Phase2TrainError(
                f"FAIL_CLOSED: --load-in-4bit requested but bitsandbytes not installed: {exc.__class__.__name__}"
            )

        dtype_s = str(trainer_cfg.get("bnb_4bit_compute_dtype", "float16"))
        if dtype_s == "bfloat16":
            compute_dtype = torch.bfloat16
        elif dtype_s == "float32":
            compute_dtype = torch.float32
        else:
            compute_dtype = torch.float16

        model_kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type=str(trainer_cfg.get("bnb_4bit_quant_type", "nf4")),
            bnb_4bit_use_double_quant=bool(trainer_cfg.get("bnb_4bit_use_double_quant", True)),
            bnb_4bit_compute_dtype=compute_dtype,
        )

    model = AutoModelForCausalLM.from_pretrained(str(base_model_path), **model_kwargs)
    model.config.use_cache = False
    if bool(trainer_cfg.get("gradient_checkpointing", True)) and hasattr(model, "gradient_checkpointing_enable"):
        try:
            model.gradient_checkpointing_enable()  # type: ignore[attr-defined]
        except Exception:
            pass
    model.to(device)
    model.train()
    for p in model.parameters():
        p.requires_grad_(False)

    if load_in_4bit:
        try:
            from peft import prepare_model_for_kbit_training  # type: ignore
        except Exception as exc:  # noqa: BLE001
            try:
                from peft.utils.other import prepare_model_for_kbit_training  # type: ignore
            except Exception:  # noqa: BLE001
                raise Phase2TrainError(
                    "FAIL_CLOSED: --load-in-4bit requested but prepare_model_for_kbit_training unavailable: "
                    f"{exc.__class__.__name__}"
                )
        model = prepare_model_for_kbit_training(
            model, use_gradient_checkpointing=bool(trainer_cfg.get("gradient_checkpointing", True))
        )

    # Mistral-style defaults; safe for many decoder-only models.
    target_modules = trainer_cfg.get("target_modules") or [
        "q_proj",
        "k_proj",
        "v_proj",
        "o_proj",
        "gate_proj",
        "up_proj",
        "down_proj",
    ]
    lora_cfg = LoraConfig(
        r=int(trainer_cfg.get("lora_r", 8)),
        lora_alpha=int(trainer_cfg.get("lora_alpha", 16)),
        target_modules=list(target_modules),
        lora_dropout=float(trainer_cfg.get("lora_dropout", 0.05)),
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_cfg)
    model.to(device)

    # Minimal dataset: JSONL -> text samples -> token IDs.
    ds_path = Path(req["dataset_manifest_ref"]["path"]).expanduser()
    if not ds_path.exists():
        raise Phase2TrainError("FAIL_CLOSED: dataset path does not exist")

    texts = list(_iter_text_samples(ds_path))
    if not texts:
        raise Phase2TrainError("FAIL_CLOSED: no usable text samples in dataset")

    max_samples = int(trainer_cfg.get("max_samples", 0) or 0)
    if max_samples > 0:
        texts = texts[:max_samples]

    max_len = int(trainer_cfg.get("max_seq_len", 256))
    enc = tokenizer(texts, return_tensors="pt", padding=True, truncation=True, max_length=max_len)
    input_ids = enc["input_ids"].to(device)
    attention_mask = enc.get("attention_mask")
    if attention_mask is not None:
        attention_mask = attention_mask.to(device)

    labels = input_ids.clone()

    bs = max(1, int(trainer_cfg.get("batch_size", 1)))
    lr = float(trainer_cfg.get("lr", 1e-4))
    max_steps = max(1, int(trainer_cfg.get("max_steps", 10)))

    trainable = [p for p in model.parameters() if getattr(p, "requires_grad", False)]
    if not trainable:
        raise Phase2TrainError("FAIL_CLOSED: no trainable parameters (expected LoRA params)")
    opt = torch.optim.AdamW(trainable, lr=lr)
    losses: List[float] = []
    n = input_ids.size(0)
    for step in range(max_steps):
        idx0 = (step * bs) % n
        idx = torch.arange(idx0, min(n, idx0 + bs), device=device)
        xb = input_ids.index_select(0, idx)
        yb = labels.index_select(0, idx)
        ab = attention_mask.index_select(0, idx) if attention_mask is not None else None

        opt.zero_grad(set_to_none=True)
        out = model(input_ids=xb, attention_mask=ab, labels=yb)
        loss = out.loss
        if loss is None:
            raise Phase2TrainError("FAIL_CLOSED: model output missing loss")
        loss.backward()
        opt.step()
        losses.append(float(loss.detach().cpu().item()))

    # Save adapter weights/config.
    # peft will write adapter_model.safetensors when safetensors is installed and safe_serialization=True.
    model.save_pretrained(run_dir_abs, safe_serialization=True)
    if not (run_dir_abs / "adapter_model.safetensors").exists():
        raise Phase2TrainError("FAIL_CLOSED: expected adapter_model.safetensors not produced (safetensors required)")
    if not (run_dir_abs / "adapter_config.json").exists():
        raise Phase2TrainError("FAIL_CLOSED: expected adapter_config.json not produced")

    mean_loss = sum(losses) / max(1, len(losses))
    report = {
        "kind": "phase2_train_eval_report",
        "mean_train_loss": mean_loss,
        "steps": max_steps,
        "batch_size": bs,
        "lr": lr,
        "device": str(device),
    }
    _write_json(run_dir_abs / "eval_report.json", report)
    return report


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Phase2 MRT-1 trainer (LoRA; fail-closed; offline + IO-guarded).")
    ap.add_argument("--work-order", required=True, help="Path to kt.phase2_work_order.v1.json")
    ap.add_argument("--adapter-id", required=True, help="Adapter ID (doctrine-derived lobe.*.v1)")
    ap.add_argument("--adapter-version", default="1")
    ap.add_argument("--base-model-id", required=True, help="Base model identifier (recorded in receipts)")
    ap.add_argument("--base-model-path", required=True, help="Local path to base model (offline required)")
    ap.add_argument("--dataset", required=True, help="Dataset JSONL path (offline; content-hash bound)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    ap.add_argument(
        "--export-shadow-root",
        default="KT_PROD_CLEANROOM/exports/adapters_mrt1_shadow/_runs",
        help="Relative export root for MRT-1 shadow packages.",
    )
    ap.add_argument(
        "--export-promoted-root",
        default="KT_PROD_CLEANROOM/exports/adapters_mrt1",
        help="Relative export root for MRT-1 promoted packages (promotion is separate).",
    )
    ap.add_argument("--max-steps", type=int, default=10)
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--max-seq-len", type=int, default=256)
    ap.add_argument("--max-samples", type=int, default=0, help="0 = no limit")
    ap.add_argument(
        "--gradient-checkpointing",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable gradient checkpointing for reduced VRAM (recommended for 7B-class models).",
    )
    ap.add_argument(
        "--load-in-4bit",
        action="store_true",
        help="Enable QLoRA-style 4-bit base model load (requires bitsandbytes).",
    )
    ap.add_argument(
        "--bnb-4bit-quant-type",
        default="nf4",
        choices=["nf4", "fp4"],
        help="bitsandbytes 4-bit quant type (only used with --load-in-4bit).",
    )
    ap.add_argument(
        "--bnb-4bit-compute-dtype",
        default="float16",
        choices=["float16", "bfloat16", "float32"],
        help="bitsandbytes 4-bit compute dtype (only used with --load-in-4bit).",
    )
    ap.add_argument(
        "--bnb-4bit-use-double-quant",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="bitsandbytes double quantization (only used with --load-in-4bit).",
    )
    return ap.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = _repo_root_from(Path(__file__))
    _bootstrap_syspath(repo_root=repo_root)

    _enforce_offline_and_guard()
    _require_io_guard_installed()

    work_order_path = Path(args.work_order).resolve()
    work_order = load_no_dupes(work_order_path)
    if not isinstance(work_order, dict):
        raise Phase2TrainError("FAIL_CLOSED: work order must be JSON object")
    from tools.verification.fl3_validators import validate_schema_bound_object  # type: ignore

    validate_schema_bound_object(work_order)
    if work_order.get("schema_id") != "kt.phase2_work_order.v1":
        raise Phase2TrainError("FAIL_CLOSED: work order schema_id mismatch")
    work_order_id = str(work_order.get("work_order_id", "")).strip()
    if not work_order_id:
        raise Phase2TrainError("FAIL_CLOSED: work_order_id missing/invalid")

    adapter_id = str(args.adapter_id).strip()
    adapter_version = str(args.adapter_version).strip()
    if not adapter_id or not adapter_version:
        raise Phase2TrainError("FAIL_CLOSED: adapter_id/adapter_version missing/invalid")

    pinned_sha = _git_sha(repo_root)
    role_id = _derive_role_id_from_adapter_id(repo_root=repo_root, adapter_id=adapter_id)

    dataset_path = Path(args.dataset).expanduser().resolve()
    if not dataset_path.exists():
        raise Phase2TrainError(f"FAIL_CLOSED: dataset not found: {dataset_path.as_posix()}")
    dataset_sha = _sha256_file(dataset_path)

    base_model_path = Path(args.base_model_path).expanduser().resolve()
    if not base_model_path.exists():
        raise Phase2TrainError(f"FAIL_CLOSED: base model path not found: {base_model_path.as_posix()}")

    req = _build_train_request(
        repo_root=repo_root,
        work_order_id=work_order_id,
        pinned_sha=pinned_sha,
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        role_id=role_id,
        base_model_id=str(args.base_model_id),
        base_model_path=str(base_model_path),
        dataset_path=str(dataset_path),
        dataset_sha256=dataset_sha,
        seed=int(args.seed),
        device=str(args.device),
        export_shadow_root=str(args.export_shadow_root),
        export_promoted_root=str(args.export_promoted_root),
    )

    request_id = str(req["train_request_id"])
    paths = _resolve_export_roots(
        repo_root=repo_root,
        export_shadow_root=req["output"]["export_root_shadow"],
        export_promoted_root=req["output"]["export_root_promoted"],
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        request_id=request_id,
    )

    run_dir = paths.run_dir_abs
    if run_dir.exists():
        raise Phase2TrainError(f"FAIL_CLOSED: run_dir already exists: {run_dir.as_posix()}")
    run_dir.mkdir(parents=True, exist_ok=False)

    _write_json(run_dir / "train_request.json", req)

    trainer_cfg = {
        "kind": "phase2_train_config",
        "training_mode": "lora_mrt1",
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "base_model_id": str(args.base_model_id),
        "seed": int(args.seed),
        "device": str(args.device),
        "max_steps": int(args.max_steps),
        "batch_size": int(args.batch_size),
        "lr": float(args.lr),
        "max_seq_len": int(args.max_seq_len),
        "max_samples": int(args.max_samples),
        "gradient_checkpointing": bool(args.gradient_checkpointing),
        "load_in_4bit": bool(args.load_in_4bit),
        "bnb_4bit_quant_type": str(args.bnb_4bit_quant_type),
        "bnb_4bit_compute_dtype": str(args.bnb_4bit_compute_dtype),
        "bnb_4bit_use_double_quant": bool(args.bnb_4bit_use_double_quant),
        # Stable default: Mistral-family targets; callers may override by editing this file + re-running with a new request.
        "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        "lora_r": 8,
        "lora_alpha": 16,
        "lora_dropout": 0.05,
    }
    _write_json(run_dir / "trainer_config.json", trainer_cfg)

    created_at = _utc_now_z()
    status = "PASS"
    failure_reason: Optional[str] = None

    try:
        _ = _run_lora_training(req=req, run_dir_abs=run_dir, trainer_cfg=trainer_cfg)
    except Exception as exc:  # noqa: BLE001
        status = "FAIL"
        failure_reason = f"{exc.__class__.__name__}: {str(exc)}"
        _safe_write_failure_evidence(run_dir, failure_reason=failure_reason)

    # Always emit a schema-bound manifest+receipt (even on failure) so audits can explain what happened.
    manifest = _build_weight_manifest(
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        base_model_id=str(args.base_model_id),
        run_dir_abs=run_dir,
        created_at=created_at,
    )
    manifest_path = run_dir / "adapter_weight_manifest.json"
    _write_json(manifest_path, manifest)
    # Deterministic reference: manifest_id is computed from the canonical hash surface excluding created_at.
    manifest_ref_hash = str(manifest.get("manifest_id", "")).strip()
    if len(manifest_ref_hash) != 64:
        raise Phase2TrainError("FAIL_CLOSED: manifest_id missing/invalid for artifact_manifest_ref")

    receipt = _build_train_receipt(
        pinned_sha=pinned_sha,
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        status=status,
        failure_reason=failure_reason,
        base_model_id=str(args.base_model_id),
        base_model_path=str(base_model_path),
        dataset_path=str(dataset_path),
        dataset_sha256=dataset_sha,
        train_request_id=request_id,
        shadow_dir_rel=paths.run_dir_rel,
        content_hash=str(manifest["root_hash"]),
        artifact_manifest_path_rel=f"{paths.run_dir_rel}/adapter_weight_manifest.json".replace("\\", "/"),
        artifact_manifest_sha256=manifest_ref_hash,
        created_at=created_at,
    )
    _write_json(run_dir / "train_receipt.json", receipt)

    print(json.dumps({"status": status, "run_dir": paths.run_dir_rel, "content_hash": str(manifest["root_hash"])}, indent=2))
    if status != "PASS":
        raise SystemExit("FAIL_CLOSED: training failed; see train_receipt.json + error.txt (if present)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
