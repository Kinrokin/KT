from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Tuple

import torch
from safetensors.torch import save_file

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import repo_root_from, sha256_bytes, sha256_json


def _schema_hash(schema_file: str) -> str:
    from schemas.schema_files import schema_version_hash  # type: ignore

    return schema_version_hash(schema_file)


def _features_from_text(text: str, *, dim: int) -> torch.Tensor:
    b = hashlib.sha256(text.encode("utf-8")).digest()
    vals = [(x / 255.0) for x in b[:dim]]
    return torch.tensor(vals, dtype=torch.float32)


def _build_xy(*, dataset: Dict[str, Any], dim: int) -> Tuple[torch.Tensor, torch.Tensor]:
    rows = dataset.get("rows")
    if not isinstance(rows, list) or len(rows) == 0:
        raise ValueError("dataset.rows missing/empty (fail-closed)")
    xs = []
    ys = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("dataset row must be object (fail-closed)")
        text = row.get("text")
        label = row.get("label")
        if not isinstance(text, str) or not isinstance(label, int):
            raise ValueError("dataset rows must contain text:str and label:int (fail-closed)")
        xs.append(_features_from_text(text, dim=dim))
        ys.append(label)
    x = torch.stack(xs, dim=0)
    y = torch.tensor(ys, dtype=torch.long)
    return x, y


def _train_head_only(*, x: torch.Tensor, y: torch.Tensor, seed: int) -> Dict[str, torch.Tensor]:
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)

    model = torch.nn.Linear(x.shape[1], 2)
    opt = torch.optim.SGD(model.parameters(), lr=0.2)
    loss_fn = torch.nn.CrossEntropyLoss()

    # Tiny, deterministic training loop (real gradients, bounded steps).
    for _ in range(25):
        opt.zero_grad(set_to_none=True)
        logits = model(x)
        loss = loss_fn(logits, y)
        loss.backward()
        opt.step()

    return {"head.weight": model.weight.detach().cpu(), "head.bias": model.bias.detach().cpu()}


def _train_lora_toy(*, x: torch.Tensor, y: torch.Tensor, seed: int, rank: int = 4) -> Dict[str, torch.Tensor]:
    """
    Minimal LoRA-like training without loading a large base model.
    This produces real tensors and real gradients, but is intentionally tiny.
    """
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)

    in_dim = x.shape[1]
    out_dim = 2
    # Frozen base weight (deterministic, not trained here).
    base = torch.nn.Linear(in_dim, out_dim, bias=False)
    for p in base.parameters():
        p.requires_grad_(False)

    # LoRA matrices A (out_dim x rank) and B (rank x in_dim)
    a = torch.nn.Parameter(torch.zeros(out_dim, rank))
    b = torch.nn.Parameter(torch.zeros(rank, in_dim))
    torch.nn.init.normal_(a, mean=0.0, std=0.01)
    torch.nn.init.normal_(b, mean=0.0, std=0.01)

    opt = torch.optim.SGD([a, b], lr=0.5)
    loss_fn = torch.nn.CrossEntropyLoss()

    for _ in range(25):
        opt.zero_grad(set_to_none=True)
        w_eff = base.weight + (a @ b)
        logits = x @ w_eff.t()
        loss = loss_fn(logits, y)
        loss.backward()
        opt.step()

    return {"lora.A": a.detach().cpu(), "lora.B": b.detach().cpu(), "base.weight": base.weight.detach().cpu()}


def build_train_manifest(*, job: Dict[str, Any], dataset: Dict[str, Any], out_dir: Path) -> Dict[str, Any]:
    training_mode = str(job["training_mode"])

    dim = 16
    x, y = _build_xy(dataset=dataset, dim=dim)

    seed = int(job.get("seed", 0))
    if training_mode == "head_only":
        tensors = _train_head_only(x=x, y=y, seed=seed)
    elif training_mode == "lora":
        tensors = _train_lora_toy(x=x, y=y, seed=seed)
    else:
        raise ValueError("training_mode must be head_only or lora (fail-closed)")

    bundle_dir = out_dir / "bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    weights_path = bundle_dir / "weights.safetensors"
    save_file(tensors, str(weights_path))

    artifact_hash = sha256_bytes(weights_path.read_bytes())

    repo_root = repo_root_from(Path(__file__))
    artifact_rel = weights_path.resolve().relative_to(repo_root.resolve()).as_posix()

    record = {
        "schema_id": "kt.factory.train_manifest.v1",
        "schema_version_hash": _schema_hash("fl3/kt.factory.train_manifest.v1.json"),
        "train_id": "",
        "job_id": job["job_id"],
        "dataset_id": dataset["dataset_id"],
        "base_model_id": job["base_model_id"],
        "training_mode": training_mode,
        "output_bundle": {"artifact_path": artifact_rel, "artifact_hash": artifact_hash},
        "created_at": utc_now_z(),
    }
    record["train_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "train_id"}})
    return record

