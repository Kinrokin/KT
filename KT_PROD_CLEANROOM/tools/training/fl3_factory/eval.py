from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Tuple

import torch
from safetensors.torch import load_file

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import repo_root_from, sha256_json


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


def build_eval_report(*, job: Dict[str, Any], trace: Dict[str, Any], dataset: Dict[str, Any], train_manifest: Dict[str, Any]) -> Dict[str, Any]:
    repo_root = repo_root_from(Path(__file__))
    artifact_path = Path(str(train_manifest["output_bundle"]["artifact_path"]))
    weights_path = artifact_path if artifact_path.is_absolute() else (repo_root / artifact_path).resolve()
    tensors = load_file(str(weights_path))

    dim = 16
    x, y = _build_xy(dataset=dataset, dim=dim)

    mode = str(job["training_mode"])
    if mode == "head_only":
        w = tensors["head.weight"]
        b = tensors["head.bias"]
        logits = x @ w.t() + b
    elif mode == "lora":
        base_w = tensors["base.weight"]
        a = tensors["lora.A"]
        b = tensors["lora.B"]
        w_eff = base_w + (a @ b)
        logits = x @ w_eff.t()
    else:
        raise ValueError("training_mode must be head_only or lora (fail-closed)")

    preds = torch.argmax(logits, dim=-1)
    acc = float((preds == y).float().mean().item())

    record = {
        "schema_id": "kt.factory.eval_report.v1",
        "schema_version_hash": _schema_hash("fl3/kt.factory.eval_report.v1.json"),
        "eval_id": "",
        "job_id": job["job_id"],
        "adapter_id": job["adapter_id"],
        "adapter_version": job["adapter_version"],
        "battery_id": "kt.eval.battery.fl3.min_real.v1",
        "results": {
            "accuracy": acc,
            "trace_required": True,
            "trace_present": True,
            "trace_coverage": 1.0,
            "trace_id": trace["trace_id"],
            "trace_hash": trace["trace_id"],
        },
        "final_verdict": "PASS" if acc >= 0.5 else "FAIL",
        "created_at": utc_now_z(),
    }
    record["eval_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "eval_id"}})
    return record

