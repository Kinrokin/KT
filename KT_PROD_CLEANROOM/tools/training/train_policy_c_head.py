from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import torch
import torch.nn as nn


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def set_determinism(seed: int) -> None:
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)


def safe_read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def flatten_numeric(prefix: str, obj: Any, out: Dict[str, float]) -> None:
    if isinstance(obj, dict):
        for key in sorted(obj.keys()):
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            flatten_numeric(next_prefix, obj[key], out)
    elif isinstance(obj, list):
        out[f"{prefix}.__len__"] = float(len(obj))
        for idx, value in enumerate(obj[:32]):
            flatten_numeric(f"{prefix}[{idx}]", value, out)
    elif isinstance(obj, bool):
        out[prefix] = 1.0 if obj else 0.0
    elif is_number(obj):
        out[prefix] = float(obj)


def feature_hash(features: Dict[str, float], dim: int) -> torch.Tensor:
    x = torch.zeros(dim, dtype=torch.float32)
    for key, value in features.items():
        h = hashlib.sha256(key.encode("utf-8")).digest()
        idx = int.from_bytes(h[:4], "little") % dim
        sign = -1.0 if (h[4] & 1) else 1.0
        x[idx] += sign * float(value)
    return x


@dataclass
class RecordRefs:
    pressure_tensor_path: Path | None
    epoch_summary_path: Path | None
    drift_report_path: Path | None
    status: str


def parse_record(line: str) -> Dict[str, Any]:
    return json.loads(line)


def normalize_ref_path(raw: str) -> Path:
    return Path(raw)


def _path_from_ref(ref: Dict[str, Any]) -> Path | None:
    raw = ref.get("path")
    return normalize_ref_path(raw) if isinstance(raw, str) and raw else None


def load_record_refs(rec: Dict[str, Any]) -> RecordRefs:
    ptr = rec.get("pressure_tensor_ref", {}) or {}
    esr = rec.get("epoch_summary_ref", {}) or {}
    drr = rec.get("drift_report_ref", {}) or {}
    labels = rec.get("labels", {}) or {}
    return RecordRefs(
        pressure_tensor_path=_path_from_ref(ptr),
        epoch_summary_path=_path_from_ref(esr),
        drift_report_path=_path_from_ref(drr),
        status=str(labels.get("status", "UNKNOWN")),
    )


def build_features(refs: RecordRefs) -> Dict[str, float]:
    feats: Dict[str, float] = {}
    if refs.pressure_tensor_path and refs.pressure_tensor_path.exists():
        flatten_numeric("pressure_tensor", safe_read_json(refs.pressure_tensor_path), feats)
    if refs.epoch_summary_path and refs.epoch_summary_path.exists():
        flatten_numeric("epoch_summary", safe_read_json(refs.epoch_summary_path), feats)
    if refs.drift_report_path and refs.drift_report_path.exists():
        flatten_numeric("drift_report", safe_read_json(refs.drift_report_path), feats)

    feats["has_pressure_tensor"] = 1.0 if (refs.pressure_tensor_path and refs.pressure_tensor_path.exists()) else 0.0
    feats["has_epoch_summary"] = 1.0 if (refs.epoch_summary_path and refs.epoch_summary_path.exists()) else 0.0
    feats["has_drift_report"] = 1.0 if (refs.drift_report_path and refs.drift_report_path.exists()) else 0.0
    return feats


def status_to_label(status: str) -> float:
    normalized = status.upper().strip()
    if normalized == "PASS":
        return 1.0
    if normalized == "FAIL":
        return 0.0
    return 0.0


class TinyHead(nn.Module):
    def __init__(self, dim: int) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(dim, 256),
            nn.ReLU(),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x).squeeze(-1)


def main() -> None:
    ap = argparse.ArgumentParser(description="Policy C head-only trainer (receipt -> trajectory head).")
    ap.add_argument("--dataset", required=True, help="Path to kt_policy_c_dataset_v1.jsonl")
    ap.add_argument("--output-dir", required=True, help="Output directory for head artifacts")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--feature-dim", type=int, default=1024)
    ap.add_argument("--steps", type=int, default=200)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    ap.add_argument("--max-records", type=int, default=0, help="0 = no limit")
    ap.add_argument("--require-dataset-hash", default="", help="If set, refuse unless sha256(dataset)==this")
    cfg = ap.parse_args()

    ds_path = Path(cfg.dataset).resolve()
    out_dir = Path(cfg.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not ds_path.exists():
        raise SystemExit(f"Dataset not found: {ds_path}")

    ds_hash = sha256_file(ds_path)
    if cfg.require_dataset_hash and cfg.require_dataset_hash != ds_hash:
        raise SystemExit(f"Dataset hash mismatch: expected {cfg.require_dataset_hash} got {ds_hash}")

    set_determinism(cfg.seed)

    if cfg.device == "auto":
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    elif cfg.device == "cuda":
        device = torch.device("cuda")
    else:
        device = torch.device("cpu")

    records: List[Tuple[torch.Tensor, float]] = []
    lines = ds_path.read_text(encoding="utf-8").splitlines()
    if cfg.max_records and cfg.max_records > 0:
        lines = lines[: cfg.max_records]

    for line in lines:
        if not line.strip():
            continue
        rec = parse_record(line)
        refs = load_record_refs(rec)
        feats = build_features(refs)
        x = feature_hash(feats, cfg.feature_dim)
        y = status_to_label(refs.status)
        records.append((x, y))

    if not records:
        raise SystemExit("No records loaded from dataset.")

    X = torch.stack([r[0] for r in records]).to(device)
    y = torch.tensor([r[1] for r in records], dtype=torch.float32, device=device)

    model = TinyHead(cfg.feature_dim).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=cfg.lr)
    loss_fn = nn.BCEWithLogitsLoss()

    model.train()
    n = X.shape[0]
    bs = max(1, int(cfg.batch_size))

    for step in range(cfg.steps):
        idx = torch.arange(n, device=device)
        start = (step * bs) % n
        batch_idx = idx[start : start + bs]
        xb = X[batch_idx]
        yb = y[batch_idx]

        opt.zero_grad(set_to_none=True)
        logits = model(xb)
        loss = loss_fn(logits, yb)
        loss.backward()
        opt.step()

    model_path = out_dir / "policy_c_head.pt"
    torch.save(
        {
            "state_dict": model.state_dict(),
            "feature_dim": cfg.feature_dim,
            "seed": cfg.seed,
        },
        model_path,
    )

    weights_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
    manifest = {
        "schema_id": "kt.policy_c.head_train_manifest.v1",
        "dataset_path": str(ds_path),
        "dataset_hash": ds_hash,
        "seed": cfg.seed,
        "feature_dim": cfg.feature_dim,
        "steps": cfg.steps,
        "batch_size": bs,
        "lr": cfg.lr,
        "device": str(device),
        "artifact": {"path": str(model_path), "sha256": weights_hash},
    }
    (out_dir / "train_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print("TRAIN_OK")
    print("OUT_DIR", str(out_dir))
    print("DATASET_HASH", ds_hash)
    print("HEAD_SHA256", weights_hash)


if __name__ == "__main__":
    main()
