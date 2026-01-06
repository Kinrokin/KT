import argparse
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset, random_split
from transformers import AutoModel, AutoTokenizer, BitsAndBytesConfig


class PhaseA2TrainError(RuntimeError):
    pass


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PhaseA2TrainError(f"Failed to read JSON: {path.as_posix()}") from exc


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    if not rows:
        raise PhaseA2TrainError(f"No readable rows in dataset: {path.as_posix()}")
    return rows


@dataclass(frozen=True)
class Sample:
    text: str
    label_id: int


class TextDataset(Dataset):
    def __init__(self, samples: List[Sample]):
        self.samples = samples

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Sample:
        return self.samples[idx]


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Phase A.2: train a policy head only (freeze base model; no LoRA).")
    p.add_argument(
        "--dataset",
        type=Path,
        default=Path("KT_PROD_CLEANROOM/tools/growth/bench/kt_phaseA2_dataset.jsonl"),
        help="Phase A.2 dataset JSONL (from build_phaseA2_dataset.py).",
    )
    p.add_argument(
        "--label-map",
        type=Path,
        default=Path("KT_PROD_CLEANROOM/tools/growth/state/kt_phaseA2_label_map.json"),
        help="Label map JSON (from build_phaseA2_dataset.py).",
    )
    p.add_argument(
        "--base-model",
        type=str,
        default=os.environ.get("KT_LANE_BASE_MODEL", "mistralai/Mistral-7B-v0.1"),
        help="HF base model id (must be accessible on the GPU host).",
    )
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch-size", type=int, default=8)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--seed", type=int, default=123)
    p.add_argument(
        "--out-dir",
        type=Path,
        default=Path("KT_TRAINING_OUT/phaseA2_head_only"),
        help="Output directory (head weights + report).",
    )
    return p.parse_args()


def _set_seed(seed: int) -> None:
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def _pool_last_token(hidden: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
    # hidden: [B, T, H], attention_mask: [B, T]
    idx = attention_mask.long().sum(dim=1) - 1
    idx = idx.clamp(min=0)
    batch = torch.arange(hidden.size(0), device=hidden.device)
    return hidden[batch, idx, :]


def main() -> int:
    args = _parse_args()
    if not torch.cuda.is_available():
        raise PhaseA2TrainError("CUDA is required for Phase A.2 head-only training.")

    _set_seed(int(args.seed))

    dataset_path = args.dataset.resolve()
    label_map_path = args.label_map.resolve()
    rows = _read_jsonl(dataset_path)
    label_map = _load_json(label_map_path)

    label2id = label_map.get("label2id") or {}
    if not isinstance(label2id, dict) or not label2id:
        raise PhaseA2TrainError("Invalid label_map: missing label2id")

    samples: List[Sample] = []
    for r in rows:
        text = r.get("state_text")
        lab = r.get("phaseA2_label")
        if not isinstance(text, str) or not isinstance(lab, str):
            continue
        if lab not in label2id:
            continue
        samples.append(Sample(text=text, label_id=int(label2id[lab])))

    if len(samples) < 50:
        raise PhaseA2TrainError("Too few samples after filtering (fail-closed).")

    tokenizer = AutoTokenizer.from_pretrained(args.base_model, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16,
    )

    base = AutoModel.from_pretrained(
        args.base_model,
        device_map="auto",
        quantization_config=bnb,
        torch_dtype=torch.float16,
    )
    base.eval()
    for p in base.parameters():
        p.requires_grad_(False)

    hidden_size = int(getattr(base.config, "hidden_size", 4096))
    num_labels = len(label2id)
    head = nn.Linear(hidden_size, num_labels, bias=False).to(base.device)

    full = TextDataset(samples)
    n_val = max(1, int(0.1 * len(full)))
    n_train = len(full) - n_val
    train_set, val_set = random_split(full, [n_train, n_val])

    def collate(batch: List[Sample]) -> Dict[str, torch.Tensor]:
        texts = [b.text for b in batch]
        labels = torch.tensor([b.label_id for b in batch], dtype=torch.long)
        enc = tokenizer(
            texts,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=256,
        )
        enc["labels"] = labels
        return enc

    train_loader = DataLoader(train_set, batch_size=int(args.batch_size), shuffle=True, collate_fn=collate)
    val_loader = DataLoader(val_set, batch_size=int(args.batch_size), shuffle=False, collate_fn=collate)

    optim = torch.optim.AdamW(head.parameters(), lr=float(args.lr))
    loss_fn = nn.CrossEntropyLoss()

    def run_eval() -> Tuple[float, float]:
        head.eval()
        total = 0
        correct = 0
        loss_sum = 0.0
        with torch.no_grad():
            for batch in val_loader:
                labels = batch.pop("labels").to(base.device)
                batch = {k: v.to(base.device) for k, v in batch.items()}
                out = base(**batch)
                pooled = _pool_last_token(out.last_hidden_state, batch["attention_mask"])
                logits = head(pooled)
                loss = loss_fn(logits, labels)
                loss_sum += float(loss.item()) * labels.size(0)
                pred = logits.argmax(dim=-1)
                correct += int((pred == labels).sum().item())
                total += int(labels.size(0))
        return (loss_sum / max(1, total), correct / max(1, total))

    history: List[Dict[str, Any]] = []
    for epoch in range(1, int(args.epochs) + 1):
        head.train()
        total = 0
        loss_sum = 0.0
        for batch in train_loader:
            labels = batch.pop("labels").to(base.device)
            batch = {k: v.to(base.device) for k, v in batch.items()}
            with torch.no_grad():
                out = base(**batch)
                pooled = _pool_last_token(out.last_hidden_state, batch["attention_mask"]).detach()
            logits = head(pooled)
            loss = loss_fn(logits, labels)
            optim.zero_grad(set_to_none=True)
            loss.backward()
            optim.step()
            loss_sum += float(loss.item()) * labels.size(0)
            total += int(labels.size(0))

        val_loss, val_acc = run_eval()
        rec = {
            "epoch": epoch,
            "train_loss": loss_sum / max(1, total),
            "val_loss": val_loss,
            "val_acc": val_acc,
        }
        history.append(rec)
        print(json.dumps(rec))

    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    torch.save({"head_state_dict": head.state_dict(), "label2id": label2id}, out_dir / "head.pt")
    (out_dir / "label_map.json").write_text(json.dumps(label_map, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "train_report.json").write_text(
        json.dumps(
            {
                "schema": "KT_PHASE_A2_HEAD_TRAIN_REPORT_V1",
                "base_model": args.base_model,
                "dataset": dataset_path.as_posix(),
                "label_map": label_map_path.as_posix(),
                "num_train": n_train,
                "num_val": n_val,
                "epochs": int(args.epochs),
                "batch_size": int(args.batch_size),
                "lr": float(args.lr),
                "history": history,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print(f"wrote: {(out_dir / 'head.pt').as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

