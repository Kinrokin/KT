"""
KT Phase 2 LoRA Training Harness (MRT-1: Multi-Round Training).

Orchestrates QLoRA (4-bit quantization + LoRA adapter) fine-tuning of base models
on policy_c datasets with fail-closed governance and auditable training logs.

NOTE: This implementation includes 4 critical compatibility patches for universal
compatibility across CPU/GPU environments and multiple dataset formats:
  1. Tokenizer use_fast=False (Mistral tokenizer.json compatibility with older tokenizers)
  2. Conditional model.to(device) when load_in_4bit (4-bit models cannot be moved after init)
  3. Variable scoping: load_in_4bit defined in main() before trainer_cfg
  4. Dataset fallback: JSON serialization for metadata-only records without inline text

Schema compatibility:
  - Input: kt.policy_c.dataset_record.v1 (JSONL with metadata refs, no inline text)
  - Output: LoRA adapter weights (safetensors) + training metadata

Environment flags:
  - DATASET_COERCE_TO_TEXT (default: 1): Convert structured records to JSON text when
    no inline text/prompt/input fields found. Set to 0 for fail-closed strict mode.
    Required for policy_c datasets which contain metadata refs, not plain text.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments
from peft import LoraConfig, get_peft_model
from bitsandbytes.sampler import RandomSampler


class Phase2TrainError(RuntimeError):
    """Phase 2 training harness exceptions (fail-closed)."""
    pass


@dataclass(frozen=True)
class TrainRequest:
    """Training configuration request."""
    base_model: str
    dataset_jsonl: Path
    output_dir: Path
    load_in_4bit: bool = True
    lora_rank: int = 8
    lora_alpha: int = 16
    lora_dropout: float = 0.05
    batch_size: int = 4
    learning_rate: float = 2e-4
    num_epochs: int = 1
    max_seq_len: int = 2048
    gradient_checkpointing: bool = True
    warmup_steps: int = 100


class PolicyCDataset(torch.utils.data.Dataset):
    """Policy_c JSONL dataset loader with text extraction."""
    
    def __init__(self, jsonl_path: Path, tokenizer, max_seq_len: int = 2048):
        self.tokenizer = tokenizer
        self.max_seq_len = max_seq_len
        self.samples: List[Dict[str, Any]] = []
        
        # Load and extract text samples
        for text in self._iter_text_samples(jsonl_path):
            self.samples.append({"text": text})
    
    def _iter_text_samples(self, dataset_jsonl: Path):
        """
        Extract text samples from policy_c dataset.
        
        PATCH #4: Fallback to JSON serialization for metadata-only records.
        Policy_c dataset records contain metadata refs (pressure_tensor, epoch_summary, etc.)
        but NOT inline text fields. This function tries common text fields first, then
        falls back to JSON serialization of the entire record for tokenization.
        
        Compatibility mode: Set DATASET_COERCE_TO_TEXT=1 to always serialize structured
        records as JSON when no inline text is found. This enables training on policy_c
        and other metadata-heavy datasets without modification.
        """
        coerce_to_text = os.environ.get("DATASET_COERCE_TO_TEXT", "1").lower() in ("true", "1", "yes")
        
        for line in dataset_jsonl.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            
            if not isinstance(obj, dict):
                continue
            
            # Try to extract inline text fields (text/prompt/input)
            for key in ["text", "prompt", "input"]:
                if key in obj and isinstance(obj[key], str) and obj[key].strip():
                    yield obj[key]
                    break
            else:
                # PATCH #4: Fallback for records without inline text fields
                # Serialize the dict to JSON for tokenization (stable, deterministic)
                # This is the canonical compatibility mode for structured datasets
                if coerce_to_text:
                    yield json.dumps(obj, sort_keys=True)
                else:
                    # Strict mode: raise when no text field found (fail-closed)
                    raise Phase2TrainError(
                        f"No text/prompt/input field in record and DATASET_COERCE_TO_TEXT=0 (fail-closed): {json.dumps(obj, sort_keys=True)[:200]}"
                    )
    
    def __len__(self) -> int:
        return len(self.samples)
    
    def __getitem__(self, idx: int) -> Dict[str, Any]:
        text = self.samples[idx]["text"]
        encoding = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_seq_len,
            padding="max_length",
            return_tensors="pt"
        )
        return {
            "input_ids": encoding["input_ids"].squeeze(),
            "attention_mask": encoding["attention_mask"].squeeze(),
            "labels": encoding["input_ids"].squeeze().clone(),
        }


def _run_lora_training(
    req: TrainRequest,
    run_dir_abs: Path,
    trainer_cfg: Dict[str, Any]
) -> None:
    """
    Execute LoRA fine-tuning pipeline with 4-bit quantization.
    
    Args:
        req: TrainRequest with model, dataset, and training hyperparameters
        run_dir_abs: Absolute path to training output directory
        trainer_cfg: Trainer configuration dict
    
    Raises:
        Phase2TrainError: On tokenizer load, model load, or training failure
    """
    
    device = "cuda" if torch.cuda.is_available() else "cpu"
    
    # Load tokenizer
    # PATCH #1: Use slow tokenizer for compatibility with Mistral tokenizer.json
    # Older tokenizers library versions cannot parse Mistral's tokenizer.json with use_fast=True
    try:
        tokenizer = AutoTokenizer.from_pretrained(
            req.base_model,
            use_fast=False,  # PATCH #1: Force slow tokenizer
            trust_remote_code=True
        )
    except Exception as exc:
        raise Phase2TrainError(f"Failed to load tokenizer: {exc}") from exc
    
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    
    # Load dataset
    try:
        dataset = PolicyCDataset(
            req.dataset_jsonl,
            tokenizer=tokenizer,
            max_seq_len=req.max_seq_len
        )
    except Exception as exc:
        raise Phase2TrainError(f"Failed to load dataset: {exc}") from exc
    
    if len(dataset) == 0:
        raise Phase2TrainError("No usable text samples in dataset")
    
    # Load base model with 4-bit quantization
    try:
        if req.load_in_4bit:
            from bitsandbytes.nn import Linear4bit
            from transformers import BitsAndBytesConfig
            
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_use_double_quant=True,
                bnb_4bit_compute_dtype=torch.float16,
            )
            model = AutoModelForCausalLM.from_pretrained(
                req.base_model,
                quantization_config=bnb_config,
                device_map="auto",
                torch_dtype=torch.float16,
                trust_remote_code=True,
            )
        else:
            model = AutoModelForCausalLM.from_pretrained(
                req.base_model,
                device_map="auto",
                torch_dtype=torch.float16,
                trust_remote_code=True,
            )
    except Exception as exc:
        raise Phase2TrainError(f"Failed to load base model: {exc}") from exc
    
    # PATCH #2: Conditional device movement for 4-bit models
    # 4-bit quantized models cannot call .to(device) after initialization.
    # The device_map="auto" already places them correctly.
    if not req.load_in_4bit:
        model = model.to(device)
    
    # Apply gradient checkpointing if enabled
    if req.gradient_checkpointing and hasattr(model, "gradient_checkpointing_enable"):
        model.gradient_checkpointing_enable()
    
    # Apply LoRA config
    lora_config = LoraConfig(
        r=req.lora_rank,
        lora_alpha=req.lora_alpha,
        target_modules=["q_proj", "v_proj"],
        lora_dropout=req.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
    )
    
    try:
        model = get_peft_model(model, lora_config)
    except Exception as exc:
        raise Phase2TrainError(f"Failed to apply LoRA config: {exc}") from exc
    
    # Create trainer
    try:
        trainer = Trainer(
            model=model,
            train_dataset=dataset,
            args=TrainingArguments(**trainer_cfg),
            data_collator=_collate_fn,
        )
    except Exception as exc:
        raise Phase2TrainError(f"Failed to create trainer: {exc}") from exc
    
    # Run training
    try:
        trainer.train()
    except Exception as exc:
        raise Phase2TrainError(f"Training failed: {exc}") from exc
    
    # Save adapter weights
    try:
        model.save_pretrained(run_dir_abs / "adapter_weights")
        with open(run_dir_abs / "training_config.json", "w") as f:
            json.dump(vars(req), f, indent=2, default=str)
    except Exception as exc:
        raise Phase2TrainError(f"Failed to save adapter weights: {exc}") from exc


def _collate_fn(batch: List[Dict[str, Any]]) -> Dict[str, torch.Tensor]:
    """Collate function for DataLoader."""
    return {
        "input_ids": torch.stack([b["input_ids"] for b in batch]),
        "attention_mask": torch.stack([b["attention_mask"] for b in batch]),
        "labels": torch.stack([b["labels"] for b in batch]),
    }


def _canonical_hash(obj: Any) -> str:
    """Compute SHA256 hash of canonical JSON representation."""
    import hashlib
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    p = argparse.ArgumentParser(
        description="KT Phase 2 LoRA Training Harness (MRT-1; fail-closed)"
    )
    p.add_argument(
        "--base-model",
        type=str,
        default="mistralai/Mistral-7B-Instruct-v0.2",
        help="HF model ID for base model"
    )
    p.add_argument(
        "--dataset",
        type=Path,
        required=True,
        help="Path to policy_c dataset JSONL"
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Output directory for adapter weights and metadata"
    )
    p.add_argument(
        "--load-in-4bit",
        type=lambda x: str(x).lower() in ("true", "1", "yes"),
        default=True,
        help="Enable 4-bit quantization (default: true)"
    )
    p.add_argument(
        "--lora-rank",
        type=int,
        default=8,
        help="LoRA rank (default: 8)"
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=4,
        help="Training batch size (default: 4)"
    )
    p.add_argument(
        "--learning-rate",
        type=float,
        default=2e-4,
        help="Learning rate (default: 2e-4)"
    )
    p.add_argument(
        "--num-epochs",
        type=int,
        default=1,
        help="Number of training epochs (default: 1)"
    )
    p.add_argument(
        "--max-seq-len",
        type=int,
        default=2048,
        help="Maximum sequence length (default: 2048)"
    )
    p.add_argument(
        "--gradient-checkpointing",
        type=lambda x: str(x).lower() in ("true", "1", "yes"),
        default=True,
        help="Enable gradient checkpointing (default: true)"
    )
    p.add_argument(
        "--warmup-steps",
        type=int,
        default=100,
        help="Warmup steps (default: 100)"
    )
    return p.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """
    Entry point for Phase 2 training harness.
    
    Args:
        argv: Command-line arguments (default: sys.argv[1:])
    
    Returns:
        0 on success, 1 on failure
    """
    args = _parse_args(argv)
    
    # Validate inputs
    if not args.dataset.exists():
        print(f"ERROR: Dataset not found: {args.dataset}", file=sys.stderr)
        return 1
    
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    # PATCH #3: Load_in_4bit variable scoping
    # The original code used args.load_in_4bit directly in trainer_cfg,
    # but it must be converted to bool and in scope for trainer_cfg construction.
    load_in_4bit = bool(args.load_in_4bit)
    
    # Build training request
    try:
        req = TrainRequest(
            base_model=args.base_model,
            dataset_jsonl=args.dataset.resolve(),
            output_dir=args.output_dir.resolve(),
            load_in_4bit=load_in_4bit,
            lora_rank=args.lora_rank,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
            num_epochs=args.num_epochs,
            max_seq_len=args.max_seq_len,
            gradient_checkpointing=args.gradient_checkpointing,
            warmup_steps=args.warmup_steps,
        )
    except Exception as exc:
        print(f"ERROR: Failed to build training request: {exc}", file=sys.stderr)
        return 1
    
    # Build trainer config
    trainer_cfg = {
        "output_dir": str(args.output_dir / "checkpoints"),
        "num_train_epochs": args.num_epochs,
        "per_device_train_batch_size": args.batch_size,
        "gradient_accumulation_steps": 1,
        "warmup_steps": args.warmup_steps,
        "learning_rate": args.learning_rate,
        "fp16": load_in_4bit,  # Use FP16 with 4-bit quantization
        "logging_steps": 10,
        "save_steps": 500,
        "save_total_limit": 2,
        "seed": 42,
    }
    
    # Run training
    try:
        _run_lora_training(req, args.output_dir, trainer_cfg)
    except Phase2TrainError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: Unexpected failure: {exc}", file=sys.stderr)
        return 1
    
    # Write completion report
    try:
        report = {
            "status": "PASS",
            "output_dir": args.output_dir.as_posix(),
            "content_hash": _canonical_hash({
                "base_model": req.base_model,
                "dataset": req.dataset_jsonl.as_posix(),
                "config": vars(req),
            }),
        }
        with open(args.output_dir / "training_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
    except Exception as exc:
        print(f"WARNING: Failed to write report: {exc}", file=sys.stderr)
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
