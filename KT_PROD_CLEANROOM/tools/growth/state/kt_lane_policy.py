from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional

import torch
from peft import PeftModel
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_NAME = "mistralai/Mistral-7B-v0.1"
LORA_PATH = "KT_LANE_LORA_PHASE_A/kt_lane_lora/kt_lane_lora_adapter"


class KTLanePolicy:
    def __init__(self, model, tokenizer, threshold: float = 0.6):
        self.model = model
        self.tokenizer = tokenizer
        self.threshold = threshold
        self.model.eval()

    def predict(self, state_text: str):
        inputs = self.tokenizer(
            state_text,
            return_tensors="pt",
            truncation=True,
            padding=True,
        ).to(self.model.device)

        with torch.no_grad():
            logits = self.model(**inputs).logits

        probs = logits.softmax(dim=-1)[0]
        best_id = int(probs.argmax())
        confidence = float(probs[best_id])
        label = (
            self.model.config.id2label.get(str(best_id))
            or self.model.config.id2label.get(best_id)
            or str(best_id)
        )

        result = {
            "recommendation": "none" if confidence < self.threshold else label,
            "confidence": confidence,
            "policy_used": confidence >= self.threshold,
            "probs": probs.tolist(),
        }
        if confidence < self.threshold:
            result["fallback_label"] = label

        return result


def build_default_policy(
    model_name: str = MODEL_NAME,
    lora_path: str = LORA_PATH,
    device_map: str | Dict[str, str] = "auto",
    dtype: Optional[torch.dtype] = torch.float16,
    num_labels: int = 2,
) -> KTLanePolicy:
    model_name = os.environ.get("KT_LANE_BASE_MODEL", model_name)
    lora_path = os.environ.get("KT_LANE_LORA_PATH", lora_path)

    lora_dir = Path(lora_path)
    if not lora_dir.exists():
        raise FileNotFoundError(f"LoRA adapter not found at {lora_dir}")

    label_map_path = lora_dir / "label_map.json"
    if label_map_path.exists():
        try:
            label_map = json.loads(label_map_path.read_text(encoding="utf-8"))
            label_list = label_map.get("label_list") if isinstance(label_map, dict) else None
            if isinstance(label_list, list) and label_list:
                num_labels = len(label_list)
        except Exception:
            pass

    tokenizer = None
    try:
        tokenizer = AutoTokenizer.from_pretrained(str(lora_dir), use_fast=True, local_files_only=True)
    except Exception:
        tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True)
    tokenizer.pad_token = tokenizer.eos_token

    quantization_config = None
    if torch.cuda.is_available():
        try:
            from transformers import BitsAndBytesConfig

            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_use_double_quant=True,
                bnb_4bit_compute_dtype=torch.float16,
            )
        except Exception:
            quantization_config = None

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required to load the lane policy (shadow mode).")

    model = AutoModelForSequenceClassification.from_pretrained(
        model_name,
        num_labels=num_labels,
        dtype=dtype,
        device_map=device_map,
        low_cpu_mem_usage=True,
        quantization_config=quantization_config,
    )

    model = PeftModel.from_pretrained(model, str(lora_dir), local_files_only=True)
    if label_map_path.exists():
        try:
            label_map = json.loads(label_map_path.read_text(encoding="utf-8"))
            id2label = label_map.get("id2label") if isinstance(label_map, dict) else None
            label2id = label_map.get("label2id") if isinstance(label_map, dict) else None
            if isinstance(id2label, dict):
                model.config.id2label = {int(k): v for k, v in id2label.items()}
            if isinstance(label2id, dict):
                model.config.label2id = dict(label2id)
        except Exception:
            pass
    return KTLanePolicy(model, tokenizer)
