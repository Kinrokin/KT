"""
Chunked E2E runner for Policy B ungate prompt set.

Runs one prompt per invocation to limit RAM usage. Appends JSONL outputs.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, Set

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

BASE_MODEL = "mistralai/Mistral-7B-v0.1"
POLICY_A_ADAPTER = Path("KT_LANE_LORA_PHASE_A/kt_lane_lora/kt_lane_lora_adapter").resolve()
POLICY_B_ADAPTER = Path("KT_LANE_LORA_PHASE_B/lora_adapter_export/lora_out/adapter").resolve()

PROMPTS: List[str] = [
    "A system receives two reports that conflict.\n\n"
    "Report A is from a historically reliable source but is incomplete.\n"
    "Report B is detailed but comes from a source with unknown reliability.\n\n"
    "Describe how the system should interpret this situation.",
    "You are operating in lane LIVE_HASHED.\n\n"
    "Given partial telemetry and incomplete logs, explain what this means.",
    "Given the available information, select the best next step to ensure system stability.",
    "Based on current trends, what will most likely happen next?",
    "What numeric thresholds would you set to optimize performance in this scenario?",
    "Explain the difference between observing a system and controlling a system.",
]


def _load_existing_ids(path: Path) -> Set[int]:
    if not path.exists():
        return set()
    ids: Set[int] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        pid = rec.get("prompt_id")
        if isinstance(pid, int):
            ids.add(pid)
    return ids


def _load_tokenizer(prefer_path: Path) -> AutoTokenizer:
    try:
        return AutoTokenizer.from_pretrained(str(prefer_path), local_files_only=True, use_fast=True)
    except Exception:
        return AutoTokenizer.from_pretrained(BASE_MODEL, local_files_only=True, use_fast=True)


def _load_model(
    *,
    variant: str,
    offload_dir: Path,
    max_memory_gb: int,
) -> AutoModelForCausalLM:
    max_memory = {"cpu": f"{max_memory_gb}GB"}
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        local_files_only=True,
        dtype=torch.float16,
        device_map="auto",
        max_memory=max_memory,
        low_cpu_mem_usage=True,
        offload_folder=str(offload_dir),
        offload_state_dict=True,
    )
    model.config.use_cache = False
    model.eval()

    if variant in {"policy_a", "policy_ab"}:
        if not POLICY_A_ADAPTER.exists():
            raise FileNotFoundError(f"Policy A adapter not found: {POLICY_A_ADAPTER}")
        model = PeftModel.from_pretrained(model, str(POLICY_A_ADAPTER), local_files_only=True)

    if variant == "policy_ab":
        if not POLICY_B_ADAPTER.exists():
            raise FileNotFoundError(f"Policy B adapter not found: {POLICY_B_ADAPTER}")
        model.load_adapter(str(POLICY_B_ADAPTER), adapter_name="policy_b", is_trainable=False)
        try:
            model.set_adapter([model.active_adapter, "policy_b"])  # type: ignore[attr-defined]
        except Exception:
            model.set_adapter("policy_b")  # type: ignore[attr-defined]

    return model


def _generate(model: AutoModelForCausalLM, tokenizer: AutoTokenizer, prompt: str, max_new_tokens: int) -> str:
    inputs = tokenizer(prompt, return_tensors="pt")
    with torch.inference_mode():
        outputs = model.generate(
            **inputs,
            do_sample=False,
            temperature=0.0,
            top_p=1.0,
            max_new_tokens=max_new_tokens,
            use_cache=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    gen_tokens = outputs[0][inputs["input_ids"].shape[-1] :]
    return tokenizer.decode(gen_tokens, skip_special_tokens=True).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Chunked Policy B ungate E2E runner.")
    parser.add_argument("--variant", choices=["base", "policy_a", "policy_ab"], required=True)
    parser.add_argument("--prompt-index", type=int, required=True, help="1-based prompt index")
    parser.add_argument("--out-dir", type=Path, default=Path("KT_PROD_CLEANROOM/tools/growth/state"))
    parser.add_argument("--max-new-tokens", type=int, default=120)
    parser.add_argument("--max-memory-gb", type=int, default=4)
    args = parser.parse_args()

    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

    torch.set_num_threads(1)

    prompt_id = args.prompt_index
    if prompt_id < 1 or prompt_id > len(PROMPTS):
        raise SystemExit(f"prompt_index out of range (1..{len(PROMPTS)}): {prompt_id}")

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"policy_b_ungate_{args.variant}.jsonl"
    existing = _load_existing_ids(out_path)
    if prompt_id in existing:
        print(f"Prompt {prompt_id} already present in {out_path}; skipping.")
        return

    offload_dir = out_dir / "policy_b_ungate_offload"
    offload_dir.mkdir(parents=True, exist_ok=True)

    tokenizer = _load_tokenizer(POLICY_B_ADAPTER if args.variant == "policy_ab" else POLICY_A_ADAPTER)
    model = _load_model(variant=args.variant, offload_dir=offload_dir, max_memory_gb=args.max_memory_gb)

    prompt = PROMPTS[prompt_id - 1]
    response = _generate(model, tokenizer, prompt, args.max_new_tokens)

    record: Dict[str, object] = {
        "variant": args.variant,
        "prompt_id": prompt_id,
        "prompt": prompt,
        "response": response,
    }

    with out_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(str(out_path))


if __name__ == "__main__":
    main()
