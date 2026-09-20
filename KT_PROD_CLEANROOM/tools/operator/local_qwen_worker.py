"""Pinned, offline NF4 inference worker; only the operator provider starts this file.

Model loading and activation checks are derived from the qualified atlas_worker
implementation. This separate process never executes effects or grants authority.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import random
import sys
import time


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def emit(value):
    print(json.dumps(value, sort_keys=True, allow_nan=False), flush=True)


def main():
    started = time.perf_counter()
    path = Path(sys.argv[1])
    contract_sha = sys.argv[2]
    if digest(path) != contract_sha:
        raise RuntimeError("WORKER_CONTRACT_PIN")
    contract = json.loads(path.read_bytes())
    backend = contract["backend"]
    versions = {name: importlib.metadata.version(name) for name in backend["required_versions"]}
    if versions != backend["required_versions"]:
        raise RuntimeError("WORKER_ENVIRONMENT_PIN")
    for label in ("base", "adapter"):
        root = backend[label + "_root"]
        if root is None:
            continue
        root = Path(root)
        actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
        # README/license metadata can exist but every runtime-readable model asset is pinned.
        runtime = {p for p in actual if p.endswith((".json", ".safetensors", ".model", ".txt", ".bin", ".py"))}
        if runtime - {"README.txt", "LICENSE.txt"} != set(backend[label + "_files"]):
            raise RuntimeError("WORKER_ASSET_COVERAGE")
        for rel, sha in backend[label + "_files"].items():
            candidate = root / rel
            if candidate.resolve(strict=True) != candidate or digest(candidate) != sha:
                raise RuntimeError("WORKER_ASSET_PIN")
    base = Path(backend["base_root"])
    index = json.loads((base / "model.safetensors.index.json").read_bytes())
    if not set(index["weight_map"].values()) <= set(backend["base_files"]):
        raise RuntimeError("WORKER_WEIGHT_SHARDS_UNPINNED")
    import torch
    import bitsandbytes
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, GenerationConfig
    from peft import PeftModel

    if not 0 < torch.cuda.device_count() <= 2:
        raise RuntimeError("WORKER_GPU_COUNT")
    if any(torch.cuda.get_device_name(i) != "Tesla T4" for i in range(torch.cuda.device_count())):
        raise RuntimeError("WORKER_UNQUALIFIED_GPU")
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.backends.cudnn.benchmark = False
    tokenizer = AutoTokenizer.from_pretrained(str(base), local_files_only=True, trust_remote_code=False)
    if hashlib.sha256(tokenizer.chat_template.encode()).hexdigest() != backend["chat_template_sha256"]:
        raise RuntimeError("WORKER_TEMPLATE_PIN")
    quantization = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                    bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.float16)
    model = AutoModelForCausalLM.from_pretrained(str(base), quantization_config=quantization,
              device_map={"": 0}, torch_dtype=torch.float16, local_files_only=True, trust_remote_code=False)
    if not model.is_loaded_in_4bit or not any(isinstance(module, bitsandbytes.nn.Linear4bit) for module in model.modules()):
        raise RuntimeError("WORKER_NOT_REAL_4BIT")
    branch = {"calls": 0, "abs_max": None, "scaling": None}
    if backend["adapter_root"] is not None:
        adapter = Path(backend["adapter_root"])
        cfg = json.loads((adapter / "adapter_config.json").read_bytes())
        if cfg.get("base_model_name_or_path") != backend["base_repo"] or cfg.get("peft_type") != "LORA" or cfg.get("task_type") != "CAUSAL_LM":
            raise RuntimeError("WORKER_ADAPTER_COMPATIBILITY")
        model = PeftModel.from_pretrained(model, str(adapter), is_trainable=False, local_files_only=True)
        status = model.get_model_status()
        layers = model.get_layer_status()
        if (status.enabled is not True or status.active_adapters != ["default"] or status.merged_adapters != []
                or not layers or any(x.enabled is not True or x.active_adapters != ["default"] or x.merged_adapters != [] for x in layers)):
            raise RuntimeError("WORKER_ADAPTER_ACTIVATION")
        branches = [module for name, module in model.named_modules() if name.endswith(".lora_B.default")]
        if not branches or not any(torch.count_nonzero(module.weight).item() > 0 for module in branches):
            raise RuntimeError("WORKER_ZERO_ADAPTER")
        parents = [module for module in model.modules() if hasattr(module, "lora_B") and "default" in module.lora_B]
        branch["scaling"] = float(parents[0].scaling["default"])
        if not math.isfinite(branch["scaling"]) or branch["scaling"] == 0:
            raise RuntimeError("WORKER_ZERO_ADAPTER_SCALING")

        def observe(module, args, result):
            branch["calls"] += 1
            if branch["abs_max"] is None:
                branch["abs_max"] = float(result.detach().abs().max().item())

        branches[0].register_forward_hook(observe)
    elif hasattr(model, "peft_config") or any("lora_" in name for name, _ in model.named_modules()):
        raise RuntimeError("WORKER_BASE_ADAPTER_PRESENT")
    model.eval()
    if any(parameter.requires_grad for name, parameter in model.named_parameters() if "lora_" in name):
        raise RuntimeError("WORKER_TRAINABLE_ADAPTER")
    if any(parameter.device.type != "cuda" for parameter in model.parameters()):
        raise RuntimeError("WORKER_CPU_OR_META_FALLBACK")
    config = GenerationConfig.from_pretrained(str(base), local_files_only=True)
    config.do_sample, config.num_beams, config.use_cache = False, 1, True
    if config.pad_token_id is None:
        config.pad_token_id = tokenizer.pad_token_id or tokenizer.eos_token_id
    eos = config.eos_token_id
    eos = [eos] if isinstance(eos, int) else list(eos or [])
    if not eos:
        raise RuntimeError("WORKER_EOS_MISSING")
    emit({"kind": "READY", "contract_sha256": contract_sha, "versions": versions,
          "load_seconds": time.perf_counter() - started, "base_adapter_absence_asserted": backend["adapter_root"] is None,
          "actual_device": 0, "allocated_device_count": torch.cuda.device_count(), "real_nf4": True,
          "model_identity": backend, "fresh_generation": False})
    calls = 0
    reserved_tokens = 0
    for line in sys.stdin:
        request = json.loads(line)
        cap = request["max_new_tokens"]
        if type(cap) is not int or not 0 < cap <= contract["limits"]["max_new_tokens"]:
            raise RuntimeError("WORKER_GENERATION_CAP")
        calls += 1
        reserved_tokens += cap
        if calls > contract["limits"]["calls"] or reserved_tokens > contract["limits"]["generated_tokens"]:
            raise RuntimeError("WORKER_CAMPAIGN_CAP")
        if time.time() >= contract["expires_at"] or time.perf_counter() - started >= contract["limits"]["wall_seconds"]:
            raise RuntimeError("WORKER_EXPIRED")
        random.seed(backend["seed"])
        torch.manual_seed(backend["seed"])
        torch.cuda.manual_seed_all(backend["seed"])
        config.max_new_tokens = cap
        rendered = tokenizer.apply_chat_template([{"role": "user", "content": request["prompt"]}], tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(rendered, return_tensors="pt", add_special_tokens=False)
        in_ids = inputs["input_ids"][0].tolist()
        if len(in_ids) > 8192:
            raise RuntimeError("WORKER_INPUT_CAP")
        inputs = {key: value.to("cuda:0") for key, value in inputs.items()}
        branch.update(calls=0, abs_max=None)
        torch.cuda.synchronize(0)
        torch.cuda.reset_peak_memory_stats(0)
        before = time.perf_counter()
        with torch.inference_mode():
            output = model.generate(**inputs, generation_config=config)
        torch.cuda.synchronize(0)
        elapsed = time.perf_counter() - before
        ids = output[0][len(in_ids):].tolist()
        result = {"kind": "GENERATED", "nonce": request["nonce"], "contract_sha256": contract_sha,
                  "prompt_sha256": hashlib.sha256(request["prompt"].encode()).hexdigest(),
                  "rendered_prompt": rendered, "input_token_ids": in_ids, "generated_token_ids": ids,
                  "input_tokens": len(in_ids), "output_tokens": len(ids), "output_text": tokenizer.decode(ids, skip_special_tokens=True),
                  "max_new_tokens": cap, "finish_reason": "EOS" if ids and ids[-1] in eos else "MAX_NEW_TOKENS",
                  "eos_token_ids": eos, "generation_seconds": elapsed, "peak_allocated_bytes": torch.cuda.max_memory_allocated(0),
                  "generation_config": config.to_dict(), "adapter_observation": dict(branch),
                  "fresh_generation": True}
        emit(result)
        if backend["adapter_root"] is not None and (branch["calls"] <= 0 or branch["abs_max"] is None or not math.isfinite(branch["abs_max"]) or branch["abs_max"] <= 0):
            raise RuntimeError("WORKER_NONZERO_ADAPTER_NOT_OBSERVED")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        emit({"kind": "ERROR", "error_type": type(exc).__name__})
        raise
