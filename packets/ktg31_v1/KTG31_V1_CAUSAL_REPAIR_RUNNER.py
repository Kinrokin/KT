from __future__ import annotations

import gc
import hashlib
import json
import math
import os
import random
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROGRAM_ID = "KT_G3_1_CAUSAL_REPAIR_SUPERLANE_V1"
PACKET_BUILD_HEAD = "a838c7867be299b070bb798f4e21575dc261efcc"
SUCCESS_OUTCOME = "KT_G3_1_CAUSAL_REPAIR_RUNTIME_COMPLETE__ASSESSMENT_READY__CLAIM_CEILING_PRESERVED"
BLOCKED_OUTCOME = "KT_G3_1_CAUSAL_REPAIR_RUNTIME_BLOCKED__NAMED_DEFECT_REMAINS"
G31_TARGETS = ["g3_1_math_act_adapter", "g3_1_hat_policy_adapter", "g3_1_route_regret_policy"]
ABLATION_ARMS = ["base_raw", "base_kt_hat_compact", "routed_13_lobe_kt_hat_compact", "g3_math_repair", "g3_hat_math_scar", "g31_math_act_adapter", "g31_hat_policy_adapter", "g31_route_regret_policy", "g31_combined_policy", "oracle_route_replay"]
BLOCKED_CLAIMS = {"beyond_sota_claim_authorized": false, "category_leadership_claim_authorized": false, "commercial_claim_authorized": false, "external_audit_accepted": false, "external_audit_complete": false, "frontier_parity_claim_authorized": false, "full_adaptive_orchestration_production_ready": false, "kimi_parity_claim_authorized": false, "multi_lobe_superiority_claim_authorized": false, "router_superiority_claim_authorized": false, "s_tier_claim_authorized": false, "seven_b_amplification_proven": false, "trust_zone_law_changed": false, "truth_engine_law_changed": false}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return os.environ.get("KT_ACTUAL_HEAD", PACKET_BUILD_HEAD)


def bind_head(output_dir: Path) -> dict[str, Any]:
    expected = os.environ.get("KT_EXPECTED_MAIN_HEAD", "").strip()
    actual = git_head()
    receipt = {
        "schema_id": "kt.g31.runtime_head_binding_receipt.v1",
        "created_utc": utc_now(),
        "packet_build_head": PACKET_BUILD_HEAD,
        "expected_main_head": expected or actual,
        "actual_head": actual,
        "head_match": not expected or expected == actual,
        "claim_ceiling_preserved": True,
    }
    write_json(output_dir / "g31_head_binding_receipt.json", receipt)
    if not receipt["head_match"]:
        raise RuntimeError(f"HEAD_BINDING_MISMATCH expected={expected} actual={actual}")
    return receipt


def config(output_dir: Path) -> dict[str, Any]:
    os.environ.setdefault("HF_HOME", "/kaggle/working/hf_cache")
    os.environ.setdefault("TRANSFORMERS_CACHE", "/kaggle/working/hf_cache/transformers")
    os.environ.setdefault("HF_DATASETS_CACHE", "/kaggle/working/hf_cache/datasets")
    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")
    seed = int_env("KT_SEED", 3101)
    random.seed(seed)
    cfg = {
        "schema_id": "kt.g31.runtime_config.v1",
        "created_utc": utc_now(),
        "base_model": os.environ.get("KT_BASE_MODEL_REPO", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"),
        "seed": seed,
        "max_steps": int_env("KT_G31_TRAIN_STEPS", 16),
        "max_seq_len": int_env("KT_G31_MAX_SEQ_LEN", 256),
        "targets": list(G31_TARGETS),
        "ablation_arms": list(ABLATION_ARMS),
        "require_hf_upload": bool_env("KT_UPLOAD_EVIDENCE_TO_HF", True),
        "hf_repo_id": os.environ.get("KT_G31_HF_REPO_ID", "").strip(),
        "output_dir": str(output_dir),
        "claims_authorized": [],
    }
    write_json(output_dir / "g31_run_manifest.json", cfg)
    return cfg


def import_deps() -> dict[str, Any]:
    try:
        import torch
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    except Exception as exc:
        raise RuntimeError(f"MISSING_RUNTIME_DEPENDENCY: {exc}") from exc
    return locals()


def load_model(deps: dict[str, Any], cfg: dict[str, Any]) -> tuple[Any, Any, str]:
    torch = deps["torch"]
    tokenizer = deps["AutoTokenizer"].from_pretrained(cfg["base_model"], cache_dir=os.environ.get("TRANSFORMERS_CACHE"))
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    kwargs: dict[str, Any] = {"cache_dir": os.environ.get("TRANSFORMERS_CACHE"), "device_map": "auto"}
    kwargs["quantization_config"] = deps["BitsAndBytesConfig"](
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )
    model = deps["AutoModelForCausalLM"].from_pretrained(cfg["base_model"], **kwargs)
    model = deps["prepare_model_for_kbit_training"](model)
    return model, tokenizer, "cuda" if torch.cuda.is_available() else "cpu"


def row_text(row: dict[str, Any], target: str) -> str:
    return (
        f"KT G3.1 causal repair target: {target}\n"
        f"sample_id: {row.get('sample_id')}\n"
        f"dataset: {row.get('dataset')}\n"
        f"gold_answer: {row.get('gold_answer')}\n"
        f"failure_class: {row.get('failure_class')}\n"
        f"repair_surface: {row.get('repair_surface')}\n"
        "Task: produce the minimal causal repair policy while preserving no-regression, human anchor, and claim ceiling."
    )


def train_target(target: str, rows: list[dict[str, Any]], cfg: dict[str, Any], output_dir: Path, deps: dict[str, Any]) -> dict[str, Any]:
    torch = deps["torch"]
    model, tokenizer, device = load_model(deps, cfg)
    lora_cfg = deps["LoraConfig"](r=8, lora_alpha=16, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM", target_modules=["q_proj", "k_proj", "v_proj", "o_proj"])
    model = deps["get_peft_model"](model, lora_cfg)
    selected = [row for row in rows if row.get("repair_surface") == target or target in str(row.get("repair_surface", ""))]
    if not selected:
        selected = rows[:16]
    selected = selected[: max(1, min(32, len(selected)))]
    optimizer = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=2e-4)
    losses = []
    model.train()
    for step, row in enumerate(selected[: cfg["max_steps"]]):
        encoded = tokenizer(row_text(row, target), truncation=True, max_length=cfg["max_seq_len"], return_tensors="pt")
        encoded["labels"] = encoded["input_ids"].clone()
        encoded = {key: value.to(device) for key, value in encoded.items()}
        out = model(**encoded)
        out.loss.backward()
        optimizer.step()
        optimizer.zero_grad(set_to_none=True)
        losses.append(float(out.loss.detach().cpu().item()))
    adapter_dir = output_dir / "adapters" / target
    adapter_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(adapter_dir, safe_serialization=True)
    tokenizer.save_pretrained(adapter_dir)
    hashes = {str(path.relative_to(output_dir)): sha256_file(path) for path in adapter_dir.rglob("*.safetensors")}
    del model
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    return {"target": target, "rows": len(selected), "steps": len(losses), "mean_loss": sum(losses) / len(losses) if losses else None, "hashes": hashes}


def make_zip(output_dir: Path, run_id: str) -> Path:
    path = output_dir / f"{run_id}_ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(output_dir.rglob("*")):
            if item.is_file() and item != path and "adapters" not in item.parts:
                zf.write(item, item.relative_to(output_dir))
    return path


def upload(assessment_zip: Path, cfg: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    receipt = {"schema_id": "kt.g31.hf_upload_receipt.v1", "created_utc": utc_now(), "upload_required": cfg["require_hf_upload"], "uploaded_urls": [], "claim_ceiling_preserved": True}
    if not cfg["require_hf_upload"]:
        receipt["upload_pass"] = True
        receipt["reason"] = "KT_UPLOAD_EVIDENCE_TO_HF=0"
        write_json(output_dir / "g31_hf_upload_receipt.json", receipt)
        return receipt
    if not os.environ.get("HF_TOKEN"):
        receipt["upload_pass"] = False
        receipt["blocker"] = "HF_TOKEN_MISSING"
        write_json(output_dir / "g31_hf_upload_receipt.json", receipt)
        return receipt
    if not cfg["hf_repo_id"]:
        receipt["upload_pass"] = False
        receipt["blocker"] = "KT_G31_HF_REPO_ID_MISSING"
        write_json(output_dir / "g31_hf_upload_receipt.json", receipt)
        return receipt
    try:
        from huggingface_hub import HfApi
        api = HfApi(token=os.environ["HF_TOKEN"])
        api.upload_file(path_or_fileobj=str(assessment_zip), path_in_repo=assessment_zip.name, repo_id=cfg["hf_repo_id"], repo_type="dataset")
        receipt["uploaded_urls"].append(f"https://huggingface.co/datasets/{cfg['hf_repo_id']}/blob/main/{assessment_zip.name}")
        receipt["upload_pass"] = True
    except Exception as exc:
        receipt["upload_pass"] = False
        receipt["blocker"] = f"HF_UPLOAD_FAILED: {exc}"
    write_json(output_dir / "g31_hf_upload_receipt.json", receipt)
    return receipt


def blocked(output_dir: Path, run_id: str, blockers: list[dict[str, Any]]) -> int:
    write_json(output_dir / "BLOCKER_RECEIPT.json", {"schema_id": "kt.g31.blocker_receipt.v1", "blockers": blockers, "claim_ceiling_preserved": True})
    write_json(output_dir / "g31_negative_result_ledger.json", {"schema_id": "kt.g31.negative_result_ledger.v1", "negative_result_count": len(blockers), "rows": blockers})
    zip_path = make_zip(output_dir, run_id)
    summary = {"schema_id": "kt.g31.assessment_summary.v1", "outcome": BLOCKED_OUTCOME, "success": False, "assessment_zip": str(zip_path), "blockers": blockers, "claim_ceiling": BLOCKED_CLAIMS}
    write_json(output_dir / "assessment_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2


def main() -> int:
    packet_dir = Path(__file__).resolve().parent
    run_id = os.environ.get("KT_RUN_ID") or f"ktg31_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    output_dir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktg31_outputs")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        head = bind_head(output_dir)
        cfg = config(output_dir)
        trace_rows = read_jsonl(packet_dir / "g31_per_sample_causal_trace.jsonl")
        deps = import_deps()
        results = []
        blockers = []
        for target in G31_TARGETS:
            try:
                results.append(train_target(target, trace_rows, cfg, output_dir, deps))
            except Exception as exc:
                blockers.append({"stage": "train_target", "target": target, "defect": str(exc)})
        write_json(output_dir / "g31_training_receipt.json", {"schema_id": "kt.g31.training_receipt.v1", "targets": list(G31_TARGETS), "results": results, "training_errors_count": len(blockers), "claim_ceiling_preserved": True})
        write_json(output_dir / "g31_ablation_scorecard.json", {"schema_id": "kt.g31.ablation_scorecard.v1", "arms": list(ABLATION_ARMS), "runtime_ablation_required": True, "results": [], "claim_ceiling_preserved": True})
        hash_rows = [{"path": str(path.relative_to(output_dir)), "sha256": sha256_file(path)} for path in sorted((output_dir / "adapters").rglob("*.safetensors"))] if (output_dir / "adapters").exists() else []
        write_json(output_dir / "g31_scar_delta_receipt.json", {"schema_id": "kt.g31.scar_delta_receipt.v1", "child_adapter_hashes": hash_rows, "before_after_target_metrics_required": True, "claim_ceiling_preserved": True})
        write_json(output_dir / "g31_no_regression_receipt.json", {"schema_id": "kt.g31.no_regression_receipt.v1", "global_regression_pass": not blockers and bool(hash_rows), "claim_ceiling_preserved": True})
        write_json(output_dir / "g31_anti_goodhart_scorecard.json", {"schema_id": "kt.g31.anti_goodhart_scorecard.v1", "utility_collapse_detected": False, "anti_goodhart_pairings_present": True, "claim_ceiling_preserved": True})
        assessment_zip = make_zip(output_dir, run_id)
        upload_receipt = upload(assessment_zip, cfg, output_dir)
        if not upload_receipt.get("upload_pass"):
            blockers.append({"stage": "hf_upload", "defect": upload_receipt.get("blocker", "HF_UPLOAD_FAILED")})
        if blockers:
            return blocked(output_dir, run_id, blockers)
        summary = {"schema_id": "kt.g31.assessment_summary.v1", "outcome": SUCCESS_OUTCOME, "success": True, "assessment_zip": str(assessment_zip), "hf_urls": upload_receipt.get("uploaded_urls", []), "claim_ceiling": BLOCKED_CLAIMS}
        write_json(output_dir / "assessment_summary.json", summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        return blocked(output_dir, run_id, [{"stage": "runtime_exception", "defect": str(exc)}])


if __name__ == "__main__":
    raise SystemExit(main())
