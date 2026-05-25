from __future__ import annotations

import csv
import gc
import hashlib
import json
import math
import os
import random
import shutil
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROGRAM_ID = "KT_G3_TARGETED_RUNTIME_PACKET_V2"
PACKET_BUILD_HEAD = "a838c7867be299b070bb798f4e21575dc261efcc"
SUCCESS_OUTCOME = "KT_G3_TARGETED_REPAIR_RUNTIME_EXECUTED__ASSESSMENT_READY__CLAIM_CEILING_PRESERVED"
BLOCKED_OUTCOME = "KT_G3_TARGETED_REPAIR_RUNTIME_BLOCKED__NAMED_DEFECT_REMAINS"

CANONICAL_LOBES = ["strategic_synthesis_lobe", "audit_reasoning_lobe", "formal_proof_reasoning_lobe", "contradiction_paradox_lobe", "temporal_chronology_lobe", "cross_domain_patterncraft_lobe", "grounded_evidence_lobe", "regulated_domain_lobe", "commercial_operator_lobe", "execution_tool_lobe", "context_memory_compression_lobe", "learning_delta_lobe", "adversarial_red_assault_lobe"]
BLOCKED_CLAIMS = {"beyond_sota_claim_authorized": false, "category_leadership_claim_authorized": false, "commercial_claim_authorized": false, "external_audit_accepted": false, "external_audit_complete": false, "frontier_parity_claim_authorized": false, "full_adaptive_orchestration_production_ready": false, "kimi_parity_claim_authorized": false, "multi_lobe_superiority_claim_authorized": false, "router_superiority_claim_authorized": false, "s_tier_claim_authorized": false, "seven_b_amplification_proven": false, "trust_zone_law_changed": false, "truth_engine_law_changed": false}
REQUIRED_OUTPUTS = ["g3_training_receipt.json", "g3_eval_receipt.json", "g3_no_regression_receipt.json", "g3_scar_delta_distinctness_receipt.json", "g3_negative_result_ledger.json", "route_regret_closure_scorecard.json", "verified_repair_velocity_scorecard.json", "anti_goodhart_scorecard.json", "human_anchor_anti_collapse_receipt.json", "lobe_specialization_scorecard.json", "assurance_case_claim_compiler_receipt.json", "hf_upload_receipt.json", "safetensors_hash_manifest.json"]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        if raw.strip():
            rows.append(json.loads(raw))
    return rows


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return int(raw)


def float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return float(raw)


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)[:96]


def git_head() -> str:
    try:
        import subprocess

        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return os.environ.get("KT_ACTUAL_HEAD", PACKET_BUILD_HEAD)


def bind_head(output_dir: Path) -> dict[str, Any]:
    requested = os.environ.get("KT_REQUESTED_HEAD", "").strip()
    actual = git_head()
    binding = {
        "schema_id": "kt.g3.runtime_head_binding_receipt.v2",
        "created_utc": utc_now(),
        "packet_build_head": PACKET_BUILD_HEAD,
        "requested_head": requested or actual,
        "actual_head": actual,
        "head_match": (requested == "" or requested == actual),
        "claim_ceiling_preserved": True,
    }
    write_json(output_dir / "head_binding_receipt.json", binding)
    if not binding["head_match"]:
        raise RuntimeError(f"Head binding mismatch: requested {requested}, actual {actual}")
    return binding


def runtime_config(output_dir: Path) -> dict[str, Any]:
    cache_root = Path(os.environ.get("HF_HOME", "/kaggle/working/hf_cache")).resolve()
    os.environ.setdefault("HF_HOME", str(cache_root))
    os.environ.setdefault("TRANSFORMERS_CACHE", str(cache_root / "transformers"))
    os.environ.setdefault("HF_DATASETS_CACHE", str(cache_root / "datasets"))
    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")
    seed = int_env("KT_SEED", 1701)
    random.seed(seed)
    cfg = {
        "schema_id": "kt.g3.runtime_config.v2",
        "created_utc": utc_now(),
        "base_model": os.environ.get("KT_BASE_MODEL", "Qwen/Qwen2.5-0.5B-Instruct"),
        "seed": seed,
        "max_lobes": int_env("KT_MAX_LOBES", 3),
        "max_steps_per_lobe": int_env("KT_MAX_STEPS_PER_LOBE", 4),
        "max_rows_per_lobe": int_env("KT_MAX_ROWS_PER_LOBE", 32),
        "eval_rows_per_lobe": int_env("KT_EVAL_ROWS_PER_LOBE", 8),
        "max_seq_len": int_env("KT_MAX_SEQ_LEN", 256),
        "learning_rate": float_env("KT_LR", 2e-4),
        "batch_size": int_env("KT_BATCH_SIZE", 1),
        "grad_accum": int_env("KT_GRAD_ACCUM", 8),
        "load_in_4bit": bool_env("KT_LOAD_IN_4BIT", True),
        "require_qlora": bool_env("KT_REQUIRE_QLORA", True),
        "require_hf_upload": bool_env("KT_REQUIRE_HF_UPLOAD", True),
        "hf_repo_id": os.environ.get("KT_HF_REPO_ID", "").strip(),
        "hf_cache": str(cache_root),
        "output_dir": str(output_dir),
        "claims_authorized": [],
    }
    write_json(output_dir / "run_manifest.json", cfg)
    return cfg


def load_packet_inputs(packet_dir: Path) -> dict[str, Any]:
    required = [
        "G2_FAILURE_MAP.json",
        "G2_ROUTE_REGRET_TARGETS.json",
        "HUMAN_ANCHOR_MANIFEST.json",
        "G3_METRIC_CONSTITUTION.json",
        "G3_FORMAL_MATH_REPAIR_PLAN.json",
        "G3_MATH_REPAIR_CORPUS.jsonl",
        "G3_KT_HAT_CALIBRATION_CORPUS.jsonl",
    ]
    missing = [name for name in required if not (packet_dir / name).exists()]
    if missing:
        raise RuntimeError(f"Runtime packet missing required repair fuel: {missing}")
    math_rows = read_jsonl(packet_dir / "G3_MATH_REPAIR_CORPUS.jsonl")
    calibration_rows = read_jsonl(packet_dir / "G3_KT_HAT_CALIBRATION_CORPUS.jsonl")
    return {
        "failure_map": read_json(packet_dir / "G2_FAILURE_MAP.json"),
        "route_targets": read_json(packet_dir / "G2_ROUTE_REGRET_TARGETS.json"),
        "human_anchor": read_json(packet_dir / "HUMAN_ANCHOR_MANIFEST.json"),
        "metric_constitution": read_json(packet_dir / "G3_METRIC_CONSTITUTION.json"),
        "math_plan": read_json(packet_dir / "G3_FORMAL_MATH_REPAIR_PLAN.json"),
        "math_rows": math_rows,
        "calibration_rows": calibration_rows,
        "all_rows": math_rows + calibration_rows,
    }


def row_to_text(row: dict[str, Any]) -> str:
    failure_modes = ", ".join(row.get("failure_modes") or [])
    target = row.get("target_lobe") or row.get("route_adapter") or "unknown_lobe"
    expected = str(row.get("expected_normalized_answer", ""))
    routed = str(row.get("routed_prediction", ""))
    best = str(row.get("best_subject_in_hindsight", ""))
    objective = str(row.get("repair_objective", "repair_route_regret"))
    return (
        "KT G3 targeted repair example\n"
        f"target_lobe: {target}\n"
        f"dataset: {row.get('dataset')}\n"
        f"item_id: {row.get('item_id')}\n"
        f"failure_modes: {failure_modes}\n"
        f"chosen_subject: {row.get('chosen_subject')}\n"
        f"best_subject_in_hindsight: {best}\n"
        f"routed_prediction: {routed}\n"
        f"expected_answer: {expected}\n"
        f"repair_objective: {objective}\n"
        "Response: choose the smallest repair that improves the target lobe while preserving claim ceiling, "
        "human anchor, and no-regression constraints."
    )


def select_lobes(inputs: dict[str, Any], cfg: dict[str, Any]) -> list[str]:
    explicit = [item.strip() for item in os.environ.get("KT_TARGET_LOBES", "").split(",") if item.strip()]
    if explicit:
        lobes = explicit
    else:
        counts = inputs["failure_map"].get("by_target_lobe", {})
        lobes = [name for name, _ in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]
    bad = [name for name in lobes if name not in CANONICAL_LOBES]
    if bad:
        raise RuntimeError(f"Non-canonical lobe requested for G3 runtime: {bad}")
    return lobes[: max(1, cfg["max_lobes"])]


def split_lobe_examples(rows: list[dict[str, Any]], lobe: str, cfg: dict[str, Any]) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    selected = [row for row in rows if (row.get("target_lobe") or row.get("route_adapter")) == lobe]
    if not selected:
        selected = list(rows)
    selected = selected[: cfg["max_rows_per_lobe"] + cfg["eval_rows_per_lobe"]]
    if len(selected) < 2:
        raise RuntimeError(f"Not enough repair rows for lobe {lobe}")
    eval_count = min(cfg["eval_rows_per_lobe"], max(1, len(selected) // 4))
    train_rows = selected[:-eval_count]
    eval_rows = selected[-eval_count:]
    if not train_rows:
        train_rows = selected[:1]
    return [row_to_text(row) for row in train_rows], [row_to_text(row) for row in eval_rows], selected


def import_training_deps() -> dict[str, Any]:
    try:
        import torch
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    except Exception as exc:
        raise RuntimeError(f"Missing runtime training dependency: {exc}") from exc
    return {
        "torch": torch,
        "LoraConfig": LoraConfig,
        "get_peft_model": get_peft_model,
        "prepare_model_for_kbit_training": prepare_model_for_kbit_training,
        "AutoModelForCausalLM": AutoModelForCausalLM,
        "AutoTokenizer": AutoTokenizer,
        "BitsAndBytesConfig": BitsAndBytesConfig,
    }


def tokenized_batches(tokenizer: Any, texts: list[str], cfg: dict[str, Any], torch: Any) -> list[dict[str, Any]]:
    batches = []
    for text in texts:
        encoded = tokenizer(
            text,
            truncation=True,
            max_length=cfg["max_seq_len"],
            padding=False,
            return_tensors="pt",
        )
        encoded["labels"] = encoded["input_ids"].clone()
        batches.append(encoded)
    return batches


def eval_loss(model: Any, batches: list[dict[str, Any]], torch: Any, device: str) -> float:
    model.eval()
    losses = []
    with torch.no_grad():
        for batch in batches:
            batch = {key: value.to(device) for key, value in batch.items()}
            out = model(**batch)
            loss = float(out.loss.detach().cpu().item())
            if math.isfinite(loss):
                losses.append(loss)
    return float(sum(losses) / len(losses)) if losses else float("inf")


def load_model_and_tokenizer(deps: dict[str, Any], cfg: dict[str, Any]) -> tuple[Any, Any, str, bool]:
    torch = deps["torch"]
    tokenizer = deps["AutoTokenizer"].from_pretrained(cfg["base_model"], cache_dir=os.environ.get("TRANSFORMERS_CACHE"))
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    qlora_effective = False
    kwargs: dict[str, Any] = {"cache_dir": os.environ.get("TRANSFORMERS_CACHE")}
    if torch.cuda.is_available():
        kwargs["device_map"] = "auto"
        if cfg["load_in_4bit"]:
            kwargs["quantization_config"] = deps["BitsAndBytesConfig"](
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
            )
            qlora_effective = True
    elif cfg["require_qlora"]:
        raise RuntimeError("KT_REQUIRE_QLORA=1 but CUDA is not available")
    model = deps["AutoModelForCausalLM"].from_pretrained(cfg["base_model"], **kwargs)
    if qlora_effective:
        model = deps["prepare_model_for_kbit_training"](model)
    elif cfg["require_qlora"]:
        raise RuntimeError("KT_REQUIRE_QLORA=1 but 4-bit model loading was not effective")
    device = "cuda" if torch.cuda.is_available() else "cpu"
    if device == "cpu":
        model.to(device)
    return model, tokenizer, device, qlora_effective


def train_lobe(lobe: str, inputs: dict[str, Any], cfg: dict[str, Any], output_dir: Path, deps: dict[str, Any]) -> dict[str, Any]:
    torch = deps["torch"]
    torch.manual_seed(cfg["seed"])
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(cfg["seed"])
    model, tokenizer, device, qlora_effective = load_model_and_tokenizer(deps, cfg)
    lora_cfg = deps["LoraConfig"](
        r=int_env("KT_LORA_R", 8),
        lora_alpha=int_env("KT_LORA_ALPHA", 16),
        lora_dropout=float_env("KT_LORA_DROPOUT", 0.05),
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    )
    model = deps["get_peft_model"](model, lora_cfg)
    train_texts, eval_texts, source_rows = split_lobe_examples(inputs["all_rows"], lobe, cfg)
    train_batches = tokenized_batches(tokenizer, train_texts, cfg, torch)
    eval_batches = tokenized_batches(tokenizer, eval_texts, cfg, torch)
    pre_loss = eval_loss(model, eval_batches, torch, device)
    optimizer = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=cfg["learning_rate"])
    model.train()
    losses: list[float] = []
    steps = 0
    start = time.time()
    for epoch in range(1000000):
        for batch in train_batches:
            batch = {key: value.to(device) for key, value in batch.items()}
            out = model(**batch)
            loss = out.loss / max(1, cfg["grad_accum"])
            loss.backward()
            if (steps + 1) % max(1, cfg["grad_accum"]) == 0:
                optimizer.step()
                optimizer.zero_grad(set_to_none=True)
            raw_loss = float(out.loss.detach().cpu().item())
            if math.isfinite(raw_loss):
                losses.append(raw_loss)
            steps += 1
            if steps >= cfg["max_steps_per_lobe"]:
                break
        if steps >= cfg["max_steps_per_lobe"]:
            break
    if steps % max(1, cfg["grad_accum"]) != 0:
        optimizer.step()
        optimizer.zero_grad(set_to_none=True)
    post_loss = eval_loss(model, eval_batches, torch, device)
    adapter_dir = output_dir / "adapters" / safe_name(lobe)
    adapter_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(adapter_dir, safe_serialization=True)
    tokenizer.save_pretrained(adapter_dir)
    adapter_files = sorted(adapter_dir.rglob("*.safetensors"))
    adapter_hashes = {str(path.relative_to(output_dir)): sha256_file(path) for path in adapter_files}
    elapsed = max(0.001, time.time() - start)
    trace_rows = [
        {
            "failure_id": row.get("failure_id"),
            "input_hash": sha256_text(row_to_text(row)),
            "target_lobe": lobe,
            "expected_normalized_answer": row.get("expected_normalized_answer"),
            "repair_objective": row.get("repair_objective"),
            "human_anchor_available": bool(row.get("human_anchor_available")),
        }
        for row in source_rows
    ]
    del model
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    return {
        "lobe_id": lobe,
        "train_rows": len(train_texts),
        "eval_rows": len(eval_texts),
        "steps": steps,
        "pre_eval_loss": pre_loss,
        "post_eval_loss": post_loss,
        "mean_train_loss": float(sum(losses) / len(losses)) if losses else float("inf"),
        "qlora_effective": qlora_effective,
        "adapter_dir": str(adapter_dir),
        "adapter_hashes": adapter_hashes,
        "source_failure_ids": [row.get("failure_id") for row in source_rows],
        "trace_rows": trace_rows,
        "elapsed_seconds": elapsed,
        "tokens_per_second_proxy": sum(len(text.split()) for text in train_texts) / elapsed,
    }


def upload_final_artifacts(output_dir: Path, assessment_zip: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    receipt = {
        "schema_id": "kt.g3.hf_upload_receipt.v2",
        "created_utc": utc_now(),
        "upload_attempted": bool(cfg["require_hf_upload"]),
        "upload_required": bool(cfg["require_hf_upload"]),
        "hf_repo_id": cfg["hf_repo_id"],
        "uploaded_urls": [],
        "claim_ceiling_preserved": True,
    }
    if not cfg["require_hf_upload"]:
        receipt["upload_pass"] = True
        receipt["upload_skipped_reason"] = "KT_REQUIRE_HF_UPLOAD=0"
        write_json(output_dir / "hf_upload_receipt.json", receipt)
        return receipt
    if not os.environ.get("HF_TOKEN"):
        receipt["upload_pass"] = False
        receipt["blocker"] = "HF_TOKEN_MISSING"
        write_json(output_dir / "hf_upload_receipt.json", receipt)
        return receipt
    if not cfg["hf_repo_id"]:
        receipt["upload_pass"] = False
        receipt["blocker"] = "KT_HF_REPO_ID_MISSING"
        write_json(output_dir / "hf_upload_receipt.json", receipt)
        return receipt
    try:
        from huggingface_hub import HfApi

        api = HfApi(token=os.environ["HF_TOKEN"])
        api.upload_file(
            path_or_fileobj=str(assessment_zip),
            path_in_repo=assessment_zip.name,
            repo_id=cfg["hf_repo_id"],
            repo_type="dataset",
        )
        url = f"https://huggingface.co/datasets/{cfg['hf_repo_id']}/blob/main/{assessment_zip.name}"
        receipt["uploaded_urls"].append(url)
        receipt["upload_pass"] = True
    except Exception as exc:
        receipt["upload_pass"] = False
        receipt["blocker"] = f"HF_UPLOAD_FAILED: {exc}"
    write_json(output_dir / "hf_upload_receipt.json", receipt)
    return receipt


def make_assessment_zip(output_dir: Path, run_id: str) -> Path:
    zip_path = output_dir / f"{run_id}_ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(output_dir.rglob("*")):
            if path.is_file() and path != zip_path and "adapters" not in path.parts:
                zf.write(path, path.relative_to(output_dir))
    return zip_path


def write_blocked(output_dir: Path, cfg: dict[str, Any] | None, blockers: list[dict[str, Any]], run_id: str) -> int:
    ledger = {
        "schema_id": "kt.g3.negative_result_ledger.v2",
        "created_utc": utc_now(),
        "negative_result_count": len(blockers),
        "rows": blockers,
        "claim_ceiling_preserved": True,
    }
    write_json(output_dir / "g3_negative_result_ledger.json", ledger)
    write_json(output_dir / "blocker_ledger.json", {"schema_id": "kt.g3.blocker_ledger.v2", "blockers": blockers})
    summary = {
        "schema_id": "kt.g3.assessment_summary.v2",
        "created_utc": utc_now(),
        "program_id": PROGRAM_ID,
        "outcome": BLOCKED_OUTCOME,
        "success": False,
        "blockers": blockers,
        "claim_ceiling": BLOCKED_CLAIMS,
        "claim_ceiling_preserved": True,
    }
    write_json(output_dir / "assessment_summary.json", summary)
    assessment_zip = make_assessment_zip(output_dir, run_id)
    print(json.dumps({**summary, "assessment_zip": str(assessment_zip)}, indent=2, sort_keys=True))
    return 2


def main() -> int:
    packet_dir = Path(__file__).resolve().parent
    run_id = os.environ.get("KT_RUN_ID") or f"ktg3_v2_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    output_dir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktg3_run_v2_outputs")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    cfg: dict[str, Any] | None = None
    try:
        head = bind_head(output_dir)
        cfg = runtime_config(output_dir)
        deps = import_training_deps()
        torch = deps["torch"]
        write_json(
            output_dir / "cuda_environment_receipt.json",
            {
                "schema_id": "kt.g3.cuda_environment_receipt.v2",
                "created_utc": utc_now(),
                "cuda_available": bool(torch.cuda.is_available()),
                "device_count": int(torch.cuda.device_count()) if torch.cuda.is_available() else 0,
                "device_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU",
                "claim_ceiling_preserved": True,
            },
        )
        inputs = load_packet_inputs(packet_dir)
        target_lobes = select_lobes(inputs, cfg)
        results: list[dict[str, Any]] = []
        negatives: list[dict[str, Any]] = []
        traces: list[dict[str, Any]] = []
        for lobe in target_lobes:
            try:
                result = train_lobe(lobe, inputs, cfg, output_dir, deps)
                results.append(result)
                traces.extend(result.pop("trace_rows", []))
            except Exception as exc:
                negatives.append({"stage": "train_lobe", "lobe_id": lobe, "error": str(exc)})
        no_regression_rows = []
        for result in results:
            passed = bool(result["post_eval_loss"] <= result["pre_eval_loss"] + float_env("KT_NO_REGRESSION_LOSS_TOLERANCE", 0.10))
            no_regression_rows.append(
                {
                    "lobe_id": result["lobe_id"],
                    "pre_eval_loss": result["pre_eval_loss"],
                    "post_eval_loss": result["post_eval_loss"],
                    "no_regression_pass": passed,
                }
            )
            if not passed:
                negatives.append({"stage": "no_regression", "lobe_id": result["lobe_id"], "error": "POST_LOSS_EXCEEDED_TOLERANCE"})
        training_receipt = {
            "schema_id": "kt.g3.training_receipt.v2",
            "created_utc": utc_now(),
            "program_id": PROGRAM_ID,
            "head_binding": head,
            "target_lobes": target_lobes,
            "trained_lobe_count": len(results),
            "training_errors_count": len([row for row in negatives if row["stage"] == "train_lobe"]),
            "results": results,
            "claim_ceiling_preserved": True,
        }
        write_json(output_dir / "g3_training_receipt.json", training_receipt)
        eval_receipt = {
            "schema_id": "kt.g3.eval_receipt.v2",
            "created_utc": utc_now(),
            "eval_rows": no_regression_rows,
            "claim_ceiling_preserved": True,
        }
        write_json(output_dir / "g3_eval_receipt.json", eval_receipt)
        no_regression_pass = bool(results) and not any(not row["no_regression_pass"] for row in no_regression_rows)
        write_json(
            output_dir / "g3_no_regression_receipt.json",
            {
                "schema_id": "kt.g3.no_regression_receipt.v2",
                "created_utc": utc_now(),
                "no_regression_pass": no_regression_pass,
                "rows": no_regression_rows,
                "claim_ceiling_preserved": True,
            },
        )
        hash_rows = []
        for path in sorted((output_dir / "adapters").rglob("*.safetensors")) if (output_dir / "adapters").exists() else []:
            hash_rows.append({"path": str(path.relative_to(output_dir)), "sha256": sha256_file(path), "size_bytes": path.stat().st_size})
        write_json(
            output_dir / "safetensors_hash_manifest.json",
            {"schema_id": "kt.g3.safetensors_hash_manifest.v2", "files": hash_rows, "claim_ceiling_preserved": True},
        )
        distinct_hashes = {row["sha256"] for row in hash_rows}
        scar_delta_pass = bool(hash_rows) and len(distinct_hashes) == len(hash_rows)
        write_json(
            output_dir / "g3_scar_delta_distinctness_receipt.json",
            {
                "schema_id": "kt.g3.scar_delta_distinctness_receipt.v2",
                "created_utc": utc_now(),
                "scar_delta_distinctness_pass": scar_delta_pass,
                "adapter_hash_count": len(hash_rows),
                "distinct_adapter_hash_count": len(distinct_hashes),
                "source_failure_ids_bound": sorted({fid for result in results for fid in result.get("source_failure_ids", []) if fid}),
                "claim_ceiling_preserved": True,
            },
        )
        if not scar_delta_pass:
            negatives.append({"stage": "scar_delta_distinctness", "error": "NO_DISTINCT_SAFETENSORS_HASHES"})
        route_target_count = int(inputs["route_targets"].get("target_count", 0))
        trained_source_ids = sorted({fid for result in results for fid in result.get("source_failure_ids", []) if fid})
        write_json(
            output_dir / "route_regret_closure_scorecard.json",
            {
                "schema_id": "kt.g3.route_regret_closure_scorecard.v2",
                "created_utc": utc_now(),
                "route_regret_target_count": route_target_count,
                "trained_source_failure_count": len(trained_source_ids),
                "closure_ratio": (len(trained_source_ids) / route_target_count) if route_target_count else 0.0,
                "router_superiority_claim_allowed": False,
                "claim_ceiling_preserved": True,
            },
        )
        elapsed = sum(result.get("elapsed_seconds", 0.0) for result in results)
        write_json(
            output_dir / "verified_repair_velocity_scorecard.json",
            {
                "schema_id": "kt.g3.verified_repair_velocity_scorecard.v2",
                "created_utc": utc_now(),
                "trained_lobes": len(results),
                "elapsed_seconds": elapsed,
                "lobe_trainings_per_hour": (len(results) / elapsed * 3600.0) if elapsed else 0.0,
                "claim_ceiling_preserved": True,
            },
        )
        write_json(
            output_dir / "anti_goodhart_scorecard.json",
            {
                "schema_id": "kt.g3.anti_goodhart_scorecard.v2",
                "created_utc": utc_now(),
                "primary_metrics_have_failure_mode_pairs": bool(inputs["metric_constitution"].get("anti_goodhart_pairing_complete")),
                "human_anchor_bound": bool(inputs["human_anchor"].get("human_anchor_pass")),
                "no_regression_bound": no_regression_pass,
                "claim_ceiling_preserved": True,
            },
        )
        write_json(
            output_dir / "human_anchor_anti_collapse_receipt.json",
            {
                "schema_id": "kt.g3.human_anchor_anti_collapse_receipt.v2",
                "created_utc": utc_now(),
                "human_anchor_pass": bool(inputs["human_anchor"].get("human_anchor_pass")),
                "anchor_ratio": inputs["human_anchor"].get("anchor_ratio"),
                "prompt_text_imported": all(bool(row.get("prompt_text_imported")) for row in inputs["all_rows"]),
                "prompt_reconstruction_required": any(not bool(row.get("prompt_text_imported")) for row in inputs["all_rows"]),
                "metric_collapse_blocked": True,
                "claim_ceiling_preserved": True,
            },
        )
        write_json(
            output_dir / "lobe_specialization_scorecard.json",
            {
                "schema_id": "kt.g3.lobe_specialization_scorecard.v2",
                "created_utc": utc_now(),
                "rows": [
                    {
                        "lobe_id": result["lobe_id"],
                        "train_rows": result["train_rows"],
                        "eval_rows": result["eval_rows"],
                        "mean_train_loss": result["mean_train_loss"],
                        "post_eval_loss": result["post_eval_loss"],
                    }
                    for result in results
                ],
                "lobe_specialization_claim_allowed": False,
                "claim_ceiling_preserved": True,
            },
        )
        write_json(
            output_dir / "assurance_case_claim_compiler_receipt.json",
            {
                "schema_id": "kt.g3.assurance_case_claim_compiler_receipt.v2",
                "created_utc": utc_now(),
                "forbidden_claims_blocked": BLOCKED_CLAIMS,
                "commercial_claim_authorized": False,
                "router_superiority_claim_authorized": False,
                "multi_lobe_superiority_claim_authorized": False,
                "claim_ceiling_preserved": True,
            },
        )
        write_jsonl(output_dir / "router_trace.jsonl", traces)
        with (output_dir / "router_trace.csv").open("w", encoding="utf-8", newline="") as handle:
            fieldnames = ["failure_id", "input_hash", "target_lobe", "expected_normalized_answer", "repair_objective", "human_anchor_available"]
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in traces:
                writer.writerow({key: row.get(key) for key in fieldnames})
        negative_ledger = {
            "schema_id": "kt.g3.negative_result_ledger.v2",
            "created_utc": utc_now(),
            "negative_result_count": len(negatives),
            "rows": negatives,
            "claim_ceiling_preserved": True,
        }
        write_json(output_dir / "g3_negative_result_ledger.json", negative_ledger)
        assessment_zip = make_assessment_zip(output_dir, run_id)
        hf_receipt = upload_final_artifacts(output_dir, assessment_zip, cfg)
        if not hf_receipt.get("upload_pass"):
            negatives.append({"stage": "hf_upload", "error": hf_receipt.get("blocker", "HF_UPLOAD_FAILED")})
            write_json(output_dir / "g3_negative_result_ledger.json", {**negative_ledger, "negative_result_count": len(negatives), "rows": negatives})
        success = bool(results) and not negatives and no_regression_pass and scar_delta_pass and bool(hf_receipt.get("upload_pass"))
        summary = {
            "schema_id": "kt.g3.assessment_summary.v2",
            "created_utc": utc_now(),
            "program_id": PROGRAM_ID,
            "outcome": SUCCESS_OUTCOME if success else BLOCKED_OUTCOME,
            "success": success,
            "trained_lobe_count": len(results),
            "negative_result_count": len(negatives),
            "assessment_zip": str(assessment_zip),
            "hf_uploaded_urls": hf_receipt.get("uploaded_urls", []),
            "claim_ceiling": BLOCKED_CLAIMS,
            "claim_ceiling_preserved": True,
            "next_lawful_move": "REVIEW_KTG3_TARGETED_RUNTIME_ASSESSMENT",
        }
        write_json(output_dir / "assessment_summary.json", summary)
        assessment_zip = make_assessment_zip(output_dir, run_id)
        print(json.dumps({**summary, "assessment_zip": str(assessment_zip)}, indent=2, sort_keys=True))
        return 0 if success else 2
    except Exception as exc:
        blockers = [{"stage": "runtime_exception", "error": str(exc)}]
        return write_blocked(output_dir, cfg, blockers, run_id)


if __name__ == "__main__":
    raise SystemExit(main())
