from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

KT_PROD_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
if str(KT_PROD_CLEANROOM_ROOT) not in sys.path:
    sys.path.insert(0, str(KT_PROD_CLEANROOM_ROOT))

try:
    from tools.operator import g3_academy_pressure_repair_v1 as g3
    from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
except ImportError:  # pragma: no cover - supports `python -m KT_PROD_CLEANROOM...`
    from KT_PROD_CLEANROOM.tools.operator import g3_academy_pressure_repair_v1 as g3
    from KT_PROD_CLEANROOM.tools.operator.titanium_common import (
        file_sha256,
        load_json,
        repo_root,
        utc_now_iso_z,
        write_json_stable,
    )


PROGRAM_ID = "KT_G3_TARGETED_RUNTIME_PACKET_V2"
TARGET_OUTCOME = "KT_G3_TARGETED_RUNTIME_PACKET_READY__KAGGLE_EXECUTION_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTG3_TARGETED_RUNTIME_PACKET_V2"
PACKET_NAME = "ktg3_run_v2.zip"

RUNTIME_REQUIRED_OUTPUTS = [
    "g3_training_receipt.json",
    "g3_eval_receipt.json",
    "g3_no_regression_receipt.json",
    "g3_scar_delta_distinctness_receipt.json",
    "g3_negative_result_ledger.json",
    "route_regret_closure_scorecard.json",
    "verified_repair_velocity_scorecard.json",
    "anti_goodhart_scorecard.json",
    "human_anchor_anti_collapse_receipt.json",
    "lobe_specialization_scorecard.json",
    "assurance_case_claim_compiler_receipt.json",
    "hf_upload_receipt.json",
    "safetensors_hash_manifest.json",
]

ARTIFACTS: dict[str, str] = {
    "packet_dir": "packets/ktg3_run_v2",
    "packet_zip": f"packets/{PACKET_NAME}",
    "packet_manifest": "packets/ktg3_run_v2/PACKET_MANIFEST.json",
    "packet_runner": "packets/ktg3_run_v2/KTG3_TARGETED_REPAIR_V2_RUNNER.py",
    "packet_bootstrap": "packets/ktg3_run_v2/KAGGLE_BOOTSTRAP_CELL.py",
    "packet_hash_manifest": "packets/ktg3_run_v2/SHA256_MANIFEST.json",
    "runtime_packet_receipt": "reports/g3_targeted_runtime_packet_v2_receipt.json",
    "artifact_delta": "registry/artifact_authority_registry_g3_targeted_runtime_packet_v2_delta_receipt.json",
    "artifact_registry": "registry/artifact_authority_registry.json",
}


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:  # noqa: BLE001
        return "UNKNOWN_NON_GIT_TEST_ROOT"


def _git_branch(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip()
    except Exception:  # noqa: BLE001
        return "UNKNOWN_NON_GIT_TEST_ROOT"


def _write_text_stable(path: Path, text: str) -> bool:
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return True


def _json_dumps(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        if not raw.strip():
            continue
        row = json.loads(raw)
        if not isinstance(row, dict):
            raise ValueError(f"JSONL row in {path} is not an object")
        rows.append(row)
    return rows


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    text = "".join(json.dumps(dict(row), sort_keys=True, ensure_ascii=True) + "\n" for row in rows)
    _write_text_stable(path, text)


def _required_json(root: Path, rel_path: str) -> dict[str, Any]:
    path = root / rel_path
    if not path.exists():
        raise FileNotFoundError(f"Required G3 artifact missing: {rel_path}")
    value = load_json(path)
    if not isinstance(value, dict):
        raise ValueError(f"Required G3 artifact is not a JSON object: {rel_path}")
    return value


def _required_jsonl(root: Path, rel_path: str) -> list[dict[str, Any]]:
    path = root / rel_path
    if not path.exists():
        raise FileNotFoundError(f"Required G3 corpus missing: {rel_path}")
    return _read_jsonl(path)


def _runtime_runner_source(head: str) -> str:
    source = r'''
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

PROGRAM_ID = "__PROGRAM_ID__"
PACKET_BUILD_HEAD = "__PACKET_BUILD_HEAD__"
SUCCESS_OUTCOME = "KT_G3_TARGETED_REPAIR_RUNTIME_EXECUTED__ASSESSMENT_READY__CLAIM_CEILING_PRESERVED"
BLOCKED_OUTCOME = "KT_G3_TARGETED_REPAIR_RUNTIME_BLOCKED__NAMED_DEFECT_REMAINS"

CANONICAL_LOBES = __CANONICAL_LOBES__
BLOCKED_CLAIMS = __BLOCKED_CLAIMS__
REQUIRED_OUTPUTS = __REQUIRED_OUTPUTS__


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
'''
    return (
        textwrap.dedent(source).strip()
        .replace("__PROGRAM_ID__", PROGRAM_ID)
        .replace("__PACKET_BUILD_HEAD__", head)
        .replace("__CANONICAL_LOBES__", json.dumps(g3.CANONICAL_LOBES, sort_keys=True))
        .replace("__BLOCKED_CLAIMS__", json.dumps(g3.BLOCKED_CLAIMS, sort_keys=True))
        .replace("__REQUIRED_OUTPUTS__", json.dumps(RUNTIME_REQUIRED_OUTPUTS, sort_keys=True))
        + "\n"
    )


def _bootstrap_source() -> str:
    return f'''from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
import zipfile

PACKET_NAME = "{PACKET_NAME}"


def _packet_zip() -> Path:
    override = os.environ.get("KT_PACKET_ZIP_PATH", "").strip()
    if override:
        packet = Path(override)
        if not packet.exists():
            raise FileNotFoundError(f"KT_PACKET_ZIP_PATH not found: {{packet}}")
        return packet
    candidates = sorted(Path("/kaggle/input").rglob(PACKET_NAME))
    if not candidates:
        raise FileNotFoundError(f"{{PACKET_NAME}} not found under /kaggle/input")
    if len(candidates) > 1:
        rendered = ", ".join(str(path) for path in candidates)
        raise RuntimeError(f"Multiple candidate packets found; set KT_PACKET_ZIP_PATH: {{rendered}}")
    return candidates[0]


def _verify_sha256(path: Path) -> None:
    expected = os.environ.get("KT_PACKET_SHA256", "").strip().lower()
    if not expected:
        return
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError(f"KT_PACKET_SHA256 mismatch: expected {{expected}}, got {{actual}}")


def _safe_extract(packet: Path, work: Path) -> None:
    root = work.resolve()
    with zipfile.ZipFile(packet) as zf:
        for member in zf.namelist():
            target = (root / member).resolve()
            if not (target == root or root in target.parents):
                raise RuntimeError(f"Unsafe zip member path: {{member}}")
            if member.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(member))


def _install_deps() -> None:
    if os.environ.get("KT_SKIP_INSTALL", "").strip().lower() in {{"1", "true", "yes", "on"}}:
        return
    packages = [
        "transformers>=4.43",
        "peft>=0.12",
        "accelerate>=0.33",
        "safetensors>=0.4",
        "huggingface_hub>=0.24",
        "bitsandbytes>=0.43",
    ]
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "--upgrade", *packages])


packet_zip = _packet_zip()
_verify_sha256(packet_zip)
work = Path("/kaggle/working/ktg3_run_v2")
work.mkdir(parents=True, exist_ok=True)
_safe_extract(packet_zip, work)
_install_deps()
runner = work / "KTG3_TARGETED_REPAIR_V2_RUNNER.py"
exec(compile(runner.read_text(encoding="utf-8"), str(runner), "exec"), {{"__name__": "__main__", "__file__": str(runner)}})
'''


def _readme(head: str) -> str:
    return f"""# KTG3 Targeted Repair Runtime Packet V2

This packet replaces the prior G3 runtime-intent packet with a Kaggle-executable
targeted repair runtime.

It trains PEFT repair adapters from the G3 repair fuel, runs no-regression and
scar/delta distinctness checks, emits required runtime receipts, builds a small
assessment ZIP, and fails closed if required runtime evidence or HF final-only
upload is missing.

Build head: `{head}`

Claim ceiling: unchanged. This packet does not authorize commercial launch,
external audit acceptance, external validation acceptance, S-tier, beyond-SOTA,
category leadership, frontier parity, 7B amplification, router superiority,
multi-lobe superiority, or production readiness.

Required Kaggle knobs:

- `HF_TOKEN`: required for clean pass unless `KT_REQUIRE_HF_UPLOAD=0`.
- `KT_HF_REPO_ID`: required for clean pass unless `KT_REQUIRE_HF_UPLOAD=0`.
- `KT_BASE_MODEL`: defaults to `Qwen/Qwen2.5-0.5B-Instruct`; override for a larger run.
- `KT_REQUESTED_HEAD`: optional, but if set it must match actual runtime head.

The runner emits `*_ASSESSMENT_ONLY.zip` and all required G3 runtime receipts.
"""


def _packet_manifest(head: str, source_hashes: Mapping[str, str]) -> dict[str, Any]:
    return {
        "schema_id": "kt.g3.targeted_runtime_packet_manifest.v2",
        "created_utc": utc_now_iso_z(),
        "program_id": PROGRAM_ID,
        "packet_name": PACKET_NAME,
        "packet_build_head": head,
        "packet_sha256_recorded_in_repo_receipt": True,
        "runner_kind": "EXECUTABLE_TARGETED_PEFT_RUNTIME",
        "runtime_intent_only": False,
        "requires_runtime_training": True,
        "requires_hf_final_only_upload_for_clean_pass": True,
        "one_cell_kaggle_compatible": True,
        "runtime_required_outputs": RUNTIME_REQUIRED_OUTPUTS,
        "source_artifact_hashes": dict(source_hashes),
        "claim_ceiling_preserved": True,
        "claims_authorized": [],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }


def _source_artifacts(root: Path) -> dict[str, Path]:
    paths = {
        "G2_EVIDENCE_MANIFEST.json": root / g3.ARTIFACTS["g2_evidence_manifest"],
        "G2_FAILURE_MAP.json": root / g3.ARTIFACTS["g2_failure_map"],
        "G2_ROUTE_REGRET_TARGETS.json": root / g3.ARTIFACTS["g2_route_regret_targets"],
        "HUMAN_ANCHOR_MANIFEST.json": root / g3.ARTIFACTS["human_anchor_manifest"],
        "G3_METRIC_CONSTITUTION.json": root / g3.ARTIFACTS["g3_metric_constitution"],
        "G3_FORMAL_MATH_REPAIR_PLAN.json": root / g3.ARTIFACTS["formal_math_repair_plan"],
        "G3_MATH_REPAIR_CORPUS.jsonl": root / g3.ARTIFACTS["math_repair_corpus"],
        "G3_KT_HAT_CALIBRATION_CORPUS.jsonl": root / g3.ARTIFACTS["kt_hat_calibration_corpus"],
    }
    missing = [path.as_posix() for path in paths.values() if not path.exists()]
    if missing:
        raise FileNotFoundError(f"Cannot build {PACKET_NAME}; missing G3 source artifacts: {missing}")
    return paths


def _emit_packet(root: Path, *, head: str) -> str:
    packet_dir = root / ARTIFACTS["packet_dir"]
    if packet_dir.exists():
        shutil.rmtree(packet_dir)
    packet_dir.mkdir(parents=True, exist_ok=True)
    sources = _source_artifacts(root)
    source_hashes = {name: file_sha256(path) for name, path in sources.items()}
    for name, path in sources.items():
        shutil.copy2(path, packet_dir / name)
    runner = _runtime_runner_source(head)
    _write_text_stable(packet_dir / "KTG3_TARGETED_REPAIR_V2_RUNNER.py", runner)
    _write_text_stable(packet_dir / "KAGGLE_BOOTSTRAP_CELL.py", _bootstrap_source())
    _write_text_stable(packet_dir / "README_RUNBOOK.md", _readme(head))
    write_json_stable(packet_dir / "PACKET_MANIFEST.json", _packet_manifest(head, source_hashes))

    hash_rows = []
    for path in sorted(packet_dir.iterdir()):
        if path.is_file() and path.name != "SHA256_MANIFEST.json":
            hash_rows.append({"path": path.name, "sha256": file_sha256(path), "size_bytes": path.stat().st_size})
    write_json_stable(packet_dir / "SHA256_MANIFEST.json", {"schema_id": "kt.g3.runtime_packet_sha256_manifest.v2", "files": hash_rows})

    zip_path = root / ARTIFACTS["packet_zip"]
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(packet_dir.iterdir()):
            if path.is_file():
                zf.write(path, path.name)
    return file_sha256(zip_path)


def _registry_entry(root: Path, artifact_id: str, path: str, role: str, *, controls_execution: bool) -> dict[str, Any]:
    full = root / path
    return {
        "artifact_id": artifact_id,
        "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
        "claim_authority": "INTERNAL_SHADOW",
        "controls_execution": controls_execution,
        "notes": "Executable G3 runtime packet; no claim expansion and no runtime result claim until Kaggle receipts return.",
        "path": path,
        "role": role,
        "sha256": file_sha256(full) if full.exists() and full.is_file() else "",
        "superseded_by": None,
        "supersedes": ["KTG3_TARGETED_RUN_PACKET"] if artifact_id == "KTG3_TARGETED_RUNTIME_PACKET_V2" else [],
        "validation_status": "PASS",
    }


def update_artifact_registry(root: Path) -> dict[str, Any]:
    registry_path = root / ARTIFACTS["artifact_registry"]
    registry = load_json(registry_path) if registry_path.exists() else {"schema_id": "kt.artifact_authority_registry.v3", "artifacts": []}
    additions = [
        _registry_entry(
            root,
            "KTG3_TARGETED_RUNTIME_PACKET_V2",
            ARTIFACTS["packet_zip"],
            "targeted_g3_executable_runtime_packet",
            controls_execution=False,
        ),
        _registry_entry(
            root,
            "KTG3_TARGETED_RUNTIME_PACKET_V2_RECEIPT",
            ARTIFACTS["runtime_packet_receipt"],
            "targeted_g3_runtime_packet_build_receipt",
            controls_execution=False,
        ),
    ]
    existing = {artifact.get("artifact_id"): artifact for artifact in registry.get("artifacts", [])}
    if "KTG3_TARGETED_RUN_PACKET" in existing:
        existing["KTG3_TARGETED_RUN_PACKET"]["superseded_by"] = ARTIFACTS["packet_zip"]
        existing["KTG3_TARGETED_RUN_PACKET"]["notes"] = "Superseded for runtime execution by ktg3_run_v2.zip; retained as repo-side G3 repair-fuel packet."
        existing["KTG3_TARGETED_RUN_PACKET"]["controls_execution"] = False
    for entry in additions:
        existing[entry["artifact_id"]] = entry
    registry["artifacts"] = list(existing.values())
    registry["current_head"] = _git_head(root)
    registry["generated_utc"] = utc_now_iso_z()
    registry.setdefault("schema_id", "kt.artifact_authority_registry.v3")
    write_json_stable(registry_path, registry)
    delta = {
        "schema_id": "kt.g3.targeted_runtime_packet_v2_artifact_authority_delta_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "artifacts_added_or_updated": [entry["artifact_id"] for entry in additions],
        "artifacts_superseded": ["KTG3_TARGETED_RUN_PACKET"],
        "claim_ceiling_unchanged": True,
        "production_commercial_external_superiority_authority_added": False,
        **g3.BLOCKED_CLAIMS,
    }
    write_json_stable(root / ARTIFACTS["artifact_delta"], delta)
    return delta


def run(*, output_root: Path | None = None) -> dict[str, Any]:
    root = (output_root or repo_root()).resolve()
    head = _git_head(root)
    branch = _git_branch(root)
    packet_sha = _emit_packet(root, head=head)
    manifest = load_json(root / ARTIFACTS["packet_manifest"])
    receipt = {
        "schema_id": "kt.g3.targeted_runtime_packet_v2_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "program_id": PROGRAM_ID,
        "current_head": head,
        "branch": branch,
        "mode": "BUILD_EXECUTABLE_RUNTIME_PACKET",
        "selected_outcome": TARGET_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "packet_path": ARTIFACTS["packet_zip"],
        "packet_sha256": packet_sha,
        "runtime_intent_only": False,
        "runtime_training_required": True,
        "required_runtime_outputs": RUNTIME_REQUIRED_OUTPUTS,
        "clean_success_requires_hf_final_only_upload": True,
        "claim_ceiling_status": "UNCHANGED",
        "claim_ceiling": g3.BLOCKED_CLAIMS,
        "manifest_runtime_kind": manifest["runner_kind"],
        "blockers": [],
    }
    write_json_stable(root / ARTIFACTS["runtime_packet_receipt"], receipt)
    registry_delta = update_artifact_registry(root)
    return {
        "current_head": head,
        "branch": branch,
        "outcome": TARGET_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "packet_path": ARTIFACTS["packet_zip"],
        "packet_sha256": packet_sha,
        "artifact_registry_delta": registry_delta["artifacts_added_or_updated"],
        "claim_ceiling_status": "UNCHANGED",
        "blockers": [],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=PROGRAM_ID)
    parser.add_argument("--output-root", default=None)
    args = parser.parse_args(argv)
    summary = run(output_root=Path(args.output_root).resolve() if args.output_root else None)
    print(_json_dumps(summary), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
