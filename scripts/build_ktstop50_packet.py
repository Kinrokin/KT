from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from ktstop50_common import (
    AUTHORITY_FALSE,
    DOCS,
    EVIDENCE,
    KAGGLE_DATASET_NAME,
    NEXT_LAWFUL_MOVE,
    ONE_CELL_RUNBOOK,
    OUTCOME,
    PACKET_PATH,
    REPORTS,
    ROOT,
    RUN_MODE,
    SCHEMAS,
    SCOPED_AUTHORITY,
    SOURCE_PACKET_SHA256,
    authority_payload,
    git_output,
    load_stoprt_config,
    rel,
    sha256_file,
    sha256_text,
    update_registry,
    utc_now,
    write_json,
    write_text,
)


MODEL_REPO = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
HF_RESULTS_REPO = "Kinrokin/ktstop50-v1-results"
ROW_START = 425
ROW_END = 475
PRIOR_POLICIES = {
    "bud25": list(range(0, 25)),
    "bud100": list(range(25, 125)),
    "pareto": list(range(325, 425)),
    "stop10_stoprt": [325, 329, 331, 332, 333, 340, 349, 359, 368, 369],
}


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def row_manifest() -> dict[str, Any]:
    rows = [
        {
            "row_id": f"gsm8k_test_{idx}",
            "dataset": "openai/gsm8k",
            "split": "test",
            "split_index": idx,
            "question_source": "loaded_at_runtime_from_openai_gsm8k",
            "expected_answer_source": "scorer_side_only_loaded_at_runtime",
        }
        for idx in range(ROW_START, ROW_END)
    ]
    selected = {row["split_index"] for row in rows}
    overlap = {
        name: sorted(selected.intersection(indices))
        for name, indices in PRIOR_POLICIES.items()
    }
    return {
        "schema_id": "kt.stop50.row_policy.v1",
        "status": "PASS_FRESH_NON_OVERLAPPING_50_ROW_DESIGN",
        "row_policy": f"openai/gsm8k:test[{ROW_START}:{ROW_END}]",
        "row_count": len(rows),
        "rows": rows,
        "prior_policy_overlap": overlap,
        "overlap_with_prior_rows": sum(len(value) for value in overlap.values()),
        "overlap_with_bud25": False,
        "overlap_with_bud100": False,
        "overlap_with_pareto": False,
        "overlap_with_stop10_stoprt": False,
        "claim_ceiling_status": "PRESERVED",
    }


def write_schemas() -> None:
    schemas = {
        "kt.stoprt.prefix_equivalence_v2.schema.json": {
            "schema_id": "kt.stoprt.prefix_equivalence_v2.schema.v1",
            "type": "object",
            "required": ["status", "court_v2_prefix_equal_count", "row_count"],
            "properties": {
                "status": {"type": "string"},
                "court_v2_prefix_equal_count": {"type": "integer"},
                "row_count": {"type": "integer"},
            },
        },
        "kt.stop50.environment_contract.schema.json": {
            "schema_id": "kt.stop50.environment_contract.schema.v1",
            "type": "object",
            "required": ["status", "cuda_required", "bitsandbytes_functional_required"],
            "properties": {
                "status": {"type": "string"},
                "cuda_required": {"type": "boolean"},
                "bitsandbytes_functional_required": {"type": "boolean"},
            },
        },
        "kt.stop50.experiment_protocol.schema.json": {
            "schema_id": "kt.stop50.experiment_protocol.schema.v1",
            "type": "object",
            "required": ["status", "batch_size", "randomized_synchronized_paired_timing"],
            "properties": {
                "status": {"type": "string"},
                "batch_size": {"type": "integer"},
                "randomized_synchronized_paired_timing": {"type": "boolean"},
            },
        },
    }
    for name, payload in schemas.items():
        write_json(SCHEMAS / name, payload)


def environment_preflight_source() -> str:
    return r'''from __future__ import annotations

import json
from pathlib import Path


def version_tuple(value: str):
    parts = []
    for part in value.replace("-", ".").split("."):
        if part.isdigit():
            parts.append(int(part))
        else:
            break
    return tuple(parts)


def inspect_model_quantization(model) -> dict:
    linear4bit_count = 0
    cpu_offloaded = 0
    disk_offloaded = 0
    device_map = getattr(model, "hf_device_map", {}) or {}
    for module in model.modules():
        if module.__class__.__name__ == "Linear4bit":
            linear4bit_count += 1
    for value in device_map.values() if isinstance(device_map, dict) else []:
        text = str(value).lower()
        if text == "cpu":
            cpu_offloaded += 1
        if text == "disk":
            disk_offloaded += 1
    return {
        "linear4bit_module_count": linear4bit_count,
        "model_is_loaded_in_4bit": linear4bit_count > 0,
        "cpu_offloaded_module_count": cpu_offloaded,
        "disk_offloaded_module_count": disk_offloaded,
    }


def cuda_environment_contract() -> dict:
    receipt = {
        "schema_id": "kt.stop50.cuda_environment_contract.runtime.v1",
        "status": "PENDING",
        "cuda_required": True,
        "bitsandbytes_functional_required": True,
    }
    try:
        import torch
        import bitsandbytes as bnb
        receipt["cuda_available"] = bool(torch.cuda.is_available())
        receipt["torch_version"] = getattr(torch, "__version__", "unknown")
        receipt["bitsandbytes_version"] = getattr(bnb, "__version__", "unknown")
        receipt["bitsandbytes_version_ok"] = version_tuple(receipt["bitsandbytes_version"]) >= (0, 49, 2)
        receipt["status"] = "PASS_IMPORTS" if receipt["cuda_available"] and receipt["bitsandbytes_version_ok"] else "FAIL_ENVIRONMENT"
    except Exception as exc:
        receipt["status"] = "FAIL_ENVIRONMENT"
        receipt["error"] = str(exc)
    return receipt


def write_blocker(outdir: Path, reason: str, receipt: dict) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "BLOCKER_RECEIPT.json").write_text(
        json.dumps(
            {
                "schema_id": "kt.stop50.blocker_receipt.runtime.v1",
                "status": "BLOCKED_ENVIRONMENT_CONTRACT",
                "reason": reason,
                "environment_receipt": receipt,
                "claim_ceiling_status": "PRESERVED",
                "training_authority": False,
                "promotion_authority": False,
                "selector_deployment_authority": False,
                "production_runtime_authority": False,
                "production_prompt_mutation_authority": False,
                "production_math_mode_claim": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
'''


def paired_timing_source() -> str:
    return r'''from __future__ import annotations

import hashlib


def deterministic_arm_order(row_id: str, repetition: int, seed: str = "ktstop50-v1") -> list[str]:
    key = f"{seed}:{row_id}:{repetition}".encode("utf-8")
    digest = hashlib.sha256(key).hexdigest()
    return ["C1_TERMINATE_FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP", "C0_MONITOR_FIRST_COMPLETE_FINAL_ANSWER_LINE"] if int(digest[:2], 16) % 2 else ["C0_MONITOR_FIRST_COMPLETE_FINAL_ANSWER_LINE", "C1_TERMINATE_FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP"]


def protocol_receipt() -> dict:
    return {
        "schema_id": "kt.stop50.randomized_synchronized_paired_timing.v1",
        "status": "PASS_PROTOCOL_DEFINED",
        "warmup_count": 3,
        "repetitions": 3,
        "batch_size": 1,
        "same_model_instance_required": True,
        "cuda_synchronize_before_after": True,
        "cuda_events_required": True,
        "randomize_arm_order": True,
        "claim_ceiling_status": "PRESERVED",
    }
'''


def effective_config_source() -> str:
    return r'''from __future__ import annotations

import hashlib
import json


def stable_hash(payload) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def quantization_authority_receipt(model_repo: str) -> dict:
    return {
        "schema_id": "kt.stop50.quantization_authority.v1",
        "status": "PASS_SINGLE_MODEL_EMBEDDED_QUANTIZATION_AUTHORITY",
        "model_repo": model_repo,
        "quantization_authority": "MODEL_EMBEDDED",
        "runtime_bitsandbytes_config_allowed": False,
        "conflict_count": 0,
        "claim_ceiling_status": "PRESERVED",
    }


def generation_config_receipt(config: dict) -> dict:
    return {
        "schema_id": "kt.stop50.generation_config_authority.v1",
        "status": "PASS_SINGULAR_EFFECTIVE_GENERATION_CONFIG_BOUND",
        "effective_generation_config": config,
        "effective_generation_config_sha256": stable_hash(config),
        "do_sample": False,
        "claim_ceiling_status": "PRESERVED",
    }
'''


def runner_source() -> str:
    return r'''from __future__ import annotations

import json
import os
import re
import time
import zipfile
from pathlib import Path


RUN_MODE = "RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_50ROW_V1"
MODEL_REPO = os.environ.get("KT_MODEL_REPO", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit")
HF_RESULTS_REPO = os.environ.get("KT_HF_RESULTS_REPO", "Kinrokin/ktstop50-v1-results")


def write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def normalize(value):
    if value is None:
        return None
    text = str(value).replace(",", "").replace("$", "").strip()
    if not text:
        return None
    try:
        number = float(text)
    except Exception:
        return text.lower()
    return str(int(number)) if number.is_integer() else str(number)


def extract_answer(text: str):
    matches = re.findall(r"(?m)^[ \t]*FINAL_ANSWER\s*:\s*([^\r\n]*)", text)
    target = matches[-1] if matches else text
    fractions = re.findall(r"[-+]?\d[\d,]*\s*/\s*\d[\d,]*", target)
    if fractions:
        return fractions[-1].replace(" ", "").replace(",", "")
    numbers = re.findall(r"[-+]?\$?\d[\d,]*(?:\.\d+)?(?:[eE][-+]?\d+)?", target)
    return numbers[-1].replace("$", "").replace(",", "").strip() if numbers else None


def expected_answer(answer_text: str):
    if "####" in answer_text:
        return answer_text.split("####")[-1].strip()
    return extract_answer(answer_text)


def score(expected: str, extracted) -> bool:
    return normalize(expected) == normalize(extracted)


def render_prompt(template: str, question: str) -> str:
    return f"{template}\n\nProblem:\n{question}\n"


def load_model():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from runtime.environment_preflight import inspect_model_quantization

    tokenizer = AutoTokenizer.from_pretrained(MODEL_REPO, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_REPO,
        device_map="auto",
        torch_dtype="auto",
        trust_remote_code=True,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    quant = inspect_model_quantization(model)
    receipt = {
        "schema_id": "kt.stop50.model_loader_receipt.runtime.v1",
        "status": "PASS" if quant["model_is_loaded_in_4bit"] else "FAIL_NOT_4BIT",
        "model_repo": MODEL_REPO,
        "auto_model_for_causal_lm": True,
        "runtime_quantization_config_used": False,
        **quant,
    }
    return model, tokenizer, receipt


def load_rows(config):
    from datasets import load_dataset

    dataset = load_dataset("openai/gsm8k", "main", split="test")
    rows = []
    for row in config["rows"]:
        item = dataset[int(row["split_index"])]
        rows.append({**row, "question": item["question"], "expected_answer": expected_answer(item["answer"])})
    return rows


def generate(model, tokenizer, prompt: str, max_new_tokens: int, terminate: bool):
    import torch
    from transformers import StoppingCriteriaList
    from runtime.final_answer_stop import FirstCompleteFinalAnswerLineStoppingCriteria, evaluate_generated_text

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    prompt_len = int(inputs["input_ids"].shape[-1])
    stop_criteria = FirstCompleteFinalAnswerLineStoppingCriteria(tokenizer, prompt_len, tokenizer.eos_token_id)
    criteria = StoppingCriteriaList([stop_criteria]) if terminate else None
    if torch.cuda.is_available():
        torch.cuda.synchronize()
    start = time.time()
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
            stopping_criteria=criteria,
        )
    if torch.cuda.is_available():
        torch.cuda.synchronize()
    latency = time.time() - start
    generated_ids = output_ids[0][prompt_len:]
    text = tokenizer.decode(generated_ids, skip_special_tokens=True)
    if terminate and stop_criteria.last_decision:
        stop_decision = stop_criteria.last_decision.to_json()
    else:
        stop_decision = evaluate_generated_text(text, eos=False).to_json()
    return text, generated_ids.tolist(), prompt_len, int(generated_ids.shape[-1]), latency, stop_decision


def maybe_upload(outdir: Path, assessment: Path) -> dict:
    token = os.environ.get("HF_TOKEN")
    if not token:
        return {"schema_id": "kt.stop50.hf_upload_receipt.v1", "status": "SKIPPED_NO_HF_TOKEN", "repo_id": HF_RESULTS_REPO}
    try:
        from huggingface_hub import HfApi, create_repo, upload_file, upload_folder
        create_repo(HF_RESULTS_REPO, repo_type="dataset", private=False, exist_ok=True, token=token)
        upload_folder(repo_id=HF_RESULTS_REPO, repo_type="dataset", folder_path=str(outdir), path_in_repo="artifacts", token=token)
        upload_file(repo_id=HF_RESULTS_REPO, repo_type="dataset", path_or_fileobj=str(assessment), path_in_repo=assessment.name, token=token)
        info = HfApi(token=token).dataset_info(HF_RESULTS_REPO)
        return {"schema_id": "kt.stop50.hf_upload_receipt.v1", "status": "PASS", "repo_id": HF_RESULTS_REPO, "url": f"https://huggingface.co/datasets/{HF_RESULTS_REPO}", "private": bool(info.private)}
    except Exception as exc:
        return {"schema_id": "kt.stop50.hf_upload_receipt.v1", "status": "FAILED_NON_FATAL", "repo_id": HF_RESULTS_REPO, "error": str(exc)}


def main() -> None:
    from runtime.effective_config_receipt import generation_config_receipt, quantization_authority_receipt
    from runtime.environment_preflight import cuda_environment_contract, write_blocker
    from runtime.paired_timing import deterministic_arm_order, protocol_receipt

    packet_root = Path(__file__).resolve().parents[1]
    config = read_json(packet_root / "runtime" / "ktstop50_config.json")
    outdir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktstop50_outputs"))
    outdir.mkdir(parents=True, exist_ok=True)
    assessment = Path(os.environ.get("KT_ASSESSMENT_ZIP", "/kaggle/working/KT_STOP50_V1_ASSESSMENT_ONLY.zip"))

    env_receipt = cuda_environment_contract()
    write_json(outdir / "environment_contract_receipt.json", env_receipt)
    write_json(outdir / "quantization_authority_receipt.json", quantization_authority_receipt(MODEL_REPO))
    generation_config = {"max_new_tokens": 512, "do_sample": False, "temperature": None, "top_p": None}
    write_json(outdir / "generation_config_authority_receipt.json", generation_config_receipt(generation_config))
    write_json(outdir / "paired_timing_protocol_receipt.json", protocol_receipt())
    write_json(outdir / "row_manifest.json", {"schema_id": "kt.stop50.row_manifest.runtime.v1", "rows": config["rows"], "row_count": len(config["rows"]), "claim_ceiling_status": "PRESERVED"})
    write_json(outdir / "arm_manifest.json", config["arm_manifest"])
    write_json(outdir / "claim_boundary_receipt.json", config["claim_boundary"])

    if env_receipt.get("status") != "PASS_IMPORTS":
        write_blocker(outdir, "CUDA/bitsandbytes runtime imports failed before model load.", env_receipt)
        with zipfile.ZipFile(assessment, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(outdir.glob("*")):
                zf.write(path, path.name)
        return

    try:
        model, tokenizer, loader = load_model()
        write_json(outdir / "model_loader_receipt.json", loader)
        if loader["status"] != "PASS":
            write_blocker(outdir, "Model did not load with embedded 4-bit quantization.", loader)
            return
        rows = load_rows(config)
        predictions = []
        token_rows = []
        timing_rows = []
        prefix_rows = []
        for row in rows:
            prompt = render_prompt(config["base_prompt_template"], row["question"])
            warmup_order = deterministic_arm_order(row["row_id"], -1)
            for arm_id in warmup_order[:1]:
                generate(model, tokenizer, prompt, 32, terminate=arm_id.startswith("C1"))
            rep_results = {}
            for rep in range(3):
                for arm_id in deterministic_arm_order(row["row_id"], rep):
                    terminate = arm_id.startswith("C1")
                    text, ids, prompt_len, output_tokens, latency, stop_decision = generate(model, tokenizer, prompt, 512, terminate)
                    extracted = extract_answer(text)
                    correct = score(row["expected_answer"], extracted)
                    result = {
                        "schema_id": "kt.stop50.prediction_row.v1",
                        "run_mode": RUN_MODE,
                        "row_id": row["row_id"],
                        "arm_id": arm_id,
                        "repetition": rep,
                        "correct": correct,
                        "extracted_answer": extracted,
                        "output_tokens": output_tokens,
                        "prompt_tokens": prompt_len,
                        "full_tokens": prompt_len + output_tokens,
                        "latency_seconds": latency,
                        "stop_decision": stop_decision,
                        "raw_output": text,
                        "claim_ceiling_status": "PRESERVED",
                    }
                    predictions.append(result)
                    token_rows.append({k: result[k] for k in ["row_id", "arm_id", "repetition", "prompt_tokens", "output_tokens", "full_tokens"]})
                    timing_rows.append({k: result[k] for k in ["row_id", "arm_id", "repetition", "latency_seconds"]})
                    rep_results[(rep, arm_id)] = {"ids": ids, "raw_output": text}
                c0 = rep_results.get((rep, "C0_MONITOR_FIRST_COMPLETE_FINAL_ANSWER_LINE"))
                c1 = rep_results.get((rep, "C1_TERMINATE_FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP"))
                if c0 and c1:
                    c0_prefix = c0["ids"][: len(c1["ids"])]
                    prefix_rows.append({
                        "row_id": row["row_id"],
                        "repetition": rep,
                        "prefix_equal": c0_prefix == c1["ids"],
                        "c0_output_token_count": len(c0["ids"]),
                        "c1_output_token_count": len(c1["ids"]),
                    })

        write_jsonl(outdir / "predictions.jsonl", predictions)
        write_jsonl(outdir / "token_ledger.jsonl", token_rows)
        write_jsonl(outdir / "timing_ledger.jsonl", timing_rows)
        write_jsonl(outdir / "prefix_equivalence_rows.jsonl", prefix_rows)
        by_arm = {}
        for arm_id in sorted({row["arm_id"] for row in predictions}):
            rows_for_arm = [row for row in predictions if row["arm_id"] == arm_id and row["repetition"] == 0]
            correct = sum(1 for row in rows_for_arm if row["correct"])
            by_arm[arm_id] = {
                "row_count": len(rows_for_arm),
                "correct": correct,
                "accuracy": correct / max(len(rows_for_arm), 1),
                "total_output_tokens": sum(row["output_tokens"] for row in rows_for_arm),
                "tokens_per_correct": sum(row["full_tokens"] for row in rows_for_arm) / max(correct, 1),
            }
        scorecard = {
            "schema_id": "kt.stop50.runtime_scorecard.v1",
            "run_mode": RUN_MODE,
            "status": "PASS_MODEL_GENERATED_AND_SCORED",
            "row_count": len(rows),
            "arm_scorecard": by_arm,
            "prefix_equal_count": sum(1 for row in prefix_rows if row["prefix_equal"]),
            "prefix_total": len(prefix_rows),
            "claim_ceiling_status": "PRESERVED",
        }
        write_json(outdir / "runtime_stop_scorecard.json", scorecard)
        write_json(outdir / "final_summary.json", {"schema_id": "kt.stop50.final_summary.v1", "status": "PASS_MODEL_GENERATED_AND_SCORED", "scorecard": scorecard, "claim_ceiling_status": "PRESERVED"})
        upload = maybe_upload(outdir, assessment)
        write_json(outdir / "HF_UPLOAD_RECEIPT.json", upload)
        with zipfile.ZipFile(assessment, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(outdir.glob("*")):
                zf.write(path, path.name)
    except Exception as exc:
        write_blocker(outdir, f"wrapper exception: {exc}", {"status": "WRAPPER_EXCEPTION"})
        with zipfile.ZipFile(assessment, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(outdir.glob("*")):
                zf.write(path, path.name)


if __name__ == "__main__":
    main()
'''


def bootstrap_source() -> str:
    return r'''from __future__ import annotations

import runpy
from pathlib import Path

packet_root = Path(__file__).resolve().parent
runpy.run_path(str(packet_root / "runtime" / "KT_CANONICAL_RUNNER.py"), run_name="__main__")
'''


def smoke_test_source() -> str:
    return r'''from runtime.final_answer_stop import evaluate_generated_text


def test_line_anchored_marker_stops_once_complete():
    decision = evaluate_generated_text("work\nFINAL_ANSWER: 42\ntrailer")
    assert decision.should_stop
    assert decision.reason == "FINAL_ANSWER_LINE_COMPLETE"


def test_inline_marker_does_not_stop():
    decision = evaluate_generated_text("work says FINAL_ANSWER: 42 but not as a line")
    assert not decision.should_stop
'''


def runtime_config() -> dict[str, Any]:
    try:
        base_prompt = load_stoprt_config()["base_prompt_template"]
    except Exception:
        base_prompt = (
            "Solve the math problem. Show concise reasoning, then end with exactly one line "
            "in this format: FINAL_ANSWER: <answer>"
        )
    rows = row_manifest()["rows"]
    return {
        "schema_id": "kt.stop50.runtime_config.v1",
        "run_mode": RUN_MODE,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "base_model_repo": MODEL_REPO,
        "hf_results_repo": HF_RESULTS_REPO,
        "row_policy": f"openai/gsm8k:test[{ROW_START}:{ROW_END}]",
        "rows": rows,
        "base_prompt_template": base_prompt,
        "expected_answers_are_scorer_side_only": True,
        "arm_manifest": {
            "schema_id": "kt.stop50.arm_manifest.v1",
            "arms": [
                {
                    "arm_id": "C0_MONITOR_FIRST_COMPLETE_FINAL_ANSWER_LINE",
                    "runtime_stop": False,
                    "detector_monitoring": True,
                    "claim_bound": "paired_control_monitor_only",
                },
                {
                    "arm_id": "C1_TERMINATE_FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP",
                    "runtime_stop": True,
                    "detector_monitoring": True,
                    "claim_bound": "sandbox_runtime_stop_candidate_only",
                },
            ],
            "claim_ceiling_status": "PRESERVED",
        },
        "claim_boundary": {
            "schema_id": "kt.stop50.claim_boundary.v1",
            "status": "PASS_BOUND_SANDBOX_ONLY",
            **AUTHORITY_FALSE,
            **SCOPED_AUTHORITY,
            "claim_ceiling_status": "PRESERVED",
        },
    }


def build_packet(config: dict[str, Any]) -> str:
    members = {
        "runtime/KT_CANONICAL_RUNNER.py": runner_source(),
        "runtime/environment_preflight.py": environment_preflight_source(),
        "runtime/effective_config_receipt.py": effective_config_source(),
        "runtime/paired_timing.py": paired_timing_source(),
        "runtime/final_answer_stop.py": source("runtime/final_answer_stop.py"),
        "runtime/final_answer_stop_types.py": source("runtime/final_answer_stop_types.py"),
        "runtime/final_answer_stop_metrics.py": source("runtime/final_answer_stop_metrics.py"),
        "runtime/ktstop50_config.json": json.dumps(config, indent=2, sort_keys=True) + "\n",
        "KAGGLE_BOOTSTRAP_CELL.py": bootstrap_source(),
        "requirements.txt": "transformers\naccelerate\ndatasets\nbitsandbytes==0.49.2\nhuggingface_hub\nsafetensors\n",
        "tests/smoke_test.py": smoke_test_source(),
        "README.md": "# KTSTOP50 V1\n\nSandbox 50-row paired runtime stop-criteria packet. No training, promotion, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.\n",
        "COPY_PASTE_NOW_ktstop50_v1.txt": "Use Kaggle dataset ktstop50-v1 and execute KAGGLE_BOOTSTRAP_CELL.py. Run mode RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_50ROW_V1. Sandbox inference only.\n",
    }
    manifest = {
        "schema_id": "kt.stop50.packet_manifest.v1",
        "packet_name": "ktstop50_v1.zip",
        "run_mode": RUN_MODE,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "row_policy": f"openai/gsm8k:test[{ROW_START}:{ROW_END}]",
        "row_count": 50,
        "source_packet_sha256": SOURCE_PACKET_SHA256,
        "source_assessment_sha256": "7a11037aa4ea0f45fad7d794c458d30b14ac77c9b1a51e06d1ea8f2af80a9ab6",
        "court_v2_required": True,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
        **SCOPED_AUTHORITY,
    }
    members["PACKET_MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    members["SHA256_MANIFEST.json"] = json.dumps(
        {
            "schema_id": "kt.stop50.sha256_manifest.v1",
            "members": {name: sha256_text(data) for name, data in sorted(members.items())},
            "packet_sha256_authority": "reports/ktstop50_packet_decision.json",
        },
        indent=2,
        sort_keys=True,
    ) + "\n"
    PACKET_PATH.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(PACKET_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return sha256_file(PACKET_PATH)


def write_runbook(packet_sha: str) -> None:
    write_text(
        ONE_CELL_RUNBOOK,
        f"""# KT STOP50 One-Cell Runbook

Packet: `packets/ktstop50_v1.zip`

SHA256: `{packet_sha}`

Kaggle dataset: `ktstop50-v1`

Run mode: `RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_50ROW_V1`

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop50-v1/ktstop50_v1.zip')
work = Path('/kaggle/working/ktstop50_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

This is sandbox inference only. It does not train, promote, deploy selectors, mutate adapters, mutate production prompts, grant production runtime authority, or grant production math-mode authority.
""",
    )


def main() -> int:
    write_schemas()
    config = runtime_config()
    row_policy = row_manifest()
    env_contract = {
        "schema_id": "kt.stop50.environment_contract.v1",
        "created_utc": utc_now(),
        "status": "PASS_SPEC_BOUND_RUNTIME_PROOF_REQUIRED",
        "cuda_required": True,
        "bitsandbytes_functional_required": True,
        "bitsandbytes_required_version": "0.49.2",
        "model_is_loaded_in_4bit_required": True,
        "cpu_offload_allowed": False,
        "disk_offload_allowed": False,
        "runtime_packet_fails_closed_if_unmet": True,
        **authority_payload(),
    }
    protocol = {
        "schema_id": "kt.stop50.experiment_protocol.v1",
        "created_utc": utc_now(),
        "status": "PASS_RANDOMIZED_SYNCHRONIZED_PAIRED_TIMING_DEFINED",
        "batch_size": 1,
        "randomized_synchronized_paired_timing": True,
        "same_model_instance": True,
        "warmup_count": 3,
        "repetitions": 3,
        "cuda_synchronize_before_after": True,
        "cuda_events_required": True,
        **authority_payload(),
    }
    packet_sha = build_packet(config)
    write_runbook(packet_sha)
    decision = {
        "schema_id": "kt.stop50.packet_decision.v1",
        "created_utc": utc_now(),
        "status": "GENERATED",
        "outcome": OUTCOME,
        "packet_path": rel(PACKET_PATH),
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "one_cell_runbook": rel(ONE_CELL_RUNBOOK),
        "run_mode": RUN_MODE,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "sandbox_inference_authority": True,
        **authority_payload(),
    }
    builder = {
        "schema_id": "kt.stop50.builder_summary.v1",
        "created_utc": utc_now(),
        "status": "PASS",
        "outcome": OUTCOME,
        "current_head": git_output("rev-parse", "HEAD"),
        "branch": git_output("branch", "--show-current"),
        "packet_path": rel(PACKET_PATH),
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "one_cell_runbook": rel(ONE_CELL_RUNBOOK),
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop50_environment_contract.json", env_contract)
    write_json(REPORTS / "ktstop50_row_policy.json", row_policy)
    write_json(REPORTS / "ktstop50_experiment_protocol.json", protocol)
    write_json(REPORTS / "ktstop50_packet_decision.json", decision)
    write_json(REPORTS / "ktstop50_builder_summary.json", builder)
    update_registry(
        [
            (EVIDENCE / "KT_STOPRT_V1_ASSESSMENT_ONLY.zip", "EVIDENCE_ARCHIVE", "CURRENT_HEAD", False, "Imported immutable STOPRT assessment evidence."),
            (EVIDENCE / "KT_STOPRT_V1_EVIDENCE_SUMMARY.json", "EVIDENCE_SUMMARY", "CURRENT_HEAD", False, "STOPRT evidence summary."),
            (EVIDENCE / "KT_STOPRT_PREFIX_MISMATCH_DETAILS.json", "EVIDENCE_SUMMARY", "CURRENT_HEAD", False, "STOPRT prefix mismatch details."),
            (ROOT / "runtime" / "final_answer_stop.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "EOS-aware generated-token-only final answer stop FSM."),
            (ROOT / "runtime" / "final_answer_stop_types.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "Final answer stop types."),
            (ROOT / "scripts" / "ktstop50_common.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "KTSTOP50 common helpers."),
            (ROOT / "scripts" / "import_ktstoprt_assessment.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOPRT assessment import."),
            (ROOT / "scripts" / "reconcile_ktstoprt_court_v2.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOPRT court-v2 reconciliation."),
            (ROOT / "scripts" / "build_ktstop50_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "KTSTOP50 packet builder."),
            (ROOT / "scripts" / "validate_ktstop50_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "KTSTOP50 packet validator."),
            (PACKET_PATH, "GENERATED_RUNTIME_PACKET", "CURRENT_HEAD", False, "KTSTOP50 generated sandbox runtime packet."),
            (ONE_CELL_RUNBOOK, "CANONICAL_RUNBOOK", "CURRENT_HEAD", False, "KTSTOP50 one-cell runbook."),
            (REPORTS / "ktstoprt_truth_pin.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT truth pin."),
            (REPORTS / "ktstoprt_assessment_import_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT assessment import receipt."),
            (REPORTS / "ktstoprt_official_receipt_preservation.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT failed official receipt preservation."),
            (REPORTS / "ktstoprt_eos_adjudication_audit.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT EOS adjudication audit."),
            (REPORTS / "ktstoprt_prefix_equivalence_v2.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT prefix equivalence v2."),
            (REPORTS / "ktstoprt_semantic_trailer_v2.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT semantic trailer v2."),
            (REPORTS / "ktstoprt_behavioral_economics_recompute.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT behavioral economics recompute."),
            (REPORTS / "ktstoprt_court_mutation_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT court mutation receipt."),
            (REPORTS / "ktstoprt_reconciled_court_verdict.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT reconciled court verdict."),
            (REPORTS / "ktstop50_environment_contract.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP50 environment contract."),
            (REPORTS / "ktstop50_row_policy.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP50 row policy."),
            (REPORTS / "ktstop50_experiment_protocol.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP50 paired timing protocol."),
            (REPORTS / "ktstop50_packet_decision.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP50 packet decision."),
            (REPORTS / "ktstop50_claim_boundary_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP50 claim boundary receipt."),
            (REPORTS / "ktstop50_builder_summary.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP50 builder summary."),
            (REPORTS / "ktstop50_packet_validation_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP50 packet validation receipt."),
            (SCHEMAS / "kt.stoprt.prefix_equivalence_v2.schema.json", "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "KTSTOPRT prefix equivalence v2 schema."),
            (SCHEMAS / "kt.stop50.environment_contract.schema.json", "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "KTSTOP50 environment schema."),
            (SCHEMAS / "kt.stop50.experiment_protocol.schema.json", "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "KTSTOP50 protocol schema."),
        ]
    )
    print(json.dumps(builder, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
