from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from ktstoprt_common import (
    AUTHORITY_FALSE,
    DOCS,
    EVIDENCE,
    KAGGLE_DATASET_NAME,
    NEXT_LAWFUL_MOVE,
    ONE_CELL_RUNBOOK,
    OUTCOME,
    PACKET_PATH,
    REPORTS,
    RUN_MODE,
    SCHEMAS,
    SCOPED_AUTHORITY,
    SOURCE_PACKET_SHA256,
    ROOT,
    authority_payload,
    git_output,
    load_ktstop10_config,
    rel,
    sha256_file,
    sha256_text,
    update_registry,
    utc_now,
    write_json,
    write_text,
)


MODEL_REPO = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
HF_RESULTS_REPO = "Kinrokin/ktstoprt-v1-results"


def runtime_stop_source() -> str:
    return (ROOT / "runtime" / "final_answer_stop.py").read_text(encoding="utf-8")


def runtime_stop_types_source() -> str:
    return (ROOT / "runtime" / "final_answer_stop_types.py").read_text(encoding="utf-8")


def runtime_metrics_source() -> str:
    return (ROOT / "runtime" / "final_answer_stop_metrics.py").read_text(encoding="utf-8")


def canonical_runner_source() -> str:
    return r'''from __future__ import annotations

import hashlib
import json
import os
import re
import time
import zipfile
from pathlib import Path


RUN_MODE = "RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_10ROW_V1"
MODEL_REPO = os.environ.get("KT_MODEL_REPO", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit")
HF_RESULTS_REPO = os.environ.get("KT_HF_RESULTS_REPO", "Kinrokin/ktstoprt-v1-results")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
    matches = re.findall(r"FINAL_ANSWER\s*:\s*([^\r\n]*)", text)
    if matches:
        target = matches[-1]
    else:
        target = text
    fractions = re.findall(r"[-+]?\d[\d,]*\s*/\s*\d[\d,]*", target)
    if fractions:
        return fractions[-1].replace(" ", "").replace(",", "")
    numbers = re.findall(r"[-+]?\$?\d[\d,]*(?:\.\d+)?(?:[eE][-+]?\d+)?", target)
    return numbers[-1].replace("$", "").replace(",", "").strip() if numbers else None


def first_complete_line(text: str):
    marker = "FINAL_ANSWER:"
    start = text.find(marker)
    if start < 0:
        return text
    suffix = text[start:]
    line = re.match(r"[^\r\n]*(?:\r\n|\n|\r)", suffix)
    if not line:
        return text
    return text[: start + line.end()]


def score(expected: str, extracted) -> bool:
    return normalize(expected) == normalize(extracted)


def render_prompt(template: str, question: str) -> str:
    return f"{template}\n\nProblem:\n{question}\n"


def version_tuple(value: str):
    nums = []
    for part in re.split(r"[.+-]", value):
        if part.isdigit():
            nums.append(int(part))
        else:
            break
    return tuple(nums)


def load_model():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    try:
        import bitsandbytes as bnb
    except Exception as exc:
        raise RuntimeError(f"bitsandbytes unavailable: {exc}") from exc
    bnb_version = getattr(bnb, "__version__", "0.0.0")
    if version_tuple(bnb_version) < (0, 46, 1):
        raise RuntimeError(f"bitsandbytes>=0.46.1 required, found {bnb_version}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_REPO, trust_remote_code=True)
    kwargs = {"device_map": "auto", "trust_remote_code": True}
    if os.environ.get("KT_LOAD_IN_4BIT", "1") != "0":
        kwargs["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16)
    model = AutoModelForCausalLM.from_pretrained(MODEL_REPO, **kwargs)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return model, tokenizer, {"schema_id": "kt.ktstoprt.model_loader_receipt.v1", "status": "PASS", "model_repo": MODEL_REPO, "bitsandbytes_version": bnb_version, "quantization_config_used": "quantization_config" in kwargs}


def generate(model, tokenizer, prompt: str, max_new_tokens: int, use_runtime_stop: bool):
    import torch
    from transformers import StoppingCriteriaList
    from runtime.final_answer_stop import FirstCompleteFinalAnswerLineStoppingCriteria, evaluate_generated_text

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    prompt_len = int(inputs["input_ids"].shape[-1])
    criteria = None
    stop_criteria = None
    if use_runtime_stop:
        stop_criteria = FirstCompleteFinalAnswerLineStoppingCriteria(tokenizer, prompt_len, tokenizer.eos_token_id)
        criteria = StoppingCriteriaList([stop_criteria])
    start = time.time()
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
            stopping_criteria=criteria,
        )
    latency = time.time() - start
    generated_ids = output_ids[0][prompt_len:]
    text = tokenizer.decode(generated_ids, skip_special_tokens=True)
    stop_decision = stop_criteria.last_decision.to_json() if stop_criteria and stop_criteria.last_decision else evaluate_generated_text(text, eos=False).to_json()
    return text, generated_ids.tolist(), prompt_len, int(generated_ids.shape[-1]), latency, stop_decision


def write_blocker(outdir: Path, status: str, reason: str) -> None:
    write_json(outdir / "BLOCKER_RECEIPT.json", {
        "schema_id": "kt.ktstoprt.blocker_receipt.runtime.v1",
        "status": status,
        "reason": reason,
        "run_mode": RUN_MODE,
        "claim_ceiling_status": "PRESERVED",
        "training_authority": False,
        "promotion_authority": False,
        "selector_deployment_authority": False,
        "adapter_mutation_authority": False,
        "production_prompt_mutation_authority": False,
        "production_math_mode_claim": False,
    })


def maybe_upload(outdir: Path, assessment: Path) -> dict:
    token = os.environ.get("HF_TOKEN")
    if not token:
        return {"schema_id": "kt.ktstoprt.hf_upload_receipt.v1", "status": "SKIPPED_NO_HF_TOKEN", "repo_id": HF_RESULTS_REPO}
    try:
        from huggingface_hub import HfApi, create_repo, upload_file, upload_folder
        create_repo(HF_RESULTS_REPO, repo_type="dataset", private=False, exist_ok=True, token=token)
        upload_folder(repo_id=HF_RESULTS_REPO, repo_type="dataset", folder_path=str(outdir), path_in_repo="artifacts", token=token)
        upload_file(repo_id=HF_RESULTS_REPO, repo_type="dataset", path_or_fileobj=str(assessment), path_in_repo=assessment.name, token=token)
        info = HfApi(token=token).dataset_info(HF_RESULTS_REPO)
        return {"schema_id": "kt.ktstoprt.hf_upload_receipt.v1", "status": "PASS", "repo_id": HF_RESULTS_REPO, "url": f"https://huggingface.co/datasets/{HF_RESULTS_REPO}", "private": bool(info.private)}
    except Exception as exc:
        return {"schema_id": "kt.ktstoprt.hf_upload_receipt.v1", "status": "FAILED_NON_FATAL", "repo_id": HF_RESULTS_REPO, "error": str(exc)}


def main() -> None:
    packet_root = Path(__file__).resolve().parents[1]
    config = read_json(packet_root / "runtime" / "ktstoprt_config.json")
    outdir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktstoprt_outputs"))
    outdir.mkdir(parents=True, exist_ok=True)
    assessment = Path(os.environ.get("KT_ASSESSMENT_ZIP", "/kaggle/working/KT_STOPRT_V1_ASSESSMENT_ONLY.zip"))
    events = [{"event": "start", "run_mode": RUN_MODE, "row_count": len(config["rows"])}]
    try:
        write_json(outdir / "row_manifest.json", {"schema_id": "kt.ktstoprt.row_manifest.v1", "rows": config["rows"], "row_count": len(config["rows"]), "claim_ceiling_status": "PRESERVED"})
        write_json(outdir / "arm_manifest.json", config["arm_manifest"])
        write_json(outdir / "metric_definition_receipt.json", config["metric_definition_receipt"])
        write_json(outdir / "claim_boundary_receipt.json", config["claim_boundary"])
        model, tokenizer, loader = load_model()
        write_json(outdir / "model_loader_receipt.json", loader)
        predictions = []
        token_rows = []
        stop_rows = []
        prefix_rows = []
        for row in config["rows"]:
            expected = config["scorer_expected_answers"][row["row_id"]]
            prompt = render_prompt(config["base_prompt_template"], row["question"])
            b0_text, b0_ids, b0_prompt_tokens, b0_out_tokens, b0_latency, b0_stop = generate(model, tokenizer, prompt, 512, False)
            b1_text, b1_ids, b1_prompt_tokens, b1_out_tokens, b1_latency, b1_stop = generate(model, tokenizer, prompt, 512, True)
            b0_first = first_complete_line(b0_text)
            b0_prefix_ids = tokenizer(b0_first, add_special_tokens=False)["input_ids"]
            prefix_equal = b0_prefix_ids == b1_ids
            for arm_id, text, ids, prompt_tokens, output_tokens, latency, stop in [
                ("B0_CURRENT_PROMPT_LEGACY_GENERATION", b0_text, b0_ids, b0_prompt_tokens, b0_out_tokens, b0_latency, b0_stop),
                ("B1_CURRENT_PROMPT_FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP", b1_text, b1_ids, b1_prompt_tokens, b1_out_tokens, b1_latency, b1_stop),
            ]:
                extracted = extract_answer(text)
                predictions.append({
                    "schema_id": "kt.ktstoprt.prediction_row.v1",
                    "row_id": row["row_id"],
                    "arm_id": arm_id,
                    "raw_output": text,
                    "raw_output_hash": sha256_text(text),
                    "extracted_answer": extracted,
                    "correct": score(expected, extracted),
                    "output_tokens": output_tokens,
                    "latency_seconds": round(latency, 3),
                    "stop_reason": stop.get("reason"),
                    "claim_ceiling_status": "PRESERVED",
                })
                token_rows.append({"schema_id": "kt.ktstoprt.token_ledger_row.v1", "row_id": row["row_id"], "arm_id": arm_id, "prompt_tokens": prompt_tokens, "output_tokens": output_tokens})
                stop_rows.append({"schema_id": "kt.ktstoprt.stop_reason_row.v1", "row_id": row["row_id"], "arm_id": arm_id, **stop})
            b2_text = first_complete_line(b1_text)
            b2_extracted = extract_answer(b2_text)
            predictions.append({
                "schema_id": "kt.ktstoprt.prediction_row.v1",
                "row_id": row["row_id"],
                "arm_id": "B2_B1_PLUS_CANONICALIZER_V2_REPLAY",
                "raw_output": b2_text,
                "raw_output_hash": sha256_text(b2_text),
                "extracted_answer": b2_extracted,
                "correct": score(expected, b2_extracted),
                "output_tokens": len(tokenizer(b2_text, add_special_tokens=False)["input_ids"]),
                "latency_seconds": 0.0,
                "stop_reason": "OFFLINE_REPLAY",
                "claim_ceiling_status": "PRESERVED",
            })
            prefix_rows.append({
                "schema_id": "kt.ktstoprt.prefix_equivalence_row.v1",
                "row_id": row["row_id"],
                "baseline_prefix_hash": sha256_text(json.dumps(b0_prefix_ids)),
                "runtime_stop_sequence_hash": sha256_text(json.dumps(b1_ids)),
                "prefix_equal": prefix_equal,
                "first_complete_line_token_count": len(b0_prefix_ids),
                "prompt_boundary_token_index": b0_prompt_tokens,
                "stop_token_index": b1_prompt_tokens + len(b1_ids),
            })
        write_jsonl(outdir / "predictions.jsonl", predictions)
        write_jsonl(outdir / "token_ledger.jsonl", token_rows)
        write_jsonl(outdir / "stop_reason_ledger.jsonl", stop_rows)
        b0 = [r for r in predictions if r["arm_id"] == "B0_CURRENT_PROMPT_LEGACY_GENERATION"]
        b1 = [r for r in predictions if r["arm_id"] == "B1_CURRENT_PROMPT_FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP"]
        prefix_pass = sum(1 for row in prefix_rows if row["prefix_equal"])
        b1_trailer_count = sum(1 for r in b1 if r["stop_reason"] not in {"FINAL_ANSWER_LINE_COMPLETE", "EOS"})
        scorecard = {
            "schema_id": "kt.ktstoprt.runtime_stop_scorecard.v1",
            "b0_correct": sum(1 for r in b0 if r["correct"]),
            "b1_correct": sum(1 for r in b1 if r["correct"]),
            "correctness_delta": sum(1 for r in b1 if r["correct"]) - sum(1 for r in b0 if r["correct"]),
            "prefix_equivalence": f"{prefix_pass}/10",
            "semantic_trailer_rate": b1_trailer_count / max(len(b1), 1),
            "b0_total_output_tokens": sum(r["output_tokens"] for r in b0),
            "b1_total_output_tokens": sum(r["output_tokens"] for r in b1),
            "pass_gate": prefix_pass == 10 and sum(1 for r in b1 if r["correct"]) >= sum(1 for r in b0 if r["correct"]) and sum(r["output_tokens"] for r in b1) < sum(r["output_tokens"] for r in b0),
            "claim_ceiling_status": "PRESERVED",
        }
        write_json(outdir / "runtime_stop_scorecard.json", scorecard)
        write_json(outdir / "prefix_equivalence_receipt.json", {"schema_id": "kt.ktstoprt.prefix_equivalence_receipt.v1", "rows": prefix_rows, "prefix_equal_count": prefix_pass, "claim_ceiling_status": "PRESERVED"})
        write_json(outdir / "first_last_final_audit.json", config["first_last_final_audit"])
        write_json(outdir / "final_summary.json", {"schema_id": "kt.ktstoprt.final_summary.v1", "status": "PASS_MODEL_GENERATED_AND_SCORED", "run_mode": RUN_MODE, "row_count": len(config["rows"]), "pass_gate": scorecard["pass_gate"], "claim_ceiling_status": "PRESERVED"})
        events.append({"event": "completed", "pass_gate": scorecard["pass_gate"]})
    except Exception as exc:
        write_blocker(outdir, "KT_STOPRT_RUNTIME_BLOCKED", str(exc))
        events.append({"event": "blocked", "reason": str(exc)})
        assessment = Path(os.environ.get("KT_ASSESSMENT_ZIP", "/kaggle/working/KT_STOPRT_V1_BLOCKER_ASSESSMENT_ONLY.zip"))
    write_jsonl(outdir / "run_events.jsonl", events)
    with zipfile.ZipFile(assessment, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(outdir.iterdir()):
            zf.write(path, path.name)
    upload = maybe_upload(outdir, assessment)
    write_json(outdir / "HF_UPLOAD_RECEIPT.json", upload)
    with zipfile.ZipFile(assessment, "a", zipfile.ZIP_DEFLATED) as zf:
        zf.write(outdir / "HF_UPLOAD_RECEIPT.json", "HF_UPLOAD_RECEIPT.json")
    print(str(assessment))


if __name__ == "__main__":
    main()
'''


def bootstrap_source() -> str:
    return "from pathlib import Path\nimport runpy\nrunpy.run_path(str(Path(__file__).parent / 'runtime' / 'KT_CANONICAL_RUNNER.py'), run_name='__main__')\n"


def smoke_test_source() -> str:
    return """from pathlib import Path
import json
root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / 'PACKET_MANIFEST.json').read_text(encoding='utf-8'))
config = json.loads((root / 'runtime' / 'ktstoprt_config.json').read_text(encoding='utf-8'))
assert manifest['run_mode'] == 'RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_10ROW_V1'
assert manifest['kaggle_dataset_name'] == 'ktstoprt-v1'
assert manifest['training_authority'] is False
assert manifest['production_prompt_mutation_authority'] is False
assert len(config['rows']) == 10
assert {arm['arm_id'] for arm in config['arm_manifest']['generation_arms']} == {'B0_CURRENT_PROMPT_LEGACY_GENERATION', 'B1_CURRENT_PROMPT_FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP'}
assert config['arm_manifest']['offline_derived_arm']['arm_id'] == 'B2_B1_PLUS_CANONICALIZER_V2_REPLAY'
assert all('expected_answer' not in row for row in config['rows'])
"""


def write_schemas() -> None:
    schemas = {
        "kt.stoprt.first_answer_lock_gate.schema.json": ["schema_id", "status", "first_final_wrong_later_corrected"],
        "kt.stoprt.metric_definition_receipt.schema.json": ["schema_id", "status", "corrected_fields_added"],
        "kt.stoprt.runtime_stop_trace.schema.json": ["schema_id", "row_id", "arm_id", "stop_reason"],
        "kt.stoprt.scoped_authority_receipt.schema.json": ["schema_id", "status", "sandbox_inference_authority"],
    }
    for filename, required in schemas.items():
        write_json(
            SCHEMAS / filename,
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "additionalProperties": True,
                "required": required,
                "properties": {field: {} for field in required},
            },
        )


def build_runtime_config() -> dict[str, Any]:
    ktstop10 = load_ktstop10_config()
    first_last = json.loads((REPORTS / "ktstop10_first_last_final_audit.json").read_text(encoding="utf-8"))
    return {
        "schema_id": "kt.ktstoprt.runtime_config.v1",
        "run_mode": RUN_MODE,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "base_model_repo": MODEL_REPO,
        "hf_results_repo": HF_RESULTS_REPO,
        "rows": ktstop10["rows"],
        "scorer_expected_answers": ktstop10["scorer_expected_answers"],
        "expected_answers_are_scorer_side_only": True,
        "base_prompt_template": ktstop10["prompt_arm_manifest"]["arms"][0]["template_text"],
        "arm_manifest": {
            "schema_id": "kt.ktstoprt.arm_manifest.v1",
            "generation_arms": [
                {"arm_id": "B0_CURRENT_PROMPT_LEGACY_GENERATION", "prompt_mutation": False, "runtime_stop": False, "claim_bound": "legacy_current_prompt_control"},
                {"arm_id": "B1_CURRENT_PROMPT_FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP", "prompt_mutation": False, "runtime_stop": True, "claim_bound": "sandbox_runtime_stop_confirmation_only"},
            ],
            "offline_derived_arm": {"arm_id": "B2_B1_PLUS_CANONICALIZER_V2_REPLAY", "model_generation": False, "claim_bound": "offline_replay_only"},
            "claim_ceiling_status": "PRESERVED",
        },
        "metric_definition_receipt": json.loads((REPORTS / "ktstop10_metric_definition_audit.json").read_text(encoding="utf-8")),
        "first_last_final_audit": first_last,
        "claim_boundary": json.loads((REPORTS / "ktstoprt_claim_boundary_receipt.json").read_text(encoding="utf-8")),
    }


def build_packet(config: dict[str, Any]) -> str:
    members = {
        "runtime/KT_CANONICAL_RUNNER.py": canonical_runner_source(),
        "runtime/final_answer_stop.py": runtime_stop_source(),
        "runtime/final_answer_stop_types.py": runtime_stop_types_source(),
        "runtime/final_answer_stop_metrics.py": runtime_metrics_source(),
        "runtime/ktstoprt_config.json": json.dumps(config, indent=2, sort_keys=True) + "\n",
        "KAGGLE_BOOTSTRAP_CELL.py": bootstrap_source(),
        "requirements.txt": "bitsandbytes>=0.46.1\ntransformers\naccelerate\ndatasets\nsafetensors\nhuggingface_hub\n",
        "tests/smoke_test.py": smoke_test_source(),
        "README.md": "# KTSTOPRT V1\n\nSandbox 10-row runtime stop-criteria confirmation packet. It uses the current prompt and compares legacy generation against generated-token-only FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP. No training, promotion, selector deployment, adapter mutation, production prompt mutation, production math-mode claim, or claim expansion.\n",
        "COPY_PASTE_NOW_ktstoprt_v1.txt": "Upload/use Kaggle dataset ktstoprt-v1 and execute KAGGLE_BOOTSTRAP_CELL.py. Run mode RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_10ROW_V1. This is sandbox inference only; no training, promotion, selector deployment, adapter mutation, production prompt mutation, production math-mode claim, or claim expansion.\n",
    }
    manifest = {
        "schema_id": "kt.ktstoprt.packet_manifest.v1",
        "packet_name": "ktstoprt_v1.zip",
        "run_mode": RUN_MODE,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "row_count": 10,
        "generation_arm_count": 2,
        "offline_derived_arm_count": 1,
        "source_packet_sha256": SOURCE_PACKET_SHA256,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
        **SCOPED_AUTHORITY,
    }
    members["PACKET_MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    members["SHA256_MANIFEST.json"] = json.dumps(
        {
            "schema_id": "kt.ktstoprt.sha256_manifest.v1",
            "members": {name: sha256_text(data) for name, data in sorted(members.items())},
            "packet_sha256_authority": "reports/ktstoprt_next_runtime_packet_decision.json",
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
        f"""# KT STOPRT One-Cell Runbook

Packet: `packets/ktstoprt_v1.zip`

SHA256: `{packet_sha}`

Kaggle dataset: `ktstoprt-v1`

Run mode: `RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_10ROW_V1`

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstoprt-v1/ktstoprt_v1.zip')
work = Path('/kaggle/working/ktstoprt_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

This is sandbox inference confirmation only. It does not train, promote, deploy selectors, mutate adapters, mutate production prompts, or grant production math-mode authority.
""",
    )


def main() -> int:
    write_schemas()
    config = build_runtime_config()
    packet_sha = build_packet(config)
    write_runbook(packet_sha)
    spec = {
        "schema_id": "kt.ktstoprt.runtime_stop_criteria_spec.v1",
        "status": "PASS",
        "mechanism": "FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP",
        "generated_tokens_only": True,
        "batch_size": 1,
        "task_class_scope": "NUMERIC_SINGLE_LINE_FINAL",
        "primary_remedy": "DETERMINISTIC_TERMINATION",
        **authority_payload(),
    }
    prefix = {
        "schema_id": "kt.ktstoprt.prefix_equivalence_contract.v1",
        "status": "REQUIRED_AT_RUNTIME",
        "hard_gate": "prefix_equal = true for 10/10",
        "meaning": "runtime stop may only prevent post-answer waste; it must not alter decoding before first complete final-answer line",
        **authority_payload(),
    }
    scoped = {
        "schema_id": "kt.ktstoprt.scoped_authority_receipt.v1",
        "status": "PASS",
        **SCOPED_AUTHORITY,
        **authority_payload(),
    }
    decision = {
        "schema_id": "kt.ktstoprt.next_runtime_packet_decision.v1",
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
    summary = {
        "schema_id": "kt.ktstoprt.builder_summary.v1",
        "status": "PASS",
        "outcome": OUTCOME,
        "current_head": git_output("rev-parse", "HEAD"),
        "branch": git_output("branch", "--show-current"),
        "packet_path": rel(PACKET_PATH),
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "one_cell_runbook": rel(ONE_CELL_RUNBOOK),
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "sandbox_inference_authority": True,
        **authority_payload(),
    }
    write_json(REPORTS / "ktstoprt_runtime_stop_criteria_spec.json", spec)
    write_json(REPORTS / "ktstoprt_prefix_equivalence_contract.json", prefix)
    write_json(REPORTS / "ktstoprt_scoped_authority_receipt.json", scoped)
    write_json(REPORTS / "ktstoprt_next_runtime_packet_decision.json", decision)
    write_json(REPORTS / "ktstoprt_builder_summary.json", summary)
    update_registry(
        [
            (EVIDENCE / "KT_STOP10_V1_ASSESSMENT_ONLY.zip", "EVIDENCE_ARCHIVE", "CURRENT_HEAD", False, "Imported STOP10 assessment evidence."),
            (SCHEMAS / "kt.stoprt.first_answer_lock_gate.schema.json", "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "KTSTOPRT first-answer lock schema."),
            (SCHEMAS / "kt.stoprt.metric_definition_receipt.schema.json", "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "KTSTOPRT metric definition schema."),
            (SCHEMAS / "kt.stoprt.runtime_stop_trace.schema.json", "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "KTSTOPRT runtime stop trace schema."),
            (SCHEMAS / "kt.stoprt.scoped_authority_receipt.schema.json", "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "KTSTOPRT scoped authority schema."),
            (ROOT / "runtime" / "final_answer_stop.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "Generated-token-only final answer stop FSM."),
            (ROOT / "runtime" / "__init__.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "Runtime helper package marker."),
            (ROOT / "runtime" / "final_answer_stop_types.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "Final answer stop types."),
            (ROOT / "runtime" / "final_answer_stop_metrics.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "Final answer stop metric helpers."),
            (ROOT / "scripts" / "ktstoprt_common.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "KTSTOPRT common helpers."),
            (ROOT / "scripts" / "import_ktstop10_assessment.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP10 assessment import."),
            (ROOT / "scripts" / "reconcile_ktstop10_metrics.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP10 metric reconciliation."),
            (ROOT / "scripts" / "audit_first_last_final_answers.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "First-vs-last final answer audit."),
            (ROOT / "scripts" / "replay_first_complete_final_line.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "First-complete-line truncation replay."),
            (ROOT / "scripts" / "build_ktstoprt_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "KTSTOPRT packet builder."),
            (ROOT / "scripts" / "validate_ktstoprt_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "KTSTOPRT packet validator."),
            (ROOT / "tests" / "test_ktstop10_assessment_import.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP10 assessment import test."),
            (ROOT / "tests" / "test_ktstop10_metric_definition.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP10 metric definition test."),
            (ROOT / "tests" / "test_ktstop10_first_answer_lock.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP10 first-answer lock test."),
            (ROOT / "tests" / "test_ktstop10_truncation_replay.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP10 truncation replay test."),
            (ROOT / "tests" / "test_ktstoprt_generated_only_marker.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "Generated-only marker test."),
            (ROOT / "tests" / "test_ktstoprt_token_boundary_marker.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "Token-boundary marker test."),
            (ROOT / "tests" / "test_ktstoprt_answer_line_grammar.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "Answer-line grammar preservation test."),
            (ROOT / "tests" / "test_ktstoprt_prefix_equivalence.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "Prefix equivalence contract test."),
            (ROOT / "tests" / "test_ktstoprt_packet_shape.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "KTSTOPRT packet shape test."),
            (ROOT / "tests" / "test_ktstoprt_claim_ceiling.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "KTSTOPRT claim ceiling test."),
            (PACKET_PATH, "GENERATED_RUNTIME_PACKET", "CURRENT_HEAD", False, "KTSTOPRT generated runtime packet."),
            (ONE_CELL_RUNBOOK, "CANONICAL_RUNBOOK", "CURRENT_HEAD", False, "KTSTOPRT one-cell runbook."),
            (REPORTS / "ktstoprt_truth_pin.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT truth pin."),
            (REPORTS / "ktstoprt_assessment_import_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP10 assessment import receipt."),
            (REPORTS / "ktstoprt_source_binding_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT source binding receipt."),
            (REPORTS / "ktstoprt_live_repo_delta_if_any.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT live repo delta receipt."),
            (REPORTS / "ktstoprt_claim_boundary_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT claim boundary receipt."),
            (REPORTS / "ktstop10_scorecard_reconciliation.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP10 scorecard reconciliation."),
            (REPORTS / "ktstop10_metric_definition_audit.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP10 metric definition audit."),
            (REPORTS / "ktstop10_semantic_trailer_recompute.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP10 semantic trailer recompute."),
            (REPORTS / "ktstop10_row_level_forensics.jsonl", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP10 row-level forensics."),
            (REPORTS / "ktstop10_prompt_instruction_failure_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP10 prompt instruction failure receipt."),
            (REPORTS / "ktstop10_first_last_final_audit.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP10 first-vs-last final audit."),
            (REPORTS / "ktstop10_first_last_final_audit.jsonl", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP10 first-vs-last final audit rows."),
            (REPORTS / "ktstop10_first_answer_lock_gate.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP10 first-answer lock gate."),
            (REPORTS / "ktstop10_first_complete_line_truncation_replay.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP10 first-complete-line truncation replay."),
            (REPORTS / "ktstop10_truncation_savings.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP10 truncation savings receipt."),
            (REPORTS / "ktstop10_truncation_damage_rows.jsonl", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP10 truncation damage rows."),
            (REPORTS / "ktstoprt_runtime_stop_criteria_spec.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT runtime stop criteria spec."),
            (REPORTS / "ktstoprt_prefix_equivalence_contract.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT prefix equivalence contract."),
            (REPORTS / "ktstoprt_scoped_authority_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT scoped authority receipt."),
            (REPORTS / "ktstoprt_next_runtime_packet_decision.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT packet decision."),
            (REPORTS / "ktstoprt_builder_summary.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT builder summary."),
            (REPORTS / "ktstoprt_packet_validation_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOPRT packet validation receipt."),
        ]
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
