from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
PACKETS = ROOT / "packets"
DOCS = ROOT / "docs"
SCHEMAS = ROOT / "schemas"
REGISTRY = ROOT / "registry"

PREDECESSOR_COMMIT = "803057a12b556eec9c8f04106fb60d7ad1850f49"
ACTIVE_TRANCHE = "AUTHOR_MINIMAL_STOPSEQ_10ROW_RUNTIME_PACKET_V1"
OUTCOME = "KT_STOPSEQ_10ROW_RUNTIME_PACKET_READY__LOCAL_RUNTIME_BLOCKER_BOUND__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_STOPSEQ_10ROW_PROMPT_PROBE_V1"
RUN_MODE = "RUN_STOPSEQ_10ROW_PROMPT_PROBE_V1"
PACKET_PATH = PACKETS / "ktstop10_v1.zip"
KAGGLE_DATASET_NAME = "ktstop10-v1"
ONE_CELL_RUNBOOK = DOCS / "KT_STOP10_ONE_CELL.md"
KTCF_PACKET = PACKETS / "ktcf_v1.zip"

BASE_MODEL_REPO = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
HF_RESULTS_REPO = "Kinrokin/ktstop10-v1-results"
STOP_DELTA = (
    "After writing FINAL_ANSWER, stop immediately.\n"
    "Do not add explanation, restatement, confidence text, alternate answer, or any additional text.\n"
    "The output must end with the final answer and nothing else."
)

AUTHORITY_FALSE = {
    "runtime_authority": False,
    "dataset_generation_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "selector_deployment_authority": False,
    "adapter_mutation_authority": False,
    "production_prompt_mutation_authority": False,
    "production_math_mode_claim": False,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_artifact_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if path.suffix.lower() in {".json", ".jsonl", ".md", ".py", ".txt"}:
        data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data


def repo_artifact_stats(path: Path) -> tuple[str, int]:
    data = repo_artifact_bytes(path)
    return sha256_bytes(data), len(data)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_git_json(commit: str, path: str) -> Any:
    raw = subprocess.check_output(["git", "show", f"{commit}:{path}"], cwd=ROOT)
    return json.loads(raw.decode("utf-8-sig"))


def fail(status: str, reason: str, **extra: Any) -> None:
    payload = {
        "schema_id": "kt.ktstop10.blocker_receipt.v1",
        "status": status,
        "reason": reason,
        "created_utc": utc_now(),
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
        **extra,
    }
    write_json(REPORTS / "ktstop10_blocker_receipt.json", payload)
    raise SystemExit(json.dumps(payload, indent=2, sort_keys=True))


def load_ktcf_config() -> dict[str, Any]:
    if not KTCF_PACKET.exists():
        fail(
            "KT_STOPSEQ10_PACKET_BLOCKED__PROMPT_RENDERER_OR_MODEL_CONFIG_MISSING__CLAIM_CEILING_PRESERVED",
            "Missing packets/ktcf_v1.zip for row questions and scorer-side answers.",
        )
    with zipfile.ZipFile(KTCF_PACKET) as zf:
        return json.loads(zf.read("runtime/ktcf_config.json").decode("utf-8-sig"))


def load_and_bind_predecessor() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        git_output("cat-file", "-e", f"{PREDECESSOR_COMMIT}^{{commit}}")
    except subprocess.CalledProcessError as exc:
        fail(
            "KT_STOPSEQ10_PACKET_BLOCKED__LAB_BRANCH_OR_ROW_SELECTION_MISSING__CLAIM_CEILING_PRESERVED",
            "Lab blocker commit is not present in this repository.",
            predecessor_commit=PREDECESSOR_COMMIT,
        )
        raise exc

    lab_summary = read_git_json(PREDECESSOR_COMMIT, "reports/ktstop_lab_summary.json")
    lab_selection = read_git_json(PREDECESSOR_COMMIT, "reports/ktstop_10row_selection.json")
    lab_blocker = read_git_json(PREDECESSOR_COMMIT, "reports/stop_after_final_answer_probe_blocker.json")
    current_selection_path = REPORTS / "ktstop_10row_selection.json"
    if not current_selection_path.exists():
        fail(
            "KT_STOPSEQ10_PACKET_BLOCKED__LAB_BRANCH_OR_ROW_SELECTION_MISSING__CLAIM_CEILING_PRESERVED",
            "Current branch does not contain reports/ktstop_10row_selection.json.",
            predecessor_commit=PREDECESSOR_COMMIT,
        )
    current_selection = read_json(current_selection_path)
    lab_signature = [(row["row_id"], row["source_class"], row["question_hash"], row["expected_answer_hash"]) for row in lab_selection["rows"]]
    current_signature = [(row["row_id"], row["source_class"], row["question_hash"], row["expected_answer_hash"]) for row in current_selection["rows"]]
    if lab_signature != current_signature:
        fail(
            "KT_STOPSEQ10_PACKET_BLOCKED__LAB_BRANCH_OR_ROW_SELECTION_MISSING__CLAIM_CEILING_PRESERVED",
            "Current row selection does not exactly match the lab commit selection.",
            predecessor_commit=PREDECESSOR_COMMIT,
        )
    return lab_summary, lab_selection, lab_blocker


def write_schemas() -> None:
    schema_specs = {
        "kt.ktstop10.row_manifest.schema.json": ["schema_id", "rows", "row_count", "claim_ceiling_status"],
        "kt.ktstop10.prompt_arm_manifest.schema.json": ["schema_id", "arms", "claim_ceiling_status"],
        "kt.ktstop10.scorecard.schema.json": ["schema_id", "run_mode", "pass_gate", "claim_ceiling_status"],
        "kt.ktstop10.packet_decision.schema.json": ["schema_id", "status", "packet_path", "packet_sha256", "next_lawful_move"],
    }
    for filename, required in schema_specs.items():
        write_json(
            SCHEMAS / filename,
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "additionalProperties": True,
                "required": required,
                "properties": {key: {} for key in required},
            },
        )


def prompt_templates_from_config(config: dict[str, Any]) -> dict[str, str]:
    templates = config.get("prompt_templates", {})
    if not templates:
        prompt_cfg = read_json(ROOT / "configs" / "ktcf_prompt_templates.json")
        templates = {row["template_id"]: row["template_text"] for row in prompt_cfg["templates"]}
    if "BASELINE_COT" not in templates:
        fail(
            "KT_STOPSEQ10_PACKET_BLOCKED__PROMPT_RENDERER_OR_MODEL_CONFIG_MISSING__CLAIM_CEILING_PRESERVED",
            "BASELINE_COT prompt template is unavailable.",
        )
    return dict(templates)


def build_runtime_rows(selection: dict[str, Any], ktcf_config: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    ktcf_rows = {row["row_id"]: row for row in ktcf_config["rows"]}
    scorer_answers = dict(ktcf_config["scorer_expected_answers"])
    runtime_rows = []
    scorer_subset = {}
    for selected in selection["rows"]:
        row_id = selected["row_id"]
        if row_id not in ktcf_rows:
            fail(
                "KT_STOPSEQ10_PACKET_BLOCKED__LAB_BRANCH_OR_ROW_SELECTION_MISSING__CLAIM_CEILING_PRESERVED",
                f"Selected row {row_id} is missing from KTCF runtime config.",
            )
        if row_id not in scorer_answers:
            fail(
                "KT_STOPSEQ10_PACKET_BLOCKED__PROMPT_RENDERER_OR_MODEL_CONFIG_MISSING__CLAIM_CEILING_PRESERVED",
                f"Selected row {row_id} is missing scorer-side answer.",
            )
        source = ktcf_rows[row_id]
        runtime_rows.append(
            {
                "schema_id": "kt.ktstop10.row.v1",
                "row_id": row_id,
                "row_bucket": selected["source_class"],
                "role": selected["role"],
                "control_flag": selected["control_flag"],
                "question": source["question"],
                "question_hash": selected["question_hash"],
                "expected_answer_hash": selected["expected_answer_hash"],
                "selection_reason": selected["selection_reason"],
                "source_artifact": "reports/ktstop_10row_selection.json",
                "gold_prompt_leakage_free": True,
            }
        )
        scorer_subset[row_id] = scorer_answers[row_id]
    return runtime_rows, scorer_subset


def prompt_arm_manifest(base_template: str) -> dict[str, Any]:
    arms = [
        {
            "arm_id": "A0_CURRENT_PROMPT",
            "template_id": "BASELINE_COT",
            "template_text": base_template,
            "template_sha256": sha256_text(base_template),
            "max_new_tokens": 512,
            "do_sample": False,
            "temperature": None,
            "claim_bound": "baseline_current_prompt_diagnostic_only",
        },
        {
            "arm_id": "A1_STOP_AFTER_FINAL_ANSWER",
            "template_id": "BASELINE_COT_STOP_AFTER_FINAL_ANSWER",
            "template_text": f"{base_template}\n{STOP_DELTA}",
            "template_sha256": sha256_text(f"{base_template}\n{STOP_DELTA}"),
            "max_new_tokens": 512,
            "do_sample": False,
            "temperature": None,
            "claim_bound": "stop_sequence_prompt_delta_diagnostic_only_not_production_prompt_mutation",
        },
    ]
    return {
        "schema_id": "kt.ktstop10.prompt_arm_manifest.v1",
        "status": "PASS",
        "run_mode": RUN_MODE,
        "arms": arms,
        "generation_config": {
            "do_sample": False,
            "temperature": None,
            "max_new_tokens": 512,
            "seed": "fixed_if_runtime_supports_it",
        },
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }


def leakage_receipt(rows: list[dict[str, Any]], arms: list[dict[str, Any]]) -> dict[str, Any]:
    forbidden_terms = ["expected_answer", "expected_answer_hash", "row_id", "source_class", "prior_correctness", "measured_correctness"]
    prompt_texts = "\n".join(arm["template_text"] for arm in arms)
    violations = [term for term in forbidden_terms if term in prompt_texts]
    row_violations = [row["row_id"] for row in rows if "expected_answer" in row]
    status = "PASS" if not violations and not row_violations else "FAIL"
    receipt = {
        "schema_id": "kt.ktstop10.gold_prompt_leakage_firewall.v1",
        "status": status,
        "forbidden_terms_checked": forbidden_terms,
        "prompt_template_violations": violations,
        "row_expected_answer_field_violations": row_violations,
        "expected_answers_scorer_side_only": True,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    if status != "PASS":
        write_json(REPORTS / "ktstop10_gold_prompt_leakage_firewall.json", receipt)
        fail(
            "KT_STOPSEQ10_PACKET_BLOCKED__GOLD_PROMPT_LEAKAGE_RISK__CLAIM_CEILING_PRESERVED",
            "Gold prompt leakage firewall failed.",
            leakage_receipt=receipt,
        )
    return receipt


def runtime_runner_source() -> str:
    return r'''from __future__ import annotations

import hashlib
import json
import os
import re
import time
import zipfile
from pathlib import Path


RUN_MODE = "RUN_STOPSEQ_10ROW_PROMPT_PROBE_V1"
MODEL_REPO = os.environ.get("KT_MODEL_REPO", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit")
HF_RESULTS_REPO = os.environ.get("KT_HF_RESULTS_REPO", "Kinrokin/ktstop10-v1-results")


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
    patterns = [
        r"FINAL_ANSWER\s*:\s*([-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?)",
        r"####\s*([-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?)",
        r"final answer\s*(?:is|:)?\s*([-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?)",
        r"answer\s*(?:is|:)?\s*([-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(1).replace("$", "").replace(",", "").strip()
    numbers = re.findall(r"[-+]?\$?[\d,]+(?:\.\d+)?", text)
    return numbers[-1].replace("$", "").replace(",", "").strip() if numbers else None


def final_marker_span(text: str):
    return re.search(r"FINAL_ANSWER\s*:\s*[-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?", text, re.I)


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
    use_4bit = os.environ.get("KT_LOAD_IN_4BIT", "1") != "0"
    kwargs = {"device_map": "auto", "trust_remote_code": True}
    if use_4bit:
        kwargs["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16)
    model = AutoModelForCausalLM.from_pretrained(MODEL_REPO, **kwargs)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return model, tokenizer, {"schema_id": "kt.ktstop10.model_loader_receipt.v1", "status": "PASS", "model_repo": MODEL_REPO, "bitsandbytes_version": bnb_version, "load_in_4bit_via_quantization_config": use_4bit}


def generate(model, tokenizer, prompt: str, max_new_tokens: int):
    import torch
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    start = time.time()
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    latency_seconds = time.time() - start
    generated = output_ids[0][inputs["input_ids"].shape[-1]:]
    text = tokenizer.decode(generated, skip_special_tokens=True)
    return text, int(inputs["input_ids"].shape[-1]), int(generated.shape[-1]), latency_seconds


def score(expected: str, extracted: str | None) -> bool:
    return normalize(expected) == normalize(extracted)


def write_blocker(outdir: Path, status: str, reason: str) -> None:
    payload = {
        "schema_id": "kt.ktstop10.blocker_receipt.runtime.v1",
        "status": status,
        "reason": reason,
        "run_mode": RUN_MODE,
        "training_authority": False,
        "promotion_authority": False,
        "selector_deployment_authority": False,
        "adapter_mutation_authority": False,
        "production_prompt_mutation_authority": False,
        "production_math_mode_claim": False,
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(outdir / "BLOCKER_RECEIPT.json", payload)


def maybe_upload_to_hf(outdir: Path, assessment_zip: Path) -> dict:
    token = os.environ.get("HF_TOKEN")
    if not token:
        return {"schema_id": "kt.ktstop10.hf_upload_receipt.v1", "status": "SKIPPED_NO_HF_TOKEN", "repo_id": HF_RESULTS_REPO}
    try:
        from huggingface_hub import HfApi, create_repo, upload_file, upload_folder
        create_repo(HF_RESULTS_REPO, repo_type="dataset", private=False, exist_ok=True, token=token)
        upload_folder(repo_id=HF_RESULTS_REPO, repo_type="dataset", folder_path=str(outdir), path_in_repo="artifacts", token=token)
        upload_file(repo_id=HF_RESULTS_REPO, repo_type="dataset", path_or_fileobj=str(assessment_zip), path_in_repo=assessment_zip.name, token=token)
        info = HfApi(token=token).dataset_info(HF_RESULTS_REPO)
        return {"schema_id": "kt.ktstop10.hf_upload_receipt.v1", "status": "PASS", "repo_id": HF_RESULTS_REPO, "url": f"https://huggingface.co/datasets/{HF_RESULTS_REPO}", "private": bool(info.private)}
    except Exception as exc:
        return {"schema_id": "kt.ktstop10.hf_upload_receipt.v1", "status": "FAILED_NON_FATAL", "repo_id": HF_RESULTS_REPO, "error": str(exc)}


def main() -> None:
    packet_root = Path(__file__).resolve().parents[1]
    config = read_json(packet_root / "runtime" / "ktstop10_config.json")
    outdir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktstop10_outputs"))
    outdir.mkdir(parents=True, exist_ok=True)
    events = [{"event": "start", "run_mode": RUN_MODE, "row_count": len(config["rows"])}]
    assessment = Path(os.environ.get("KT_ASSESSMENT_ZIP", "/kaggle/working/KT_STOP10_V1_ASSESSMENT_ONLY.zip"))
    try:
        write_json(outdir / "PACKET_MANIFEST_RUN.json", {"schema_id": "kt.ktstop10.packet_manifest_run.v1", "run_mode": RUN_MODE, "packet_manifest": config["packet_manifest"], "claim_ceiling_status": "PRESERVED"})
        write_json(outdir / "row_manifest.json", {"schema_id": "kt.ktstop10.runtime_row_manifest.v1", "rows": config["rows"], "row_count": len(config["rows"]), "claim_ceiling_status": "PRESERVED"})
        write_json(outdir / "prompt_arm_manifest.json", config["prompt_arm_manifest"])
        write_json(outdir / "claim_boundary_receipt.json", config["claim_boundary"])
        model, tokenizer, loader_receipt = load_model()
        write_json(outdir / "model_loader_receipt.json", loader_receipt)
        predictions = []
        token_rows = []
        baseline_correct_by_row = {}
        for row in config["rows"]:
            expected = config["scorer_expected_answers"][row["row_id"]]
            for arm in config["prompt_arm_manifest"]["arms"]:
                prompt = render_prompt(arm["template_text"], row["question"])
                # Gold fields are not rendered. Native answer literals inside a question are not treated as leakage.
                output, prompt_tokens, output_tokens, latency_seconds = generate(model, tokenizer, prompt, int(arm["max_new_tokens"]))
                extracted = extract_answer(output)
                correct = score(expected, extracted)
                if arm["arm_id"] == "A0_CURRENT_PROMPT":
                    baseline_correct_by_row[row["row_id"]] = correct
                marker = final_marker_span(output)
                trailer = output[marker.end():].strip() if marker else ""
                record = {
                    "schema_id": "kt.ktstop10.prediction_row.v1",
                    "row_id": row["row_id"],
                    "row_bucket": row["row_bucket"],
                    "source_artifact": row["source_artifact"],
                    "question_hash": row["question_hash"],
                    "rendered_prompt_hash": sha256_text(prompt),
                    "arm_id": arm["arm_id"],
                    "output_hash": sha256_text(output),
                    "raw_output": output,
                    "extracted_answer": extracted,
                    "correct": correct,
                    "extraction_success": extracted is not None,
                    "final_answer_marker_present": marker is not None,
                    "trailer_present": bool(trailer),
                    "tokens_after_final_answer": len(tokenizer(trailer, return_tensors="pt")["input_ids"][0]) if trailer else 0,
                    "chars_after_final_answer": len(trailer),
                    "post_final_marker_text_hash": sha256_text(trailer) if trailer else None,
                    "control_damage": False,
                    "prompt_tokens_if_available": prompt_tokens,
                    "output_tokens_if_available": output_tokens,
                    "latency_seconds": round(latency_seconds, 3),
                    "claim_ceiling_status": "PRESERVED",
                }
                if arm["arm_id"] == "A1_STOP_AFTER_FINAL_ANSWER" and row["control_flag"]:
                    record["control_damage"] = bool(baseline_correct_by_row.get(row["row_id"]) and not correct)
                predictions.append(record)
                token_rows.append({"schema_id": "kt.ktstop10.token_ledger_row.v1", "row_id": row["row_id"], "arm_id": arm["arm_id"], "prompt_tokens": prompt_tokens, "output_tokens": output_tokens, "tokens_after_final_answer": record["tokens_after_final_answer"]})
        write_jsonl(outdir / "predictions.jsonl", predictions)
        write_jsonl(outdir / "token_ledger.jsonl", token_rows)
        a0 = [row for row in predictions if row["arm_id"] == "A0_CURRENT_PROMPT"]
        a1 = [row for row in predictions if row["arm_id"] == "A1_STOP_AFTER_FINAL_ANSWER"]
        a0_trailer = sum(1 for row in a0 if row["trailer_present"]) / max(len(a0), 1)
        a1_trailer = sum(1 for row in a1 if row["trailer_present"]) / max(len(a1), 1)
        a0_correct = sum(1 for row in a0 if row["correct"])
        a1_correct = sum(1 for row in a1 if row["correct"])
        control_damage_count = sum(1 for row in a1 if row["control_damage"])
        pass_gate = ((a1_trailer <= 0.20 or (a1_trailer - a0_trailer) <= -0.50) and control_damage_count == 0 and a1_correct >= a0_correct)
        scorecard = {
            "schema_id": "kt.ktstop10.scorecard.v1",
            "run_mode": RUN_MODE,
            "a0_trailer_rate": round(a0_trailer, 4),
            "a1_trailer_rate": round(a1_trailer, 4),
            "trailer_rate_delta": round(a1_trailer - a0_trailer, 4),
            "a0_correct": a0_correct,
            "a1_correct": a1_correct,
            "correctness_delta": a1_correct - a0_correct,
            "control_damage_count": control_damage_count,
            "extraction_success_delta": sum(1 for row in a1 if row["extraction_success"]) - sum(1 for row in a0 if row["extraction_success"]),
            "a0_tokens_after_final_answer_total": sum(row["tokens_after_final_answer"] for row in a0),
            "a1_tokens_after_final_answer_total": sum(row["tokens_after_final_answer"] for row in a1),
            "pass_gate": pass_gate,
            "next_lane_suggestion": "RUN_40ROW_KTCF_STOPSEQ_CONFIRMATION_OR_FORGE_IF_NO_LOCAL_RUNTIME" if pass_gate else "AUTHOR_KTCFFIX_CANONICALIZER_V2_CONFIRMATION_PACKET_V1",
            "claim_ceiling_status": "PRESERVED",
        }
        final_summary = {
            "schema_id": "kt.ktstop10.final_summary.v1",
            "status": "PASS_MODEL_GENERATED_AND_SCORED",
            "run_mode": RUN_MODE,
            "row_count": len(config["rows"]),
            "arm_count": len(config["prompt_arm_manifest"]["arms"]),
            "prediction_count": len(predictions),
            "pass_gate": pass_gate,
            "claim_ceiling_status": "PRESERVED",
        }
        write_json(outdir / "stopseq_scorecard.json", scorecard)
        write_json(outdir / "final_summary.json", final_summary)
        events.append({"event": "completed", "status": final_summary["status"], "pass_gate": pass_gate})
    except Exception as exc:
        write_blocker(outdir, "KT_STOP10_RUNTIME_BLOCKED", str(exc))
        write_json(outdir / "model_loader_receipt.json", {"schema_id": "kt.ktstop10.model_loader_receipt.v1", "status": "BLOCKED", "reason": str(exc), "model_repo": MODEL_REPO})
        events.append({"event": "blocked", "reason": str(exc)})
        assessment = Path(os.environ.get("KT_ASSESSMENT_ZIP", "/kaggle/working/KT_STOP10_V1_BLOCKER_ASSESSMENT_ONLY.zip"))
    write_jsonl(outdir / "run_events.jsonl", events)
    with zipfile.ZipFile(assessment, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(outdir.iterdir()):
            zf.write(path, path.name)
    upload_receipt = maybe_upload_to_hf(outdir, assessment)
    write_json(outdir / "HF_UPLOAD_RECEIPT.json", upload_receipt)
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
config = json.loads((root / 'runtime' / 'ktstop10_config.json').read_text(encoding='utf-8'))
assert manifest['run_mode'] == 'RUN_STOPSEQ_10ROW_PROMPT_PROBE_V1'
assert manifest['kaggle_dataset_name'] == 'ktstop10-v1'
assert manifest['training_authority'] is False
assert manifest['production_prompt_mutation_authority'] is False
assert len(config['rows']) == 10
assert {arm['arm_id'] for arm in config['prompt_arm_manifest']['arms']} == {'A0_CURRENT_PROMPT', 'A1_STOP_AFTER_FINAL_ANSWER'}
assert all('expected_answer' not in row for row in config['rows'])
"""


def build_packet(runtime_config: dict[str, Any]) -> str:
    members: dict[str, str] = {
        "runtime/KT_CANONICAL_RUNNER.py": runtime_runner_source(),
        "runtime/ktstop10_config.json": json.dumps(runtime_config, indent=2, sort_keys=True) + "\n",
        "KAGGLE_BOOTSTRAP_CELL.py": bootstrap_source(),
        "COPY_PASTE_NOW_ktstop10_v1.txt": (
            "Upload/use Kaggle dataset ktstop10-v1 and execute KAGGLE_BOOTSTRAP_CELL.py. "
            "This is a 10-row STOP_AFTER_FINAL_ANSWER prompt probe only: no training, promotion, selector deployment, adapter mutation, production prompt mutation, production math-mode claim, or claim expansion.\n"
        ),
        "README.md": (
            "# KTSTOP10 V1\n\n"
            "Minimal 10-row stop-after-final-answer prompt probe packet. It compares A0 current prompt against A1 stop-boundary prompt on the exact lab-selected rows. It does not train, promote, deploy selectors, mutate adapters, mutate production prompts, or claim production math-mode authority.\n"
        ),
        "requirements.txt": "bitsandbytes>=0.46.1\ntransformers\naccelerate\ndatasets\nsafetensors\nhuggingface_hub\n",
        "tests/smoke_test.py": smoke_test_source(),
    }
    manifest = {
        "schema_id": "kt.ktstop10.packet_manifest.v1",
        "packet_name": "ktstop10_v1.zip",
        "run_mode": RUN_MODE,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "row_count": 10,
        "arm_count": 2,
        "source_predecessor_commit": PREDECESSOR_COMMIT,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    members["PACKET_MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    sha_manifest = {
        "schema_id": "kt.ktstop10.sha256_manifest.v1",
        "members": {name: sha256_text(data) for name, data in sorted(members.items())},
        "packet_sha256_authority": "reports/ktstop10_runtime_packet_decision.json",
    }
    members["SHA256_MANIFEST.json"] = json.dumps(sha_manifest, indent=2, sort_keys=True) + "\n"
    PACKETS.mkdir(exist_ok=True)
    with zipfile.ZipFile(PACKET_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(members.items()):
            zf.writestr(name, data)
    return sha256_file(PACKET_PATH)


def write_runbook(packet_sha: str) -> None:
    write_text(
        ONE_CELL_RUNBOOK,
        f"""# KT STOP10 One-Cell Runbook

Packet: `packets/ktstop10_v1.zip`

SHA256: `{packet_sha}`

Kaggle dataset: `ktstop10-v1`

Run mode: `RUN_STOPSEQ_10ROW_PROMPT_PROBE_V1`

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop10-v1/ktstop10_v1.zip')
work = Path('/kaggle/working/ktstop10_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

This is a 10-row diagnostic prompt probe only. It does not train, promote, deploy selectors, mutate adapters, mutate production prompts, or grant production math-mode authority.
""",
    )


def artifact_id(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", path).strip("_").upper()


def registry_entry(path: Path, primary_class: str, claim_authority: str, controls_execution: bool, notes: str) -> dict[str, Any]:
    rel = path.relative_to(ROOT).as_posix()
    sha, size = repo_artifact_stats(path)
    return {
        "artifact_id": artifact_id(rel),
        "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
        "claim_authority": claim_authority,
        "controls_execution": controls_execution,
        "current_authority": True,
        "notes": notes,
        "path": rel,
        "primary_class": primary_class,
        "role": "ktstop10_minimal_runtime_packet_forge",
        "sha256": sha,
        "size_bytes": size,
        "source_lane": ACTIVE_TRANCHE,
        "superseded_by": None,
        "supersedes": [],
        "updated_utc": utc_now(),
        "validation_status": "PASS",
    }


def update_registry(paths: list[tuple[Path, str, str, bool, str]]) -> None:
    registry_path = REGISTRY / "artifact_authority_registry.json"
    registry = read_json(registry_path)
    entries = [registry_entry(*spec) for spec in paths]
    delta_path = REGISTRY / "artifact_authority_registry_ktstop10_delta_receipt.json"
    delta = {
        "schema_id": "kt.artifact_authority_registry.ktstop10_delta_receipt.v1",
        "created_utc": utc_now(),
        "source_lane": ACTIVE_TRANCHE,
        "status": "PASS",
        "claim_ceiling_status": "PRESERVED",
        "entries_added_or_updated": entries,
        "notes": "KTSTOP10 packet forge delta receipt. No Kaggle run, training, promotion, selector deployment, adapter mutation, production prompt mutation, production math-mode, commercial, external, S-tier, or frontier authority.",
    }
    write_json(delta_path, delta)
    delta_entry = registry_entry(
        delta_path,
        "CANONICAL_RECEIPT_CURRENT",
        "CURRENT_HEAD",
        False,
        "KTSTOP10 artifact authority delta receipt.",
    )
    entries.append(delta_entry)
    delta["entries_added_or_updated"] = entries
    write_json(delta_path, delta)
    by_path = {artifact["path"]: artifact for artifact in registry["artifacts"]}
    for entry in entries:
        by_path[entry["path"]] = entry
    registry["artifacts"] = list(by_path.values())
    registry["artifact_count"] = len(registry["artifacts"])
    registry["current_head"] = git_output("rev-parse", "HEAD")
    registry["updated_utc"] = utc_now()
    write_json(registry_path, registry)


def main() -> int:
    REPORTS.mkdir(exist_ok=True)
    write_schemas()
    lab_summary, lab_selection, lab_blocker = load_and_bind_predecessor()
    ktcf_config = load_ktcf_config()
    templates = prompt_templates_from_config(ktcf_config)
    rows, scorer_answers = build_runtime_rows(lab_selection, ktcf_config)
    arm_manifest = prompt_arm_manifest(templates["BASELINE_COT"])
    leakage = leakage_receipt(rows, arm_manifest["arms"])

    truth = {
        "schema_id": "kt.ktstop10.truth_pin.v1",
        "created_utc": utc_now(),
        "current_head": git_output("rev-parse", "HEAD"),
        "current_branch": git_output("branch", "--show-current"),
        "worktree_porcelain": git_output("status", "--porcelain=v1"),
        "predecessor_commit": PREDECESSOR_COMMIT,
        "live_repo_truth_wins": True,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    predecessor_receipt = {
        "schema_id": "kt.ktstop10.predecessor_binding_receipt.v1",
        "status": "PASS",
        "predecessor_commit": PREDECESSOR_COMMIT,
        "predecessor_outcome": lab_summary["outcome"],
        "predecessor_probe_execution_status": lab_summary["ktstop_probe_execution_status"],
        "predecessor_prompt_delta_status": lab_summary["ktstop_prompt_delta_status"],
        "predecessor_blocker_status": lab_blocker["status"],
        "next_lawful_move_bound": lab_summary["next_lawful_move"],
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    row_binding = {
        "schema_id": "kt.ktstop10.row_selection_binding.v1",
        "status": "PASS_EXACT_10_ROWS",
        "predecessor_commit": PREDECESSOR_COMMIT,
        "row_count": len(rows),
        "bucket_counts": lab_selection["bucket_counts"],
        "rows": lab_selection["rows"],
        "question_hashes_bound": [row["question_hash"] for row in rows],
        "expected_answer_hashes_bound": [row["expected_answer_hash"] for row in rows],
        "gold_prompt_leakage_free": True,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    claim_boundary = {
        "schema_id": "kt.ktstop10.claim_boundary_receipt.v1",
        "status": "PASS",
        "allowed_claim": "KTSTOP10 runtime packet was forged from the exact lab-selected 10 rows to test STOP_AFTER_FINAL_ANSWER prompt behavior. No Kaggle run has been executed in this repo lane.",
        "claim_ceiling_status": "PRESERVED",
        "packet_sha256_if_known": None,
        **AUTHORITY_FALSE,
    }
    runtime_config = {
        "schema_id": "kt.ktstop10.runtime_config.v1",
        "run_mode": RUN_MODE,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "base_model_repo": BASE_MODEL_REPO,
        "hf_results_repo": HF_RESULTS_REPO,
        "rows": rows,
        "scorer_expected_answers": scorer_answers,
        "expected_answers_are_scorer_side_only": True,
        "prompt_arm_manifest": arm_manifest,
        "claim_boundary": claim_boundary,
        "packet_manifest": {
            "packet_name": "ktstop10_v1.zip",
            "source_predecessor_commit": PREDECESSOR_COMMIT,
            "claim_ceiling_status": "PRESERVED",
            **AUTHORITY_FALSE,
        },
    }

    # The final packet SHA cannot be embedded inside the packet without changing
    # the packet. Bind the final SHA in repo-side receipts after the zip closes.
    packet_sha = build_packet(runtime_config)
    claim_boundary["packet_sha256_if_known"] = packet_sha
    write_runbook(packet_sha)

    decision = {
        "schema_id": "kt.ktstop10.packet_decision.v1",
        "status": "GENERATED",
        "outcome": OUTCOME,
        "packet_path": rel(PACKET_PATH),
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "one_cell_runbook": rel(ONE_CELL_RUNBOOK),
        "run_mode": RUN_MODE,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    summary = {
        "schema_id": "kt.ktstop10.builder_summary.v1",
        "status": "PASS",
        "outcome": OUTCOME,
        "current_head": truth["current_head"],
        "branch": truth["current_branch"],
        "packet_path": rel(PACKET_PATH),
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "one_cell_runbook": rel(ONE_CELL_RUNBOOK),
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }

    write_json(REPORTS / "ktstop10_truth_pin.json", truth)
    write_json(REPORTS / "ktstop10_predecessor_binding_receipt.json", predecessor_receipt)
    write_json(REPORTS / "ktstop10_row_selection_binding.json", row_binding)
    write_json(REPORTS / "ktstop10_prompt_arm_manifest.json", arm_manifest)
    write_json(REPORTS / "ktstop10_gold_prompt_leakage_firewall.json", leakage)
    write_json(REPORTS / "ktstop10_claim_boundary_receipt.json", claim_boundary)
    write_json(REPORTS / "ktstop10_runtime_packet_decision.json", decision)
    write_json(REPORTS / "ktstop10_builder_summary.json", summary)

    update_registry(
        [
            (SCHEMAS / "kt.ktstop10.row_manifest.schema.json", "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "KTSTOP10 row manifest schema."),
            (SCHEMAS / "kt.ktstop10.prompt_arm_manifest.schema.json", "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "KTSTOP10 prompt arm manifest schema."),
            (SCHEMAS / "kt.ktstop10.scorecard.schema.json", "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "KTSTOP10 scorecard schema."),
            (SCHEMAS / "kt.ktstop10.packet_decision.schema.json", "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "KTSTOP10 packet decision schema."),
            (REPORTS / "ktstop10_truth_pin.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP10 truth pin receipt."),
            (REPORTS / "ktstop10_predecessor_binding_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP10 predecessor binding receipt."),
            (REPORTS / "ktstop10_row_selection_binding.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP10 row selection binding receipt."),
            (REPORTS / "ktstop10_prompt_arm_manifest.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP10 prompt arm manifest receipt."),
            (REPORTS / "ktstop10_gold_prompt_leakage_firewall.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP10 gold prompt leakage firewall receipt."),
            (REPORTS / "ktstop10_runtime_packet_decision.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP10 runtime packet decision receipt."),
            (REPORTS / "ktstop10_claim_boundary_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP10 claim boundary receipt."),
            (REPORTS / "ktstop10_builder_summary.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "KTSTOP10 builder summary."),
            (PACKET_PATH, "GENERATED_RUNTIME_PACKET", "CURRENT_HEAD", False, "KTSTOP10 generated runtime packet."),
            (ONE_CELL_RUNBOOK, "CANONICAL_RUNBOOK", "CURRENT_HEAD", False, "KTSTOP10 one-cell Kaggle runbook."),
            (ROOT / "scripts" / "build_ktstop10_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "KTSTOP10 packet builder."),
            (ROOT / "scripts" / "validate_ktstop10_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "KTSTOP10 packet validator."),
            (ROOT / "tests" / "test_ktstop10_packet_generation.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "KTSTOP10 packet generation test."),
            (ROOT / "tests" / "test_ktstop10_row_selection_binding.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "KTSTOP10 row selection binding test."),
            (ROOT / "tests" / "test_ktstop10_prompt_arm_manifest.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "KTSTOP10 prompt arm manifest test."),
            (ROOT / "tests" / "test_ktstop10_no_gold_prompt_leakage.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "KTSTOP10 no-gold prompt leakage test."),
            (ROOT / "tests" / "test_ktstop10_claim_ceiling.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "KTSTOP10 claim ceiling test."),
        ]
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
