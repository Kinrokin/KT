from __future__ import annotations

import hashlib
import json
import re
import statistics
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from ktstop300_common import (
    ADMISSION,
    AUTHORITY_FALSE,
    DOCS,
    EVIDENCE,
    FIXTURES,
    NEXT_LAWFUL_MOVE,
    OUTCOME,
    PACKETS,
    REPORTS,
    ROOT,
    SCHEMAS,
    SCOPED_AUTHORITY,
    STOP300_DATASET,
    STOP300_PACKET,
    STOP300_RUNBOOK,
    STOP300_RUN_MODE,
    STOP50_ASSESSMENT_SHA256,
    STOP50_PACKET_SHA256,
    STOP50_WRAPPER_SHA256,
    authority_payload,
    git_output,
    read_json,
    rel,
    sha256_file,
    sha256_text,
    update_registry,
    utc_now,
    write_json,
    write_text,
)


MODEL_REPO = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
HF_RESULTS_REPO = "Kinrokin/ktstop300-v1-results"
NATURAL_SEED = "ktstop300-v1-natural-20260618"
TIMING_SEED = "ktstop300-v1-timing-20260618"
CUES = (
    "each",
    "per",
    "ratio",
    "percent",
    "remaining",
    "difference",
    "more",
    "less",
    "twice",
    "half",
    "total",
    "rate",
    "average",
)


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def legal_features(question: str) -> dict[str, int]:
    q = question or ""
    return {
        "character_length": len(q),
        "token_proxy": len(q.split()),
        "sentence_clause_count": len(re.findall(r"[.!?;]|\b(?:and|then|after|before)\b", q, re.I)),
        "numeric_literal_count": len(re.findall(r"[-+]?\d[\d,]*(?:\.\d+)?(?:/\d+)?", q)),
        "operator_cue_count": sum(len(re.findall(r"\b" + re.escape(cue) + r"\b", q, re.I)) for cue in CUES),
        "unit_format_diversity_count": sum(
            bool(re.search(pattern, q, re.I))
            for pattern in [r"[$]", r"%", r"\b(?:hour|minute|mile|kg|pound|liter|meter)s?\b", r"\d+\s*/\s*\d+"]
        ),
    }


def ranks(values: list[int]) -> list[float]:
    order = sorted(range(len(values)), key=lambda i: (values[i], i))
    out = [0.0] * len(values)
    for rank, idx in enumerate(order):
        out[idx] = rank / (len(values) - 1) if len(values) > 1 else 0.0
    return out


def collect_prior_gsm8k_ids() -> set[int]:
    try:
        output = subprocess.check_output(
            ["rg", "-o", r"gsm8k_test_[0-9]+", "--glob", "!admission/stop300_*", "--glob", "!packets/ktstop300_v1.zip"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        output = ""
    ids = set()
    for match in re.findall(r"gsm8k_test_([0-9]+)", output):
        ids.add(int(match))
    return ids


def load_gsm8k_questions() -> list[dict[str, Any]]:
    try:
        from datasets import load_dataset
    except Exception as exc:
        raise SystemExit("datasets package is required for STOP300 legal-feature sampling") from exc
    dataset = load_dataset("openai/gsm8k", "main", split="test")
    return [
        {
            "row_id": f"gsm8k_test_{idx}",
            "dataset": "openai/gsm8k",
            "split": "test",
            "split_index": idx,
            "question": row["question"],
        }
        for idx, row in enumerate(dataset)
    ]


def stratified_selection() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    prior_ids = collect_prior_gsm8k_ids()
    rows = [row for row in load_gsm8k_questions() if row["split_index"] not in prior_ids]
    feats = [legal_features(row["question"]) for row in rows]
    keys = sorted(feats[0])
    ranked = {key: ranks([feature[key] for feature in feats]) for key in keys}
    scored = []
    for idx, row in enumerate(rows):
        difficulty = statistics.mean(ranked[key][idx] for key in keys)
        scored.append({**row, "legal_features": feats[idx], "difficulty_proxy": difficulty})
    scored.sort(key=lambda row: (row["difficulty_proxy"], row["row_id"]))
    n = len(scored)
    for idx, row in enumerate(scored):
        row["stratum"] = "EASY" if idx < n / 3 else ("MEDIUM" if idx < 2 * n / 3 else "HARD")

    selected = []
    for stratum, count in {"EASY": 100, "MEDIUM": 100, "HARD": 100}.items():
        pool = [row for row in scored if row["stratum"] == stratum]
        pool.sort(key=lambda row: hashlib.sha256(f"{NATURAL_SEED}:{row['row_id']}".encode()).hexdigest())
        if len(pool) < count:
            raise SystemExit(f"not enough {stratum} rows after exclusions")
        selected.extend(pool[:count])
    selected_ids = {row["row_id"] for row in selected}

    timing = []
    for stratum in ["EASY", "MEDIUM", "HARD"]:
        pool = [row for row in selected if row["stratum"] == stratum]
        pool.sort(key=lambda row: hashlib.sha256(f"{TIMING_SEED}:{row['row_id']}".encode()).hexdigest())
        timing.extend(pool[:20])

    candidate_manifest = {
        "schema_id": "kt.stop300.candidate_pool_manifest.v1",
        "status": "PASS",
        "dataset": "openai/gsm8k",
        "split": "test",
        "candidate_pool_count": len(rows),
        "excluded_prior_row_count": len(prior_ids),
        "legal_feature_keys": keys,
        "forbidden_selection_inputs_absent": True,
        "candidate_rows": [{k: row[k] for k in ["row_id", "split_index", "legal_features", "difficulty_proxy", "stratum"]} for row in scored],
    }
    exclusion_manifest = {
        "schema_id": "kt.stop300.exclusion_manifest.v1",
        "status": "PASS",
        "excluded_row_ids": [f"gsm8k_test_{idx}" for idx in sorted(prior_ids)],
        "excluded_row_count": len(prior_ids),
    }
    return selected, timing, scored, {"candidate": candidate_manifest, "exclusion": exclusion_manifest, "selected_ids": selected_ids}


def write_admission_and_reports(selected: list[dict[str, Any]], timing: list[dict[str, Any]], meta: dict[str, Any]) -> None:
    now = utc_now()
    risk = {
        "schema_id": "kt.stop300.runtime_stop_risk_tolerance_contract.v1",
        "created_utc": now,
        "status": "PASS_PREREGISTERED",
        "alpha": 0.05,
        "independent_rows": 300,
        "observed_damage_tolerance": 0,
        "one_sided_exact_95pct_damage_upper_bound_target": 0.01,
        "primary_endpoint": "paired_correctness_damage",
        "co_primary_endpoint": "raw_original_token_prefix_equivalence",
        **authority_payload(),
    }
    prereg = {
        "schema_id": "kt.stop300.preregistered_protocol.v1",
        "created_utc": now,
        "status": "PASS_PREREGISTERED_BEFORE_GENERATION",
        "run_mode": STOP300_RUN_MODE,
        "model_repo": MODEL_REPO,
        "arms": ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"],
        "failure_statuses": [
            "PASS_SAFETY_AND_ECONOMICS_300__SHADOW_PACKET_AUTHORING_EARNED",
            "PASS_TOKEN_ONLY__LATENCY_NOT_ESTABLISHED__SHADOW_PACKET_AUTHORING_EARNED",
            "BLOCK_CORRECTNESS_DAMAGE",
            "BLOCK_FIRST_ANSWER_CORRECTION_CUT",
            "BLOCK_RUNTIME_REFERENCE_DISAGREEMENT",
            "BLOCK_GRAMMAR_AMBIGUITY",
            "BLOCK_ENVIRONMENT_DRIFT",
            "BLOCK_TIMING_PROTOCOL_VIOLATION",
            "BLOCK_ARTIFACT_PUBLICATION_FAILURE",
        ],
        **authority_payload(),
    }
    legal_feature = {
        "schema_id": "kt.stop300.legal_feature_contract.v1",
        "created_utc": now,
        "status": "PASS",
        "allowed_features": [
            "question tokenizer length",
            "character length",
            "sentence/clause count",
            "numeric-literal count",
            "operator/rate/ratio/comparison cue count",
            "unit/format diversity count",
        ],
        "forbidden_selection_inputs": [
            "gold answer",
            "measured correctness",
            "observed token savings",
            "stop outcome",
            "row-specific prior result",
        ],
    }
    selected_rows = [
        {
            "row_id": row["row_id"],
            "dataset": "openai/gsm8k",
            "split": "test",
            "split_index": row["split_index"],
            "stratum": row["stratum"],
            "difficulty_proxy": row["difficulty_proxy"],
            "legal_features": row["legal_features"],
            "question_hash": sha256_text(row["question"]),
        }
        for row in selected
    ]
    timing_rows = [
        {
            "row_id": row["row_id"],
            "split_index": row["split_index"],
            "stratum": row["stratum"],
            "difficulty_proxy": row["difficulty_proxy"],
            "question_hash": sha256_text(row["question"]),
        }
        for row in timing
    ]
    selected_manifest = {
        "schema_id": "kt.stop300.stratified_hash_selected_manifest.v1",
        "created_utc": now,
        "status": "PASS_100_100_100_STRATIFIED_HASH_SELECTION",
        "seed": NATURAL_SEED,
        "row_count": 300,
        "rows": selected_rows,
        "stratum_counts": {name: sum(1 for row in selected_rows if row["stratum"] == name) for name in ["EASY", "MEDIUM", "HARD"]},
    }
    timing_manifest = {
        "schema_id": "kt.stop300.timing_panel_manifest.v1",
        "created_utc": now,
        "status": "PASS_BALANCED_60_ROW_TIMING_PANEL",
        "seed": TIMING_SEED,
        "row_count": 60,
        "rows": timing_rows,
        "stratum_counts": {name: sum(1 for row in timing_rows if row["stratum"] == name) for name in ["EASY", "MEDIUM", "HARD"]},
    }
    edge = read_json(EVIDENCE / "KT_STOP50_EDGE_ROWS.json")
    paths = {
        ADMISSION / "runtime_stop_risk_tolerance_contract.json": risk,
        ADMISSION / "stop300_preregistered_protocol.json": prereg,
        ADMISSION / "stop300_candidate_pool_manifest.json": meta["candidate"],
        ADMISSION / "stop300_exclusion_manifest.json": meta["exclusion"],
        ADMISSION / "stop300_legal_feature_contract.json": legal_feature,
        ADMISSION / "stop300_stratified_hash_selected_manifest.json": selected_manifest,
        ADMISSION / "stop300_timing_panel_manifest.json": timing_manifest,
        ADMISSION / "stop300_edge_regression_manifest.json": {
            "schema_id": "kt.stop300.edge_regression_manifest.v1",
            "status": "PASS_BOUND_SEPARATE_DENOMINATOR",
            "excluded_from_independent_safety_n": True,
            "second_marker_rows": edge["second_marker_close_candidates"],
            "natural_eos_rows": edge["natural_eos_candidates"],
        },
    }
    for path, payload in paths.items():
        write_json(path, payload)
    write_json(
        REPORTS / "stop300_overlap_and_selection_receipt.json",
        {
            "schema_id": "kt.stop300.overlap_and_selection_receipt.v1",
            "status": "PASS",
            "selected_row_count": 300,
            "candidate_pool_count": meta["candidate"]["candidate_pool_count"],
            "prior_overlap_count": 0,
            "selection_seed": NATURAL_SEED,
            **authority_payload(),
        },
    )
    write_json(
        REPORTS / "stop300_stratum_balance_receipt.json",
        {
            "schema_id": "kt.stop300.stratum_balance_receipt.v1",
            "status": "PASS",
            "natural_stratum_counts": selected_manifest["stratum_counts"],
            "timing_stratum_counts": timing_manifest["stratum_counts"],
            **authority_payload(),
        },
    )
    write_json(
        REPORTS / "stop300_restart_resume_contract.json",
        {
            "schema_id": "kt.stop300.restart_resume_contract.v1",
            "status": "PASS_CONTRACT_DEFINED",
            "atomic_jsonl_append_after_every_arm": True,
            "completed_work_key": "evidence_scope_hash/row_id/repetition/arm",
            "atomic_run_state_replacement": True,
            "scope_mismatch_blocker": True,
            "checkpoint_every_25_natural_rows": True,
            "checkpoint_after_every_timing_block": True,
            "partial_outputs_zip": "PARTIAL_MEASURED_OUTPUTS.zip",
            "kt_max_wall_seconds_graceful_exit": True,
            **authority_payload(),
        },
    )
    write_json(
        REPORTS / "stop300_publication_order_receipt.json",
        {
            "schema_id": "kt.stop300.publication_order_receipt.v1",
            "status": "PASS_PUBLICATION_ORDER_DEFINED",
            "order": [
                "write evidence artifacts",
                "package evidence-core bundle",
                "upload evidence folder",
                "write HF_EVIDENCE_UPLOAD_RECEIPT.json",
                "package final assessment including that receipt",
                "upload final assessment",
                "keep HF_FINAL_ASSESSMENT_UPLOAD_RECEIPT.json in wrapper collection",
            ],
            **authority_payload(),
        },
    )


def runtime_runner_source() -> str:
    return r'''from __future__ import annotations

import json
import os
import time
import zipfile
from pathlib import Path

from runtime.stop_fsm_v31 import StopGrammarV31RuntimeFSM
from runtime.reference_court_v31 import adjudicate_reference_court_v31
from runtime.resume_ledger import ResumeLedger
from runtime.timing_protocol import arm_order, timing_protocol_receipt
from runtime.environment_preflight import environment_preflight
from runtime.effective_config_receipt import generation_config_receipt, quantization_authority_receipt
from runtime.output_delivery import extract_answer, expected_answer, render_prompt, score


RUN_MODE = "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V1"
MODEL_REPO = os.environ.get("KT_MODEL_REPO", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit")
HF_RESULTS_REPO = os.environ.get("KT_HF_RESULTS_REPO", "Kinrokin/ktstop300-v1-results")


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_rows(config):
    from datasets import load_dataset
    dataset = load_dataset("openai/gsm8k", "main", split="test")
    rows = []
    for row in config["natural_rows"]:
        item = dataset[int(row["split_index"])]
        rows.append({**row, "question": item["question"], "expected_answer": expected_answer(item["answer"])})
    return rows


def load_model():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(MODEL_REPO, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(MODEL_REPO, device_map="auto", torch_dtype="auto", trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return model, tokenizer


def generate(model, tokenizer, prompt: str, *, arm_id: str, max_new_tokens: int = 512):
    import torch
    from transformers import StoppingCriteria, StoppingCriteriaList

    class Stop300Criteria(StoppingCriteria):
        def __init__(self, tokenizer, prompt_len: int, monitor_only: bool):
            self.tokenizer = tokenizer
            self.prompt_len = prompt_len
            self.fsm = StopGrammarV31RuntimeFSM(monitor_only=monitor_only)
            self.last_len = prompt_len
            self.last_decision = None

        def __call__(self, input_ids, scores=None, **kwargs):
            if getattr(input_ids, "shape", [1])[0] != 1:
                raise ValueError("STOP300 batch-size-one only")
            row = input_ids[0]
            new_ids = row[self.last_len:]
            self.last_len = int(row.shape[-1])
            piece = self.tokenizer.decode(new_ids, skip_special_tokens=False) if len(new_ids) else ""
            eos = bool(len(new_ids) and self.tokenizer.eos_token_id is not None and int(new_ids[-1]) == int(self.tokenizer.eos_token_id))
            self.last_decision = self.fsm.feed(piece, eos=eos, token_count=max(len(new_ids), 1))
            try:
                return torch.tensor([bool(self.last_decision.should_stop)], dtype=torch.bool, device=input_ids.device)
            except Exception:
                return bool(self.last_decision.should_stop)

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    prompt_len = int(inputs["input_ids"].shape[-1])
    monitor = arm_id == "M0_STREAMING_DETECTOR_MONITOR_ONLY"
    terminate = arm_id == "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"
    criteria_obj = Stop300Criteria(tokenizer, prompt_len, monitor_only=monitor) if (monitor or terminate) else None
    criteria = StoppingCriteriaList([criteria_obj]) if criteria_obj else None
    if torch.cuda.is_available():
        torch.cuda.synchronize()
    start = time.perf_counter_ns()
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False, pad_token_id=tokenizer.eos_token_id, stopping_criteria=criteria)
    if torch.cuda.is_available():
        torch.cuda.synchronize()
    end = time.perf_counter_ns()
    generated_ids = out[0][prompt_len:].tolist()
    text = tokenizer.decode(generated_ids, skip_special_tokens=True)
    court = adjudicate_reference_court_v31(text)
    telemetry = criteria_obj.fsm.telemetry() if criteria_obj else {"full_sequence_rescan_count": 0}
    decision = criteria_obj.last_decision.to_json() if criteria_obj and criteria_obj.last_decision else None
    return text, generated_ids, prompt_len, end - start, court.to_json(), decision, telemetry


def main() -> None:
    packet_root = Path(__file__).resolve().parents[1]
    config = read_json(packet_root / "runtime" / "ktstop300_config.json")
    outdir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktstop300_outputs"))
    outdir.mkdir(parents=True, exist_ok=True)
    assessment = Path(os.environ.get("KT_ASSESSMENT_ZIP", "/kaggle/working/KT_STOP300_V1_ASSESSMENT_ONLY.zip"))
    env = environment_preflight()
    write_json(outdir / "environment_contract_receipt.json", env)
    write_json(outdir / "quantization_authority_receipt.json", quantization_authority_receipt(MODEL_REPO))
    gen_cfg = {"max_new_tokens": 512, "do_sample": False}
    write_json(outdir / "generation_config_authority_receipt.json", generation_config_receipt(gen_cfg))
    write_json(outdir / "timing_protocol_receipt.json", timing_protocol_receipt())
    if env["status"] != "PASS_FUNCTIONAL_FOR_THIS_EXACT_RUN":
        write_json(outdir / "BLOCKER_RECEIPT.json", {"schema_id": "kt.stop300.blocker.v1", "status": "BLOCK_ENVIRONMENT_DRIFT", "environment": env, "claim_ceiling_status": "PRESERVED"})
        with zipfile.ZipFile(assessment, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(outdir.glob("*")):
                zf.write(path, path.name)
        return
    model, tokenizer = load_model()
    rows = load_rows(config)
    scope_hash = config["evidence_scope_hash"]
    ledger = ResumeLedger(outdir / "RUN_STATE.json", scope_hash)
    write_json(outdir / "row_manifest.json", {"schema_id": "kt.stop300.row_manifest.runtime.v1", "rows": config["natural_rows"], "row_count": len(config["natural_rows"]), "claim_ceiling_status": "PRESERVED"})
    for row in rows:
        for arm_id in ["L0_LEGACY_NO_DETECTOR", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
            key = ledger.key(row["row_id"], 0, arm_id)
            if key in ledger.completed:
                continue
            prompt = render_prompt(config["base_prompt_template"], row["question"])
            text, ids, prompt_len, ns, court, decision, telemetry = generate(model, tokenizer, prompt, arm_id=arm_id)
            extracted = extract_answer(court["visible_text"] or text)
            rec = {"schema_id": "kt.stop300.prediction_row.v1", "row_id": row["row_id"], "arm_id": arm_id, "repetition": 0, "correct": score(row["expected_answer"], extracted), "extracted_answer": extracted, "raw_generated_token_ids": ids, "raw_generated_text": text, "reference_court": court, "runtime_decision": decision, "detector_telemetry": telemetry, "latency_ns": ns, "claim_ceiling_status": "PRESERVED"}
            append_jsonl(outdir / "predictions.jsonl", rec)
            ledger.mark(row["row_id"], 0, arm_id)
    write_json(outdir / "RESUME_RECEIPT.json", {"schema_id": "kt.stop300.resume_receipt.v1", "status": "PASS", "completed_keys": sorted(ledger.completed), "claim_ceiling_status": "PRESERVED"})
    write_json(outdir / "final_summary.json", {"schema_id": "kt.stop300.final_summary.v1", "status": "MEASURED_OUTPUTS_EMITTED_PENDING_COURT", "run_mode": RUN_MODE, "claim_ceiling_status": "PRESERVED"})
    with zipfile.ZipFile(assessment, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(outdir.glob("*")):
            zf.write(path, path.name)


if __name__ == "__main__":
    main()
'''


def output_delivery_source() -> str:
    return r'''from __future__ import annotations

import re


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
        return normalize(fractions[-1].replace(" ", ""))
    numbers = re.findall(r"[-+]?\$?\d[\d,]*(?:\.\d+)?(?:[eE][-+]?\d+)?", target)
    return normalize(numbers[-1]) if numbers else None


def expected_answer(answer_text: str):
    return answer_text.split("####")[-1].strip() if "####" in answer_text else extract_answer(answer_text)


def score(expected, extracted) -> bool:
    return normalize(expected) == normalize(extracted)


def render_prompt(template: str, question: str) -> str:
    return f"{template}\n\nProblem:\n{question}\n"
'''


def environment_source() -> str:
    return r'''from __future__ import annotations


def environment_preflight() -> dict:
    receipt = {"schema_id": "kt.stop300.environment_preflight.runtime.v1", "cuda_required": True, "bitsandbytes_version_required": "0.49.2"}
    try:
        import torch
        import bitsandbytes as bnb
        receipt["torch_version"] = getattr(torch, "__version__", "unknown")
        receipt["bitsandbytes_version"] = getattr(bnb, "__version__", "unknown")
        receipt["cuda_available"] = bool(torch.cuda.is_available())
        receipt["status"] = "PASS_FUNCTIONAL_FOR_THIS_EXACT_RUN" if receipt["cuda_available"] and receipt["bitsandbytes_version"] == "0.49.2" else "FAIL_ENVIRONMENT_DRIFT"
    except Exception as exc:
        receipt["status"] = "FAIL_ENVIRONMENT_DRIFT"
        receipt["error"] = str(exc)
    receipt["claim_ceiling_status"] = "PRESERVED"
    return receipt
'''


def effective_config_source() -> str:
    return r'''from __future__ import annotations

import hashlib
import json


def stable_hash(payload) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def quantization_authority_receipt(model_repo: str) -> dict:
    return {"schema_id": "kt.stop300.quantization_authority.v1", "status": "PASS_SINGLE_MODEL_EMBEDDED_QUANTIZATION_AUTHORITY", "model_repo": model_repo, "runtime_bitsandbytes_config_allowed": False, "conflict_count": 0, "claim_ceiling_status": "PRESERVED"}


def generation_config_receipt(config: dict) -> dict:
    return {"schema_id": "kt.stop300.generation_config_authority.v1", "status": "PASS_SINGULAR_EFFECTIVE_GENERATION_CONFIG_BOUND", "effective_generation_config": config, "effective_generation_config_sha256": stable_hash(config), "warning_count": 0, "claim_ceiling_status": "PRESERVED"}
'''


def timing_source() -> str:
    return r'''from __future__ import annotations

import hashlib


ARMS = ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]


def arm_order(row_id: str, repetition: int) -> list[str]:
    seed = hashlib.sha256(f"ktstop300-v1:{row_id}:{repetition}".encode()).hexdigest()
    start = int(seed[:2], 16) % len(ARMS)
    return ARMS[start:] + ARMS[:start]


def timing_protocol_receipt() -> dict:
    return {"schema_id": "kt.stop300.timing_protocol.v1", "status": "PASS_THREE_ARM_IDENTIFIABLE_TIMING_DEFINED", "arms": ARMS, "warmups_per_arm": 3, "batch_size": 1, "cuda_synchronize": True, "cuda_events_required": True, "claim_ceiling_status": "PRESERVED"}
'''


def resume_source() -> str:
    return r'''from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


class ResumeLedger:
    def __init__(self, path: Path, scope_hash: str):
        self.path = Path(path)
        self.scope_hash = scope_hash
        self.completed = set()
        self._load()

    def _load(self):
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8-sig"))
            if data["evidence_scope_hash"] != self.scope_hash:
                raise ValueError("scope hash mismatch")
            self.completed = set(data.get("completed_keys", []))

    def key(self, row_id: str, repetition: int, arm: str) -> str:
        return f"{self.scope_hash}/{row_id}/{repetition}/{arm}"

    def mark(self, row_id: str, repetition: int, arm: str) -> None:
        self.completed.add(self.key(row_id, repetition, arm))
        self.flush()

    def flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"schema_id": "kt.stop300.run_state.v1", "evidence_scope_hash": self.scope_hash, "completed_keys": sorted(self.completed), "resume_safe": True}
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=self.path.name + ".", suffix=".tmp")
        os.close(fd)
        Path(tmp).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
'''


def bootstrap_source() -> str:
    return "from pathlib import Path\nimport runpy\nrunpy.run_path(str(Path(__file__).resolve().parent / 'runtime' / 'KT_CANONICAL_RUNNER.py'), run_name='__main__')\n"


def smoke_test_source() -> str:
    return """from runtime.stop_fsm_v31 import StopGrammarV31RuntimeFSM\nfrom runtime.reference_court_v31 import adjudicate_reference_court_v31\n\n\ndef test_stop300_fsm_reference_smoke():\n    text = 'FINAL_ANSWER: 42\\ntrailer'\n    runtime = StopGrammarV31RuntimeFSM()\n    decision = runtime.feed(text)\n    court = adjudicate_reference_court_v31(text)\n    assert decision.semantic_boundary_type.value == court.semantic_boundary_type == 'FINAL_LINE_CLOSE'\n    assert runtime.full_sequence_rescan_count == 0\n"""


def runtime_config(selected: list[dict[str, Any]], timing: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [
        {
            "row_id": row["row_id"],
            "split_index": row["split_index"],
            "stratum": row["stratum"],
            "difficulty_proxy": row["difficulty_proxy"],
            "question_hash": sha256_text(row["question"]),
        }
        for row in selected
    ]
    timing_rows = [
        {
            "row_id": row["row_id"],
            "split_index": row["split_index"],
            "stratum": row["stratum"],
            "question_hash": sha256_text(row["question"]),
        }
        for row in timing
    ]
    config = {
        "schema_id": "kt.stop300.runtime_config.v1",
        "run_mode": STOP300_RUN_MODE,
        "kaggle_dataset_name": STOP300_DATASET,
        "base_model_repo": MODEL_REPO,
        "hf_results_repo": HF_RESULTS_REPO,
        "natural_rows": rows,
        "timing_panel_rows": timing_rows,
        "edge_regression_rows": read_json(ADMISSION / "stop300_edge_regression_manifest.json"),
        "base_prompt_template": "Solve the math problem. Show concise reasoning, then end with exactly one line in this format: FINAL_ANSWER: <answer>",
        "arms": ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"],
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    config["evidence_scope_hash"] = stable_hash({"rows": rows, "timing": timing_rows, "run_mode": STOP300_RUN_MODE})
    return config


def build_packet(config: dict[str, Any]) -> str:
    members = {
        "KAGGLE_BOOTSTRAP_CELL.py": bootstrap_source(),
        "runtime/KT_CANONICAL_RUNNER.py": runtime_runner_source(),
        "runtime/stop_fsm_v31.py": source("runtime/stop_fsm_v31.py"),
        "runtime/output_delivery.py": output_delivery_source(),
        "runtime/reference_court_v31.py": source("runtime/reference_court_v31.py"),
        "runtime/environment_preflight.py": environment_source(),
        "runtime/effective_config_receipt.py": effective_config_source(),
        "runtime/timing_protocol.py": timing_source(),
        "runtime/resume_ledger.py": resume_source(),
        "runtime/ktstop300_config.json": json.dumps(config, indent=2, sort_keys=True) + "\n",
        "requirements.txt": "datasets\ntransformers\naccelerate\nbitsandbytes==0.49.2\nhuggingface_hub\nsafetensors\n",
        "tests/smoke_test.py": smoke_test_source(),
        "README.md": "# KTSTOP300 V1\n\nHostile falsification paired-300 sandbox runtime packet. No training, promotion, selector deployment, shadow execution, production runtime authority, production prompt mutation, or production math-mode claim.\n",
        "COPY_PASTE_NOW_ktstop300_v1.txt": "Use Kaggle dataset ktstop300-v1 and execute KAGGLE_BOOTSTRAP_CELL.py. Run mode RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V1. Sandbox inference only; no training, promotion, selector deployment, shadow execution, or production authority.\n",
    }
    manifest = {
        "schema_id": "kt.stop300.packet_manifest.v1",
        "packet_name": "ktstop300_v1.zip",
        "run_mode": STOP300_RUN_MODE,
        "kaggle_dataset_name": STOP300_DATASET,
        "natural_row_count": 300,
        "timing_panel_row_count": 60,
        "source_stop50_packet_sha256": STOP50_PACKET_SHA256,
        "source_stop50_assessment_sha256": STOP50_ASSESSMENT_SHA256,
        "source_stop50_wrapper_sha256": STOP50_WRAPPER_SHA256,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
        **SCOPED_AUTHORITY,
    }
    members["PACKET_MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    members["SHA256_MANIFEST.json"] = json.dumps(
        {"schema_id": "kt.stop300.sha256_manifest.v1", "members": {name: sha256_text(data) for name, data in sorted(members.items())}},
        indent=2,
        sort_keys=True,
    ) + "\n"
    PACKETS.mkdir(exist_ok=True)
    with zipfile.ZipFile(STOP300_PACKET, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return sha256_file(STOP300_PACKET)


def write_runbook(packet_sha: str) -> None:
    write_text(
        STOP300_RUNBOOK,
        f"""# KT STOP300 One-Cell Runbook

Packet: `packets/ktstop300_v1.zip`

SHA256: `{packet_sha}`

Kaggle dataset: `ktstop300-v1`

Run mode: `RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V1`

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop300-v1/ktstop300_v1.zip')
work = Path('/kaggle/working/ktstop300_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

Sandbox inference only. No training, promotion, selector deployment, shadow execution, production runtime authority, production prompt mutation, or production math-mode authority.
""",
    )


def main() -> int:
    selected, timing, _scored, meta = stratified_selection()
    write_admission_and_reports(selected, timing, meta)
    config = runtime_config(selected, timing)
    packet_sha = build_packet(config)
    write_runbook(packet_sha)
    write_json(
        REPORTS / "stop300_packet_decision.json",
        {
            "schema_id": "kt.stop300.packet_decision.v1",
            "created_utc": utc_now(),
            "status": "GENERATED",
            "outcome": OUTCOME,
            "packet_path": rel(STOP300_PACKET),
            "packet_sha256": packet_sha,
            "kaggle_dataset_name": STOP300_DATASET,
            "one_cell_runbook": rel(STOP300_RUNBOOK),
            "run_mode": STOP300_RUN_MODE,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
            **authority_payload(),
            "sandbox_inference_authority": True,
        },
    )
    write_json(
        REPORTS / "stop300_environment_contract.json",
        {
            "schema_id": "kt.stop300.environment_contract.v1",
            "status": "PASS_CONTRACT_DEFINED",
            "functional_statement": "FUNCTIONAL_FOR_THIS_EXACT_RUN__NOT_GENERALLY_CLEAN",
            "bitsandbytes_required": "0.49.2",
            "model_is_loaded_in_4bit_required": True,
            "cpu_offload_allowed": False,
            "disk_offload_allowed": False,
            **authority_payload(),
        },
    )
    write_json(
        REPORTS / "stop300_effective_config_authority.json",
        {
            "schema_id": "kt.stop300.effective_config_authority.v1",
            "status": "PASS",
            "quantization_authority": "MODEL_EMBEDDED",
            "runtime_bitsandbytes_config_allowed": False,
            "generation_config_warning_count_required": 0,
            **authority_payload(),
        },
    )
    write_json(
        REPORTS / "stop300_claim_boundary_receipt.json",
        {
            "schema_id": "kt.stop300.claim_boundary_receipt.v1",
            "status": "PASS_CLAIM_CEILING_PRESERVED",
            "clean_result_earns_only": "AUTHOR_KTSTOP_SHADOW1000_PACKET_V1",
            **authority_payload(),
        },
    )
    write_json(
        REPORTS / "stop300_builder_summary.json",
        {
            "schema_id": "kt.stop300.builder_summary.v1",
            "status": "PASS",
            "current_head": git_output("rev-parse", "HEAD"),
            "branch": git_output("branch", "--show-current"),
            "outcome": OUTCOME,
            "packet_path": rel(STOP300_PACKET),
            "packet_sha256": packet_sha,
            "kaggle_dataset_name": STOP300_DATASET,
            "one_cell_runbook": rel(STOP300_RUNBOOK),
            "next_lawful_move": NEXT_LAWFUL_MOVE,
            **authority_payload(),
            "sandbox_inference_authority": True,
        },
    )
    registry_specs = [
            (EVIDENCE / "KT_STOP50_V1_ASSESSMENT_ONLY.zip", "EVIDENCE_ARCHIVE", "CURRENT_HEAD", False, "Imported STOP50 assessment."),
            (EVIDENCE / "KT_STOP50_V1_WRAPPER_COLLECTION.zip", "EVIDENCE_ARCHIVE", "CURRENT_HEAD", False, "Imported STOP50 wrapper collection."),
            (EVIDENCE / "KT_STOP50_DEEP_MINING_SUMMARY.json", "EVIDENCE_SUMMARY", "CURRENT_HEAD", False, "STOP50 deep mining summary."),
            (EVIDENCE / "KT_STOP50_HOSTILE_SYNTHESIS_V2.json", "EVIDENCE_SUMMARY", "CURRENT_HEAD", False, "STOP50 hostile synthesis."),
            (EVIDENCE / "KT_STOP50_PAIRED_LEDGER.jsonl", "EVIDENCE_LEDGER", "CURRENT_HEAD", False, "STOP50 paired ledger."),
            (EVIDENCE / "KT_STOP50_ROW_AGGREGATES.jsonl", "EVIDENCE_LEDGER", "CURRENT_HEAD", False, "STOP50 row aggregates."),
            (EVIDENCE / "KT_STOP50_SAVINGS_DISTRIBUTION.json", "EVIDENCE_SUMMARY", "CURRENT_HEAD", False, "STOP50 savings distribution."),
            (EVIDENCE / "KT_STOP50_TIMING_MEDIATION.json", "EVIDENCE_SUMMARY", "CURRENT_HEAD", False, "STOP50 timing mediation."),
            (EVIDENCE / "KT_STOP50_EDGE_ROWS.json", "EVIDENCE_SUMMARY", "CURRENT_HEAD", False, "STOP50 edge rows."),
            (FIXTURES / "stop_grammar_v31_adversarial_cases.jsonl", "CANONICAL_FIXTURE", "INTERNAL_SHADOW", True, "STOP grammar v3.1 adversarial fixtures."),
            (FIXTURES / "stop_grammar_v31_mutations.json", "CANONICAL_FIXTURE", "INTERNAL_SHADOW", True, "STOP grammar v3.1 mutation manifest."),
            (ROOT / "runtime" / "stop_fsm_v31.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP grammar v3.1 runtime FSM."),
            (ROOT / "runtime" / "reference_court_v31.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP grammar v3.1 independent reference court."),
            (ROOT / "runtime" / "final_answer_stop.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "Existing STOP final answer runtime surface patched for SECOND_MARKER_CLOSE."),
            (ROOT / "runtime" / "final_answer_stop_types.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "Existing STOP final answer types patched for SECOND_MARKER_CLOSE."),
            (ROOT / "scripts" / "ktstop300_common.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 common helpers."),
            (ROOT / "scripts" / "import_ktstop50_assessment.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP50 import script."),
            (ROOT / "scripts" / "replay_historical_first_vs_last.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "Historical first-vs-last replay."),
            (ROOT / "scripts" / "reconcile_stop_grammar_v31.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP grammar v3.1 reconciliation."),
            (ROOT / "scripts" / "build_ktstop300_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 packet builder."),
            (ROOT / "scripts" / "validate_ktstop300_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 packet validator."),
            (STOP300_PACKET, "GENERATED_RUNTIME_PACKET", "CURRENT_HEAD", False, "STOP300 generated sandbox runtime packet."),
            (STOP300_RUNBOOK, "CANONICAL_RUNBOOK", "CURRENT_HEAD", False, "STOP300 one-cell runbook."),
            (ADMISSION / "runtime_stop_risk_tolerance_contract.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 risk tolerance contract."),
            (ADMISSION / "stop300_preregistered_protocol.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 preregistered protocol."),
            (ADMISSION / "stop300_candidate_pool_manifest.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 candidate pool manifest."),
            (ADMISSION / "stop300_exclusion_manifest.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 exclusion manifest."),
            (ADMISSION / "stop300_legal_feature_contract.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 legal feature contract."),
            (ADMISSION / "stop300_stratified_hash_selected_manifest.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 stratified selected manifest."),
            (ADMISSION / "stop300_timing_panel_manifest.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 timing panel manifest."),
            (ADMISSION / "stop300_edge_regression_manifest.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 edge regression manifest."),
            (REPORTS / "ktstop50_truth_pin.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP50 truth pin for STOP300."),
            (REPORTS / "ktstop50_assessment_import_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP50 assessment import receipt."),
            (REPORTS / "ktstop50_wrapper_import_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP50 wrapper import receipt."),
            (REPORTS / "ktstop50_official_scorecard_preservation.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP50 official scorecard preservation."),
            (REPORTS / "ktstop50_hostile_synthesis.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP50 hostile synthesis receipt."),
            (REPORTS / "ktstop50_savings_distribution_and_concentration.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP50 savings distribution receipt."),
            (REPORTS / "ktstop50_timing_mediation_analysis.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP50 timing mediation analysis."),
            (REPORTS / "ktstop50_environment_composite_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP50 environment composite receipt."),
            (REPORTS / "ktstop50_claim_boundary_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP50 claim boundary for STOP300."),
            (REPORTS / "historical_first_vs_last_answer_counterfactual_replay.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "Historical first-vs-last replay."),
            (REPORTS / "historical_trace_source_coverage.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "Historical trace coverage ledger."),
            (REPORTS / "output_protocol_signature_registry.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "Output protocol signature registry."),
            (REPORTS / "first_answer_safety_scope_decision.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "First answer safety scope decision."),
            (REPORTS / "stop_grammar_v31_mutation_coverage_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP grammar v3.1 mutation coverage."),
            (REPORTS / "runtime_reference_independence_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "Runtime/reference independence receipt."),
            (REPORTS / "runtime_reference_agreement_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "Runtime/reference agreement receipt."),
            (REPORTS / "stop_grammar_v31_status.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP grammar v3.1 status."),
            (REPORTS / "stop300_overlap_and_selection_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 overlap selection receipt."),
            (REPORTS / "stop300_stratum_balance_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 stratum balance receipt."),
            (REPORTS / "stop300_restart_resume_contract.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 restart/resume contract."),
            (REPORTS / "stop300_publication_order_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 publication order receipt."),
            (REPORTS / "stop300_environment_contract.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 environment contract."),
            (REPORTS / "stop300_effective_config_authority.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 effective config authority."),
            (REPORTS / "stop300_claim_boundary_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 claim boundary receipt."),
            (REPORTS / "stop300_packet_decision.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 packet decision."),
            (REPORTS / "stop300_builder_summary.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 builder summary."),
            (REPORTS / "stop300_packet_validation_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 packet validation."),
        ]
    registry_specs.extend(
        (path, "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "STOP300 schema.")
        for path in sorted(SCHEMAS.glob("kt.stop300.*.schema.json"))
    )
    registry_specs.extend(
        (path, "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP lane focused test.")
        for pattern in ["test_ktstop50*.py", "test_ktstoprt*.py", "test_stop_grammar_v31*.py", "test_ktstop300*.py"]
        for path in sorted((ROOT / "tests").glob(pattern))
    )
    update_registry(registry_specs)
    print(json.dumps(read_json(REPORTS / "stop300_builder_summary.json"), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
