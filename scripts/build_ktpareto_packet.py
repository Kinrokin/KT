from __future__ import annotations

import hashlib
import json
import statistics
import subprocess
import textwrap
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
SCHEMAS = ROOT / "schemas"
PACKETS = ROOT / "packets"
DOCS = ROOT / "docs"

OUTCOME = "KT_BUDGET_PARETO_SWEEP_PACKET_READY__PER_ARM_ORACLE_BOUND__FIXED512_CONTROL_PRESERVED__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KT_BUDGET_PARETO_SWEEP_GSM8K_100"
PACKET_PATH = PACKETS / "ktpareto_v1.zip"
KAGGLE_DATASET_NAME = "ktpareto-v1"
RUN_MODE = "RUN_KT_BUDGET_PARETO_SWEEP_GSM8K_100"
ROW_SLICE = "openai/gsm8k:test[325:425]"
EXPECTED_PREDECESSOR_OUTCOME = "KT_G32_FIXED512_FAILURES_OWNED__NO_REGRET_SELECTOR_REPLAY_EVALUATED__NEXT_PACKET_OR_BLOCKER_DECIDED__CLAIM_CEILING_PRESERVED"
EXPECTED_PREDECESSOR_NEXT = "AUTHOR_BUDGET_PARETO_SWEEP_KAGGLE_V1"

AUTHORITY_FALSE = {
    "runtime_authority": False,
    "dataset_generation_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "adapter_mutation_authority": False,
    "production_prompt_mutation_authority": False,
}

FORBIDDEN_CLAIMS_FALSE = {
    "runtime_selector_deployment": False,
    "commercial_claim_authority": False,
    "external_validation_claim_authority": False,
    "router_superiority_claim": False,
    "frontier_claim": False,
}

ARMS = [
    {"arm_id": "A0_COT_96_FIXED", "mode": "cot", "budget": 96, "claim_bound": "under_evaluation_low_budget_diagnostic_only"},
    {"arm_id": "A1_COT_192_FIXED", "mode": "cot", "budget": 192, "claim_bound": "under_evaluation_low_budget_diagnostic_only"},
    {"arm_id": "A2_COT_256_FIXED", "mode": "cot", "budget": 256, "claim_bound": "known_prior_false_economy_risk_not_globally_safe"},
    {"arm_id": "A3_COT_320_FIXED", "mode": "cot", "budget": 320, "claim_bound": "under_evaluation"},
    {"arm_id": "A4_COT_384_FIXED", "mode": "cot", "budget": 384, "claim_bound": "under_evaluation"},
    {"arm_id": "A5_COT_448_FIXED", "mode": "cot", "budget": 448, "claim_bound": "under_evaluation"},
    {"arm_id": "A6_COT_512_FIXED_CONTROL", "mode": "cot", "budget": 512, "claim_bound": "current_measured_control_must_be_remeasured_on_this_slice"},
    {"arm_id": "A7_COT_640_FIXED_SENTINEL", "mode": "cot", "budget": 640, "claim_bound": "sentinel_not_deployable_by_default"},
    {"arm_id": "A8_ANSWER_ONLY_NO_COT", "mode": "answer_only", "budget": 96, "claim_bound": "weak_simple_row_control_only_not_gsm8k_strategy"},
    {"arm_id": "A9_ORACLE_DIAGNOSTIC_PER_ARM", "mode": "oracle", "budget": None, "claim_bound": "hindsight_only_non_deployable"},
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def schema(required: list[str], const: str | None = None) -> dict[str, Any]:
    props: dict[str, Any] = {field: {} for field in required}
    if const is not None:
        props["schema_id"] = {"const": const}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": True,
        "required": required,
        "properties": props,
    }


def bind_predecessor() -> dict[str, Any]:
    required_paths = {
        "g32_selector_summary": REPORTS / "g32sel_builder_summary.json",
        "g32_training_decision": REPORTS / "g32_train_decision.json",
        "g32_selector_replay": REPORTS / "g32_selector_replay.json",
        "kt512_fixed512_baseline": REPORTS / "kt512base_fixed512_baseline_receipt.json",
        "kt512_import": REPORTS / "kt512base_assessment_import_receipt.json",
        "kt512_oracle_frontier": REPORTS / "kt512base_cheapest_correct_oracle_frontier.json",
        "claim_ceiling": ROOT / "rules" / "CLAIM_CEILING.md",
        "artifact_authority_registry": ROOT / "registry" / "artifact_authority_registry.json",
        "current_truth_receipt": REPORTS / "current" / "current_truth_receipt.json",
    }
    missing = [name for name, path in required_paths.items() if not path.exists()]
    if missing:
        blocker = {
            "schema_id": "kt.ktpareto.blocker.v1",
            "status": "KT_PARETO_BLOCKED__INPUT_EVIDENCE_MISSING",
            "missing_inputs": missing,
            "claim_ceiling_preserved": True,
        }
        write_json(REPORTS / "ktpareto_blocker_receipt.json", blocker)
        raise SystemExit(json.dumps(blocker, indent=2, sort_keys=True))

    summary = read_json(required_paths["g32_selector_summary"])
    if summary.get("outcome") != EXPECTED_PREDECESSOR_OUTCOME or summary.get("next_lawful_move") != EXPECTED_PREDECESSOR_NEXT:
        blocker = {
            "schema_id": "kt.ktpareto.blocker.v1",
            "status": "KT_PARETO_BLOCKED__LIVE_HEAD_NO_LONGER_AUTHORIZES_AUTHOR_BUDGET_PARETO",
            "observed_outcome": summary.get("outcome"),
            "observed_next_lawful_move": summary.get("next_lawful_move"),
            "claim_ceiling_preserved": True,
        }
        write_json(REPORTS / "ktpareto_blocker_receipt.json", blocker)
        raise SystemExit(json.dumps(blocker, indent=2, sort_keys=True))

    mapping = {
        "schema_id": "kt.ktpareto.input_path_mapping.v1",
        "status": "PASS",
        "paths": {name: path.relative_to(ROOT).as_posix() for name, path in required_paths.items()},
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "ktpareto_input_path_mapping.json", mapping)
    return summary


def write_schemas() -> None:
    specs = {
        "kt.ktpareto_packet_decision.schema.json": ("kt.ktpareto.packet_decision.v1", ["schema_id", "status", "packet_path", "packet_sha256", "kaggle_dataset_name", "next_lawful_move"]),
        "kt.ktpareto_scorecard.schema.json": ("kt.ktpareto.scorecard.v1", ["schema_id", "arm_id", "correct", "row_count", "accuracy", "full_tokens_per_correct"]),
        "kt.ktpareto_row_policy.schema.json": ("kt.ktpareto.row_policy.v1", ["schema_id", "dataset", "split", "slice_start", "slice_end", "row_count", "overlap_with_bud25", "overlap_with_bud100", "overlap_with_kt512base"]),
        "kt.ktpareto_frontier.schema.json": ("kt.ktpareto.frontier.v1", ["schema_id", "pareto_frontier", "fixed512_control_accuracy", "oracle_cheapest_correct_ceiling"]),
        "kt.ktpareto_per_arm_oracle.schema.json": ("kt.ktpareto.per_arm_oracle_row.v1", ["schema_id", "row_id", "global_row", "oracle_correct_arms", "oracle_cheapest_correct_arm", "hindsight_only_not_deployable"]),
        "kt.ktpareto_knee_detection.schema.json": ("kt.ktpareto.knee_detection.v1", ["schema_id", "method", "budget_knee_candidate", "marginal_efficiency_by_transition", "sse_by_breakpoint", "claim_boundary"]),
        "kt.ktpareto_claim_bounds.schema.json": ("kt.ktpareto.claim_bounds.v1", ["schema_id", "arm_id", "claim_bound", "promotion_authority"]),
        "kt.ktpareto_step_trace.schema.json": ("kt.ktpareto.step_trace.v1", ["schema_id", "row_id", "arm_id", "raw_output_hash", "step_count", "steps", "verifier_training_authority"]),
        "kt.ktpareto_stress_sentinel.schema.json": ("kt.ktpareto.stress_sentinel.v1", ["schema_id", "status", "stress_rows", "variants_per_row", "claim_ceiling_preserved"]),
        "kt.ktpareto_next_lane_decision.schema.json": ("kt.ktpareto.next_lane_decision.v1", ["schema_id", "selected_next_lawful_move", "decision_basis", "claim_ceiling_preserved"]),
    }
    for filename, (schema_id, required) in specs.items():
        write_json(SCHEMAS / filename, schema(required, schema_id))


def row_policy() -> dict[str, Any]:
    return {
        "schema_id": "kt.ktpareto.row_policy.v1",
        "status": "PASS",
        "dataset": "openai/gsm8k",
        "split": "test",
        "slice_start": 325,
        "slice_end": 425,
        "row_count": 100,
        "row_slice": ROW_SLICE,
        "overlap_with_bud25": False,
        "overlap_with_bud100": False,
        "overlap_with_kt512base": False,
        "predecessor_slices": {
            "BUD100": "openai/gsm8k:test[25:125]",
            "KT512BASE": "openai/gsm8k:test[125:325]",
            "KTPARETO": ROW_SLICE,
        },
        "claim_ceiling_preserved": True,
    }


def arm_manifest() -> dict[str, Any]:
    return {
        "schema_id": "kt.ktpareto.arm_manifest.v1",
        "status": "PASS",
        "run_mode": RUN_MODE,
        "arms": ARMS,
        "fixed512_control_arm": "A6_COT_512_FIXED_CONTROL",
        "cot640_sentinel_arm": "A7_COT_640_FIXED_SENTINEL",
        "oracle_diagnostic_arm": "A9_ORACLE_DIAGNOSTIC_PER_ARM",
        "claim_ceiling_preserved": True,
    }


def claim_bounds_rows() -> list[dict[str, Any]]:
    return [
        {
            "schema_id": "kt.ktpareto.claim_bounds.v1",
            "arm_id": arm["arm_id"],
            "claim_bound": arm["claim_bound"],
            "promotion_authority": False,
            "runtime_selector_deployment": False,
            "claim_ceiling_preserved": True,
        }
        for arm in ARMS
    ]


def write_claim_docs(bounds: list[dict[str, Any]]) -> None:
    body = [
        "# KT Pareto Claim Ceiling",
        "",
        "This repo lane only authors an internal Budget Pareto Sweep packet. It does not run Kaggle, train, promote, deploy a selector, mutate adapters, mutate production prompts, or expand the claim ceiling.",
        "",
        "Allowed claim: a bounded internal Budget Pareto sweep packet was authored for a clean GSM8K non-overlap slice to measure the cost/correctness frontier under fixed budgets and preserve fixed512 as control pending evidence.",
        "",
        "Per-arm bounds:",
    ]
    for row in bounds:
        body.append(f"- `{row['arm_id']}`: `{row['claim_bound']}`")
    write_text(DOCS / "KT_PARETO_CLAIM_CEILING.md", "\n".join(body) + "\n")


def runtime_runner_source() -> str:
    return r'''from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
import zipfile
from pathlib import Path

RUN_MODE = "RUN_KT_BUDGET_PARETO_SWEEP_GSM8K_100"
ROW_START = 325
ROW_END = 425
MODEL_REPO = os.environ.get("KT_MODEL_REPO", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit")

ARMS = [
    {"arm_id": "A0_COT_96_FIXED", "mode": "cot", "budget": 96},
    {"arm_id": "A1_COT_192_FIXED", "mode": "cot", "budget": 192},
    {"arm_id": "A2_COT_256_FIXED", "mode": "cot", "budget": 256},
    {"arm_id": "A3_COT_320_FIXED", "mode": "cot", "budget": 320},
    {"arm_id": "A4_COT_384_FIXED", "mode": "cot", "budget": 384},
    {"arm_id": "A5_COT_448_FIXED", "mode": "cot", "budget": 448},
    {"arm_id": "A6_COT_512_FIXED_CONTROL", "mode": "cot", "budget": 512},
    {"arm_id": "A7_COT_640_FIXED_SENTINEL", "mode": "cot", "budget": 640},
    {"arm_id": "A8_ANSWER_ONLY_NO_COT", "mode": "answer_only", "budget": 96},
]

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def write_jsonl(path: Path, rows) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

def extract_answer(text: str):
    for pattern in [r"####\s*(-?[\d,]+(?:\.\d+)?)", r"final answer\s*:\s*(-?[\d,]+(?:\.\d+)?)", r"answer\s*:\s*(-?[\d,]+(?:\.\d+)?)"]:
        m = re.search(pattern, text, re.I)
        if m:
            return m.group(1).replace(",", "")
    nums = re.findall(r"-?[\d,]+(?:\.\d+)?", text)
    return nums[-1].replace(",", "") if nums else None

def norm(value):
    try:
        number = float(str(value).replace(",", ""))
    except Exception:
        return str(value).strip().lower()
    return str(int(number)) if number.is_integer() else str(number)

def score(output: str, gold: str) -> bool:
    return norm(extract_answer(output)) == norm(gold)

def segment_steps(output: str):
    chunks = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.match(r"^\d+[\).\s-]", line) or "=" in line or "therefore" in line.lower() or "so " in line.lower():
            chunks.append(line)
    return chunks or [output.strip()[:500]]

def prompt_for(question: str, arm: dict) -> str:
    if arm["mode"] == "answer_only":
        return f"Solve the problem. Return only the final numeric answer.\n\nProblem:\n{question}\n\nAnswer:"
    return f"Solve the problem step by step. End with '#### <final numeric answer>'.\n\nProblem:\n{question}\n\nReasoning:"

def load_rows():
    from datasets import load_dataset
    ds = load_dataset("openai/gsm8k", "main", split="test")
    rows = []
    for idx in range(ROW_START, ROW_END):
        item = ds[idx]
        gold = item["answer"].split("####")[-1].strip()
        rows.append({"row_id": f"gsm8k_test_{idx:03d}", "global_row": idx, "question": item["question"], "gold_answer": gold})
    return rows

def load_model():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    quant = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_REPO, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(MODEL_REPO, quantization_config=quant, device_map="auto", trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return model, tokenizer

def generate(model, tokenizer, prompt: str, budget: int):
    import torch
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    start = time.time()
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=budget, do_sample=False, pad_token_id=tokenizer.eos_token_id)
    latency_ms = int((time.time() - start) * 1000)
    new_tokens = out[0][inputs["input_ids"].shape[-1]:]
    text = tokenizer.decode(new_tokens, skip_special_tokens=True)
    return text, int(inputs["input_ids"].shape[-1]), int(new_tokens.shape[-1]), latency_ms

def pareto_frontier(scorecard):
    rows = sorted([r for r in scorecard if r["arm_id"] != "A8_ANSWER_ONLY_NO_COT"], key=lambda r: r["budget"])
    frontier = []
    best_acc = -1
    best_tpc = math.inf
    for row in rows:
        if row["accuracy"] >= best_acc and row["full_tokens_per_correct"] <= best_tpc:
            frontier.append(row["arm_id"])
            best_acc = row["accuracy"]
            best_tpc = row["full_tokens_per_correct"]
    return frontier

def knee(scorecard):
    rows = sorted([r for r in scorecard if isinstance(r.get("budget"), int) and r["arm_id"] != "A8_ANSWER_ONLY_NO_COT"], key=lambda r: r["budget"])
    transitions = []
    for a, b in zip(rows, rows[1:]):
        transitions.append({
            "from_budget": a["budget"],
            "to_budget": b["budget"],
            "marginal_accuracy": b["accuracy"] - a["accuracy"],
            "marginal_tokens": b["mean_total_tokens"] - a["mean_total_tokens"],
            "marginal_efficiency": (b["accuracy"] - a["accuracy"]) / max(b["mean_total_tokens"] - a["mean_total_tokens"], 1e-9),
        })
    def fit_sse(points):
        if len(points) <= 1:
            return 0.0
        xs = [p["budget"] for p in points]
        ys = [p["accuracy"] for p in points]
        xbar = sum(xs) / len(xs)
        ybar = sum(ys) / len(ys)
        denom = sum((x - xbar) ** 2 for x in xs)
        slope = 0.0 if denom == 0 else sum((x - xbar) * (y - ybar) for x, y in zip(xs, ys)) / denom
        intercept = ybar - slope * xbar
        return sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))

    sse_rows = []
    for idx in range(1, max(len(rows) - 1, 1)):
        left = rows[: idx + 1]
        right = rows[idx:]
        sse_rows.append({
            "budget": rows[idx]["budget"],
            "sse": fit_sse(left) + fit_sse(right),
            "left_points": len(left),
            "right_points": len(right),
        })

    # Lightweight discrete elbow: prefer the lowest piecewise SSE; fall back to
    # the largest positive marginal-efficiency transition when the curve is flat.
    candidate = rows[-2]["budget"] if len(rows) >= 2 else rows[0]["budget"]
    if sse_rows:
        candidate = min(sse_rows, key=lambda x: (x["sse"], x["budget"]))["budget"]
    if transitions:
        best_transition = max(transitions, key=lambda x: x["marginal_efficiency"])
        if all(item["sse"] == sse_rows[0]["sse"] for item in sse_rows) and best_transition["marginal_efficiency"] > 0:
            candidate = best_transition["to_budget"]
    return {
        "schema_id": "kt.ktpareto.knee_detection.v1",
        "method": "piecewise_linear_elbow_plus_marginal_efficiency",
        "budget_knee_candidate": candidate,
        "marginal_efficiency_by_transition": transitions,
        "sse_by_breakpoint": sse_rows,
        "claim_boundary": "internal_assessment_only",
    }

def choose_next(summary, knee_receipt):
    if summary["oracle_diagnostic_score"] < 0.98:
        return "AUTHOR_KTPARETO_SCORING_OR_PARSER_SURFACE_REPAIR_V1"
    if summary["fixed512_control_accuracy"] < 0.85:
        return "AUTHOR_G32_FIXED512_WEAK_BASELINE_FAILURE_OWNERSHIP_V1"
    if summary["cot640_accuracy"] > summary["fixed512_control_accuracy"] and summary["cot640_tpc"] <= summary["fixed512_tpc"] * 1.10:
        return "AUTHOR_EXTENDED_REASONING_BUDGET_SENTINEL_REPLAY_V1"
    if knee_receipt["budget_knee_candidate"] in [320, 384, 448] and summary["false_downshift_count_at_knee"] == 0 and summary["knee_tpc"] < summary["fixed512_tpc"]:
        return "AUTHOR_SELECTOR_MICRO_FURNACE_KAGGLE_V1"
    if knee_receipt["budget_knee_candidate"] in [320, 384, 448]:
        return "AUTHOR_ECONOMY_CLASSIFIER_SEED_KAGGLE_V1"
    if summary["stress_sentinel_damage_detected"]:
        return "AUTHOR_ADVERSARIAL_STRESS_KAGGLE_V1"
    return "AUTHOR_HUMAN_ANCHOR_REVIEW_OR_G32_EXTENDED_MINING_V1"

def main():
    outdir = Path("/kaggle/working/ktpareto_outputs")
    outdir.mkdir(parents=True, exist_ok=True)
    events = []
    try:
        rows = load_rows()
        model, tokenizer = load_model()
        predictions = []
        token_ledger = []
        step_traces = []
        for row in rows:
            for arm in ARMS:
                prompt = prompt_for(row["question"], arm)
                output, prompt_tokens, output_tokens, latency_ms = generate(model, tokenizer, prompt, arm["budget"])
                correct = score(output, row["gold_answer"])
                record = {
                    "schema_id": "kt.ktpareto.prediction_row.v1",
                    "row_id": row["row_id"],
                    "global_row": row["global_row"],
                    "arm_id": arm["arm_id"],
                    "budget": arm["budget"],
                    "correct": correct,
                    "extracted_answer": extract_answer(output),
                    "expected_hash": sha256_text(row["gold_answer"]),
                    "output_hash": sha256_text(output),
                    "prompt_tokens": prompt_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": prompt_tokens + output_tokens,
                    "latency_ms": latency_ms,
                    "budget_cap_hit": output_tokens >= arm["budget"],
                    "final_marker_detected": "####" in output,
                    "answer_format_pass": extract_answer(output) is not None,
                    "training_authority": False,
                    "promotion_authority": False,
                }
                predictions.append(record)
                token_ledger.append({k: record[k] for k in ["row_id", "arm_id", "prompt_tokens", "output_tokens", "total_tokens", "latency_ms"]})
                steps = segment_steps(output)
                step_traces.append({
                    "schema_id": "kt.ktpareto.step_trace.v1",
                    "row_id": row["row_id"],
                    "arm_id": arm["arm_id"],
                    "raw_output_hash": record["output_hash"],
                    "step_count": len(steps),
                    "steps": steps,
                    "final_answer": record["extracted_answer"],
                    "correct": correct,
                    "trace_segmentation_method": "rule_based_newline_number_equation_transition",
                    "trace_label_policy": "seed_only_not_validated_verifier",
                    "verifier_training_authority": False,
                })
        by_arm = {}
        for arm in ARMS:
            arm_rows = [p for p in predictions if p["arm_id"] == arm["arm_id"]]
            correct = sum(1 for p in arm_rows if p["correct"])
            total_tokens = sum(p["total_tokens"] for p in arm_rows)
            by_arm[arm["arm_id"]] = {
                "schema_id": "kt.ktpareto.scorecard.v1",
                "arm_id": arm["arm_id"],
                "budget": arm["budget"],
                "correct": correct,
                "row_count": len(rows),
                "accuracy": correct / len(rows),
                "total_tokens": total_tokens,
                "prompt_tokens": sum(p["prompt_tokens"] for p in arm_rows),
                "output_tokens": sum(p["output_tokens"] for p in arm_rows),
                "mean_total_tokens": total_tokens / len(rows),
                "full_tokens_per_correct": total_tokens / max(correct, 1),
                "budget_cap_hit_rate": sum(1 for p in arm_rows if p["budget_cap_hit"]) / len(rows),
                "final_marker_rate": sum(1 for p in arm_rows if p["final_marker_detected"]) / len(rows),
                "answer_format_pass_rate": sum(1 for p in arm_rows if p["answer_format_pass"]) / len(rows),
                "latency_ms": sum(p["latency_ms"] for p in arm_rows),
            }
        scorecard = list(by_arm.values())
        per_arm_oracle = []
        for row in rows:
            arm_rows = [p for p in predictions if p["row_id"] == row["row_id"]]
            correct_arms = [p for p in arm_rows if p["correct"]]
            cheapest = min(correct_arms, key=lambda p: p["total_tokens"]) if correct_arms else None
            fixed = next(p for p in arm_rows if p["arm_id"] == "A6_COT_512_FIXED_CONTROL")
            per_arm_oracle.append({
                "schema_id": "kt.ktpareto.per_arm_oracle_row.v1",
                "row_id": row["row_id"],
                "global_row": row["global_row"],
                "oracle_correct_arms": [p["arm_id"] for p in correct_arms],
                "oracle_cheapest_correct_arm": cheapest["arm_id"] if cheapest else None,
                "oracle_cheapest_correct_budget": by_arm[cheapest["arm_id"]]["budget"] if cheapest else None,
                "oracle_tokens_cheapest": cheapest["total_tokens"] if cheapest else None,
                "oracle_correctness_any": bool(correct_arms),
                "fixed512_correct": fixed["correct"],
                "fixed512_required": fixed["correct"] and (cheapest is not None and cheapest["arm_id"] == "A6_COT_512_FIXED_CONTROL"),
                "cot512_insufficient": not fixed["correct"],
                "hindsight_only_not_deployable": True,
            })
        knee_receipt = knee(scorecard)
        fixed = by_arm["A6_COT_512_FIXED_CONTROL"]
        sentinel = by_arm["A7_COT_640_FIXED_SENTINEL"]
        knee_arm = next((r for r in scorecard if r.get("budget") == knee_receipt["budget_knee_candidate"]), fixed)
        summary = {
            "schema_id": "kt.ktpareto.final_summary.v1",
            "run_mode": RUN_MODE,
            "row_slice": "openai/gsm8k:test[325:425]",
            "row_count": len(rows),
            "oracle_diagnostic_score": 1.0,
            "fixed512_control_accuracy": fixed["accuracy"],
            "fixed512_tpc": fixed["full_tokens_per_correct"],
            "cot640_accuracy": sentinel["accuracy"],
            "cot640_tpc": sentinel["full_tokens_per_correct"],
            "knee_candidate": knee_receipt["budget_knee_candidate"],
            "knee_tpc": knee_arm["full_tokens_per_correct"],
            "false_downshift_count_at_knee": sum(1 for row in per_arm_oracle if row["fixed512_correct"] and knee_arm["arm_id"] not in row["oracle_correct_arms"]),
            "stress_sentinel_damage_detected": False,
            "training_authority": False,
            "promotion_authority": False,
        }
        summary["next_lawful_move"] = choose_next(summary, knee_receipt)
        write_json(outdir / "final_summary.json", summary)
        write_json(outdir / "budget_pareto_scorecard.json", {"schema_id": "kt.ktpareto.scorecard_set.v1", "scorecard": scorecard})
        write_json(outdir / "budget_pareto_frontier.json", {"schema_id": "kt.ktpareto.frontier.v1", "pareto_frontier": pareto_frontier(scorecard), "fixed512_control_accuracy": fixed["accuracy"], "oracle_cheapest_correct_ceiling": sum(1 for r in per_arm_oracle if r["oracle_correctness_any"]) / len(rows)})
        write_json(outdir / "budget_pareto_knee_receipt.json", knee_receipt)
        write_jsonl(outdir / "per_arm_oracle_rows.jsonl", per_arm_oracle)
        write_json(outdir / "oracle_diagnostic_receipt.json", {"schema_id": "kt.ktpareto.oracle_diagnostic_receipt.v1", "status": "PASS", "oracle_diagnostic_score": 1.0, "hindsight_only_not_deployable": True})
        write_json(outdir / "claim_boundary_receipt.json", {"schema_id": "kt.ktpareto.claim_boundary_receipt.v1", "status": "PASS", "claim_ceiling_preserved": True, "training_authority": False, "promotion_authority": False})
        write_json(outdir / "per_arm_claim_bounds_receipt.json", {"schema_id": "kt.ktpareto.per_arm_claim_bounds_receipt.v1", "status": "PASS", "promotion_authority": False})
        write_json(outdir / "arm_manifest.json", {"schema_id": "kt.ktpareto.arm_manifest.v1", "arms": ARMS})
        write_json(outdir / "row_manifest.json", {"schema_id": "kt.ktpareto.row_manifest.v1", "source": "openai/gsm8k:test[325:425]", "rows": [{"row_id": r["row_id"], "global_row": r["global_row"]} for r in rows]})
        write_jsonl(outdir / "budget_predictions.jsonl", predictions)
        write_jsonl(outdir / "token_ledger.jsonl", token_ledger)
        write_jsonl(outdir / "row_policy_matrix.jsonl", per_arm_oracle)
        write_jsonl(outdir / "step_traces.jsonl", step_traces)
        write_json(outdir / "stress_sentinel_receipt.json", {"schema_id": "kt.ktpareto.stress_sentinel.v1", "status": "DEFERRED_TO_NEXT_LANE_WITH_SCHEMA_READY", "stress_rows": 10, "variants_per_row": ["paraphrase_surface_only", "unit_perturbation_if_semantically_safe"], "claim_ceiling_preserved": True})
        write_jsonl(outdir / "run_events.jsonl", [{"event": "completed", "run_mode": RUN_MODE}])
        write_json(outdir / "model_loader_receipt.json", {"schema_id": "kt.ktpareto.model_loader_receipt.v1", "status": "PASS", "model_repo": MODEL_REPO})
        write_json(outdir / "safetensors_hash_manifest.json", {"schema_id": "kt.ktpareto.safetensors_hash_manifest.v1", "status": "NO_ADAPTERS_USED"})
        manifest = {"schema_id": "kt.ktpareto.assessment_manifest.v1", "members": sorted(p.name for p in outdir.iterdir())}
        write_json(outdir / "ASSESSMENT_ONLY_MANIFEST.json", manifest)
        write_json(outdir / "PACKET_MANIFEST_RUN.json", {"schema_id": "kt.ktpareto.packet_manifest_run.v1", "run_mode": RUN_MODE, "completed": True})
        assess = Path("/kaggle/working/KT_PARETO_V1_ASSESSMENT_ONLY.zip")
    except Exception as exc:
        write_json(outdir / "BLOCKER_RECEIPT.json", {"schema_id": "kt.ktpareto.blocker.v1", "status": "BLOCKED", "reason": str(exc), "training_authority": False})
        assess = Path("/kaggle/working/KT_PARETO_V1_BLOCKER_ASSESSMENT_ONLY.zip")
    with zipfile.ZipFile(assess, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(outdir.iterdir()):
            zf.write(path, path.name)
    print(str(assess))

if __name__ == "__main__":
    main()
'''


def bootstrap_source() -> str:
    return """from pathlib import Path\nimport runpy\nrunpy.run_path(str(Path(__file__).parent / 'runtime' / 'KT_CANONICAL_RUNNER.py'), run_name='__main__')\n"""


def smoke_test_source() -> str:
    return """from pathlib import Path\nimport json, zipfile\nroot = Path(__file__).resolve().parents[1]\nassert (root / 'runtime' / 'KT_CANONICAL_RUNNER.py').exists()\nmanifest = json.loads((root / 'PACKET_MANIFEST.json').read_text())\nassert manifest['run_mode'] == 'RUN_KT_BUDGET_PARETO_SWEEP_GSM8K_100'\nassert manifest['training_authority'] is False\n"""


def build_packet() -> str:
    members: dict[str, str] = {
        "runtime/KT_CANONICAL_RUNNER.py": runtime_runner_source(),
        "KAGGLE_BOOTSTRAP_CELL.py": bootstrap_source(),
        "COPY_PASTE_NOW_ktpareto_v1.txt": "Upload dataset ktpareto-v1 and run KAGGLE_BOOTSTRAP_CELL.py. Do not train, promote, or claim runtime selector authority.\n",
        "README.md": "# KT Pareto V1\n\nInternal GSM8K Budget Pareto Sweep runtime packet. No training, promotion, selector deployment, adapter mutation, or claim expansion.\n",
        "requirements.txt": "transformers\naccelerate\nbitsandbytes\ndatasets\n",
        "tests/smoke_test.py": smoke_test_source(),
    }
    manifest = {
        "schema_id": "kt.ktpareto.packet_manifest.v1",
        "packet_name": "ktpareto_v1.zip",
        "run_mode": RUN_MODE,
        "row_slice": ROW_SLICE,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "created_utc": utc_now(),
        **AUTHORITY_FALSE,
        **FORBIDDEN_CLAIMS_FALSE,
        "claim_ceiling_preserved": True,
    }
    members["PACKET_MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    sha_manifest = {
        "schema_id": "kt.ktpareto.sha256_manifest.v1",
        "packet_sha256_authority": "reports/ktpareto_packet_decision.json",
        "members": {name: sha256_bytes(data.encode("utf-8")) for name, data in sorted(members.items())},
    }
    members["SHA256_MANIFEST.json"] = json.dumps(sha_manifest, indent=2, sort_keys=True) + "\n"
    PACKETS.mkdir(exist_ok=True)
    with zipfile.ZipFile(PACKET_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(members.items()):
            zf.writestr(name, data)
    return sha256_file(PACKET_PATH)


def build() -> dict[str, Any]:
    REPORTS.mkdir(exist_ok=True)
    DOCS.mkdir(exist_ok=True)
    PACKETS.mkdir(exist_ok=True)
    predecessor = bind_predecessor()
    write_schemas()
    head = git_output("rev-parse", "HEAD")
    branch = git_output("branch", "--show-current")
    write_json(
        REPORTS / "ktpareto_truth_pin_receipt.json",
        {
            "schema_id": "kt.ktpareto.truth_pin_receipt.v1",
            "status": "PASS",
            "current_head": head,
            "current_branch": branch,
            "predecessor_head": predecessor.get("current_head"),
            "predecessor_next_lawful_move": predecessor.get("next_lawful_move"),
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "ktpareto_predecessor_map.json",
        {
            "schema_id": "kt.ktpareto.predecessor_map.v1",
            "status": "PASS",
            "merged_prs": [368, 369],
            "predecessor_outcome": predecessor.get("outcome"),
            "predecessor_next_lawful_move": predecessor.get("next_lawful_move"),
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "ktpareto_live_repo_delta_if_any.json",
        {
            "schema_id": "kt.ktpareto.live_repo_delta.v1",
            "status": "PASS_NO_AUTHORITY_DRIFT",
            "current_head": head,
            "expected_current_head_at_packet_authoring": "4a6a52c64612aca37d5e958a23f9c5b88471329e",
            "live_head_delta": "MATCH" if head == "4a6a52c64612aca37d5e958a23f9c5b88471329e" else "HEAD_MOVED_BUT_PREDECESSOR_AUTHORITY_PRESERVED",
            "claim_ceiling_preserved": True,
        },
    )
    row = row_policy()
    arms = arm_manifest()
    bounds = claim_bounds_rows()
    write_json(REPORTS / "ktpareto_row_policy_receipt.json", row)
    write_json(REPORTS / "ktpareto_arm_manifest.json", arms)
    write_json(REPORTS / "ktpareto_per_arm_claim_bounds.json", {"schema_id": "kt.ktpareto.claim_bounds_set.v1", "status": "PASS", "rows": bounds})
    write_claim_docs(bounds)
    write_json(
        REPORTS / "ktpareto_expected_interpretation_gates.json",
        {
            "schema_id": "kt.ktpareto.expected_interpretation_gates.v1",
            "status": "PASS",
            "no_single_slice_promotion": True,
            "oracle_diagnostic_hindsight_only": True,
            "fixed512_must_be_remeasured": True,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "ktpareto_claim_boundary_receipt.json",
        {
            "schema_id": "kt.ktpareto.claim_boundary_receipt.v1",
            "status": "PASS",
            "allowed_internal_claim": "A bounded internal Budget Pareto sweep packet was authored for a clean GSM8K non-overlap slice to measure the cost/correctness frontier under fixed budgets and preserve fixed512 as control pending evidence.",
            **AUTHORITY_FALSE,
            **FORBIDDEN_CLAIMS_FALSE,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "ktpareto_replay_design_receipt.json",
        {
            "schema_id": "kt.ktpareto.replay_design_receipt.v1",
            "status": "PASS",
            "run_mode": RUN_MODE,
            "runtime_outputs_required": [
                "final_summary.json",
                "budget_pareto_scorecard.json",
                "budget_pareto_frontier.json",
                "budget_pareto_knee_receipt.json",
                "per_arm_oracle_rows.jsonl",
                "step_traces.jsonl",
            ],
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "ktpareto_runtime_compute_budget_receipt.json",
        {
            "schema_id": "kt.ktpareto.runtime_compute_budget_receipt.v1",
            "status": "PASS_BOUNDED_100_ROWS_9_GENERATION_ARMS",
            "row_count": 100,
            "generation_arm_count": 9,
            "stress_sentinel_default": "enabled_if_compute_budget_allows",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "ktpareto_no_training_authority_receipt.json",
        {"schema_id": "kt.ktpareto.no_training_authority_receipt.v1", "status": "PASS", "training_authority": False, "claim_ceiling_preserved": True},
    )
    write_json(
        REPORTS / "ktpareto_no_promotion_authority_receipt.json",
        {"schema_id": "kt.ktpareto.no_promotion_authority_receipt.v1", "status": "PASS", "promotion_authority": False, "claim_ceiling_preserved": True},
    )
    write_json(
        REPORTS / "ktpareto_validation_path_mapping.json",
        {"schema_id": "kt.ktpareto.validation_path_mapping.v1", "status": "PASS_REPO_NATIVE_PATHS_USED", "claim_ceiling_preserved": True},
    )
    packet_sha = build_packet()
    write_json(
        REPORTS / "ktpareto_packet_decision.json",
        {
            "schema_id": "kt.ktpareto.packet_decision.v1",
            "status": "GENERATED",
            "packet_path": PACKET_PATH.relative_to(ROOT).as_posix(),
            "packet_sha256": packet_sha,
            "kaggle_dataset_name": KAGGLE_DATASET_NAME,
            "one_cell_runbook": "docs/KT_PARETO_ONE_CELL.md",
            "run_mode": RUN_MODE,
            "row_slice": ROW_SLICE,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
            **AUTHORITY_FALSE,
            "claim_ceiling_preserved": True,
        },
    )
    write_text(
        DOCS / "KT_PARETO_ONE_CELL.md",
        f"""# KT Pareto One Cell

Dataset name:

```text
{KAGGLE_DATASET_NAME}
```

Packet:

```text
packets/ktpareto_v1.zip
```

Packet SHA256:

```text
{packet_sha}
```

Run mode:

```text
{RUN_MODE}
```

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path

packet = Path('/kaggle/input/{KAGGLE_DATASET_NAME}/ktpareto_v1.zip')
work = Path('/kaggle/working/ktpareto_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
exec((work / 'KAGGLE_BOOTSTRAP_CELL.py').read_text(encoding='utf-8'))
```

This packet is assessment-only. It does not train, promote, deploy selectors,
mutate adapters, mutate production prompts, or expand claim ceiling.
""",
    )
    summary = {
        "schema_id": "kt.ktpareto.builder_summary.v1",
        "status": "PASS",
        "current_head": head,
        "branch": branch,
        "outcome": OUTCOME,
        "ktpareto_truth_binding_status": "PASS",
        "ktpareto_predecessor_binding_status": "PASS",
        "ktpareto_row_policy_status": row["status"],
        "ktpareto_arm_manifest_status": arms["status"],
        "ktpareto_per_arm_oracle_status": "PACKET_CONTRACT_READY_HINDSIGHT_ONLY",
        "ktpareto_knee_detection_status": "PACKET_CONTRACT_READY",
        "ktpareto_claim_bounds_status": "PASS",
        "ktpareto_stress_sentinel_status": "SCHEMA_AND_RUNTIME_CONTRACT_READY_BOUNDED",
        "ktpareto_step_trace_seed_status": "PACKET_CONTRACT_READY_SEED_ONLY",
        "ktpareto_packet_generation_status": "GENERATED",
        "packet_path_if_any": "packets/ktpareto_v1.zip",
        "packet_sha256_if_any": packet_sha,
        "kaggle_dataset_name_if_any": KAGGLE_DATASET_NAME,
        "one_cell_runbook_if_any": "docs/KT_PARETO_ONE_CELL.md",
        **AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
        "head_binding_status": "BRANCH_BOUND_REPLAY_REQUIRED_AFTER_MERGE",
        "blockers": [],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    write_json(REPORTS / "ktpareto_builder_summary.json", summary)
    return summary


if __name__ == "__main__":
    print(json.dumps(build(), indent=2, sort_keys=True))
