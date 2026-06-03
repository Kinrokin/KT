from __future__ import annotations

import hashlib
import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "admission" / "v17_7_4_realbench_row_manifest.json"
DATASET_SERVER = "https://datasets-server.huggingface.co/rows"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fetch_rows(dataset: str, config: str, split: str, length: int) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode(
        {
            "dataset": dataset,
            "config": config,
            "split": split,
            "offset": 0,
            "length": length,
        }
    )
    with urllib.request.urlopen(f"{DATASET_SERVER}?{query}", timeout=45) as response:
        payload = json.load(response)
    rows = payload.get("rows", [])
    if len(rows) < length:
        raise RuntimeError(f"dataset fetch returned {len(rows)} rows for {dataset}/{config}/{split}, expected {length}")
    return rows[:length]


def gsm8k_rows(count: int) -> list[dict[str, Any]]:
    rows = []
    for item in fetch_rows("openai/gsm8k", "main", "test", count):
        raw = item["row"]
        answer = str(raw["answer"]).split("####")[-1].strip()
        question = str(raw["question"]).strip()
        rows.append(make_row("gsm8k", "test", item["row_idx"], question, answer, "formal_math", "numeric_final_answer", "exact_normalized"))
    return rows


def arc_rows(count: int) -> list[dict[str, Any]]:
    rows = []
    for item in fetch_rows("allenai/ai2_arc", "ARC-Challenge", "test", count):
        raw = item["row"]
        labels = raw["choices"]["label"]
        texts = raw["choices"]["text"]
        choices = "\n".join(f"{label}. {text}" for label, text in zip(labels, texts))
        question = f"{raw['question']}\nChoices:\n{choices}"
        answer = str(raw["answerKey"]).strip()
        rows.append(make_row("arc_challenge", "test", item["row_idx"], question, answer, "science_reasoning", "multiple_choice_letter", "multiple_choice_letter"))
    return rows


def hellaswag_rows(count: int) -> list[dict[str, Any]]:
    rows = []
    for item in fetch_rows("Rowan/hellaswag", "default", "validation", count):
        raw = item["row"]
        labels = ["A", "B", "C", "D"]
        endings = raw["endings"]
        choices = "\n".join(f"{label}. {ending}" for label, ending in zip(labels, endings))
        question = f"Complete the scenario: {raw['ctx']}\nChoices:\n{choices}"
        answer = labels[int(raw["label"])]
        rows.append(make_row("hellaswag", "validation", item["row_idx"], question, answer, "commonsense_completion", "multiple_choice_letter", "multiple_choice_letter"))
    return rows


def make_row(
    dataset: str,
    split: str,
    row_idx: int,
    question: str,
    answer: str,
    task_family: str,
    answer_type: str,
    scoring_rule: str,
) -> dict[str, Any]:
    sample_id = f"{dataset}:{split}:{row_idx}"
    return {
        "schema_id": "kt.v17_7_4.truegen_row.v1",
        "sample_id": sample_id,
        "dataset": dataset,
        "split": split,
        "task_family": task_family,
        "benchmark_source": "REAL_BENCHMARK_ROW",
        "question_text": question,
        "question_text_hash": sha256_text(question),
        "expected_answer": answer,
        "expected_answer_hash": sha256_text(answer),
        "expected_label_or_oracle_label": answer,
        "answer_type": answer_type,
        "answer_format_contract": "Emit only the final answer. For multiple choice, emit only the option letter.",
        "source_hash": sha256_text(json.dumps({"sample_id": sample_id, "question": question, "answer": answer}, sort_keys=True)),
        "leakage_status": "PUBLIC_BENCHMARK_ROW_NO_TRAINING_AUTHORITY",
        "prompt": question,
        "prompt_hash": sha256_text(question),
        "label_source": "PUBLIC_BENCHMARK_GROUND_TRUTH",
        "scoring_rule": scoring_rule,
        "holdout_status": "HELDOUT_NOT_FOR_PROMOTION",
        "evidence_band": "REAL_BENCHMARK_GAUGE",
        "route_boundary_class": "REAL_BENCHMARK_GAUGE",
        "source_replay_reference_if_any": {},
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "adapter_training_authorized": False,
        "router_training_authorized": False,
        "policy_optimization_authorized": False,
        "learned_router_superiority_claim": False,
        "v18_runtime_authority": False,
    }


def main() -> int:
    rows = [*gsm8k_rows(20), *arc_rows(15), *hellaswag_rows(15)]
    payload = {
        "schema_id": "kt.v17_7_4.realbench_row_manifest.v1",
        "status": "PASS",
        "selection_source": "HF_DATASET_VIEWER_PUBLIC_BENCHMARK_ROWS",
        "row_count": len(rows),
        "measurement_mode": "REAL_BENCHMARK_GAUGE",
        "row_target_default": 50,
        "rows": rows,
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "adapter_training_authorized": False,
        "router_training_authorized": False,
        "policy_optimization_authorized": False,
        "learned_router_superiority_claim": False,
        "v18_runtime_authority": False,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({"path": OUTPUT.as_posix(), "row_count": len(rows), "sha256": sha256_text(OUTPUT.read_text(encoding="utf-8"))}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
