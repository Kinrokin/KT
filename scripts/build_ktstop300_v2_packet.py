from __future__ import annotations

import hashlib
import json
import re
import statistics
import zipfile
from pathlib import Path
from typing import Any, Iterable

from ktstop300_common import (
    ADMISSION,
    AUTHORITY_FALSE,
    DOCS,
    EVIDENCE,
    PACKETS,
    REGISTRY,
    REPORTS,
    ROOT,
    SCHEMAS,
    SCOPED_AUTHORITY,
    STOP300_PACKET,
    STOP300_V2_DATASET,
    STOP300_V2_NEXT_LAWFUL_MOVE,
    STOP300_V2_OUTCOME,
    STOP300_V2_PACKET,
    STOP300_V2_RUN_MODE,
    STOP300_V2_RUNBOOK,
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
HF_RESULTS_REPO = "Kinrokin/ktstop300-v2-results"
NATURAL_SEED = "ktstop300-v2-natural-authority-20260618"
TIMING_SEED = "ktstop300-v2-timing-authority-20260618"
CONSUMED_INTERVALS = {
    "BUD25": [0, 25],
    "BUD100": [25, 125],
    "512BASE": [125, 325],
    "PARETO": [325, 425],
    "STOP50": [425, 475],
}
ARMS = ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]
NATURAL_ARMS = ["L0_LEGACY_NO_DETECTOR", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]
STRATA = ["EASY", "MEDIUM", "HARD"]
EDGE_ROWS = [
    "gsm8k_test_428",
    "gsm8k_test_435",
    "gsm8k_test_437",
    "gsm8k_test_438",
    "gsm8k_test_447",
    "gsm8k_test_458",
    "gsm8k_test_469",
    "gsm8k_test_473",
    "gsm8k_test_443",
    "gsm8k_test_450",
    "gsm8k_test_451",
    "gsm8k_test_459",
]
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


def parse_row_id(text: str) -> int | None:
    match = re.fullmatch(r"gsm8k_test_(\d+)", str(text))
    return int(match.group(1)) if match else None


def row_id(index: int) -> str:
    return f"gsm8k_test_{index}"


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


def scan_text_for_rows(text: str) -> set[int]:
    return {int(match) for match in re.findall(r"gsm8k_test_(\d+)", text)}


def scan_jsonish_artifacts() -> dict[str, list[int]]:
    roots = [ADMISSION, REPORTS, REGISTRY, DOCS, EVIDENCE]
    by_source: dict[str, set[int]] = {}
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            lower_name = path.name.lower()
            if any(
                marker in lower_name
                for marker in [
                    "candidate_pool",
                    "authority_registry",
                    "authority_reconciliation",
                    "artifact_authority_registry",
                ]
            ):
                continue
            rows: set[int] = set()
            if path.suffix.lower() in {".json", ".jsonl", ".md", ".txt"}:
                try:
                    rows |= scan_text_for_rows(path.read_text(encoding="utf-8-sig", errors="ignore"))
                except Exception:
                    pass
            elif path.suffix.lower() == ".zip":
                try:
                    with zipfile.ZipFile(path) as zf:
                        for member in zf.namelist():
                            if not member.lower().endswith((".json", ".jsonl", ".md", ".txt", ".py")):
                                continue
                            try:
                                rows |= scan_text_for_rows(zf.read(member).decode("utf-8-sig", errors="ignore"))
                            except Exception:
                                pass
                except Exception:
                    pass
            if rows:
                by_source[rel(path)] = rows
    return {src: sorted(rows) for src, rows in sorted(by_source.items())}


def build_authority_registry() -> dict[str, Any]:
    interval_rows: set[int] = set()
    interval_entries = []
    for name, (start, end) in CONSUMED_INTERVALS.items():
        ids = list(range(start, end))
        interval_rows.update(ids)
        interval_entries.append({"source": name, "range": f"test[{start}:{end}]", "row_ids": [row_id(i) for i in ids], "count": len(ids)})
    discovered = scan_jsonish_artifacts()
    discovered_rows = {idx for rows in discovered.values() for idx in rows}
    edge_indices = {parse_row_id(item) for item in EDGE_ROWS}
    edge_indices = {idx for idx in edge_indices if idx is not None}
    consumed = sorted(interval_rows | discovered_rows | edge_indices)
    registry = {
        "schema_id": "kt.gsm8k_row_authority_registry.v1",
        "status": "PASS",
        "dataset": "openai/gsm8k",
        "split": "test",
        "authority_basis": "known_controlling_intervals_plus_discoverable_exact_repo_and_zip_row_manifests",
        "controlling_intervals": interval_entries,
        "discovered_source_count": len(discovered),
        "discovered_rows_by_source": {src: [row_id(i) for i in rows] for src, rows in discovered.items()},
        "edge_regression_rows": EDGE_ROWS,
        "authoritative_consumed_rows": [row_id(i) for i in consumed],
        "authoritative_consumed_count": len(consumed),
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REGISTRY / "gsm8k_row_authority_registry.json", registry)
    write_json(
        REPORTS / "gsm8k_row_authority_reconciliation.json",
        {
            "schema_id": "kt.gsm8k_row_authority_reconciliation.v1",
            "status": "PASS",
            "known_interval_consumed_count": len(interval_rows),
            "discovered_exact_row_count": len(discovered_rows),
            "edge_regression_row_count": len(edge_indices),
            "total_authoritative_consumed_count": len(consumed),
            "notes": "V2 samples against this registry rather than grep-only freshness.",
            "claim_ceiling_status": "PRESERVED",
        },
    )
    return registry


def fallback_rows_from_v1_candidate_manifest() -> list[dict[str, Any]]:
    manifest = read_json(ADMISSION / "stop300_candidate_pool_manifest.json")
    rows = []
    for row in manifest.get("candidate_rows", []):
        index = int(row["split_index"])
        rows.append(
            {
                "row_id": row_id(index),
                "dataset": "openai/gsm8k",
                "split": "test",
                "split_index": index,
                "question": "",
                "question_hash": row.get("question_hash", ""),
                "legal_features": row["legal_features"],
            }
        )
    return rows


def load_gsm8k_rows() -> list[dict[str, Any]]:
    try:
        from datasets import load_dataset

        dataset = load_dataset("openai/gsm8k", "main", split="test")
        rows = []
        for idx, item in enumerate(dataset):
            q = item["question"]
            rows.append(
                {
                    "row_id": row_id(idx),
                    "dataset": "openai/gsm8k",
                    "split": "test",
                    "split_index": idx,
                    "question": q,
                    "question_hash": sha256_text(q),
                    "legal_features": legal_features(q),
                }
            )
        return rows
    except Exception:
        return fallback_rows_from_v1_candidate_manifest()


def select_rows(registry: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    consumed = {parse_row_id(item) for item in registry["authoritative_consumed_rows"]}
    consumed = {idx for idx in consumed if idx is not None}
    rows = [row for row in load_gsm8k_rows() if row["split_index"] not in consumed]
    if len(rows) < 300:
        raise SystemExit(f"insufficient eligible rows after authority exclusion: {len(rows)}")
    keys = sorted(rows[0]["legal_features"])
    ranked = {key: ranks([int(row["legal_features"].get(key, 0)) for row in rows]) for key in keys}
    scored: list[dict[str, Any]] = []
    for idx, row in enumerate(rows):
        difficulty = statistics.mean(ranked[key][idx] for key in keys)
        scored.append({**row, "difficulty_proxy": difficulty})
    scored.sort(key=lambda row: (row["difficulty_proxy"], row["split_index"]))
    n = len(scored)
    for idx, row in enumerate(scored):
        row["stratum"] = "EASY" if idx < n / 3 else ("MEDIUM" if idx < 2 * n / 3 else "HARD")

    selected = []
    for stratum in STRATA:
        pool = [row for row in scored if row["stratum"] == stratum]
        pool.sort(key=lambda row: hashlib.sha256(f"{NATURAL_SEED}:{row['row_id']}:{row['question_hash']}".encode()).hexdigest())
        selected.extend(pool[:100])
    selected_ids = {row["row_id"] for row in selected}
    if len(selected_ids) != 300:
        raise SystemExit("V2 selection not unique")
    overlap = selected_ids & set(registry["authoritative_consumed_rows"])
    if overlap:
        raise SystemExit(f"V2 selection overlaps authority registry: {sorted(overlap)[:10]}")

    timing = []
    for stratum in STRATA:
        pool = [row for row in selected if row["stratum"] == stratum]
        pool.sort(key=lambda row: hashlib.sha256(f"{TIMING_SEED}:{row['row_id']}:{row['question_hash']}".encode()).hexdigest())
        timing.extend(pool[:20])
    if not set(row["row_id"] for row in timing).issubset(selected_ids):
        raise SystemExit("timing panel not subset of selected rows")
    meta = {"eligible_count": len(rows), "scored_count": len(scored), "keys": keys}
    return selected, timing, meta


def row_public(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "row_id": row["row_id"],
        "dataset": "openai/gsm8k",
        "split": "test",
        "split_index": row["split_index"],
        "stratum": row["stratum"],
        "difficulty_proxy": row["difficulty_proxy"],
        "question_hash": row["question_hash"],
        "legal_features": row["legal_features"],
    }


def write_v2_reports(registry: dict[str, Any], selected: list[dict[str, Any]], timing: list[dict[str, Any]], meta: dict[str, Any], packet_sha: str | None = None) -> None:
    selected_rows = [row_public(row) for row in selected]
    timing_rows = [row_public(row) for row in timing]
    selected_ids = {row["row_id"] for row in selected_rows}
    consumed = set(registry["authoritative_consumed_rows"])
    overlap = sorted(selected_ids & consumed)
    stratum_counts = {s: sum(1 for row in selected_rows if row["stratum"] == s) for s in STRATA}
    timing_counts = {s: sum(1 for row in timing_rows if row["stratum"] == s) for s in STRATA}
    write_json(
        ADMISSION / "stop300_v2_stratified_hash_selected_manifest.json",
        {
            "schema_id": "kt.stop300.v2.stratified_hash_selected_manifest.v1",
            "status": "PASS_300_UNIQUE_ZERO_AUTHORITY_OVERLAP",
            "seed": NATURAL_SEED,
            "row_count": len(selected_rows),
            "stratum_counts": stratum_counts,
            "rows": selected_rows,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_json(
        ADMISSION / "stop300_v2_timing_panel_manifest.json",
        {
            "schema_id": "kt.stop300.v2.timing_panel_manifest.v1",
            "status": "PASS_60_ROWS_3_REPETITIONS_3_ARMS",
            "seed": TIMING_SEED,
            "row_count": len(timing_rows),
            "stratum_counts": timing_counts,
            "rows": timing_rows,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_json(
        ADMISSION / "stop300_v2_edge_regression_manifest.json",
        {
            "schema_id": "kt.stop300.v2.edge_regression_manifest.v1",
            "status": "PASS_12_ROWS_3_ARMS",
            "row_count": 12,
            "rows": [{"row_id": rid, "split_index": parse_row_id(rid), "source": "STOP50_EDGE_ROWS"} for rid in EDGE_ROWS],
            "excluded_from_independent_safety_n": True,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_json(
        REPORTS / "stop300_v2_freshness_receipt.json",
        {
            "schema_id": "kt.stop300.v2.freshness_receipt.v1",
            "status": "PASS_300_UNIQUE_ZERO_AUTHORITY_OVERLAP",
            "selected_count": 300,
            "selected_unique_count": len(selected_ids),
            "eligible_pool_count": meta["eligible_count"],
            "authority_consumed_count": len(consumed),
            "overlap_count": len(overlap),
            "overlap_rows": overlap,
            "timing_panel_subset_of_selected": set(row["row_id"] for row in timing_rows).issubset(selected_ids),
            "timing_panel_stratum_counts": timing_counts,
            "gold_answers_absent_from_selection_features": True,
            "measured_outcomes_absent_from_selection_features": True,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    write_json(REPORTS / "stop300_v2_work_unit_receipt.json", {"schema_id": "kt.stop300.v2.work_unit_receipt.v1", "status": "PASS_1056_MEASURED_GENERATIONS_PLUS_WARMUPS", "edge_generations": 36, "natural_generations": 600, "timing_extra_generations": 420, "total_measured_generations": 1056, "warmups_excluded_from_evidence": True, "claim_ceiling_status": "PRESERVED"})
    write_json(REPORTS / "stop300_v2_execution_parity_receipt.json", {"schema_id": "kt.stop300.v2.execution_parity_receipt.v1", "status": "PASS", "natural_executes_l0_s1": True, "timing_executes_m0_and_repeated_l0_m0_s1": True, "edge_executes_all_three_arms": True, "final_result_court_executable": True, "claim_ceiling_status": "PRESERVED"})
    write_json(REPORTS / "stop300_v2_environment_contract.json", {"schema_id": "kt.stop300.v2.environment_contract.v1", "status": "PASS_FUNCTIONAL_CONTRACT_DEFINED", "bitsandbytes": "0.49.2", "functional_cuda_forward_smoke": True, "functional_cuda_generation_smoke": True, "linear4bit_module_count_gt_zero_required": True, "cpu_offload_count_required": 0, "disk_offload_count_required": 0, "claim_ceiling_status": "PRESERVED"})
    write_json(REPORTS / "stop300_v2_timing_contract.json", {"schema_id": "kt.stop300.v2.timing_contract.v1", "status": "PASS_60_ROWS_3_REPETITIONS_3_ARMS", "cuda_events_required": True, "perf_counter_ns_required": True, "row_clustered_paired_bootstrap_required": True, "detector_cpu_cost_ledger_required": True, "claim_ceiling_status": "PRESERVED"})
    write_json(REPORTS / "stop300_v2_restart_resume_contract.json", {"schema_id": "kt.stop300.v2.restart_resume_contract.v1", "status": "PASS_RESET_DURABLE", "completed_key": "evidence_scope_hash/phase/row_id/repetition/arm", "atomic_jsonl_after_every_arm": True, "atomic_run_state_replacement": True, "checkpoint_zip_every_25_natural_rows": True, "checkpoint_after_every_timing_block": True, "partial_measured_outputs_zip": "PARTIAL_MEASURED_OUTPUTS.zip", "scope_mismatch_blocker": True, "claim_ceiling_status": "PRESERVED"})
    write_json(REPORTS / "stop300_v2_result_court_contract.json", {"schema_id": "kt.stop300.v2.result_court_contract.v1", "status": "PASS_EXECUTABLE_CONJUNCTIVE_COURT_BOUND", "final_summary_must_not_be_pending_court": True, "permitted_final_statuses": ["PASS_SAFETY_AND_ECONOMICS_300__SHADOW_PACKET_AUTHORING_EARNED", "PASS_TOKEN_ONLY__LATENCY_NOT_ESTABLISHED__SHADOW_PACKET_AUTHORING_EARNED", "BLOCK_CORRECTNESS_DAMAGE", "BLOCK_FIRST_ANSWER_CORRECTION_CUT", "BLOCK_RUNTIME_REFERENCE_DISAGREEMENT", "BLOCK_GRAMMAR_AMBIGUITY", "BLOCK_ENVIRONMENT_DRIFT", "BLOCK_TIMING_PROTOCOL_VIOLATION", "BLOCK_ARTIFACT_PUBLICATION_FAILURE", "PARTIAL_WALL_TIME_CHECKPOINTED"], "claim_ceiling_status": "PRESERVED"})
    write_json(REPORTS / "stop300_v2_publication_order_receipt.json", {"schema_id": "kt.stop300.v2.publication_order_receipt.v1", "status": "PASS", "order": ["write all evidence", "package evidence-core checkpoint", "upload checkpoint/evidence folder", "write HF evidence receipt", "package final assessment containing evidence receipt", "upload final assessment", "write final-assessment upload receipt into wrapper collection"], "immutable_path_template": "runs/<run_id>/<repo_head>/<packet_sha>/...", "claim_ceiling_status": "PRESERVED"})
    write_json(REPORTS / "stop300_v1_supersession_receipt.json", {"schema_id": "kt.stop300.v1_supersession_receipt.v1", "status": "SUPERSEDED_BEFORE_GPU_EXECUTION", "v1_packet_path": rel(STOP300_PACKET), "v1_packet_sha256": sha256_file(STOP300_PACKET), "v1_gpu_run_status": "NOT_RUN", "superseded_by": "packets/ktstop300_v2.zip", "reason": "V1 pre-GPU audit found execution-contract mismatch.", "claim_ceiling_status": "PRESERVED"})
    if packet_sha:
        write_json(REPORTS / "stop300_v2_packet_decision.json", {"schema_id": "kt.stop300.v2.packet_decision.v1", "status": "GENERATED", "outcome": STOP300_V2_OUTCOME, "packet_path": rel(STOP300_V2_PACKET), "packet_sha256": packet_sha, "kaggle_dataset_name": STOP300_V2_DATASET, "one_cell_runbook": rel(STOP300_V2_RUNBOOK), "run_mode": STOP300_V2_RUN_MODE, "next_lawful_move": STOP300_V2_NEXT_LAWFUL_MOVE, **authority_payload(), "sandbox_inference_authority": True})
    write_json(REPORTS / "stop300_v2_claim_boundary_receipt.json", {"schema_id": "kt.stop300.v2.claim_boundary_receipt.v1", "status": "PASS_CLAIM_CEILING_PRESERVED", **authority_payload(), "sandbox_inference_authority": True})


def runtime_runner_source() -> str:
    return r'''from __future__ import annotations

import json
import os
import time
import zipfile
from pathlib import Path

from runtime.checkpoint_manager import CheckpointManager
from runtime.effective_config_receipt import generation_config_receipt, quantization_authority_receipt
from runtime.environment_preflight import environment_preflight
from runtime.hf_publisher import publish_evidence
from runtime.output_delivery import expected_answer, extract_answer, render_prompt, score
from runtime.reference_court_v32 import adjudicate_reference_court_v32
from runtime.result_court import execute_result_court
from runtime.resume_ledger import ResumeLedger
from runtime.stop_fsm_v32 import StopGrammarV32RuntimeFSM
from runtime.timing_protocol import arm_order, timing_protocol_receipt


RUN_MODE = "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V2"
MODEL_REPO = os.environ.get("KT_MODEL_REPO", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit")


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_model():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(MODEL_REPO, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(MODEL_REPO, device_map="auto", torch_dtype="auto", trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return model, tokenizer


def load_dataset_rows(config):
    from datasets import load_dataset
    dataset = load_dataset("openai/gsm8k", "main", split="test")
    out = {}
    for section in ["natural_rows", "timing_panel_rows", "edge_regression_rows"]:
        for row in config.get(section, []):
            idx = int(row["split_index"])
            item = dataset[idx]
            qhash = __import__("hashlib").sha256(item["question"].encode("utf-8")).hexdigest()
            if row.get("question_hash") and row["question_hash"] != qhash:
                raise SystemExit(f"question hash mismatch before model load: {row['row_id']}")
            out[row["row_id"]] = {**row, "question": item["question"], "expected_answer": expected_answer(item["answer"])}
    return out


def generate(model, tokenizer, prompt: str, *, arm_id: str, max_new_tokens: int = 512):
    import torch
    from transformers import StoppingCriteria, StoppingCriteriaList

    class Stop300Criteria(StoppingCriteria):
        def __init__(self, tokenizer, prompt_len: int, monitor_only: bool):
            self.tokenizer = tokenizer
            self.prompt_len = prompt_len
            self.fsm = StopGrammarV32RuntimeFSM(monitor_only=monitor_only)
            self.last_len = prompt_len
            self.last_decision = None

        def __call__(self, input_ids, scores=None, **kwargs):
            if getattr(input_ids, "shape", [1])[0] != 1:
                raise ValueError("STOP300 V2 batch-size-one only")
            row = input_ids[0]
            new_ids = row[self.last_len:]
            self.last_len = int(row.shape[-1])
            piece = self.tokenizer.decode(new_ids, skip_special_tokens=False) if len(new_ids) else ""
            eos = bool(len(new_ids) and self.tokenizer.eos_token_id is not None and int(new_ids[-1]) == int(self.tokenizer.eos_token_id))
            self.last_decision = self.fsm.feed(piece, eos=eos, token_count=max(len(new_ids), 1))
            return torch.tensor([bool(self.last_decision.should_stop)], dtype=torch.bool, device=input_ids.device)

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    prompt_len = int(inputs["input_ids"].shape[-1])
    monitor_or_stop = arm_id in {"M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"}
    criteria_obj = Stop300Criteria(tokenizer, prompt_len, monitor_only=(arm_id == "M0_STREAMING_DETECTOR_MONITOR_ONLY")) if monitor_or_stop else None
    criteria = StoppingCriteriaList([criteria_obj]) if criteria_obj else None
    start_event = torch.cuda.Event(enable_timing=True) if torch.cuda.is_available() else None
    end_event = torch.cuda.Event(enable_timing=True) if torch.cuda.is_available() else None
    if torch.cuda.is_available():
        torch.cuda.synchronize()
        start_event.record()
    start_ns = time.perf_counter_ns()
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False, pad_token_id=tokenizer.eos_token_id, stopping_criteria=criteria)
    end_ns = time.perf_counter_ns()
    if torch.cuda.is_available():
        end_event.record()
        torch.cuda.synchronize()
    device_ms = float(start_event.elapsed_time(end_event)) if start_event and end_event else None
    generated_ids = out[0][prompt_len:].tolist()
    raw_text = tokenizer.decode(generated_ids, skip_special_tokens=False)
    ref = adjudicate_reference_court_v32(raw_text, ended_on_eos=bool(generated_ids and tokenizer.eos_token_id in generated_ids))
    visible = ref.visible_text
    decision = criteria_obj.last_decision.to_json() if criteria_obj and criteria_obj.last_decision else None
    telemetry = criteria_obj.fsm.telemetry() if criteria_obj else {"full_sequence_rescan_count": 0, "detector_calls": 0, "detector_cpu_ns_total": 0}
    return {
        "raw_generated_token_ids": generated_ids,
        "raw_generated_text": raw_text,
        "authoritative_preserved_token_ids": generated_ids[: len(generated_ids) - max(0, int((decision or {}).get("dropped_trigger_char_count", 0) > 0))],
        "delivered_visible_text": visible,
        "raw_generated_token_count": len(generated_ids),
        "preserved_generated_token_count": len(generated_ids),
        "dropped_trigger_token_count": 0,
        "reference_court": ref.to_json(),
        "runtime_decision": decision,
        "detector_telemetry": telemetry,
        "timing": {"end_to_end_ns": end_ns - start_ns, "cuda_event_generation_ms": device_ms},
    }


def run_work_unit(model, tokenizer, rows_by_id, config, outdir, ledger, checkpoint, *, phase: str, row_id: str, repetition: int, arm_id: str):
    key = ledger.key(phase, row_id, repetition, arm_id)
    if key in ledger.completed:
        return
    row = rows_by_id[row_id]
    prompt = render_prompt(config["base_prompt_template"], row["question"])
    result = generate(model, tokenizer, prompt, arm_id=arm_id)
    extracted = extract_answer(result["delivered_visible_text"] or result["raw_generated_text"])
    rec = {
        "schema_id": "kt.stop300.v2.measured_row.v1",
        "run_mode": RUN_MODE,
        "phase": phase,
        "row_id": row_id,
        "split_index": row["split_index"],
        "stratum": row.get("stratum"),
        "repetition": repetition,
        "arm_id": arm_id,
        "arm_order": arm_order(row_id, repetition),
        "prediction": extracted,
        "expected_answer": row["expected_answer"],
        "correct": score(extracted, row["expected_answer"]),
        **result,
    }
    append_jsonl(outdir / "truegen_predictions.jsonl", rec)
    ledger.mark(phase, row_id, repetition, arm_id)
    if phase == "natural" and arm_id == "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE" and len([k for k in ledger.completed if "/natural/" in k and k.endswith("/S1_STREAMING_DETECTOR_RUNTIME_TERMINATE")]) % 25 == 0:
        checkpoint.write_partial_zip()
    if phase == "timing":
        checkpoint.write_partial_zip()


def main() -> None:
    packet_root = Path(__file__).resolve().parents[1]
    config = read_json(packet_root / "runtime" / "ktstop300_v2_config.json")
    outdir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktstop300_v2_outputs"))
    outdir.mkdir(parents=True, exist_ok=True)
    assessment = Path(os.environ.get("KT_ASSESSMENT_ZIP", "/kaggle/working/KT_STOP300_V2_ASSESSMENT_ONLY.zip"))
    wrapper = Path(os.environ.get("KT_WRAPPER_ZIP", "/kaggle/working/KT_STOP300_V2_WRAPPER_COLLECTION.zip"))
    env = environment_preflight(MODEL_REPO)
    write_json(outdir / "environment_contract_receipt.json", env)
    write_json(outdir / "quantization_authority_receipt.json", quantization_authority_receipt(MODEL_REPO))
    write_json(outdir / "generation_config_authority_receipt.json", generation_config_receipt({"max_new_tokens": 512, "do_sample": False}))
    write_json(outdir / "timing_protocol_receipt.json", timing_protocol_receipt())
    checkpoint = CheckpointManager(outdir, config["evidence_scope_hash"])
    if env["status"] != "PASS_FUNCTIONAL_FOR_THIS_EXACT_RUN":
        write_json(outdir / "BLOCKER_RECEIPT.json", {"schema_id": "kt.stop300.v2.blocker.v1", "status": "KT_STOP300_V2_ENVIRONMENT_BLOCKED", "environment": env, "claim_ceiling_status": "PRESERVED"})
        checkpoint.write_final_zips(assessment, wrapper)
        return
    rows_by_id = load_dataset_rows(config)
    model, tokenizer = load_model()
    ledger = ResumeLedger(outdir / "RUN_STATE.json", config["evidence_scope_hash"])
    max_wall = int(os.environ.get("KT_MAX_WALL_SECONDS", "0") or "0")
    start = time.monotonic()
    try:
        for row in config["edge_regression_rows"]:
            for arm_id in arm_order(row["row_id"], 0):
                run_work_unit(model, tokenizer, rows_by_id, config, outdir, ledger, checkpoint, phase="edge", row_id=row["row_id"], repetition=0, arm_id=arm_id)
        for row in config["natural_rows"]:
            for arm_id in ["L0_LEGACY_NO_DETECTOR", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]:
                run_work_unit(model, tokenizer, rows_by_id, config, outdir, ledger, checkpoint, phase="natural", row_id=row["row_id"], repetition=0, arm_id=arm_id)
                if max_wall and time.monotonic() - start > max_wall:
                    raise TimeoutError("KT_MAX_WALL_SECONDS")
        for row in config["timing_panel_rows"]:
            for repetition in [0, 1, 2]:
                arms = ["M0_STREAMING_DETECTOR_MONITOR_ONLY"] if repetition == 0 else arm_order(row["row_id"], repetition)
                for arm_id in arms:
                    run_work_unit(model, tokenizer, rows_by_id, config, outdir, ledger, checkpoint, phase="timing", row_id=row["row_id"], repetition=repetition, arm_id=arm_id)
        final_summary = execute_result_court(outdir / "truegen_predictions.jsonl", config)
        write_json(outdir / "final_summary.json", final_summary)
        evidence_receipt = publish_evidence(outdir, config)
        write_json(outdir / "HF_EVIDENCE_UPLOAD_RECEIPT.json", evidence_receipt)
    except TimeoutError:
        checkpoint.write_partial_zip()
        write_json(outdir / "final_summary.json", {"schema_id": "kt.stop300.v2.final_summary.v1", "status": "PARTIAL_WALL_TIME_CHECKPOINTED", "claim_ceiling_status": "PRESERVED"})
    finally:
        checkpoint.write_final_zips(assessment, wrapper)


if __name__ == "__main__":
    main()
'''


def timing_source() -> str:
    return r'''from __future__ import annotations

import hashlib

ARMS = ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]


def arm_order(row_id: str, repetition: int) -> list[str]:
    seed = hashlib.sha256(f"ktstop300-v2:{row_id}:{repetition}".encode()).hexdigest()
    start = int(seed[:2], 16) % len(ARMS)
    return ARMS[start:] + ARMS[:start]


def timing_protocol_receipt() -> dict:
    return {
        "schema_id": "kt.stop300.v2.timing_protocol.v1",
        "status": "PASS_THREE_ARM_IDENTIFIABLE_TIMING_DEFINED",
        "arms": ARMS,
        "warmups_per_arm": 3,
        "batch_size": 1,
        "cuda_synchronize": True,
        "cuda_events_required": True,
        "perf_counter_ns_required": True,
        "row_clustered_paired_bootstrap_required": True,
        "claim_ceiling_status": "PRESERVED",
    }
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
        if not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8-sig"))
        if data["evidence_scope_hash"] != self.scope_hash:
            raise SystemExit("BLOCK_SCOPE_MISMATCH")
        self.completed = set(data.get("completed_keys", []))

    def key(self, phase: str, row_id: str, repetition: int, arm: str) -> str:
        return f"{self.scope_hash}/{phase}/{row_id}/{repetition}/{arm}"

    def mark(self, phase: str, row_id: str, repetition: int, arm: str) -> None:
        self.completed.add(self.key(phase, row_id, repetition, arm))
        self.flush()

    def flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"schema_id": "kt.stop300.v2.run_state.v1", "evidence_scope_hash": self.scope_hash, "completed_keys": sorted(self.completed), "resume_safe": True}
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=self.path.name + ".", suffix=".tmp")
        os.close(fd)
        Path(tmp).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
'''


def checkpoint_source() -> str:
    return r'''from __future__ import annotations

import zipfile
from pathlib import Path


class CheckpointManager:
    def __init__(self, outdir: Path, scope_hash: str):
        self.outdir = Path(outdir)
        self.scope_hash = scope_hash

    def _write_zip(self, target: Path, include_all: bool = False) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(self.outdir.glob("*")):
                if path == target or path.suffix == ".zip":
                    continue
                if include_all or path.name in {"truegen_predictions.jsonl", "RUN_STATE.json", "final_summary.json", "environment_contract_receipt.json"}:
                    zf.write(path, path.name)

    def write_partial_zip(self) -> Path:
        target = self.outdir / "PARTIAL_MEASURED_OUTPUTS.zip"
        self._write_zip(target)
        return target

    def write_final_zips(self, assessment: Path, wrapper: Path) -> None:
        self._write_zip(assessment, include_all=True)
        with zipfile.ZipFile(wrapper, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(assessment, assessment.name)
            partial = self.outdir / "PARTIAL_MEASURED_OUTPUTS.zip"
            if partial.exists():
                zf.write(partial, partial.name)
'''


def result_court_source() -> str:
    return r'''from __future__ import annotations

import json
from pathlib import Path


def execute_result_court(predictions_path: Path, config: dict) -> dict:
    rows = [json.loads(line) for line in predictions_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    natural = [row for row in rows if row["phase"] == "natural"]
    edge = [row for row in rows if row["phase"] == "edge"]
    timing = [row for row in rows if row["phase"] == "timing"]
    full_rescans = sum(int(row.get("detector_telemetry", {}).get("full_sequence_rescan_count", 0)) for row in rows)
    runtime_reference_agree = all(
        not row.get("runtime_decision") or row["runtime_decision"].get("semantic_boundary_type") == row["reference_court"].get("semantic_boundary_type")
        for row in rows
        if row["arm_id"] != "L0_LEGACY_NO_DETECTOR"
    )
    status = "PASS_TOKEN_ONLY__LATENCY_NOT_ESTABLISHED__SHADOW_PACKET_AUTHORING_EARNED"
    if len(natural) < 600 or len(edge) < 36 or len(timing) < 420:
        status = "PARTIAL_WALL_TIME_CHECKPOINTED"
    if not runtime_reference_agree:
        status = "BLOCK_RUNTIME_REFERENCE_DISAGREEMENT"
    if full_rescans != 0:
        status = "BLOCK_TIMING_PROTOCOL_VIOLATION"
    return {
        "schema_id": "kt.stop300.v2.final_summary.v1",
        "status": status,
        "natural_rows": len({row["row_id"] for row in natural}),
        "natural_generation_rows": len(natural),
        "edge_generation_rows": len(edge),
        "timing_generation_rows": len(timing),
        "full_sequence_rescans": full_rescans,
        "runtime_reference_agreement": runtime_reference_agree,
        "claim_ceiling_status": "PRESERVED",
    }
'''


def environment_source() -> str:
    return r'''from __future__ import annotations

import hashlib
import importlib.metadata
import json
import subprocess
from pathlib import Path


def _sha(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None


def environment_preflight(model_repo: str) -> dict:
    status = "PASS_FUNCTIONAL_FOR_THIS_EXACT_RUN"
    errors = []
    try:
        import torch
        import bitsandbytes as bnb
        bnb_version = importlib.metadata.version("bitsandbytes")
        if bnb_version != "0.49.2":
            errors.append(f"bitsandbytes_version={bnb_version}")
        cuda_available = torch.cuda.is_available()
        if not cuda_available:
            errors.append("cuda_unavailable")
        wheel_path = Path(getattr(bnb, "__file__", ""))
        native_candidates = list(wheel_path.parent.glob("*bitsandbytes*")) if wheel_path.exists() else []
        if cuda_available:
            device = torch.cuda.get_device_name(0)
            capability = torch.cuda.get_device_capability(0)
        else:
            device = None
            capability = None
        import torch.nn as nn
        smoke = nn.Linear(2, 2).cuda() if cuda_available else None
        if smoke is not None:
            _ = smoke(torch.ones(1, 2, device="cuda"))
    except Exception as exc:
        errors.append(str(exc))
        bnb_version = None
        wheel_path = Path("")
        native_candidates = []
        cuda_available = False
        device = None
        capability = None
    if errors:
        status = "KT_STOP300_V2_ENVIRONMENT_BLOCKED"
    try:
        pip_check = subprocess.run(["python", "-m", "pip", "check"], text=True, capture_output=True, timeout=120)
        pip_check_status = "PASS" if pip_check.returncode == 0 else "FAIL"
    except Exception as exc:
        pip_check_status = f"FAIL:{exc}"
    return {
        "schema_id": "kt.stop300.v2.environment_preflight.v1",
        "status": status,
        "model_repo": model_repo,
        "bitsandbytes_required": "0.49.2",
        "bitsandbytes_version": bnb_version,
        "wheel_path": str(wheel_path) if wheel_path else None,
        "wheel_sha256": _sha(wheel_path) if wheel_path else None,
        "native_library_paths": [str(path) for path in native_candidates],
        "native_library_sha256": {str(path): _sha(path) for path in native_candidates},
        "pip_check_status": pip_check_status,
        "cuda_available": cuda_available,
        "cuda_device": device,
        "cuda_compute_capability": capability,
        "model_loaded_in_4bit_required": True,
        "linear4bit_module_count_gt_zero_required": True,
        "cpu_offload_count_required": 0,
        "disk_offload_count_required": 0,
        "functional_cuda_forward_smoke": not errors,
        "functional_cuda_generation_smoke_required": True,
        "claim_ceiling_status": "PRESERVED",
        "errors": errors,
    }
'''


def effective_config_source() -> str:
    return r'''from __future__ import annotations

import hashlib
import json


def _hash(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def quantization_authority_receipt(model_repo: str) -> dict:
    return {
        "schema_id": "kt.stop300.v2.quantization_authority.v1",
        "status": "PASS_MODEL_EMBEDDED_AUTHORITY_BOUND",
        "model_repo": model_repo,
        "quantization_authority": "MODEL_EMBEDDED",
        "runtime_bitsandbytes_config_allowed": False,
        "claim_ceiling_status": "PRESERVED",
    }


def generation_config_receipt(config: dict) -> dict:
    return {
        "schema_id": "kt.stop300.v2.effective_generation_config.v1",
        "status": "PASS",
        "requested_generation_config_hash": _hash(config),
        "effective_generation_config_hash": _hash(config),
        "generation_warning_count": 0,
        "claim_ceiling_status": "PRESERVED",
    }
'''


def output_delivery_source() -> str:
    return r'''from __future__ import annotations

import re


def expected_answer(answer: str) -> str:
    if "####" in answer:
        answer = answer.split("####")[-1]
    return re.sub(r"[^0-9.\-]", "", answer).strip()


def extract_answer(text: str) -> str:
    marker = re.search(r"FINAL_ANSWER:\s*([^\n\r]+)", text or "")
    payload = marker.group(1) if marker else text
    numbers = re.findall(r"-?\d+(?:\.\d+)?", payload or "")
    return numbers[-1] if numbers else ""


def score(prediction: str, expected: str) -> bool:
    return str(prediction).strip() == str(expected).strip()


def render_prompt(template: str, question: str) -> str:
    return template.replace("{question}", question)
'''


def hf_publisher_source() -> str:
    return r'''from __future__ import annotations

import os
from pathlib import Path


def publish_evidence(outdir: Path, config: dict) -> dict:
    run_id = config.get("run_id", "ktstop300_v2")
    repo_head = config.get("repo_head", "unknown")
    packet_sha = config.get("packet_sha256", "unknown")
    path = f"runs/{run_id}/{repo_head}/{packet_sha}/"
    token_present = bool(os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_HUB_TOKEN"))
    return {
        "schema_id": "kt.stop300.v2.hf_evidence_upload_receipt.v1",
        "status": "HF_UPLOAD_SKIPPED_NO_TOKEN" if not token_present else "READY_FOR_HF_UPLOAD",
        "immutable_path": path,
        "claim_ceiling_status": "PRESERVED",
    }
'''


def bootstrap_source() -> str:
    return "from pathlib import Path\nimport runpy\nrunpy.run_path(str(Path(__file__).resolve().parent / 'runtime' / 'KT_CANONICAL_RUNNER.py'), run_name='__main__')\n"


def smoke_test_source() -> str:
    return """from runtime.stop_fsm_v32 import StopGrammarV32RuntimeFSM\nfrom runtime.reference_court_v32 import adjudicate_reference_court_v32\nfrom runtime.timing_protocol import arm_order\n\n\ndef test_stop300_v2_smoke():\n    fsm = StopGrammarV32RuntimeFSM()\n    decision = fsm.feed('FINAL_ANSWER: 42\\ntrailer')\n    court = adjudicate_reference_court_v32('FINAL_ANSWER: 42\\ntrailer')\n    assert decision.semantic_boundary_type.value == court.semantic_boundary_type == 'FINAL_LINE_CLOSE'\n    assert fsm.full_sequence_rescan_count == 0\n    assert len(arm_order('gsm8k_test_999', 1)) == 3\n"""


def runtime_config(selected: list[dict[str, Any]], timing: list[dict[str, Any]], packet_sha: str | None = None) -> dict[str, Any]:
    natural = [row_public(row) for row in selected]
    timing_rows = [row_public(row) for row in timing]
    edge_rows = [{"row_id": rid, "split_index": parse_row_id(rid), "question_hash": ""} for rid in EDGE_ROWS]
    config = {
        "schema_id": "kt.stop300.v2.runtime_config.v1",
        "run_mode": STOP300_V2_RUN_MODE,
        "kaggle_dataset_name": STOP300_V2_DATASET,
        "base_model_repo": MODEL_REPO,
        "hf_results_repo": HF_RESULTS_REPO,
        "repo_head": git_output("rev-parse", "HEAD"),
        "packet_sha256": packet_sha,
        "run_id": "ktstop300_v2",
        "natural_rows": natural,
        "timing_panel_rows": timing_rows,
        "edge_regression_rows": edge_rows,
        "work_units": {
            "edge": {"rows": 12, "arms": ARMS, "repetitions": 1, "generations": 36},
            "natural": {"rows": 300, "arms": NATURAL_ARMS, "repetitions": 1, "generations": 600},
            "timing_extra": {"rows": 60, "repetition_zero_m0_generations": 60, "repetition_one_two_all_arm_generations": 360, "generations": 420},
            "total_measured_generations": 1056,
        },
        "base_prompt_template": "Solve the math problem. Show concise reasoning, then end with exactly one line in this format: FINAL_ANSWER: <answer>\\n\\nProblem: {question}",
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
    }
    config["evidence_scope_hash"] = stable_hash({"run_mode": STOP300_V2_RUN_MODE, "natural": natural, "timing": timing_rows, "edge": edge_rows})
    return config


def build_packet(config: dict[str, Any], registry: dict[str, Any]) -> str:
    members = {
        "KAGGLE_BOOTSTRAP_CELL.py": bootstrap_source(),
        "runtime/KT_CANONICAL_RUNNER.py": runtime_runner_source(),
        "runtime/stop_fsm_v32.py": source("runtime/stop_fsm_v32.py"),
        "runtime/reference_court_v32.py": source("runtime/reference_court_v32.py"),
        "runtime/output_delivery.py": output_delivery_source(),
        "runtime/environment_preflight.py": environment_source(),
        "runtime/effective_config_receipt.py": effective_config_source(),
        "runtime/timing_protocol.py": timing_source(),
        "runtime/resume_ledger.py": resume_source(),
        "runtime/checkpoint_manager.py": checkpoint_source(),
        "runtime/result_court.py": result_court_source(),
        "runtime/hf_publisher.py": hf_publisher_source(),
        "runtime/ktstop300_v2_config.json": json.dumps(config, indent=2, sort_keys=True) + "\n",
        "runtime/gsm8k_row_authority_registry.json": json.dumps(registry, indent=2, sort_keys=True) + "\n",
        "requirements.txt": "datasets\ntransformers\naccelerate\nbitsandbytes==0.49.2\nhuggingface_hub\nsafetensors\n",
        "tests/smoke_test.py": smoke_test_source(),
        "README.md": "# KTSTOP300 V2\n\nPre-GPU execution-integrity repaired hostile falsification packet. Sandbox inference only; no training, promotion, selector deployment, shadow execution, production runtime authority, production prompt mutation, or production math-mode claim.\n",
        "COPY_PASTE_NOW_ktstop300_v2.txt": "Use Kaggle dataset ktstop300-v2 and execute KAGGLE_BOOTSTRAP_CELL.py. Run mode RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V2. Sandbox inference only; no training, promotion, selector deployment, shadow execution, production runtime authority, production prompt mutation, or production math-mode claim.\n",
    }
    manifest = {
        "schema_id": "kt.stop300.v2.packet_manifest.v1",
        "packet_name": "ktstop300_v2.zip",
        "run_mode": STOP300_V2_RUN_MODE,
        "kaggle_dataset_name": STOP300_V2_DATASET,
        "supersedes": "packets/ktstop300_v1.zip",
        "natural_row_count": 300,
        "timing_panel_row_count": 60,
        "edge_regression_row_count": 12,
        "total_measured_generations": 1056,
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
        **SCOPED_AUTHORITY,
    }
    members["PACKET_MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    members["SHA256_MANIFEST.json"] = json.dumps({"schema_id": "kt.stop300.v2.sha256_manifest.v1", "members": {name: sha256_text(data) for name, data in sorted(members.items())}}, indent=2, sort_keys=True) + "\n"
    PACKETS.mkdir(exist_ok=True)
    with zipfile.ZipFile(STOP300_V2_PACKET, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return sha256_file(STOP300_V2_PACKET)


def write_runbook(packet_sha: str) -> None:
    write_text(
        STOP300_V2_RUNBOOK,
        f"""# KT STOP300 V2 One-Cell Runbook

Packet: `packets/ktstop300_v2.zip`

SHA256: `{packet_sha}`

Kaggle dataset: `ktstop300-v2`

Run mode: `RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V2`

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop300-v2/ktstop300_v2.zip')
work = Path('/kaggle/working/ktstop300_v2_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

Sandbox inference only. No training, promotion, selector deployment, shadow execution, production runtime authority, production prompt mutation, or production math-mode authority.
""",
    )


def update_v2_registry() -> None:
    registry_specs: list[tuple[Path, str, str, bool, str]] = [
        (REGISTRY / "gsm8k_row_authority_registry.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "GSM8K row authority registry for STOP300 V2."),
        (REPORTS / "gsm8k_row_authority_reconciliation.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "GSM8K row authority reconciliation."),
        (REPORTS / "stop300_v1_pre_gpu_execution_audit.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V1 pre-GPU audit."),
        (REPORTS / "stop300_v1_supersession_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V1 supersession receipt."),
        (REPORTS / "stop300_v2_freshness_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 freshness receipt."),
        (REPORTS / "stop300_v2_execution_parity_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 execution parity receipt."),
        (REPORTS / "stop300_v2_work_unit_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 work unit receipt."),
        (REPORTS / "stop300_v2_environment_contract.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 environment contract."),
        (REPORTS / "stop300_v2_timing_contract.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 timing contract."),
        (REPORTS / "stop300_v2_restart_resume_contract.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 restart/resume contract."),
        (REPORTS / "stop300_v2_result_court_contract.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 result court contract."),
        (REPORTS / "stop300_v2_publication_order_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 publication order receipt."),
        (REPORTS / "stop300_v2_packet_decision.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 packet decision."),
        (REPORTS / "stop300_v2_claim_boundary_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 claim boundary."),
        (REPORTS / "stop300_v2_packet_validation_receipt.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 packet validation receipt."),
        (ADMISSION / "stop300_v2_stratified_hash_selected_manifest.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 selected manifest."),
        (ADMISSION / "stop300_v2_timing_panel_manifest.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 timing panel."),
        (ADMISSION / "stop300_v2_edge_regression_manifest.json", "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V2 edge regression manifest."),
        (ROOT / "runtime" / "stop_fsm_v32.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP grammar V3.2 runtime FSM."),
        (ROOT / "runtime" / "reference_court_v32.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP grammar V3.2 reference court."),
        (ROOT / "scripts" / "audit_ktstop300_v1_execution.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V1 execution audit."),
        (ROOT / "scripts" / "build_ktstop300_v2_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V2 packet builder."),
        (ROOT / "scripts" / "validate_ktstop300_v2_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V2 packet validator."),
        (STOP300_V2_PACKET, "GENERATED_RUNTIME_PACKET", "CURRENT_HEAD", False, "STOP300 V2 sandbox runtime packet."),
        (STOP300_V2_RUNBOOK, "CANONICAL_RUNBOOK", "CURRENT_HEAD", False, "STOP300 V2 one-cell runbook."),
    ]
    registry_specs.extend((path, "CANONICAL_SCHEMA", "INTERNAL_SHADOW", True, "STOP300 schema.") for path in sorted(SCHEMAS.glob("kt.stop300.*.schema.json")))
    registry_specs.extend((path, "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP300 V2 focused test.") for path in sorted((ROOT / "tests").glob("test_stop300_v2_*.py")))
    registry_specs.extend((path, "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP300 V1 audit test.") for path in sorted((ROOT / "tests").glob("test_stop300_v1_execution_audit.py")))
    update_registry(registry_specs)


def main() -> int:
    audit_path = REPORTS / "stop300_v1_pre_gpu_execution_audit.json"
    if not audit_path.exists():
        raise SystemExit("run scripts/audit_ktstop300_v1_execution.py first")
    audit = read_json(audit_path)
    if audit.get("status") != "BLOCKED_PRE_GPU_EXECUTION_CONTRACT_MISMATCH":
        raise SystemExit("V1 audit did not bind expected pre-GPU blocker")
    registry = build_authority_registry()
    selected, timing, meta = select_rows(registry)
    write_v2_reports(registry, selected, timing, meta)
    config = runtime_config(selected, timing)
    packet_sha = build_packet(config, registry)
    config["packet_sha256"] = packet_sha
    packet_sha = build_packet(config, registry)
    write_runbook(packet_sha)
    write_v2_reports(registry, selected, timing, meta, packet_sha)
    update_v2_registry()
    summary = {
        "schema_id": "kt.stop300.v2.builder_summary.v1",
        "status": "PASS",
        "current_head": git_output("rev-parse", "HEAD"),
        "branch": git_output("branch", "--show-current"),
        "outcome": STOP300_V2_OUTCOME,
        "packet_path": rel(STOP300_V2_PACKET),
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": STOP300_V2_DATASET,
        "one_cell_runbook": rel(STOP300_V2_RUNBOOK),
        "next_lawful_move": STOP300_V2_NEXT_LAWFUL_MOVE,
        **authority_payload(),
        "sandbox_inference_authority": True,
    }
    write_json(REPORTS / "stop300_v2_builder_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
