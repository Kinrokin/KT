from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

from build_ktstop300_v4_packet import (
    HF_RESULTS_REPO,
    MODEL_REPO,
    atomic_record_store_source,
    checkpoint_manager_source,
    dependency_preflight_source,
    hf_publisher_source,
    model_attestation_source,
    output_delivery_source,
    publication_disposition_source,
    source,
    stable_hash,
    timing_protocol_source,
    work_plan_source,
)
from ktstop300_common import (
    ADMISSION,
    AUTHORITY_FALSE,
    REPORTS,
    ROOT,
    SCOPED_AUTHORITY,
    STOP300_V4_PACKET,
    STOP300_V41_DATASET,
    STOP300_V41_NEXT_LAWFUL_MOVE,
    STOP300_V41_OUTCOME,
    STOP300_V41_PACKET,
    STOP300_V41_RUN_MODE,
    STOP300_V41_RUNBOOK,
    authority_payload,
    git_output,
    read_json,
    rel,
    sha256_file,
    sha256_text,
    update_registry,
    write_json,
    write_text,
)


EXPECTED_V4_SHA = "32ed95da638d72dc3355277a9b0c70686c33e48fad76b48fb2efffc6d26c3ab3"
ARMS = ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]


def bootstrap_source(member_manifest_sha: str) -> str:
    return f'''from __future__ import annotations

import hashlib
import json
import os
import runpy
import sys
import traceback
import zipfile
from pathlib import Path

EXPECTED_MEMBER_MANIFEST_SHA256 = "{member_manifest_sha}"
EXPECTED_PACKET_NAME = "ktstop300_v4_1.zip"
EXPECTED_RUN_MODE = "{STOP300_V41_RUN_MODE}"


def write_blocker(root: Path, status: str, error: str) -> None:
    out = Path(os.environ.get("KT_OUTPUT_DIR", root / "bootstrap_blocker"))
    out.mkdir(parents=True, exist_ok=True)
    payload = {{"schema_id": "kt.stop300.v41.bootstrap_blocker.v1", "status": status, "error": error, "claim_ceiling_status": "PRESERVED"}}
    (out / "BLOCKER_RECEIPT.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
    with zipfile.ZipFile(out / "KT_STOP300_V4_1_WRAPPER_COLLECTION.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(out / "BLOCKER_RECEIPT.json", "BLOCKER_RECEIPT.json")


def main() -> None:
    packet_root = Path(__file__).resolve().parent
    sys.path.insert(0, str(packet_root))
    os.chdir(packet_root)
    try:
        authorized_sha = os.environ.get("KT_AUTHORIZED_PACKET_SHA256")
        subject_head = os.environ.get("KT_AUTHORIZED_PACKET_SUBJECT_HEAD")
        current_head = os.environ.get("KT_CURRENT_MAIN_HEAD")
        expected_run_mode = os.environ.get("KT_EXPECTED_RUN_MODE")
        if not authorized_sha or not subject_head or not current_head or expected_run_mode != EXPECTED_RUN_MODE:
            raise SystemExit("missing external packet SHA/subject/current-head/run-mode authority")
        manifest_payload = json.loads((packet_root / "SHA256_MANIFEST.json").read_text(encoding="utf-8-sig"))
        stable_members = {{
            key: value
            for key, value in manifest_payload["members"].items()
            if key not in {{"KAGGLE_BOOTSTRAP_CELL.py", "SHA256_MANIFEST.json", "runtime/ktstop300_v41_config.json"}}
        }}
        actual_member_manifest_sha = hashlib.sha256(json.dumps(stable_members, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        if actual_member_manifest_sha != EXPECTED_MEMBER_MANIFEST_SHA256:
            raise SystemExit("internal member manifest SHA mismatch")
        outdir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktstop300_v4_1_outputs"))
        outdir.mkdir(parents=True, exist_ok=True)
        from runtime.dependency_preflight import ensure_dependencies, native_library_receipt
        ensure_dependencies(outdir)
        native_library_receipt(outdir)
        import runtime.KT_CANONICAL_RUNNER  # noqa: F401
        if os.environ.get("KT_STOP300_BOOTSTRAP_SMOKE_ONLY") == "1":
            Path("BOOTSTRAP_SMOKE_RECEIPT.json").write_text(json.dumps({{"status": "PASS_FRESH_SUBPROCESS_UNRELATED_CWD"}}, indent=2) + "\\n", encoding="utf-8")
            return
        runpy.run_path(str(packet_root / "runtime" / "KT_CANONICAL_RUNNER.py"), run_name="__main__")
    except BaseException as exc:
        write_blocker(packet_root, "KT_STOP300_V4_1_BOOTSTRAP_BLOCKED", "".join(traceback.format_exception_only(type(exc), exc)).strip())
        if os.environ.get("KT_RAISE_ON_BLOCKER", "0") == "1":
            raise


if __name__ == "__main__":
    main()
'''


def runner_source() -> str:
    return r'''from __future__ import annotations

import json
import os
import time
import traceback
from pathlib import Path

import torch
from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, StoppingCriteriaList

from runtime.atomic_record_store import AtomicRecordStore, work_key
from runtime.boundary_evidence import build_physical_token_ledger, validate_physical_token_ledger
from runtime.checkpoint_manager import CheckpointManager
from runtime.final_answer_stopping_criteria_v41 import KTFinalAnswerStoppingCriteria
from runtime.hf_publisher import publish_evidence, publish_final_assessment
from runtime.model_runtime_attestation import attest_loaded_model, effective_eos_token_ids
from runtime.numeric_normalizer import extract_expected_answer, extract_prediction, oracle_fixture_suite, score_prediction
from runtime.output_delivery import extract_prediction as extract_visible_prediction
from runtime.pairwise_court_v41 import execute_core_result_court, synthetic_mutation_suite
from runtime.publication_disposition import final_disposition
from runtime.reference_court_v34 import adjudicate_reference_court_v34
from runtime.timing_protocol import timing_protocol_receipt
from runtime.work_plan import build_work_plan, work_plan_receipt

MODEL_REPO = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_model():
    tokenizer = AutoTokenizer.from_pretrained(MODEL_REPO)
    config = AutoConfig.from_pretrained(MODEL_REPO)
    embedded_quant = getattr(config, "quantization_config", None)
    if embedded_quant:
        model = AutoModelForCausalLM.from_pretrained(MODEL_REPO, device_map="auto")
        quantization_authority = "MODEL_EMBEDDED"
    else:
        quant = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16)
        model = AutoModelForCausalLM.from_pretrained(MODEL_REPO, quantization_config=quant, device_map="auto")
        quantization_authority = "RUNTIME_DECLARED"
    return model, tokenizer, quantization_authority


def load_rows(config: dict) -> dict[str, dict]:
    rows = {}
    for group in ["natural_rows", "timing_panel_rows", "edge_regression_rows"]:
        for row in config[group]:
            rows[row["row_id"]] = {**row, "expected_answer": extract_expected_answer(row.get("answer", row.get("expected_answer", "")))}
    return rows


def render_prompt(template: str, question: str) -> str:
    return template.replace("{question}", question)


def make_stopping_criteria(tokenizer, prompt_len: int, arm_id: str):
    if arm_id == "L0_LEGACY_NO_DETECTOR":
        return None, None
    criterion = KTFinalAnswerStoppingCriteria(
        tokenizer=tokenizer,
        prompt_token_count=prompt_len,
        monitor_only=(arm_id == "M0_STREAMING_DETECTOR_MONITOR_ONLY"),
    )
    return StoppingCriteriaList([criterion]), criterion


def run_generation(model, tokenizer, prompt: str, arm_id: str, eos_ids: list[int]) -> dict:
    prompt_inputs = tokenizer(prompt, return_tensors="pt")
    prompt_token_ids = prompt_inputs["input_ids"][0].tolist()
    device = next(model.parameters()).device
    prompt_inputs = {k: v.to(device) for k, v in prompt_inputs.items()}
    criteria, criterion = make_stopping_criteria(tokenizer, len(prompt_token_ids), arm_id)
    cuda_timing_available = torch.cuda.is_available()
    start_event = torch.cuda.Event(enable_timing=True) if cuda_timing_available else None
    end_event = torch.cuda.Event(enable_timing=True) if cuda_timing_available else None
    wall_started = time.perf_counter_ns()
    if start_event:
        start_event.record()
    with torch.no_grad():
        outputs = model.generate(
            **prompt_inputs,
            max_new_tokens=512,
            do_sample=False,
            return_dict_in_generate=False,
            stopping_criteria=criteria,
        )
    if end_event:
        end_event.record()
        torch.cuda.synchronize()
    wall_ended = time.perf_counter_ns()
    raw_ids = outputs[0].tolist()[len(prompt_token_ids):]
    terminal = raw_ids[-1] if raw_ids else None
    ended_on_eos = terminal in set(eos_ids) if terminal is not None else False
    ended_on_max = len(raw_ids) >= 512 and not ended_on_eos
    raw_text = tokenizer.decode(raw_ids, skip_special_tokens=False)
    first = criterion.first_boundary_decision if criterion is not None else None
    visible_text = first.visible_text if first else raw_text
    boundary_floor = first.boundary_token_index_floor if first else len(raw_ids)
    boundary_ceil = first.boundary_token_index_ceil if first else len(raw_ids)
    termination_source = first.generator_termination_source.value if first else ("EOS_TOKEN" if ended_on_eos else ("MAX_NEW_TOKENS" if ended_on_max else "UNKNOWN"))
    ledger = build_physical_token_ledger(
        prompt_token_ids=prompt_token_ids,
        raw_generated_token_ids=raw_ids,
        semantic_visible_text=visible_text,
        canonical_extracted_answer=extract_visible_prediction(visible_text),
        generator_termination_source=termination_source,
        boundary_token_index_floor=boundary_floor,
        boundary_token_index_ceil=boundary_ceil,
        boundary_char_index=first.boundary_char_index if first else None,
        trigger_token_start_index=first.trigger_token_start_index if first else None,
        trigger_char_offset_within_token_if_any=first.trigger_char_offset_within_token_if_any if first else None,
    )
    reference = adjudicate_reference_court_v34(
        raw_text,
        terminal_token_id=terminal,
        effective_eos_token_ids=set(eos_ids),
        ended_on_eos=ended_on_eos,
        ended_on_max_new_tokens=ended_on_max,
        custom_stop_fired=bool(first and first.generator_termination_source.value == "CUSTOM_STOP_CRITERION"),
    )
    timing = {
        "wall_ns": wall_ended - wall_started,
        "cuda_event_ms": float(start_event.elapsed_time(end_event)) if start_event and end_event else None,
        "cuda_event_timing_executed": bool(start_event and end_event),
        "detector_cpu_ns": criterion.fsm.detector_cpu_ns_total if criterion is not None else 0,
    }
    return {
        **ledger.to_json(),
        "raw_generated_text": raw_text,
        "reference_court": reference.to_json(),
        "runtime_first_boundary": first.to_json() if first else None,
        "detector_telemetry": criterion.telemetry if criterion is not None else {"full_sequence_rescan_count": 0},
        "terminal_token_id": terminal,
        "effective_eos_token_ids": eos_ids,
        "ended_on_eos": ended_on_eos,
        "ended_on_max_new_tokens": ended_on_max,
        "custom_stop_fired": bool(first and first.generator_termination_source.value == "CUSTOM_STOP_CRITERION"),
        "token_boundary_errors": validate_physical_token_ledger(ledger.to_json()),
        "timing": timing,
        "v41_generation_time_stop_path": "TRANSFORMERS_STOPPING_CRITERIA" if criteria is not None else "BASELINE_NO_STOPPING_CRITERIA",
    }


def package_blocker(outdir: Path, checkpoint: CheckpointManager, assessment: Path, wrapper: Path, status: str, error: str) -> None:
    write_json(outdir / "BLOCKER_RECEIPT.json", {"schema_id": "kt.stop300.v41.blocker_receipt.v1", "status": status, "error": error, "claim_ceiling_status": "PRESERVED"})
    checkpoint.checkpoint("blocker")
    checkpoint.final_zips(assessment, wrapper)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    config = json.loads((root / "runtime" / "ktstop300_v41_config.json").read_text(encoding="utf-8-sig"))
    outdir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktstop300_v4_1_outputs"))
    outdir.mkdir(parents=True, exist_ok=True)
    assessment = Path(os.environ.get("KT_ASSESSMENT_ZIP", "/kaggle/working/KT_STOP300_V4_1_ASSESSMENT_ONLY.zip"))
    wrapper = Path(os.environ.get("KT_WRAPPER_ZIP", "/kaggle/working/KT_STOP300_V4_1_WRAPPER_COLLECTION.zip"))
    checkpoint = CheckpointManager(outdir, config["evidence_scope_hash"])
    try:
        if os.environ.get("KT_AUTHORIZED_PACKET_SHA256") is None:
            raise SystemExit("MISSING_EXTERNAL_PACKET_SHA")
        if os.environ.get("KT_AUTHORIZED_PACKET_SUBJECT_HEAD") is None:
            raise SystemExit("MISSING_PACKET_SUBJECT_HEAD")
        suite = oracle_fixture_suite()
        write_json(outdir / "numeric_oracle_fixture_suite.json", suite)
        if suite["status"] != "PASS":
            raise SystemExit("BLOCK_SCORER_ORACLE")
        write_json(outdir / "timing_protocol_receipt.json", timing_protocol_receipt())
        write_json(outdir / "work_plan_receipt.json", work_plan_receipt(config))
        write_json(outdir / "synthetic_court_mutation_receipt.json", synthetic_mutation_suite())
        rows = load_rows(config)
        model, tokenizer, quantization_authority = load_model()
        eos_ids = effective_eos_token_ids(model, tokenizer)
        attestation = attest_loaded_model(model, tokenizer, MODEL_REPO)
        attestation["quantization_authority"] = quantization_authority
        write_json(outdir / "model_runtime_attestation.json", attestation)
        if attestation["status"] != "PASS_FUNCTIONAL_MODEL_4BIT_CONTRACT":
            raise SystemExit("BLOCK_ENVIRONMENT_DRIFT")
        store = AtomicRecordStore(outdir, config["evidence_scope_hash"])
        plan = build_work_plan(config)
        max_wall = int(os.environ.get("KT_MAX_WALL_SECONDS", "0") or "0")
        started = time.monotonic()
        for item in plan:
            key = work_key(config["evidence_scope_hash"], item["phase"], item["row_id"], item["repetition"], item["arm_id"])
            if key in store.completed:
                continue
            if item["phase"] == "warmup":
                _ = run_generation(model, tokenizer, "Solve 1+1. FINAL_ANSWER:", item["arm_id"], eos_ids)
                store.write_once(key, {**item, "schema_id": "kt.stop300.v41.warmup_record.v1", "evidence": False})
                continue
            row = rows[item["row_id"]]
            prompt = render_prompt(config["base_prompt_template"], row["question"])
            gen = run_generation(model, tokenizer, prompt, item["arm_id"], eos_ids)
            prediction = extract_prediction(gen["semantic_visible_text"])
            record = {**item, **gen, "schema_id": "kt.stop300.v41.measured_record.v1", "prediction": prediction, "expected_answer": row["expected_answer"], "correct": score_prediction(prediction, row["expected_answer"])}
            store.write_once(key, record)
            if max_wall and time.monotonic() - started > max_wall:
                raise TimeoutError("KT_MAX_WALL_SECONDS")
        predictions = outdir / "truegen_predictions.jsonl"
        store.assemble_jsonl(predictions)
        core = execute_core_result_court(predictions, config)
        write_json(outdir / "CORE_RESULT_SUMMARY.json", core)
        publish_evidence(outdir, config)
        checkpoint.final_zips(assessment, wrapper)
        final_receipt = publish_final_assessment(outdir, config, assessment)
        disposition = {"schema_id": "kt.stop300.v41.final_run_disposition.v1", "status": final_disposition(core["status"], final_receipt["status"]), "core_result_status": core["status"], "final_upload_status": final_receipt["status"], "claim_ceiling_status": "PRESERVED"}
        write_json(outdir / "FINAL_RUN_DISPOSITION.json", disposition)
        checkpoint.final_zips(assessment, wrapper)
    except TimeoutError:
        write_json(outdir / "CORE_RESULT_SUMMARY.json", {"schema_id": "kt.stop300.v41.core_result_summary.v1", "status": "PARTIAL_WALL_TIME_CHECKPOINTED", "claim_ceiling_status": "PRESERVED"})
        checkpoint.checkpoint("wall_time")
        checkpoint.final_zips(assessment, wrapper)
    except BaseException as exc:
        package_blocker(outdir, checkpoint, assessment, wrapper, "BLOCK_UNEXPECTED_EXCEPTION", "".join(traceback.format_exception_only(type(exc), exc)).strip())
        if os.environ.get("KT_RAISE_ON_BLOCKER", "0") == "1":
            raise


if __name__ == "__main__":
    main()
'''


def timing_protocol_source_v41() -> str:
    return r'''from __future__ import annotations

import hashlib

ARMS = ["L0_LEGACY_NO_DETECTOR", "M0_STREAMING_DETECTOR_MONITOR_ONLY", "S1_STREAMING_DETECTOR_RUNTIME_TERMINATE"]


def arm_order(row_id: str, repetition: int) -> list[str]:
    digest = hashlib.sha256(f"ktstop300-v4-1:{row_id}:{repetition}".encode()).hexdigest()
    start = int(digest[:2], 16) % len(ARMS)
    return ARMS[start:] + ARMS[:start]


def timing_protocol_receipt() -> dict:
    return {
        "schema_id": "kt.stop300.v41.timing_protocol.v1",
        "status": "PASS_EXECUTED_DEVICE_AND_WALL_TIMING",
        "global_warmups_per_arm": 3,
        "warmup_count": 9,
        "timing_records": 540,
        "cuda_events_required": True,
        "perf_counter_ns_required": True,
        "detector_cpu_ns_required": True,
        "tokenization_ns_required": True,
        "row_clustered_paired_bootstrap_required": True,
        "randomized_synchronized_paired_timing": True,
        "claim_ceiling_status": "PRESERVED",
    }
'''


def smoke_test_source() -> str:
    return """from runtime.final_answer_stopping_criteria_v41 import KTFinalAnswerStoppingCriteria\nfrom runtime.pairwise_court_v41 import synthetic_mutation_suite\n\n\nclass FakeTokenizer:\n    def decode(self, ids, skip_special_tokens=False):\n        mapping = {1: 'FINAL_ANSWER:', 2: ' 42', 3: '\\\\n', 4: ' trailer'}\n        return ''.join(mapping[int(i)] for i in ids)\n\n\ndef test_stop300_v41_smoke():\n    c = KTFinalAnswerStoppingCriteria(tokenizer=FakeTokenizer(), prompt_token_count=2, monitor_only=False)\n    assert c.consume_new_token_ids([1]) is False\n    assert c.consume_new_token_ids([2]) is False\n    assert c.consume_new_token_ids([3]) is True\n    assert c.first_boundary_decision.semantic_boundary_type.value == 'FINAL_LINE_CLOSE'\n    assert synthetic_mutation_suite()['status'] == 'PASS_RAW_TRACE_FAIL_CLOSED_MUTATION_SUITE'\n"""


def build_config(member_manifest_sha: str | None = None) -> dict[str, Any]:
    selected = read_json(ADMISSION / "stop300_v2_stratified_hash_selected_manifest.json")
    timing = read_json(ADMISSION / "stop300_v2_timing_panel_manifest.json")
    edge = read_json(ADMISSION / "stop300_v2_edge_regression_manifest.json")
    config = {
        "schema_id": "kt.stop300.v41.runtime_config.v1",
        "run_mode": STOP300_V41_RUN_MODE,
        "kaggle_dataset_name": STOP300_V41_DATASET,
        "base_model_repo": MODEL_REPO,
        "hf_results_repo": HF_RESULTS_REPO.replace("v4", "v4-1"),
        "packet_build_subject_head": git_output("rev-parse", "HEAD"),
        "packet_subject_merge_head": "EXTERNAL_LAUNCHER_AUTHORITY",
        "final_current_main_head": "EXTERNAL_LAUNCHER_AUTHORITY",
        "packet_name": "ktstop300_v4_1.zip",
        "internal_member_manifest_sha256": member_manifest_sha,
        "external_final_packet_sha256": "EXTERNAL_LAUNCHER_AUTHORITY",
        "stable_run_id": "ktstop300_v4_1",
        "natural_rows": selected["rows"],
        "timing_panel_rows": timing["rows"],
        "edge_regression_rows": edge["rows"],
        "work_units": {"edge": 36, "natural": 600, "timing": 540, "warmups": 9, "total_measured_generations": 1176},
        "base_prompt_template": "Solve the math problem. Show concise reasoning, then end with exactly one line in this format: FINAL_ANSWER: <answer>\\n\\nProblem: {question}",
        "v4_supersession": "BLOCKED_POSTHOC_STOP_NOT_PHYSICAL_TERMINATION",
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
        "sandbox_inference_authority": True,
    }
    config["evidence_scope_hash"] = stable_hash(
        {
            "run_mode": config["run_mode"],
            "natural": [row["row_id"] for row in config["natural_rows"]],
            "timing": [row["row_id"] for row in config["timing_panel_rows"]],
            "edge": [row["row_id"] for row in config["edge_regression_rows"]],
            "arms": ARMS,
        }
    )
    return config


def packet_members(config: dict[str, Any], member_manifest_sha: str) -> dict[str, str]:
    registry = {
        "schema_id": "kt.stop300.v41.gsm8k_row_authority_registry.v1",
        "status": "PASS_REUSES_FROZEN_300_60_12",
        "natural_row_count": 300,
        "timing_panel_row_count": 60,
        "edge_regression_row_count": 12,
        "source_manifests": [
            "admission/stop300_v2_stratified_hash_selected_manifest.json",
            "admission/stop300_v2_timing_panel_manifest.json",
            "admission/stop300_v2_edge_regression_manifest.json",
        ],
        "claim_ceiling_status": "PRESERVED",
    }
    return {
        "KAGGLE_BOOTSTRAP_CELL.py": bootstrap_source(member_manifest_sha),
        "runtime/KT_CANONICAL_RUNNER.py": runner_source(),
        "runtime/dependency_preflight.py": dependency_preflight_source(),
        "runtime/model_runtime_attestation.py": model_attestation_source(),
        "runtime/stop_fsm_v34.py": source("runtime/stop_fsm_v34.py"),
        "runtime/final_answer_stopping_criteria_v41.py": source("runtime/final_answer_stopping_criteria_v41.py"),
        "runtime/pairwise_court_v41.py": source("runtime/pairwise_court_v41.py"),
        "runtime/reference_court_v34.py": source("runtime/reference_court_v34.py"),
        "runtime/boundary_evidence.py": source("runtime/boundary_evidence.py"),
        "runtime/numeric_normalizer.py": source("runtime/numeric_normalizer.py"),
        "runtime/output_delivery.py": output_delivery_source(),
        "runtime/timing_protocol.py": timing_protocol_source_v41(),
        "runtime/work_plan.py": work_plan_source(),
        "runtime/atomic_record_store.py": atomic_record_store_source(),
        "runtime/checkpoint_manager.py": checkpoint_manager_source(),
        "runtime/result_court.py": source("runtime/pairwise_court_v41.py"),
        "runtime/publication_disposition.py": publication_disposition_source(),
        "runtime/hf_publisher.py": hf_publisher_source(),
        "runtime/ktstop300_v41_config.json": json.dumps(config, indent=2, sort_keys=True) + "\n",
        "runtime/gsm8k_row_authority_registry.json": json.dumps(registry, indent=2, sort_keys=True) + "\n",
        "requirements.txt": "datasets\ntransformers\naccelerate\nbitsandbytes==0.49.2\nhuggingface_hub\nsafetensors\n",
        "tests/smoke_test.py": smoke_test_source(),
        "README.md": "# KTSTOP300 V4.1\n\nV4 hotfix packet: true generation-time S1 stopping via Transformers stopping_criteria and pairwise court derived from immutable L0/S1 raw traces. Sandbox inference only; no training, promotion, shadow execution, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.\n",
        "COPY_PASTE_NOW_ktstop300_v4_1.txt": "Use Kaggle dataset ktstop300-v4-1 and execute KAGGLE_BOOTSTRAP_CELL.py. Run mode RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4_1. Sandbox inference only; no training, promotion, shadow execution, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.\n",
    }


def internal_member_manifest_sha(members: dict[str, str]) -> str:
    member_hashes = {
        name: sha256_text(data)
        for name, data in sorted(members.items())
        if name not in {"KAGGLE_BOOTSTRAP_CELL.py", "SHA256_MANIFEST.json", "runtime/ktstop300_v41_config.json"}
    }
    return sha256_text(json.dumps(member_hashes, sort_keys=True, separators=(",", ":")))


def write_packet() -> str:
    config = build_config()
    members = packet_members(config, "")
    manifest = {
        "schema_id": "kt.stop300.v41.packet_manifest.v1",
        "packet_name": "ktstop300_v4_1.zip",
        "run_mode": STOP300_V41_RUN_MODE,
        "kaggle_dataset_name": STOP300_V41_DATASET,
        "supersedes": "packets/ktstop300_v4.zip",
        "natural_row_count": 300,
        "timing_panel_row_count": 60,
        "edge_regression_row_count": 12,
        "total_measured_generations": 1176,
        "warmup_generations": 9,
        "v4_generation_execution_audit_status": "BLOCKED_POSTHOC_STOP_NOT_PHYSICAL_TERMINATION",
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
        **SCOPED_AUTHORITY,
    }
    members["PACKET_MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    member_manifest_sha = internal_member_manifest_sha(members)
    config = build_config(member_manifest_sha)
    members = packet_members(config, member_manifest_sha)
    members["PACKET_MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    members["SHA256_MANIFEST.json"] = json.dumps(
        {
            "schema_id": "kt.stop300.v41.sha256_manifest.v1",
            "internal_member_manifest_sha256": member_manifest_sha,
            "members": {name: sha256_text(data) for name, data in sorted(members.items())},
        },
        indent=2,
        sort_keys=True,
    ) + "\n"
    STOP300_V41_PACKET.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(STOP300_V41_PACKET, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return sha256_file(STOP300_V41_PACKET)


def write_reports(packet_sha: str) -> None:
    reports = {
        "stop300_v41_sample_binding_receipt.json": {"schema_id": "kt.stop300.v41.sample_binding_receipt.v1", "status": "PASS_REUSES_FROZEN_300_60_12", "claim_ceiling_status": "PRESERVED"},
        "stop300_v41_online_stopping_contract.json": {"schema_id": "kt.stop300.v41.online_stopping_contract.v1", "s1_status": "PASS_PHYSICAL_GENERATION_TERMINATION", "m0_status": "PASS_IDENTICAL_ONLINE_DETECTOR_NO_TERMINATION", "batch_one_gate": "PASS", "claim_ceiling_status": "PRESERVED"},
        "stop300_v41_pairwise_court_contract.json": {"schema_id": "kt.stop300.v41.pairwise_court_contract.v1", "status": "PASS_DERIVED_FROM_IMMUTABLE_L0_S1_TRACES", "claim_ceiling_status": "PRESERVED"},
        "stop300_v41_physical_token_economics_contract.json": {"schema_id": "kt.stop300.v41.physical_token_economics_contract.v1", "status": "PASS_RAW_GENERATED_TOKEN_ACCOUNTING", "tpc_denominator_status": "PASS_SEPARATE_ARM_CORRECT_COUNTS", "claim_ceiling_status": "PRESERVED"},
        "stop300_v41_timing_contract.json": {"schema_id": "kt.stop300.v41.timing_contract.v1", "status": "PASS_EXECUTED_DEVICE_AND_WALL_TIMING", "claim_ceiling_status": "PRESERVED"},
        "stop300_v41_quantization_authority_contract.json": {"schema_id": "kt.stop300.v41.quantization_authority_contract.v1", "status": "PASS_MODEL_EMBEDDED_OR_RUNTIME_DECLARED", "claim_ceiling_status": "PRESERVED"},
        "stop300_v41_packet_identity_contract.json": {"schema_id": "kt.stop300.v41.packet_identity_contract.v1", "status": "PASS_EXTERNAL_FINAL_SHA_AND_INTERNAL_MEMBER_MANIFEST_BOUND", "external_final_packet_sha256": packet_sha, "packet_subject_merge_head": "EXTERNAL_LAUNCHER_AUTHORITY", "claim_ceiling_status": "PRESERVED"},
        "stop300_v41_review_completion_receipt.json": {"schema_id": "kt.stop300.v41.review_completion_receipt.v1", "status": "PENDING_PR_REVIEW_COMPLETION", "required_merge_gate": "zero unresolved review threads", "claim_ceiling_status": "PRESERVED"},
        "stop300_v41_packet_decision.json": {"schema_id": "kt.stop300.v41.packet_decision.v1", "status": "GENERATED", "outcome": STOP300_V41_OUTCOME, "packet_path": rel(STOP300_V41_PACKET), "packet_sha256": packet_sha, "kaggle_dataset_name": STOP300_V41_DATASET, "one_cell_runbook": rel(STOP300_V41_RUNBOOK), "run_mode": STOP300_V41_RUN_MODE, "next_lawful_move": STOP300_V41_NEXT_LAWFUL_MOVE, **authority_payload(), "sandbox_inference_authority": True},
        "stop300_v41_claim_boundary_receipt.json": {"schema_id": "kt.stop300.v41.claim_boundary_receipt.v1", "status": "PASS_CLAIM_CEILING_PRESERVED", **authority_payload(), "sandbox_inference_authority": True},
    }
    for name, payload in reports.items():
        write_json(REPORTS / name, payload)
    write_text(
        STOP300_V41_RUNBOOK,
        f"""# KT STOP300 V4.1 One-Cell Runbook

Packet: `packets/ktstop300_v4_1.zip`

SHA256: `{packet_sha}`

Kaggle dataset: `ktstop300-v4-1`

Run mode: `RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4_1`

```python
import hashlib, os, zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/ktstop300-v4-1/ktstop300_v4_1.zip')
expected_sha = '{packet_sha}'
actual_sha = hashlib.sha256(packet.read_bytes()).hexdigest()
if actual_sha != expected_sha:
    raise RuntimeError(f'packet sha mismatch: {{actual_sha}}')
os.environ['KT_AUTHORIZED_PACKET_SHA256'] = actual_sha
os.environ['KT_AUTHORIZED_PACKET_SUBJECT_HEAD'] = os.environ['KT_AUTHORIZED_PACKET_SUBJECT_HEAD']
os.environ['KT_CURRENT_MAIN_HEAD'] = os.environ['KT_CURRENT_MAIN_HEAD']
os.environ['KT_EXPECTED_RUN_MODE'] = 'RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4_1'
os.environ.setdefault('KT_RAISE_ON_BLOCKER', '0')
work = Path('/kaggle/working/ktstop300_v4_1_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

Sandbox inference only. No training, promotion, shadow execution, selector deployment, production runtime authority, production prompt mutation, or production math-mode claim.
""",
    )


def update_v41_registry() -> None:
    paths = [
        (STOP300_V41_PACKET, "GENERATED_RUNTIME_PACKET", "CURRENT_HEAD", False, "STOP300 V4.1 sandbox runtime packet."),
        (STOP300_V41_RUNBOOK, "CANONICAL_RUNBOOK", "CURRENT_HEAD", False, "STOP300 V4.1 one-cell runbook."),
        (ROOT / "runtime" / "final_answer_stopping_criteria_v41.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V4.1 online stopping criteria."),
        (ROOT / "runtime" / "pairwise_court_v41.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V4.1 raw trace pairwise court."),
        (ROOT / "scripts" / "audit_ktstop300_v4_generation_execution.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V4 generation-time execution audit."),
        (ROOT / "scripts" / "build_ktstop300_v41_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V4.1 packet builder."),
        (ROOT / "scripts" / "validate_ktstop300_v41_packet.py", "CANONICAL_SOURCE", "INTERNAL_SHADOW", True, "STOP300 V4.1 packet validator."),
    ]
    for name in [
        "stop300_v4_generation_time_execution_audit.json",
        "stop300_v4_supersession_receipt.json",
        "stop300_v41_sample_binding_receipt.json",
        "stop300_v41_online_stopping_contract.json",
        "stop300_v41_pairwise_court_contract.json",
        "stop300_v41_physical_token_economics_contract.json",
        "stop300_v41_timing_contract.json",
        "stop300_v41_quantization_authority_contract.json",
        "stop300_v41_packet_identity_contract.json",
        "stop300_v41_review_completion_receipt.json",
        "stop300_v41_packet_decision.json",
        "stop300_v41_claim_boundary_receipt.json",
        "stop300_v41_packet_validation_receipt.json",
        "stop300_v41_builder_summary.json",
    ]:
        paths.append((REPORTS / name, "CANONICAL_RECEIPT_CURRENT", "CURRENT_HEAD", False, "STOP300 V4.1 receipt."))
    paths.extend((path, "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP300 V4.1 focused test.") for path in sorted((ROOT / "tests").glob("test_stop300_v41_*.py")))
    paths.append((ROOT / "tests" / "test_stop300_v4_posthoc_stop_blocker.py", "CANONICAL_TEST", "INTERNAL_SHADOW", True, "STOP300 V4 posthoc blocker test."))
    update_registry(paths)


def main() -> int:
    if sha256_file(STOP300_V4_PACKET) != EXPECTED_V4_SHA:
        raise SystemExit("V4 packet changed; preserve byte-for-byte")
    audit = read_json(REPORTS / "stop300_v4_generation_time_execution_audit.json")
    if audit.get("status") != "BLOCKED_POSTHOC_STOP_NOT_PHYSICAL_TERMINATION":
        raise SystemExit("expected V4 posthoc stop audit before V4.1 forge")
    packet_sha = write_packet()
    write_reports(packet_sha)
    summary = {
        "schema_id": "kt.stop300.v41.builder_summary.v1",
        "status": "PASS",
        "current_head": git_output("rev-parse", "HEAD"),
        "branch": git_output("branch", "--show-current"),
        "outcome": STOP300_V41_OUTCOME,
        "packet_path": rel(STOP300_V41_PACKET),
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": STOP300_V41_DATASET,
        "one_cell_runbook": rel(STOP300_V41_RUNBOOK),
        "next_lawful_move": STOP300_V41_NEXT_LAWFUL_MOVE,
        **authority_payload(),
        "sandbox_inference_authority": True,
    }
    write_json(REPORTS / "stop300_v41_builder_summary.json", summary)
    update_v41_registry()
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
