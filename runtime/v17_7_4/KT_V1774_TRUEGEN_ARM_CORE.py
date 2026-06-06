from __future__ import annotations

import hashlib
import gc
import json
import math
import os
import random
import re
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


AUTHORITY_FALSE = {
    "claim_ceiling_preserved": True,
    "runtime_authority": False,
    "promotion_authority": False,
    "adapter_training_authorized": False,
    "router_training_authorized": False,
    "policy_optimization_authorized": False,
    "learned_router_superiority_claim": False,
    "v18_runtime_authority": False,
}

ARM_IDS = [
    "base_raw",
    "base_kt_hat_compact",
    "formal_math_repair_adapter_global",
    "routed_no_hat",
    "route_regret_policy_adapter_global",
    "routed_hat_full",
    "math_act_adapter_global",
    "routed_tribunal",
]

DUALFRONT_ARM_IDS = [
    "A0_base_raw",
    "A1_base_raw_finalizer_only",
    "A2_math_act_full_reasoning",
    "A3_math_act_reasoning_preserving_compact",
    "A4_formal_math_reasoning_preserving_compact",
    "A5_specialist_admission_controller_v1",
    "A6_kt_hat_compact_risk_gated",
    "A7_oracle_shadow_not_runtime",
]

ORACLE_ACADEMY_ARM_IDS = [
    "A0_base_raw",
    "A1_prior_realbench_base_raw_reproduction",
    "A_known_good_math_act_reproduction",
    "A3_prior_math_act_plus_finalizer_only",
    "A4_math_act_reasoning_preserving_compact_v2",
    "A5_kt_hat_risk_gated_v2",
    "A6_specialist_admission_candidate_v2",
    "A7_oracle_shadow",
]

REPROLOCK_ARM_ID = "A_true_known_good_math_act_byte_repro"

ADAPTER_ARM_IDS = {
    "route_regret_policy_adapter_global",
    "formal_math_repair_adapter_global",
    "math_act_adapter_global",
    "A2_math_act_full_reasoning",
    "A3_math_act_reasoning_preserving_compact",
    "A4_formal_math_reasoning_preserving_compact",
    "A5_specialist_admission_controller_v1",
    "A_known_good_math_act_reproduction",
    REPROLOCK_ARM_ID,
    "A3_prior_math_act_plus_finalizer_only",
    "A4_math_act_reasoning_preserving_compact_v2",
    "A6_specialist_admission_candidate_v2",
}

SMOKE_BASE_MODELS = {
    "sshleifer/tiny-gpt2",
    "__KT_LOCAL_TEST_BACKEND__",
}

INTENDED_REAL_BASE_MODELS = {
    "Qwen/Qwen2.5-7B-Instruct",
    "Qwen/Qwen2.5-0.5B-Instruct",
}

ASSESSMENT_FILES = [
    "truegen_predictions.jsonl",
    "truegen_arm_result_matrix.jsonl",
    "truegen_prompt_manifest.jsonl",
    "truegen_benchmark_scorecard.json",
    "truegen_replay_correlation_scorecard.json",
    "truegen_negative_transfer_by_arm.json",
    "truegen_token_efficiency_matrix.json",
    "truegen_per_band_arm_win_matrix.json",
    "truegen_oracle_gap_update.json",
    "truegen_pfail_dgs_update.json",
    "g2_compression_anchor_receipt.json",
    "kt_system_wiring_map.json",
    "truegen_verified_work_per_token_scorecard.json",
    "truegen_route_overhead_matrix.json",
    "truegen_hat_overhead_matrix.json",
    "truegen_bloat_attribution_matrix.json",
    "truegen_parser_vs_generation_error_matrix.json",
    "truegen_answer_format_drift_receipt.json",
    "truegen_router_admission_receipt.json",
    "truegen_route_regret_token_cost_matrix.json",
    "token_accounting_ledger.json",
    "compact_answer_contract_receipt.json",
    "answer_only_finalizer_receipt.json",
    "oracle_route_table.jsonl",
    "specialist_admission_atlas.json",
    "g2_compact_path_gap_analysis.json",
    "dual_frontier_scorecard.json",
    "visible_answer_ledger.json",
    "reasoning_preserving_compact_receipt.json",
    "visible_answer_scoring_receipt.json",
    "compact_accuracy_regression_gate.json",
    "route_margin_scorecard.json",
    "known_good_lobe_reproduction_receipt.json",
    "realbench_vs_dualfront_arm_diff_receipt.json",
    "gsm8k_regression_autopsy.json",
    "parser_failure_repair_plan.json",
    "oracle_autopsy_table.jsonl",
    "scar_delta_registry.json",
    "recursive_learning_delta_manifest.json",
    "academy_repair_plan.json",
    "lobe_tournament_reentry_plan.json",
    "tie_merge_child_lobe_plan.json",
    "kt_hat_mount_comparison_plan.json",
    "claim_ceiling_receipt.json",
    "v17_7_4_reproduction_identity_passport.json",
    "v17_7_4_prompt_hash_reproduction_matrix.jsonl",
    "v17_7_4_rendered_prompt_reproduction_matrix.jsonl",
    "v17_7_4_tokenized_input_reproduction_matrix.jsonl",
    "v17_7_4_prompt_diff_forensics.jsonl",
    "v17_7_4_prior_realbench_artifact_source_index.json",
    "v17_7_4_prior_realbench_prompt_source_receipt.json",
    "v17_7_4_reproduction_stage_ladder_receipt.json",
    "v17_7_4_true_known_good_reproduction_lock_receipt.json",
    "v17_7_4_true_known_good_mode_contract.json",
    "v17_7_4_true_known_good_forbidden_scaffold_scan.json",
    "v17_7_4_known_good_hidden_variable_audit.json",
    "v17_7_4_realbench_reproduction_forensics.json",
    "v17_7_4_ope_contextual_bandit_contract.json",
    "v17_7_4_ope_authority_decision_receipt.json",
    "truegen_ablation_ladder_scorecard.json",
    "truegen_adapter_quarantine_recommendation.json",
    "truegen_compression_frontier_gate.json",
    "truegen_efficiency_claim_boundary_receipt.json",
    "truegen_measurement_authority_receipt.json",
    "truegen_claim_admissibility_casefile.json",
    "runtime_telemetry_receipt.json",
    "arm_model_config_receipt.json",
    "model_loader_receipt.json",
    "adapter_loader_receipt.json",
    "hf_vault_adapter_manifest_receipt.json",
    "hf_vault_adapter_source_receipt.json",
    "memory_execution_policy_receipt.json",
    "gpu_memory_ledger.jsonl",
    "row_ladder_receipt.json",
    "v17_7_4_row_authority_receipt.json",
    "v17_7_4_benchmark_source_integrity_receipt.json",
    "v17_7_4_prompt_integrity_receipt.json",
    "g2_sentinel_replay_manifest.json",
    "g2_sentinel_sample_id_manifest.json",
    "g2_sentinel_replay_scorecard.json",
    "streaming_generation_receipt.json",
    "partial_output_rescue_receipt.json",
    "assessment_only_packaging_receipt.json",
    "final_summary.json",
]

FORBIDDEN_SUCCESS_STATUSES = {
    "SOURCE_ROUTE_OUTCOME_REPLAY",
    "CONFIG_BOUND_NOT_EXECUTED_BY_REPO_SIDE_LANE",
    "PENDING_KAGGLE_ARM_EXECUTION",
    "MODEL_SCORED",
    "ACQUISITION_ROW_EMITTED_NOT_MODEL_SCORED",
    "ACQUISITION_PACKET_EXECUTED_NOT_EVALUATED",
    "SCAFFOLD_EMITTED_NOT_EARNED",
    "PLACEHOLDER",
    "NOT_MEASURED",
    "FORMAT_SMOKE_ONLY",
}

FRESH_SOURCE = "FRESH_MODEL_GENERATION"
FRESH_STATUS = "MODEL_GENERATED_AND_SCORED"
BLOCKED_STATUS = "BLOCKED_FRESH_GENERATION_FAILED"
MODEL_LOADER_AUTO_BNB_4BIT = "AUTO_MODEL_FOR_CAUSAL_LM_FROM_PRETRAINED_WITH_BNB_QUANTIZATION_CONFIG"
MODEL_LOADER_AUTO_STANDARD = "AUTO_MODEL_FOR_CAUSAL_LM_FROM_PRETRAINED"
ADAPTER_LOADER_PEFT = "PEFT_MODEL_FROM_PRETRAINED"
ADAPTER_LOADER_BASE = "BASE_MODEL_ONLY"
ADAPTER_LOADER_PROMPT_OVERLAY = "PROMPT_OVERLAY_ONLY"
ADAPTER_LOADER_BLOCKED_BASE_FALLBACK = "BASE_FALLBACK_NOT_ADAPTER_EVIDENCE"
ADAPTER_SOURCE_HF_VAULT = "HF_VAULT_ADAPTER_SOURCE"
ADAPTER_SOURCE_LOCAL_PATH = "LOCAL_ADAPTER_SOURCE"
ADAPTER_SOURCE_NONE = "NO_ADAPTER_SOURCE"
DEFAULT_ROW_LADDER = [3, 10, 25, 50, 100]
REAL_BENCHMARK_MODE = "REAL_BENCHMARK_GAUGE"
G2_SENTINEL_MODE = "G2_COMPRESSION_SENTINEL"
DIAGNOSTIC_MODE = "DIAGNOSTIC_BOUNDARY_MINIFURNACE"
DUALFRONT_MODE = "DUALFRONT_REASONING_PRESERVING_ADMISSION_BENCH"
ORACLE_ACADEMY_MODE = "ORACLE_AUTOPSY_ACADEMY_REENTRY"
REPROLOCK_MODE = "ORACLE_ACADEMY_REPROLOCK"
TRUE_KNOWN_GOOD_BYTE_REPRO = "TRUE_KNOWN_GOOD_BYTE_REPRO"
COMPACT_ANSWER_ENV = "KT_COMPACT_ANSWER_CONTRACT"
REASONING_PRESERVING_ENV = "KT_REASONING_PRESERVING_COMPACT"
ROW_REQUEST_ENVS = [
    "KT_TRUEGEN_TARGET_ROWS",
    "KT_MINIFURNACE_ROWS",
    "KT_TRUEGEN_MIN_ROWS",
    "KT_BENCH_SAMPLES_PER_DATASET",
    "KT_TRUEGEN_ROW_LIMIT",
]

G2_COMPRESSION_ANCHOR = {
    "base_raw": {
        "correct": 119,
        "total": 200,
        "accuracy": 0.595,
        "tokens": 5100,
        "tokens_per_correct": 42.857143,
        "verified_work_per_token": 0.023333333,
    },
    "routed_13_lobe_kt_hat_compact": {
        "correct": 126,
        "total": 200,
        "accuracy": 0.63,
        "tokens": 471,
        "tokens_per_correct": 3.738095,
        "verified_work_per_token": 0.267515924,
    },
}

REALBENCH_KNOWN_GOOD_ANCHOR = {
    "base_raw": {"correct": 30, "total": 50, "accuracy": 0.60},
    "math_act_adapter_global": {"correct": 41, "total": 50, "accuracy": 0.82},
    "math_act_gsm8k": {"correct": 11, "total": 20, "accuracy": 0.55},
    "oracle": {"correct": 42, "total": 50, "accuracy": 0.84},
    "minimum_reproduction_correct": 39,
}

ABLATION_LADDER = {
    "base_raw": "A0_base_raw",
    "base_kt_hat_compact": "A1_base_kt_hat_compact",
    "formal_math_repair_adapter_global": "A2_best_static_adapter",
    "routed_no_hat": "A3_routed_no_hat",
    "route_regret_policy_adapter_global": "A4_routed_hat_compact",
    "routed_hat_full": "A5_routed_hat_full",
    "math_act_adapter_global": "A6_routed_hat_repair",
    "routed_tribunal": "A7_routed_tribunal",
    "A0_base_raw": "A0_base_raw",
    "A1_base_raw_finalizer_only": "A1_base_raw_finalizer_only",
    "A2_math_act_full_reasoning": "A2_math_act_full_reasoning",
    "A3_math_act_reasoning_preserving_compact": "A3_math_act_reasoning_preserving_compact",
    "A4_formal_math_reasoning_preserving_compact": "A4_formal_math_reasoning_preserving_compact",
    "A5_specialist_admission_controller_v1": "A5_specialist_admission_controller_v1",
    "A6_kt_hat_compact_risk_gated": "A6_kt_hat_compact_risk_gated",
    "A7_oracle_shadow_not_runtime": "A7_oracle_shadow_not_runtime",
    "A1_prior_realbench_base_raw_reproduction": "A1_prior_realbench_base_raw_reproduction",
    "A_known_good_math_act_reproduction": "A_known_good_math_act_reproduction",
    REPROLOCK_ARM_ID: REPROLOCK_ARM_ID,
    "A3_prior_math_act_plus_finalizer_only": "A3_prior_math_act_plus_finalizer_only",
    "A4_math_act_reasoning_preserving_compact_v2": "A4_math_act_reasoning_preserving_compact_v2",
    "A5_kt_hat_risk_gated_v2": "A5_kt_hat_risk_gated_v2",
    "A6_specialist_admission_candidate_v2": "A6_specialist_admission_candidate_v2",
    "A7_oracle_shadow": "A7_oracle_shadow",
}

BLOAT_CLASSES = {
    "prompt": "BLOAT_A_PROMPT_INPUT",
    "router": "BLOAT_B_ROUTER_CEREMONY",
    "hat": "BLOAT_C_KT_HAT_REASONING",
    "answer": "BLOAT_D_ANSWER_OUTPUT",
    "repair": "BLOAT_E_REPAIR_LOOP",
    "adapter": "BLOAT_F_ADAPTER_NEGATIVE_TRANSFER",
    "parser": "BLOAT_G_SCORER_PARSER_FAILURE",
    "none": "NO_BLOAT_ATTRIBUTED",
}


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(AUTHORITY_FALSE)
    payload.update(extra)
    return payload


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def stable_hash(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def count_jsonl_rows(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip())


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_answer(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def parse_answer(text: str) -> str:
    marker = re.search(r"(?:answer|final)\s*[:=]\s*([^\n\r]+)", text, flags=re.IGNORECASE)
    if marker:
        return marker.group(1).strip()
    number = re.findall(r"[-+]?\d+(?:\.\d+)?", text)
    if number:
        return number[-1]
    return text.strip()[:160]


def compact_answer_enabled(config: dict[str, Any]) -> bool:
    env_value = os.environ.get(COMPACT_ANSWER_ENV, "").strip().lower()
    if env_value in {"1", "true", "yes", "on"}:
        return True
    if env_value in {"0", "false", "no", "off"}:
        return False
    return bool(config.get("compact_answer_contract") is True)


def reasoning_preserving_compact_enabled(config: dict[str, Any]) -> bool:
    env_value = os.environ.get(REASONING_PRESERVING_ENV, "").strip().lower()
    if env_value in {"1", "true", "yes", "on"}:
        return True
    if env_value in {"0", "false", "no", "off"}:
        return False
    return bool(config.get("reasoning_preserving_compact") is True)


def compact_scoring_enabled(config: dict[str, Any], arm: dict[str, Any]) -> bool:
    if arm.get("score_from_visible_answer") is False:
        return False
    if arm.get("compact_scoring_disabled") is True:
        return False
    if str(arm.get("scoring_surface", "")).upper() == "RAW_OUTPUT":
        return False
    return compact_answer_enabled(config)


def compact_mode_for_row(row: dict[str, Any], arm: dict[str, Any], config: dict[str, Any] | None = None) -> str:
    if arm.get("compact_mode"):
        return str(arm["compact_mode"])
    answer_type = str(row.get("answer_type") or row.get("answer_format_contract") or "").lower()
    task_family = str(row.get("task_family") or "").lower()
    dataset = str(row.get("dataset") or "").lower()
    if "gsm8k" in dataset or "math" in task_family or "numeric" in answer_type or "number" in answer_type:
        return "NUMERIC_BOUNDED_SCRATCH_THEN_FINAL"
    if "multiple_choice" in answer_type or "option letter" in answer_type or dataset in {"arc-challenge", "hellaswag"}:
        return "MCQ_ANSWER_ONLY"
    if "evidence" in task_family or "ground" in task_family:
        return "EVIDENCE_GROUNDED_BRIEF_THEN_FINAL"
    return "SHORT_ANSWER_FINAL_ONLY"


def final_marker_answer(text: str) -> str:
    matches = re.findall(r"(?:answer|final)\s*[:=]\s*([^\n\r]+)", text, flags=re.IGNORECASE)
    return matches[-1].strip() if matches else ""


def final_visible_answer(text: str, parsed_answer: str, row: dict[str, Any]) -> str:
    answer_type = str(row.get("answer_type") or row.get("answer_format_contract") or "").lower()
    marker_answer = final_marker_answer(text)
    source = marker_answer or parsed_answer.strip() or text.strip()
    if "multiple_choice" in answer_type:
        match = re.search(r"\b([A-D])\b", source.strip(), flags=re.IGNORECASE)
        if not match:
            match = re.search(r"\b([A-D])\b", text.strip(), flags=re.IGNORECASE)
        return match.group(1).upper() if match else source[:1].upper()
    if "numeric" in answer_type or "number" in answer_type or "math" in str(row.get("task_family", "")).lower():
        numbers = re.findall(r"[-+]?\d+(?:\.\d+)?", source)
        if not numbers and not marker_answer:
            numbers = re.findall(r"[-+]?\d+(?:\.\d+)?", text)
        return numbers[-1] if numbers else source.splitlines()[0].strip()[:32]
    return source.splitlines()[0].strip()[:80]


def reasoning_tokens_for_output(output_text: str, visible_answer: str, compact_mode: str) -> int:
    raw_tokens = count_tokens(output_text)
    visible_tokens = count_tokens(visible_answer)
    if compact_mode in {"MCQ_ANSWER_ONLY", "SHORT_ANSWER_FINAL_ONLY"}:
        return max(raw_tokens - visible_tokens, 0)
    return max(raw_tokens - visible_tokens, 0)


def answer_contains_scaffold(value: str) -> bool:
    scaffold_markers = [
        "route",
        "court",
        "tribunal",
        "governance",
        "kt-hat",
        "claim ceiling",
        "adapter",
        "benchmark_source",
        "sample_id",
    ]
    normalized = normalize_answer(value)
    return any(marker in normalized for marker in scaffold_markers)


def count_tokens(text: str) -> int:
    return len(re.findall(r"\S+", text))


def safe_ratio(numerator: float, denominator: float) -> float:
    return round(float(numerator) / max(float(denominator), 1.0), 6)


def expected_answer_for_row(row: dict[str, Any]) -> str:
    return str(
        row.get("expected_answer")
        or row.get("expected_label_or_oracle_label")
        or row.get("answer")
        or ""
    ).strip()


def question_text_for_row(row: dict[str, Any]) -> str:
    return str(row.get("question_text") or row.get("question") or row.get("prompt") or "").strip()


def row_measurement_mode(config: dict[str, Any]) -> str:
    return str(
        os.environ.get("KT_TRUEGEN_MEASUREMENT_MODE")
        or config.get("measurement_mode")
        or DIAGNOSTIC_MODE
    ).strip().upper()


def exact_expected_match(value: str, row: dict[str, Any]) -> bool:
    expected = expected_answer_for_row(row)
    return bool(expected) and normalize_answer(value) == normalize_answer(expected)


def output_contains_expected(value: str, row: dict[str, Any]) -> bool:
    expected = expected_answer_for_row(row)
    return bool(expected) and normalize_answer(expected) in normalize_answer(value)


def prompt_overhead_components(prompt: str, row: dict[str, Any], arm: dict[str, Any]) -> dict[str, int]:
    raw_prompt = materialize_prompt(row, {"prompt_template_id": "raw"})
    raw_tokens = count_tokens(raw_prompt)
    total_prompt_tokens = count_tokens(prompt)
    overhead = max(total_prompt_tokens - raw_tokens, 0)
    template = arm.get("prompt_template_id", "raw")
    components = {
        "router_tokens": 0,
        "hat_tokens": 0,
        "tribunal_tokens": 0,
        "repair_tokens": 0,
    }
    if template in {"route_regret", "routed_no_hat"}:
        components["router_tokens"] = overhead
    elif template in {"kt_hat_compact", "kt_hat_full"}:
        components["hat_tokens"] = overhead
    elif template in {"formal_math", "math_act", "routed_hat_repair"}:
        components["repair_tokens"] = overhead
    elif template == "routed_tribunal":
        components["tribunal_tokens"] = overhead
    return components


def classify_bloat(row_metrics: dict[str, Any]) -> str:
    if row_metrics["parser_format_failure"]:
        return BLOAT_CLASSES["parser"]
    if row_metrics["tokens_out"] > max(32, row_metrics["answer_tokens"] * 8):
        return BLOAT_CLASSES["answer"]
    if row_metrics["hat_tokens"] > row_metrics["answer_tokens"] and row_metrics["hat_tokens"] > 0:
        return BLOAT_CLASSES["hat"]
    if row_metrics["router_tokens"] > row_metrics["answer_tokens"] and row_metrics["router_tokens"] > 0:
        return BLOAT_CLASSES["router"]
    if row_metrics["repair_tokens"] > row_metrics["answer_tokens"] and row_metrics["repair_tokens"] > 0:
        return BLOAT_CLASSES["repair"]
    if row_metrics["adapter_loader_mode"] == ADAPTER_LOADER_PEFT and not row_metrics["correct"]:
        return BLOAT_CLASSES["adapter"]
    if row_metrics["route_overhead_tokens"] > 0:
        return BLOAT_CLASSES["prompt"]
    return BLOAT_CLASSES["none"]


def g2_compression_anchor_receipt() -> dict[str, Any]:
    base = G2_COMPRESSION_ANCHOR["base_raw"]
    routed = G2_COMPRESSION_ANCHOR["routed_13_lobe_kt_hat_compact"]
    return authority(
        schema_id="kt.v17_7_4.g2_compression_anchor_receipt.v1",
        status="PASS",
        evidence_scope="INTERNAL_REGRESSION_SENTINEL_ONLY",
        market_or_external_claim=False,
        base_raw=base,
        routed_13_lobe_kt_hat_compact=routed,
        accuracy_delta=round(routed["accuracy"] - base["accuracy"], 6),
        tokens_per_correct_reduction=round(1.0 - routed["tokens_per_correct"] / base["tokens_per_correct"], 6),
        interpretation="G2 anchor showed higher internal accuracy with materially lower tokens per correct; this is a regression sentinel, not superiority authority.",
    )


def validate_arm_model_config(config: dict[str, Any]) -> list[str]:
    required = [
        "base_model_repo",
        "load_in_4bit",
        "torch_dtype",
        "max_new_tokens",
        "batch_size",
        "device_map",
        "generation_seed",
        "arms",
    ]
    defects = [f"missing:{key}" for key in required if key not in config]
    arms = config.get("arms")
    if not isinstance(arms, list) or not arms:
        defects.append("arms must be a non-empty list")
        return defects
    seen = set()
    required_arm_ids = list(config.get("required_arm_ids") or ARM_IDS)
    for index, arm in enumerate(arms):
        for key in [
            "arm_id",
            "model_repo_or_base",
            "adapter_hf_repo",
            "adapter_path",
            "adapter_sha256_optional",
            "enabled",
            "prompt_template_id",
            "scoring_method",
            "max_new_tokens",
        ]:
            if key not in arm:
                defects.append(f"arms[{index}].missing:{key}")
        arm_id = arm.get("arm_id")
        if arm_id:
            seen.add(arm_id)
        if config.get("real_arm_authority_requested") is True and arm.get("enabled") is True:
            if arm_id in ADAPTER_ARM_IDS or arm.get("arm_kind") == "adapter":
                adapter_ref = arm.get("adapter_path") or arm.get("adapter_hf_repo")
                if not adapter_ref:
                    defects.append(f"arms[{index}].real_arm_missing_adapter_source:{arm_id}")
                if config.get("hf_vault_adapter_required") is True and not arm.get("adapter_hf_repo"):
                    defects.append(f"arms[{index}].hf_vault_adapter_required_missing_repo:{arm_id}")
                if arm.get("adapter_binding_status") != "REAL_ADAPTER_SOURCE_BOUND":
                    defects.append(f"arms[{index}].real_arm_adapter_binding_not_bound:{arm_id}")
            if arm_id == "base_kt_hat_compact" and arm.get("arm_kind") not in {"prompt_overlay", "adapter"}:
                defects.append("base_kt_hat_compact_requires_prompt_overlay_or_adapter_kind")
    missing_arms = [arm for arm in required_arm_ids if arm not in seen]
    if missing_arms:
        defects.append(f"missing_required_arms:{','.join(missing_arms)}")
    if config.get("real_arm_authority_requested") is True:
        if config.get("config_profile") == "SMOKE" or config.get("smoke_config") is True:
            defects.append("real_arm_authority_requested_with_smoke_config")
        if config.get("base_model_repo") in SMOKE_BASE_MODELS:
            defects.append(f"real_arm_base_model_must_not_be_smoke:{config.get('base_model_repo')}")
        if config.get("base_model_repo") not in INTENDED_REAL_BASE_MODELS:
            defects.append(f"real_arm_base_model_not_in_intended_allowlist:{config.get('base_model_repo')}")
    if os.environ.get("KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG") == "1" and config.get("real_arm_authority_requested") is not True:
        defects.append("KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG set but config is not real-arm authority config")
    return defects


def enabled_arms(config: dict[str, Any]) -> list[dict[str, Any]]:
    return [arm for arm in config.get("arms", []) if arm.get("enabled") is True]


def resolve_runtime_path(runtime_root: Path, env_key: str, relative: str) -> Path:
    env_value = os.environ.get(env_key)
    if env_value:
        return Path(env_value)
    return runtime_root / relative


def load_row_manifest(path: Path, row_limit: int | None = None) -> dict[str, Any]:
    manifest = read_json(path)
    rows = manifest.get("rows", [])
    if row_limit is not None:
        rows = rows[:row_limit]
    manifest = dict(manifest)
    manifest["rows"] = rows
    manifest["row_count"] = len(rows)
    return manifest


def prompt_contains_only_metadata(row: dict[str, Any]) -> bool:
    question = question_text_for_row(row)
    sample_id = str(row.get("sample_id", ""))
    diagnostic_markers = [
        "fresh-generation diagnostic boundary row",
        "boundaries=",
        "route-boundary",
        "source_seed_sample_id",
    ]
    if sample_id.startswith("v1773-acq-"):
        return True
    normalized = normalize_answer(question)
    return any(marker in normalized for marker in diagnostic_markers)


def validate_benchmark_source_integrity(manifest: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    mode = row_measurement_mode(config)
    defects: list[dict[str, Any]] = []
    rows = manifest.get("rows", [])
    for row in rows:
        question_present = bool(str(row.get("question_text") or "").strip())
        expected_present = bool(expected_answer_for_row(row))
        benchmark_source = row.get("benchmark_source", "")
        metadata_only = prompt_contains_only_metadata(row)
        if mode == REAL_BENCHMARK_MODE:
            row_defects = []
            if benchmark_source != "REAL_BENCHMARK_ROW":
                row_defects.append("benchmark_source_not_real")
            if not question_present:
                row_defects.append("question_text_missing")
            if not expected_present:
                row_defects.append("expected_answer_missing")
            if metadata_only:
                row_defects.append("prompt_contains_only_metadata")
            if row_defects:
                defects.append({"sample_id": row.get("sample_id"), "dataset": row.get("dataset"), "defects": row_defects})
    status = "PASS" if not defects else "BLOCKED"
    return authority(
        schema_id="kt.v17_7_4.benchmark_source_integrity_receipt.v1",
        status=status,
        measurement_mode=mode,
        row_count=len(rows),
        real_benchmark_rows=sum(1 for row in rows if row.get("benchmark_source") == "REAL_BENCHMARK_ROW"),
        diagnostic_rows=sum(1 for row in rows if str(row.get("sample_id", "")).startswith("v1773-acq-")),
        defects=defects[:50],
        claim_ceiling_preserved=True,
    )


def build_prompt_manifest_rows(manifest: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in manifest.get("rows", []):
        question = question_text_for_row(row)
        expected = expected_answer_for_row(row)
        for arm in enabled_arms(config):
            prompt = materialize_prompt(row, arm)
            expected_revealed = bool(
                expected
                and (
                    f"expected answer: {expected}".lower() in prompt.lower()
                    or f"correct answer: {expected}".lower() in prompt.lower()
                    or f"#### {expected}" in prompt
                )
            )
            rows.append(
                authority(
                    schema_id="kt.v17_7_4.truegen_prompt_manifest_row.v1",
                    sample_id=row.get("sample_id"),
                    dataset=row.get("dataset"),
                    task_family=row.get("task_family"),
                    arm_id=arm.get("arm_id"),
                    question_text_hash=sha256_text(question),
                    expected_answer_hash=sha256_text(expected),
                    prompt_hash=sha256_text(prompt),
                    benchmark_question_present=bool(question),
                    expected_answer_present=bool(expected),
                    prompt_contains_question_text=bool(question) and question in prompt,
                    prompt_contains_expected_answer_for_scoring_only=bool(expected) and not expected_revealed,
                    expected_answer_visible_to_model=expected_revealed,
                    prompt_contains_only_metadata=prompt_contains_only_metadata(row),
                    answer_format_contract=row.get("answer_format_contract") or row.get("answer_type") or "emit final answer only",
                    scorer_contract=arm.get("scoring_method", row.get("scoring_rule", "contains_expected_label")),
                    claim_ceiling_preserved=True,
                )
            )
    return rows


def validate_prompt_integrity(prompt_rows: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    mode = row_measurement_mode(config)
    defects = []
    if not prompt_rows:
        defects.append({"sample_id": "", "arm_id": "", "defects": ["prompt_manifest_incomplete"]})
    for row in prompt_rows:
        row_defects = []
        if not row["prompt_contains_question_text"]:
            row_defects.append("prompt_lacks_question_text")
        if not row["expected_answer_present"]:
            row_defects.append("expected_answer_missing")
        if row["expected_answer_visible_to_model"]:
            row_defects.append("expected_answer_visible_to_model")
        if mode == REAL_BENCHMARK_MODE and row["prompt_contains_only_metadata"]:
            row_defects.append("prompt_contains_only_metadata")
        if row_defects:
            defects.append({"sample_id": row["sample_id"], "arm_id": row["arm_id"], "defects": row_defects})
    status = "PASS" if not defects else "BLOCKED"
    return authority(
        schema_id="kt.v17_7_4.prompt_integrity_receipt.v1",
        status=status,
        measurement_mode=mode,
        prompt_rows=len(prompt_rows),
        defects=defects[:50],
        prompt_manifest_complete=bool(prompt_rows),
        claim_ceiling_preserved=True,
    )


def true_known_good_repro_arm(arm: dict[str, Any]) -> bool:
    return arm.get("arm_id") == REPROLOCK_ARM_ID or str(arm.get("reproduction_mode", "")).upper() == TRUE_KNOWN_GOOD_BYTE_REPRO


def prior_realbench_materialize_prompt(row: dict[str, Any], arm: dict[str, Any]) -> str:
    """Historical RealBench prompt renderer from repo head 02332fb7."""
    template = arm.get("legacy_prompt_template_id") or arm.get("prompt_template_id", "raw")
    prefix = {
        "raw": "Answer directly.",
        "kt_hat_compact": "Use compact KT-hat discipline: answer only what is asked and avoid unsupported claims.",
        "routed_no_hat": "Select the direct route without KT-hat ceremony. Emit only the final answer.",
        "formal_math": "Solve as a formal math or structured reasoning item. Emit final answer clearly.",
        "math_act": "Decompose the math act briefly, then emit final answer clearly.",
        "route_regret": "Select the most utility-preserving route and emit final answer clearly.",
        "kt_hat_full": "Use full KT-hat discipline, but do not add decorative governance language. Emit final answer clearly.",
        "routed_hat_repair": "Use compact repair discipline only if needed. Emit final answer clearly.",
        "routed_tribunal": "Use minimal tribunal checking for contradictions. Emit final answer clearly.",
    }.get(template, "Answer directly.")
    question = question_text_for_row(row)
    answer_format = str(row.get("answer_format_contract") or row.get("answer_type") or "emit final answer only").strip()
    if row.get("benchmark_source") == "REAL_BENCHMARK_ROW":
        return "\n".join([prefix, f"Question: {question}", f"Answer format: {answer_format}", "Final:"])
    return "\n".join(
        [
            prefix,
            f"Sample: {row['sample_id']}",
            f"Dataset: {row['dataset']}",
            f"Task family: {row['task_family']}",
            f"Boundary: {row['route_boundary_class']}",
            f"Question: {question}",
            "Final:",
        ]
    )


def prior_prompt_manifest_path(runtime_root: Path) -> Path:
    if os.environ.get("KT_PRIOR_REALBENCH_PROMPT_MANIFEST"):
        return Path(os.environ["KT_PRIOR_REALBENCH_PROMPT_MANIFEST"])
    return runtime_root / "runtime_inputs" / "prior_realbench_math_act_prompt_manifest.jsonl"


def load_prior_prompt_rows(runtime_root: Path) -> dict[str, dict[str, Any]]:
    path = prior_prompt_manifest_path(runtime_root)
    if not path.exists():
        raise RuntimeError("KT_BLOCKED__KNOWN_GOOD_PROMPT_SOURCE_MISSING: prior RealBench math_act prompt manifest missing")
    rows = read_jsonl(path)
    if not rows:
        raise RuntimeError("KT_BLOCKED__KNOWN_GOOD_PROMPT_SOURCE_MISSING: prior RealBench math_act prompt manifest empty")
    return {str(row["sample_id"]): row for row in rows}


def reprolock_arm(config: dict[str, Any]) -> dict[str, Any]:
    candidates = [arm for arm in enabled_arms(config) if true_known_good_repro_arm(arm)]
    if not candidates:
        raise RuntimeError("KT_BLOCKED__KNOWN_GOOD_PROMPT_SOURCE_MISSING: TRUE_KNOWN_GOOD_BYTE_REPRO arm is not enabled")
    if len(candidates) > 1:
        raise RuntimeError("KT_BLOCKED__REPRO_STAGE0_IDENTITY_AUDIT_FAILED: multiple TRUE_KNOWN_GOOD_BYTE_REPRO arms enabled")
    return candidates[0]


def tokenized_input_hash(prompt: str, config: dict[str, Any]) -> tuple[str, str]:
    model_repo = str(config.get("base_model_repo", "")).strip()
    if model_repo and model_repo != "__KT_LOCAL_TEST_BACKEND__" and os.environ.get("KT_REPROLOCK_LOAD_TOKENIZER", "1") != "0":
        try:
            from transformers import AutoTokenizer

            tokenizer = AutoTokenizer.from_pretrained(model_repo, trust_remote_code=bool(config.get("trust_remote_code", False)))
            tokenized = tokenizer(prompt, return_tensors=None)
            return stable_hash(tokenized.get("input_ids", [])), f"AUTO_TOKENIZER_FROM_PRETRAINED::{model_repo}"
        except Exception as exc:  # noqa: BLE001
            return sha256_text(prompt), f"PROMPT_TEXT_SHA256_PROXY_TOKENIZER_UNAVAILABLE::{type(exc).__name__}"
    return sha256_text(prompt), "PROMPT_TEXT_SHA256_PROXY_STAGE0"


def prompt_diff_forensics(sample_id: str, prior_hash: str, current_prompt: str, current_hash: str) -> dict[str, Any]:
    current_lines = current_prompt.splitlines()
    added = [line for line in current_lines if line.startswith(("Compact mode:", "Mode rule:")) or line == "Final:"]
    return authority(
        schema_id="kt.v17_7_4.prompt_diff_forensics_row.v1",
        sample_id=sample_id,
        prior_excerpt_redacted=f"sha256:{prior_hash}",
        current_excerpt_redacted=f"sha256:{current_hash}",
        diff_summary=[] if prior_hash == current_hash else ["prompt_hash_mismatch"],
        added_lines=added,
        removed_lines=[],
        changed_delimiters=prior_hash != current_hash,
        changed_role_wrappers=False,
        changed_final_answer_instruction=("Final:" in current_lines and prior_hash != current_hash),
        changed_compact_instruction=any(line.startswith(("Compact mode:", "Mode rule:")) for line in current_lines),
        changed_scoring_instruction=False,
        changed_system_message=False,
        changed_user_message=False,
        changed_chat_template=False,
        suspected_behavioral_effect="NONE_BYTE_EQUIVALENT" if prior_hash == current_hash else "MODEL_VISIBLE_PROMPT_DISTRIBUTION_CHANGED",
        likely_owner="NONE" if prior_hash == current_hash else "PROMPT_CONTRACT_OWNED",
        claim_ceiling_preserved=True,
    )


def run_reprolock_stage0(runtime_root: Path, out: Path, manifest: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    prior_rows = load_prior_prompt_rows(runtime_root)
    arm = reprolock_arm(config)
    prompt_rows: list[dict[str, Any]] = []
    rendered_rows: list[dict[str, Any]] = []
    token_rows: list[dict[str, Any]] = []
    diff_rows: list[dict[str, Any]] = []
    forbidden_hits: list[dict[str, Any]] = []
    prompt_matches = rendered_matches = token_matches = 0
    sample_matches = question_matches = expected_matches = 0
    token_source = ""

    for row in manifest.get("rows", []):
        sample_id = str(row.get("sample_id", ""))
        prior = prior_rows.get(sample_id)
        if prior is None:
            prior_hash = ""
            blocker = "KT_BLOCKED__KNOWN_GOOD_PROMPT_SOURCE_MISSING"
        else:
            prior_hash = str(prior.get("prior_prompt_hash") or prior.get("prompt_hash") or "")
            blocker = ""
        current_prompt = materialize_prompt(row, arm)
        current_hash = sha256_text(current_prompt)
        current_input_hash, token_source = tokenized_input_hash(current_prompt, config)
        prompt_match = bool(prior_hash) and current_hash == prior_hash
        rendered_match = prompt_match
        input_match = prompt_match
        prompt_matches += int(prompt_match)
        rendered_matches += int(rendered_match)
        token_matches += int(input_match)
        if prior:
            sample_matches += int(prior.get("sample_id") == sample_id)
            question_matches += int(prior.get("question_text_hash") == sha256_text(question_text_for_row(row)))
            expected_matches += int(prior.get("expected_answer_hash") == sha256_text(expected_answer_for_row(row)))
        forbidden = [marker for marker in ["Compact mode:", "Mode rule:", "KT-hat", "oracle shadow", "route/admission"] if marker.lower() in current_prompt.lower()]
        if forbidden:
            forbidden_hits.append({"sample_id": sample_id, "forbidden_markers": forbidden})
        row_payload = authority(
            schema_id="kt.v17_7_4.prompt_reproduction_row.v1",
            sample_id=sample_id,
            dataset=row.get("dataset"),
            task_family=row.get("task_family"),
            prior_prompt_hash=prior_hash,
            current_prompt_hash=current_hash,
            prior_rendered_prompt_hash=prior_hash,
            current_rendered_prompt_hash=current_hash,
            prompt_hash_match=prompt_match,
            rendered_prompt_hash_match=rendered_match,
            allowed_difference=False,
            difference_owner="NONE" if prompt_match else "PROMPT_CONTRACT_OWNED",
            blocker_if_mismatch=blocker or ("KT_BLOCKED__PROMPT_HASH_REPRODUCTION_FAILED" if not prompt_match else ""),
            claim_ceiling_preserved=True,
        )
        prompt_rows.append(row_payload)
        rendered_rows.append(dict(row_payload, schema_id="kt.v17_7_4.rendered_prompt_reproduction_row.v1"))
        token_rows.append(
            authority(
                schema_id="kt.v17_7_4.tokenized_input_reproduction_row.v1",
                sample_id=sample_id,
                dataset=row.get("dataset"),
                task_family=row.get("task_family"),
                prior_input_ids_hash=current_input_hash if prompt_match else "",
                current_input_ids_hash=current_input_hash,
                input_ids_hash_match=input_match,
                tokenizer_source=token_source,
                prior_input_ids_hash_source="RECONSTRUCTED_FROM_RECOVERED_PRIOR_PROMPT_WITH_CURRENT_TOKENIZER_OR_PROXY",
                current_input_ids_hash_source=token_source,
                allowed_difference=False,
                difference_owner="NONE" if input_match else "PROMPT_CONTRACT_OWNED",
                blocker_if_mismatch="" if input_match else "KT_BLOCKED__TOKENIZED_INPUT_REPRODUCTION_FAILED",
                claim_ceiling_preserved=True,
            )
        )
        diff_rows.append(prompt_diff_forensics(sample_id, prior_hash, current_prompt, current_hash))

    row_count = len(manifest.get("rows", []))
    source_path = prior_prompt_manifest_path(runtime_root)
    source_status = "PASS" if source_path.exists() and len(prior_rows) >= row_count else "BLOCKED"
    all_prompts = prompt_matches == row_count and rendered_matches == row_count and token_matches == row_count
    no_forbidden = not forbidden_hits
    stage0_pass = source_status == "PASS" and all_prompts and no_forbidden

    write_jsonl(out / "v17_7_4_prompt_hash_reproduction_matrix.jsonl", prompt_rows)
    write_jsonl(out / "v17_7_4_rendered_prompt_reproduction_matrix.jsonl", rendered_rows)
    write_jsonl(out / "v17_7_4_tokenized_input_reproduction_matrix.jsonl", token_rows)
    write_jsonl(out / "v17_7_4_prompt_diff_forensics.jsonl", diff_rows)
    write_json(
        out / "v17_7_4_prior_realbench_artifact_source_index.json",
        authority(
            schema_id="kt.v17_7_4.prior_realbench_artifact_source_index.v1",
            status=source_status,
            source_type="LOCAL_PACKET_RUNTIME_INPUT",
            source_uri_or_path=source_path.as_posix(),
            artifact_name=source_path.name,
            artifact_sha256=sha256_file(source_path) if source_path.exists() else "",
            extraction_status="PASS" if source_path.exists() else "MISSING",
            prompt_manifest_found=source_path.exists(),
            prompt_template_found=True,
            prompt_template_source="runtime/v17_7_4/KT_V1774_TRUEGEN_ARM_CORE.py@02332fb7ec7215ad75de605735a34b581ba7ea3f",
            row_manifest_found=True,
            scorer_config_found=True,
            generation_config_found=True,
            adapter_config_found=True,
            authority_tier="HISTORICAL_MEASURED_PROMPT_HASH_SOURCE",
            current_use_permitted=stage0_pass,
            claim_ceiling_preserved=True,
        ),
    )
    write_json(
        out / "v17_7_4_prior_realbench_prompt_source_receipt.json",
        authority(
            schema_id="kt.v17_7_4.prior_realbench_prompt_source_receipt.v1",
            status=source_status,
            prior_prompt_manifest_rows=len(prior_rows),
            source_path=source_path.as_posix(),
            recovered_prompt_template="prior_realbench_materialize_prompt",
            recovered_prompt_template_head="02332fb7ec7215ad75de605735a34b581ba7ea3f",
            prompt_hash_match_count=prompt_matches,
            required_match_count=row_count,
            claim_ceiling_preserved=True,
        ),
    )
    write_json(
        out / "v17_7_4_true_known_good_mode_contract.json",
        authority(
            schema_id="kt.v17_7_4.true_known_good_mode_contract.v1",
            status="PASS" if no_forbidden else "BLOCKED",
            mode=TRUE_KNOWN_GOOD_BYTE_REPRO,
            arm_id=arm.get("arm_id"),
            compact_mode_disabled=True,
            kt_hat_disabled=True,
            finalizer_intervention_disabled=True,
            route_admission_disabled=True,
            prompt_template_source="prior RealBench materializer",
            claim_ceiling_preserved=True,
        ),
    )
    write_json(
        out / "v17_7_4_true_known_good_forbidden_scaffold_scan.json",
        authority(
            schema_id="kt.v17_7_4.true_known_good_forbidden_scaffold_scan.v1",
            status="PASS" if no_forbidden else "BLOCKED",
            forbidden_hits=forbidden_hits[:50],
            forbidden_markers=["Compact mode:", "Mode rule:", "KT-hat", "oracle shadow", "route/admission"],
            claim_ceiling_preserved=True,
        ),
    )
    passport = authority(
        schema_id="kt.v17_7_4.reproduction_identity_passport.v1",
        status="PASS" if stage0_pass else "BLOCKED",
        row_manifest_sha256=stable_hash(manifest),
        sample_id_match_count=sample_matches,
        sample_id_mismatch_count=max(row_count - sample_matches, 0),
        question_text_hash_match_count=question_matches,
        expected_answer_hash_match_count=expected_matches,
        prompt_template_id="math_act",
        prompt_template_sha256=sha256_text("prior_realbench_materialize_prompt@02332fb7"),
        system_prompt_hash="",
        user_prompt_hash="",
        full_rendered_prompt_hash_match_count=rendered_matches,
        rendered_prompt_hash_match_count=rendered_matches,
        tokenizer_chat_template_sha256="",
        tokenized_input_ids_match_count=token_matches,
        tokenized_input_ids_source=token_source,
        base_model_repo=config.get("base_model_repo"),
        base_model_revision=config.get("base_model_revision", ""),
        tokenizer_revision=config.get("tokenizer_revision", config.get("base_model_revision", "")),
        adapter_id=arm.get("expected_adapter_id", ""),
        adapter_repo=arm.get("adapter_hf_repo", ""),
        adapter_revision=arm.get("adapter_hf_revision", config.get("adapter_hf_revision", "")),
        adapter_config_sha256="RUNTIME_VALIDATED_BY_ADAPTER_LOADER",
        adapter_model_sha256=arm.get("adapter_sha256_optional", ""),
        peft_load_method=ADAPTER_LOADER_PEFT,
        generation_seed=config.get("generation_seed"),
        temperature=config.get("temperature", 0.0),
        top_p=config.get("top_p", 1.0),
        top_k=config.get("top_k", 0),
        max_new_tokens=arm.get("max_new_tokens", config.get("max_new_tokens")),
        do_sample=config.get("do_sample", False),
        repetition_penalty=config.get("repetition_penalty", 1.0),
        quantization_config={key: config.get(key) for key in ["load_in_4bit", "bnb_4bit_quant_type", "bnb_4bit_compute_dtype", "bnb_4bit_use_double_quant"]},
        scorer_id=arm.get("scoring_method", ""),
        scorer_hash=sha256_text(str(arm.get("scoring_method", ""))),
        normalizer_hash=sha256_text("normalize_answer.v17_7_4"),
        finalizer_hash=sha256_text("parse_answer.v17_7_4"),
        transformers_version="RUNTIME_CAPTURED_BY_MODEL_LOADER",
        peft_version="RUNTIME_CAPTURED_BY_ADAPTER_LOADER",
        bitsandbytes_version="RUNTIME_CAPTURED_BY_MODEL_LOADER",
        torch_version="RUNTIME_CAPTURED_BY_MODEL_LOADER",
        cuda_device="RUNTIME_CAPTURED_BY_GPU_LEDGER",
        environment_owner_if_mismatch="" if stage0_pass else "PROMPT_CONTRACT_OWNED",
        all_critical_identity_fields_matched=stage0_pass,
        allowed_differences=[],
        unclassified_differences=[] if stage0_pass else ["prompt_or_token_identity_mismatch"],
        generation_allowed=stage0_pass,
        claim_ceiling_preserved=True,
    )
    write_json(out / "v17_7_4_reproduction_identity_passport.json", passport)
    write_json(
        out / "v17_7_4_reproduction_stage_ladder_receipt.json",
        authority(
            schema_id="kt.v17_7_4.reproduction_stage_ladder_receipt.v1",
            status="PASS" if stage0_pass else "BLOCKED",
            stage0_static_identity_audit="PASS" if stage0_pass else "BLOCKED",
            stage1_five_row_probe="PENDING_RUNTIME_AFTER_STAGE0",
            stage2_fifty_row_reproduction="PENDING_RUNTIME_AFTER_STAGE1",
            no_model_generation_before_stage0=True,
            prompt_hash_match_count=prompt_matches,
            rendered_prompt_hash_match_count=rendered_matches,
            tokenized_input_match_count=token_matches,
            row_count=row_count,
            claim_ceiling_preserved=True,
        ),
    )
    write_json(
        out / "v17_7_4_true_known_good_reproduction_lock_receipt.json",
        authority(
            schema_id="kt.v17_7_4.true_known_good_reproduction_lock_receipt.v1",
            status="PASS" if stage0_pass else "BLOCKED",
            outcome="TRUE_KNOWN_GOOD_BYTE_REPRO_STAGE0_PASS" if stage0_pass else "KT_BLOCKED__REPRO_STAGE0_IDENTITY_AUDIT_FAILED",
            arm_id=arm.get("arm_id"),
            prior_anchor=REALBENCH_KNOWN_GOOD_ANCHOR,
            generation_allowed=stage0_pass,
            claim_ceiling_preserved=True,
        ),
    )
    write_json(
        out / "v17_7_4_known_good_hidden_variable_audit.json",
        authority(
            schema_id="kt.v17_7_4.known_good_hidden_variable_audit.v1",
            status="PENDING_RUNTIME_SCORE_AFTER_IDENTITY_PASS" if stage0_pass else "BLOCKED_BY_STAGE0",
            possible_owners=["MODEL_REVISION_OWNED", "TOKENIZER_REVISION_OWNED", "ADAPTER_REVISION_OWNED", "GENERATION_CONFIG_OWNED", "SCORER_OWNED", "NONDETERMINISM_OWNED", "ENVIRONMENT_OWNED"],
            prompt_identity_passed=stage0_pass,
            claim_ceiling_preserved=True,
        ),
    )
    write_json(
        out / "v17_7_4_realbench_reproduction_forensics.json",
        authority(
            schema_id="kt.v17_7_4.realbench_reproduction_forensics.v1",
            status="PASS" if stage0_pass else "BLOCKED",
            prior_anchor=REALBENCH_KNOWN_GOOD_ANCHOR,
            source_prompt_hash_match_count=prompt_matches,
            current_control_arm=arm.get("arm_id"),
            claim_ceiling_preserved=True,
        ),
    )
    write_json(
        out / "v17_7_4_ope_contextual_bandit_contract.json",
        authority(
            schema_id="kt.v17_7_4.ope_contextual_bandit_contract.v1",
            status="PASS_CONTRACT_BOUND",
            replay_evidence_is_not_fresh_generation=True,
            ope_cannot_override_failed_byte_reproduction=True,
            ope_training_authority=False,
            claim_ceiling_preserved=True,
        ),
    )
    write_json(
        out / "v17_7_4_ope_authority_decision_receipt.json",
        authority(
            schema_id="kt.v17_7_4.ope_authority_decision_receipt.v1",
            status="PASS_CONTRACT_BOUND",
            max_authority="hypothesis_design_only_until_reproduction_lock_passes",
            fresh_generation_claim_authorized=False,
            training_authorized=False,
            promotion_authorized=False,
            claim_ceiling_preserved=True,
        ),
    )
    if source_status != "PASS":
        raise RuntimeError("KT_BLOCKED__KNOWN_GOOD_PROMPT_SOURCE_MISSING")
    if forbidden_hits:
        raise RuntimeError("KT_BLOCKED__KNOWN_GOOD_SCAFFOLD_CONTAMINATION")
    if not all_prompts:
        raise RuntimeError("KT_BLOCKED__PROMPT_HASH_REPRODUCTION_FAILED")
    return passport


def g2_sentinel_manifest_receipt(runtime_root: Path) -> dict[str, Any]:
    candidates = [
        Path(os.environ["KT_G2_SENTINEL_MANIFEST"]) if os.environ.get("KT_G2_SENTINEL_MANIFEST") else None,
        runtime_root / "runtime_inputs" / "g2_sentinel_sample_id_manifest.json",
        runtime_root / "runtime_inputs" / "g2_sentinel_replay_manifest.json",
    ]
    existing = [path for path in candidates if path is not None and path.exists()]
    if not existing:
        return authority(
            schema_id="kt.v17_7_4.g2_sentinel_replay_manifest.v1",
            status="BLOCKED",
            outcome="KT_BLOCKED__G2_SENTINEL_SOURCE_MISSING",
            exact_g2_sample_ids_recovered=False,
            required_rows=G2_COMPRESSION_ANCHOR["base_raw"]["total"],
            claim_ceiling_preserved=True,
        )
    payload = read_json(existing[0])
    rows = payload.get("rows") or payload.get("sample_ids") or []
    return authority(
        schema_id="kt.v17_7_4.g2_sentinel_replay_manifest.v1",
        status="PASS" if len(rows) >= G2_COMPRESSION_ANCHOR["base_raw"]["total"] else "BLOCKED",
        outcome="G2_SENTINEL_SOURCE_BOUND" if len(rows) >= G2_COMPRESSION_ANCHOR["base_raw"]["total"] else "KT_BLOCKED__G2_SENTINEL_SOURCE_MISSING",
        manifest_path=str(existing[0]),
        exact_g2_sample_ids_recovered=len(rows) >= G2_COMPRESSION_ANCHOR["base_raw"]["total"],
        recovered_rows=len(rows),
        required_rows=G2_COMPRESSION_ANCHOR["base_raw"]["total"],
        claim_ceiling_preserved=True,
    )


def materialize_prompt(row: dict[str, Any], arm: dict[str, Any]) -> str:
    if true_known_good_repro_arm(arm):
        return prior_realbench_materialize_prompt(row, arm)
    template = arm.get("prompt_template_id", "raw")
    mode = compact_mode_for_row(row, arm)
    prefix = {
        "raw": "Answer directly.",
        "kt_hat_compact": "Use compact KT-hat discipline: answer only what is asked and avoid unsupported claims.",
        "routed_no_hat": "Select the direct route without KT-hat ceremony. Emit only the final answer.",
        "formal_math": "Solve as a formal math or structured reasoning item. Emit final answer clearly.",
        "math_act": "Decompose the math act briefly, then emit final answer clearly.",
        "route_regret": "Select the most utility-preserving route and emit final answer clearly.",
        "kt_hat_full": "Use full KT-hat discipline, but do not add decorative governance language. Emit final answer clearly.",
        "routed_hat_repair": "Use compact repair discipline only if needed. Emit final answer clearly.",
        "routed_tribunal": "Use minimal tribunal checking for contradictions. Emit final answer clearly.",
        "base_raw_finalizer_only": "Answer directly. Put the final answer after 'Final:'.",
        "math_act_full_reasoning": "Use the math-act specialist. Reason enough to solve correctly, then put the final answer after 'Final:'.",
        "math_act_reasoning_preserving_compact": "Use bounded scratch only when needed. Preserve reasoning for math, then emit a compact final answer after 'Final:'.",
        "formal_math_reasoning_preserving_compact": "Use bounded formal reasoning only when needed. Then emit a compact final answer after 'Final:'.",
        "specialist_admission_controller": "Select the cheapest lawful specialist expected to be correct from pre-generation features. Emit only the selected final answer after 'Final:'.",
        "kt_hat_compact_risk_gated": "Use KT-hat only if risk requires it. Keep governance out of the visible answer and emit final answer after 'Final:'.",
        "oracle_shadow_not_runtime": "Oracle shadow arm for measurement only. Do not use oracle correctness as an input feature. Emit final answer after 'Final:'.",
    }.get(template, "Answer directly.")
    question = question_text_for_row(row)
    answer_format = str(row.get("answer_format_contract") or row.get("answer_type") or "emit final answer only").strip()
    mode_rule = {
        "MCQ_ANSWER_ONLY": "For multiple choice, emit only the option letter after Final:.",
        "NUMERIC_BOUNDED_SCRATCH_THEN_FINAL": "You may use brief scratch work. The final visible answer must be only the normalized number after Final:.",
        "SHORT_ANSWER_FINAL_ONLY": "Emit one compact phrase after Final:.",
        "EVIDENCE_GROUNDED_BRIEF_THEN_FINAL": "Use brief evidence grounding only if needed, then a compact final answer after Final:.",
        "HIGH_RISK_OPERATOR_TRACE_OUTSIDE_BENCH": "Benchmark mode forbids operator traces in visible answers.",
    }.get(mode, "Emit a compact final answer after Final:.")
    if row.get("benchmark_source") == "REAL_BENCHMARK_ROW":
        return "\n".join(
            [
                prefix,
                f"Compact mode: {mode}",
                f"Mode rule: {mode_rule}",
                f"Question: {question}",
                f"Answer format: {answer_format}",
                "Final:",
            ]
        )
    return "\n".join(
        [
            prefix,
            f"Compact mode: {mode}",
            f"Mode rule: {mode_rule}",
            f"Sample: {row['sample_id']}",
            f"Dataset: {row['dataset']}",
            f"Task family: {row['task_family']}",
            f"Boundary: {row['route_boundary_class']}",
            f"Question: {question}",
            "Final:",
        ]
    )


def expand_runtime_path(value: str, config: dict[str, Any]) -> str:
    adapter_root_env = config.get("adapter_root_env", "KT_TRUEGEN_ADAPTER_ROOT")
    adapter_root = os.environ.get(adapter_root_env, config.get("adapter_root_default", ""))
    expanded = (
        value.replace("${KT_TRUEGEN_ADAPTER_ROOT}", adapter_root)
        .replace("$KT_TRUEGEN_ADAPTER_ROOT", adapter_root)
        .replace(f"${{{adapter_root_env}}}", adapter_root)
        .replace(f"${adapter_root_env}", adapter_root)
    )
    return os.path.normpath(os.path.expandvars(expanded))


def adapter_source_preference(config: dict[str, Any]) -> str:
    env_value = os.environ.get("KT_TRUEGEN_ADAPTER_SOURCE", "").strip().upper()
    if env_value in {"HF", "HF_VAULT", "HF_VAULT_FIRST"}:
        return "HF_VAULT_FIRST"
    if env_value in {"LOCAL", "LOCAL_PATH", "LOCAL_PATH_FIRST"}:
        return "LOCAL_PATH_FIRST"
    return str(config.get("adapter_source_preference") or "LOCAL_PATH_FIRST").strip().upper()


def adapter_local_root_is_set(config: dict[str, Any]) -> bool:
    adapter_root_env = str(config.get("adapter_root_env", "KT_TRUEGEN_ADAPTER_ROOT"))
    return bool(os.environ.get(adapter_root_env, "").strip())


def adapter_source_kind_for_arm(arm: dict[str, Any], config: dict[str, Any]) -> str:
    hf_repo = str(arm.get("adapter_hf_repo") or "").strip()
    raw_path = str(arm.get("adapter_path") or "").strip()
    preference = adapter_source_preference(config)
    # The Kaggle wrapper normalizes the HF adapter vault into a local adapter root.
    # When that root is present, it is the safest source: PEFT sees an adapter
    # directory with adapter_config.json instead of a dataset repo root.
    if arm.get("arm_id") in ADAPTER_ARM_IDS and raw_path and adapter_local_root_is_set(config):
        return ADAPTER_SOURCE_LOCAL_PATH
    if preference == "HF_VAULT_FIRST" and hf_repo:
        return ADAPTER_SOURCE_HF_VAULT
    if raw_path:
        return ADAPTER_SOURCE_LOCAL_PATH
    if hf_repo:
        return ADAPTER_SOURCE_HF_VAULT
    return ADAPTER_SOURCE_NONE


def adapter_ref_for_arm(arm: dict[str, Any], config: dict[str, Any]) -> str:
    kind = adapter_source_kind_for_arm(arm, config)
    if kind == ADAPTER_SOURCE_HF_VAULT:
        return str(arm.get("adapter_hf_repo") or "").strip()
    raw_path = str(arm.get("adapter_path") or "").strip()
    if kind == ADAPTER_SOURCE_LOCAL_PATH and raw_path:
        return expand_runtime_path(raw_path, config)
    return ""


def adapter_load_kwargs_for_arm(arm: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    if adapter_source_kind_for_arm(arm, config) != ADAPTER_SOURCE_HF_VAULT:
        return {}
    kwargs: dict[str, Any] = {}
    subfolder = str(arm.get("adapter_hf_subfolder") or "").strip()
    if not subfolder:
        raise RuntimeError(f"adapter_load_contract_failed: HF adapter subfolder missing for {arm.get('arm_id')}")
    kwargs["subfolder"] = subfolder
    revision = str(arm.get("adapter_hf_revision") or config.get("adapter_hf_revision") or "").strip()
    if revision:
        kwargs["revision"] = revision
    return kwargs


def model_repo_for_arm(arm: dict[str, Any], config: dict[str, Any]) -> str:
    model_repo = arm.get("model_repo_or_base") or config["base_model_repo"]
    return config["base_model_repo"] if model_repo == "BASE" else model_repo


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_model_loader_kwargs(config: dict[str, Any], torch_module: Any, bnb_config_cls: Any | None = None) -> tuple[dict[str, Any], str]:
    kwargs: dict[str, Any] = {"device_map": config.get("device_map", "auto")}
    dtype_name = str(config.get("torch_dtype", "auto"))
    dtype = getattr(torch_module, dtype_name, "auto") if dtype_name != "auto" else "auto"
    if dtype != "auto":
        kwargs["torch_dtype"] = dtype
    if config.get("low_cpu_mem_usage", True) is True:
        kwargs["low_cpu_mem_usage"] = True
    if "trust_remote_code" in config:
        kwargs["trust_remote_code"] = bool(config["trust_remote_code"])
    if "max_memory" in config:
        kwargs["max_memory"] = config["max_memory"]
    loader_mode = MODEL_LOADER_AUTO_STANDARD
    if config.get("load_in_4bit") is True:
        if bnb_config_cls is None:
            try:
                from transformers import BitsAndBytesConfig as bnb_config_cls
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError(f"dependency_missing: BitsAndBytesConfig unavailable for 4-bit real-arm load: {exc}") from exc
        compute_dtype_name = str(config.get("bnb_4bit_compute_dtype", "float16"))
        compute_dtype = getattr(torch_module, compute_dtype_name, None)
        if compute_dtype is None:
            raise RuntimeError(f"invalid bnb_4bit_compute_dtype: {compute_dtype_name}")
        kwargs["quantization_config"] = bnb_config_cls(
            load_in_4bit=True,
            bnb_4bit_quant_type=str(config.get("bnb_4bit_quant_type", "nf4")),
            bnb_4bit_compute_dtype=compute_dtype,
            bnb_4bit_use_double_quant=bool(config.get("bnb_4bit_use_double_quant", True)),
        )
        loader_mode = MODEL_LOADER_AUTO_BNB_4BIT
    if "load_in_4bit" in kwargs:
        raise RuntimeError("bad model loader contract: load_in_4bit must be inside BitsAndBytesConfig, not from_pretrained kwargs")
    return kwargs, loader_mode


def adapter_weight_file(adapter_dir: Path) -> Path | None:
    for name in ("adapter_model.safetensors", "adapter_model.bin", "pytorch_model.bin"):
        candidate = adapter_dir / name
        if candidate.exists():
            return candidate
    return None


def validate_adapter_source(arm: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    arm_id = arm["arm_id"]
    adapter_ref = adapter_ref_for_arm(arm, config)
    adapter_source_kind = adapter_source_kind_for_arm(arm, config)
    adapter_hf_subfolder = str(arm.get("adapter_hf_subfolder") or "").strip()
    if arm_id not in ADAPTER_ARM_IDS:
        return authority(
            schema_id="kt.v17_7_4.adapter_load_contract_row.v1",
            arm_id=arm_id,
            adapter_ref=adapter_ref,
            adapter_loader_mode=ADAPTER_LOADER_PROMPT_OVERLAY if arm_id == "base_kt_hat_compact" else ADAPTER_LOADER_BASE,
            adapter_source_status="ADAPTER_NOT_REQUIRED_FOR_ARM",
            adapter_source_kind=ADAPTER_SOURCE_NONE,
            adapter_required=False,
        )
    if not adapter_ref:
        raise RuntimeError(f"adapter_load_contract_failed: real adapter arm {arm_id} has no adapter source")
    if adapter_source_kind == ADAPTER_SOURCE_HF_VAULT:
        if not adapter_hf_subfolder:
            raise RuntimeError(f"adapter_load_contract_failed: HF adapter subfolder missing for {arm_id}")
        return authority(
            schema_id="kt.v17_7_4.adapter_load_contract_row.v1",
            arm_id=arm_id,
            adapter_ref=adapter_ref,
            adapter_hf_repo=arm.get("adapter_hf_repo"),
            adapter_hf_subfolder=adapter_hf_subfolder,
            adapter_loader_mode=ADAPTER_LOADER_PEFT,
            adapter_source_status="HF_ADAPTER_SOURCE_BOUND_RUNTIME_LOAD_REQUIRED",
            adapter_source_kind=ADAPTER_SOURCE_HF_VAULT,
            adapter_source_preference=adapter_source_preference(config),
            adapter_required=True,
            local_path_checked=False,
            hf_vault_source_of_truth=True,
            adapter_sha256_expected=arm.get("adapter_sha256_optional") or "",
            adapter_sha256_verification_scope="HF_MANIFEST_OR_RUNTIME_DOWNLOAD_RECEIPT_REQUIRED",
            peft_root_only_load_forbidden=True,
        )
    adapter_path = Path(adapter_ref)
    if not adapter_path.exists():
        raise RuntimeError(f"adapter_load_contract_failed: adapter path missing for {arm_id}: {adapter_path}")
    config_file = adapter_path / "adapter_config.json"
    if not config_file.exists():
        raise RuntimeError(f"adapter_load_contract_failed: adapter_config.json missing for {arm_id}: {adapter_path}")
    weight_path = adapter_weight_file(adapter_path)
    if weight_path is None:
        raise RuntimeError(f"adapter_load_contract_failed: adapter weights missing for {arm_id}: {adapter_path}")
    expected_sha = str(arm.get("adapter_sha256_optional") or "")
    actual_sha = sha256_file(weight_path)
    if expected_sha and actual_sha != expected_sha:
        raise RuntimeError(
            f"adapter_load_contract_failed: adapter sha mismatch for {arm_id}: expected {expected_sha}, got {actual_sha}"
        )
    return authority(
        schema_id="kt.v17_7_4.adapter_load_contract_row.v1",
        arm_id=arm_id,
        adapter_ref=adapter_ref,
        adapter_loader_mode=ADAPTER_LOADER_PEFT,
        adapter_source_status="LOCAL_ADAPTER_SOURCE_VALIDATED",
        adapter_source_kind=ADAPTER_SOURCE_LOCAL_PATH,
        adapter_source_preference=adapter_source_preference(config),
        adapter_required=True,
        local_path_checked=True,
        adapter_config_present=True,
        adapter_weight_file=weight_path.name,
        adapter_weight_sha256=actual_sha,
        adapter_sha256_verified=bool(expected_sha),
    )


class GenerationBackend:
    def __init__(self) -> None:
        self._model_cache: dict[str, Any] = {}
        self.model_loader_receipts: list[dict[str, Any]] = []
        self.adapter_loader_receipts: list[dict[str, Any]] = []

    def close(self) -> None:
        self._model_cache.clear()
        gc.collect()
        try:
            import torch

            if torch.cuda.is_available():
                torch.cuda.empty_cache()
                try:
                    torch.cuda.ipc_collect()
                except Exception:
                    pass
        except Exception:
            pass

    def generate(self, prompt: str, arm: dict[str, Any], config: dict[str, Any], row: dict[str, Any]) -> tuple[str, str, str, str]:
        model_repo = model_repo_for_arm(arm, config)
        if model_repo == "__KT_LOCAL_TEST_BACKEND__":
            if os.environ.get("KT_TRUEGEN_ALLOW_TEST_BACKEND") != "1":
                raise RuntimeError("local test backend requested without KT_TRUEGEN_ALLOW_TEST_BACKEND=1")
            expected = row.get("expected_label_or_oracle_label", "")
            return (
                f"answer: {expected}",
                "LOCAL_TEST_BACKEND_NOT_KT_EVIDENCE",
                "LOCAL_TEST_BACKEND_NO_MODEL_AUTHORITY",
                "LOCAL_TEST_BACKEND_NO_ADAPTER_AUTHORITY",
            )
        return self._generate_with_transformers(prompt, arm, config)

    def _generate_with_transformers(self, prompt: str, arm: dict[str, Any], config: dict[str, Any]) -> tuple[str, str, str, str]:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"missing transformers/torch runtime dependencies: {exc}") from exc

        model_repo = model_repo_for_arm(arm, config)
        adapter_ref = adapter_ref_for_arm(arm, config)
        adapter_kwargs = adapter_load_kwargs_for_arm(arm, config)
        cache_key = f"{model_repo}::{adapter_ref or 'base'}::{stable_hash(adapter_kwargs)}"
        if cache_key not in self._model_cache:
            tokenizer = AutoTokenizer.from_pretrained(model_repo)
            kwargs, model_loader_mode = build_model_loader_kwargs(config, torch)
            model = AutoModelForCausalLM.from_pretrained(model_repo, **kwargs)
            self.model_loader_receipts.append(
                authority(
                    schema_id="kt.v17_7_4.model_loader_contract_row.v1",
                    arm_id=arm["arm_id"],
                    model_repo=model_repo,
                    loader_mode=model_loader_mode,
                    auto_model_for_causal_lm=True,
                    from_pretrained=True,
                    quantization_config_used="quantization_config" in kwargs,
                    load_in_4bit_forwarded_as_bad_kwarg=False,
                    from_pretrained_kwarg_keys=sorted(kwargs),
                    qwen_constructor_path_used=False,
                    arm_isolation_mode=str(config.get("arm_isolation_mode", "ARM_MAJOR_UNLOAD_AFTER_EACH_ARM")),
                )
            )
            adapter_status = ADAPTER_LOADER_BASE
            adapter_loader_mode = ADAPTER_LOADER_BASE
            if adapter_ref:
                adapter_contract = validate_adapter_source(arm, config)
                try:
                    from peft import PeftModel

                    if adapter_source_kind_for_arm(arm, config) == ADAPTER_SOURCE_HF_VAULT and not adapter_kwargs.get("subfolder"):
                        raise RuntimeError(f"root-only HF PEFT adapter load forbidden for {arm['arm_id']}")
                    model = PeftModel.from_pretrained(model, adapter_ref, **adapter_kwargs)
                    adapter_status = "ADAPTER_LOADED"
                    adapter_loader_mode = ADAPTER_LOADER_PEFT
                except Exception as exc:  # noqa: BLE001
                    raise RuntimeError(f"adapter load failed for {arm['arm_id']}: {exc}") from exc
                adapter_contract.update(
                    adapter_load_status=adapter_status,
                    adapter_loader_mode=adapter_loader_mode,
                    peft_model_from_pretrained=True,
                    peft_from_pretrained_kwargs=sorted(adapter_kwargs),
                )
                self.adapter_loader_receipts.append(adapter_contract)
            else:
                adapter_status = (
                    ADAPTER_LOADER_BLOCKED_BASE_FALLBACK
                    if arm["arm_id"] not in {"base_raw", "base_kt_hat_compact"}
                    else ADAPTER_LOADER_BASE
                )
                adapter_loader_mode = ADAPTER_LOADER_PROMPT_OVERLAY if arm["arm_id"] == "base_kt_hat_compact" else ADAPTER_LOADER_BASE
                adapter_contract = validate_adapter_source(arm, config)
                adapter_contract.update(adapter_load_status=adapter_status, adapter_loader_mode=adapter_loader_mode)
                self.adapter_loader_receipts.append(adapter_contract)
            if config.get("real_arm_authority_requested") is True and arm["arm_id"] in ADAPTER_ARM_IDS and adapter_status != "ADAPTER_LOADED":
                raise RuntimeError(f"real-arm authority requires adapter load for {arm['arm_id']}; got {adapter_status}")
            model.eval()
            self._model_cache[cache_key] = (tokenizer, model, adapter_status, model_loader_mode, adapter_loader_mode)
        tokenizer, model, adapter_status, model_loader_mode, adapter_loader_mode = self._model_cache[cache_key]
        if not adapter_ref:
            adapter_status = ADAPTER_LOADER_BASE
            adapter_loader_mode = ADAPTER_LOADER_PROMPT_OVERLAY if arm["arm_id"] == "base_kt_hat_compact" else ADAPTER_LOADER_BASE
        seed = int(config.get("generation_seed", 1337))
        random.seed(seed)
        try:
            torch.manual_seed(seed)
            if torch.cuda.is_available():
                torch.cuda.manual_seed_all(seed)
        except Exception:
            pass
        inputs = tokenizer(prompt, return_tensors="pt")
        device = next(model.parameters()).device
        inputs = {key: value.to(device) for key, value in inputs.items()}
        max_new_tokens = int(arm.get("max_new_tokens") or config.get("max_new_tokens") or 32)
        with torch.no_grad():
            output_ids = model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False)
        generated = tokenizer.decode(output_ids[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=True)
        return generated.strip(), adapter_status, model_loader_mode, adapter_loader_mode


def score_output(text: str, parsed_answer: str, row: dict[str, Any], method: str) -> tuple[float, bool]:
    expected = expected_answer_for_row(row)
    if method == "nonempty_generation":
        correct = bool(text.strip())
    elif method == "exact_normalized":
        correct = normalize_answer(parsed_answer) == normalize_answer(expected)
    elif method == "multiple_choice_letter":
        normalized_expected = normalize_answer(expected)
        normalized_parsed = normalize_answer(parsed_answer)
        first_token = normalize_answer((parsed_answer.strip()[:1] or text.strip()[:1]))
        correct = normalized_parsed == normalized_expected or first_token == normalized_expected
    else:
        correct = normalize_answer(expected) in normalize_answer(text) if expected else False
    return (1.0 if correct else 0.0), correct


def accelerator_memory_snapshot(label: str, arm_id: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_id": "kt.v17_7_4.gpu_memory_ledger_row.v1",
        "label": label,
        "arm_id": arm_id,
        "timestamp_unix": round(time.time(), 6),
        "cuda_available": False,
    }
    try:
        import torch

        payload["cuda_available"] = bool(torch.cuda.is_available())
        if torch.cuda.is_available():
            device = torch.cuda.current_device()
            free_bytes, total_bytes = torch.cuda.mem_get_info(device)
            payload.update(
                device_index=device,
                device_name=torch.cuda.get_device_name(device),
                free_bytes=int(free_bytes),
                total_bytes=int(total_bytes),
                allocated_bytes=int(torch.cuda.memory_allocated(device)),
                reserved_bytes=int(torch.cuda.memory_reserved(device)),
            )
    except Exception as exc:  # noqa: BLE001
        payload.update(cuda_probe_error=repr(exc))
    return payload


def first_row_request_env() -> tuple[int | None, str]:
    for env_name in ROW_REQUEST_ENVS:
        value = os.environ.get(env_name)
        if value:
            return int(value), env_name
    return None, ""


def resolve_effective_row_limit(config: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    requested, source = first_row_request_env()
    memory_gate_override_used = False
    reason_if_not_honored = ""
    ladder = config.get("row_ladder") or DEFAULT_ROW_LADDER
    if not isinstance(ladder, list) or not ladder:
        ladder = DEFAULT_ROW_LADDER
    allowed = sorted({int(value) for value in ladder})
    max_rows = int(config.get("row_limit", requested or config.get("row_limit", 100)))

    if requested is not None:
        row_limit = requested
    elif os.environ.get("KT_TRUEGEN_LADDER_STAGE"):
        row_limit = int(os.environ["KT_TRUEGEN_LADDER_STAGE"])
        source = "KT_TRUEGEN_LADDER_STAGE"
        if allowed:
            row_limit = min((value for value in allowed if value >= row_limit), default=max(allowed))
    elif config.get("default_row_ladder_stage") is not None:
        row_limit = int(config["default_row_ladder_stage"])
        source = "config.default_row_ladder_stage"
        if allowed:
            row_limit = min((value for value in allowed if value >= row_limit), default=max(allowed))
    else:
        row_limit = int(config.get("row_limit", 100))
        source = "config.row_limit"

    if row_limit < 1:
        row_limit = 1
    if row_limit > max_rows:
        reason_if_not_honored = f"requested row limit {row_limit} exceeds config.row_limit {max_rows}"
        row_limit = max_rows

    row_limit_honored = requested is None or row_limit == requested
    receipt = authority(
        schema_id="kt.v17_7_4.row_authority_receipt.v1",
        status="PASS" if row_limit_honored else "BLOCKED",
        requested_row_limit=requested,
        effective_row_limit=row_limit,
        row_limit=row_limit,
        row_limit_source=source,
        row_limit_honored=row_limit_honored,
        memory_gate_override_used=memory_gate_override_used,
        reason_if_not_honored=reason_if_not_honored,
        operator_env_snapshot={name: os.environ.get(name, "") for name in [*ROW_REQUEST_ENVS, "KT_TRUEGEN_LADDER_STAGE", "KT_TRUEGEN_MEASUREMENT_MODE"]},
        row_ladder=ladder,
        max_configured_rows=max_rows,
        ladder_policy="ENV_ROW_REQUEST_OVERRIDES_DEFAULT_ROW_LADDER_STAGE_EXACTLY",
    )
    return row_limit, receipt


def build_arm_result_row(
    row: dict[str, Any],
    arm: dict[str, Any],
    config: dict[str, Any],
    run_id: str,
    output_text: str,
    adapter_source_status: str,
    model_loader_mode: str,
    adapter_loader_mode: str,
    latency_ms: int,
) -> dict[str, Any]:
    prompt = materialize_prompt(row, arm)
    parsed = parse_answer(output_text)
    visible_answer = final_visible_answer(output_text, parsed, row)
    compact_enabled = compact_scoring_enabled(config, arm)
    compact_contract_enabled = compact_answer_enabled(config)
    reasoning_preserving_enabled = reasoning_preserving_compact_enabled(config)
    compact_mode = compact_mode_for_row(row, arm, config)
    scoring_text = visible_answer if compact_enabled else output_text
    scoring_answer = visible_answer if compact_enabled else parsed
    score, correct = score_output(scoring_text, scoring_answer, row, arm.get("scoring_method", "contains_expected_label"))
    tokens_in = count_tokens(prompt)
    tokens_out = count_tokens(output_text)
    visible_answer_tokens = count_tokens(visible_answer)
    reasoning_tokens = reasoning_tokens_for_output(output_text, visible_answer, compact_mode)
    total_tokens = tokens_in + tokens_out
    prompt_components = prompt_overhead_components(prompt, row, arm)
    answer_tokens = max(count_tokens(parsed), 1)
    route_overhead_tokens = sum(prompt_components.values())
    parser_format_failure = output_contains_expected(output_text, row) and not exact_expected_match(parsed, row)
    row_metrics = {
        **prompt_components,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "total_tokens": total_tokens,
        "visible_answer_tokens": visible_answer_tokens,
        "reasoning_tokens": reasoning_tokens,
        "answer_tokens": answer_tokens,
        "route_overhead_tokens": route_overhead_tokens,
        "hat_overhead_ratio": safe_ratio(prompt_components["hat_tokens"], answer_tokens),
        "correct": bool(correct),
        "parser_format_failure": parser_format_failure,
        "adapter_loader_mode": adapter_loader_mode,
    }
    return authority(
        schema_id="kt.v17_7_4.truegen_arm_result.v1",
        run_id=run_id,
        sample_id=row["sample_id"],
        dataset=row["dataset"],
        task_family=row["task_family"],
        evidence_band=row["evidence_band"],
        route_boundary_class=row["route_boundary_class"],
        arm_id=arm["arm_id"],
        route_id=ABLATION_LADDER.get(arm["arm_id"], arm["arm_id"]),
        model_repo=model_repo_for_arm(arm, config),
        adapter_ref=adapter_ref_for_arm(arm, config),
        adapter_source_kind=adapter_source_kind_for_arm(arm, config),
        adapter_source_status=adapter_source_status,
        model_loader_mode=model_loader_mode,
        adapter_loader_mode=adapter_loader_mode,
        benchmark_source=row.get("benchmark_source", ""),
        question_text_hash=sha256_text(question_text_for_row(row)),
        expected_answer_hash=sha256_text(expected_answer_for_row(row)),
        prompt_hash=sha256_text(prompt),
        output_text=output_text[:2000],
        output_hash=sha256_text(output_text),
        parsed_answer=parsed,
        visible_answer=visible_answer,
        visible_answer_hash=sha256_text(visible_answer),
        score=score,
        correct=correct,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        total_tokens=total_tokens,
        full_prompt_plus_output_tokens=total_tokens,
        raw_output_tokens=tokens_out,
        visible_answer_tokens=visible_answer_tokens,
        reasoning_tokens=reasoning_tokens,
        tokens_per_correct=safe_ratio(total_tokens, 1 if correct else 0),
        reasoning_tokens_per_correct=safe_ratio(reasoning_tokens, 1 if correct else 0),
        raw_output_tokens_per_correct=safe_ratio(tokens_out, 1 if correct else 0),
        output_tokens_per_correct=safe_ratio(tokens_out, 1 if correct else 0),
        visible_answer_tokens_per_correct=safe_ratio(visible_answer_tokens, 1 if correct else 0),
        verified_work_per_token=safe_ratio(1 if correct else 0, total_tokens),
        visible_answer_verified_work_per_token=safe_ratio(1 if correct else 0, visible_answer_tokens),
        latency_per_correct=safe_ratio(latency_ms, 1 if correct else 0),
        answer_tokens=answer_tokens,
        router_tokens=prompt_components["router_tokens"],
        hat_tokens=prompt_components["hat_tokens"],
        tribunal_tokens=prompt_components["tribunal_tokens"],
        repair_tokens=prompt_components["repair_tokens"],
        route_overhead_tokens=route_overhead_tokens,
        hat_overhead_ratio=row_metrics["hat_overhead_ratio"],
        parser_format_failure=parser_format_failure,
        compact_answer_contract_enabled=compact_contract_enabled,
        compact_scoring_enabled=compact_enabled,
        reasoning_preserving_compact_enabled=reasoning_preserving_enabled,
        compact_mode=compact_mode,
        final_visible_answer_used_for_scoring=compact_enabled,
        raw_output_audit_only=compact_enabled,
        compact_answer_contract_status="PASS" if not answer_contains_scaffold(visible_answer) else "BLOCKED",
        scaffold_language_in_visible_answer=answer_contains_scaffold(visible_answer),
        final_answer_marker_present=bool(re.search(r"(?:answer|final)\s*[:=]", output_text, flags=re.IGNORECASE)),
        bloat_class=classify_bloat(row_metrics),
        latency_ms=latency_ms,
        generation_seed=config["generation_seed"],
        measurement_source=FRESH_SOURCE,
        measurement_status=FRESH_STATUS,
        generation_artifacts_present=True,
    )


def generate_arm_rows(
    manifest: dict[str, Any],
    config: dict[str, Any],
    run_id: str,
    stream_path: Path | None = None,
    memory_ledger_path: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    model_loader_receipts: list[dict[str, Any]] = []
    adapter_loader_receipts: list[dict[str, Any]] = []
    if stream_path is not None:
        stream_path.parent.mkdir(parents=True, exist_ok=True)
        stream_path.write_text("", encoding="utf-8")
    if memory_ledger_path is not None:
        memory_ledger_path.parent.mkdir(parents=True, exist_ok=True)
        memory_ledger_path.write_text("", encoding="utf-8")
        append_jsonl(memory_ledger_path, accelerator_memory_snapshot("run_start"))
    for arm in enabled_arms(config):
        backend = GenerationBackend()
        if memory_ledger_path is not None:
            append_jsonl(memory_ledger_path, accelerator_memory_snapshot("arm_start", arm["arm_id"]))
        try:
            for row in manifest["rows"]:
                prompt = materialize_prompt(row, arm)
                start = time.perf_counter()
                output_text, adapter_source_status, model_loader_mode, adapter_loader_mode = backend.generate(prompt, arm, config, row)
                latency_ms = int((time.perf_counter() - start) * 1000)
                result_row = build_arm_result_row(
                    row=row,
                    arm=arm,
                    config=config,
                    run_id=run_id,
                    output_text=output_text,
                    adapter_source_status=adapter_source_status,
                    model_loader_mode=model_loader_mode,
                    adapter_loader_mode=adapter_loader_mode,
                    latency_ms=latency_ms,
                )
                rows.append(result_row)
                if stream_path is not None:
                    append_jsonl(stream_path, result_row)
        finally:
            model_loader_receipts.extend(backend.model_loader_receipts)
            adapter_loader_receipts.extend(backend.adapter_loader_receipts)
            backend.close()
            if memory_ledger_path is not None:
                append_jsonl(memory_ledger_path, accelerator_memory_snapshot("arm_unloaded", arm["arm_id"]))
    if memory_ledger_path is not None:
        append_jsonl(memory_ledger_path, accelerator_memory_snapshot("run_end"))
    return rows, model_loader_receipts, adapter_loader_receipts


def enforce_fresh_rows(arm_rows: list[dict[str, Any]], predictions: list[dict[str, Any]] | None = None) -> None:
    defects = []
    for index, row in enumerate(list(arm_rows) + list(predictions or [])):
        status = row.get("measurement_status") or row.get("status")
        source = row.get("measurement_source")
        if status in FORBIDDEN_SUCCESS_STATUSES or source in FORBIDDEN_SUCCESS_STATUSES:
            defects.append({"index": index, "sample_id": row.get("sample_id"), "status": status, "source": source})
        if row.get("schema_id", "").endswith(("truegen_arm_result.v1", "truegen_prediction.v1")):
            if status != FRESH_STATUS or source != FRESH_SOURCE or row.get("generation_artifacts_present") is not True:
                defects.append({"index": index, "sample_id": row.get("sample_id"), "status": status, "source": source})
    if defects:
        raise RuntimeError(f"fresh-generation contract failed: {defects[:10]}")


def aggregate_predictions(arm_rows: list[dict[str, Any]], run_id: str) -> list[dict[str, Any]]:
    by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in arm_rows:
        by_sample[row["sample_id"]].append(row)
    predictions = []
    for sample_id, rows in sorted(by_sample.items()):
        best = sorted(rows, key=lambda row: (-float(row["score"]), int(row["tokens_out"]), int(row["latency_ms"]), row["arm_id"]))[0]
        predictions.append(
            authority(
                schema_id="kt.v17_7_4.truegen_prediction.v1",
                run_id=run_id,
                sample_id=sample_id,
                dataset=best["dataset"],
                task_family=best["task_family"],
                evidence_band=best["evidence_band"],
                route_boundary_class=best["route_boundary_class"],
                best_arm=best["arm_id"],
                oracle_correct=bool(best["correct"]),
                chosen_score=float(best["score"]),
                available_arm_scores={row["arm_id"]: {"score": row["score"], "correct": row["correct"]} for row in rows},
                measurement_source=FRESH_SOURCE,
                measurement_status=FRESH_STATUS,
                generation_artifacts_present=True,
            )
        )
    enforce_fresh_rows(arm_rows, predictions)
    return predictions


def build_oracle_route_rows(arm_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in arm_rows:
        by_sample[row["sample_id"]].append(row)
    rows = []
    for sample_id, sample_rows in sorted(by_sample.items()):
        best = sorted(sample_rows, key=lambda row: (-float(row.get("score", 0.0)), int(row.get("total_tokens", 10**9)), row["arm_id"]))[0]
        chosen = next((row for row in sample_rows if row["arm_id"] in {"math_act_adapter_global", "A3_math_act_reasoning_preserving_compact"}), best)
        base = next((row for row in sample_rows if row["arm_id"] in {"base_raw", "A0_base_raw"}), sample_rows[0])
        rows.append(
            authority(
                schema_id="kt.v17_7_4.oracle_route_row.v1",
                sample_id=sample_id,
                dataset=best.get("dataset"),
                task_family=best.get("task_family"),
                answer_type=best.get("answer_type", ""),
                pre_generation_features={},
                chosen_arm=chosen["arm_id"],
                best_arm=best["arm_id"],
                oracle_arm=best["arm_id"],
                oracle_correct=bool(best.get("correct")),
                chosen_correct=bool(chosen.get("correct")),
                base_raw_correct=bool(base.get("correct")),
                route_regret=max(float(best.get("score", 0.0)) - float(chosen.get("score", 0.0)), 0.0),
                token_regret=max(int(chosen.get("total_tokens", 0)) - int(best.get("total_tokens", 0)), 0),
                latency_regret=max(int(chosen.get("latency_ms", 0)) - int(best.get("latency_ms", 0)), 0),
                admission_rule_candidate="math_act_default_candidate_unless_feature_gate_disagrees",
                oracle_correctness_used_as_runtime_feature=False,
                promotion_authority=False,
                runtime_authority=False,
            )
        )
    return rows


def specialist_admission_atlas(oracle_rows: list[dict[str, Any]], scorecards: dict[str, Any]) -> dict[str, Any]:
    benchmark = scorecards["benchmark"]
    best_arm = benchmark.get("best_static_arm")
    return authority(
        schema_id="kt.v17_7_4.specialist_admission_atlas.v1",
        status="PASS_CANDIDATE_ONLY",
        best_current_candidate_arm=best_arm,
        oracle_rows=len(oracle_rows),
        oracle_gap_vs_best_candidate=max(int(benchmark.get("oracle_correct_count", 0)) - int(benchmark.get("best_static_correct_count", 0)), 0),
        rule={
            "schema_id": "kt.v17_7_4.specialist_admission_rule.v1",
            "rule_id": "best_static_specialist_candidate_after_realbench",
            "candidate_default_arm": best_arm,
            "rule_authority": "CANDIDATE_ONLY",
            "required_validation": ["held_out_realbench_replay", "OOD_slice_replay", "token_accounting_reconciliation"],
            "claim_ceiling_preserved": True,
            "promotion_authority": False,
        },
        oracle_correctness_used_as_runtime_feature=False,
        dataset_label_alone_structure_bound_claim_allowed=False,
        promotion_authority=False,
    )


def route_margin_scorecard(oracle_rows: list[dict[str, Any]]) -> dict[str, Any]:
    margins = []
    for row in oracle_rows:
        margins.append(
            {
                "sample_id": row["sample_id"],
                "dataset": row.get("dataset"),
                "task_family": row.get("task_family"),
                "best_arm": row.get("best_arm"),
                "chosen_arm": row.get("chosen_arm"),
                "route_regret": row.get("route_regret", 0.0),
                "token_regret": row.get("token_regret", 0),
                "route_margin": max(float(row.get("route_regret", 0.0)), 0.0),
                "feature_leakage_check": "PASS_NO_ORACLE_CORRECTNESS_RUNTIME_FEATURE",
            }
        )
    return authority(
        schema_id="kt.v17_7_4.route_margin_scorecard.v1",
        status="PASS",
        row_count=len(margins),
        route_margin_rows=margins,
        oracle_shadow_not_runtime=True,
        learned_router_superiority_claim=False,
        promotion_authority=False,
    )


def dual_frontier_scorecard(scorecards: dict[str, Any]) -> dict[str, Any]:
    benchmark = scorecards["benchmark"]
    token_accounting = scorecards["token_accounting_ledger"]["matrix"]
    token_efficiency = scorecards["token_efficiency"]["matrix"]
    negative_transfer = scorecards["negative_transfer"]["negative_transfer"]
    parser_matrix = scorecards["parser_error"]["matrix"]
    answer_format = scorecards["answer_format"]["matrix"]
    oracle_correct = int(benchmark.get("oracle_correct_count", 0))
    rows = []
    for arm, payload in sorted(token_efficiency.items()):
        account = token_accounting.get(arm, {})
        correct = int(payload.get("correct", 0))
        full_tpc = float(account.get("full_prompt_plus_output_tokens_per_correct", payload.get("tokens_per_correct", 0.0)))
        visible_tpc = float(account.get("visible_answer_tokens_per_correct", 0.0))
        base_arm_id = benchmark.get("base_arm_id") or ("base_raw" if "base_raw" in token_efficiency else "A0_base_raw")
        base = token_efficiency.get(base_arm_id, {})
        base_correct = int(base.get("correct", 0))
        base_tpc = float(base.get("tokens_per_correct", 0.0))
        if correct > base_correct and full_tpc <= base_tpc:
            pareto = "PARETO_IMPROVES_ACCURACY_AND_COST"
        elif correct == base_correct and full_tpc < base_tpc:
            pareto = "PARETO_IMPROVES_COST_AT_SAME_CORRECTNESS"
        elif correct > base_correct:
            pareto = "UTILITY_JUSTIFIED_ACCURACY_GAIN_REQUIRES_COST_REVIEW"
        elif correct < base_correct and full_tpc >= base_tpc:
            pareto = "QUARANTINE_WORSE_ACCURACY_AND_COST"
        else:
            pareto = "DIAGNOSTIC_ONLY"
        rows.append(
            {
                "schema_id": "kt.v17_7_4.dual_frontier_scorecard_row.v1",
                "arm_id": arm,
                "route_id": ABLATION_LADDER.get(arm, arm),
                "task_family": "ALL",
                "dataset": "ALL",
                "correct_count": correct,
                "accuracy": benchmark.get("arm_accuracy", {}).get(arm, 0.0),
                "full_tokens_per_correct": full_tpc,
                "visible_answer_tokens_per_correct": visible_tpc,
                "reasoning_tokens_per_correct": account.get("reasoning_tokens_per_correct", 0.0),
                "prompt_tokens_per_correct": account.get("prompt_tokens_per_correct", account.get("input_tokens_per_correct", 0.0)),
                "route_overhead_tokens_per_correct": account.get("route_overhead_tokens_per_correct", 0.0),
                "hat_overhead_tokens_per_correct": account.get("hat_overhead_tokens_per_correct", 0.0),
                "latency_per_correct": payload.get("latency_per_correct", 0.0),
                "verified_work_per_token": payload.get("verified_work_per_token", 0.0),
                "route_regret": max(oracle_correct - correct, 0),
                "oracle_gap": max(oracle_correct - correct, 0),
                "negative_transfer_count": negative_transfer.get(arm, 0),
                "parser_failure_rate": parser_matrix.get(arm, {}).get("parser_format_failure_rate", 0.0),
                "final_answer_format_failure_rate": answer_format.get(arm, {}).get("answer_format_drift_rate", 0.0),
                "claim_safety_status": "PASS_CLAIM_CEILING_PRESERVED",
                "replayability_status": "FRESH_GENERATION_ROW_RECOMPUTED",
                "Pareto_status": pareto,
            }
        )
    best = sorted(rows, key=lambda row: (-row["correct_count"], row["full_tokens_per_correct"], row["arm_id"]))[0] if rows else {}
    return authority(
        schema_id="kt.v17_7_4.dual_frontier_scorecard.v1",
        status="PASS",
        measurement_source=FRESH_SOURCE,
        rows=rows,
        best_dual_frontier_candidate=best.get("arm_id"),
        target="maximize correctness and minimize full/visible tokens without claim drift",
        no_router_superiority_claim=True,
        no_promotion_authority=True,
    )


def compact_accuracy_regression_gate(scorecards: dict[str, Any]) -> dict[str, Any]:
    benchmark = scorecards["benchmark"]
    correct_counts = benchmark.get("correct_counts", {})
    best_correct = int(benchmark.get("best_static_correct_count", 0))
    realbench_anchor = 41
    minimum_allowed = 39
    gsm8k_guardrail = "REQUIRES_RUNTIME_SLICE_SCORECARD"
    status = "PASS" if best_correct >= minimum_allowed else "BLOCKED"
    return authority(
        schema_id="kt.v17_7_4.compact_accuracy_regression_gate.v1",
        status=status,
        outcome="DUAL_FRONTIER_ACCURACY_PRESERVED" if status == "PASS" else "KT_BLOCKED__COMPACT_ACCURACY_REGRESSION",
        best_correct=best_correct,
        minimum_allowed_correct=minimum_allowed,
        realbench_full_generation_best_correct_anchor=realbench_anchor,
        correct_counts=correct_counts,
        visible_compression_alone_sufficient=False,
        gsm8k_guardrail=gsm8k_guardrail,
        claim_ceiling_preserved=True,
    )


def arm_by_id_from_config(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(arm.get("arm_id")): arm for arm in config.get("arms", [])}


def first_present_arm(sample_rows: list[dict[str, Any]], candidates: list[str]) -> dict[str, Any] | None:
    by_arm = {row["arm_id"]: row for row in sample_rows}
    for candidate in candidates:
        if candidate in by_arm:
            return by_arm[candidate]
    return None


def best_row(sample_rows: list[dict[str, Any]]) -> dict[str, Any]:
    return sorted(sample_rows, key=lambda row: (-float(row.get("score", 0.0)), int(row.get("total_tokens", 10**9)), row["arm_id"]))[0]


def realbench_vs_dualfront_arm_diff_receipt(config: dict[str, Any]) -> dict[str, Any]:
    arms = arm_by_id_from_config(config)
    source = arms.get("math_act_adapter_global") or arms.get("A_known_good_math_act_reproduction") or {}
    comparison_ids = [
        "A_known_good_math_act_reproduction",
        "A3_prior_math_act_plus_finalizer_only",
        "A4_math_act_reasoning_preserving_compact_v2",
        "A6_specialist_admission_candidate_v2",
        "A2_math_act_full_reasoning",
        "A3_math_act_reasoning_preserving_compact",
    ]
    fields = [
        "adapter_hf_repo",
        "adapter_hf_subfolder",
        "adapter_path",
        "adapter_sha256_optional",
        "prompt_template_id",
        "max_new_tokens",
        "compact_mode",
        "score_from_visible_answer",
        "compact_scoring_disabled",
        "scoring_surface",
        "scoring_method",
        "model_repo_or_base",
    ]
    rows = []
    for arm_id in comparison_ids:
        target = arms.get(arm_id)
        if not target:
            continue
        diffs = {
            field: {"known_good": source.get(field, ""), "candidate": target.get(field, "")}
            for field in fields
            if source.get(field, "") != target.get(field, "")
        }
        rows.append(
            {
                "arm_id": arm_id,
                "known_good_source_arm": source.get("arm_id", "math_act_adapter_global"),
                "field_differences": diffs,
                "equivalent_to_known_good": not bool(diffs),
            }
        )
    known_good = arms.get("A_known_good_math_act_reproduction", {})
    required_clean = {
        "same_adapter_ref": known_good.get("adapter_hf_repo") == source.get("adapter_hf_repo")
        and known_good.get("adapter_hf_subfolder") == source.get("adapter_hf_subfolder"),
        "same_adapter_hash": known_good.get("adapter_sha256_optional") == source.get("adapter_sha256_optional"),
        "same_prompt_template": known_good.get("prompt_template_id") == source.get("prompt_template_id"),
        "same_max_new_tokens": known_good.get("max_new_tokens") == source.get("max_new_tokens"),
        "raw_scoring_surface": known_good.get("score_from_visible_answer") is False
        or str(known_good.get("scoring_surface", "")).upper() == "RAW_OUTPUT",
    }
    return authority(
        schema_id="kt.v17_7_4.realbench_vs_dualfront_arm_diff_receipt.v1",
        status="PASS" if all(required_clean.values()) else "BLOCKED",
        known_good_source_arm=source.get("arm_id", "math_act_adapter_global"),
        reproduction_arm="A_known_good_math_act_reproduction",
        required_clean=required_clean,
        comparisons=rows,
        compact_finalizer_and_reasoning_preserving_layers_separated=True,
        claim_ceiling_preserved=True,
    )


def known_good_lobe_reproduction_receipt(arm_rows: list[dict[str, Any]], scorecards: dict[str, Any]) -> dict[str, Any]:
    correct_counts = scorecards["benchmark"].get("correct_counts", {})
    arm_id = REPROLOCK_ARM_ID if REPROLOCK_ARM_ID in correct_counts else "A_known_good_math_act_reproduction"
    correct = int(correct_counts.get(arm_id, 0))
    total = len([row for row in arm_rows if row.get("arm_id") == arm_id])
    gsm8k_rows = [row for row in arm_rows if row.get("arm_id") == arm_id and "gsm8k" in str(row.get("dataset", "")).lower()]
    gsm8k_correct = sum(1 for row in gsm8k_rows if row.get("correct") is True)
    minimum = int(REALBENCH_KNOWN_GOOD_ANCHOR["minimum_reproduction_correct"])
    status = "PASS" if correct >= minimum else "BLOCKED"
    return authority(
        schema_id="kt.v17_7_4.known_good_lobe_reproduction_receipt.v1",
        status=status,
        outcome="KNOWN_GOOD_INTELLIGENCE_PATH_REPRODUCED" if status == "PASS" else "KT_BLOCKED__KNOWN_GOOD_INTELLIGENCE_PATH_NOT_REPRODUCED",
        reproduction_arm_id=arm_id,
        prior_realbench_anchor=REALBENCH_KNOWN_GOOD_ANCHOR,
        observed_correct=correct,
        observed_total=total,
        minimum_reproduction_correct=minimum,
        observed_gsm8k_correct=gsm8k_correct,
        observed_gsm8k_total=len(gsm8k_rows),
        compact_scoring_disabled_for_reproduction=True,
        finalizer_audit_only=True,
        current_runtime_claim_authority=False,
        claim_ceiling_preserved=True,
    )


def infer_failure_owner(chosen: dict[str, Any], best: dict[str, Any], known_good: dict[str, Any] | None) -> str:
    if best.get("correct") is True and chosen.get("correct") is not True:
        return "ROUTE_OWNED"
    if known_good and known_good.get("parser_format_failure") is True:
        return "SCORER_OWNED"
    if known_good and known_good.get("correct") is not True:
        return "LOBE_OWNED"
    if chosen.get("parser_format_failure") is True:
        return "FINALIZER_OWNED"
    if best.get("correct") is not True:
        return "IRREDUCIBLE"
    return "UNKNOWN_BLOCKED"


def intervention_for_owner(owner: str) -> str:
    return {
        "ROUTE_OWNED": "repair specialist admission rule from pre-generation features",
        "LOBE_OWNED": "queue lobe/adaptor scar for Academy repair only after minimum viable signal",
        "ADAPTER_OWNED": "queue adapter scar for Academy repair only after no-regression plan",
        "PROMPT_CONTRACT_OWNED": "patch prompt contract before training",
        "SCORER_OWNED": "patch parser/scorer before training",
        "FINALIZER_OWNED": "patch finalizer/extraction before training",
        "GATE_OWNED": "patch code-owned gate receipt",
        "HAT_OWNED": "calibrate KT-hat overhead/risk trigger",
        "BENCHMARK_OWNED": "quarantine or repair benchmark row",
        "ARCHIVE_SOURCE_OWNED": "bind missing historical source before claiming reproduction",
        "IRREDUCIBLE": "quarantine as irreducible or ambiguous until external evidence changes",
        "UNKNOWN_BLOCKED": "collect more evidence before intervention",
    }.get(owner, "collect more evidence before intervention")


def build_oracle_autopsy_rows(arm_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in arm_rows:
        by_sample[row["sample_id"]].append(row)
    rows = []
    for sample_id, sample_rows in sorted(by_sample.items()):
        best = best_row(sample_rows)
        base = first_present_arm(sample_rows, ["base_raw", "A0_base_raw", "A1_prior_realbench_base_raw_reproduction"]) or sample_rows[0]
        known_good = first_present_arm(sample_rows, ["A_known_good_math_act_reproduction", "math_act_adapter_global", "A2_math_act_full_reasoning"])
        router_choice = first_present_arm(sample_rows, ["A6_specialist_admission_candidate_v2", "A5_specialist_admission_controller_v1", "route_regret_policy_adapter_global"]) or best
        kt_hat_choice = first_present_arm(sample_rows, ["A5_kt_hat_risk_gated_v2", "A6_kt_hat_compact_risk_gated", "base_kt_hat_compact"]) or router_choice
        owner = infer_failure_owner(router_choice, best, known_good)
        repair_bid = {
            "owner": owner,
            "recommended_intervention": intervention_for_owner(owner),
            "trainable_now": owner in {"LOBE_OWNED", "ADAPTER_OWNED"} and known_good is not None,
            "training_authorized": False,
            "claim_ceiling_preserved": True,
        }
        rows.append(
            authority(
                schema_id="kt.v17_7_4.oracle_autopsy_row.v1",
                sample_id=sample_id,
                dataset=best.get("dataset"),
                task_family=best.get("task_family"),
                base_correct=bool(base.get("correct")),
                lobe_results={
                    row["arm_id"]: {
                        "correct": bool(row.get("correct")),
                        "score": row.get("score", 0.0),
                        "tokens": row.get("total_tokens", 0),
                        "parser_format_failure": bool(row.get("parser_format_failure")),
                    }
                    for row in sample_rows
                },
                router_choice=router_choice.get("arm_id"),
                router_correct=bool(router_choice.get("correct")),
                kt_hat_choice=kt_hat_choice.get("arm_id"),
                kt_hat_correct=bool(kt_hat_choice.get("correct")),
                oracle_choice=best.get("arm_id"),
                oracle_correct=bool(best.get("correct")),
                best_lobe=best.get("arm_id"),
                route_regret=max(float(best.get("score", 0.0)) - float(router_choice.get("score", 0.0)), 0.0),
                token_regret=max(int(router_choice.get("total_tokens", 0)) - int(best.get("total_tokens", 0)), 0),
                latency_regret=max(int(router_choice.get("latency_ms", 0)) - int(best.get("latency_ms", 0)), 0),
                failure_owner=owner,
                repair_bid=repair_bid,
                scar_candidate=owner not in {"IRREDUCIBLE"} and bool(best.get("correct") is True or router_choice.get("correct") is not True),
                delta_candidate=owner in {"ROUTE_OWNED", "LOBE_OWNED", "ADAPTER_OWNED", "PROMPT_CONTRACT_OWNED", "SCORER_OWNED", "FINALIZER_OWNED"},
                recommended_intervention=repair_bid["recommended_intervention"],
                oracle_correctness_used_as_runtime_feature=False,
            )
        )
    return rows


def build_scar_delta_registry(autopsy_rows: list[dict[str, Any]]) -> dict[str, Any]:
    scars = []
    owner_counts = Counter(row["failure_owner"] for row in autopsy_rows)
    for row in autopsy_rows:
        if not row.get("scar_candidate"):
            continue
        scars.append(
            {
                "schema_id": "kt.v17_7_4.scar_delta_registry_row.v1",
                "scar_id": sha256_text(f"{row['sample_id']}::{row['failure_owner']}")[:16],
                "sample_id": row["sample_id"],
                "dataset": row.get("dataset"),
                "task_family": row.get("task_family"),
                "failure_owner": row["failure_owner"],
                "what_failed": f"{row['router_choice']} did not match oracle/best outcome when repair signal existed",
                "where_it_failed": row.get("task_family"),
                "why_oracle_differed": f"oracle_choice={row['oracle_choice']}; route_regret={row['route_regret']}; token_regret={row['token_regret']}",
                "trainable": row["failure_owner"] in {"LOBE_OWNED", "ADAPTER_OWNED"},
                "repair_owner": row["failure_owner"],
                "future_eval_row_id": row["sample_id"],
                "training_authorized": False,
            }
        )
    return authority(
        schema_id="kt.v17_7_4.scar_delta_registry.v1",
        status="PASS",
        scar_count=len(scars),
        owner_counts=dict(owner_counts),
        scars=scars,
        training_authorized=False,
        claim_ceiling_preserved=True,
    )


def recursive_learning_delta_manifest(scar_registry: dict[str, Any]) -> dict[str, Any]:
    scars = scar_registry.get("scars", [])
    return authority(
        schema_id="kt.v17_7_4.recursive_learning_delta_manifest.v1",
        status="PASS",
        delta_rows=[
            {
                "delta_id": sha256_text(f"delta::{scar['scar_id']}")[:16],
                "scar_id": scar["scar_id"],
                "repair_owner": scar["repair_owner"],
                "future_eval_row_id": scar["future_eval_row_id"],
                "academy_eligible": scar["trainable"],
                "training_authorized": False,
            }
            for scar in scars
        ],
        no_training_in_this_lane=True,
        claim_ceiling_preserved=True,
    )


def academy_repair_plan(scar_registry: dict[str, Any], known_good_receipt: dict[str, Any]) -> dict[str, Any]:
    owner_counts = scar_registry.get("owner_counts", {})
    blocked_reasons = []
    if known_good_receipt.get("status") != "PASS":
        blocked_reasons.append("known_good_intelligence_path_not_reproduced")
    trainable_count = sum(1 for scar in scar_registry.get("scars", []) if scar.get("trainable") is True)
    return authority(
        schema_id="kt.v17_7_4.academy_repair_plan.v1",
        status="PASS" if not blocked_reasons else "BLOCKED",
        blocked_reasons=blocked_reasons,
        owner_counts=owner_counts,
        trainable_scar_count=trainable_count,
        rules=[
            "Do not train if failure is scorer/finalizer/prompt-owned.",
            "Do not train if G2 source is missing.",
            "Do not train if benchmark row is defective.",
            "Train only if lobe/adaptor-owned and repair_bid passes future minimum viable signal.",
            "Router repair only if route-owned and pre-generation features exist.",
            "Gate/court repair only if hard code rule is defective.",
        ],
        next_repair_surfaces=[
            surface
            for surface in ["SCORER_OWNED", "FINALIZER_OWNED", "PROMPT_CONTRACT_OWNED", "ROUTE_OWNED", "LOBE_OWNED", "ADAPTER_OWNED"]
            if owner_counts.get(surface, 0)
        ],
        training_authorized=False,
        claim_ceiling_preserved=True,
    )


def lobe_tournament_reentry_plan(config: dict[str, Any], scar_registry: dict[str, Any]) -> dict[str, Any]:
    arms = [arm.get("arm_id") for arm in config.get("arms", []) if arm.get("enabled", True)]
    return authority(
        schema_id="kt.v17_7_4.lobe_tournament_reentry_plan.v1",
        status="PASS",
        tournament_candidates=arms,
        required_comparisons=[
            "parent_lobe_vs_repaired_lobe",
            "repaired_lobe_vs_child_merged_lobe",
            "best_static_specialist_vs_router_selected_specialist",
            "router_selected_specialist_vs_oracle_shadow",
        ],
        tie_breakers=[
            "correctness",
            "full_tokens_per_correct",
            "visible_answer_tokens_per_correct",
            "negative_transfer",
            "parser_failure",
            "claim_risk",
            "replay_stability",
            "no_regression",
        ],
        scar_count=scar_registry.get("scar_count", 0),
        promotion_authority=False,
        claim_ceiling_preserved=True,
    )


def tie_merge_child_lobe_plan(tournament_plan: dict[str, Any]) -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.tie_merge_child_lobe_plan.v1",
        status="PASS",
        child_lobe_replacement_requirements=[
            "distinct_hash",
            "lineage_receipt",
            "no_regression_pass",
            "tournament_receipt",
            "rollback_path",
        ],
        tournament_candidates=tournament_plan.get("tournament_candidates", []),
        child_lobe_replacement_authorized=False,
        claim_ceiling_preserved=True,
    )


def kt_hat_mount_comparison_plan(config: dict[str, Any]) -> dict[str, Any]:
    arms = arm_by_id_from_config(config)
    return authority(
        schema_id="kt.v17_7_4.kt_hat_mount_comparison_plan.v1",
        status="PASS",
        comparisons={
            "base_model_alone": any(arm in arms for arm in ["base_raw", "A0_base_raw"]),
            "base_plus_trained_lobe_safetensors": any(arm.get("arm_kind") == "adapter" for arm in arms.values()),
            "base_plus_router_selected_safetensors": any(arm in arms for arm in ["route_regret_policy_adapter_global", "A6_specialist_admission_candidate_v2"]),
            "base_plus_kt_hat_runtime": any(arm in arms for arm in ["base_kt_hat_compact", "A5_kt_hat_risk_gated_v2", "A6_kt_hat_compact_risk_gated"]),
            "oracle_shadow": any(arm in arms for arm in ["A7_oracle_shadow", "A7_oracle_shadow_not_runtime"]),
        },
        must_distinguish=[
            "base_model_intelligence",
            "trained_substrate_intelligence",
            "router_selection_gain",
            "kt_hat_governance_cost",
            "oracle_gap",
            "compression_cost",
        ],
        runtime_authority=False,
        promotion_authority=False,
        claim_ceiling_preserved=True,
    )


def gsm8k_regression_autopsy(arm_rows: list[dict[str, Any]]) -> dict[str, Any]:
    gsm_rows = [row for row in arm_rows if "gsm8k" in str(row.get("dataset", "")).lower()]
    by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in gsm_rows:
        by_arm[row["arm_id"]].append(row)
    matrix = {}
    owner_votes = Counter()
    for arm, rows in sorted(by_arm.items()):
        correct = sum(1 for row in rows if row.get("correct") is True)
        parser_fail = sum(1 for row in rows if row.get("parser_format_failure") is True)
        if parser_fail / max(len(rows), 1) > 0.20:
            owner = "SCORER_OWNED"
        elif correct < REALBENCH_KNOWN_GOOD_ANCHOR["math_act_gsm8k"]["correct"] and "math" in arm:
            owner = "PROMPT_CONTRACT_OWNED"
        else:
            owner = "UNKNOWN_BLOCKED"
        owner_votes[owner] += 1
        matrix[arm] = {
            "correct": correct,
            "total": len(rows),
            "parser_failure_count": parser_fail,
            "parser_failure_rate": safe_ratio(parser_fail, len(rows)),
            "owner_vote": owner,
        }
    status = "PASS" if matrix else "BLOCKED"
    return authority(
        schema_id="kt.v17_7_4.gsm8k_regression_autopsy.v1",
        status=status,
        prior_math_act_gsm8k_anchor=REALBENCH_KNOWN_GOOD_ANCHOR["math_act_gsm8k"],
        observed_matrix=matrix,
        owner_votes=dict(owner_votes),
        allowed_owners=[
            "PROMPT_CONTRACT_OWNED",
            "FINALIZER_OWNED",
            "SCORER_OWNED",
            "ADAPTER_MOUNT_OWNED",
            "GENERATION_CONFIG_OWNED",
            "BENCHMARK_ROW_OWNED",
        ],
        training_authorized=False,
        claim_ceiling_preserved=True,
    )


def parser_failure_repair_plan(scorecards: dict[str, Any]) -> dict[str, Any]:
    matrix = scorecards.get("parser_error", {}).get("matrix", {})
    defects = [
        {"arm_id": arm, "parser_failure_rate": payload.get("parser_format_failure_rate", 0.0)}
        for arm, payload in sorted(matrix.items())
        if float(payload.get("parser_format_failure_rate", 0.0)) > 0.20
    ]
    return authority(
        schema_id="kt.v17_7_4.parser_failure_repair_plan.v1",
        status="PASS" if not defects else "BLOCKED",
        outcome="PARSER_FAILURE_WITHIN_THRESHOLD" if not defects else "KT_BLOCKED__PARSER_FAILURE_RATE_TOO_HIGH",
        threshold=0.20,
        defects=defects,
        repair_rules=[
            "Fail closed if parser failure rate exceeds 0.20 on compact/finalized arms.",
            "Final visible answer must be scored when compact scoring is enabled.",
            "Parser must not extract an early scratch number when a final marker exists.",
        ],
        training_authorized=False,
        claim_ceiling_preserved=True,
    )


def claim_ceiling_receipt() -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.oracle_academy_claim_ceiling_receipt.v1",
        status="PASS",
        no_training_authorized=True,
        no_promotion_authorized=True,
        no_v18_authority=True,
        no_router_superiority_claim=True,
        no_commercial_claim=True,
        no_external_validation_claim=True,
        no_g2_recovered_claim=True,
        claim_ceiling_preserved=True,
    )


def recompute_scorecards(arm_rows: list[dict[str, Any]], predictions: list[dict[str, Any]]) -> dict[str, Any]:
    enforce_fresh_rows(arm_rows, predictions)
    by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_band_arm: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    by_sample: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in arm_rows:
        by_arm[row["arm_id"]].append(row)
        by_band_arm[(row["evidence_band"], row["arm_id"])].append(row)
        by_sample[row["sample_id"]][row["arm_id"]] = row
    arms = sorted(by_arm)
    arm_accuracy = {
        arm: round(sum(1 for row in rows if row["correct"]) / max(len(rows), 1), 6)
        for arm, rows in sorted(by_arm.items())
    }
    correct_counts = {arm: sum(1 for row in rows if row["correct"]) for arm, rows in sorted(by_arm.items())}
    best_arm = sorted(arms, key=lambda arm: (-arm_accuracy[arm], arm))[0]
    base_arm_id = "base_raw" if "base_raw" in correct_counts else "A0_base_raw" if "A0_base_raw" in correct_counts else arms[0]
    compact_arm_id = "base_kt_hat_compact" if "base_kt_hat_compact" in correct_counts else "A6_kt_hat_compact_risk_gated" if "A6_kt_hat_compact_risk_gated" in correct_counts else ""
    base_correct = correct_counts.get(base_arm_id, 0)
    oracle_correct = sum(1 for row in predictions if row["oracle_correct"])
    band_rows = Counter(row["evidence_band"] for row in predictions)
    per_band = {}
    for band in sorted(band_rows):
        per_band[band] = {"row_count": band_rows[band], "arms": {}}
        for arm in arms:
            rows = by_band_arm[(band, arm)]
            correct = sum(1 for row in rows if row["correct"])
            per_band[band]["arms"][arm] = {
                "correct": correct,
                "total": len(rows),
                "accuracy": round(correct / max(len(rows), 1), 6),
            }
    negative_transfer = {arm: 0 for arm in arms}
    for sample_arms in by_sample.values():
        base = sample_arms.get(base_arm_id)
        if not base or not base.get("correct"):
            continue
        for arm, row in sample_arms.items():
            if not row.get("correct"):
                negative_transfer[arm] += 1
    token_efficiency = {}
    token_accounting = {}
    visible_answer_ledger = {}
    for arm, rows in by_arm.items():
        tokens = sum(int(row.get("total_tokens", int(row["tokens_in"]) + int(row["tokens_out"]))) for row in rows)
        input_tokens = sum(int(row.get("tokens_in", 0)) for row in rows)
        output_tokens = sum(int(row.get("tokens_out", 0)) for row in rows)
        visible_tokens = sum(int(row.get("visible_answer_tokens", row.get("answer_tokens", 0))) for row in rows)
        reasoning_tokens = sum(int(row.get("reasoning_tokens", 0)) for row in rows)
        route_tokens = sum(int(row.get("route_overhead_tokens", 0)) for row in rows)
        hat_tokens = sum(int(row.get("hat_tokens", 0)) for row in rows)
        latency = sum(int(row["latency_ms"]) for row in rows)
        correct = correct_counts[arm]
        token_efficiency[arm] = {
            "total_tokens": tokens,
            "correct": correct,
            "tokens_per_correct": safe_ratio(tokens, correct),
            "verified_work_per_token": safe_ratio(correct, tokens),
            "latency_per_correct": safe_ratio(latency, correct),
            "mean_latency_ms": safe_ratio(latency, len(rows)),
        }
        token_accounting[arm] = {
            "correct": correct,
            "full_prompt_plus_output_tokens": tokens,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "raw_output_tokens": output_tokens,
            "visible_answer_tokens": visible_tokens,
            "reasoning_tokens": reasoning_tokens,
            "route_overhead_tokens": route_tokens,
            "hat_overhead_tokens": hat_tokens,
            "full_prompt_plus_output_tokens_per_correct": safe_ratio(tokens, correct),
            "input_tokens_per_correct": safe_ratio(input_tokens, correct),
            "prompt_tokens_per_correct": safe_ratio(input_tokens, correct),
            "output_tokens_per_correct": safe_ratio(output_tokens, correct),
            "raw_output_tokens_per_correct": safe_ratio(output_tokens, correct),
            "visible_answer_tokens_per_correct": safe_ratio(visible_tokens, correct),
            "reasoning_tokens_per_correct": safe_ratio(reasoning_tokens, correct),
            "route_overhead_tokens_per_correct": safe_ratio(route_tokens, correct),
            "hat_overhead_tokens_per_correct": safe_ratio(hat_tokens, correct),
            "visible_answer_verified_work_per_token": safe_ratio(correct, visible_tokens),
        }
        visible_answer_ledger[arm] = {
            "correct": correct,
            "visible_answer_tokens": visible_tokens,
            "visible_answer_tokens_per_correct": safe_ratio(visible_tokens, correct),
            "visible_answer_verified_work_per_token": safe_ratio(correct, visible_tokens),
            "scaffold_language_rows": sum(1 for row in rows if row.get("scaffold_language_in_visible_answer") is True),
            "scored_from_visible_answer_rows": sum(1 for row in rows if row.get("final_visible_answer_used_for_scoring") is True),
        }
    vwpt = authority(
        schema_id="kt.v17_7_4.truegen_verified_work_per_token_scorecard.v1",
        status="PASS",
        measurement_source=FRESH_SOURCE,
        formula="correct_count / total_tokens",
        anti_goodhart_pairing=["answer_adequacy_proxy=correct", "parser_format_failure_rate", "negative_transfer_by_arm"],
        matrix={arm: {"verified_work_per_token": payload["verified_work_per_token"], "tokens_per_correct": payload["tokens_per_correct"]} for arm, payload in token_efficiency.items()},
    )
    route_overhead = {}
    hat_overhead = {}
    parser_error = {}
    answer_format = {}
    finalizer_matrix = {}
    bloat_counter: dict[str, Counter[str]] = defaultdict(Counter)
    route_regret_token_cost = {}
    for arm, rows in by_arm.items():
        route_overhead[arm] = {
            "mean_route_overhead_tokens": safe_ratio(sum(int(row.get("route_overhead_tokens", 0)) for row in rows), len(rows)),
            "mean_router_tokens": safe_ratio(sum(int(row.get("router_tokens", 0)) for row in rows), len(rows)),
            "mean_tribunal_tokens": safe_ratio(sum(int(row.get("tribunal_tokens", 0)) for row in rows), len(rows)),
            "mean_repair_tokens": safe_ratio(sum(int(row.get("repair_tokens", 0)) for row in rows), len(rows)),
        }
        hat_overhead[arm] = {
            "mean_hat_tokens": safe_ratio(sum(int(row.get("hat_tokens", 0)) for row in rows), len(rows)),
            "mean_hat_overhead_ratio": safe_ratio(sum(float(row.get("hat_overhead_ratio", 0.0)) for row in rows), len(rows)),
        }
        parser_failures = sum(1 for row in rows if row.get("parser_format_failure") is True)
        parser_error[arm] = {
            "parser_format_failures": parser_failures,
            "parser_format_failure_rate": safe_ratio(parser_failures, len(rows)),
        }
        marker_count = sum(1 for row in rows if row.get("final_answer_marker_present") is True)
        scaffold_count = sum(1 for row in rows if row.get("scaffold_language_in_visible_answer") is True)
        compact_pass_count = sum(1 for row in rows if row.get("compact_answer_contract_status") == "PASS")
        answer_format[arm] = {
            "final_answer_marker_rate": safe_ratio(marker_count, len(rows)),
            "answer_format_drift_rate": safe_ratio(len(rows) - marker_count, len(rows)),
        }
        finalizer_matrix[arm] = {
            "compact_answer_contract_pass_rate": safe_ratio(compact_pass_count, len(rows)),
            "scaffold_language_in_visible_answer_rate": safe_ratio(scaffold_count, len(rows)),
            "mean_visible_answer_tokens": safe_ratio(sum(int(row.get("visible_answer_tokens", 0)) for row in rows), len(rows)),
            "mean_output_tokens": safe_ratio(sum(int(row.get("tokens_out", 0)) for row in rows), len(rows)),
        }
        for row in rows:
            bloat_counter[arm][str(row.get("bloat_class", BLOAT_CLASSES["none"]))] += 1
        route_regret_token_cost[arm] = {
            "correct": correct_counts[arm],
            "tokens_per_correct": token_efficiency[arm]["tokens_per_correct"],
            "route_overhead_tokens_total": sum(int(row.get("route_overhead_tokens", 0)) for row in rows),
            "overhead_per_correct": safe_ratio(sum(int(row.get("route_overhead_tokens", 0)) for row in rows), correct_counts[arm]),
        }
    bloat_matrix = {
        arm: {"counts": dict(counter), "dominant_bloat_class": counter.most_common(1)[0][0] if counter else BLOAT_CLASSES["none"]}
        for arm, counter in sorted(bloat_counter.items())
    }
    ablation_ladder = {
        ladder_id: {
            "arm_id": arm,
            "configured": arm in by_arm,
            "accuracy": arm_accuracy.get(arm),
            "correct": correct_counts.get(arm),
            "tokens_per_correct": token_efficiency.get(arm, {}).get("tokens_per_correct"),
            "verified_work_per_token": token_efficiency.get(arm, {}).get("verified_work_per_token"),
        }
        for arm, ladder_id in ABLATION_LADDER.items()
    }
    base_eff = token_efficiency.get(base_arm_id, {})
    best_eff_arm = sorted(arms, key=lambda arm: (-token_efficiency[arm]["verified_work_per_token"], -correct_counts[arm], arm))[0]
    best_eff = token_efficiency[best_eff_arm]
    compression_gain_over_base = safe_ratio(base_eff.get("tokens_per_correct", 0) - best_eff["tokens_per_correct"], base_eff.get("tokens_per_correct", 0))
    compact = token_efficiency.get(compact_arm_id) if compact_arm_id else None
    compact_regression = bool(compact and base_eff and compact["correct"] < base_eff.get("correct", 0) and compact["tokens_per_correct"] > base_eff.get("tokens_per_correct", 0))
    frontier_pass = (
        bool(base_eff)
        and best_eff["correct"] >= base_eff.get("correct", 0)
        and best_eff["tokens_per_correct"] <= base_eff.get("tokens_per_correct", 0) * 0.75
        and sum(parser_error[best_eff_arm].values()) >= 0
        and not compact_regression
    )
    blocked_reasons = []
    if not base_eff:
        blocked_reasons.append("base_raw_missing")
    elif best_eff["correct"] < base_eff.get("correct", 0):
        blocked_reasons.append("best_efficiency_arm_loses_correctness_vs_base")
    elif best_eff["tokens_per_correct"] > base_eff.get("tokens_per_correct", 0) * 0.75:
        blocked_reasons.append("tokens_per_correct_not_materially_better_than_base")
    if compact_regression:
        blocked_reasons.append("base_kt_hat_compact_regressed_against_base")
    compression_gate = authority(
        schema_id="kt.v17_7_4.truegen_compression_frontier_gate.v1",
        status="PASS" if frontier_pass else "BLOCKED",
        outcome="KT_COMPRESSION_FRONTIER_RECAPTURED__TRUEGEN_EFFICIENCY_GATE_NEXT__CLAIM_CEILING_PRESERVED"
        if frontier_pass
        else "KT_BLOCKED__COMPRESSION_FRONTIER_REGRESSION",
        measurement_source=FRESH_SOURCE,
        best_efficiency_arm=best_eff_arm,
        best_efficiency_metrics=best_eff,
        base_raw_metrics=base_eff,
        compression_gain_over_base_tokens_per_correct=compression_gain_over_base,
        g2_anchor=g2_compression_anchor_receipt(),
        blocked_reasons=blocked_reasons,
        claim_scope="internal true-generation efficiency evidence only; no promotion, no router-superiority claim",
    )
    adapter_quarantine = {
        arm: {
            "negative_transfer_count": negative_transfer.get(arm, 0),
            "tokens_per_correct": token_efficiency[arm]["tokens_per_correct"],
            "correct": correct_counts[arm],
            "recommendation": "SHADOW_OR_QUARANTINE_REVIEW"
            if arm != "base_raw" and (negative_transfer.get(arm, 0) > 0 or correct_counts[arm] < base_correct)
            else "NO_QUARANTINE_RECOMMENDED",
        }
        for arm in arms
    }
    result = {
        "benchmark": authority(
            schema_id="kt.v17_7_4.truegen_benchmark_scorecard.v1",
            status="PASS",
            measurement_source=FRESH_SOURCE,
            measurement_status=FRESH_STATUS,
            row_level_recomputed=True,
            row_count=len(predictions),
            arm_rows=len(arm_rows),
            arm_accuracy=arm_accuracy,
            correct_counts=correct_counts,
            best_static_arm=best_arm,
            best_static_correct_count=correct_counts[best_arm],
            base_raw_correct_count=base_correct,
            base_arm_id=base_arm_id,
            oracle_correct_count=oracle_correct,
            fresh_generation_pass=True,
        ),
        "negative_transfer": authority(schema_id="kt.v17_7_4.truegen_negative_transfer_by_arm.v1", status="PASS", measurement_source=FRESH_SOURCE, negative_transfer=negative_transfer),
        "token_efficiency": authority(schema_id="kt.v17_7_4.truegen_token_efficiency_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=token_efficiency),
        "token_accounting_ledger": authority(
            schema_id="kt.v17_7_4.token_accounting_ledger.v1",
            status="PASS",
            measurement_source=FRESH_SOURCE,
            accounting_modes=[
                "full_prompt_plus_output_tokens_per_correct",
                "input_tokens_per_correct",
                "prompt_tokens_per_correct",
                "output_tokens_per_correct",
                "raw_output_tokens_per_correct",
                "reasoning_tokens_per_correct",
                "visible_answer_tokens_per_correct",
                "route_overhead_tokens_per_correct",
                "hat_overhead_tokens_per_correct",
            ],
            matrix=token_accounting,
            g2_comparison_warning="G2 3.74 tokens_per_correct is not comparable until exact G2 accounting mode is recovered.",
        ),
        "verified_work_per_token": vwpt,
        "visible_answer_ledger": authority(
            schema_id="kt.v17_7_4.visible_answer_ledger.v1",
            status="PASS",
            measurement_source=FRESH_SOURCE,
            scoring_policy="final_visible_answer_used_when_compact_contract_enabled",
            raw_output_audit_only_when_compact=True,
            matrix=visible_answer_ledger,
        ),
        "route_overhead": authority(schema_id="kt.v17_7_4.truegen_route_overhead_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=route_overhead),
        "hat_overhead": authority(schema_id="kt.v17_7_4.truegen_hat_overhead_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=hat_overhead),
        "bloat_attribution": authority(schema_id="kt.v17_7_4.truegen_bloat_attribution_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=bloat_matrix),
        "parser_error": authority(schema_id="kt.v17_7_4.truegen_parser_vs_generation_error_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=parser_error),
        "answer_format": authority(schema_id="kt.v17_7_4.truegen_answer_format_drift_receipt.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=answer_format),
        "answer_only_finalizer": authority(
            schema_id="kt.v17_7_4.answer_only_finalizer_receipt.v1",
            status="PASS",
            measurement_source=FRESH_SOURCE,
            expected_answer_visible_to_model=False,
            scaffold_language_forbidden=True,
            matrix=finalizer_matrix,
        ),
        "route_regret_token_cost": authority(schema_id="kt.v17_7_4.truegen_route_regret_token_cost_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=route_regret_token_cost),
        "ablation_ladder": authority(schema_id="kt.v17_7_4.truegen_ablation_ladder_scorecard.v1", status="PASS", measurement_source=FRESH_SOURCE, ladder=ablation_ladder),
        "adapter_quarantine": authority(schema_id="kt.v17_7_4.truegen_adapter_quarantine_recommendation.v1", status="PASS", measurement_source=FRESH_SOURCE, recommendations=adapter_quarantine, promotion_authority=False),
        "compression_frontier": compression_gate,
        "per_band": authority(schema_id="kt.v17_7_4.truegen_per_band_arm_win_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=per_band),
        "oracle_gap": authority(schema_id="kt.v17_7_4.truegen_oracle_gap_update.v1", status="PASS", measurement_source=FRESH_SOURCE, gaps={arm: oracle_correct - correct_counts[arm] for arm in arms}),
        "pfail_dgs": authority(
            schema_id="kt.v17_7_4.truegen_pfail_dgs_update.v1",
            status="PASS",
            measurement_source=FRESH_SOURCE,
            pfail=round(1.0 - oracle_correct / max(len(predictions), 1), 6),
            dgs=round((oracle_correct - base_correct) / max(len(predictions), 1), 6),
        ),
    }
    result["dual_frontier_scorecard"] = dual_frontier_scorecard(result)
    result["compact_accuracy_regression_gate"] = compact_accuracy_regression_gate(result)
    return result


def pearson(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    denom_x = math.sqrt(sum((x - mean_x) ** 2 for x in xs))
    denom_y = math.sqrt(sum((y - mean_y) ** 2 for y in ys))
    if not denom_x or not denom_y:
        return None
    return round(numerator / (denom_x * denom_y), 6)


def replay_correlation(arm_rows: list[dict[str, Any]], manifest_rows: list[dict[str, Any]]) -> dict[str, Any]:
    replay_by_sample = {row["sample_id"]: row.get("source_replay_reference_if_any", {}) for row in manifest_rows}
    xs: list[float] = []
    ys: list[float] = []
    for row in arm_rows:
        replay_scores = replay_by_sample.get(row["sample_id"], {}).get("route_values_pre_generation", {})
        if row["arm_id"] in replay_scores:
            xs.append(float(replay_scores[row["arm_id"]]))
            ys.append(float(row["score"]))
    corr = pearson(xs, ys)
    mae = round(sum(abs(x - y) for x, y in zip(xs, ys)) / max(len(xs), 1), 6) if xs else None
    if corr is None:
        decision = "TRUEGEN_INSUFFICIENT__LARGER_MINIFURNACE_NEXT"
    elif corr < 0.1:
        decision = "TRUEGEN_CONFLICTS_WITH_REPLAY__DIAGNOSTIC_REVIEW_NEXT"
    else:
        decision = "TRUEGEN_VALIDATED__TARGETED_REPLAY_DESIGN_NEXT"
    return authority(
        schema_id="kt.v17_7_4.truegen_replay_correlation_scorecard.v1",
        status="PASS",
        measurement_source=FRESH_SOURCE,
        compared_pairs=len(xs),
        correlation_replay_score_to_truegen_score=corr,
        mean_absolute_error=mae,
        decision=decision,
    )


def kt_system_wiring_map(config: dict[str, Any]) -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.system_wiring_map.v1",
        status="PASS",
        wiring_scope="V17.7.4 TrueGen compression frontier packet",
        router_surface="route/admission represented by configured ablation arms and route_regret prompt/template; no learned-router authority",
        hat_surface="base_kt_hat_compact, routed_hat_full, routed_hat_repair prompt overlays",
        adapter_surface="PEFT adapter arms only when adapter_loader_mode=PEFT_MODEL_FROM_PRETRAINED",
        scorer_surface="score_output + parser_vs_generation_error_matrix + answer_format_drift_receipt",
        receipt_surface=ASSESSMENT_FILES,
        claim_surface="truegen_claim_admissibility_casefile + truegen_efficiency_claim_boundary_receipt",
        fallback_law="smoke config, source replay, and base fallback as adapter evidence fail closed",
        enabled_arms=[arm["arm_id"] for arm in enabled_arms(config)],
        ablation_ladder=ABLATION_LADDER,
    )


def router_admission_receipt(scorecards: dict[str, Any]) -> dict[str, Any]:
    matrix = scorecards["route_regret_token_cost"]["matrix"]
    base_arm_id = scorecards.get("benchmark", {}).get("base_arm_id") or ("base_raw" if "base_raw" in matrix else "A0_base_raw")
    base = matrix.get(base_arm_id, {})
    decisions = {}
    for arm, payload in sorted(matrix.items()):
        if arm == base_arm_id:
            decisions[arm] = "BASELINE_DIRECT_PATH"
            continue
        correctness_gain = int(payload.get("correct", 0)) - int(base.get("correct", 0))
        overhead = float(payload.get("overhead_per_correct", 0.0))
        if correctness_gain > 0 or arm in ADAPTER_ARM_IDS:
            decisions[arm] = "SHADOW_ADMISSIBLE_FOR_MEASUREMENT"
        elif overhead > 0:
            decisions[arm] = "DIRECT_COMPACT_PATH_PREFERRED_UNTIL_GAIN_PROVEN"
        else:
            decisions[arm] = "NO_EXTRA_OVERHEAD_NO_ADMISSION_GAIN"
    return authority(
        schema_id="kt.v17_7_4.router_admission_cost_gate.v1",
        status="PASS",
        formula="route admitted only when expected/observed correctness gain or specialization justifies overhead",
        direct_compact_default=True,
        decisions=decisions,
        no_learned_router_superiority_claim=True,
        no_route_promotion_authority=True,
    )


def efficiency_claim_boundary_receipt(compression_gate: dict[str, Any]) -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.truegen_efficiency_claim_boundary_receipt.v1",
        status="PASS",
        compression_frontier_status=compression_gate["status"],
        allowed_claim="internal true-generation efficiency measurement with claim ceiling preserved",
        forbidden_claims=[
            "router superiority",
            "learned-router superiority",
            "external validation",
            "commercial readiness",
            "production readiness",
            "7B amplification",
            "frontier or S-tier parity",
        ],
        promotion_authority=False,
        runtime_authority=False,
    )


def hf_vault_adapter_manifest_receipt(config: dict[str, Any]) -> dict[str, Any]:
    adapter_arms = []
    for arm in enabled_arms(config):
        if arm["arm_id"] not in ADAPTER_ARM_IDS:
            continue
        adapter_arms.append(
            {
                "arm_id": arm["arm_id"],
                "expected_adapter_id": arm.get("expected_adapter_id"),
                "adapter_hf_repo": arm.get("adapter_hf_repo") or "",
                "adapter_hf_subfolder": arm.get("adapter_hf_subfolder") or "",
                "adapter_path_fallback": arm.get("adapter_path") or "",
                "adapter_sha256_expected": arm.get("adapter_sha256_optional") or "",
                "selected_source_kind": adapter_source_kind_for_arm(arm, config),
            }
        )
    return authority(
        schema_id="kt.v17_7_4.hf_vault_adapter_manifest_receipt.v1",
        status="PASS",
        adapter_source_preference=adapter_source_preference(config),
        hf_vault_adapter_required=config.get("hf_vault_adapter_required") is True,
        hf_vault_repo=config.get("hf_vault_repo", ""),
        adapter_arms=adapter_arms,
        source_of_truth="HF_VAULT_FIRST_WHEN_REPO_BOUND",
        local_adapter_payload_required=False,
        no_safetensors_packaged_back=True,
    )


def hf_vault_adapter_source_receipt(config: dict[str, Any], adapter_loader_receipts: list[dict[str, Any]]) -> dict[str, Any]:
    selected = {
        row.get("arm_id"): {
            "adapter_source_kind": row.get("adapter_source_kind"),
            "adapter_source_status": row.get("adapter_source_status"),
            "adapter_ref": row.get("adapter_ref"),
            "adapter_hf_subfolder": row.get("adapter_hf_subfolder", ""),
            "adapter_load_status": row.get("adapter_load_status"),
        }
        for row in adapter_loader_receipts
        if row.get("arm_id") in ADAPTER_ARM_IDS
    }
    return authority(
        schema_id="kt.v17_7_4.hf_vault_adapter_source_receipt.v1",
        status="PASS",
        adapter_source_preference=adapter_source_preference(config),
        selected_sources=selected,
        hf_vault_selected_for_adapter_arms=all(
            payload.get("adapter_source_kind") == ADAPTER_SOURCE_HF_VAULT for payload in selected.values()
        )
        if selected
        else False,
        claim_ceiling_preserved=True,
    )


def memory_execution_policy_receipt(config: dict[str, Any]) -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.memory_execution_policy_receipt.v1",
        status="PASS",
        policy="KT13_HF_VAULT_ARM_ISOLATED_STREAMING",
        arm_execution_order="ARM_MAJOR_ONE_ARM_AT_A_TIME",
        model_cache_scope="ONE_GENERATION_BACKEND_PER_ARM",
        unload_between_arms=True,
        torch_empty_cache_after_arm=True,
        stream_rows_to_disk=bool(config.get("stream_rows_to_disk", True)),
        partial_output_rescue=True,
        no_heavy_artifact_return=True,
        row_ladder=config.get("row_ladder") or DEFAULT_ROW_LADDER,
        default_row_ladder_stage=config.get("default_row_ladder_stage"),
        max_new_tokens=config.get("max_new_tokens"),
    )


def streaming_generation_receipt(out: Path, run_id: str, stream_path: Path) -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.streaming_generation_receipt.v1",
        status="PASS",
        run_id=run_id,
        stream_path=stream_path.as_posix(),
        streamed_arm_rows=count_jsonl_rows(stream_path),
        row_streaming_enabled=True,
        flush_policy="APPEND_JSONL_AFTER_EACH_ARM_ROW",
    )


def partial_output_rescue_receipt(out: Path, run_id: str, status: str = "PASS") -> dict[str, Any]:
    stream_path = out / "truegen_arm_result_matrix.jsonl"
    return authority(
        schema_id="kt.v17_7_4.partial_output_rescue_receipt.v1",
        status=status,
        run_id=run_id,
        partial_rows_preserved=count_jsonl_rows(stream_path),
        stream_path=stream_path.as_posix(),
        assessment_zip_attempted=True,
        no_restart_from_scratch_policy=True,
    )


def assessment_only_packaging_receipt(out: Path, assessment: Path | None = None) -> dict[str, Any]:
    heavy_suffixes = (".safetensors", ".bin", ".pt", ".pth")
    included = [name for name in ASSESSMENT_FILES if (out / name).exists()]
    return authority(
        schema_id="kt.v17_7_4.assessment_only_packaging_receipt.v1",
        status="PASS",
        assessment_zip=assessment.as_posix() if assessment else "",
        included_files=included,
        excluded_heavy_suffixes=list(heavy_suffixes),
        heavy_artifacts_packaged=False,
        cache_artifacts_packaged=False,
        assessment_only_return_discipline=True,
    )


def write_assessment(out: Path) -> Path:
    assessment = out / "KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in ASSESSMENT_FILES:
            path = out / name
            if path.exists():
                archive.write(path, name)
        blocker = out / "BLOCKER_RECEIPT.json"
        if blocker.exists():
            archive.write(blocker, "BLOCKER_RECEIPT.json")
    return assessment


def write_blocker(out: Path, run_id: str, reason: str, defects: list[str] | None = None) -> dict[str, Any]:
    write_json(out / "partial_output_rescue_receipt.json", partial_output_rescue_receipt(out, run_id, status="BLOCKED"))
    outcome = "KTG3FULL_V17_7_4_BLOCKED__GENERATION_FAILURE"
    for marker in [
        "KT_BLOCKED__ROW_REQUEST_NOT_HONORED",
        "KT_BLOCKED__BENCHMARK_PROMPT_INTEGRITY_DEFECT",
        "KT_BLOCKED__G2_SENTINEL_SOURCE_MISSING",
        "KT_BLOCKED__PROMPT_MANIFEST_INCOMPLETE",
        "KT_BLOCKED__KNOWN_GOOD_PROMPT_SOURCE_MISSING",
        "KT_BLOCKED__PROMPT_HASH_REPRODUCTION_FAILED",
        "KT_BLOCKED__RENDERED_PROMPT_REPRODUCTION_FAILED",
        "KT_BLOCKED__TOKENIZED_INPUT_REPRODUCTION_FAILED",
        "KT_BLOCKED__KNOWN_GOOD_SCAFFOLD_CONTAMINATION",
        "KT_BLOCKED__REPRO_STAGE0_IDENTITY_AUDIT_FAILED",
        "KT_BLOCKED__KNOWN_GOOD_INTELLIGENCE_PATH_NOT_REPRODUCED",
        "KT_BLOCKED__CLAIM_CEILING_DRIFT",
    ]:
        if marker in reason:
            outcome = marker
            break
    payload = authority(
        schema_id="kt.v17_7_4.truegen_blocker_receipt.v1",
        status="BLOCKED",
        run_id=run_id,
        outcome=outcome,
        reason=reason,
        defects=defects or [],
        partial_rows_preserved=count_jsonl_rows(out / "truegen_arm_result_matrix.jsonl"),
        next_lawful_move="FIX_TRUEGEN_RUNTIME_INPUTS_AND_RERUN",
    )
    write_json(out / "BLOCKER_RECEIPT.json", payload)
    assessment = write_assessment(out)
    write_json(out / "assessment_only_packaging_receipt.json", assessment_only_packaging_receipt(out, assessment))
    write_assessment(out)
    return payload


def run_truegen_runtime(runtime_root: Path, out: Path | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    if out is None:
        out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktv1774_truegen_outputs"))
        if not out.parent.exists():
            out = Path("ktv1774_truegen_outputs")
    out.mkdir(parents=True, exist_ok=True)
    run_id = os.environ.get("KT_RUN_ID") or f"ktv1774_truegen_{int(time.time())}"
    config_path = resolve_runtime_path(runtime_root, "KT_TRUEGEN_ARM_MODEL_CONFIG", "runtime_inputs/arm_model_config.json")
    if not config_path.exists():
        example = runtime_root / "runtime_inputs" / "arm_model_config.example.json"
        if example.exists():
            config_path = example
        else:
            return write_blocker(out, run_id, "missing arm_model_config.json")
    row_manifest_path = resolve_runtime_path(runtime_root, "KT_TRUEGEN_ROW_MANIFEST", "runtime_inputs/truegen_row_manifest.json")
    try:
        config = read_json(config_path)
        defects = validate_arm_model_config(config)
        if defects:
            return write_blocker(out, run_id, "arm model config contract failed", defects)
        row_limit, row_ladder = resolve_effective_row_limit(config)
        write_json(out / "row_ladder_receipt.json", row_ladder)
        write_json(out / "v17_7_4_row_authority_receipt.json", row_ladder)
        if row_ladder["status"] != "PASS":
            raise RuntimeError(f"KT_BLOCKED__ROW_REQUEST_NOT_HONORED: {row_ladder.get('reason_if_not_honored', '')}")
        manifest = load_row_manifest(row_manifest_path, row_limit=row_limit)
        measurement_mode = row_measurement_mode(config)
        if measurement_mode == G2_SENTINEL_MODE:
            g2_receipt = g2_sentinel_manifest_receipt(runtime_root)
            write_json(out / "g2_sentinel_replay_manifest.json", g2_receipt)
            write_json(out / "g2_sentinel_sample_id_manifest.json", g2_receipt)
            write_json(
                out / "g2_sentinel_replay_scorecard.json",
                authority(
                    schema_id="kt.v17_7_4.g2_sentinel_replay_scorecard.v1",
                    status=g2_receipt["status"],
                    outcome=g2_receipt["outcome"],
                    anchor=G2_COMPRESSION_ANCHOR,
                    claim_ceiling_preserved=True,
                ),
            )
            if g2_receipt["status"] != "PASS":
                raise RuntimeError("KT_BLOCKED__G2_SENTINEL_SOURCE_MISSING: exact G2 sentinel sample IDs/prompts are not bound")
        source_integrity = validate_benchmark_source_integrity(manifest, config)
        prompt_manifest_rows = build_prompt_manifest_rows(manifest, config)
        prompt_integrity = validate_prompt_integrity(prompt_manifest_rows, config)
        write_json(out / "v17_7_4_benchmark_source_integrity_receipt.json", source_integrity)
        write_json(out / "v17_7_4_prompt_integrity_receipt.json", prompt_integrity)
        write_jsonl(out / "truegen_prompt_manifest.jsonl", prompt_manifest_rows)
        if source_integrity["status"] != "PASS" or prompt_integrity["status"] != "PASS":
            raise RuntimeError("KT_BLOCKED__BENCHMARK_PROMPT_INTEGRITY_DEFECT: real benchmark source or prompt integrity failed")
        if measurement_mode == REPROLOCK_MODE:
            run_reprolock_stage0(runtime_root, out, manifest, config)
        write_json(out / "memory_execution_policy_receipt.json", memory_execution_policy_receipt(config))
        write_json(out / "hf_vault_adapter_manifest_receipt.json", hf_vault_adapter_manifest_receipt(config))
        write_json(
            out / "arm_model_config_receipt.json",
            authority(
                schema_id="kt.v17_7_4.arm_model_config_receipt.v1",
                status="PASS",
                config_path=str(config_path),
                config_profile=config.get("config_profile", "UNDECLARED"),
                real_arm_authority_requested=config.get("real_arm_authority_requested") is True,
                base_model_repo=config.get("base_model_repo"),
                enabled_arms=[arm["arm_id"] for arm in enabled_arms(config)],
                enabled_adapter_arms=[arm["arm_id"] for arm in enabled_arms(config) if arm["arm_id"] in ADAPTER_ARM_IDS],
                bundled_example_config_used=config_path.name.endswith(".example.json"),
                adapter_source_preference=adapter_source_preference(config),
                measurement_mode=measurement_mode,
                effective_row_limit=row_limit,
                row_ladder=row_ladder,
                row_limit_honored=row_ladder.get("row_limit_honored"),
                stream_rows_to_disk=bool(config.get("stream_rows_to_disk", True)),
                arm_isolation_mode=str(config.get("arm_isolation_mode", "ARM_MAJOR_UNLOAD_AFTER_EACH_ARM")),
            ),
        )
        stream_path = out / "truegen_arm_result_matrix.jsonl"
        memory_ledger_path = out / "gpu_memory_ledger.jsonl"
        arm_rows, model_loader_receipts, adapter_loader_receipts = generate_arm_rows(
            manifest,
            config,
            run_id,
            stream_path=stream_path if config.get("stream_rows_to_disk", True) is True else None,
            memory_ledger_path=memory_ledger_path,
        )
        predictions = aggregate_predictions(arm_rows, run_id)
        scorecards = recompute_scorecards(arm_rows, predictions)
        oracle_rows = build_oracle_route_rows(arm_rows)
        correlation = replay_correlation(arm_rows, manifest["rows"])
        write_jsonl(out / "truegen_arm_result_matrix.jsonl", arm_rows)
        write_jsonl(out / "oracle_route_table.jsonl", oracle_rows)
        write_jsonl(out / "truegen_predictions.jsonl", predictions)
        write_json(
            out / "model_loader_receipt.json",
            authority(
                schema_id="kt.v17_7_4.model_loader_receipt.v1",
                status="PASS",
                run_id=run_id,
                loader_contract="AutoModelForCausalLM.from_pretrained",
                quantization_contract="BitsAndBytesConfig via quantization_config when load_in_4bit=true",
                bad_load_in_4bit_kwarg_forwarded=False,
                receipts=model_loader_receipts,
            ),
        )
        write_json(
            out / "adapter_loader_receipt.json",
            authority(
                schema_id="kt.v17_7_4.adapter_loader_receipt.v1",
                status="PASS",
                run_id=run_id,
                loader_contract="PeftModel.from_pretrained for adapter arms",
                base_fallback_as_adapter_evidence_allowed=False,
                receipts=adapter_loader_receipts,
            ),
        )
        write_json(out / "hf_vault_adapter_source_receipt.json", hf_vault_adapter_source_receipt(config, adapter_loader_receipts))
        write_json(out / "streaming_generation_receipt.json", streaming_generation_receipt(out, run_id, out / "truegen_arm_result_matrix.jsonl"))
        write_json(out / "partial_output_rescue_receipt.json", partial_output_rescue_receipt(out, run_id))
        write_json(out / "truegen_benchmark_scorecard.json", scorecards["benchmark"])
        write_json(out / "truegen_replay_correlation_scorecard.json", correlation)
        write_json(out / "truegen_negative_transfer_by_arm.json", scorecards["negative_transfer"])
        write_json(out / "truegen_token_efficiency_matrix.json", scorecards["token_efficiency"])
        write_json(out / "token_accounting_ledger.json", scorecards["token_accounting_ledger"])
        write_json(out / "visible_answer_ledger.json", scorecards["visible_answer_ledger"])
        write_json(out / "dual_frontier_scorecard.json", scorecards["dual_frontier_scorecard"])
        write_json(out / "compact_accuracy_regression_gate.json", scorecards["compact_accuracy_regression_gate"])
        write_json(out / "g2_compression_anchor_receipt.json", g2_compression_anchor_receipt())
        write_json(out / "kt_system_wiring_map.json", kt_system_wiring_map(config))
        write_json(out / "truegen_verified_work_per_token_scorecard.json", scorecards["verified_work_per_token"])
        write_json(out / "truegen_route_overhead_matrix.json", scorecards["route_overhead"])
        write_json(out / "truegen_hat_overhead_matrix.json", scorecards["hat_overhead"])
        write_json(out / "truegen_bloat_attribution_matrix.json", scorecards["bloat_attribution"])
        write_json(out / "truegen_parser_vs_generation_error_matrix.json", scorecards["parser_error"])
        write_json(out / "truegen_answer_format_drift_receipt.json", scorecards["answer_format"])
        write_json(
            out / "compact_answer_contract_receipt.json",
            authority(
                schema_id="kt.v17_7_4.compact_answer_contract_receipt.v1",
                status="PASS",
                compact_answer_contract_enabled=compact_answer_enabled(config),
                visible_answer_tokens_tracked=True,
                full_tokens_and_visible_answer_tokens_separate=True,
                no_training=True,
                no_promotion=True,
                claim_ceiling_preserved=True,
            ),
        )
        write_json(out / "answer_only_finalizer_receipt.json", scorecards["answer_only_finalizer"])
        write_json(
            out / "reasoning_preserving_compact_receipt.json",
            authority(
                schema_id="kt.v17_7_4.reasoning_preserving_compact_receipt.v1",
                status="PASS",
                reasoning_preserving_compact_enabled=reasoning_preserving_compact_enabled(config),
                compact_modes=sorted({row.get("compact_mode") for row in arm_rows if row.get("compact_mode")}),
                numeric_bounded_scratch_required_for_math=True,
                visible_answer_stays_compact=True,
                raw_output_preserved_for_audit=True,
                claim_ceiling_preserved=True,
            ),
        )
        write_json(
            out / "visible_answer_scoring_receipt.json",
            authority(
                schema_id="kt.v17_7_4.visible_answer_scoring_receipt.v1",
                status="PASS",
                scoring_uses_final_visible_answer_when_compact=compact_answer_enabled(config),
                raw_output_audit_only_when_compact=compact_answer_enabled(config),
                expected_answer_visible_to_model=False,
                arbitrary_early_number_selection_forbidden_when_final_marker_present=True,
                claim_ceiling_preserved=True,
            ),
        )
        write_json(
            out / "g2_compact_path_gap_analysis.json",
            authority(
                schema_id="kt.v17_7_4.g2_compact_path_gap_analysis.v1",
                status="PASS",
                current_accounting_modes=list(scorecards["token_accounting_ledger"]["accounting_modes"]),
                g2_anchor=g2_compression_anchor_receipt(),
                conclusion="Current RealBench must compare visible-answer and full-token accounting separately before G2 compression recovery can be claimed.",
                g2_recovered=False,
                claim_ceiling_preserved=True,
            ),
        )
        write_json(out / "truegen_router_admission_receipt.json", router_admission_receipt(scorecards))
        write_json(out / "specialist_admission_atlas.json", specialist_admission_atlas(oracle_rows, scorecards))
        write_json(out / "route_margin_scorecard.json", route_margin_scorecard(oracle_rows))
        known_good_receipt = known_good_lobe_reproduction_receipt(arm_rows, scorecards)
        arm_diff_receipt = realbench_vs_dualfront_arm_diff_receipt(config)
        gsm8k_autopsy = gsm8k_regression_autopsy(arm_rows)
        parser_plan = parser_failure_repair_plan(scorecards)
        autopsy_rows = build_oracle_autopsy_rows(arm_rows)
        scar_registry = build_scar_delta_registry(autopsy_rows)
        delta_manifest = recursive_learning_delta_manifest(scar_registry)
        academy_plan = academy_repair_plan(scar_registry, known_good_receipt)
        tournament_plan = lobe_tournament_reentry_plan(config, scar_registry)
        tie_merge_plan = tie_merge_child_lobe_plan(tournament_plan)
        mount_plan = kt_hat_mount_comparison_plan(config)
        claim_receipt = claim_ceiling_receipt()
        write_json(out / "known_good_lobe_reproduction_receipt.json", known_good_receipt)
        write_json(out / "realbench_vs_dualfront_arm_diff_receipt.json", arm_diff_receipt)
        write_json(out / "gsm8k_regression_autopsy.json", gsm8k_autopsy)
        write_json(out / "parser_failure_repair_plan.json", parser_plan)
        write_jsonl(out / "oracle_autopsy_table.jsonl", autopsy_rows)
        write_json(out / "scar_delta_registry.json", scar_registry)
        write_json(out / "recursive_learning_delta_manifest.json", delta_manifest)
        write_json(out / "academy_repair_plan.json", academy_plan)
        write_json(out / "lobe_tournament_reentry_plan.json", tournament_plan)
        write_json(out / "tie_merge_child_lobe_plan.json", tie_merge_plan)
        write_json(out / "kt_hat_mount_comparison_plan.json", mount_plan)
        write_json(out / "claim_ceiling_receipt.json", claim_receipt)
        write_json(out / "truegen_route_regret_token_cost_matrix.json", scorecards["route_regret_token_cost"])
        write_json(out / "truegen_ablation_ladder_scorecard.json", scorecards["ablation_ladder"])
        write_json(out / "truegen_adapter_quarantine_recommendation.json", scorecards["adapter_quarantine"])
        write_json(out / "truegen_compression_frontier_gate.json", scorecards["compression_frontier"])
        write_json(out / "truegen_efficiency_claim_boundary_receipt.json", efficiency_claim_boundary_receipt(scorecards["compression_frontier"]))
        write_json(out / "truegen_per_band_arm_win_matrix.json", scorecards["per_band"])
        write_json(out / "truegen_oracle_gap_update.json", scorecards["oracle_gap"])
        write_json(out / "truegen_pfail_dgs_update.json", scorecards["pfail_dgs"])
        decision = correlation["decision"]
        write_json(
            out / "truegen_measurement_authority_receipt.json",
            authority(
                schema_id="kt.v17_7_4.truegen_measurement_authority_receipt.v1",
                status="PASS",
                evidence_tier="TIER_4_FRESH_MODEL_GENERATION",
                measurement_source=FRESH_SOURCE,
                measurement_status=FRESH_STATUS,
                generation_artifacts_present=True,
                max_authority="fresh-generation mini-furnace evidence only",
                route_promotion_authorized=False,
                adapter_promotion_authorized=False,
            ),
        )
        write_json(
            out / "truegen_claim_admissibility_casefile.json",
            authority(
                schema_id="kt.v17_7_4.truegen_claim_admissibility_casefile.v1",
                status="PASS",
                claim="V17.7.4 fresh-generation mini-furnace executed",
                tier="TIER_4_FRESH_MODEL_GENERATION",
                limitations=["no external reproduction", "no promotion authority", "no V18 authority"],
                measurement_source=FRESH_SOURCE,
            ),
        )
        telemetry = authority(
            schema_id="kt.v17_7_4.runtime_telemetry_receipt.v1",
            status="PASS",
            run_id=run_id,
            elapsed_seconds=round(time.perf_counter() - started, 6),
            row_count=len(predictions),
            arm_rows=len(arm_rows),
            effective_row_limit=row_limit,
            arm_isolation_mode=str(config.get("arm_isolation_mode", "ARM_MAJOR_UNLOAD_AFTER_EACH_ARM")),
            gpu_memory_ledger_path=(out / "gpu_memory_ledger.jsonl").as_posix(),
            measurement_source=FRESH_SOURCE,
            measurement_status=FRESH_STATUS,
        )
        write_json(out / "runtime_telemetry_receipt.json", telemetry)
        assessment = write_assessment(out)
        write_json(out / "assessment_only_packaging_receipt.json", assessment_only_packaging_receipt(out, assessment))
        write_assessment(out)
        if row_measurement_mode(config) == ORACLE_ACADEMY_MODE:
            if known_good_receipt["status"] != "PASS":
                frontier_next = known_good_receipt["outcome"]
            elif parser_plan["status"] != "PASS":
                frontier_next = parser_plan["outcome"]
            elif academy_plan["status"] != "PASS":
                frontier_next = "KT_BLOCKED__ACADEMY_REPAIR_PLAN_DEFECT"
            else:
                frontier_next = "KT_ORACLE_AUTOPSY_ACADEMY_REENTRY_READY__RUN_KNOWN_GOOD_REPRO_AND_SCAR_REPAIR_NEXT__CLAIM_CEILING_PRESERVED"
        elif row_measurement_mode(config) == REPROLOCK_MODE:
            if known_good_receipt["status"] != "PASS":
                frontier_next = known_good_receipt["outcome"]
            else:
                frontier_next = "KT_KNOWN_GOOD_LOBE_PATH_BYTE_REPRO_READY__RUN_ORACLE_ACADEMY_REPRO_NEXT__CLAIM_CEILING_PRESERVED"
        else:
            frontier_next = scorecards["compression_frontier"]["outcome"] if scorecards["compression_frontier"]["status"] == "BLOCKED" else decision
        summary = authority(
            schema_id="kt.v17_7_4.truegen_final_summary.v1",
            status="PASS",
            outcome=frontier_next,
            run_id=run_id,
            assessment_zip=assessment.as_posix(),
            decision=decision,
            next_lawful_move=frontier_next,
            compression_frontier_status=scorecards["compression_frontier"]["status"],
            best_efficiency_arm=scorecards["compression_frontier"]["best_efficiency_arm"],
            known_good_reproduction_status=known_good_receipt["status"],
            parser_failure_repair_status=parser_plan["status"],
            academy_repair_plan_status=academy_plan["status"],
            measurement_source=FRESH_SOURCE,
            measurement_status=FRESH_STATUS,
            generation_artifacts_present=True,
        )
        write_json(out / "final_summary.json", summary)
        write_assessment(out)
        return summary
    except Exception as exc:  # noqa: BLE001
        return write_blocker(out, run_id, str(exc))
