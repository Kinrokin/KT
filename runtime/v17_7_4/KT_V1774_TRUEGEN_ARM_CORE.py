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

ADAPTER_ARM_IDS = {
    "route_regret_policy_adapter_global",
    "formal_math_repair_adapter_global",
    "math_act_adapter_global",
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

ABLATION_LADDER = {
    "base_raw": "A0_base_raw",
    "base_kt_hat_compact": "A1_base_kt_hat_compact",
    "formal_math_repair_adapter_global": "A2_best_static_adapter",
    "routed_no_hat": "A3_routed_no_hat",
    "route_regret_policy_adapter_global": "A4_routed_hat_compact",
    "routed_hat_full": "A5_routed_hat_full",
    "math_act_adapter_global": "A6_routed_hat_repair",
    "routed_tribunal": "A7_routed_tribunal",
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


def count_tokens(text: str) -> int:
    return len(re.findall(r"\S+", text))


def safe_ratio(numerator: float, denominator: float) -> float:
    return round(float(numerator) / max(float(denominator), 1.0), 6)


def exact_expected_match(value: str, row: dict[str, Any]) -> bool:
    expected = str(row.get("expected_label_or_oracle_label", ""))
    return bool(expected) and normalize_answer(value) == normalize_answer(expected)


def output_contains_expected(value: str, row: dict[str, Any]) -> bool:
    expected = str(row.get("expected_label_or_oracle_label", ""))
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
            if arm_id in ADAPTER_ARM_IDS:
                adapter_ref = arm.get("adapter_path") or arm.get("adapter_hf_repo")
                if not adapter_ref:
                    defects.append(f"arms[{index}].real_arm_missing_adapter_source:{arm_id}")
                if config.get("hf_vault_adapter_required") is True and not arm.get("adapter_hf_repo"):
                    defects.append(f"arms[{index}].hf_vault_adapter_required_missing_repo:{arm_id}")
                if arm.get("adapter_binding_status") != "REAL_ADAPTER_SOURCE_BOUND":
                    defects.append(f"arms[{index}].real_arm_adapter_binding_not_bound:{arm_id}")
            if arm_id == "base_kt_hat_compact" and arm.get("arm_kind") not in {"prompt_overlay", "adapter"}:
                defects.append("base_kt_hat_compact_requires_prompt_overlay_or_adapter_kind")
    missing_arms = [arm for arm in ARM_IDS if arm not in seen]
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


def materialize_prompt(row: dict[str, Any], arm: dict[str, Any]) -> str:
    template = arm.get("prompt_template_id", "raw")
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
    return "\n".join(
        [
            prefix,
            f"Sample: {row['sample_id']}",
            f"Dataset: {row['dataset']}",
            f"Task family: {row['task_family']}",
            f"Boundary: {row['route_boundary_class']}",
            f"Question: {row['prompt']}",
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
    expected = str(row.get("expected_label_or_oracle_label", ""))
    if method == "nonempty_generation":
        correct = bool(text.strip())
    elif method == "exact_normalized":
        correct = normalize_answer(parsed_answer) == normalize_answer(expected)
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


def resolve_effective_row_limit(config: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    if os.environ.get("KT_TRUEGEN_ROW_LIMIT"):
        row_limit = int(os.environ["KT_TRUEGEN_ROW_LIMIT"])
        source = "KT_TRUEGEN_ROW_LIMIT"
    else:
        ladder = config.get("row_ladder") or DEFAULT_ROW_LADDER
        if not isinstance(ladder, list) or not ladder:
            ladder = DEFAULT_ROW_LADDER
        if os.environ.get("KT_TRUEGEN_LADDER_STAGE"):
            row_limit = int(os.environ["KT_TRUEGEN_LADDER_STAGE"])
            source = "KT_TRUEGEN_LADDER_STAGE"
        elif config.get("default_row_ladder_stage") is not None:
            row_limit = int(config["default_row_ladder_stage"])
            source = "config.default_row_ladder_stage"
        else:
            row_limit = int(config.get("row_limit", 100))
            source = "config.row_limit"
        allowed = sorted({int(value) for value in ladder})
        if source != "config.row_limit" and allowed:
            row_limit = min((value for value in allowed if value >= row_limit), default=max(allowed))
    max_rows = int(config.get("row_limit", row_limit))
    row_limit = max(1, min(row_limit, max_rows))
    receipt = authority(
        schema_id="kt.v17_7_4.row_ladder_receipt.v1",
        status="PASS",
        row_limit=row_limit,
        row_limit_source=source,
        row_ladder=config.get("row_ladder") or DEFAULT_ROW_LADDER,
        max_configured_rows=max_rows,
        ladder_policy="3_TO_10_TO_25_TO_50_TO_100_BY_ENV_OR_CONFIG_DEFAULT",
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
    score, correct = score_output(output_text, parsed, row, arm.get("scoring_method", "contains_expected_label"))
    tokens_in = count_tokens(prompt)
    tokens_out = count_tokens(output_text)
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
        prompt_hash=sha256_text(prompt),
        output_text=output_text[:2000],
        output_hash=sha256_text(output_text),
        parsed_answer=parsed,
        score=score,
        correct=correct,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        total_tokens=total_tokens,
        tokens_per_correct=safe_ratio(total_tokens, 1 if correct else 0),
        verified_work_per_token=safe_ratio(1 if correct else 0, total_tokens),
        latency_per_correct=safe_ratio(latency_ms, 1 if correct else 0),
        answer_tokens=answer_tokens,
        router_tokens=prompt_components["router_tokens"],
        hat_tokens=prompt_components["hat_tokens"],
        tribunal_tokens=prompt_components["tribunal_tokens"],
        repair_tokens=prompt_components["repair_tokens"],
        route_overhead_tokens=route_overhead_tokens,
        hat_overhead_ratio=row_metrics["hat_overhead_ratio"],
        parser_format_failure=parser_format_failure,
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
    base_correct = correct_counts.get("base_raw", 0)
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
        base = sample_arms.get("base_raw")
        if not base or not base.get("correct"):
            continue
        for arm, row in sample_arms.items():
            if not row.get("correct"):
                negative_transfer[arm] += 1
    token_efficiency = {}
    for arm, rows in by_arm.items():
        tokens = sum(int(row.get("total_tokens", int(row["tokens_in"]) + int(row["tokens_out"]))) for row in rows)
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
        answer_format[arm] = {
            "final_answer_marker_rate": safe_ratio(marker_count, len(rows)),
            "answer_format_drift_rate": safe_ratio(len(rows) - marker_count, len(rows)),
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
    base_eff = token_efficiency.get("base_raw", {})
    best_eff_arm = sorted(arms, key=lambda arm: (-token_efficiency[arm]["verified_work_per_token"], -correct_counts[arm], arm))[0]
    best_eff = token_efficiency[best_eff_arm]
    compression_gain_over_base = safe_ratio(base_eff.get("tokens_per_correct", 0) - best_eff["tokens_per_correct"], base_eff.get("tokens_per_correct", 0))
    compact = token_efficiency.get("base_kt_hat_compact")
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
    return {
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
            oracle_correct_count=oracle_correct,
            fresh_generation_pass=True,
        ),
        "negative_transfer": authority(schema_id="kt.v17_7_4.truegen_negative_transfer_by_arm.v1", status="PASS", measurement_source=FRESH_SOURCE, negative_transfer=negative_transfer),
        "token_efficiency": authority(schema_id="kt.v17_7_4.truegen_token_efficiency_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=token_efficiency),
        "verified_work_per_token": vwpt,
        "route_overhead": authority(schema_id="kt.v17_7_4.truegen_route_overhead_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=route_overhead),
        "hat_overhead": authority(schema_id="kt.v17_7_4.truegen_hat_overhead_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=hat_overhead),
        "bloat_attribution": authority(schema_id="kt.v17_7_4.truegen_bloat_attribution_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=bloat_matrix),
        "parser_error": authority(schema_id="kt.v17_7_4.truegen_parser_vs_generation_error_matrix.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=parser_error),
        "answer_format": authority(schema_id="kt.v17_7_4.truegen_answer_format_drift_receipt.v1", status="PASS", measurement_source=FRESH_SOURCE, matrix=answer_format),
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
    base = matrix.get("base_raw", {})
    decisions = {}
    for arm, payload in sorted(matrix.items()):
        if arm == "base_raw":
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
    payload = authority(
        schema_id="kt.v17_7_4.truegen_blocker_receipt.v1",
        status="BLOCKED",
        run_id=run_id,
        outcome="KTG3FULL_V17_7_4_BLOCKED__GENERATION_FAILURE",
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
        manifest = load_row_manifest(row_manifest_path, row_limit=row_limit)
        write_json(out / "row_ladder_receipt.json", row_ladder)
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
                effective_row_limit=row_limit,
                row_ladder=row_ladder,
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
        correlation = replay_correlation(arm_rows, manifest["rows"])
        write_jsonl(out / "truegen_arm_result_matrix.jsonl", arm_rows)
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
        write_json(out / "g2_compression_anchor_receipt.json", g2_compression_anchor_receipt())
        write_json(out / "kt_system_wiring_map.json", kt_system_wiring_map(config))
        write_json(out / "truegen_verified_work_per_token_scorecard.json", scorecards["verified_work_per_token"])
        write_json(out / "truegen_route_overhead_matrix.json", scorecards["route_overhead"])
        write_json(out / "truegen_hat_overhead_matrix.json", scorecards["hat_overhead"])
        write_json(out / "truegen_bloat_attribution_matrix.json", scorecards["bloat_attribution"])
        write_json(out / "truegen_parser_vs_generation_error_matrix.json", scorecards["parser_error"])
        write_json(out / "truegen_answer_format_drift_receipt.json", scorecards["answer_format"])
        write_json(out / "truegen_router_admission_receipt.json", router_admission_receipt(scorecards))
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
        frontier_next = scorecards["compression_frontier"]["outcome"] if scorecards["compression_frontier"]["status"] == "BLOCKED" else decision
        summary = authority(
            schema_id="kt.v17_7_4.truegen_final_summary.v1",
            status="PASS",
            outcome=scorecards["compression_frontier"]["outcome"],
            run_id=run_id,
            assessment_zip=assessment.as_posix(),
            decision=decision,
            next_lawful_move=frontier_next,
            compression_frontier_status=scorecards["compression_frontier"]["status"],
            best_efficiency_arm=scorecards["compression_frontier"]["best_efficiency_arm"],
            measurement_source=FRESH_SOURCE,
            measurement_status=FRESH_STATUS,
            generation_artifacts_present=True,
        )
        write_json(out / "final_summary.json", summary)
        write_assessment(out)
        return summary
    except Exception as exc:  # noqa: BLE001
        return write_blocker(out, run_id, str(exc))
