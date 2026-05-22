from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


PROGRAM_ID = "KT_7B_Q_LORA_SMOKE_REPAIR_SUPERLANE_V1"
PARTIAL_OUTCOME = (
    "KT_7B_Q_LORA_SMOKE_PARTIAL__7B_LOAD_AND_ADAPTER_TRAINING_PROVEN__"
    "OOM_AND_ROUTER_CLASS_SUPPORT_BLOCK_CLEAN_SMOKE"
)
NEXT_LAWFUL_MOVE = "RUN_7B_Q_LORA_SMOKE_REPAIR"
CLEAN_TARGET_OUTCOME = "KT_7B_Q_LORA_SMOKE_CLEAN_VALIDATED__TRANCHE_NEXT"

BLOCKED_CLAIMS = {
    "external_audit_accepted": False,
    "external_audit_complete": False,
    "commercial_claim_authorized": False,
    "seven_b_amplification_proven": False,
    "category_leadership_claim_authorized": False,
    "beyond_sota_claim_authorized": False,
    "full_adaptive_orchestration_production_ready": False,
    "truth_engine_law_changed": False,
    "trust_zone_law_changed": False,
    "tranche_authorized": False,
    "heavy_run_authorized": False,
}

INPUTS = {
    "registry": "registry/artifact_authority_registry.json",
    "pre7b_next_move": "KT_PROD_CLEANROOM/reports/kt_7b_q_lora_smoke_next_lawful_move.json",
    "final_pre7b_scorecard": "KT_PROD_CLEANROOM/reports/kt_final_pre7b_scorecard.json",
    "claim_ceiling": "KT_PROD_CLEANROOM/reports/kt_final_claim_boundary_before_external_attestation.json",
    "gpu_import_contract": "KT_PROD_CLEANROOM/reports/kt_gpu_artifact_import_hash_receipt_contract.json",
}

OUTPUTS = {
    "partial_receipt": "KT_PROD_CLEANROOM/reports/kt_7b_q_lora_smoke_partial_receipt.json",
    "repair_packet": "KT_PROD_CLEANROOM/reports/kt_7b_q_lora_smoke_repair_packet.json",
    "repair_next_move": "KT_PROD_CLEANROOM/reports/kt_7b_q_lora_smoke_repair_next_lawful_move.json",
    "repair_runbook": "training/kaggle_7b_q_lora_smoke_repair_runbook.md",
    "registry_delta": "registry/artifact_authority_registry_7b_repair_delta_receipt.json",
}


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:  # noqa: BLE001
        return "UNKNOWN_NON_GIT_TEST_ROOT"


def _git_origin_main(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "origin/main"], cwd=root, text=True).strip()
    except Exception:  # noqa: BLE001
        return "UNKNOWN_ORIGIN_MAIN"


def _remote_contains_head(root: Path) -> bool:
    try:
        output = subprocess.check_output(["git", "branch", "-r", "--contains", "HEAD"], cwd=root, text=True)
        return bool(output.strip())
    except Exception:  # noqa: BLE001
        return False


def _hash_or_none(root: Path, raw: str) -> str | None:
    path = root / raw
    return file_sha256(path) if path.is_file() else None


def _assert_preconditions(root: Path) -> None:
    for raw in INPUTS.values():
        if not (root / raw).is_file():
            raise RuntimeError(f"Missing required input for 7B smoke repair: {raw}")
    next_move = load_json(root / INPUTS["pre7b_next_move"])
    if next_move.get("next_lawful_move") != "RUN_7B_Q_LORA_SMOKE":
        raise RuntimeError("Pre-7B gate did not authorize RUN_7B_Q_LORA_SMOKE before repair assessment")
    for raw in (INPUTS["claim_ceiling"], INPUTS["final_pre7b_scorecard"], INPUTS["pre7b_next_move"]):
        obj = load_json(root / raw)
        for key, expected in BLOCKED_CLAIMS.items():
            if key in obj and obj[key] is not expected:
                raise RuntimeError(f"Claim ceiling drift in {raw}: expected {key}={expected!r}")


def _partial_receipt(root: Path, current_head: str, origin_main: str, remote_reachable: bool) -> dict[str, Any]:
    scorecard = load_json(root / INPUTS["final_pre7b_scorecard"])
    return {
        "schema_id": "kt.7b_q_lora.smoke_partial_receipt.v1",
        "artifact_id": "KT_7B_Q_LORA_SMOKE_PARTIAL_RECEIPT",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "selected_outcome": PARTIAL_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "requested_head": current_head,
        "actual_subject_head": scorecard.get("current_head"),
        "origin_main_head": origin_main,
        "requested_head_remote_reachable": remote_reachable,
        "current_head_mismatch_detected": scorecard.get("current_head") != current_head,
        "valid_as_runtime_smoke_attempt": True,
        "valid_as_clean_current_head_proof": False,
        "run_mode": "RUN_7B_Q_LORA_SMOKE",
        "base_model": "Qwen/Qwen2.5-7B-Instruct",
        "gpu": "Tesla T4",
        "dataset": "repo-derived current-head allowed surfaces, class-balanced",
        "dataset_class_balance_pass": True,
        "import_ready": True,
        "trained_adapters": ["cohort_pass1_all_selected_lobes", "lobe_claim_boundary"],
        "router_no_regression_pass": True,
        "router_accuracy": 0.7626,
        "static_baseline_accuracy": 0.0959,
        "macro_f1": 0.7252,
        "training_errors_count": 2,
        "negative_result_count": 2,
        "clean_smoke_pass": False,
        "blockers": [
            {
                "blocker_id": "cuda_oom_lobe_router_controller",
                "class": "CUDA_OOM",
                "scope": "lobe_router_controller",
                "blocks_clean_smoke": True,
            },
            {
                "blocker_id": "cuda_oom_cohort_pass2_delta",
                "class": "CUDA_OOM",
                "scope": "cohort_pass2_delta",
                "blocks_clean_smoke": True,
            },
            {
                "blocker_id": "router_eval_class_support_below_floor",
                "class": "ROUTER_CLASS_SUPPORT",
                "min_class_support": 3,
                "required_min_class_support": 4,
                "router_eval_class_balance_pass": False,
                "blocks_clean_smoke": True,
            },
        ],
        **BLOCKED_CLAIMS,
    }


def _repair_packet(root: Path, current_head: str) -> dict[str, Any]:
    return {
        "schema_id": "kt.7b_q_lora.smoke_repair_packet.v1",
        "artifact_id": "KT_7B_Q_LORA_SMOKE_REPAIR_PACKET",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "prior_partial_outcome": PARTIAL_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "clean_target_outcome_after_success": CLEAN_TARGET_OUTCOME,
        "repair_required_before_tranche": True,
        "tranche_authorized": False,
        "heavy_run_authorized": False,
        "head_binding_policy": {
            "preferred": "push_or_merge_requested_head_to_reachable_GitHub_ref_before_Kaggle_run",
            "fallback": "if binding to public main, label result as public-main smoke and not requested-head proof",
            "fail_clean_current_head_proof_if_requested_head_unreachable": True,
        },
        "bitsandbytes_policy": {
            "install_before_model_load": True,
            "import_before_model_load": True,
            "fail_closed_if_unavailable": True,
            "fail_closed_if_4bit_modules_not_detected": True,
            "do_not_silently_fallback_to_full_precision_for_clean_qlora_smoke": True,
        },
        "memory_hygiene_policy": {
            "clear_gpu_between_adapter_trainings": True,
            "delete_model_optimizer_and_dataloader_refs_between_adapters": True,
            "run_gc_collect": True,
            "run_torch_cuda_empty_cache": True,
            "run_torch_cuda_ipc_collect_if_available": True,
            "log_allocated_reserved_and_peak_memory": True,
        },
        "repair_run_settings": {
            "KT_RUN_MODE": NEXT_LAWFUL_MOVE,
            "KT_MAX_STEPS_COHORT": 1,
            "KT_MAX_STEPS_PER_LOBE": 1,
            "KT_MAX_STEPS_COHORT2": 1,
            "KT_MAX_SEQ_LEN": 96,
            "KT_BATCH_SIZE": 1,
            "KT_GRAD_ACCUM": 32,
            "KT_MIN_ROWS_PER_LOBE": 24,
            "KT_MIN_VAL_PER_LOBE": 4,
            "KT_ROUTER_EVAL_MIN_PER_CLASS": 4,
            "PYTORCH_CUDA_ALLOC_CONF": "expandable_segments:True,max_split_size_mb:64",
        },
        "clean_pass_required_conditions": {
            "training_errors_count": 0,
            "negative_result_count": 0,
            "class_balance_pass": True,
            "router_eval_class_balance_pass": True,
            "router_no_regression_pass": True,
            "import_ready": True,
            "qlora_effective": True,
        },
        "source_bindings": {
            "partial_receipt": OUTPUTS["partial_receipt"],
            "partial_receipt_sha256": _hash_or_none(root, OUTPUTS["partial_receipt"]),
            "gpu_import_contract": INPUTS["gpu_import_contract"],
            "gpu_import_contract_sha256": _hash_or_none(root, INPUTS["gpu_import_contract"]),
        },
        **BLOCKED_CLAIMS,
    }


def _next_move(current_head: str) -> dict[str, Any]:
    return {
        "schema_id": "kt.7b_q_lora.smoke_repair_next_lawful_move.v1",
        "artifact_id": "KT_7B_Q_LORA_SMOKE_REPAIR_NEXT_LAWFUL_MOVE",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "selected_outcome": PARTIAL_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "clean_target_outcome_after_success": CLEAN_TARGET_OUTCOME,
        "seven_b_clean_smoke_passed": False,
        "repair_smoke_authorized_next": True,
        **BLOCKED_CLAIMS,
    }


def _write_text_if_changed(path: Path, text: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and path.read_text(encoding="utf-8-sig") == text:
        return False
    path.write_text(text, encoding="utf-8", newline="\n")
    return True


def _runbook() -> str:
    return """# KT 7B QLoRA Smoke Repair Runbook

Authority: repair smoke only. This runbook does not authorize TRANCHE, HEAVY, 7B amplification, category leadership, beyond-SOTA, commercial claims, or external audit acceptance.

## Required Kaggle settings

```python
import os

os.environ["KT_RUN_MODE"] = "RUN_7B_Q_LORA_SMOKE_REPAIR"
os.environ["KT_MAX_STEPS_COHORT"] = "1"
os.environ["KT_MAX_STEPS_PER_LOBE"] = "1"
os.environ["KT_MAX_STEPS_COHORT2"] = "1"
os.environ["KT_MAX_SEQ_LEN"] = "96"
os.environ["KT_BATCH_SIZE"] = "1"
os.environ["KT_GRAD_ACCUM"] = "32"
os.environ["KT_MIN_ROWS_PER_LOBE"] = "24"
os.environ["KT_MIN_VAL_PER_LOBE"] = "4"
os.environ["KT_ROUTER_EVAL_MIN_PER_CLASS"] = "4"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True,max_split_size_mb:64"
```

## Bitsandbytes must be real

```python
import importlib
import subprocess
import sys

subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "bitsandbytes>=0.43.1", "peft", "accelerate", "transformers"])
bnb = importlib.import_module("bitsandbytes")
assert bnb is not None, "bitsandbytes import failed"
```

After model load, fail closed unless 4-bit modules are present. Do not silently fall back to full precision and call it QLoRA.

## GPU cleanup between adapters

```python
import gc
import torch

def kt_clear_gpu(*objects):
    for obj in objects:
        del obj
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
        if hasattr(torch.cuda, "ipc_collect"):
            torch.cuda.ipc_collect()
        torch.cuda.reset_peak_memory_stats()
```

Call `kt_clear_gpu(...)` after every adapter training segment and before loading the next adapter/model stage.

## Clean repair pass criteria

```text
training_errors_count = 0
negative_result_count = 0
class_balance_pass = true
router_eval_class_balance_pass = true
router_no_regression_pass = true
import_ready = true
qlora_effective = true
```

If the requested git head is not reachable from Kaggle, label the result as public-main smoke, not current-head proof.
"""


def _update_registry(root: Path, current_head: str) -> tuple[dict[str, Any], dict[str, Any]]:
    registry_path = root / INPUTS["registry"]
    registry = load_json(registry_path)
    artifacts = list(registry.get("artifacts", []))
    for artifact in artifacts:
        if artifact.get("artifact_id") == "NEXT_LAWFUL_MOVE":
            artifact["controls_execution"] = False
            artifact["authority_state"] = "SUPERSEDED"
            artifact["superseded_by"] = OUTPUTS["repair_next_move"]
            artifact["notes"] = "Superseded by the partial 7B smoke repair next-move receipt after first 7B contact returned OOM and router class-support blockers."
    artifacts.extend(
        [
            {
                "artifact_id": "KT_7B_Q_LORA_SMOKE_PARTIAL_RECEIPT",
                "path": OUTPUTS["partial_receipt"],
                "role": "seven_b_smoke_partial_result",
                "authority_state": "LIVE_CURRENT_HEAD_VALIDATED",
                "validation_status": "PASS",
                "controls_execution": True,
                "claim_authority": "INTERNAL_SHADOW",
                "sha256": _hash_or_none(root, OUTPUTS["partial_receipt"]),
                "supersedes": [],
                "superseded_by": None,
                "notes": "Partial runtime evidence only; clean smoke and TRANCHE remain blocked.",
            },
            {
                "artifact_id": "KT_7B_Q_LORA_SMOKE_REPAIR_PACKET",
                "path": OUTPUTS["repair_packet"],
                "role": "seven_b_smoke_repair_policy",
                "authority_state": "LIVE_CURRENT_HEAD_VALIDATED",
                "validation_status": "PASS",
                "controls_execution": True,
                "claim_authority": "INTERNAL_SHADOW",
                "sha256": _hash_or_none(root, OUTPUTS["repair_packet"]),
                "supersedes": [],
                "superseded_by": None,
                "notes": "T4-safe repair settings, QLoRA enforcement, GPU memory hygiene, class-support floor, and head-binding policy.",
            },
            {
                "artifact_id": "KT_7B_Q_LORA_SMOKE_REPAIR_NEXT_LAWFUL_MOVE",
                "path": OUTPUTS["repair_next_move"],
                "role": "seven_b_smoke_next_move",
                "authority_state": "LIVE_CURRENT_HEAD_VALIDATED",
                "validation_status": "PASS",
                "controls_execution": True,
                "claim_authority": "INTERNAL_SHADOW",
                "sha256": _hash_or_none(root, OUTPUTS["repair_next_move"]),
                "supersedes": [INPUTS["pre7b_next_move"]],
                "superseded_by": None,
                "notes": "Current next lawful move after partial smoke.",
            },
        ]
    )
    registry["current_head"] = current_head
    registry["generated_utc"] = utc_now_iso_z()
    registry["artifacts"] = artifacts

    delta = {
        "schema_id": "kt.artifact_authority_registry_7b_repair_delta_receipt.v1",
        "artifact_id": "KT_ARTIFACT_AUTHORITY_REGISTRY_7B_REPAIR_DELTA_RECEIPT",
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "superseded_artifacts": [INPUTS["pre7b_next_move"]],
        "created_or_updated_artifacts": [
            OUTPUTS["partial_receipt"],
            OUTPUTS["repair_packet"],
            OUTPUTS["repair_next_move"],
            OUTPUTS["repair_runbook"],
            INPUTS["registry"],
        ],
        "duplicate_controlling_artifacts": [],
        "claim_ceiling_unchanged": True,
    }
    return registry, delta


def run(*, output_root: Path | None = None) -> dict[str, Any]:
    root = output_root or repo_root()
    _assert_preconditions(root)
    current_head = _git_head(root)
    origin_main = _git_origin_main(root)
    remote_reachable = _remote_contains_head(root)
    changed: list[str] = []

    partial = _partial_receipt(root, current_head, origin_main, remote_reachable)
    if write_json_stable(root / OUTPUTS["partial_receipt"], partial):
        changed.append(OUTPUTS["partial_receipt"])

    repair = _repair_packet(root, current_head)
    next_move = _next_move(current_head)
    for raw, obj in ((OUTPUTS["repair_packet"], repair), (OUTPUTS["repair_next_move"], next_move)):
        if write_json_stable(root / raw, obj):
            changed.append(raw)
    if _write_text_if_changed(root / OUTPUTS["repair_runbook"], _runbook()):
        changed.append(OUTPUTS["repair_runbook"])

    registry, delta = _update_registry(root, current_head)
    if write_json_stable(root / INPUTS["registry"], registry):
        changed.append(INPUTS["registry"])
    if write_json_stable(root / OUTPUTS["registry_delta"], delta):
        changed.append(OUTPUTS["registry_delta"])

    return {
        "current_head": current_head,
        "outcome": PARTIAL_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "clean_target_outcome_after_success": CLEAN_TARGET_OUTCOME,
        "changed_outputs": changed,
        "claim_ceiling": "unchanged",
        "blockers": partial["blockers"],
    }


def main(argv: Sequence[str] | None = None, *, output_root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bind KT 7B QLoRA smoke partial result and emit repair-next packet.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    summary = run(output_root=output_root)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(PARTIAL_OUTCOME)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
