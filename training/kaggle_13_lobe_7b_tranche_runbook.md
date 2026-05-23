# KT 13-Lobe 7B Tranche Kaggle Runbook

Authority: internal/shadow training execution only.

This runbook is the current 13-lobe tranche path. It does not authorize commercial launch, external audit completion, external validation acceptance, 7B amplification, router superiority, multi-lobe superiority, S-tier, beyond-SOTA, category leadership, frontier parity, or production promotion.

## Current Inputs

- Config: `training/kt_13_lobe_7b_tranche_config.json`
- Cognitive lobe registry: `adaptive/cognitive_lobe_registry.json`
- Lobe target matrix: `KT_PROD_CLEANROOM/reports/kt_lobe_target_matrix.json`
- Adapter target matrix: `KT_PROD_CLEANROOM/reports/kt_adapter_target_matrix.json`

## Canonical Training Targets

The Kaggle runner must train only these 13 cognitive lobes:

- `strategic_synthesis_lobe`
- `audit_reasoning_lobe`
- `formal_proof_reasoning_lobe`
- `contradiction_paradox_lobe`
- `temporal_chronology_lobe`
- `cross_domain_patterncraft_lobe`
- `grounded_evidence_lobe`
- `regulated_domain_lobe`
- `commercial_operator_lobe`
- `execution_tool_lobe`
- `context_memory_compression_lobe`
- `learning_delta_lobe`
- `adversarial_red_assault_lobe`

Forbidden gate/court/validator/router/factory/runtime/benchmark labels must not appear as canonical training targets:

`claim_boundary`, `proof_validator`, `truth_engine`, `bio_med_firewall`, `evaluator_integrity`, `primitive_invariance`, `metacognitive_admission`, `runtime_execution_chain`, `delta_to_primitive`, `router_control`, `router_controller`, `adapter_forge`, `lobe_trainer`, `benchmark_evaluator`, `external_attestation`, `commercial_boundary`, `truth_grounding`, `claim_compiler`, `detached_verifier`, `supply_chain_gate`

## Required Head Binding

Before any model load or training step, emit `head_binding_receipt.json` with:

```json
{
  "requested_head": "<repo head requested by operator>",
  "actual_head": "<head reachable inside Kaggle or imported snapshot>",
  "head_match": true,
  "fail_closed_if_mismatch": true
}
```

If `requested_head != actual_head`, stop or label the run as non-current-head assessment. Do not import it as current-head proof.

## Required Outputs

- `head_binding_receipt.json`
- `run_manifest.json`
- `training_receipt.json`
- `eval_receipt.json`
- `negative_result_ledger.json`
- `router_trace.csv`
- `router_trace.json`
- `router_vs_static_scorecard.json`
- `router_vs_best_adapter_scorecard.json`
- `safetensors_hash_manifest.json`
- `kt_hat_adapter_mount_manifest.json`
- `benchmark_tranche_receipt.json`
- `blocker_ledger.json`
- `KT_13_LOBE_ASSESSMENT_REVIEW_SUMMARY.json`
- `assessment_summary.json`
- `cuda_environment_receipt.json`
- `qlora_effectiveness_receipt.json`
- `hf_cache_network_retry_receipt.json`
- `partial_run_resume_receipt.json`

Both `router_trace.csv` and `router_trace.json` are required for this tranche so tabular inspection and structured replay can be checked independently.

## Minimum Execution Rules

1. Load `training/kt_13_lobe_7b_tranche_config.json`.
2. Fail closed if target lobe IDs differ from the config or contain forbidden labels.
3. Set deterministic seeds before dataset construction.
4. Emit CUDA, HF cache/retry, and QLoRA effectiveness receipts before training.
5. Save checkpoints and partial-run receipts after each lobe/adapter segment.
6. Clear GPU memory between lobe/adapter segments.
7. Emit negative results and blocker ledger instead of deleting failed segments.
8. Import artifacts only through the hash/import contract after the run.

## T4-Safe Defaults

```python
import os

os.environ["KT_RUN_MODE"] = "RUN_13_LOBE_7B_TRANCHE"
os.environ["KT_MAX_SEQ_LEN"] = "96"
os.environ["KT_BATCH_SIZE"] = "1"
os.environ["KT_GRAD_ACCUM"] = "32"
os.environ["KT_MIN_ROWS_PER_LOBE"] = "24"
os.environ["KT_MIN_VAL_PER_LOBE"] = "4"
os.environ["KT_ROUTER_EVAL_MIN_PER_CLASS"] = "4"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True,max_split_size_mb:64"
```

## Clean Tranche Readiness Criteria

```text
target_lobe_count = 13
forbidden_target_count = 0
head_match = true
qlora_effective = true
training_errors_count = 0
negative_result_count = 0
router_no_regression_pass = true
class_balance_pass = true
import_ready = true
claim_ceiling_preserved = true
```

If any criterion fails, emit `blocker_ledger.json` and keep the result assessment-only until repaired.
