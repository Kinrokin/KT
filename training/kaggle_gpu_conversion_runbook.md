# KT GPU Conversion Kaggle Runbook

Authority: staging only.

This runbook prepares Kaggle execution for lobe, adapter, and router training. It does not claim trained weights exist, router superiority, external audit acceptance, commercial authorization, category leadership, beyond-SOTA status, 7B proof, or full adaptive production readiness.

## Kaggle defaults

```text
RUN_ID=kt_gpu_conversion_<utc_timestamp>_<short_uuid>
SEED=1337
WORK_DIR=/kaggle/working/kt_gpu_conversion
HF_HOME=/kaggle/working/hf_cache
LOCAL_CACHE=/kaggle/working/kt_gpu_conversion/cache
CHECKPOINT_DIR=/kaggle/working/kt_gpu_conversion/checkpoints
LATEST_RUN=/kaggle/working/kt_gpu_conversion/latest_run.json
```

Local Windows paths must be copied or mounted into Kaggle input datasets before execution. Kaggle cells must use `/kaggle/input` and `/kaggle/working` paths only.

## Required order

1. Copy the validated GPU conversion packet artifacts into the Kaggle notebook input area.
2. Set deterministic seeds and cache directories.
3. Run a tiny smoke lane first.
4. Save checkpoint and receipt outputs every 25 steps or less.
5. Stop early before session timeout and preserve partial receipts.
6. Import outputs only through `KT_GPU_ARTIFACT_IMPORT_HASH_RECEIPT_CONTRACT`.

## Smoke phases

```text
environment_smoke
dataset_provenance_smoke
lora_smoke
qlora_optional_smoke_if_bitsandbytes_available
router_trace_smoke
artifact_import_hash_smoke
```

If `bitsandbytes` or GPU memory checks fail, exclude QLoRA from the first campaign with a receipt and fall back to LoRA. Do not convert that exclusion into a claim failure or a success claim.

## Required Kaggle outputs

```text
dataset_manifest.json
training_config.json
checkpoint_manifest.json
training_run_receipt.json
eval_receipt.json
router_trace.csv
candidate_provenance.json
negative_result_ledger.json
```

Every output must be hashable before import. Partial runs must still emit `training_run_receipt.json`, `checkpoint_manifest.json`, and `negative_result_ledger.json`.

## Target after this packet validates

```text
KT_LOBE_ADAPTER_ROUTER_GPU_CONVERSION_READY__TRAINING_EXECUTION_PENDING__CLAIM_CEILING_PRESERVED
```
