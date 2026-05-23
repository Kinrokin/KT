# KT 7B QLoRA Smoke Repair Runbook

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
