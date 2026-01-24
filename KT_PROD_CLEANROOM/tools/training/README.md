# Policy C Head Trainer (Cleanroom)

This package provides a tiny, deterministic head-only trainer that learns from
Policy C receipt-style datasets. It does not load or fine-tune large LLMs.

Usage:
```
python -m tools.training.train_policy_c_head \
  --dataset KT_PROD_CLEANROOM/exports/policy_c/datasets/kt_policy_c_dataset_v1.jsonl \
  --output-dir KT_PROD_CLEANROOM/policy_c/heads/run_001 \
  --device cpu
```

Outputs:
- `policy_c_head.pt`
- `train_manifest.json` (dataset hash + artifact hash)
