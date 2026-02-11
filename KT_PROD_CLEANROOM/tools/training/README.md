# KT Training Harnesses

This package contains multiple training utilities for King's Theorem.

## Phase 2 LoRA Training Harness (MRT-1)

**Primary harness: Multi-Round Training orchestrator for policy_c dataset fine-tuning with QLoRA (4-bit quantization + LoRA).**

### Overview

`phase2_train.py` is the canonical Phase 2 training harness for King's Theorem. It orchestrates fine-tuning of base models (e.g., Mistral-7B) on policy_c datasets using QLoRA with fail-closed governance.

### Critical Patches (Universal Compatibility)

This implementation includes **4 essential compatibility patches** required for universal functionality across CPU/GPU environments and multiple dataset formats:

#### Patch #1: Tokenizer `use_fast=False`
**Line**: ~95 (tokenizer initialization)  
**Issue**: Mistral's `tokenizer.json` is incompatible with older `tokenizers` library versions when `use_fast=True`  
**Fix**: Force slow tokenizer mode
```python
tokenizer = AutoTokenizer.from_pretrained(
    req.base_model,
    use_fast=False,  # Force slow tokenizer for compatibility
    trust_remote_code=True
)
```

#### Patch #2: Conditional `model.to(device)` for 4-bit Models
**Issue**: 4-bit quantized models cannot call `.to(device)` after initialization (incompatible with BitsAndBytes)  
**Fix**: Skip device movement when using 4-bit quantization
```python
if not req.load_in_4bit:
    model = model.to(device)
```

#### Patch #3: Variable Scoping `load_in_4bit` in `main()`
**Issue**: Original code used `args.load_in_4bit` directly, but it must be in scope for trainer_cfg construction  
**Fix**: Explicitly convert to bool in main() scope before using in trainer_cfg
```python
load_in_4bit = bool(args.load_in_4bit)
```

#### Patch #4: Dataset Fallback to JSON Serialization
**Issue**: policy_c dataset records are metadata-only (contain refs to pressure_tensor, epoch_summary, etc.) but no inline `text`/`prompt`/`input` fields  
**Fix**: Try common text fields first; fallback to JSON serialization of entire record
```python
for key in ["text", "prompt", "input"]:
    if key in obj and isinstance(obj[key], str) and obj[key].strip():
        yield obj[key]
        break
else:
    # Fallback: serialize the dict to JSON for tokenization
    yield json.dumps(obj, sort_keys=True)
```

### Schema Compatibility

#### Input
- **Format**: JSONL (one record per line)
- **Schema**: `kt.policy_c.dataset_record.v1`
- **Record structure**:
  - Metadata references: `pressure_tensor`, `epoch_summary`, `drift_report`
  - Labels: classification targets for policy_c
  - **No inline text**: Records do NOT contain `text`, `prompt`, or `input` fields
  - Patch #4 handles this via JSON serialization

#### Output
- **Format**: SafeTensors (HF standard)
- **Contents**: LoRA adapter weights (rank=8, trainable parameters only)
- **Metadata**: `training_config.json`, `training_report.json`

### Usage

#### Basic Command
```bash
python KT_PROD_CLEANROOM/tools/training/phase2_train.py \
  --base-model mistralai/Mistral-7B-Instruct-v0.2 \
  --dataset /path/to/policy_c_dataset.jsonl \
  --output-dir /path/to/output
```

#### Configuration Flags
| Flag | Default | Description |
|------|---------|-------------|
| `--base-model` | `mistralai/Mistral-7B-Instruct-v0.2` | HuggingFace model ID |
| `--dataset` | — | Path to policy_c JSONL (required) |
| `--output-dir` | — | Output directory (required) |
| `--load-in-4bit` | `true` | Enable 4-bit quantization |
| `--lora-rank` | `8` | LoRA rank (lower = fewer parameters) |
| `--batch-size` | `4` | Training batch size per GPU |
| `--learning-rate` | `2e-4` | Optimizer learning rate |
| `--num-epochs` | `1` | Training epochs |
| `--max-seq-len` | `2048` | Maximum token sequence length |
| `--gradient-checkpointing` | `true` | Trade compute for memory |
| `--warmup-steps` | `100` | Learning rate warmup steps |

### Environment Requirements

#### Python Packages
```
torch>=2.2.0+cu121
transformers>=4.36.0
peft>=0.7.0
bitsandbytes>=0.43.1
tokenizers>=0.15.2  # CRITICAL: must be >= 0.15.2 for Mistral compatibility
safetensors>=0.4.0
```

#### Hardware
- **GPU**: NVIDIA CUDA 12.1+ (tested on T4, V100)
- **Memory**: Minimum 20GB VRAM (4-bit quantization reduces memory ~8x vs FP16)
- **Fallback**: CPU-only training supported but extremely slow (not recommended)

### Output

#### Directory Structure
```
output_dir/
├── adapter_weights/                  # LoRA adapter weights (safetensors)
│   ├── adapter_config.json
│   ├── adapter_model.bin
│   └── ...
├── checkpoints/                      # Training checkpoints (every 500 steps)
│   ├── checkpoint-500/
│   ├── checkpoint-1000/
│   └── ...
├── training_config.json              # Full training hyperparameters
├── training_report.json              # Completion status + content hash
└── runs/                             # TensorBoard logs (if enabled)
```

#### Completion Report Example
```json
{
  "status": "PASS",
  "output_dir": "/path/to/output",
  "content_hash": "eed452409c8627c16db62e67caac805f37ba896e458bc597e8c03c78e9a8c854"
}
```

### Error Handling (Fail-Closed)

The harness raises `Phase2TrainError` exceptions for all critical failures:
- Tokenizer incompatibility (patch #1 mitigation)
- Model loading failures
- Dataset parsing errors (patch #4 mitigation)
- Training exceptions

All exceptions exit with status code 1 and write detailed error messages to stderr.

### Patch Verification Checklist

When deploying to new environments, verify:
- [ ] Tokenizer patch (#1): `use_fast=False` in AutoTokenizer call
- [ ] Model device patch (#2): Conditional `.to(device)` skip for 4-bit models
- [ ] Variable scoping patch (#3): `load_in_4bit` defined in main() before trainer_cfg
- [ ] Dataset fallback patch (#4): JSON serialization in `_iter_text_samples`
- [ ] tokenizers>=0.15.2 installed (use `pip show tokenizers`)
- [ ] transformers>=4.36.0 installed
- [ ] bitsandbytes>=0.43.1 installed (if using 4-bit)

### Related Files

- **Dataset builder**: `KT_PROD_CLEANROOM/tools/growth/state/build_phaseA2_dataset.py`
- **Head-only training** (deprecated): `KT_PROD_CLEANROOM/tools/growth/state/train_head_only_phaseA2.py`
- **FL3 factory** (orchestration): `KT_PROD_CLEANROOM/tools/training/fl3_factory/`

---

## License

Part of King's Theorem (KT) governed reasoning system. See [LICENSE](../../LICENSE) for details.
