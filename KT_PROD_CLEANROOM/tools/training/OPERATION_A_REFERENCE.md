# Operation A: MRT-1 Training Lane Refactor

## Mission Statement

Create a deterministic, governed, replayable training lane that transforms:
```
Policy-C output → Valid dataset → Adapter training → Receipted promotion → Runtime snapshot
```

**Non-Goals**: Not improving model quality, not adding adapters, not changing Policy-C logic. This is **plumbing correctness**, not intelligence improvement.

---

## System Boundaries

Each layer has a single responsibility and a boundary that cannot be crossed:

| Layer | Responsibility | Must NOT Do |
|-------|---|---|
| **Policy-C** | Generate behavioral signals | Care about model training format |
| **Dataset Layer** | Convert signals → LLM-readable text | Inject training logic |
| **Training Lane (MRT-1)** | Train adapters under governance | Modify datasets or policy |
| **Promotion Layer** | Validate + register adapter | Retrain or mutate weights |
| **Snapshot Layer** | Freeze runtime registry | Interpret training results |

**Why this matters**: Previous failures occurred because the dataset contract was undefined. Now it is law.

---

## Root Problem

Policy-C produces **structured cognitive artifacts** with metadata references and pressure tensor links, not plain text.

MRT-1 expects **plain text training samples** in the canonical format: `{"text": "<string>"}`

The interface between cognition and training was **undefined**, causing silent failures:
- Metadata records arrived at trainer
- Trainer found no text fields
- Coercion fell back to JSON serialization without validation
- Model trained on JSON garbage
- Adapters never learned anything useful
- Failure was silent, not fail-closed

**Operation A fixes this by defining the boundary in code.**

---

## Canonical Interface Contract (NEW LAW)

### Dataset Format (Immutable)

Every MRT-1 dataset line **MUST** be exactly:
```json
{"text": "<string of training text>"}
```

No other fields. No variations. **100% compliance enforced by Gate D2.**

### Text Extraction Priority (When Coercing Records)

When converting a Policy-C record to training text, try in order:
1. `text` field (if exists and non-empty string)
2. `prompt` field
3. `input` field
4. `output` field
5. `completion` field
6. **Fallback**: `json.dumps(full_record, sort_keys=True)`

This priority order ensures we use explicitly-labeled text first, then serialize structured records as last resort.

### Error Handling (Fail-Closed)

If a record yields empty/null text after all priority attempts:
- **Reject the line** (do not pass to trainer)
- **Count it as a coercion failure**
- **Gate D2 validates** that zero empty strings exist in output

Empty strings are **violations** of the contract. They must be caught at the boundary.

---

## Operation A Pipeline (7 Stages)

### Stage 1: Policy Sweep

**Input**: None (internal Policy-C generation)  
**Output**: `policy_c_sweep_result.json`

**Responsibility**: Generate behavioral signals, episode traces, pressure tensors.

**Gate P1 — Policy Sweep Gate**

| Condition | Pass Criteria |
|-----------|---|
| File exists | sweep result present |
| Schema valid | JSON conforms to policy_c_sweep_result_schema_v1 |
| Non-empty | contains ≥ 1 episode |

**Fail-Closed**: If gate fails, halt entire run. No retries.

---

### Stage 2: Dataset Export

**Input**: `policy_c_sweep_result.json`  
**Output**: `kt_policy_c_dataset_v1.jsonl` (raw, uncoerced)

**Responsibility**: Convert Policy-C episodes into structured records (JSONL).

Records may contain metadata fields, pressure refs, epoch summaries—not plain text.

**Gate D1 — Raw Dataset Gate**

| Condition | Pass Criteria |
|-----------|---|
| File exists | dataset file written |
| Non-empty | ≥ 1 line |
| JSON parse rate | ≥ 95% of lines are valid JSON |

**Fail-Closed**: If gate fails, halt entire run.

---

### Stage 3: Dataset Coercion (NEW CORE STAGE)

**Input**: `kt_policy_c_dataset_v1.jsonl` (raw)  
**Output**: `dataset_coerced.jsonl` (canonical)

**Responsibility**: Transform raw metadata-heavy records → canonical `{"text": ...}` format.

This is where layer separation is **enforced**:
- Cognition (Policy-C) never touches this
- Training (MRT-1) never sees raw records
- Dataset layer owns the translation

**Algorithm**:
```python
for each line in raw_dataset:
    try:
        record = parse_json(line)
        text = extract_text_by_priority(record)  # text → prompt → input → output → completion → json.dumps
        if text.strip():
            write({"text": text.strip()})
        else:
            fail_line()  # Empty text = coercion failure
    except:
        fail_line()  # Parse error = coercion failure
```

**Gate D2 — Coercion Gate**

| Condition | Pass Criteria |
|-----------|---|
| File exists | coerced dataset written |
| Non-empty | ≥ 1 line |
| Schema | EVERY line is `{"text": str}` (no other fields) |
| Empty strings | 0 empty text entries (all text.strip() is non-empty) |

**Fail-Closed**: If any line violates schema, entire coercion fails. No partial outputs.

This gate **prevents silent zero-signal training**.

---

### Stage 4: MRT-0 Manufacture

**Input**: None (deterministic generation)  
**Output**: `cohort0_adapter_set.json`

**Responsibility**: Create adapter identity scaffolding.

Produces:
- Adapter IDs: `adapter_1` through `adapter_13`
- Version lock: All adapters version `1`
- Governance metadata: Creation timestamp, ordinals, status

**Gate M0 — MRT-0 Manufacture Gate**

| Condition | Pass Criteria |
|-----------|---|
| Manifest exists | `cohort0_adapter_set.json` present |
| Adapter count | Exactly 13 adapters |
| Adapter IDs | Must be `adapter_1`, `adapter_2`, ..., `adapter_13` |
| Schema | Valid JSON conforming to schema |
| Version | All adapters version `1` |

**Fail-Closed**: If any condition fails, halt. No partial manifests.

---

### Stage 5: MRT-1 Training Loop

**Input**: 
- `dataset_coerced.jsonl`
- `cohort0_adapter_set.json`
- Base model + hyperparameters

**Output**: 13 × `train_receipt.json` (per adapter)

**Responsibility**: Train LoRA adapters under governance.

For each adapter `adapter_1` through `adapter_13`:
```
1. Load coerced dataset
2. Load base model (Mistral-7B-Instruct-v0.2)
3. Apply 4-bit quantization + LoRA
4. Run training
5. Save adapter weights
6. Generate train_receipt.json
```

**Gate T1 — Training Gate (per adapter)**

| Condition | Pass Criteria |
|-----------|---|
| Receipt exists | `train_receipt.json` written |
| Receipt is JSON | Valid JSON document |
| Status field | `"status": "PASS"` |
| Weights exist | `adapter_weights/` directory contains safetensors files |
| Log file | Training log file present |
| Metadata | adapter_id, base_model, dataset fields present |

**Fail-Closed**: If any adapter fails T1, **stop entire run**. No partial training.

**Receipt Format**:
```json
{
  "adapter_id": "adapter_1",
  "status": "PASS",
  "weights_dir": "/path/to/adapter_weights",
  "log_file": "/path/to/training.log",
  "report_file": "/path/to/training_report.json",
  "base_model": "mistralai/Mistral-7B-Instruct-v0.2",
  "dataset": "/path/to/dataset_coerced.jsonl",
  "metrics": {...},
  "trained_at": "2026-02-11T12:34:56.789Z"
}
```

---

### Stage 6: Promotion

**Input**: 13 × `train_receipt.json`  
**Output**: `promotion_registry.jsonl` + `promotion_manifest.json`

**Responsibility**: Register trained adapters into canonical registry.

For each training receipt:
```
1. Validate receipt (T1 gate compliance)
2. Compute SHA256 hash of receipt (immutable proof)
3. Create promotion record
4. Write to promotion_registry.jsonl
```

**Gate PR1 — Promotion Gate (per adapter)**

| Condition | Pass Criteria |
|-----------|---|
| Receipt valid | JSON, well-formed |
| Status | Receipt has `"status": "PASS"` |
| Adapter ID | Matches expected `adapter_N` pattern |
| Promotion hash | SHA256 hash computed and stored |
| Registry entry | Written to promotion_registry.jsonl |

**Fail-Closed**: If any adapter fails PR1, stop entire run.

**Registry Format** (one line per adapter):
```json
{
  "adapter_id": "adapter_1",
  "status": "PROMOTED",
  "promotion_hash": "abc123...",
  "training_receipt": "/path/to/train_receipt.json",
  "weights_dir": "/path/to/adapter_weights",
  "promoted_at": "2026-02-11T12:34:56.789Z",
  "training_metrics": {...}
}
```

---

### Stage 7: Runtime Snapshot

**Input**: `promotion_registry.jsonl`  
**Output**: `mrt1_runtime_snapshot.json` (immutable, frozen)

**Responsibility**: Build final canonical runtime registry.

Creates a **frozen, version-locked snapshot** that training and evaluation use:
- All 13 adapters present
- All metadata immutable
- No further edits allowed
- Timestamp frozen
- Version lock: v1

**Gate RS1 — Runtime Snapshot Gate**

| Condition | Pass Criteria |
|-----------|---|
| Snapshot exists | `mrt1_runtime_snapshot.json` written |
| Valid JSON | Parses as JSON object |
| Adapter count | Exactly 13 adapters |
| Adapter IDs | adapter_1 through adapter_13 present |
| Version | All adapters version `1` |
| Timestamp | `frozen_at` field present and valid |
| Immutability marker | `"status": "frozen"` |

**Fail-Closed**: If gate fails, halt. Snapshot is all-or-nothing.

**Snapshot Format**:
```json
{
  "schema": "kt.mrt1_runtime_snapshot.v1",
  "version": "1",
  "adapters": [
    {
      "adapter_id": "adapter_1",
      "status": "PROMOTED",
      "promotion_hash": "...",
      "weights_dir": "...",
      "promoted_at": "...",
      "training_metrics": {...}
    },
    ...
  ],
  "adapter_count": 13,
  "frozen_at": "2026-02-11T12:34:56.789Z",
  "status": "frozen",
  "_note": "IMMUTABLE - Do not edit. Use for training, evaluation, and inference only."
}
```

---

## Global Fail-Closed Law

Operation A enforces this law **at every stage**:

```
IF any_gate fails:
  THEN halt_entire_run()
  NO retries
  NO auto_repair
  NO skipping_adapters
```

**Why fail-closed?**
- Ensures determinism
- Prevents silent failures
- Makes debugging clear
- Maintains governance integrity
- Produces audit trail

**No partial runs allowed.** Either all 13 adapters train and promote successfully, or the entire operation halts with a clear error message.

---

## Success Definition (Operation A Complete)

Operation A is complete when:

✓ Policy-C sweep runs without manual edits  
✓ Dataset export produces structured data  
✓ Coercion produces non-empty text dataset (100% schema compliance)  
✓ MRT-0 manufacture creates 13 adapter IDs  
✓ All 13 adapters train with PASS receipts  
✓ All 13 adapters are promoted  
✓ Runtime snapshot builds with version lock  

**This means**: The cognition → training bridge is solved permanently.

---

## What Operation A Does NOT Solve

Operation A is foundational plumbing only:

| Excluded | Why | Future Operation |
|----------|-----|---|
| Better adapter performance | Quality improvement | Operation B |
| Multi-GPU scaling | Performance optimization | Operation C |
| Smarter Policy-C signals | Policy improvement | Operation D |
| Adapter evolution | Version management | Operation E |
| Distributed training | Scale-out | Operation F |

---

## Why This Fix Is Canonical

Because it restores **layer separation** as law:

| Layer | Owns What | Doesn't Touch |
|-------|-----------|---|
| **Policy** | Behavior signals | Training format, learning |
| **Dataset** | Signal → text translation | Training logic, policy |
| **Training** | Learning + optimization | Policy, dataset format |
| **Promotion** | Adapter validation | Training, weights |
| **Snapshot** | Runtime state | Interpretation, retraining |

Previously, dataset format assumptions **leaked into training code**, causing undefined behavior.

Now the boundary is **explicit and law-enforced at every gate**.

---

## Implementation Files

```
KT_PROD_CLEANROOM/tools/training/
├── operation_a_gates.py              # All 7 gates (P1, D1, D2, M0, T1, PR1, RS1)
├── stage3_coerce_dataset.py          # Stage 3 implementation
├── stage4_mrt0_manufacture.py        # Stage 4 implementation
├── stage6_promotion.py               # Stage 6 implementation
├── stage7_runtime_snapshot.py        # Stage 7 implementation
├── operation_a_runner.py             # Master orchestrator
├── phase2_train.py                   # Modified to output train_receipt.json
└── operation_a_reference.md          # This file
```

---

## CLI Usage

### Run entire Operation A:
```bash
python operation_a_runner.py \
  --base-model mistralai/Mistral-7B-Instruct-v0.2 \
  --batch-size 1 \
  --learning-rate 1e-4 \
  --num-epochs 1 \
  --max-seq-len 512 \
  --output /path/to/operation_a_run
```

### Skip Stage 1-2 (provide pre-computed):
```bash
python operation_a_runner.py \
  --sweep-result /path/to/policy_c_sweep_result.json \
  --raw-dataset /path/to/kt_policy_c_dataset_v1.jsonl \
  --output /path/to/operation_a_run
```

### Run individual stages:
```bash
python stage3_coerce_dataset.py --input raw.jsonl --output coerced.jsonl
python stage4_mrt0_manufacture.py --output-dir ./mrt0 --adapter-count 13
python stage6_promotion.py --receipts receipt1.json receipt2.json ... --output-dir ./promotion --registry promotion_registry.jsonl
python stage7_runtime_snapshot.py --registry promotion_registry.jsonl --output mrt1_runtime_snapshot.json
```

---

## Output Structure

After Operation A completes:
```
operation_a_run_TIMESTAMP/
├── operation_a_result.json                  # Audit trail of all gates
├── policy_c_sweep/
│   └── policy_c_sweep_result.json
├── policy_c_export/
│   └── kt_policy_c_dataset_v1.jsonl
├── stage3_coercion/
│   └── dataset_coerced.jsonl
├── stage4_mrt0/
│   └── cohort0_adapter_set.json
├── stage5_training/
│   ├── adapter_1/
│   │   ├── adapter_weights/
│   │   ├── train_receipt.json
│   │   ├── training_report.json
│   │   └── training.log
│   ├── adapter_2/
│   │   └── ...
│   └── ... (adapter_3 through adapter_13)
├── stage6_promotion/
│   ├── promotion_registry.jsonl
│   └── promotion_manifest.json
└── stage7_snapshot/
    └── mrt1_runtime_snapshot.json
```

---

## Audit Trail

`operation_a_result.json` contains complete execution history:
```json
{
  "operation": "Operation A: MRT-1 Training Lane Refactor",
  "started_at": "2026-02-11T12:34:56.789Z",
  "status": "PASS",
  "output_root": "/path/to/run",
  "stages": {
    "stage3_coercion": {
      "status": "PASS",
      "reason": "Coerced dataset valid: ...",
      "line_count": 5000,
      "...": "..."
    },
    ...
  },
  "runtime_snapshot": "/path/to/mrt1_runtime_snapshot.json",
  "completed_at": "2026-02-11T13:45:00.123Z"
}
```

This is the permanent record of training governance.

---

## Debugging Failed Gates

If a gate fails, the error message clearly identifies:
1. Which gate failed (P1, D1, D2, M0, T1, PR1, RS1)
2. Why it failed (pass criteria)
3. What metadata was collected before failure

Example:
```
Gate D2 FAILED: Line 1523: Expected only 'text' key, got ['text', 'extra_field']
```

Check the full `operation_a_result.json` for detailed metadata.

---

## Next Operations

After Operation A successfully completes and `mrt1_runtime_snapshot.json` is frozen:

- **Operation B**: Use snapshot for evaluation (EVAL phase)
- **Operation C**: Use snapshot for inference (RUNTIME phase)
- **Operation D**: Improve Policy-C signals (next iteration)
- **Operation E**: Add new adapters to cohort (expansion)

But foundational governance is now in place.

---

*Operation A Reference Document*  
*Created: 2026-02-11*  
*Status: Canonical*  
*Layer Separation: Enforced*
