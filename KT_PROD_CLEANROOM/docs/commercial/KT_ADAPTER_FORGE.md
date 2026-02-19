# KT Adapter Forge (Offline, Receipted Loop)

This offering produces a controlled training + evaluation loop with WORM evidence. It is offline by default.

## Inputs
- Local dataset path (file or directory).
- Seeded JSON config (training parameters, job label).
- (Optional) Local base model directory for real LoRA training (no downloads).

## Operator Command
Stub (works without ML deps; produces schema-bound artifacts for pipeline rehearsal):
- `python -m tools.training.rapid_lora_loop --dataset <path> --config <cfg.json> --engine stub`

Real LoRA (gated; fail-closed unless explicitly enabled and deps/models are present offline):
- `python -m tools.training.rapid_lora_loop --dataset <path> --config <cfg.json> --engine hf_lora --base-model-dir <local_model_dir>`

## Outputs (WORM)
Per run (under `KT_PROD_CLEANROOM/exports/_runs/...`):
- dataset hash manifest (if dataset is a directory)
- `training_run_manifest*.json`
- adapter bundle artifacts (engine-dependent)
- `verdict.txt` (one line)

## Acceptance Criteria
- No network calls.
- No installs performed by the tool.
- All artifacts are WORM (create-once).
- If deps/models missing: FAIL_CLOSED with a next-action message recorded in the manifest.

