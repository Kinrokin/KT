# KT Adapter Forge (Offline, Receipted Loop)

This offering produces a controlled training + evaluation loop with WORM evidence. It is offline by default.

SKU: `SKU_FORGE`  
Lane: `forge.v1` (operator orchestration) + `tools.training.rapid_lora_loop` (training sub-lane; stub by default)

## Business outcome (what you can say)
- “We can remediate measured failures via controlled adaptation, and we can prove promotion/blocks mechanically with evidence artifacts.”

## Inputs
- Local dataset path (file or directory).
- Seeded JSON config (training parameters, job label).
- (Optional) Local base model directory for real LoRA training (no downloads).

## Operator Command
Stub (works without ML deps; produces schema-bound artifacts for pipeline rehearsal):
- `python -m tools.training.rapid_lora_loop --dataset <path> --config <cfg.json> --engine stub`

Real LoRA (gated; fail-closed unless explicitly enabled and deps/models are present offline):
- `python -m tools.training.rapid_lora_loop --dataset <path> --config <cfg.json> --engine hf_lora --enable-real-engine --base-model-dir <local_model_dir>`

## Outputs (WORM)
Per run (under `KT_PROD_CLEANROOM/exports/_runs/...`):
- `dataset_hash_manifest.json` + `hashes.txt`
- `training_run_manifest*.json` + `train_manifest.json` + `reasoning_trace.json` + `eval_report.json`
- adapter bundle artifacts (engine-dependent)
- `verdict.txt` (one line)

## Acceptance Criteria
- No network calls.
- No installs performed by the tool.
- All artifacts are WORM (create-once).
- If deps/models missing: FAIL_CLOSED with a next-action message recorded in the manifest.
- Rerun to the same `--out-dir` must be a read-only verify/no-op PASS if artifacts are consistent; otherwise FAIL_CLOSED.

## Typical Timeline (planning estimate)
- Stub rehearsal (no ML deps): 2–5 business days.
- Real training + validation: 2–6+ weeks depending on compute, data readiness, and iterations.

## Pricing Logic (framework; no numbers)
- Per-iteration pricing (baseline → train → validate → gate → deliver) plus compute/hardware pass-through if applicable.
