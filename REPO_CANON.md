# KT Repository Canon (Inventory Only)

This file is an **inventory** of the canonical directories and entrypoints in this repository. It contains **no code** and makes **no claims** beyond what exists on disk.

## Top-Level

- `KT_PROD_CLEANROOM/` — production cleanroom containing the V2 kernel and the tooling-only growth layer.
- `docs/` — public docs (overview, architecture, threat model, runbook).
- `LICENSE` — restricted research license (source-available; non-commercial).
- `run_kt_e2e.sh` — one-command, fail-closed end-to-end execution (local artifacts only).

## V2 Runtime Kernel (Sealed)

- Root: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/`
- Runtime surface: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/`
- Runtime registry (single source of truth): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
  - Canonical Entry module + callable (declared)
  - Canonical Spine module + callable (declared)
  - State vault relative JSONL path (declared; resolved relative to kernel workdir)
  - Allowlisted runtime import roots (declared)

## Growth Layer (Tooling-Only)

- Root: `KT_PROD_CLEANROOM/tools/growth/`
- Crucibles + runner (C019):
  - Specs: `KT_PROD_CLEANROOM/tools/growth/crucibles/`
  - Runner wrapper: `KT_PROD_CLEANROOM/tools/growth/crucible_runner.py`
- Epoch orchestrator (C018): `KT_PROD_CLEANROOM/tools/growth/orchestrator/`
- Evaluation harness (C023): `KT_PROD_CLEANROOM/tools/growth/eval_harness/`
- Eval+ (C023+): `KT_PROD_CLEANROOM/tools/growth/eval_harness_plus/`
- Teacher factory (C021): `KT_PROD_CLEANROOM/tools/growth/teacher_factory/`
- Dream loop (C020): `KT_PROD_CLEANROOM/tools/growth/dream_loop/`
- Training warehouse (C024): `KT_PROD_CLEANROOM/tools/growth/training_warehouse/`
- Distillation (C025): `KT_PROD_CLEANROOM/tools/growth/distillation/`

## Local Outputs (Not Committed)

These directories are intentionally gitignored and must remain local-only:

- `KT_PROD_CLEANROOM/tools/growth/artifacts/` — append-only run artifacts
- `KT_PROD_CLEANROOM/tools/growth/ledgers/` — append-only ledgers (tooling outputs)

Policy files exist in-tree:

- `KT_PROD_CLEANROOM/tools/growth/artifacts/ARTIFACT_POLICY.md`
- `KT_PROD_CLEANROOM/tools/growth/ledgers/LEDGER_POLICY.md`

