# King's Theorem (KT)

## Repository Notice

**KT: Source-Available, Restricted Research Use**

King's Theorem (KT) is a governed, auditable reasoning and measurement system with a sealed runtime kernel and an offline growth layer (epochs, crucibles, evaluation, curriculum compilation, training warehouse, and distillation). This repository is source-available for non-commercial research, evaluation, and educational use only.

Commercial use requires a separate written license from the copyright holder. Commercial use includes (without limitation): using KT or any KT outputs to train, fine-tune, evaluate, or distill machine learning models for commercial advantage; hosting KT as a service; bundling KT into a product; using KT to generate datasets/curricula/training materials for commercial systems; or any activity that provides direct or indirect commercial benefit.

By using this repository, you agree to the terms in `LICENSE` and acknowledge that attempts to bypass or remove KT's governance/invariants terminate all rights granted.

---

KT is a **governed, auditable intelligence system** built around a sealed runtime kernel and an offline growth layer.

## What This Repo Contains

- **V2 Runtime Kernel (sealed):** `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/`
  - Single execution topology: Entry -> Spine -> organs
  - Import Truth + Negative Space enforcement
  - Fail-closed invariants + schemas as contract perimeter
  - Append-only State Vault + deterministic replay
- **Growth Layer (tooling-only):** `KT_PROD_CLEANROOM/tools/growth/`
  - Crucibles (atomic tests) + runner
  - Epoch orchestrator (batch execution)
  - Evaluation harness + delta ledger (measurement-only)
  - Teacher factory (lossy, deterministic curriculum compilation)
  - Dream loop (counterfactual generation; draft-only)

## What KT Is Not

- Not a chatbot.
- Not a fine-tuning script.
- Not self-modifying at runtime.
- Not \"best effort\": violations halt (fail-closed).

## Reproducibility

Artifacts and ledgers are generated **locally** and are not committed:
- `KT_PROD_CLEANROOM/tools/growth/artifacts/`
- `KT_PROD_CLEANROOM/tools/growth/ledgers/`

Runbook: `docs/RUNBOOK.md`

## Docs

- Overview: `docs/KT_OVERVIEW.md`
- Architecture: `docs/KT_ARCHITECTURE.md`
- Threat model: `docs/KT_THREAT_MODEL.md`
- Glossary: `docs/KT_GLOSSARY.md`
