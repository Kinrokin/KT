# King’s Theorem (KT)

KT is a **governed, auditable intelligence system** built around a sealed runtime kernel and an offline growth layer.

## What This Repo Contains

- **V2 Runtime Kernel (sealed):** `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/`
  - Single execution topology: Entry → Spine → organs
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
- Not “best effort”: violations halt (fail-closed).

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
